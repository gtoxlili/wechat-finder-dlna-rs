use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const MULTICAST_PORT: u16 = 1900;

static NOTIFY_TYPES: &[&str] = &[
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:service:AVTransport:1",
    "urn:schemas-upnp-org:service:RenderingControl:1",
    "urn:schemas-upnp-org:service:ConnectionManager:1",
];

static SEARCH_TARGETS: &[&str] = &[
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:service:AVTransport:1",
    "urn:schemas-upnp-org:service:RenderingControl:1",
    "urn:schemas-upnp-org:service:ConnectionManager:1",
];

/// UPnP 1.1 BOOTID: bumped on every process start so controllers know
/// the device restarted and invalidate cached descriptors. A monotonic
/// second counter since epoch is fine — we just need uniqueness across
/// reboots.
fn boot_id() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1)
}

/// Parse the ST (Search Target) field from an M-SEARCH request body.
/// Returns the trimmed ST value or an empty string.
fn parse_st_header(msg: &str) -> &str {
    for line in msg.lines() {
        // Case-insensitive match per SSDP spec.
        if let Some(rest) = line
            .strip_prefix("ST:")
            .or_else(|| line.strip_prefix("ST :"))
            .or_else(|| line.strip_prefix("st:"))
            .or_else(|| line.strip_prefix("St:"))
        {
            return rest.trim();
        }
    }
    ""
}

/// Decide whether we should answer an M-SEARCH with the given ST.
/// Matches all service/device types we advertise, plus `ssdp:all`,
/// our own uuid (for controllers that remembered us), and DIAL
/// (Xiaomi/Mi Box probe for this when scanning for screen-cast
/// targets before falling back to UPnP).
fn should_respond(st: &str, device_uuid: &str) -> bool {
    if st.is_empty() {
        return false;
    }
    if st == "ssdp:all" || st == "upnp:rootdevice" {
        return true;
    }
    if st == device_uuid {
        return true;
    }
    if SEARCH_TARGETS.contains(&st) {
        return true;
    }
    // DIAL (Discovery And Launch) — used by Xiaomi cast services
    // before falling through to plain UPnP.
    if st == "urn:dial-multiscreen-org:service:dial:1" {
        return true;
    }
    // Some controllers send the device type without the :1 version suffix
    // or with a different minor version; accept any MediaRenderer variant.
    st.starts_with("urn:schemas-upnp-org:device:MediaRenderer:")
        || st.starts_with("urn:schemas-upnp-org:service:AVTransport:")
        || st.starts_with("urn:schemas-upnp-org:service:RenderingControl:")
        || st.starts_with("urn:schemas-upnp-org:service:ConnectionManager:")
}

pub struct SsdpAdvertiser {
    device_uuid: String,
    location: String,
    local_ip: String,
    boot_id: u32,
}

impl SsdpAdvertiser {
    pub fn new(device_uuid: String, location: String, local_ip: String) -> Self {
        Self {
            device_uuid,
            location,
            local_ip,
            boot_id: boot_id(),
        }
    }

    /// Run the SSDP advertiser until `cancel` is closed (sender dropped or
    /// an explicit value is sent).  Intended to be spawned with `tokio::spawn`.
    pub async fn run(self, mut cancel: tokio::sync::watch::Receiver<()>) -> anyhow::Result<()> {
        let local_ip: Ipv4Addr = self
            .local_ip
            .parse()
            .context("invalid local_ip")?;

        let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("socket2::Socket::new")?;
        raw.set_reuse_address(true).context("SO_REUSEADDR")?;
        #[cfg(not(target_os = "windows"))]
        raw.set_reuse_port(true).context("SO_REUSEPORT")?;
        raw.set_nonblocking(true).context("set_nonblocking")?;
        raw.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MULTICAST_PORT).into())
            .context("bind :1900")?;
        raw.join_multicast_v4(&MULTICAST_ADDR, &local_ip)
            .context("IP_ADD_MEMBERSHIP")?;
        raw.set_multicast_if_v4(&local_ip)
            .context("IP_MULTICAST_IF")?;
        // UPnP 2.0 recommends TTL=2 so multicast traverses a single router
        // hop. Default TTL=1 limits us to exactly the same subnet, which
        // breaks on bridged setups where the controller is one hop away.
        raw.set_multicast_ttl_v4(2).context("IP_MULTICAST_TTL")?;

        let sock = UdpSocket::from_std(raw.into()).context("UdpSocket::from_std")?;

        let mut buf = vec![0u8; 4096];

        // UPnP spec: send the initial NOTIFY burst up to 3 times with a
        // small delay to defeat packet loss during discovery. The first
        // NOTIFY goes out immediately; the second and third back-fill
        // after short random-ish delays so senders that missed the
        // first packet pick us up quickly.
        self.notify(&sock).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.notify(&sock).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.notify(&sock).await;

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    self.byebye(&sock).await;
                    break;
                }

                result = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)) => {
                    match result {
                        Err(_) => {
                            self.notify(&sock).await;
                        }
                        Ok(Ok((len, addr))) => {
                            let msg = std::str::from_utf8(&buf[..len]).unwrap_or("");
                            if !msg.starts_with("M-SEARCH") {
                                continue;
                            }
                            let st = parse_st_header(msg);
                            if should_respond(st, &self.device_uuid) {
                                self.respond(&sock, addr, st).await;
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("SSDP recv error: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn notify(&self, sock: &UdpSocket) {
        let dest = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MULTICAST_PORT);
        let nt_list = std::iter::once(self.device_uuid.as_str()).chain(NOTIFY_TYPES.iter().copied());
        for nt in nt_list {
            let usn = if nt == self.device_uuid {
                self.device_uuid.clone()
            } else {
                format!("{}::{}", self.device_uuid, nt)
            };
            let msg = format!(
                "NOTIFY * HTTP/1.1\r\n\
                 HOST: {MULTICAST_ADDR}:{MULTICAST_PORT}\r\n\
                 CACHE-CONTROL: max-age=1800\r\n\
                 LOCATION: {location}\r\n\
                 NT: {nt}\r\n\
                 NTS: ssdp:alive\r\n\
                 USN: {usn}\r\n\
                 SERVER: Linux/4.9 UPnP/1.0 DLNADOC/1.50 Xiaomi-DLNA/1.0\r\n\
                 BOOTID.UPNP.ORG: {bootid}\r\n\
                 CONFIGID.UPNP.ORG: 1\r\n\
                 \r\n",
                location = self.location,
                bootid = self.boot_id,
            );
            if let Err(e) = sock.send_to(msg.as_bytes(), dest).await {
                // ENETUNREACH/EHOSTUNREACH (errno 51/65) is routine with
                // multi-interface advertising — inactive thunderbolt
                // bridges, disconnected wifi, or interfaces that haven't
                // negotiated a route to the multicast group all produce
                // it. Log at debug to avoid spam; real problems (socket
                // closed, permission denied) surface elsewhere.
                tracing::debug!("SSDP notify send error: {e}");
            }
        }
    }

    /// Respond to an M-SEARCH. If the ST selected a specific target, echo
    /// that one back (the searching controller expects its exact ST in
    /// the answer); for `ssdp:all` or unknown patterns, respond once per
    /// advertised target.
    async fn respond(&self, sock: &UdpSocket, addr: SocketAddr, st: &str) {
        let date = httpdate::HttpDate::from(std::time::SystemTime::now());

        let targets: Vec<&str> = if st == "ssdp:all" {
            // Per UPnP spec: reply once per advertised target, plus
            // once with the device's own uuid ST.
            let mut v: Vec<&str> = SEARCH_TARGETS.to_vec();
            v.insert(0, self.device_uuid.as_str());
            v
        } else {
            // Echo the exact ST the controller asked for.
            vec![st]
        };

        for target in &targets {
            let usn = if *target == self.device_uuid {
                self.device_uuid.clone()
            } else {
                format!("{}::{}", self.device_uuid, target)
            };
            let msg = format!(
                "HTTP/1.1 200 OK\r\n\
                 CACHE-CONTROL: max-age=1800\r\n\
                 DATE: {date}\r\n\
                 EXT:\r\n\
                 LOCATION: {location}\r\n\
                 SERVER: Linux/4.9 UPnP/1.0 DLNADOC/1.50 Xiaomi-DLNA/1.0\r\n\
                 ST: {target}\r\n\
                 USN: {usn}\r\n\
                 BOOTID.UPNP.ORG: {bootid}\r\n\
                 CONFIGID.UPNP.ORG: 1\r\n\
                 \r\n",
                location = self.location,
                bootid = self.boot_id,
            );
            if let Err(e) = sock.send_to(msg.as_bytes(), addr).await {
                tracing::debug!("SSDP respond send error: {e}");
            }
        }
    }

    async fn byebye(&self, sock: &UdpSocket) {
        let dest = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MULTICAST_PORT);
        let nt_list = std::iter::once(self.device_uuid.as_str()).chain(NOTIFY_TYPES.iter().copied());
        for nt in nt_list {
            let usn = if nt == self.device_uuid {
                self.device_uuid.clone()
            } else {
                format!("{}::{}", self.device_uuid, nt)
            };
            let msg = format!(
                "NOTIFY * HTTP/1.1\r\n\
                 HOST: {MULTICAST_ADDR}:{MULTICAST_PORT}\r\n\
                 NT: {nt}\r\n\
                 NTS: ssdp:byebye\r\n\
                 USN: {usn}\r\n\
                 BOOTID.UPNP.ORG: {bootid}\r\n\
                 CONFIGID.UPNP.ORG: 1\r\n\
                 \r\n",
                bootid = self.boot_id,
            );
            if let Err(e) = sock.send_to(msg.as_bytes(), dest).await {
                tracing::debug!("SSDP byebye send error: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSEARCH_MEDIA_RENDERER: &str = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 3\r\n\
        ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n";

    const MSEARCH_ALL: &str = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 1\r\n\
        ST: ssdp:all\r\n\r\n";

    const MSEARCH_DIAL: &str = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 1\r\n\
        ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n";

    const MSEARCH_CASE: &str = "M-SEARCH * HTTP/1.1\r\n\
        Host: 239.255.255.250:1900\r\n\
        Man: \"ssdp:discover\"\r\n\
        St: upnp:rootdevice\r\n\r\n";

    #[test]
    fn parse_st_matches_exact_header() {
        assert_eq!(
            parse_st_header(MSEARCH_MEDIA_RENDERER),
            "urn:schemas-upnp-org:device:MediaRenderer:1"
        );
        assert_eq!(parse_st_header(MSEARCH_ALL), "ssdp:all");
        assert_eq!(parse_st_header(MSEARCH_DIAL), "urn:dial-multiscreen-org:service:dial:1");
    }

    #[test]
    fn parse_st_case_insensitive() {
        // Different implementations use different header casing.
        assert_eq!(parse_st_header(MSEARCH_CASE), "upnp:rootdevice");
    }

    #[test]
    fn parse_st_absent_returns_empty() {
        assert_eq!(parse_st_header("M-SEARCH * HTTP/1.1\r\n\r\n"), "");
    }

    #[test]
    fn should_respond_media_renderer() {
        assert!(should_respond(
            "urn:schemas-upnp-org:device:MediaRenderer:1",
            "uuid:abc"
        ));
    }

    #[test]
    fn should_respond_minor_version_variant() {
        // We advertise :1 but some newer senders probe :2 or later.
        assert!(should_respond(
            "urn:schemas-upnp-org:device:MediaRenderer:2",
            "uuid:abc"
        ));
    }

    #[test]
    fn should_respond_ssdp_all() {
        assert!(should_respond("ssdp:all", "uuid:abc"));
    }

    #[test]
    fn should_respond_own_uuid() {
        assert!(should_respond("uuid:abc", "uuid:abc"));
    }

    #[test]
    fn should_respond_other_uuid_rejected() {
        assert!(!should_respond("uuid:zzz", "uuid:abc"));
    }

    #[test]
    fn should_respond_dial() {
        assert!(should_respond(
            "urn:dial-multiscreen-org:service:dial:1",
            "uuid:abc"
        ));
    }

    #[test]
    fn should_respond_unknown_rejected() {
        assert!(!should_respond(
            "urn:schemas-upnp-org:service:UnknownService:1",
            "uuid:abc"
        ));
        assert!(!should_respond("", "uuid:abc"));
    }
}
