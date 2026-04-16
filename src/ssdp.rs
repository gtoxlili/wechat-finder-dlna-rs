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
];

pub struct SsdpAdvertiser {
    device_uuid: String,
    location: String,
    local_ip: String,
}

impl SsdpAdvertiser {
    pub fn new(device_uuid: String, location: String, local_ip: String) -> Self {
        Self {
            device_uuid,
            location,
            local_ip,
        }
    }

    /// Run the SSDP advertiser until `cancel` is closed (sender dropped or
    /// an explicit value is sent).  Intended to be spawned with `tokio::spawn`.
    pub async fn run(self, mut cancel: tokio::sync::watch::Receiver<()>) -> anyhow::Result<()> {
        // --- socket setup via socket2 so we can set SO_REUSEPORT / join multicast ---
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

        // Wrap into tokio UdpSocket
        let sock = UdpSocket::from_std(raw.into()).context("UdpSocket::from_std")?;

        let mut buf = vec![0u8; 4096];

        // Send initial NOTIFY burst
        self.notify(&sock).await;

        loop {
            tokio::select! {
                // Cancelled – send ssdp:byebye and exit
                _ = cancel.changed() => {
                    self.byebye(&sock).await;
                    break;
                }

                // Receive with a 2-second timeout so we can re-announce
                result = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)) => {
                    match result {
                        Err(_) => {
                            // Timeout – re-announce
                            self.notify(&sock).await;
                        }
                        Ok(Ok((len, addr))) => {
                            let msg = String::from_utf8_lossy(&buf[..len]);
                            if msg.contains("M-SEARCH")
                                && (msg.contains("MediaRenderer")
                                    || msg.contains("ssdp:all")
                                    || msg.contains("rootdevice"))
                            {
                                self.respond(&sock, addr).await;
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
                 SERVER: wechat-finder-dlna/1.0 UPnP/1.0\r\n\
                 \r\n",
                location = self.location,
            );
            if let Err(e) = sock.send_to(msg.as_bytes(), dest).await {
                tracing::warn!("SSDP notify send error: {e}");
            }
        }
    }

    async fn respond(&self, sock: &UdpSocket, addr: SocketAddr) {
        for st in SEARCH_TARGETS {
            let msg = format!(
                "HTTP/1.1 200 OK\r\n\
                 CACHE-CONTROL: max-age=1800\r\n\
                 LOCATION: {location}\r\n\
                 ST: {st}\r\n\
                 USN: {uuid}::{st}\r\n\
                 SERVER: wechat-finder-dlna/1.0 UPnP/1.0\r\n\
                 EXT:\r\n\
                 \r\n",
                location = self.location,
                uuid = self.device_uuid,
            );
            if let Err(e) = sock.send_to(msg.as_bytes(), addr).await {
                tracing::warn!("SSDP respond send error: {e}");
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
                 \r\n",
            );
            if let Err(e) = sock.send_to(msg.as_bytes(), dest).await {
                tracing::warn!("SSDP byebye send error: {e}");
            }
        }
    }
}
