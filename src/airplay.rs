//! AirPlay 2 receiver: mDNS advertisement + raw-TCP HTTP/RTSP server.
//!
//! Emulates an Apple TV so that iOS devices can:
//!   1. Discover the receiver via mDNS (_airplay._tcp.local.)
//!   2. Pair (transient pair-setup + pair-verify)
//!   3. Cast a video URL via POST /play
//!   4. Optionally push an AAC audio stream (RTSP SETUP → AudioCapture)
//!
//! Since iOS sends RTSP/1.0 requests on the same TCP connection after
//! pairing, and traffic becomes HAP-encrypted mid-stream, we use raw
//! TcpStream I/O and parse HTTP/RTSP manually.  "RTSP/1.0" in the
//! request line is replaced with "HTTP/1.1" before parsing, matching
//! the Python implementation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, warn};

use crate::audio_capture;
use crate::pairing::{fairplay_setup, HapCodec, HapSession};

const FEATURES: u64 = (1 << 48)  // TransientPairing
    | (1 << 47)  // PeerManagement
    | (1 << 46)  // HomeKitPairing
    | (1 << 41)  // PTPClock
    | (1 << 40)  // BufferedAudio
    | (1 << 30)  // UnifiedAdvertisingInfo
    | (1 << 22)  // AudioUnencrypted
    | (1 << 20)  // ReceiveAudioAAC_LC
    | (1 << 19)  // ReceiveAudioALAC
    | (1 << 18)  // ReceiveAudioPCM
    | (1 << 17)  // AudioMetaTxtDAAP
    | (1 << 16)  // AudioMetaProgress
    | (1 << 14)  // MFiSoft_FairPlay
    | (1 << 9)   // AirPlayAudio
    | (1 << 4)   // VideoHTTPLiveStreaming
    | (1 << 0); // Video

/// Derive a stable device ID from the machine's MAC address. Prefers a
/// physical (Ethernet/WiFi) interface so VPN (utun*), Tailscale, or
/// Docker bridge MACs aren't exposed as the device identity — those
/// rotate per session and would prevent iOS from caching our receiver.
fn get_device_id() -> String {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};
    let ifaces = match NetworkInterface::show() {
        Ok(v) => v,
        Err(_) => return "AA:BB:CC:DD:EE:FF".to_string(),
    };

    let pick = |filter: fn(&str) -> bool| -> Option<String> {
        for iface in &ifaces {
            if !filter(&iface.name) {
                continue;
            }
            if let Some(mac) = &iface.mac_addr {
                let mac_u = mac.to_uppercase();
                if mac_u != "00:00:00:00:00:00" && !mac_u.is_empty() {
                    return Some(mac_u);
                }
            }
        }
        None
    };

    pick(crate::net::is_physical)
        .or_else(|| pick(|_| true))
        .unwrap_or_else(|| "AA:BB:CC:DD:EE:FF".to_string())
}

use std::sync::LazyLock;
static DEVICE_ID: LazyLock<String> = LazyLock::new(get_device_id);
const PI: &str = "2e388006-13ba-4041-9a67-25dd4a43d536";
const SRCVERS: &str = "366.0";

/// Fresh Ed25519 seed per run. A previous iteration persisted the seed
/// across runs to let iOS reuse cached pair-setup state — but this tool
/// is a one-shot URL capture that exits after the first hit, and the
/// UPnP `device_uuid` is already regenerated each invocation. Keeping
/// `pk` stable while the rest of our identity rotates is inconsistent,
/// and — more importantly — iOS's negative cache of prior failed pair
/// attempts would then taint every subsequent capture. A fresh pk each
/// run is the intended behavior: we impersonate a brand-new TV every
/// time the sender opens its picker.
fn fresh_ltsk() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

struct AirPlayState {
    friendly_name: String,
    ltsk: SigningKey,
    url_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
    audio_output: Option<String>,
    audio_duration: Option<f64>,
    captured: std::sync::atomic::AtomicBool,
}

pub struct AirPlayReceiver {
    friendly_name: String,
    local_ip: String,
    port: u16,
    url_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
    audio_output: Option<String>,
    audio_duration: Option<f64>,
}

impl AirPlayReceiver {
    pub fn new(
        friendly_name: String,
        local_ip: String,
        port: u16,
        url_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
        audio_output: Option<String>,
        audio_duration: Option<f64>,
    ) -> Self {
        Self {
            friendly_name,
            local_ip,
            port,
            url_tx,
            audio_output,
            audio_duration,
        }
    }

    pub async fn run(self, mut stop_rx: tokio::sync::watch::Receiver<()>) -> Result<()> {
        let ltsk = fresh_ltsk();

        let state = Arc::new(AirPlayState {
            friendly_name: self.friendly_name.clone(),
            ltsk,
            url_tx: self.url_tx,
            audio_output: self.audio_output,
            audio_duration: self.audio_duration,
            captured: std::sync::atomic::AtomicBool::new(false),
        });

        let mdns = ServiceDaemon::new().context("failed to create mDNS daemon")?;
        let pk_hex = state.ltsk.verifying_key().to_bytes().iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        });
        let features_lo = format!("{:#x}", FEATURES & 0xFFFF_FFFF);
        let features_hi = format!("{:#x}", (FEATURES >> 32) & 0xFFFF_FFFF);
        let features_mdns = format!("{},{}", features_lo, features_hi);

        let ip_parsed: std::net::Ipv4Addr = self
            .local_ip
            .parse()
            .context("failed to parse local IP")?;

        let mut properties = HashMap::new();
        properties.insert("deviceid".to_string(), DEVICE_ID.clone());
        properties.insert("features".to_string(), features_mdns);
        properties.insert("flags".to_string(), "0x04".to_string());
        properties.insert("model".to_string(), "AppleTV6,2".to_string());
        properties.insert("srcvers".to_string(), SRCVERS.to_string());
        properties.insert("pk".to_string(), pk_hex.clone());
        properties.insert("pi".to_string(), PI.to_string());
        properties.insert("protovers".to_string(), "1.1".to_string());
        properties.insert("vv".to_string(), "2".to_string());
        properties.insert("acl".to_string(), "0".to_string());
        // Extra TXT keys some iOS builds probe for. Empty/defaults are fine —
        // missing keys occasionally cause pyatv/iOS to treat the device as
        // "partial" and skip it in the picker.
        properties.insert("rsf".to_string(), "0x0".to_string());
        properties.insert("gid".to_string(), PI.to_string());
        properties.insert("gcgl".to_string(), "0".to_string());
        properties.insert("igl".to_string(), "0".to_string());

        let svc_info = ServiceInfo::new(
            "_airplay._tcp.local.",
            &self.friendly_name,
            &format!("{}.local.", self.local_ip.replace('.', "-")),
            ip_parsed.to_string(),
            self.port,
            Some(properties),
        )
        .context("failed to build ServiceInfo")?;

        mdns.register(svc_info)
            .context("failed to register mDNS service")?;
        debug!(
            "AirPlay advertised on {}:{}",
            self.local_ip, self.port
        );

        let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], self.port)))
            .await
            .context("failed to bind AirPlay TCP listener")?;

        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    debug!("AirPlay: stop signal received");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, peer)) => {
                            debug!("AirPlay: connection from {}", peer);
                            let state = state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, state).await {
                                    debug!("AirPlay connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("AirPlay: accept error: {}", e);
                        }
                    }
                }
            }
        }

        let _ = mdns.shutdown();
        Ok(())
    }
}

/// Read/write buffer that optionally passes traffic through a HapCodec.
struct ConnBuf {
    stream: TcpStream,
    /// Plaintext bytes pending parsing after HAP decode.
    plain_buf: Vec<u8>,
    codec: Option<HapCodec>,
}

impl ConnBuf {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            plain_buf: Vec::new(),
            codec: None,
        }
    }

    fn enable_encryption(&mut self, shared_key: &[u8]) {
        self.codec = Some(HapCodec::new(shared_key));
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        if let Some(codec) = &mut self.codec {
            let enc = codec.encrypt(data);
            self.stream
                .write_all(&enc)
                .await
                .context("failed to write encrypted data")?;
        } else {
            self.stream
                .write_all(data)
                .await
                .context("failed to write data")?;
        }
        Ok(())
    }
}

struct Request {
    method: String,
    path: String,
    version: String, // "HTTP/1.1" or "RTSP/1.0"
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Read and parse one HTTP/RTSP request from the connection buffer.
async fn read_request(conn: &mut ConnBuf) -> Result<Request> {
    loop {
        let search_from = conn.plain_buf.len().saturating_sub(3);
        if let Some(pos) = find_bytes(&conn.plain_buf[search_from..], b"\r\n\r\n") {
            let header_end = search_from + pos + 4;
            let header_bytes = conn.plain_buf[..header_end].to_vec();
            conn.plain_buf.drain(..header_end);

            // Replace "RTSP/1.0" with "HTTP/1.1" in the request line before parsing
            let replaced = header_bytes.replace(b"RTSP/1.0", b"HTTP/1.1");

            let header_str = String::from_utf8_lossy(&replaced);
            let mut lines = header_str.lines();

            let req_line = lines.next().unwrap_or("").trim();
            let mut parts = req_line.splitn(3, ' ');
            let method = parts.next().unwrap_or("GET").to_string();
            let path = parts.next().unwrap_or("/").to_string();
            let version_raw = parts.next().unwrap_or("HTTP/1.1");
            // If original had RTSP/1.0 it was replaced with HTTP/1.1 for
            // parsing; report back as RTSP/1.0 if that was the case.
            let version = if header_bytes.starts_with(b"OPTIONS")
                || header_bytes.starts_with(b"SETUP")
                || header_bytes.starts_with(b"RECORD")
                || header_bytes.starts_with(b"TEARDOWN")
                || header_bytes.starts_with(b"FLUSH")
                || header_bytes.starts_with(b"GET_PARAMETER")
                || header_bytes.starts_with(b"SET_PARAMETER")
                || header_bytes.starts_with(b"SETPEERS")
                || header_bytes.starts_with(b"ANNOUNCE")
            {
                "RTSP/1.0".to_string()
            } else {
                version_raw.to_string()
            };

            let mut headers: HashMap<String, String> = HashMap::new();
            for line in lines {
                let line = line.trim();
                if line.is_empty() {
                    break;
                }
                if let Some(colon) = line.find(':') {
                    let k = line[..colon].trim().to_lowercase();
                    let v = line[colon + 1..].trim().to_string();
                    headers.insert(k, v);
                }
            }

            let content_length: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            if content_length > 0 {
                while conn.plain_buf.len() < content_length {
                    let mut tmp = [0u8; 4096];
                    let nread = conn
                        .stream
                        .read(&mut tmp)
                        .await
                        .context("reading body")?;
                    if nread == 0 {
                        return Err(anyhow::anyhow!("EOF while reading body"));
                    }
                    let raw = &tmp[..nread];
                    if let Some(c) = &mut conn.codec {
                        let plain = c.decrypt(raw);
                        conn.plain_buf.extend_from_slice(&plain);
                    } else {
                        conn.plain_buf.extend_from_slice(raw);
                    }
                }
                let body = conn.plain_buf[..content_length].to_vec();
                conn.plain_buf.drain(..content_length);
                return Ok(Request { method, path, version, headers, body });
            }

            return Ok(Request { method, path, version, headers, body: Vec::new() });
        }

        let mut tmp = [0u8; 4096];
        let nread = conn
            .stream
            .read(&mut tmp)
            .await
            .context("failed to read headers")?;
        if nread == 0 {
            return Err(anyhow::anyhow!("EOF while reading headers"));
        }
        let raw = &tmp[..nread];
        if let Some(codec) = &mut conn.codec {
            let plain = codec.decrypt(raw);
            conn.plain_buf.extend_from_slice(&plain);
        } else {
            conn.plain_buf.extend_from_slice(raw);
        }
    }
}

/// Search `haystack` for `needle`, returning the offset.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

trait SliceReplace {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
}
impl SliceReplace for Vec<u8> {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
        if let Some(pos) = find_bytes(self, from) {
            let mut out = Vec::new();
            out.extend_from_slice(&self[..pos]);
            out.extend_from_slice(to);
            out.extend_from_slice(&self[pos + from.len()..]);
            out
        } else {
            self.clone()
        }
    }
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    extra_headers: Vec<(String, String)>,
    version: String, // "HTTP/1.1" or "RTSP/1.0"
    cseq: Option<String>,
    /// If true, caller should stop parsing further requests after sending.
    /// Used for `POST /reverse` (HTTP upgrade → PTTH/1.0 event channel).
    upgrade: bool,
}

impl Response {
    fn new(version: &str, status: u16, body: Vec<u8>, content_type: &'static str) -> Self {
        Self {
            status,
            content_type,
            body,
            extra_headers: Vec::new(),
            version: version.to_string(),
            cseq: None,
            upgrade: false,
        }
    }

    fn with_cseq(mut self, cseq: Option<String>) -> Self {
        self.cseq = cseq;
        self
    }

    fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.extra_headers.push((k.into(), v.into()));
        self
    }

    fn with_upgrade(mut self) -> Self {
        self.upgrade = true;
        self
    }

    fn to_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            101 => "Switching Protocols",
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "OK",
        };
        // Estimate capacity to avoid repeated re-allocation on writes.
        let mut out = String::with_capacity(192 + self.body.len());
        out.push_str(&self.version);
        out.push(' ');
        out.push_str(&self.status.to_string());
        out.push(' ');
        out.push_str(status_text);
        out.push_str("\r\n");
        // iOS checks for "AirTunes/" in some pairing flows.
        out.push_str("Server: AirTunes/366.0\r\n");
        if let Some(cseq) = &self.cseq {
            out.push_str("CSeq: ");
            out.push_str(cseq);
            out.push_str("\r\n");
        }
        // 101 Upgrade responses must not advertise Content-Type/Length.
        if self.status != 101 {
            out.push_str("Content-Type: ");
            out.push_str(self.content_type);
            out.push_str("\r\n");
            out.push_str("Content-Length: ");
            out.push_str(&self.body.len().to_string());
            out.push_str("\r\n");
        }
        for (k, v) in &self.extra_headers {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

async fn handle_connection(stream: TcpStream, state: Arc<AirPlayState>) -> Result<()> {
    let mut conn = ConnBuf::new(stream);
    let mut hap = HapSession::new(state.ltsk.clone());
    let mut audio_port: Option<u16> = None;
    let mut is_encrypted = false;

    loop {
        let req = match read_request(&mut conn).await {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("EOF") {
                    debug!("AirPlay: connection closed");
                } else {
                    warn!("AirPlay: read_request error: {}", e);
                }
                break;
            }
        };

        let cseq = req.headers.get("cseq").cloned();

        let resp = handle_request(
            &req,
            &mut hap,
            &mut audio_port,
            &state,
        )
        .await;

        let upgrade = resp.upgrade;
        let resp_bytes = resp
            .with_cseq(cseq)
            .to_bytes();

        if let Err(e) = conn.write_all(&resp_bytes).await {
            warn!("AirPlay: write error: {}", e);
            break;
        }

        if upgrade {
            // /reverse upgraded to PTTH/1.0. The socket stays open so iOS can
            // receive server-pushed events; we never push any. Drain passively
            // until iOS closes from its side — trying to parse requests here
            // is wrong since the role has inverted.
            debug!("AirPlay: /reverse upgraded, entering passive drain");
            let mut drain = [0u8; 1024];
            loop {
                match conn.stream.read(&mut drain).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            break;
        }

        if hap.is_encrypted()
            && !is_encrypted
            && let Some(key) = hap.shared_key()
        {
            conn.enable_encryption(key);
            is_encrypted = true;
            debug!("AirPlay: connection upgraded to HAP encryption");
        }
    }

    Ok(())
}

async fn handle_request(
    req: &Request,
    hap: &mut HapSession,
    audio_port: &mut Option<u16>,
    state: &Arc<AirPlayState>,
) -> Response {
    let version = &req.version;
    let method = req.method.as_str();
    let path = req.path.as_str();
    let body = &req.body;

    debug!("AirPlay: {} {}", method, path);

    match method {
        "GET" => match path {
            "/server-info" | "/info" => send_device_info(version, hap, state),
            "/playback-info" => send_playback_info(version, state),
            // iOS may probe /getProperty/<name> for playbackAccessLog,
            // playbackErrorLog, forwardEndTime, reverseEndTime. Silent 200
            // is enough for URL capture.
            p if p.starts_with("/getProperty") => ok_empty(version),
            _ => ok_empty(version),
        },

        "POST" => match path {
            "/play" => handle_play(version, body, &req.headers, state),
            "/info" => send_device_info(version, hap, state),
            "/action" => handle_action(version, body, state),
            "/pair-setup" => {
                let res = hap.pair_setup(body);
                Response::new(version, 200, res, "application/octet-stream")
            }
            "/pair-verify" => {
                let res = hap.pair_verify(body);
                Response::new(version, 200, res, "application/octet-stream")
            }
            "/fp-setup" | "/fp-setup2" => {
                if let Some(res) = fairplay_setup(body) {
                    Response::new(version, 200, res, "application/octet-stream")
                } else {
                    ok_empty(version)
                }
            }
            // iOS 17+ opens /reverse as an HTTP Upgrade channel for
            // server-pushed events (PTTH/1.0). A non-101 reply here causes
            // some iOS builds to abort the whole session. We return 101
            // and then keep the socket idle — we never push events.
            "/reverse" => Response::new(version, 101, Vec::new(), "application/octet-stream")
                .with_header("Upgrade", "PTTH/1.0")
                .with_header("Connection", "Upgrade")
                .with_upgrade(),
            // Sent when FairPlay bit is advertised. 200 empty satisfies the
            // minimum handshake when no real FairPlay key derivation follows.
            "/auth-setup" => ok_empty(version),
            // Media control endpoints. We don't actually play anything, so
            // all are acknowledged with 200 empty — but handling them
            // explicitly documents the state machine and avoids iOS
            // treating the fallthrough as an error on strict builds.
            "/scrub" | "/rate" | "/stop" | "/feedback" | "/command"
            | "/audioMode" | "/configure" | "/setProperty"
            | "/pair-setup-pin" | "/pair-pin-start" | "/authorize"
            | "/photo" | "/slideshows" => ok_empty(version),
            _ => ok_empty(version),
        },

        // Several iOS endpoints use PUT for updates (e.g. /setProperty/<name>).
        "PUT" => ok_empty(version),

        "OPTIONS" => Response::new(version, 200, Vec::new(), "application/octet-stream")
            .with_header(
                "Public",
                "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, FLUSHBUFFERED, \
                 TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET",
            ),

        "SETUP" => handle_setup(version, body, audio_port, state).await,

        "TEARDOWN" => ok_empty(version),

        "GET_PARAMETER" => {
            if body.windows(6).any(|w| w == b"volume") {
                Response::new(version, 200, b"volume: 0.000000\r\n".to_vec(), "text/parameters")
            } else {
                ok_empty(version)
            }
        }

        "RECORD" | "FLUSH" | "FLUSHBUFFERED" | "SETPEERS" | "SET_PARAMETER" | "ANNOUNCE"
        | "PAUSE" => ok_empty(version),

        _ => ok_empty(version),
    }
}

fn send_device_info(version: &str, hap: &HapSession, state: &AirPlayState) -> Response {
    let pk_hex = hap.public_key_hex();
    let features_val: i64 = FEATURES as i64;

    let mut d = plist::Dictionary::new();
    d.insert("deviceID".into(), plist::Value::String(DEVICE_ID.clone()));
    d.insert("features".into(), plist::Value::Integer(features_val.into()));
    d.insert("model".into(), plist::Value::String("AppleTV6,2".to_string()));
    d.insert("protocolVersion".into(), plist::Value::String("1.1".to_string()));
    d.insert("sourceVersion".into(), plist::Value::String(SRCVERS.to_string()));
    d.insert("sdk".into(), plist::Value::String("AirPlay;2.0.2".to_string()));
    d.insert("name".into(), plist::Value::String(state.friendly_name.clone()));
    d.insert("macAddress".into(), plist::Value::String(DEVICE_ID.clone()));
    d.insert("pi".into(), plist::Value::String(PI.to_string()));
    d.insert("pk".into(), plist::Value::String(pk_hex));
    d.insert("statusFlags".into(), plist::Value::Integer(4.into()));
    d.insert("keepAliveLowPower".into(), plist::Value::Boolean(true));
    d.insert("keepAliveSendStatsAsBody".into(), plist::Value::Boolean(true));
    d.insert("vv".into(), plist::Value::Integer(2.into()));

    let mut buf = Vec::new();
    if plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(d)).is_err() {
        return ok_empty(version);
    }
    Response::new(version, 200, buf, "application/x-apple-binary-plist")
}

fn send_playback_info(version: &str, _state: &Arc<AirPlayState>) -> Response {
    // Always report "playing" — during the pre-capture phase so iOS
    // doesn't bail early, and during the post-capture linger phase so
    // the user's casting UI stays on "playing to TV" for a few seconds
    // before the process exits. Claiming "not ready" after capture (the
    // old behavior) made the iOS UI flip to "stopped" and tempted users
    // into retapping cast repeatedly.
    let mut d = plist::Dictionary::new();
    d.insert("duration".into(), plist::Value::Real(0.0));
    d.insert("position".into(), plist::Value::Real(0.0));
    d.insert("rate".into(), plist::Value::Real(1.0));
    d.insert("readyToPlay".into(), plist::Value::Boolean(true));
    d.insert("playbackBufferEmpty".into(), plist::Value::Boolean(false));
    d.insert("playbackBufferFull".into(), plist::Value::Boolean(true));
    d.insert("playbackLikelyToKeepUp".into(), plist::Value::Boolean(true));

    let mut buf = Vec::new();
    if plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(d)).is_err() {
        return ok_empty(version);
    }
    Response::new(version, 200, buf, "text/x-apple-plist+xml")
}

fn handle_play(
    version: &str,
    body: &[u8],
    headers: &HashMap<String, String>,
    state: &Arc<AirPlayState>,
) -> Response {
    let content_type = headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
    let mut url: Option<String> = None;

    if (content_type.contains("binary-plist") || content_type.contains("x-apple"))
        && let Ok(plist::Value::Dictionary(d)) = plist::from_bytes::<plist::Value>(body)
        && let Some(plist::Value::String(s)) = d.get("Content-Location")
    {
        url = Some(s.clone());
    }

    if url.is_none()
        && let Ok(text) = std::str::from_utf8(body)
    {
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Content-Location:") {
                let val = rest.trim();
                if !val.is_empty() {
                    url = Some(val.to_string());
                    break;
                }
            }
        }
    }

    if let Some(u) = url {
        debug!("AirPlay captured URL: {}", u);
        state
            .captured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = state.url_tx.send(Some(u));
    }

    ok_empty(version)
}

fn handle_action(version: &str, body: &[u8], state: &Arc<AirPlayState>) -> Response {
    if let Ok(plist::Value::Dictionary(d)) = plist::from_bytes::<plist::Value>(body) {
        let url = d
            .get("Content-Location")
            .or_else(|| d.get("url"));
        if let Some(plist::Value::String(u)) = url {
            debug!("AirPlay action captured URL: {}", u);
            state
                .captured
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = state.url_tx.send(Some(u.clone()));
        }
    }
    ok_empty(version)
}

async fn handle_setup(
    version: &str,
    body: &[u8],
    audio_port: &mut Option<u16>,
    state: &Arc<AirPlayState>,
) -> Response {
    if body.is_empty() {
        return ok_empty(version);
    }

    let setup_plist = match plist::from_bytes::<plist::Value>(body) {
        Ok(plist::Value::Dictionary(d)) => d,
        _ => return ok_empty(version),
    };

    if let Some(plist::Value::Array(streams)) = setup_plist.get("streams") {
        let mut streams_resp: Vec<plist::Value> = Vec::new();

        for stream_val in streams {
            let stream = match stream_val {
                plist::Value::Dictionary(d) => d,
                _ => continue,
            };

            let shk: Option<Vec<u8>> = stream.get("shk").and_then(|v| {
                if let plist::Value::Data(d) = v {
                    Some(d.clone())
                } else {
                    None
                }
            });

            let stream_type: i64 = stream
                .get("type")
                .and_then(|v| {
                    if let plist::Value::Integer(i) = v {
                        i.as_signed()
                    } else {
                        None
                    }
                })
                .unwrap_or(96);

            let data_port = if let Some(output_path) = &state.audio_output {
                if audio_port.is_none() {
                    match audio_capture::bind_capture_socket() {
                        Ok((socket, port)) => {
                            let output = output_path.clone();
                            let dur = state.audio_duration;
                            let url_tx = state.url_tx.clone();
                            tokio::spawn(async move {
                                let _ = audio_capture::run_capture(
                                    socket, port, output, shk, dur, url_tx,
                                )
                                .await;
                            });
                            *audio_port = Some(port);
                            eprintln!("  🎙️ Recording audio → {}", output_path);
                            port
                        }
                        Err(e) => {
                            warn!("Failed to create AudioCapture: {}", e);
                            7100
                        }
                    }
                } else {
                    audio_port.unwrap_or(7100)
                }
            } else {
                7100
            };

            let mut s_resp = plist::Dictionary::new();
            s_resp.insert("type".into(), plist::Value::Integer(stream_type.into()));
            s_resp.insert("dataPort".into(), plist::Value::Integer((data_port as i64).into()));
            s_resp.insert("controlPort".into(), plist::Value::Integer(7101.into()));
            streams_resp.push(plist::Value::Dictionary(s_resp));
        }

        let mut resp_dict = plist::Dictionary::new();
        resp_dict.insert("streams".into(), plist::Value::Array(streams_resp));
        let mut buf = Vec::new();
        if plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(resp_dict)).is_ok() {
            return Response::new(version, 200, buf, "application/x-apple-binary-plist");
        }
    } else if setup_plist.contains_key("timingProtocol") {
        let mut resp_dict = plist::Dictionary::new();
        resp_dict.insert("eventPort".into(), plist::Value::Integer(0.into()));
        resp_dict.insert("timingPort".into(), plist::Value::Integer(0.into()));
        let mut buf = Vec::new();
        if plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(resp_dict)).is_ok() {
            return Response::new(version, 200, buf, "application/x-apple-binary-plist");
        }
    }

    ok_empty(version)
}

fn ok_empty(version: &str) -> Response {
    Response::new(version, 200, Vec::new(), "application/octet-stream")
}
