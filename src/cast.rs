use std::sync::Arc;

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Cast V2 protocol message — hand-defined to avoid protoc dependency.
/// Wire format matches the Chromium `cast_channel.proto`.
#[derive(Clone, Debug, Default)]
pub struct CastMessage {
    pub protocol_version: i32,  // 0 = CASTV2_1_0
    pub source_id: String,
    pub destination_id: String,
    pub namespace: String,
    pub payload_type: i32,      // 0 = STRING, 1 = BINARY
    pub payload_utf8: Option<String>,
    pub payload_binary: Option<Vec<u8>>,
}

impl CastMessage {
    /// Rough upper-bound estimate of the encoded size. Each field has a
    /// ~2-byte tag + varint length header; strings and bytes contribute
    /// their length plus ~2 bytes of framing. Used to pre-allocate the
    /// output Vec so encode() runs without resizing.
    fn encoded_size_hint(&self) -> usize {
        let mut n = 4; // protocol_version + payload_type
        n += 2 + self.source_id.len();
        n += 2 + self.destination_id.len();
        n += 2 + self.namespace.len();
        if let Some(ref s) = self.payload_utf8 {
            n += 4 + s.len();
        }
        if let Some(ref b) = self.payload_binary {
            n += 4 + b.len();
        }
        n
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.encoded_size_hint());
        // Protobuf wire encoding (matching the .proto field numbers)
        // field 1: protocol_version (varint)
        encode_varint_field(buf, 1, self.protocol_version as u64);
        // field 2: source_id (length-delimited)
        encode_string_field(buf, 2, &self.source_id);
        // field 3: destination_id
        encode_string_field(buf, 3, &self.destination_id);
        // field 4: namespace
        encode_string_field(buf, 4, &self.namespace);
        // field 5: payload_type (varint)
        encode_varint_field(buf, 5, self.payload_type as u64);
        // field 6: payload_utf8 (optional)
        if let Some(ref s) = self.payload_utf8 {
            encode_string_field(buf, 6, s);
        }
        // field 7: payload_binary (optional)
        if let Some(ref b) = self.payload_binary {
            encode_bytes_field(buf, 7, b);
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut msg = CastMessage::default();
        let mut pos = 0;
        while pos < data.len() {
            let (tag, wire_type, new_pos) = decode_tag(data, pos)?;
            pos = new_pos;
            match (tag, wire_type) {
                (1, 0) => { let (v, p) = decode_varint(data, pos)?; msg.protocol_version = v as i32; pos = p; }
                (2, 2) => { let (v, p) = decode_bytes(data, pos)?; msg.source_id = String::from_utf8_lossy(v).into_owned(); pos = p; }
                (3, 2) => { let (v, p) = decode_bytes(data, pos)?; msg.destination_id = String::from_utf8_lossy(v).into_owned(); pos = p; }
                (4, 2) => { let (v, p) = decode_bytes(data, pos)?; msg.namespace = String::from_utf8_lossy(v).into_owned(); pos = p; }
                (5, 0) => { let (v, p) = decode_varint(data, pos)?; msg.payload_type = v as i32; pos = p; }
                (6, 2) => { let (v, p) = decode_bytes(data, pos)?; msg.payload_utf8 = Some(String::from_utf8_lossy(v).into_owned()); pos = p; }
                (7, 2) => { let (v, p) = decode_bytes(data, pos)?; msg.payload_binary = Some(v.to_vec()); pos = p; }
                // Skip unknown fields per protobuf forward-compat rules
                // rather than bailing — a Cast V3 message with a new
                // fixed64/fixed32 field would otherwise kill the whole
                // connection, breaking us when Google extends the wire.
                (_, 0) => { let (_, p) = decode_varint(data, pos)?; pos = p; }
                (_, 1) => {
                    anyhow::ensure!(pos + 8 <= data.len(), "fixed64 truncated");
                    pos += 8;
                }
                (_, 2) => { let (_, p) = decode_bytes(data, pos)?; pos = p; }
                (_, 5) => {
                    anyhow::ensure!(pos + 4 <= data.len(), "fixed32 truncated");
                    pos += 4;
                }
                _ => anyhow::bail!("unsupported wire type {wire_type} for tag {tag}"),
            }
        }
        Ok(msg)
    }
}

fn encode_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 { buf.push(byte); break; }
        buf.push(byte | 0x80);
    }
}

fn encode_varint_field(buf: &mut Vec<u8>, field: u32, val: u64) {
    encode_varint(buf, (field as u64) << 3); // wire type 0
    encode_varint(buf, val);
}

fn encode_string_field(buf: &mut Vec<u8>, field: u32, s: &str) {
    encode_bytes_field(buf, field, s.as_bytes());
}

fn encode_bytes_field(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    encode_varint(buf, ((field as u64) << 3) | 2); // wire type 2
    encode_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn decode_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0;
    loop {
        anyhow::ensure!(pos < data.len(), "varint truncated");
        let byte = data[pos];
        pos += 1;
        val |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        anyhow::ensure!(shift < 64, "varint too long");
    }
    Ok((val, pos))
}

fn decode_tag(data: &[u8], pos: usize) -> Result<(u32, u32, usize)> {
    let (v, p) = decode_varint(data, pos)?;
    Ok(((v >> 3) as u32, (v & 0x07) as u32, p))
}

fn decode_bytes(data: &[u8], pos: usize) -> Result<(&[u8], usize)> {
    let (len, p) = decode_varint(data, pos)?;
    let len = len as usize;
    anyhow::ensure!(p + len <= data.len(), "bytes field truncated");
    Ok((&data[p..p + len], p + len))
}

const MAX_MESSAGE_SIZE: usize = 65536;

const NS_CONNECTION: &str = "urn:x-cast:com.google.cast.tp.connection";
const NS_HEARTBEAT: &str = "urn:x-cast:com.google.cast.tp.heartbeat";
const NS_RECEIVER: &str = "urn:x-cast:com.google.cast.receiver";
const NS_MEDIA: &str = "urn:x-cast:com.google.cast.media";

pub struct CastReceiver {
    friendly_name: String,
    local_ip: String,
    port: u16,
    url_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
}

impl CastReceiver {
    pub fn new(
        friendly_name: String,
        local_ip: String,
        port: u16,
        url_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
    ) -> Self {
        Self {
            friendly_name,
            local_ip,
            port,
            url_tx,
        }
    }

    pub async fn run(self, mut stop_rx: tokio::sync::watch::Receiver<()>) -> Result<()> {
        let tls_acceptor = build_tls_acceptor()?;
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .with_context(|| format!("Failed to bind Cast TLS server on port {}", self.port))?;
        info!(
            "Cast receiver '{}' listening on {}:{}",
            self.friendly_name, self.local_ip, self.port
        );

        let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
        let device_id = Uuid::new_v4().to_string().to_uppercase();
        let cast_id = format!("{:X}", rand_hex_u64());

        let mut props: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        props.insert("id".into(), device_id.clone());
        props.insert("cd".into(), cast_id.clone());
        props.insert("rm".into(), String::new());
        props.insert("ve".into(), "05".into());
        props.insert("md".into(), "Chromecast".into());
        props.insert("fn".into(), self.friendly_name.clone());
        props.insert("ca".into(), "4101".into());
        props.insert("st".into(), "0".into());
        props.insert("bs".into(), "FA8FCA".into());
        props.insert("nf".into(), "1".into());
        props.insert("rs".into(), String::new());

        let service_name = device_id.clone();
        let service_info = ServiceInfo::new(
            "_googlecast._tcp.local.",
            &service_name,
            &format!("{}.local.", self.local_ip.replace('.', "-")),
            &self.local_ip,
            self.port,
            Some(props),
        )
        .context("Failed to create mDNS service info")?;

        mdns.register(service_info)
            .context("Failed to register mDNS service")?;
        info!("mDNS: advertised _googlecast._tcp.local. as '{}'", self.friendly_name);

        let url_tx = self.url_tx.clone();

        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    info!("Cast receiver stopping");
                    let _ = mdns.unregister(&format!("{}._googlecast._tcp.local.", service_name));
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            debug!("Cast: new connection from {}", peer);
                            let acceptor = tls_acceptor.clone();
                            let url_tx = url_tx.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) = handle_cast_connection(tls_stream, url_tx).await {
                                            debug!("Cast connection error: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Cast TLS accept error from {}: {}", peer, e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("Cast listener accept error: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn build_tls_acceptor() -> Result<TlsAcceptor> {
    // rustls 0.23 requires an explicit process-level CryptoProvider.
    // The `ring` crate feature enables the ring provider but doesn't
    // auto-install it as the default — without this, the first TLS
    // accept panics with "Could not automatically determine the
    // process-level CryptoProvider". Install once; subsequent calls
    // are no-ops by design (install_default returns the existing one
    // instead of panicking).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let key_pair = KeyPair::generate().context("Failed to generate TLS key pair")?;
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign certificate")?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
    );

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to build TLS ServerConfig")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

async fn handle_cast_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    url_tx: Arc<tokio::sync::watch::Sender<Option<String>>>,
) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("Cast: client disconnected");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        if msg_len > MAX_MESSAGE_SIZE {
            anyhow::bail!("Cast message too large: {} bytes", msg_len);
        }

        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        let msg = CastMessage::decode(&msg_buf[..])
            .context("Failed to decode CastMessage protobuf")?;

        debug!(
            "Cast recv: ns={} src={} dst={} payload={:?}",
            msg.namespace, msg.source_id, msg.destination_id,
            msg.payload_utf8.as_deref().unwrap_or("")
        );

        let payload_str = msg.payload_utf8.as_deref().unwrap_or("{}");
        let payload: Value = serde_json::from_str(payload_str).unwrap_or(json!({}));
        let msg_type = payload
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let responses = match msg.namespace.as_str() {
            NS_CONNECTION => {
                // CONNECT establishes the virtual channel; CLOSE tears it
                // down. Previously we replied CONNECTED to *every*
                // tp.connection message including CLOSE, confusing senders.
                // Now only acknowledge CONNECT, and on CLOSE let the TCP
                // side close naturally without pushing an unsolicited
                // CONNECTED back.
                match msg_type {
                    "CONNECT" => {
                        let resp = build_message(
                            "receiver-0",
                            &msg.source_id,
                            NS_CONNECTION,
                            json!({"type": "CONNECTED"}),
                        );
                        vec![resp]
                    }
                    "CLOSE" => {
                        debug!("Cast: client closed virtual channel");
                        vec![]
                    }
                    _ => vec![],
                }
            }
            NS_HEARTBEAT => {
                if msg_type == "PING" {
                    let resp = build_message(
                        "receiver-0",
                        &msg.source_id,
                        NS_HEARTBEAT,
                        json!({"type": "PONG"}),
                    );
                    vec![resp]
                } else {
                    vec![]
                }
            }
            NS_RECEIVER => {
                let request_id = payload.get("requestId").and_then(|v| v.as_i64()).unwrap_or(0);
                match msg_type {
                    "GET_STATUS" | "LAUNCH" | "STOP" => {
                        let resp = build_message(
                            "receiver-0",
                            &msg.source_id,
                            NS_RECEIVER,
                            receiver_status_payload(request_id),
                        );
                        vec![resp]
                    }
                    _ => vec![],
                }
            }
            NS_MEDIA => {
                let request_id = payload.get("requestId").and_then(|v| v.as_i64()).unwrap_or(0);
                match msg_type {
                    "LOAD" => {
                        let url = extract_url_from_load(&payload);
                        if let Some(ref u) = url {
                            info!("Cast: received media URL: {}", u);
                            if let Some(st) = payload
                                .get("media")
                                .and_then(|m| m.get("streamType"))
                                .and_then(|v| v.as_str())
                            {
                                debug!("Cast: streamType = {st}");
                            }
                            let _ = url_tx.send(Some(u.clone()));
                        }
                        // Reply with BUFFERING → PLAYING so the sender thinks
                        // the LOAD succeeded and its UI stays on "casting".
                        // We deliberately do NOT close the connection here;
                        // the outer capture() adds a post-capture linger so
                        // the user sees a stable "playing on TV" state for
                        // a few seconds before the process exits, avoiding
                        // the UX trap where instant failure prompts retaps.
                        let buf = build_message(
                            "receiver-0",
                            &msg.source_id,
                            NS_MEDIA,
                            media_status_payload(request_id, "BUFFERING", ""),
                        );
                        let play = build_message(
                            "receiver-0",
                            &msg.source_id,
                            NS_MEDIA,
                            media_status_payload(request_id, "PLAYING", ""),
                        );
                        vec![buf, play]
                    }
                    "GET_STATUS" => {
                        let resp = build_message(
                            "receiver-0",
                            &msg.source_id,
                            NS_MEDIA,
                            media_status_payload(request_id, "IDLE", "FINISHED"),
                        );
                        vec![resp]
                    }
                    "PAUSE" | "PLAY" | "STOP" | "SEEK" | "SET_VOLUME"
                    | "EDIT_TRACKS_INFO" | "QUEUE_LOAD" | "QUEUE_UPDATE" => {
                        // Acknowledge media control commands — some senders
                        // wait for a media status reply before tearing the
                        // session down, which lets us capture the URL
                        // before the TCP close.
                        let resp = build_message(
                            "receiver-0",
                            &msg.source_id,
                            NS_MEDIA,
                            media_status_payload(request_id, "PLAYING", ""),
                        );
                        vec![resp]
                    }
                    _ => vec![],
                }
            }
            ns => {
                debug!("Cast: unhandled namespace: {}", ns);
                vec![]
            }
        };

        for resp_msg in responses {
            write_cast_message(&mut stream, &resp_msg).await?;
        }
    }
}

fn extract_url_from_load(payload: &Value) -> Option<String> {
    let media = payload.get("media")?;

    // Newer CAF senders (2022+) use contentUrl; legacy senders (including
    // older WeChat builds) populate contentId with the actual URL;
    // `entity` is rarer and used by some Cast-CAF reference apps.
    for key in ["contentUrl", "contentId", "entity"] {
        if let Some(url) = media.get(key).and_then(|v| v.as_str())
            && !url.is_empty()
        {
            return Some(url.to_string());
        }
    }

    None
}

fn build_message(source: &str, destination: &str, namespace: &str, payload: Value) -> CastMessage {
    CastMessage {
        protocol_version: 0, // CASTV2_1_0
        source_id: source.to_string(),
        destination_id: destination.to_string(),
        namespace: namespace.to_string(),
        payload_type: 0, // STRING
        // serde_json::to_string on a Value produced by json!() is
        // infallible by construction — the value is always a valid
        // JSON tree. expect() documents that assumption explicitly.
        payload_utf8: Some(
            serde_json::to_string(&payload).expect("json! macro produces serializable values"),
        ),
        payload_binary: None,
    }
}

async fn write_cast_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &CastMessage,
) -> Result<()> {
    // Pack the 4-byte length prefix and the protobuf body into a single
    // Vec so one write_all syscall delivers the whole frame. Avoids the
    // interleaving risk of two separate writes under TLS and a flush
    // between them.
    let mut frame = Vec::with_capacity(4 + msg.encoded_size_hint());
    frame.extend_from_slice(&[0, 0, 0, 0]); // placeholder for length
    msg.encode(&mut frame);
    let body_len = (frame.len() - 4) as u32;
    frame[..4].copy_from_slice(&body_len.to_be_bytes());
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

fn receiver_status_payload(request_id: i64) -> Value {
    json!({
        "type": "RECEIVER_STATUS",
        "requestId": request_id,
        "status": {
            "applications": [
                {
                    "appId": "CC1AD845",
                    "displayName": "Default Media Receiver",
                    "namespaces": [
                        {"name": NS_MEDIA}
                    ],
                    "sessionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "statusText": "Ready To Cast",
                    "transportId": "web-0"
                }
            ],
            "isActiveInput": true,
            "isStandBy": false,
            "volume": {
                "level": 1.0,
                "muted": false
            }
        }
    })
}

fn media_status_payload(request_id: i64, player_state: &str, idle_reason: &str) -> Value {
    // idleReason is only meaningful when playerState == IDLE. Emitting
    // it in other states (the old behavior always set "FINISHED") makes
    // some senders treat the session as terminated.
    let mut status = json!({
        "mediaSessionId": 1,
        "playbackRate": 1,
        "playerState": player_state,
        "currentTime": 0,
        "supportedMediaCommands": 15,
        "volume": {
            "level": 1.0,
            "muted": false
        }
    });
    if player_state == "IDLE" && !idle_reason.is_empty() {
        // json!({...}) always yields an Object; expect() just documents
        // the invariant rather than allowing a silent no-op.
        status
            .as_object_mut()
            .expect("json! object literal is always an Object")
            .insert(
                "idleReason".into(),
                Value::String(idle_reason.to_string()),
            );
    }
    json!({
        "type": "MEDIA_STATUS",
        "requestId": request_id,
        "status": [status]
    })
}

fn rand_hex_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234567890ABCDEF)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> CastMessage {
        CastMessage {
            protocol_version: 0,
            source_id: "sender-0".into(),
            destination_id: "receiver-0".into(),
            namespace: "urn:x-cast:com.google.cast.media".into(),
            payload_type: 0,
            payload_utf8: Some("{\"type\":\"LOAD\",\"requestId\":42}".into()),
            payload_binary: None,
        }
    }

    #[test]
    fn encode_then_decode_roundtrip() {
        let msg = sample_message();
        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let decoded = CastMessage::decode(&buf).expect("decode");
        assert_eq!(decoded.protocol_version, msg.protocol_version);
        assert_eq!(decoded.source_id, msg.source_id);
        assert_eq!(decoded.destination_id, msg.destination_id);
        assert_eq!(decoded.namespace, msg.namespace);
        assert_eq!(decoded.payload_type, msg.payload_type);
        assert_eq!(decoded.payload_utf8, msg.payload_utf8);
        assert_eq!(decoded.payload_binary, msg.payload_binary);
    }

    #[test]
    fn decode_skips_unknown_fixed64() {
        // Real protobuf: tag=100, wire=1 (fixed64), then 8 bytes, then
        // our known tag=2 (source_id, wire=2). A strict decoder would
        // reject; we should skip the fixed64 and still read source_id.
        let mut buf = Vec::new();
        // tag 100 (field 100, wire 1) = (100<<3)|1 = 801
        encode_varint(&mut buf, 801);
        buf.extend_from_slice(&[0u8; 8]); // 8-byte payload
        // tag 2 wire 2 = 18
        encode_varint(&mut buf, 18);
        encode_varint(&mut buf, 5);
        buf.extend_from_slice(b"hello");

        let decoded = CastMessage::decode(&buf).expect("decode");
        assert_eq!(decoded.source_id, "hello");
    }

    #[test]
    fn decode_skips_unknown_fixed32() {
        let mut buf = Vec::new();
        // tag 50 wire 5 (fixed32) = (50<<3)|5 = 405
        encode_varint(&mut buf, 405);
        buf.extend_from_slice(&[0u8; 4]);
        // tag 4 wire 2 (namespace)
        encode_varint(&mut buf, 34);
        encode_varint(&mut buf, 3);
        buf.extend_from_slice(b"urn");

        let decoded = CastMessage::decode(&buf).expect("decode");
        assert_eq!(decoded.namespace, "urn");
    }

    #[test]
    fn decode_truncated_fixed64_errors() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 801); // tag 100 fixed64
        buf.extend_from_slice(&[0u8; 4]); // only 4 bytes instead of 8
        assert!(CastMessage::decode(&buf).is_err());
    }

    #[test]
    fn decode_varint_truncated_errors() {
        // A lone 0x80 byte (continuation bit set) with nothing following
        // must not loop forever or panic.
        assert!(CastMessage::decode(&[0x80]).is_err());
    }

    #[test]
    fn extract_url_prefers_content_url() {
        let p = serde_json::json!({
            "media": {
                "contentUrl": "http://a",
                "contentId": "http://b",
                "entity": "http://c",
            }
        });
        assert_eq!(extract_url_from_load(&p).as_deref(), Some("http://a"));
    }

    #[test]
    fn extract_url_falls_back_through_content_id_and_entity() {
        let p = serde_json::json!({
            "media": {
                "contentId": "http://b",
                "entity": "http://c",
            }
        });
        assert_eq!(extract_url_from_load(&p).as_deref(), Some("http://b"));

        let p = serde_json::json!({
            "media": { "entity": "http://c" }
        });
        assert_eq!(extract_url_from_load(&p).as_deref(), Some("http://c"));
    }

    #[test]
    fn extract_url_empty_values_skipped() {
        let p = serde_json::json!({
            "media": {
                "contentUrl": "",
                "contentId": "http://b",
            }
        });
        assert_eq!(extract_url_from_load(&p).as_deref(), Some("http://b"));
    }

    #[test]
    fn extract_url_missing_returns_none() {
        let p = serde_json::json!({"media": {}});
        assert_eq!(extract_url_from_load(&p), None);
    }
}
