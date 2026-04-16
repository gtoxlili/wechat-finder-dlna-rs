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
    pub fn encode(&self, buf: &mut Vec<u8>) {
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
                (_, 0) => { let (_, p) = decode_varint(data, pos)?; pos = p; } // skip unknown varint
                (_, 2) => { let (_, p) = decode_bytes(data, pos)?; pos = p; } // skip unknown len-delimited
                _ => { anyhow::bail!("unsupported wire type {wire_type} for tag {tag}"); }
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
    encode_varint(buf, ((field as u64) << 3) | 0); // wire type 0
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
        // Generate self-signed TLS certificate
        let tls_acceptor = build_tls_acceptor()?;

        // Start TCP listener
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .with_context(|| format!("Failed to bind Cast TLS server on port {}", self.port))?;
        info!(
            "Cast receiver '{}' listening on {}:{}",
            self.friendly_name, self.local_ip, self.port
        );

        // Advertise via mDNS
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

        let service_name = format!("{}", device_id);
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
        // Read 4-byte big-endian length prefix
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
                let resp = build_message(
                    "receiver-0",
                    &msg.source_id,
                    NS_CONNECTION,
                    json!({"type": "CONNECTED"}),
                );
                vec![resp]
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
                    "GET_STATUS" | "LAUNCH" => {
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
                        // Extract URL from media object
                        let url = extract_url_from_load(&payload);
                        if let Some(ref u) = url {
                            info!("Cast: received media URL: {}", u);
                            let _ = url_tx.send(Some(u.clone()));
                        }
                        let resp = build_message(
                            "receiver-0",
                            &msg.source_id,
                            NS_MEDIA,
                            media_status_payload(request_id, "IDLE", "FINISHED"),
                        );
                        vec![resp]
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
    // Try media.contentUrl first, then media.contentId
    let media = payload.get("media")?;

    if let Some(url) = media.get("contentUrl").and_then(|v| v.as_str()) {
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }

    if let Some(id) = media.get("contentId").and_then(|v| v.as_str()) {
        if !id.is_empty() {
            return Some(id.to_string());
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
        payload_utf8: Some(serde_json::to_string(&payload).unwrap()),
        payload_binary: None,
    }
}

async fn write_cast_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &CastMessage,
) -> Result<()> {
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    let len = buf.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&buf).await?;
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
    json!({
        "type": "MEDIA_STATUS",
        "requestId": request_id,
        "status": [
            {
                "mediaSessionId": 1,
                "playbackRate": 1,
                "playerState": player_state,
                "idleReason": idle_reason,
                "currentTime": 0,
                "supportedMediaCommands": 15,
                "volume": {
                    "level": 1.0,
                    "muted": false
                }
            }
        ]
    })
}

fn rand_hex_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234567890ABCDEF)
}
