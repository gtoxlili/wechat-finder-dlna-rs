use crate::descriptors;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use tracing::{debug, info, warn};

// ─── helpers ──────────────────────────────────────────────────────────────────

fn html_unescape(s: &str) -> String {
    html_escape::decode_html_entities(s).into_owned()
}

/// Extract the text content of the first `<tag ...>…</tag>`.
/// Handles tags with or without attributes (e.g. `<CurrentURI xmlns="...">`)
/// to match the Python regex `<CurrentURI[^>]*>(.*?)</CurrentURI>`.
fn extract_tag<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open_prefix = format!("<{tag}");
    let close = format!("</{tag}>");
    let tag_start = body.find(&open_prefix)?;
    let after_tag = &body[tag_start + open_prefix.len()..];
    // Find the closing '>' of the opening tag
    let gt = after_tag.find('>')?;
    let content_start = tag_start + open_prefix.len() + gt + 1;
    let end = body[content_start..].find(&close)? + content_start;
    Some(&body[content_start..end])
}

/// Extract the SOAP action name from the SOAPAction header value.
/// e.g. `"urn:schemas-upnp-org:service:AVTransport:1#Play"` → `"Play"`
fn soap_action_name(header_val: &str) -> &str {
    header_val
        .trim_matches('"')
        .rsplit('#')
        .next()
        .unwrap_or("")
}

fn text_response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(body.into()))
        .unwrap()
}

fn xml_response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/xml; charset=utf-8")
        .body(Full::new(body.into()))
        .unwrap()
}

// ─── NOTIFY sender ────────────────────────────────────────────────────────────

const NOTIFY_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
  <e:property>
    <LastChange>&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/AVT/&quot;&gt;&lt;InstanceID val=&quot;0&quot;&gt;&lt;TransportState val=&quot;STOPPED&quot;/&gt;&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange>
  </e:property>
</e:propertyset>"#;

/// Send a UPnP NOTIFY event to a single callback URL using a raw TCP write.
/// The callback URL looks like `http://192.168.1.x:PORT/path`.
async fn send_notify(callback_url: &str, sid: &str) {
    // Parse the callback URL manually – we only need host, port, path.
    let url = callback_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    let (host_port, path) = if let Some(idx) = url.find('/') {
        (&url[..idx], &url[idx..])
    } else {
        (url, "/")
    };

    let (host, port_str) = if let Some(idx) = host_port.rfind(':') {
        (&host_port[..idx], &host_port[idx + 1..])
    } else {
        (host_port, "80")
    };

    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => {
            warn!("NOTIFY: invalid port in callback URL {callback_url}");
            return;
        }
    };

    let addr = format!("{host}:{port}");
    let stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("NOTIFY: connect to {addr} failed: {e}");
            return;
        }
    };

    let body_len = NOTIFY_BODY.len();
    let request = format!(
        "NOTIFY {path} HTTP/1.1\r\n\
         HOST: {host}:{port}\r\n\
         CONTENT-TYPE: text/xml; charset=utf-8\r\n\
         NT: upnp:event\r\n\
         NTS: upnp:propchange\r\n\
         SID: {sid}\r\n\
         SEQ: 0\r\n\
         CONTENT-LENGTH: {body_len}\r\n\
         \r\n\
         {NOTIFY_BODY}"
    );

    use tokio::io::AsyncWriteExt;
    let mut stream = stream;
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        warn!("NOTIFY: write to {addr} failed: {e}");
    }
}

/// Send NOTIFY to all current subscribers (clones the map snapshot first).
async fn notify_all(subscribers: &Arc<Mutex<HashMap<String, String>>>) {
    let snapshot: Vec<(String, String)> = {
        let guard = subscribers.lock().await;
        guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };
    for (sid, cb) in snapshot {
        debug!("Sending NOTIFY to {cb} (SID={sid})");
        send_notify(&cb, &sid).await;
    }
}

// ─── server state ─────────────────────────────────────────────────────────────

pub struct UpnpServer {
    device_uuid: String,
    friendly_name: String,
    url_tx: watch::Sender<Option<String>>,
}

impl UpnpServer {
    pub fn new(
        device_uuid: String,
        friendly_name: String,
        url_tx: watch::Sender<Option<String>>,
    ) -> Self {
        Self {
            device_uuid,
            friendly_name,
            url_tx,
        }
    }

    pub async fn run(
        self: Arc<Self>,
        port: u16,
        mut stop_rx: watch::Receiver<()>,
    ) -> anyhow::Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = TcpListener::bind(addr).await?;
        info!("UPnP HTTP server listening on {addr}");

        // Shared state
        let subscribers: Arc<Mutex<HashMap<String, String>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let captured: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, peer) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("UPnP accept error: {e}");
                            continue;
                        }
                    };
                    debug!("UPnP connection from {peer}");

                    let server = Arc::clone(&self);
                    let subs = Arc::clone(&subscribers);
                    let cap = Arc::clone(&captured);

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req| {
                            handle_request(
                                req,
                                Arc::clone(&server),
                                Arc::clone(&subs),
                                Arc::clone(&cap),
                            )
                        });
                        if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                            debug!("UPnP connection error: {e}");
                        }
                    });
                }
                _ = stop_rx.changed() => {
                    info!("UPnP server stopping");
                    break;
                }
            }
        }
        Ok(())
    }
}

// ─── request handler ──────────────────────────────────────────────────────────

async fn handle_request(
    req: Request<Incoming>,
    server: Arc<UpnpServer>,
    subscribers: Arc<Mutex<HashMap<String, String>>>,
    captured: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    debug!("{method} {path}");

    let response = match method {
        Method::GET => handle_get(&path, &server),
        ref m if m.as_str() == "POST" => {
            handle_post(req, &path, &server, &subscribers, &captured).await
        }
        ref m if m.as_str() == "SUBSCRIBE" => {
            handle_subscribe(req, &path, &subscribers).await
        }
        ref m if m.as_str() == "UNSUBSCRIBE" => {
            handle_unsubscribe(req, &subscribers).await
        }
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"),
    };

    Ok(response)
}

// ─── GET ──────────────────────────────────────────────────────────────────────

fn handle_get(path: &str, server: &UpnpServer) -> Response<Full<Bytes>> {
    match path {
        "/device.xml" => {
            let xml = descriptors::device_xml(&server.friendly_name, &server.device_uuid);
            xml_response(StatusCode::OK, xml)
        }
        "/AVTransport/scpd.xml" => {
            xml_response(StatusCode::OK, descriptors::AVTRANSPORT_SCPD)
        }
        "/RenderingControl/scpd.xml" => {
            xml_response(StatusCode::OK, descriptors::RENDERING_SCPD)
        }
        "/ConnectionManager/scpd.xml" => {
            xml_response(StatusCode::OK, descriptors::CONNMGR_SCPD)
        }
        _ => text_response(StatusCode::NOT_FOUND, "Not Found"),
    }
}

// ─── POST / SOAP ──────────────────────────────────────────────────────────────

async fn handle_post(
    req: Request<Incoming>,
    path: &str,
    server: &Arc<UpnpServer>,
    subscribers: &Arc<Mutex<HashMap<String, String>>>,
    captured: &Arc<AtomicBool>,
) -> Response<Full<Bytes>> {
    // Determine service from path
    let service = if path.contains("AVTransport") {
        "AVTransport"
    } else if path.contains("RenderingControl") {
        "RenderingControl"
    } else if path.contains("ConnectionManager") {
        "ConnectionManager"
    } else {
        return text_response(StatusCode::NOT_FOUND, "Not Found");
    };

    // Extract SOAPAction header
    let soap_action = req
        .headers()
        .get("soapaction")
        .or_else(|| req.headers().get("SOAPAction"))
        .and_then(|v| v.to_str().ok())
        .map(soap_action_name)
        .unwrap_or("")
        .to_owned();

    debug!("SOAP action: {soap_action} on {service}");

    // Read body
    use http_body_util::BodyExt;
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "Bad Request"),
    };
    let body_str = String::from_utf8_lossy(&body_bytes).into_owned();

    match soap_action.as_str() {
        "SetAVTransportURI" => {
            // Extract URL from body
            let raw_url = extract_tag(&body_str, "CurrentURI")
                .map(html_unescape)
                .unwrap_or_default();

            info!("SetAVTransportURI: captured URL = {raw_url}");

            // Mark as captured and send URL
            captured.store(true, Ordering::SeqCst);
            let _ = server.url_tx.send(Some(raw_url));

            // After 3 s, notify all subscribers with STOPPED state
            let subs_clone = Arc::clone(subscribers);
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                notify_all(&subs_clone).await;
            });

            let xml = descriptors::soap_response("SetAVTransportURI", service, "");
            xml_response(StatusCode::OK, xml)
        }

        "GetTransportInfo" => {
            let state = if captured.load(Ordering::SeqCst) {
                "STOPPED"
            } else {
                "PLAYING"
            };
            let body = format!(
                "<CurrentTransportState>{state}</CurrentTransportState>\
                 <CurrentTransportStatus>OK</CurrentTransportStatus>\
                 <CurrentSpeed>1</CurrentSpeed>"
            );
            let xml = descriptors::soap_response("GetTransportInfo", service, &body);
            xml_response(StatusCode::OK, xml)
        }

        "GetPositionInfo" => {
            let body = "<Track>1</Track>\
                        <TrackDuration>00:00:00</TrackDuration>\
                        <TrackMetaData/>\
                        <TrackURI/>\
                        <RelTime>00:00:00</RelTime>\
                        <AbsTime>00:00:00</AbsTime>\
                        <RelCount>0</RelCount>\
                        <AbsCount>0</AbsCount>";
            let xml = descriptors::soap_response("GetPositionInfo", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetVolume" => {
            let body = "<CurrentVolume>50</CurrentVolume>";
            let xml = descriptors::soap_response("GetVolume", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetProtocolInfo" => {
            let body = "<Source/><Sink>\
                        http-get:*:video/mp4:*,\
                        http-get:*:video/x-matroska:*,\
                        http-get:*:video/x-msvideo:*,\
                        http-get:*:video/x-flv:*,\
                        http-get:*:video/x-ms-wmv:*,\
                        http-get:*:video/mpeg:*,\
                        http-get:*:video/webm:*,\
                        http-get:*:video/3gpp:*,\
                        http-get:*:video/quicktime:*,\
                        http-get:*:video/m3u8:*,\
                        http-get:*:application/vnd.apple.mpegurl:*,\
                        http-get:*:application/x-mpegURL:*,\
                        http-get:*:audio/mpeg:*,\
                        http-get:*:audio/mp4:*,\
                        http-get:*:audio/x-ms-wma:*,\
                        http-get:*:audio/flac:*,\
                        http-get:*:audio/ogg:*,\
                        http-get:*:audio/wav:*\
                        </Sink>";
            let xml = descriptors::soap_response("GetProtocolInfo", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "Play" | "Stop" | "Pause" => {
            let xml = descriptors::soap_response(&soap_action, service, "");
            xml_response(StatusCode::OK, xml)
        }

        _ => {
            // Python always returns 200 for any SOAP action, even unknown ones.
            // Some DLNA clients send proprietary actions and expect 200 OK.
            let xml = descriptors::soap_response(&soap_action, service, "");
            xml_response(StatusCode::OK, xml)
        }
    }
}

// ─── SUBSCRIBE ────────────────────────────────────────────────────────────────

async fn handle_subscribe(
    req: Request<Incoming>,
    path: &str,
    subscribers: &Arc<Mutex<HashMap<String, String>>>,
) -> Response<Full<Bytes>> {
    // CALLBACK header: <http://192.168.1.x:PORT/path>
    let callback_raw = req
        .headers()
        .get("callback")
        .or_else(|| req.headers().get("CALLBACK"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // Extract URL from angle brackets
    let callback_url = callback_raw
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_owned();

    if callback_url.is_empty() {
        return text_response(StatusCode::BAD_REQUEST, "Missing CALLBACK header");
    }

    let sid = format!("uuid:{}", uuid::Uuid::new_v4());
    info!("SUBSCRIBE from {callback_url}, SID={sid}");

    // Only store AVTransport subscribers (matching Python/Macast behavior)
    if path.contains("AVTransport") {
        subscribers
            .lock()
            .await
            .insert(sid.clone(), callback_url.clone());

        // UPnP spec: send initial event with current state on new subscription
        let init_sid = sid.clone();
        tokio::spawn(async move {
            send_notify(&callback_url, &init_sid).await;
        });
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("SID", &sid)
        .header("TIMEOUT", "Second-1800")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

// ─── UNSUBSCRIBE ──────────────────────────────────────────────────────────────

async fn handle_unsubscribe(
    req: Request<Incoming>,
    subscribers: &Arc<Mutex<HashMap<String, String>>>,
) -> Response<Full<Bytes>> {
    let sid = req
        .headers()
        .get("sid")
        .or_else(|| req.headers().get("SID"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    if sid.is_empty() {
        return text_response(StatusCode::BAD_REQUEST, "Missing SID header");
    }

    let removed = subscribers.lock().await.remove(&sid).is_some();
    info!("UNSUBSCRIBE SID={sid} removed={removed}");

    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
