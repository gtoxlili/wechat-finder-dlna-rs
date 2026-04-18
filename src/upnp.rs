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

fn html_unescape(s: &str) -> String {
    html_escape::decode_html_entities(s).into_owned()
}

/// Extract the text content of the first `<tag ...>…</tag>`.
/// Handles tags with or without attributes (e.g. `<CurrentURI xmlns="...">`)
/// to match the Python regex `<CurrentURI[^>]*>(.*?)</CurrentURI>`.
///
/// A naïve `body.find("<CurrentURI")` would also match `<CurrentURIMetaData`
/// as a prefix; SOAP arguments can appear in any order, so if
/// CurrentURIMetaData precedes CurrentURI in the payload we'd end up
/// parsing the metadata blob as the URL. Scan for the literal prefix
/// and confirm the character immediately after is `>` or whitespace,
/// which only matches the real tag open.
fn extract_tag<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open_prefix = format!("<{tag}");
    let close = format!("</{tag}>");

    let bytes = body.as_bytes();
    let mut search_from = 0;
    let tag_start = loop {
        let rel = body[search_from..].find(&open_prefix)?;
        let abs = search_from + rel;
        match bytes.get(abs + open_prefix.len()) {
            Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
            | Some(b'/') => break abs,
            _ => search_from = abs + open_prefix.len(),
        }
    };

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

const NOTIFY_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
  <e:property>
    <LastChange>&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/AVT/&quot;&gt;&lt;InstanceID val=&quot;0&quot;&gt;&lt;TransportState val=&quot;PLAYING&quot;/&gt;&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange>
  </e:property>
</e:propertyset>"#;

/// Send a UPnP NOTIFY event to a single callback URL using a raw TCP write.
/// The callback URL looks like `http://192.168.1.x:PORT/path`.
async fn send_notify(callback_url: &str, sid: &str) {
    use std::time::Duration;

    // Bound the entire exchange — a subscriber that ignored UNSUBSCRIBE
    // or got partitioned will otherwise block this task for ~75s on
    // OS-level TCP timeout, delaying shutdown of the whole receiver.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
    const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

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
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("NOTIFY: connect to {addr} failed: {e}");
            return;
        }
        Err(_) => {
            warn!("NOTIFY: connect to {addr} timed out");
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
    match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(request.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("NOTIFY: write to {addr} failed: {e}"),
        Err(_) => warn!("NOTIFY: write to {addr} timed out"),
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

pub struct UpnpServer {
    url_tx: watch::Sender<Option<String>>,
    /// Pre-rendered device.xml — friendly_name and uuid are immutable
    /// for the lifetime of the server, so we format! once and clone
    /// Bytes on each GET instead of re-rendering per request.
    device_xml: Bytes,
}

impl UpnpServer {
    pub fn new(
        device_uuid: String,
        friendly_name: String,
        url_tx: watch::Sender<Option<String>>,
    ) -> Self {
        let device_xml = Bytes::from(descriptors::device_xml(&friendly_name, &device_uuid));
        Self { url_tx, device_xml }
    }

    pub async fn run(
        self: Arc<Self>,
        port: u16,
        mut stop_rx: watch::Receiver<()>,
    ) -> anyhow::Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = TcpListener::bind(addr).await?;
        info!("UPnP HTTP server listening on {addr}");

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

fn handle_get(path: &str, server: &UpnpServer) -> Response<Full<Bytes>> {
    match path {
        "/device.xml" => xml_response(StatusCode::OK, server.device_xml.clone()),
        // SCPDs are static for the lifetime of the binary — serve directly
        // from their &'static str without copying into a heap Bytes.
        "/AVTransport/scpd.xml" => {
            xml_response(StatusCode::OK, Bytes::from_static(descriptors::AVTRANSPORT_SCPD.as_bytes()))
        }
        "/RenderingControl/scpd.xml" => {
            xml_response(StatusCode::OK, Bytes::from_static(descriptors::RENDERING_SCPD.as_bytes()))
        }
        "/ConnectionManager/scpd.xml" => {
            xml_response(StatusCode::OK, Bytes::from_static(descriptors::CONNMGR_SCPD.as_bytes()))
        }
        _ => text_response(StatusCode::NOT_FOUND, "Not Found"),
    }
}

async fn handle_post(
    req: Request<Incoming>,
    path: &str,
    server: &Arc<UpnpServer>,
    subscribers: &Arc<Mutex<HashMap<String, String>>>,
    captured: &Arc<AtomicBool>,
) -> Response<Full<Bytes>> {
    let service = if path.contains("AVTransport") {
        "AVTransport"
    } else if path.contains("RenderingControl") {
        "RenderingControl"
    } else if path.contains("ConnectionManager") {
        "ConnectionManager"
    } else {
        return text_response(StatusCode::NOT_FOUND, "Not Found");
    };

    let soap_action = req
        .headers()
        .get("soapaction")
        .or_else(|| req.headers().get("SOAPAction"))
        .and_then(|v| v.to_str().ok())
        .map(soap_action_name)
        .unwrap_or("")
        .to_owned();

    debug!("SOAP action: {soap_action} on {service}");

    use http_body_util::BodyExt;
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "Bad Request"),
    };
    let body_str = String::from_utf8_lossy(&body_bytes).into_owned();

    match soap_action.as_str() {
        "SetAVTransportURI" | "SetNextAVTransportURI" => {
            let raw_url = extract_tag(&body_str, "CurrentURI")
                .or_else(|| extract_tag(&body_str, "NextURI"))
                .map(html_unescape)
                .unwrap_or_default();

            if !raw_url.is_empty() {
                info!("{soap_action}: captured URL = {raw_url}");
                captured.store(true, Ordering::SeqCst);
                let _ = server.url_tx.send(Some(raw_url));

                // Push a TransportState=PLAYING NOTIFY to any subscribed
                // control point so UIs driven by eventing (rather than
                // polling) move to "playing" alongside the ones that
                // poll GetTransportInfo. Fire promptly (not after 3s)
                // because the capture-linger window is bounded.
                let subs_clone = Arc::clone(subscribers);
                tokio::spawn(async move {
                    notify_all(&subs_clone).await;
                });
            }

            let xml = descriptors::soap_response(&soap_action, service, "");
            xml_response(StatusCode::OK, xml)
        }

        "GetTransportInfo" => {
            // Before SetAVTransportURI → NO_MEDIA_PRESENT so senders
            // don't skip the Play step (they typically gate Play on
            // state ∈ {STOPPED, NO_MEDIA_PRESENT}). After capture →
            // PLAYING so the sender's casting UI stays stable during
            // the post-capture linger. Reporting STOPPED here would
            // cue the user's phone to show "cast failed" and tempt
            // retaps.
            let state = if captured.load(Ordering::SeqCst) {
                "PLAYING"
            } else {
                "NO_MEDIA_PRESENT"
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

        "GetMediaInfo" => {
            let body = "<NrTracks>0</NrTracks>\
                        <MediaDuration>00:00:00</MediaDuration>\
                        <CurrentURI/>\
                        <CurrentURIMetaData/>\
                        <NextURI/>\
                        <NextURIMetaData/>\
                        <PlayMedium>NETWORK</PlayMedium>\
                        <RecordMedium>NOT_IMPLEMENTED</RecordMedium>\
                        <WriteStatus>NOT_IMPLEMENTED</WriteStatus>";
            let xml = descriptors::soap_response("GetMediaInfo", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetDeviceCapabilities" => {
            let body = "<PlayMedia>NETWORK,HDD</PlayMedia>\
                        <RecMedia>NOT_IMPLEMENTED</RecMedia>\
                        <RecQualityModes>NOT_IMPLEMENTED</RecQualityModes>";
            let xml = descriptors::soap_response("GetDeviceCapabilities", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetTransportSettings" => {
            let body = "<PlayMode>NORMAL</PlayMode>\
                        <RecQualityMode>NOT_IMPLEMENTED</RecQualityMode>";
            let xml = descriptors::soap_response("GetTransportSettings", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetVolume" => {
            let body = "<CurrentVolume>50</CurrentVolume>";
            let xml = descriptors::soap_response("GetVolume", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetMute" => {
            let body = "<CurrentMute>0</CurrentMute>";
            let xml = descriptors::soap_response("GetMute", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetCurrentConnectionIDs" => {
            let body = "<ConnectionIDs>0</ConnectionIDs>";
            let xml = descriptors::soap_response("GetCurrentConnectionIDs", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetCurrentConnectionInfo" => {
            let body = "<RcsID>0</RcsID>\
                        <AVTransportID>0</AVTransportID>\
                        <ProtocolInfo></ProtocolInfo>\
                        <PeerConnectionManager></PeerConnectionManager>\
                        <PeerConnectionID>-1</PeerConnectionID>\
                        <Direction>Input</Direction>\
                        <Status>OK</Status>";
            let xml = descriptors::soap_response("GetCurrentConnectionInfo", service, body);
            xml_response(StatusCode::OK, xml)
        }

        "GetProtocolInfo" => {
            let body = "<Source></Source>\
                        <Sink>\
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

        "Play" | "Stop" | "Pause" | "Next" | "Previous" | "Seek"
        | "SetPlayMode" | "SetVolume" | "SetMute" => {
            let xml = descriptors::soap_response(&soap_action, service, "");
            xml_response(StatusCode::OK, xml)
        }

        _ => {
            // Generic 200 OK with empty response envelope. Some Chinese
            // controllers (Tencent/iQiyi/MiBox) send vendor extensions
            // that a strict renderer would 500 on, but a permissive 200
            // keeps the casting flow alive.
            let xml = descriptors::soap_response(&soap_action, service, "");
            xml_response(StatusCode::OK, xml)
        }
    }
}

async fn handle_subscribe(
    req: Request<Incoming>,
    path: &str,
    subscribers: &Arc<Mutex<HashMap<String, String>>>,
) -> Response<Full<Bytes>> {
    let callback_raw = req
        .headers()
        .get("callback")
        .or_else(|| req.headers().get("CALLBACK"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

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

#[cfg(test)]
mod tests {
    use super::*;

    const WECHAT_SOAP_BODY: &str = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
 <s:Body>
  <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
   <InstanceID>0</InstanceID>
   <CurrentURI>http://example.com/live.m3u8?token=abc</CurrentURI>
   <CurrentURIMetaData>&lt;DIDL-Lite...&gt;</CurrentURIMetaData>
  </u:SetAVTransportURI>
 </s:Body>
</s:Envelope>"#;

    /// Real-world-ish payload where the metadata tag appears BEFORE the
    /// URI. Some iQiyi/QQ SOAP builders emit fields in arbitrary order.
    const REVERSED_SOAP_BODY: &str = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
 <s:Body>
  <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
   <InstanceID>0</InstanceID>
   <CurrentURIMetaData>&lt;DIDL-Lite...&gt;</CurrentURIMetaData>
   <CurrentURI>http://example.com/reversed.mp4</CurrentURI>
  </u:SetAVTransportURI>
 </s:Body>
</s:Envelope>"#;

    #[test]
    fn extract_tag_ordered() {
        assert_eq!(
            extract_tag(WECHAT_SOAP_BODY, "CurrentURI"),
            Some("http://example.com/live.m3u8?token=abc")
        );
    }

    #[test]
    fn extract_tag_reversed_order() {
        // Before the prefix-match fix, this would return a truncated
        // snippet of the CurrentURIMetaData body because `<CurrentURI`
        // is a prefix of `<CurrentURIMetaData`.
        assert_eq!(
            extract_tag(REVERSED_SOAP_BODY, "CurrentURI"),
            Some("http://example.com/reversed.mp4")
        );
    }

    #[test]
    fn extract_tag_with_attributes() {
        let body = r#"<root><CurrentURI xmlns="urn:foo">http://x/y</CurrentURI></root>"#;
        assert_eq!(extract_tag(body, "CurrentURI"), Some("http://x/y"));
    }

    #[test]
    fn extract_tag_self_closing_not_treated_as_container() {
        // Self-closing tag <CurrentURI/> has no inner content; the
        // parser should return None rather than a random slice.
        let body = r#"<root><CurrentURI/></root>"#;
        assert_eq!(extract_tag(body, "CurrentURI"), None);
    }

    #[test]
    fn extract_tag_missing_returns_none() {
        let body = r#"<root><SomeOtherField>x</SomeOtherField></root>"#;
        assert_eq!(extract_tag(body, "CurrentURI"), None);
    }

    #[test]
    fn soap_action_name_strips_service_prefix() {
        assert_eq!(
            soap_action_name("\"urn:schemas-upnp-org:service:AVTransport:1#Play\""),
            "Play"
        );
        assert_eq!(
            soap_action_name("urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"),
            "SetAVTransportURI"
        );
        assert_eq!(soap_action_name(""), "");
    }
}
