//! # wechat-finder-dlna
//!
//! Capture WeChat Video Channel (视频号) live stream URLs via fake screen casting.
//!
//! Pretends to be a TV on your local network. When you cast a video to it,
//! the real stream URL (m3u8/mp4) is captured.
//!
//! Supports: **DLNA/UPnP**, **AirPlay 2**, **Google Cast (Chromecast)**.
//!
//! ## Library usage
//!
//! ```rust,no_run
//! use wechat_finder_dlna::{capture, CaptureOptions, Protocol};
//!
//! #[tokio::main]
//! async fn main() {
//!     let url = capture(CaptureOptions::default()).await.unwrap();
//!     println!("Captured: {url}");
//! }
//! ```

pub mod airplay;
pub mod audio_capture;
pub mod cast;
pub mod descriptors;
pub mod net;
pub mod pairing;
pub mod ssdp;
pub mod upnp;

use std::sync::Arc;
use tokio::sync::watch;
use tracing::warn;

/// Supported casting protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Dlna,
    AirPlay,
    Cast,
}

impl Protocol {
    pub const ALL: &[Protocol] = &[Protocol::Dlna, Protocol::AirPlay, Protocol::Cast];
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Dlna => write!(f, "DLNA"),
            Protocol::AirPlay => write!(f, "AirPlay"),
            Protocol::Cast => write!(f, "Cast"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dlna" => Ok(Protocol::Dlna),
            "airplay" => Ok(Protocol::AirPlay),
            "cast" => Ok(Protocol::Cast),
            _ => Err(format!("unknown protocol: {s}")),
        }
    }
}

/// Options for the [`capture`] function.
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// Device name shown in the cast list.
    pub name: String,
    /// Base HTTP port. DLNA uses `port`, AirPlay uses `port + 1`, Cast uses 8009.
    pub port: u16,
    /// Which protocols to enable. Defaults to all.
    pub protocols: Vec<Protocol>,
    /// Bind to a specific network interface (e.g. "en1") or IP address.
    /// If None, auto-detected via [`net::get_lan_ip`].
    pub bind: Option<String>,
    /// Optional path for AirPlay audio recording.
    pub audio_output: Option<String>,
    /// Optional recording duration in seconds.
    pub audio_duration: Option<f64>,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            name: "MAGI".into(),
            port: 9090,
            protocols: Protocol::ALL.to_vec(),
            bind: None,
            audio_output: None,
            audio_duration: None,
        }
    }
}

/// Start fake casting receivers and wait until a URL is captured.
///
/// Returns the captured stream/video URL.
pub async fn capture(opts: CaptureOptions) -> anyhow::Result<String> {
    let local_ip = match opts.bind {
        Some(ref val) => net::resolve_bind(val)?,
        None => net::get_lan_ip()?,
    };
    let dev_uuid = format!("uuid:{}", uuid::Uuid::new_v4());

    let (url_tx, mut url_rx) = watch::channel::<Option<String>>(None);
    let url_tx = Arc::new(url_tx);

    let (stop_tx, stop_rx) = watch::channel(());

    let mut started: Vec<Protocol> = Vec::new();
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if opts.protocols.contains(&Protocol::Dlna) {
        let port = opts.port;
        let location = format!("http://{}:{}/device.xml", local_ip, port);
        let server = Arc::new(upnp::UpnpServer::new(
            dev_uuid.clone(),
            opts.name.clone(),
            (*url_tx).clone(),
        ));
        let ssdp_adv = ssdp::SsdpAdvertiser::new(
            dev_uuid.clone(),
            location,
            local_ip.clone(),
        );

        let stop1 = stop_rx.clone();
        let stop2 = stop_rx.clone();

        handles.push(tokio::spawn(async move {
            if let Err(e) = server.run(port, stop1).await {
                warn!("DLNA server error: {e}");
            }
        }));
        handles.push(tokio::spawn(async move {
            if let Err(e) = ssdp_adv.run(stop2).await {
                warn!("SSDP error: {e}");
            }
        }));

        started.push(Protocol::Dlna);
        eprintln!("  📺 DLNA    \"{}\" on {}:{}", opts.name, local_ip, port);
    }

    if opts.protocols.contains(&Protocol::AirPlay) {
        let airplay_port = if opts.protocols.contains(&Protocol::Dlna) {
            opts.port + 1
        } else {
            opts.port
        };

        let recv = airplay::AirPlayReceiver::new(
            opts.name.clone(),
            local_ip.clone(),
            airplay_port,
            url_tx.clone(),
            opts.audio_output.clone(),
            opts.audio_duration,
        );
        let stop = stop_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = recv.run(stop).await {
                warn!("AirPlay error: {e}");
            }
        }));

        started.push(Protocol::AirPlay);
        eprintln!("  🍎 AirPlay \"{}\" on {}:{}", opts.name, local_ip, airplay_port);
    }

    if opts.protocols.contains(&Protocol::Cast) {
        let cast_port: u16 = 8009;
        let recv = cast::CastReceiver::new(
            opts.name.clone(),
            local_ip.clone(),
            cast_port,
            url_tx.clone(),
        );
        let stop = stop_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = recv.run(stop).await {
                warn!("Cast error: {e}");
            }
        }));

        started.push(Protocol::Cast);
        eprintln!("  📡 Cast    \"{}\" on {}:{}", opts.name, local_ip, cast_port);
    }

    if started.is_empty() {
        anyhow::bail!("No protocols started");
    }

    let enabled: Vec<_> = started.iter().map(|p| p.to_string()).collect();
    eprintln!("\n  Protocols: {}", enabled.join(", "));
    eprintln!("  Open your app > cast > select \"{}\"\n", opts.name);

    let result = loop {
        url_rx.changed().await?;
        if let Some(url) = url_rx.borrow().clone() {
            break url;
        }
    };

    drop(stop_tx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for h in handles {
        h.abort();
    }

    Ok(result)
}
