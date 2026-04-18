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
    /// How long to keep the protocol handlers running after a URL has
    /// been captured, while continuing to respond with "playing" state
    /// to the sender. Without this, the sender's phone UI flips to
    /// "cast failed" the instant the process tears down, which users
    /// read as "try again" and retap the cast button repeatedly. A
    /// few seconds of feigned-playback buys the psychological
    /// "cast succeeded" verdict before we disappear.
    ///
    /// Default: 3 seconds. Set to 0 to disable (immediate shutdown).
    pub post_capture_linger: std::time::Duration,
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
            post_capture_linger: std::time::Duration::from_secs(3),
        }
    }
}

/// Start fake casting receivers and wait until a URL is captured.
///
/// Returns the captured stream/video URL.
pub async fn capture(opts: CaptureOptions) -> anyhow::Result<String> {
    // Primary IP used for mDNS advertisement (AirPlay/Cast) and the
    // banner messages. When `bind` is None we also pick up every other
    // private IPv4 and spin up an additional SSDP advertiser per
    // interface so DLNA works across VLANs/wifi/ethernet seams.
    let (local_ip, ssdp_ips) = match opts.bind {
        Some(ref val) => {
            let ip = net::resolve_bind(val)?;
            (ip.clone(), vec![ip])
        }
        None => {
            let all = net::all_lan_ipv4()?;
            let primary = all[0].clone();
            (primary, all)
        }
    };
    let dev_uuid = format!("uuid:{}", uuid::Uuid::new_v4());

    let (url_tx, mut url_rx) = watch::channel::<Option<String>>(None);
    let url_tx = Arc::new(url_tx);

    let (stop_tx, stop_rx) = watch::channel(());

    let mut started: Vec<Protocol> = Vec::new();
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if opts.protocols.contains(&Protocol::Dlna) {
        let port = opts.port;
        let server = Arc::new(upnp::UpnpServer::new(
            dev_uuid.clone(),
            opts.name.clone(),
            (*url_tx).clone(),
        ));

        let stop_srv = stop_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = server.run(port, stop_srv).await {
                // Bind failures (port already in use) and similar fatal
                // startup errors need to be visible without --verbose,
                // otherwise the user sees the banner but wonders why
                // no device shows up in their cast picker.
                eprintln!("  ⚠️ DLNA server error: {e}");
            }
        }));

        // One SSDP advertiser per usable interface. Each uses its own
        // LOCATION URL so controllers see a reachable address for the
        // subnet they queried from. They share the stop channel and
        // all publish the same device_uuid.
        for ip in &ssdp_ips {
            let location = format!("http://{}:{}/device.xml", ip, port);
            let ssdp_adv = ssdp::SsdpAdvertiser::new(
                dev_uuid.clone(),
                location,
                ip.clone(),
            );
            let stop = stop_rx.clone();
            let ip_log = ip.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = ssdp_adv.run(stop).await {
                    eprintln!("  ⚠️ SSDP error on {ip_log}: {e}");
                }
            }));
        }

        started.push(Protocol::Dlna);
        if ssdp_ips.len() > 1 {
            eprintln!(
                "  📺 DLNA    \"{}\" on {}:{} (advertising on {} interfaces)",
                opts.name,
                local_ip,
                port,
                ssdp_ips.len()
            );
        } else {
            eprintln!("  📺 DLNA    \"{}\" on {}:{}", opts.name, local_ip, port);
        }
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
                eprintln!("  ⚠️ AirPlay error: {e}");
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
                eprintln!("  ⚠️ Cast error: {e}");
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

    // Post-capture linger: keep every protocol handler alive so the
    // sender's phone UI keeps seeing a healthy "playing on TV" status
    // (GetTransportInfo=PLAYING, /playback-info rate=1.0,
    // Cast MEDIA_STATUS=PLAYING). Without this, the sender sees an
    // abrupt RST and the UI flips to "cast failed" — which users
    // interpret as a transient network issue and retap the cast
    // button repeatedly, spawning new captures after we've already
    // exited.
    //
    // 3s default is enough for iOS/Android cast UIs to settle into
    // their "playing" affordance; after that the process exits, the
    // user sees the connection go away mid-playback (which reads as
    // "TV turned off" rather than "cast failed"), and moves on.
    if !opts.post_capture_linger.is_zero() {
        tokio::time::sleep(opts.post_capture_linger).await;
    }

    // Drop the stop channel so every watcher's `.changed()` fires.
    // 100ms grace covers SSDP byebye multicast; the protocol TCP
    // connections are closed by tokio when handles get aborted.
    drop(stop_tx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for h in handles {
        h.abort();
        let _ = h.await;
    }

    Ok(result)
}
