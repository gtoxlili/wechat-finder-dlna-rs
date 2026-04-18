use std::io::Write;

use clap::Parser;
use wechat_finder_dlna::{capture, CaptureOptions, Protocol};

#[derive(Parser)]
#[command(
    name = "wechat-finder-dlna",
    about = "Capture WeChat Video Channel (视频号) live stream URLs via fake screen casting (DLNA / AirPlay / Chromecast).",
    after_help = r#"examples:
  wechat-finder-dlna                              # all protocols, print captured URL
  wechat-finder-dlna --protocol dlna              # DLNA only
  wechat-finder-dlna --protocol airplay cast      # AirPlay + Chromecast
  wechat-finder-dlna --record live.mp4            # record with ffmpeg
  wechat-finder-dlna --name "Living Room TV"      # custom device name
  wechat-finder-dlna | xargs vlc                  # pipe to VLC"#
)]
struct Cli {
    /// Device name shown in cast list.
    #[arg(long, default_value = "MAGI")]
    name: String,

    /// Base HTTP port for DLNA.
    #[arg(long, default_value_t = 9090)]
    port: u16,

    /// Protocols to enable (dlna, airplay, cast). Default: all.
    #[arg(long = "protocol", num_args = 1..)]
    protocol: Option<Vec<String>>,

    /// Auto-record to FILE with ffmpeg after capture.
    #[arg(long, value_name = "FILE")]
    record: Option<String>,

    /// Recording duration (ffmpeg format, e.g. 01:00:00).
    #[arg(long, value_name = "HH:MM:SS")]
    duration: Option<String>,

    /// Bind to a specific interface (e.g. "en1") or IP address.
    #[arg(long, value_name = "IFACE_OR_IP")]
    bind: Option<String>,

    /// Debug logging.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(std::io::stderr)
            .init();
    }

    let protocols: Vec<Protocol> = if let Some(ref protos) = cli.protocol {
        protos
            .iter()
            .map(|s| {
                s.parse::<Protocol>().unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                })
            })
            .collect()
    } else {
        Protocol::ALL.to_vec()
    };

    let audio_dur = cli.duration.as_ref().map(|d| {
        let parts: Vec<&str> = d.split(':').collect();
        parts
            .iter()
            .zip([3600.0, 60.0, 1.0])
            .map(|(p, m)| p.parse::<f64>().unwrap_or(0.0) * m)
            .sum::<f64>()
    });

    let opts = CaptureOptions {
        name: cli.name,
        port: cli.port,
        protocols,
        bind: cli.bind,
        audio_output: cli.record.clone(),
        audio_duration: audio_dur,
        ..Default::default()
    };

    // Handle SIGINT (Ctrl+C) and SIGTERM separately so a wrapping shell
    // (Go's os/exec, systemd, docker) can stop us cleanly. Without the
    // explicit SIGTERM branch, `kill $pid` leaves us running until the
    // OS sends SIGKILL, which skips the byebye NOTIFYs.
    #[cfg(unix)]
    let sigterm = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    let result = tokio::select! {
        r = capture(opts) => r,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n  Interrupted");
            std::process::exit(130);
        }
        _ = sigterm => {
            eprintln!("\n  Terminated");
            std::process::exit(143);
        }
    };

    match result {
        Ok(url) => {
            eprintln!("\n  Captured: {url}\n");

            // Flush URL to stdout immediately — Go reads this via cmd.Stdout pipe.
            {
                let stdout = std::io::stdout();
                let mut out = stdout.lock();
                let _ = writeln!(out, "{url}");
                let _ = out.flush();
            }

            if let Some(ref record) = cli.record {
                if url == *record {
                    eprintln!("  Saved to {url}");
                } else {
                    record_with_ffmpeg(&url, record, cli.duration.as_deref()).await;
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

async fn record_with_ffmpeg(url: &str, output: &str, duration: Option<&str>) {
    let ffmpeg = which::which("ffmpeg").unwrap_or_else(|_| {
        eprintln!("Error: ffmpeg not found in PATH");
        std::process::exit(1);
    });

    let mut cmd = tokio::process::Command::new(ffmpeg);
    cmd.args(["-hide_banner", "-loglevel", "info", "-re", "-i", url, "-c", "copy"]);
    if let Some(d) = duration {
        cmd.args(["-t", d]);
    }
    cmd.args(["-y", output]);
    cmd.stdin(std::process::Stdio::null());

    eprintln!("  Recording to {output}...\n");

    // Spawn as a tokio child so SIGINT propagation works properly
    // when Go kills the process group.
    match cmd.spawn() {
        Ok(mut child) => {
            tokio::select! {
                status = child.wait() => {
                    if let Ok(s) = status
                        && s.success()
                    {
                        eprintln!("\n  Saved to {output}");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    let _ = child.kill().await;
                    eprintln!("\n  Recording interrupted");
                }
            }
        }
        Err(e) => {
            eprintln!("Error: failed to run ffmpeg: {e}");
            std::process::exit(1);
        }
    }
}
