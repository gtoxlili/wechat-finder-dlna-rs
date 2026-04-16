# wechat-finder-dlna

[中文文档](README_CN.md) · [Python version](https://github.com/gtoxlili/wechat-finder-dlna)

[![Crates.io](https://img.shields.io/crates/v/wechat-finder-dlna)](https://crates.io/crates/wechat-finder-dlna)
[![License: GPL-3.0](https://img.shields.io/crates/l/wechat-finder-dlna)](LICENSE)

Impersonate a smart TV on your LAN to intercept cast stream URLs. When any app casts a video via DLNA, AirPlay, or Chromecast, this tool captures the raw `m3u8`/`mp4` URL before it reaches the screen.

Single binary. No runtime dependencies. Built on Tokio.

## Install

```bash
cargo install wechat-finder-dlna
```

Pre-built binaries are also available in [Releases](https://github.com/gtoxlili/wechat-finder-dlna-rs/releases).

## Usage

```bash
# Listen on all three protocols, print the captured URL
wechat-finder-dlna

# DLNA only
wechat-finder-dlna --protocol dlna

# AirPlay + Chromecast
wechat-finder-dlna --protocol airplay cast

# Record with ffmpeg
wechat-finder-dlna --record live.mp4 --duration 01:00:00

# Custom device name
wechat-finder-dlna --name "Living Room TV"

# Pipe to mpv
wechat-finder-dlna | xargs mpv
```

## Protocols

| Protocol | Discovery | Capture mechanism |
|----------|-----------|-------------------|
| DLNA/UPnP | SSDP multicast | `SetAVTransportURI` SOAP action |
| AirPlay 2 | mDNS/Bonjour | Pair-Setup + Pair-Verify → `/play` |
| Google Cast | mDNS | TLS + Cast V2 protobuf `LOAD` command |

All three listeners start concurrently. The tool exits after the first URL is captured.

## Library usage

```rust
use wechat_finder_dlna::{capture, CaptureOptions, Protocol};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = capture(CaptureOptions {
        name: "My TV".into(),
        protocols: vec![Protocol::Dlna, Protocol::Airplay],
        ..Default::default()
    }).await?;
    println!("{url}");
    Ok(())
}
```

## Building from source

```bash
git clone https://github.com/gtoxlili/wechat-finder-dlna-rs
cd wechat-finder-dlna-rs
cargo build --release
# binary at target/release/wechat-finder-dlna
```

Requires Rust 2024 edition (1.85+) and `protoc` for the Cast V2 protobuf definitions.

## License

GPL-3.0-or-later
