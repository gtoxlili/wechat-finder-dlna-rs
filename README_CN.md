# wechat-finder-dlna

**[Python 版本](https://github.com/gtoxlili/wechat-finder-dlna)**

[![Crates.io](https://img.shields.io/crates/v/wechat-finder-dlna)](https://crates.io/crates/wechat-finder-dlna)
[![License: GPL-3.0](https://img.shields.io/crates/l/wechat-finder-dlna)](LICENSE)

在局域网里伪装成智能电视，截获投屏时传过来的直播流地址。支持 DLNA、AirPlay 2、Chromecast 三种投屏协议同时监听。

单文件部署，无运行时依赖，基于 Tokio 异步运行时。

## 安装

```bash
cargo install wechat-finder-dlna
```

也可以从 [Releases](https://github.com/gtoxlili/wechat-finder-dlna-rs/releases) 下载编译好的二进制文件。

## 用法

```bash
# 三种协议全开，打印捕获到的 URL
wechat-finder-dlna

# 只用 DLNA
wechat-finder-dlna --protocol dlna

# AirPlay + Chromecast
wechat-finder-dlna --protocol airplay cast

# 用 ffmpeg 录制
wechat-finder-dlna --record live.mp4 --duration 01:00:00

# 自定义设备名
wechat-finder-dlna --name "客厅电视"
```

手机和电脑在同一个 WiFi 下，打开视频号直播 → 投屏 → 选设备，URL 就出来了。

## 协议支持

| 协议 | 设备发现 | 捕获方式 |
|------|---------|---------|
| DLNA/UPnP | SSDP 组播 | `SetAVTransportURI` SOAP 请求 |
| AirPlay 2 | mDNS/Bonjour | Pair-Setup + Pair-Verify → `/play` |
| Google Cast | mDNS | TLS + Cast V2 protobuf `LOAD` 命令 |

三个协议并发监听，捕获到第一个 URL 后自动退出。

## 不只是微信

所有支持 DLNA / AirPlay / Chromecast 投屏的 App 都能用 —— B 站、爱奇艺、优酷、腾讯视频等。

## 从源码编译

```bash
git clone https://github.com/gtoxlili/wechat-finder-dlna-rs
cd wechat-finder-dlna-rs
cargo build --release
# 二进制在 target/release/wechat-finder-dlna
```

需要 Rust 2024 edition (1.85+)，Cast V2 的 protobuf 定义需要 `protoc`。

## 许可证

GPL-3.0-or-later
