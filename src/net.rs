use anyhow::{Context, Result};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use std::net::UdpSocket;

/// Physical network interface prefixes — Ethernet / WiFi only.
/// Skips VPN (utun/tun), Tailscale, Docker (veth/br), etc.
const PHYSICAL_PREFIXES: &[&str] = &["en", "eth", "wlan"];

fn is_physical(name: &str) -> bool {
    let lower = name.to_lowercase();
    PHYSICAL_PREFIXES.iter().any(|p| lower.starts_with(p))
}

fn is_private(octets: &[u8; 4]) -> bool {
    matches!(octets, [192, 168, ..] | [10, ..] | [172, 16..=31, ..])
}

/// Detect the LAN IP address of the current machine.
///
/// Only considers physical interfaces (`en*`, `eth*`, `wlan*`).
/// Falls back to any private IP, then the UDP connect trick.
pub fn get_lan_ip() -> Result<String> {
    let interfaces =
        NetworkInterface::show().context("failed to enumerate network interfaces")?;

    // Pass 1: physical interfaces only.
    for iface in &interfaces {
        if !is_physical(&iface.name) {
            continue;
        }
        for addr in &iface.addr {
            let ip = match addr {
                Addr::V4(v4) => v4.ip,
                _ => continue,
            };
            if is_private(&ip.octets()) {
                return Ok(ip.to_string());
            }
        }
    }

    // Pass 2: any interface (in case naming doesn't match).
    for iface in &interfaces {
        for addr in &iface.addr {
            let ip = match addr {
                Addr::V4(v4) => v4.ip,
                _ => continue,
            };
            let octets = ip.octets();
            if octets[0] == 127 {
                continue;
            }
            if is_private(&octets) {
                return Ok(ip.to_string());
            }
        }
    }

    // Fallback: UDP connect trick (no packets are actually sent).
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    socket
        .connect("8.8.8.8:80")
        .context("failed to connect UDP socket to 8.8.8.8:80")?;
    let addr = socket
        .local_addr()
        .context("failed to get local address from UDP socket")?;
    Ok(addr.ip().to_string())
}

/// Resolve a bind target to an IP address.
/// Accepts either an IP address ("192.168.1.100") or an interface name ("en1").
pub fn resolve_bind(val: &str) -> Result<String> {
    // If it parses as an IP, use directly.
    if val.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(val.to_string());
    }

    // Otherwise treat as interface name.
    let interfaces =
        NetworkInterface::show().context("failed to enumerate network interfaces")?;
    for iface in &interfaces {
        if iface.name == val {
            for addr in &iface.addr {
                if let Addr::V4(v4) = addr {
                    if !v4.ip.is_loopback() {
                        return Ok(v4.ip.to_string());
                    }
                }
            }
        }
    }
    anyhow::bail!("no IPv4 address found for interface '{val}'")
}
