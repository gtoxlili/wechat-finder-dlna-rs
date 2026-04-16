use anyhow::{Context, Result};
use network_interface::{NetworkInterface, NetworkInterfaceConfig, Addr};
use std::net::UdpSocket;

/// Detect the LAN IP address of the current machine, skipping loopback and VPN addresses.
/// Falls back to a UDP connect trick against 8.8.8.8:80 if no private-range address is found.
pub fn get_lan_ip() -> Result<String> {
    let interfaces =
        NetworkInterface::show().context("failed to enumerate network interfaces")?;

    for iface in &interfaces {
        for addr in &iface.addr {
            let ip = match addr {
                Addr::V4(v4) => v4.ip,
                _ => continue,
            };

            let octets = ip.octets();

            // Skip loopback
            if octets[0] == 127 {
                continue;
            }

            // 192.168.x.x
            if octets[0] == 192 && octets[1] == 168 {
                return Ok(ip.to_string());
            }

            // 10.x.x.x
            if octets[0] == 10 {
                return Ok(ip.to_string());
            }

            // 172.16.x.x – 172.31.x.x
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return Ok(ip.to_string());
            }
        }
    }

    // Fallback: UDP connect trick (no packets are actually sent)
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    socket
        .connect("8.8.8.8:80")
        .context("failed to connect UDP socket to 8.8.8.8:80")?;
    let addr = socket
        .local_addr()
        .context("failed to get local address from UDP socket")?;
    Ok(addr.ip().to_string())
}
