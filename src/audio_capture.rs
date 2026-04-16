//! UDP listener that captures AirPlay RTP audio to a raw AAC (ADTS) file.
//!
//! Packet layout expected from the AirPlay sender:
//!   [0..12]      RTP header
//!   [12..-24]    Encrypted (or plain) audio payload
//!   [-24..-8]    ChaCha20-Poly1305 auth tag (16 bytes)
//!   [-8..]       Nonce (8 bytes)
//!   AAD          = data[4..12]  (RTP timestamp + SSRC)
//!
//! The 8-byte nonce is left-padded with 4 zero bytes to reach the 12 bytes
//! required by the IETF ChaCha20-Poly1305 construction, which matches the
//! behaviour of PyCryptodome's `ChaCha20_Poly1305` with an 8-byte nonce.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Bind a UDP socket on an OS-assigned port and return `(socket, port)`.
/// The port is needed immediately for the SETUP response; the socket
/// ownership is transferred to the capture task.
pub fn bind_capture_socket() -> Result<(UdpSocket, u16)> {
    let std_sock =
        std::net::UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    std_sock
        .set_nonblocking(true)
        .context("failed to set non-blocking")?;
    let port = std_sock
        .local_addr()
        .context("failed to get local addr")?
        .port();
    let socket = UdpSocket::from_std(std_sock).context("failed to convert to tokio socket")?;
    Ok((socket, port))
}

/// Receive RTP packets until `duration` seconds have elapsed (or forever if
/// `duration` is `None`), writing ADTS-wrapped AAC frames to `output_path`.
///
/// When finished, sends `Some(output_path)` on `on_done`.
pub async fn run_capture(
    socket: UdpSocket,
    port: u16,
    output_path: String,
    shk: Option<Vec<u8>>,
    duration: Option<f64>,
    on_done: Arc<tokio::sync::watch::Sender<Option<String>>>,
) -> Result<()> {
    let cipher: Option<ChaCha20Poly1305> = shk
        .as_deref()
        .map(|key| ChaCha20Poly1305::new_from_slice(key))
        .transpose()
        .context("invalid SHK length for ChaCha20-Poly1305")?;

    let deadline = duration.map(|secs| Instant::now() + Duration::from_secs_f64(secs));

    let mut file = tokio::fs::File::create(&output_path)
        .await
        .with_context(|| format!("failed to create output file: {output_path}"))?;

    let mut buf = vec![0u8; 8192];
    let mut pkt_count: u64 = 0;

    debug!(
        "AudioCapture: listening on UDP :{} → {} (shk={}, duration={:?})",
        port,
        output_path,
        if cipher.is_some() { "yes" } else { "no" },
        duration,
    );

    loop {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                debug!("AudioCapture: duration limit reached");
                break;
            }
            let remaining = dl - Instant::now();
            let recv = tokio::time::timeout(remaining, socket.recv(&mut buf));
            match recv.await {
                Err(_elapsed) => break,
                Ok(Err(e)) => {
                    warn!("AudioCapture: recv error: {e}");
                    break;
                }
                Ok(Ok(n)) => {
                    if let Some(audio) = handle_packet(&buf[..n], cipher.as_ref()) {
                        write_frame(&mut file, &audio).await?;
                        pkt_count += 1;
                    }
                }
            }
        } else {
            match socket.recv(&mut buf).await {
                Err(e) => {
                    warn!("AudioCapture: recv error: {e}");
                    break;
                }
                Ok(n) => {
                    if let Some(audio) = handle_packet(&buf[..n], cipher.as_ref()) {
                        write_frame(&mut file, &audio).await?;
                        pkt_count += 1;
                    }
                }
            }
        }
    }

    debug!("AudioCapture: stopped, {pkt_count} packets captured");
    let _ = on_done.send(Some(output_path));
    Ok(())
}

/// Decode one RTP packet and return the raw AAC frame, or `None` if the packet
/// is too short / decryption fails.
fn handle_packet(data: &[u8], cipher: Option<&ChaCha20Poly1305>) -> Option<Vec<u8>> {
    // Minimum: 12 (RTP header) + 1 (payload) + 16 (tag) + 8 (nonce)
    if data.len() < 37 {
        return None;
    }

    let nonce_bytes = &data[data.len() - 8..];
    let tag = &data[data.len() - 24..data.len() - 8];
    let aad = &data[4..12]; // timestamp + SSRC
    let payload = &data[12..data.len() - 24];

    if payload.is_empty() {
        return None;
    }

    if let Some(cipher) = cipher {
        // Build 12-byte nonce: left-pad 8-byte nonce with 4 zero bytes.
        let mut nonce_arr = [0u8; 12];
        nonce_arr[4..].copy_from_slice(nonce_bytes);
        let nonce = Nonce::from(nonce_arr);

        // Concatenate ciphertext + tag as required by chacha20poly1305 crate.
        let mut ct_with_tag = Vec::with_capacity(payload.len() + 16);
        ct_with_tag.extend_from_slice(payload);
        ct_with_tag.extend_from_slice(tag);

        match cipher.decrypt(
            &nonce,
            Payload {
                msg: &ct_with_tag,
                aad,
            },
        ) {
            Ok(pt) => Some(pt),
            Err(_) => None, // Decryption failed — might be a control packet
        }
    } else {
        Some(payload.to_vec())
    }
}

/// Write one AAC frame wrapped in a 7-byte ADTS header.
async fn write_frame(
    file: &mut tokio::fs::File,
    audio_data: &[u8],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let header = adts_header(audio_data.len());
    file.write_all(&header).await?;
    file.write_all(audio_data).await?;
    Ok(())
}

/// 7-byte ADTS header for AAC-LC, 44100 Hz, stereo.
fn adts_header(frame_len: usize) -> [u8; 7] {
    let total = frame_len + 7;
    [
        0xFF,
        0xF1, // MPEG-4, no CRC
        0x50, // AAC-LC, 44100 Hz
        0x80 | (((total >> 11) & 0x03) as u8),
        ((total >> 3) & 0xFF) as u8,
        (((total & 0x07) << 5) as u8) | 0x1F,
        0xFC, // VBR
    ]
}
