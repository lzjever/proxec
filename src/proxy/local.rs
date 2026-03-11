// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! Local proxy server for receiving redirected connections.

use crate::error::Result;
use crate::proxy::config::{ProxyConfig, ProxyProtocol};
use crate::proxy::http;
use crate::proxy::socks5;
use crate::socket::{find_inode_by_conn, find_pid_fd_by_inode, SocketTracker};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};

/// Start the local proxy server.
pub async fn run(
    listener: TcpListener,
    tracker: Arc<Mutex<SocketTracker>>,
    proxy: ProxyConfig,
) -> Result<()> {
    tracing::info!("Local proxy server started, waiting for connections");
    loop {
        tracing::debug!("Waiting for connection...");
        let (client, client_addr) = listener.accept().await?;
        tracing::info!("Accepted connection from {}", client_addr);

        let tracker = tracker.clone();
        let proxy = proxy.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(client, client_addr, tracker, proxy).await {
                // Don't log "broken pipe" as errors - this is normal when clients disconnect
                let err_str = e.to_string();
                if err_str.contains("Broken pipe") || err_str.contains("Connection reset") {
                    tracing::debug!("Client disconnected: {}", e);
                } else {
                    tracing::error!("Error handling client {}: {}", client_addr, e);
                }
            }
        });
    }
}

async fn handle_client(
    client: TcpStream,
    client_addr: SocketAddr,
    tracker: Arc<Mutex<SocketTracker>>,
    proxy: ProxyConfig,
) -> Result<()> {
    let server_addr = client.local_addr()?;
    let client_port = client_addr.port();

    let mut dest = None;
    for attempt in 0..3 {
        let inode = find_inode_by_conn(
            client_addr.ip(),
            client_port,
            server_addr.ip(),
            server_addr.port(),
        );
        {
            let tracker_guard = tracker.lock().unwrap();
            if let Some(inode) = inode {
                if let Some(info) = tracker_guard.get_by_inode(&inode) {
                    tracing::debug!(
                        "Matched connection {} inode={} dest={}",
                        client_addr,
                        inode,
                        info.dest
                    );
                    dest = Some(info.dest);
                } else if let Some((pid, fd)) = find_pid_fd_by_inode(&inode) {
                    if let Some(info) = tracker_guard.get_by_pid_fd(pid, fd) {
                        tracing::debug!(
                            "Matched connection {} via fallback inode={} pid={} fd={} dest={}",
                            client_addr,
                            inode,
                            pid,
                            fd,
                            info.dest
                        );
                        dest = Some(info.dest);
                    }
                }
            }
        }
        if dest.is_some() {
            break;
        }
        if attempt < 2 {
            sleep(Duration::from_millis(20)).await;
        }
    }

    let dest = match dest {
        Some(dest) => dest,
        None => {
            let tracker_guard = tracker.lock().unwrap();
            tracing::warn!(
                "Could not resolve destination for connection {} (tracker entries={})",
                client_addr,
                tracker_guard.stats()
            );
            for (pid, info) in tracker_guard.entries().take(5) {
                tracing::debug!("tracker: pid={} dest={}", pid, info.dest);
            }
            return Ok(());
        }
    };

    proxy_connection(client, client_addr, proxy, dest).await
}

async fn proxy_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    proxy: ProxyConfig,
    dest: SocketAddr,
) -> Result<()> {
    tracing::info!("Proxying {} -> {} via {}", client_addr, dest, proxy.addr);

    let auth = proxy
        .auth
        .as_ref()
        .map(|(user, pass)| (user.as_str(), pass.as_str()));
    let upstream = match proxy.protocol {
        ProxyProtocol::HttpConnect => http::connect(proxy.addr, dest, auth).await,
        ProxyProtocol::Socks5 => socks5::connect(proxy.addr, dest, auth).await,
    };

    let mut proxy = match upstream {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to connect to proxy: {}", e);
            return Err(e);
        }
    };

    // Bidirectional relay
    let (mut client_rd, mut client_wr) = client.split();
    let (mut proxy_rd, mut proxy_wr) = proxy.split();

    let client_to_proxy = io::copy(&mut client_rd, &mut proxy_wr);
    let proxy_to_client = io::copy(&mut proxy_rd, &mut client_wr);

    // Use tokio::select to handle either direction failing
    tokio::select! {
        result = client_to_proxy => {
            if let Err(e) = result {
                tracing::debug!("client->proxy copy error: {}", e);
            }
        }
        result = proxy_to_client => {
            if let Err(e) = result {
                tracing::debug!("proxy->client copy error: {}", e);
            }
        }
    }

    tracing::debug!("Connection closed: {}", client_addr);

    Ok(())
}
