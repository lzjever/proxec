// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Local proxy server for receiving redirected connections.

use crate::error::Result;
use crate::proxy::http;
use crate::socket::{SocketKey, SocketTracker};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Start the local proxy server.
pub async fn run(
    listener: TcpListener,
    tracker: Arc<Mutex<SocketTracker>>,
    proxy_addr: SocketAddr,
) -> Result<()> {
    tracing::info!("Local proxy server started, waiting for connections");
    loop {
        tracing::debug!("Waiting for connection...");
        let (client, client_addr) = listener.accept().await?;
        tracing::info!("Accepted connection from {}", client_addr);

        let tracker = tracker.clone();
        let proxy_addr = proxy_addr.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(client, client_addr, tracker, proxy_addr).await {
                tracing::error!("Error handling client {}: {}", client_addr, e);
            }
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    client_addr: SocketAddr,
    tracker: Arc<Mutex<SocketTracker>>,
    proxy_addr: SocketAddr,
) -> Result<()> {
    // Look up the destination using the client's local port
    let dest = lookup_destination(&tracker, client_addr.port());

    let dest = match dest {
        Some(addr) => addr,
        None => {
            tracing::warn!("No destination found for {}", client_addr);
            return Ok(());
        }
    };

    tracing::info!("Proxying {} -> {} via {}", client_addr, dest, proxy_addr);

    // Connect through the HTTP proxy
    let mut proxy = match http::connect(proxy_addr, dest, None).await {
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

    tokio::try_join!(client_to_proxy, proxy_to_client)?;

    tracing::debug!("Connection closed: {}", client_addr);

    Ok(())
}

/// Look up destination by finding matching socket in tracker.
fn lookup_destination(tracker: &Arc<Mutex<SocketTracker>>, _local_port: u16) -> Option<SocketAddr> {
    let tracker = tracker.lock().unwrap();
    let count = tracker.sockets().count();
    tracing::debug!("Looking up destination, tracker has {} entries", count);

    // For slice 1, we use a simple approach:
    // Just return the first pending destination we find.
    for (key, info) in tracker.sockets() {
        tracing::debug!("Found entry: key={:?}, dest={}", key, info.dest);
        return Some(info.dest);
    }

    None
}
