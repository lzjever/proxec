// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! HTTP CONNECT proxy implementation.

use crate::error::{Error, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Establish a tunnel through HTTP CONNECT.
pub async fn connect(
    proxy_addr: SocketAddr,
    dest: SocketAddr,
    auth: Option<(&str, &str)>,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(Error::ProxyConnect)?;

    // Build CONNECT request
    let dest_str = format!("{}", dest);
    let mut request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        dest_str, dest_str
    );

    // Add authentication if provided
    if let Some((user, pass)) = auth {
        let creds = format!("{}:{}", user, pass);
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &creds);
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }

    request.push_str("\r\n");

    tracing::debug!("Sending CONNECT request");

    // Send request
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(Error::ProxyConnect)?;

    // Read response
    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).await.map_err(Error::ProxyConnect)?;
    let response_str = String::from_utf8_lossy(&response[..n]);

    tracing::debug!("Proxy response: {}", response_str.lines().next().unwrap_or(""));

    // Parse response
    let status_line = response_str.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        return Err(Error::HttpProxy(status_line.to_string()));
    }

    Ok(stream)
}
