// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! SOCKS5 proxy implementation.

use crate::error::{Error, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

pub async fn connect(
    proxy_addr: SocketAddr,
    dest: SocketAddr,
    auth: Option<(&str, &str)>,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(Error::ProxyConnect)?;

    let methods = if auth.is_some() {
        [METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        [METHOD_NO_AUTH, METHOD_NO_AUTH]
    };
    let methods_len = if auth.is_some() { 2 } else { 1 };
    let mut greeting = vec![SOCKS_VERSION, methods_len];
    greeting.extend_from_slice(&methods[..methods_len as usize]);

    tracing::debug!("Sending SOCKS5 greeting");
    stream
        .write_all(&greeting)
        .await
        .map_err(Error::ProxyConnect)?;

    let mut method_reply = [0u8; 2];
    stream
        .read_exact(&mut method_reply)
        .await
        .map_err(Error::ProxyConnect)?;
    if method_reply[0] != SOCKS_VERSION {
        return Err(Error::SocksProxy(format!(
            "invalid SOCKS version in method reply: {}",
            method_reply[0]
        )));
    }

    match method_reply[1] {
        METHOD_NO_AUTH => {}
        METHOD_USER_PASS => {
            let (user, pass) = auth.ok_or_else(|| {
                Error::SocksProxy("proxy requested username/password auth".into())
            })?;
            socks5_auth(&mut stream, user, pass).await?;
        }
        0xff => {
            return Err(Error::SocksProxy(
                "proxy rejected all authentication methods".into(),
            ))
        }
        other => {
            return Err(Error::SocksProxy(format!(
                "unsupported SOCKS auth method: {other}"
            )))
        }
    }

    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    match dest {
        SocketAddr::V4(addr) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    tracing::debug!("Sending SOCKS5 CONNECT request");
    stream
        .write_all(&request)
        .await
        .map_err(Error::ProxyConnect)?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(Error::ProxyConnect)?;
    if header[0] != SOCKS_VERSION {
        return Err(Error::SocksProxy(format!(
            "invalid SOCKS version in connect reply: {}",
            header[0]
        )));
    }
    if header[1] != 0x00 {
        return Err(Error::SocksProxy(format!(
            "connect failed with reply code 0x{:02x}",
            header[1]
        )));
    }

    let addr_len = match header[3] {
        ATYP_IPV4 => 4,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(Error::ProxyConnect)?;
            len[0] as usize
        }
        ATYP_IPV6 => 16,
        atyp => {
            return Err(Error::SocksProxy(format!(
                "invalid address type in connect reply: {atyp}"
            )))
        }
    };
    let mut discard = vec![0u8; addr_len + 2];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(Error::ProxyConnect)?;

    Ok(stream)
}

async fn socks5_auth(stream: &mut TcpStream, user: &str, pass: &str) -> Result<()> {
    if user.len() > u8::MAX as usize || pass.len() > u8::MAX as usize {
        return Err(Error::InvalidArgument(
            "SOCKS5 username/password too long".into(),
        ));
    }

    let mut request = Vec::with_capacity(3 + user.len() + pass.len());
    request.push(0x01);
    request.push(user.len() as u8);
    request.extend_from_slice(user.as_bytes());
    request.push(pass.len() as u8);
    request.extend_from_slice(pass.as_bytes());

    stream
        .write_all(&request)
        .await
        .map_err(Error::ProxyConnect)?;

    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(Error::ProxyConnect)?;
    if reply != [0x01, 0x00] {
        return Err(Error::SocksProxy("username/password auth failed".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks5_connect_ipv4_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [SOCKS_VERSION, 1, METHOD_NO_AUTH]);
            socket
                .write_all(&[SOCKS_VERSION, METHOD_NO_AUTH])
                .await
                .unwrap();

            let mut req = [0u8; 10];
            socket.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], SOCKS_VERSION);
            assert_eq!(req[1], CMD_CONNECT);
            assert_eq!(req[3], ATYP_IPV4);
            socket
                .write_all(&[
                    SOCKS_VERSION,
                    0x00,
                    0x00,
                    ATYP_IPV4,
                    127,
                    0,
                    0,
                    1,
                    0x12,
                    0x34,
                ])
                .await
                .unwrap();
        });

        let stream = connect(proxy_addr, "142.250.72.14:443".parse().unwrap(), None)
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), proxy_addr);
        server.await.unwrap();
    }
}
