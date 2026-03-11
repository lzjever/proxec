// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! Parsed upstream proxy configuration.

use crate::error::{Error, Result};
use std::net::SocketAddr;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    HttpConnect,
    Socks5,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub protocol: ProxyProtocol,
    pub addr: SocketAddr,
    pub auth: Option<(String, String)>,
}

impl ProxyConfig {
    pub fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw).map_err(|_| Error::InvalidProxyUrl(raw.to_string()))?;
        let protocol = match url.scheme() {
            "http" => ProxyProtocol::HttpConnect,
            "socks" | "socks5" => ProxyProtocol::Socks5,
            other => {
                return Err(Error::InvalidProxyUrl(format!(
                    "unsupported proxy scheme: {other}"
                )))
            }
        };

        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidProxyUrl("missing host".into()))?;
        let port = url
            .port()
            .ok_or_else(|| Error::InvalidProxyUrl("missing port".into()))?;
        let addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|_| Error::InvalidProxyUrl(format!("invalid address: {host}:{port}")))?;

        let auth = if url.username().is_empty() {
            None
        } else {
            Some((
                url.username().to_string(),
                url.password().unwrap_or_default().to_string(),
            ))
        };

        Ok(Self {
            protocol,
            addr,
            auth,
        })
    }
}
