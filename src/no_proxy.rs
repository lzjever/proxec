// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! no_proxy-style bypass rule parsing for connect() destinations.

use crate::error::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::net::ToSocketAddrs;

#[derive(Debug, Clone, PartialEq, Eq)]
enum NoProxyRule {
    Any,
    Loopback,
    IpExact(IpAddr),
    IpCidr(IpNet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpNet {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => contains_v4(network, ip, self.prefix_len),
            (IpAddr::V6(network), IpAddr::V6(ip)) => contains_v6(network, ip, self.prefix_len),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoProxy {
    rules: Vec<NoProxyRule>,
    unsupported_suffix_patterns: Vec<String>,
    unresolved_hostnames: Vec<String>,
}

impl NoProxy {
    pub fn parse(parts: &[String]) -> Result<Self> {
        let mut rules = Vec::new();
        let mut unsupported_suffix_patterns = Vec::new();
        let mut unresolved_hostnames = Vec::new();

        for raw in parts {
            let part = raw.trim();
            if part.is_empty() {
                continue;
            }

            if part == "*" {
                rules.push(NoProxyRule::Any);
                continue;
            }

            if part.eq_ignore_ascii_case("localhost") {
                rules.push(NoProxyRule::Loopback);
                continue;
            }

            if let Ok(ip) = part.parse::<IpAddr>() {
                rules.push(NoProxyRule::IpExact(ip));
                continue;
            }

            if part.contains('/') {
                rules.push(NoProxyRule::IpCidr(parse_cidr(part)?));
                continue;
            }

            if part.starts_with('.') {
                unsupported_suffix_patterns.push(part.to_string());
                continue;
            }

            let mut resolved = false;
            match (part, 0).to_socket_addrs() {
                Ok(addrs) => {
                    for addr in addrs {
                        rules.push(NoProxyRule::IpExact(addr.ip()));
                        resolved = true;
                    }
                    if !resolved {
                        unresolved_hostnames.push(part.to_string());
                    }
                }
                Err(_) => {
                    unresolved_hostnames.push(part.to_string());
                }
            }
        }

        Ok(Self {
            rules,
            unsupported_suffix_patterns,
            unresolved_hostnames,
        })
    }

    pub fn should_bypass(&self, dest: &SocketAddr) -> bool {
        self.rules.iter().any(|rule| match rule {
            NoProxyRule::Any => true,
            NoProxyRule::Loopback => dest.ip().is_loopback(),
            NoProxyRule::IpExact(ip) => dest.ip() == *ip,
            NoProxyRule::IpCidr(net) => net.contains(dest.ip()),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
            && self.unsupported_suffix_patterns.is_empty()
            && self.unresolved_hostnames.is_empty()
    }

    pub fn unsupported_suffix_patterns(&self) -> &[String] {
        &self.unsupported_suffix_patterns
    }

    pub fn unresolved_hostnames(&self) -> &[String] {
        &self.unresolved_hostnames
    }
}

fn parse_cidr(raw: &str) -> Result<IpNet> {
    let (addr, prefix_len) = raw
        .split_once('/')
        .ok_or_else(|| Error::InvalidArgument(format!("invalid no-proxy CIDR: {raw}")))?;
    let addr = addr
        .parse::<IpAddr>()
        .map_err(|_| Error::InvalidArgument(format!("invalid no-proxy CIDR: {raw}")))?;
    let prefix_len = prefix_len
        .parse::<u8>()
        .map_err(|_| Error::InvalidArgument(format!("invalid no-proxy CIDR: {raw}")))?;

    let max_prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len > max_prefix {
        return Err(Error::InvalidArgument(format!("invalid no-proxy CIDR: {raw}")));
    }

    Ok(IpNet { addr, prefix_len })
}

fn contains_v4(network: Ipv4Addr, ip: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (u32::from(network) & mask) == (u32::from(ip) & mask)
}

fn contains_v6(network: Ipv6Addr, ip: Ipv6Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    (u128::from(network) & mask) == (u128::from(ip) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_ip_rules() {
        let rules = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "192.168.0.0/16".to_string(),
            "::1".to_string(),
            "2001:db8::/32".to_string(),
        ];
        let no_proxy = NoProxy::parse(&rules).unwrap();

        assert!(no_proxy.should_bypass(&"127.0.0.1:8080".parse().unwrap()));
        assert!(no_proxy.should_bypass(&"192.168.1.20:443".parse().unwrap()));
        assert!(no_proxy.should_bypass(&"[::1]:8080".parse().unwrap()));
        assert!(no_proxy.should_bypass(&"[2001:db8::1]:443".parse().unwrap()));
        assert!(!no_proxy.should_bypass(&"8.8.8.8:53".parse().unwrap()));
    }

    #[test]
    fn records_unsupported_host_patterns() {
        let rules = vec![".example.com".to_string()];
        let no_proxy = NoProxy::parse(&rules).unwrap();

        assert_eq!(
            no_proxy.unsupported_suffix_patterns(),
            &[".example.com".to_string()]
        );
    }

    #[test]
    fn resolves_concrete_hostnames() {
        let rules = vec!["localhost".to_string()];
        let no_proxy = NoProxy::parse(&rules).unwrap();

        assert!(no_proxy.should_bypass(&"127.0.0.1:8080".parse().unwrap()));
        assert!(no_proxy.should_bypass(&"[::1]:8080".parse().unwrap()));
    }

    #[test]
    fn records_unresolved_hostnames() {
        let rules = vec!["nonexistent.invalid".to_string()];
        let no_proxy = NoProxy::parse(&rules).unwrap();

        assert_eq!(
            no_proxy.unresolved_hostnames(),
            &["nonexistent.invalid".to_string()]
        );
    }
}
