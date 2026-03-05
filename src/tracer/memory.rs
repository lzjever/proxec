// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Memory operations for reading/writing child process memory.

use crate::error::{Error, Result};
use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};
use nix::unistd::Pid;
use std::io::IoSliceMut;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Read a sockaddr structure from child process memory.
pub fn read_sockaddr(pid: Pid, addr: u64, _addrlen: u64) -> Result<SocketAddr> {
    let mut buf = [0u8; 28]; // sizeof(sockaddr_in6)

    let local = IoSliceMut::new(&mut buf);
    let remote = [RemoteIoVec {
        base: addr as usize,
        len: 28,
    }];

    process_vm_readv(pid, &mut [local], &remote)
        .map_err(Error::MemoryRead)?;

    // Parse address family (first 2 bytes)
    let family = u16::from_ne_bytes([buf[0], buf[1]]);

    match family as i32 {
        libc::AF_INET => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let octets = [buf[4], buf[5], buf[6], buf[7]];
            let ip = Ipv4Addr::from(octets);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip_bytes: [u8; 16] = buf[8..24].try_into().unwrap();
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => Err(Error::UnknownAddressFamily(family)),
    }
}

/// Write a sockaddr structure to child process memory.
pub fn write_sockaddr(pid: Pid, addr: u64, sockaddr: &SocketAddr) -> Result<()> {
    let mut buf = [0u8; 28];

    match sockaddr {
        SocketAddr::V4(v4) => {
            buf[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
        }
    }

    let local = std::io::IoSlice::new(&buf);
    let remote = [RemoteIoVec {
        base: addr as usize,
        len: 28,
    }];

    process_vm_writev(pid, &[local], &remote)
        .map_err(Error::MemoryWrite)?;

    Ok(())
}
