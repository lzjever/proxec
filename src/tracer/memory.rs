// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! Memory operations for reading/writing child process memory.

use crate::error::{Error, Result};
use nix::sys::ptrace;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
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

    process_vm_readv(pid, &mut [local], &remote).map_err(Error::MemoryRead)?;

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

/// Write a sockaddr structure to child process memory using PTRACE_POKEDATA.
pub fn write_sockaddr(pid: Pid, addr: u64, sockaddr: &SocketAddr) -> Result<()> {
    let mut buf = [0u8; 28]; // sockaddr_in6
    let buf_len = match sockaddr {
        SocketAddr::V4(v4) => {
            buf[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            buf[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    let buf = &buf[..buf_len];

    // Write using PTRACE_POKEDATA (like graftcp does)
    let word_size = std::mem::size_of::<libc::c_long>();
    let addr = addr as libc::c_long;

    // Write full words
    let num_words = buf.len() / word_size;
    for i in 0..num_words {
        let offset = i * word_size;
        let word_bytes: [u8; 8] = buf[offset..offset + word_size].try_into().unwrap();
        let word = libc::c_long::from_ne_bytes(word_bytes);
        unsafe {
            ptrace::write(
                pid,
                (addr + offset as libc::c_long) as *mut libc::c_void,
                word as *mut libc::c_void,
            )
            .map_err(Error::Ptrace)?;
        }
    }

    // Handle remaining bytes (if any)
    let remainder = buf.len() % word_size;
    if remainder != 0 {
        let offset = num_words * word_size;
        // Read existing word, modify the relevant bytes, write back
        let existing = ptrace::read(pid, (addr + offset as libc::c_long) as *mut libc::c_void)
            .map_err(Error::Ptrace)? as libc::c_long;
        let mut existing_bytes = existing.to_ne_bytes();
        existing_bytes[..remainder].copy_from_slice(&buf[offset..(remainder + offset)]);
        let new_word = libc::c_long::from_ne_bytes(existing_bytes);
        unsafe {
            ptrace::write(
                pid,
                (addr + offset as libc::c_long) as *mut libc::c_void,
                new_word as *mut libc::c_void,
            )
            .map_err(Error::Ptrace)?;
        }
    }

    Ok(())
}

/// Read a u64 value from child process memory.
pub fn read_u64(pid: Pid, addr: u64) -> Result<u64> {
    let mut buf = [0u8; std::mem::size_of::<u64>()];
    let len = buf.len();
    let local = IoSliceMut::new(&mut buf);
    let remote = [RemoteIoVec {
        base: addr as usize,
        len,
    }];

    process_vm_readv(pid, &mut [local], &remote).map_err(Error::MemoryRead)?;

    Ok(u64::from_ne_bytes(buf))
}

/// Write a u64 value to child process memory.
pub fn write_u64(pid: Pid, addr: u64, value: u64) -> Result<()> {
    let word = value as libc::c_long;
    unsafe {
        ptrace::write(
            pid,
            addr as usize as *mut libc::c_void,
            word as *mut libc::c_void,
        )
        .map_err(Error::Ptrace)?;
    }

    Ok(())
}
