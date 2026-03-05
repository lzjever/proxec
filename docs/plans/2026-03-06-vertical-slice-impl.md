# Vertical Slice Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement minimal working proxec that can proxy curl through an HTTP proxy.

**Architecture:** ptrace-based syscall interception + embedded local proxy server. Child's connect() is redirected to localhost, local proxy looks up original destination via /proc, establishes tunnel through HTTP CONNECT.

**Tech Stack:** Rust, tokio (async), nix (ptrace), clap (CLI)

---

## Task 1: Error Types

**Files:**
- Modify: `src/error.rs`

**Step 1: Write the error enum**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Error types with POSIX exit codes.

use std::ffi::NulError;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("no proxy configured")]
    NoProxy,

    #[error("invalid proxy URL: {0}")]
    InvalidProxyUrl(String),

    #[error("fork failed: {0}")]
    Fork(#[source] nix::Error),

    #[error("ptrace error: {0}")]
    Ptrace(#[source] nix::Error),

    #[error("exec failed: {0}")]
    Exec(#[source] io::Error),

    #[error("wait failed: {0}")]
    Wait(#[source] nix::Error),

    #[error("failed to read child memory: {0}")]
    MemoryRead(#[source] nix::Error),

    #[error("failed to write child memory: {0}")]
    MemoryWrite(#[source] nix::Error),

    #[error("unknown address family: {0}")]
    UnknownAddressFamily(u16),

    #[error("proxy connection failed: {0}")]
    ProxyConnect(#[source] io::Error),

    #[error("HTTP proxy error: {0}")]
    HttpProxy(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("nul byte in string: {0}")]
    NulByte(#[from] NulError),
}

impl Error {
    /// Return POSIX exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NoProxy => 0,
            Self::InvalidProxyUrl(_) => 2,
            Self::ProxyConnect(_) => 69,  // EX_UNAVAILABLE
            Self::Ptrace(_) => 77,        // EX_NOPERM
            Self::Exec(_) => 126,
            _ => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/error.rs
git commit -m "feat: add error types with POSIX exit codes"
```

---

## Task 2: Minimal CLI

**Files:**
- Modify: `src/cli.rs`

**Step 1: Write CLI struct**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Command-line argument parsing.

use clap::Parser;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "proxec",
    author,
    version,
    about = "Transparently proxy TCP connections through HTTP/SOCKS5",
    long_about = None
)]
pub struct Args {
    /// Proxy URL (e.g., http://127.0.0.1:8080)
    #[arg(short = 'x', long = "proxy")]
    pub proxy: String,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Debug output
    #[arg(short, long)]
    pub debug: bool,

    /// Command to execute
    #[arg(required = true)]
    pub command: String,

    /// Arguments for the command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn parse() -> Args {
    Args::parse()
}
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/cli.rs
git commit -m "feat: add minimal CLI with --proxy flag"
```

---

## Task 3: Socket Tracker

**Files:**
- Modify: `src/socket/mod.rs`
- Create: `src/socket/tracker.rs`

**Step 1: Update socket/mod.rs**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Socket tracking for intercepted connections.

mod tracker;

pub use tracker::*;
```

**Step 2: Write tracker.rs**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Socket state tracking.

use nix::unistd::Pid;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Key to identify a socket in a process.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SocketKey {
    pub pid: Pid,
    pub fd: i32,
}

impl SocketKey {
    pub fn new(pid: Pid, fd: i32) -> Self {
        Self { pid, fd }
    }
}

/// Information about an intercepted socket.
#[derive(Debug, Clone)]
pub struct SocketInfo {
    /// Original destination address.
    pub dest: SocketAddr,
}

/// Thread-safe socket tracker.
pub struct SocketTracker {
    /// Mapping from (pid, fd) to socket info.
    sockets: HashMap<SocketKey, SocketInfo>,
}

impl SocketTracker {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
        }
    }

    /// Store socket info for a pending connection.
    pub fn insert(&mut self, key: SocketKey, info: SocketInfo) {
        self.sockets.insert(key, info);
    }

    /// Get socket info.
    pub fn get(&self, key: &SocketKey) -> Option<&SocketInfo> {
        self.sockets.get(key)
    }

    /// Remove and return socket info.
    pub fn remove(&mut self, key: &SocketKey) -> Option<SocketInfo> {
        self.sockets.remove(key)
    }

    /// Clean up all sockets for a process.
    pub fn cleanup_process(&mut self, pid: Pid) {
        self.sockets.retain(|k, _| k.pid != pid);
    }
}

impl Default for SocketTracker {
    fn default() -> Self {
        Self::new()
    }
}
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 4: Commit**

```bash
git add src/socket/mod.rs src/socket/tracker.rs
git commit -m "feat: add SocketTracker for connection state"
```

---

## Task 4: x86_64 Architecture Support

**Files:**
- Create: `src/tracer/arch_x86_64.rs`

**Step 1: Write architecture module**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! x86_64 architecture-specific definitions.

use nix::unistd::Pid;

/// Syscall numbers for x86_64.
pub mod syscall {
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const CLOSE: i64 = 3;
    pub const CLONE: i64 = 56;
    pub const GETSOCKNAME: i64 = 51;
}

/// Get syscall number from registers.
pub fn get_syscall_nr(regs: &libc::user_regs_struct) -> i64 {
    regs.orig_rax as i64
}

/// Get syscall argument by index (0-5).
pub fn get_syscall_arg(regs: &libc::user_regs_struct, n: usize) -> u64 {
    match n {
        0 => regs.rdi,
        1 => regs.rsi,
        2 => regs.rdx,
        3 => regs.r10,
        4 => regs.r8,
        5 => regs.r9,
        _ => panic!("invalid syscall argument index: {n}"),
    }
}

/// Get syscall return value.
pub fn get_return_value(regs: &libc::user_regs_struct) -> i64 {
    regs.rax as i64
}

/// Set syscall return value.
pub fn set_return_value(
    pid: Pid,
    regs: &mut libc::user_regs_struct,
    val: i64,
) {
    regs.rax = val as u64;
}

/// Read registers from traced process.
pub fn get_regs(pid: Pid) -> std::io::Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut _ as *mut libc::c_void,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(regs)
}

/// Write registers to traced process.
pub fn set_regs(pid: Pid, regs: &libc::user_regs_struct) -> std::io::Result<()> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const _ as *mut libc::c_void,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/tracer/arch_x86_64.rs
git commit -m "feat: add x86_64 architecture support for ptrace"
```

---

## Task 5: Memory Operations

**Files:**
- Create: `src/tracer/memory.rs`

**Step 1: Write memory module**

```rust
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
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/tracer/memory.rs
git commit -m "feat: add memory operations for child process"
```

---

## Task 6: Ptrace Fork and Exec

**Files:**
- Create: `src/tracer/ptrace.rs`

**Step 1: Write ptrace module**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! ptrace setup and child process management.

use crate::error::{Error, Result};
use nix::sys::ptrace;
use nix::unistd::{fork, Pid};
use std::ffi::CString;

/// Fork and exec a child process with ptrace enabled.
pub fn fork_exec(command: &str, args: &[String]) -> Result<Pid> {
    match unsafe { fork() }.map_err(Error::Fork)? {
        nix::unistd::ForkResult::Parent { child } => {
            tracing::debug!("Forked child process: {child}");
            Ok(child)
        }
        nix::unistd::ForkResult::Child => {
            // Child process
            ptrace::traceme().expect("ptrace TRACEME failed");

            // Stop ourselves so parent can set options
            nix::sys::signal::raise(nix::sys::signal::SIGSTOP)
                .expect("raise SIGSTOP failed");

            // Build argument vector
            let c_cmd = CString::new(command)?;
            let c_args: Vec<CString> = std::iter::once(c_cmd.clone())
                .chain(args.iter().map(|s| CString::new(s.as_str()).unwrap()))
                .collect();

            // Exec the target program
            nix::unistd::execvp(&c_cmd, &c_args)
                .expect("execvp failed");

            unreachable!()
        }
    }
}
```

**Step 2: Update tracer/mod.rs**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! ptrace-based syscall interception.

mod arch_x86_64;
mod memory;
mod ptrace;
mod syscall;

pub use arch_x86_64::*;
pub use memory::*;
pub use ptrace::*;
pub use syscall::*;
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 4: Commit**

```bash
git add src/tracer/ptrace.rs src/tracer/mod.rs
git commit -m "feat: add fork_exec with ptrace support"
```

---

## Task 7: Syscall Tracing Loop

**Files:**
- Create: `src/tracer/syscall.rs`

**Step 1: Write syscall module**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Syscall handling and trace loop.

use crate::error::{Error, Result};
use crate::socket::{SocketInfo, SocketKey, SocketTracker};
use crate::tracer::{
    get_regs, get_syscall_arg, get_syscall_nr, read_sockaddr, write_sockaddr,
    syscall::CONNECT,
};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

/// State for tracking whether we're entering or exiting a syscall.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SyscallState {
    Entering,
    Exiting,
}

/// Run the trace loop.
pub fn run(
    child_pid: Pid,
    tracker: Arc<Mutex<SocketTracker>>,
    local_addr: SocketAddr,
) -> Result<i32> {
    let mut state = SyscallState::Entering;
    let mut exit_code = 0;

    loop {
        let status = waitpid(child_pid, None).map_err(Error::Wait)?;

        match status {
            WaitStatus::Exited(pid, code) => {
                tracing::debug!("Process {pid} exited with code {code}");
                exit_code = code;
                break;
            }
            WaitStatus::Signaled(pid, sig, _) => {
                tracing::debug!("Process {pid} killed by signal {sig}");
                exit_code = 128 + sig as i32;
                break;
            }
            WaitStatus::Stopped(pid, Signal::SIGSTOP) => {
                // Initial stop - set ptrace options
                ptrace::setoptions(
                    pid,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK,
                )
                .map_err(Error::Ptrace)?;
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::PtraceSyscall(pid) => {
                handle_syscall(pid, &mut state, &tracker, &local_addr)?;
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::Stopped(pid, sig) => {
                // Deliver signal to child
                ptrace::syscall(pid, sig).map_err(Error::Ptrace)?;
            }
            _ => {
                tracing::debug!("Unexpected wait status: {:?}", status);
                ptrace::syscall(child_pid, None).map_err(Error::Ptrace)?;
            }
        }
    }

    Ok(exit_code)
}

fn handle_syscall(
    pid: Pid,
    state: &mut SyscallState,
    tracker: &Arc<Mutex<SocketTracker>>,
    local_addr: &SocketAddr,
) -> Result<()> {
    let regs = get_regs(pid)?;
    let syscall_nr = get_syscall_nr(&regs);

    match state {
        SyscallState::Entering => {
            if syscall_nr == CONNECT {
                handle_connect_enter(pid, &regs, tracker, local_addr)?;
            }
            *state = SyscallState::Exiting;
        }
        SyscallState::Exiting => {
            *state = SyscallState::Entering;
        }
    }

    Ok(())
}

fn handle_connect_enter(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
    local_addr: &SocketAddr,
) -> Result<()> {
    let sockfd = get_syscall_arg(regs, 0) as i32;
    let addr_ptr = get_syscall_arg(regs, 1);
    let addrlen = get_syscall_arg(regs, 2);

    // Read the destination address
    let dest = match read_sockaddr(pid, addr_ptr, addrlen) {
        Ok(addr) => addr,
        Err(Error::UnknownAddressFamily(_)) => {
            // Not IPv4/IPv6, let it pass through
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    tracing::debug!("connect({sockfd}, {dest})");

    // Store the original destination
    let key = SocketKey::new(pid, sockfd);
    let info = SocketInfo { dest };
    tracker.lock().unwrap().insert(key, info);

    // Rewrite the address to point to our local proxy
    write_sockaddr(pid, addr_ptr, local_addr)?;

    tracing::debug!("redirected to {local_addr}");

    Ok(())
}
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/tracer/syscall.rs
git commit -m "feat: add syscall trace loop with connect interception"
```

---

## Task 8: HTTP CONNECT Proxy

**Files:**
- Create: `src/proxy/http.rs`

**Step 1: Write HTTP proxy module**

```rust
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
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/proxy/http.rs
git commit -m "feat: add HTTP CONNECT proxy implementation"
```

---

## Task 9: Local Proxy Server

**Files:**
- Create: `src/proxy/local.rs`

**Step 1: Write local proxy module**

```rust
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
    loop {
        let (client, client_addr) = listener.accept().await?;
        tracing::debug!("Accepted connection from {}", client_addr);

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
    // The client's port (from client_addr.port()) is what we need to find
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

    // Get the proxy connection's underlying socket for bidirectional relay
    let (mut client_rd, mut client_wr) = client.split();
    let (mut proxy_rd, mut proxy_wr) = proxy.split();

    // Bidirectional relay
    let client_to_proxy = io::copy(&mut client_rd, &mut proxy_wr);
    let proxy_to_client = io::copy(&mut proxy_rd, &mut client_wr);

    tokio::try_join!(client_to_proxy, proxy_to_client)?;

    tracing::debug!("Connection closed: {}", client_addr);

    Ok(())
}

/// Look up destination by finding matching socket in tracker.
/// This is a simplified approach - in production we'd use /proc to find exact match.
fn lookup_destination(tracker: &Arc<Mutex<SocketTracker>>, _local_port: u16) -> Option<SocketAddr> {
    // For slice 1, we use a simple approach:
    // Just return the first pending destination we find.
    // This works for single-connection scenarios like `curl`.
    let tracker = tracker.lock().unwrap();

    // Find any socket that was redirected
    // TODO: Use /proc to find exact (pid, fd) by local port
    for (key, info) in tracker.sockets() {
        tracing::debug!("Found socket: {:?} -> {}", key, info.dest);
        return Some(info.dest);
    }

    None
}
```

**Step 2: Add SocketTracker iterator method**

Update `src/socket/tracker.rs` to add:

```rust
impl SocketTracker {
    // ... existing methods ...

    /// Get iterator over all sockets.
    pub fn sockets(&self) -> impl Iterator<Item = (&SocketKey, &SocketInfo)> {
        self.sockets.iter()
    }
}
```

**Step 3: Update proxy/mod.rs**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Proxy protocol implementations.

pub mod http;
pub mod local;

pub use http::*;
pub use local::*;
```

**Step 4: Verify compilation**

Run: `cargo check`
Expected: No errors

**Step 5: Commit**

```bash
git add src/proxy/local.rs src/proxy/mod.rs src/socket/tracker.rs
git commit -m "feat: add local proxy server with HTTP CONNECT"
```

---

## Task 10: Main Entry Point

**Files:**
- Modify: `src/main.rs`
- Modify: `src/lib.rs`

**Step 1: Update lib.rs**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Transparently proxy TCP connections through HTTP/SOCKS5.

pub mod cli;
pub mod error;
pub mod proxy;
pub mod socket;
pub mod tracer;
```

**Step 2: Write main.rs**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! proxec entry point.

use proxec::cli;
use proxec::error::{Error, Result};
use proxec::proxy::local;
use proxec::socket::SocketTracker;
use proxec::tracer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use url::Url;

fn main() -> Result<()> {
    // Parse command line
    let args = cli::parse();

    // Initialize logging
    let filter = if args.debug {
        "debug"
    } else if args.verbose {
        "info"
    } else {
        "warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Parse proxy URL
    let proxy_url = Url::parse(&args.proxy).map_err(|_| Error::InvalidProxyUrl(args.proxy.clone()))?;
    let proxy_host = proxy_url.host_str().ok_or_else(|| Error::InvalidProxyUrl("missing host".into()))?;
    let proxy_port = proxy_url.port().ok_or_else(|| Error::InvalidProxyUrl("missing port".into()))?;
    let proxy_addr: SocketAddr = format!("{}:{}", proxy_host, proxy_port)
        .parse()
        .map_err(|_| Error::InvalidProxyUrl(format!("invalid address: {}:{}", proxy_host, proxy_port)))?;

    tracing::info!("Using proxy: {}", proxy_addr);

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();

    // Bind local proxy server
    let local_listener = rt.block_on(async {
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .await
            .map_err(Error::Io)
    })?;
    let local_addr = local_listener.local_addr()?;
    tracing::info!("Local proxy listening on {}", local_addr);

    // Create socket tracker
    let tracker = Arc::new(Mutex::new(SocketTracker::new()));

    // Start local proxy server in background
    let tracker_clone = tracker.clone();
    rt.spawn(async move {
        if let Err(e) = local::run(local_listener, tracker_clone, proxy_addr).await {
            tracing::error!("Local proxy error: {}", e);
        }
    });

    // Fork and exec child process
    let child_pid = tracer::fork_exec(&args.command, &args.args)?;
    tracing::info!("Started child process: {} (pid {})", args.command, child_pid);

    // Run tracer loop (blocking)
    let exit_code = tracer::run(child_pid, tracker, local_addr)?;

    tracing::info!("Child exited with code {}", exit_code);

    std::process::exit(exit_code);
}
```

**Step 3: Verify compilation**

Run: `cargo build`
Expected: Successful build

**Step 4: Commit**

```bash
git add src/main.rs src/lib.rs
git commit -m "feat: add main entry point integrating all components"
```

---

## Task 11: Integration Test

**Files:**
- Create: `tests/integration_test.rs`

**Step 1: Write integration test**

```rust
// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Integration tests.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_help_flag() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Transparently proxy"));
}

#[test]
fn test_version_flag() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("proxec"));
}

#[test]
fn test_missing_proxy() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("echo")
        .arg("hello")
        .assert()
        .failure();
}
```

**Step 2: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add tests/integration_test.rs
git commit -m "test: add basic integration tests"
```

---

## Task 12: Manual End-to-End Test

**Prerequisites:**
- A running HTTP proxy (e.g., on 127.0.0.1:8080)

**Step 1: Build release**

Run: `cargo build --release`

**Step 2: Test with curl**

Run: `./target/release/proxec --proxy http://127.0.0.1:8080 curl http://ifconfig.me`
Expected: Shows proxy's IP address

**Step 3: Test verbose mode**

Run: `./target/release/proxec -v --proxy http://127.0.0.1:8080 curl http://example.com`
Expected: Shows debug output

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete vertical slice implementation"
```

---

## Summary

This plan implements a minimal working proxec in 12 tasks:

1. Error types
2. CLI parsing
3. Socket tracker
4. x86_64 architecture support
5. Memory operations
6. Fork/exec with ptrace
7. Syscall trace loop
8. HTTP CONNECT proxy
9. Local proxy server
10. Main entry point
11. Integration tests
12. Manual E2E test
