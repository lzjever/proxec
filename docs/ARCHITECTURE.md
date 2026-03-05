# proxec Technical Architecture

## 1. System Overview

### 1.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                           proxec process                            │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      Main Thread                             │   │
│  │                                                              │   │
│  │  ┌──────────────┐         ┌──────────────────────────────┐  │   │
│  │  │  Env Parser  │         │       Process Manager        │  │   │
│  │  │              │         │                              │  │   │
│  │  │ http_proxy   │         │  fork() child process        │  │   │
│  │  │ https_proxy  │         │  set ptrace options          │  │   │
│  │  │ all_proxy    │         │  monitor child state         │  │   │
│  │  │ no_proxy     │         │                              │  │   │
│  │  └──────────────┘         └──────────────────────────────┘  │   │
│  │                                     │                        │   │
│  │                                     ▼                        │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │                   Tracer Engine                       │   │   │
│  │  │                                                       │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │   │
│  │  │  │ Syscall     │  │ Socket      │  │ Connect     │  │   │   │
│  │  │  │ Handler     │  │ Tracker     │  │ Interceptor │  │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  │                                     │                        │   │
│  │                                     ▼                        │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │                   Proxy Handler                       │   │   │
│  │  │                                                       │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │   │
│  │  │  │ HTTP        │  │ SOCKS5      │  │ Proxy       │  │   │   │
│  │  │  │ CONNECT     │  │ Protocol    │  │ Selector    │  │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────┐         ptrace          ┌──────────────────┐    │
│  │ Child Process│ ◄──────────────────────►│  Target Program  │    │
│  │  (tracee)    │                         │  (e.g., curl)    │    │
│  └──────────────┘                         └──────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ TCP Connection
                              ▼
                    ┌──────────────────┐
                    │  Proxy Server    │
                    │  (HTTP/SOCKS5)   │
                    └──────────────────┘
```

### 1.2 Core Modules

| Module | Responsibility | Dependencies |
|--------|----------------|--------------|
| `env` | Parse proxy environment variables | `url` |
| `cli` | Command-line argument parsing | `clap` |
| `tracer` | ptrace syscall interception | `nix`, `libc` |
| `proxy` | HTTP CONNECT, SOCKS5 protocols | `tokio` |
| `socket` | Socket state tracking | internal |
| `error` | Error types and exit codes | `thiserror` |

---

## 2. Environment Variable Parsing

### 2.1 Standard Variables

```rust
/// Parse standard proxy environment variables
pub struct ProxyEnv {
    http_proxy: Option<ProxyUrl>,
    https_proxy: Option<ProxyUrl>,
    all_proxy: Option<ProxyUrl>,
    no_proxy: Vec<NoProxyPattern>,
}

impl ProxyEnv {
    pub fn from_env() -> Self {
        Self {
            // Lowercase takes precedence (curl convention)
            http_proxy: Self::parse_proxy_var("http_proxy", "HTTP_PROXY"),
            https_proxy: Self::parse_proxy_var("https_proxy", "HTTPS_PROXY"),
            all_proxy: Self::parse_proxy_var("all_proxy", "ALL_PROXY"),
            no_proxy: Self::parse_no_proxy_var("no_proxy", "NO_PROXY"),
        }
    }
    
    fn parse_proxy_var(primary: &str, fallback: &str) -> Option<ProxyUrl> {
        std::env::var(primary)
            .or_else(|_| std::env::var(fallback))
            .ok()
            .and_then(|s| ProxyUrl::parse(&s).ok())
    }
    
    /// Select proxy for a given destination
    pub fn select_proxy(&self, dest: &DestAddress) -> Option<&ProxyUrl> {
        // Check no_proxy first
        if self.should_bypass(dest) {
            return None;
        }
        
        // Select based on destination port
        match dest.port() {
            443 => self.https_proxy.as_ref()
                .or(self.all_proxy.as_ref()),
            80 => self.http_proxy.as_ref()
                .or(self.all_proxy.as_ref()),
            _ => self.all_proxy.as_ref(),
        }
    }
    
    fn should_bypass(&self, dest: &DestAddress) -> bool {
        self.no_proxy.iter().any(|p| p.matches(dest))
    }
}
```

### 2.2 no_proxy Parsing

```rust
pub enum NoProxyPattern {
    Exact(String),           // localhost
    Suffix(String),          // .example.com
    IpCidr(IpNetwork),       // 192.168.0.0/16
    IpExact(IpAddr),         // 127.0.0.1
}

impl NoProxyPattern {
    pub fn parse(s: &str) -> Vec<Self> {
        s.split(',')
            .filter_map(|part| {
                let part = part.trim();
                if part.is_empty() {
                    return None;
                }
                
                // CIDR notation
                if part.contains('/') {
                    return part.parse::<IpNetwork>().ok()
                        .map(NoProxyPattern::IpCidr);
                }
                
                // Domain suffix (.example.com)
                if part.starts_with('.') {
                    return Some(NoProxyPattern::Suffix(part[1..].to_string()));
                }
                
                // IP address
                if let Ok(ip) = part.parse::<IpAddr>() {
                    return Some(NoProxyPattern::IpExact(ip));
                }
                
                // Hostname
                Some(NoProxyPattern::Exact(part.to_string()))
            })
            .collect()
    }
    
    pub fn matches(&self, dest: &DestAddress) -> bool {
        match self {
            NoProxyPattern::Exact(host) => dest.host() == host,
            NoProxyPattern::Suffix(domain) => dest.host().ends_with(domain),
            NoProxyPattern::IpCidr(network) => {
                dest.ip().map(|ip| network.contains(&ip)).unwrap_or(false)
            }
            NoProxyPattern::IpExact(ip) => dest.ip() == Some(*ip),
        }
    }
}
```

---

## 3. Data Flow

### 3.1 Program Startup

```
main()
  │
  ├── 1. Parse command-line arguments
  │      └── cli::parse_args()
  │
  ├── 2. Parse environment variables
  │      └── env::ProxyEnv::from_env()
  │
  ├── 3. Validate proxy configuration
  │      └── If no proxy configured, exec child directly
  │
  ├── 4. Fork child process
  │      │
  │      ├── Child:
  │      │     ├── ptrace::traceme()
  │      │     └── execvp(command, args)
  │      │
  │      └── Parent:
  │            └── Enter trace loop
  │
  └── 5. Trace loop
         └── tracer::run()
```

### 3.2 Syscall Interception

```
Target calls: connect(sockfd, addr, addrlen)
                    │
                    ▼
         ┌─────────────────────┐
         │  Kernel: ptrace     │
         │  stop               │
         └─────────────────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  proxec: stop child │
         │  read registers     │
         └─────────────────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  Determine syscall  │
         └─────────────────────┘
                    │
         ┌─────────┴─────────┐
         │                   │
    ┌────▼────┐         ┌────▼────┐
    │ socket  │         │ connect │
    │ handler │         │ handler │
    └────┬────┘         └────┬────┘
         │                   │
         │              ┌────┴────┐
         │              │         │
         │         ┌────▼───┐ ┌───▼────┐
         │         │ IPv4   │ │ IPv6   │
         │         │        │ │        │
         │         │        │ │ IPv6   │
         │         │        │ │enabled?│
         │         │        │ └───┬────┘
         │         │            │
         │         │       ┌────┴────┐
         │         │       │ No      │ Yes
         │         │       ▼         ▼
         │         │    Set error  Check proxy
         │         │    EAFNOSUP   for IPv6
         │         │
         └─────────┴────────► Resume child
```

### 3.3 Connect Interception Detail

```rust
fn handle_connect_enter(pid: Pid, regs: &Regs) -> Result<()> {
    let sockfd = regs.arg0() as i32;
    let addr_ptr = regs.arg1() as *const c_void;
    
    // 1. Read destination address
    let dest = memory::read_sockaddr(pid, addr_ptr)?;
    
    // 2. Check IPv6 policy
    if dest.is_ipv6() && !config.ipv6_enabled {
        socket_tracker.set_should_fail(pid, sockfd, EAFNOSUPPORT);
        return Ok(());
    }
    
    // 3. Check no_proxy
    if proxy_env.should_bypass(&dest) {
        return Ok(()); // Let it connect directly
    }
    
    // 4. Select proxy
    let proxy = match proxy_env.select_proxy(&dest) {
        Some(p) => p,
        None => return Ok(()), // No proxy, direct connect
    };
    
    // 5. Save original destination
    socket_tracker.save_dest(pid, sockfd, dest.clone());
    
    // 6. Redirect to local proxy port
    // We use a local port that will be handled by our proxy handler
    let local_addr = sockaddr_in(LOCAL_HOST, local_port);
    memory::write_sockaddr(pid, addr_ptr, &local_addr)?;
    
    Ok(())
}

fn handle_connect_exit(pid: Pid, regs: &Regs) -> Result<()> {
    let sockfd = regs.arg0() as i32;
    
    // 1. Check if should fail
    if let Some(errno) = socket_tracker.take_should_fail(pid, sockfd) {
        arch::set_return_value(pid, -errno as i64)?;
        return Ok(());
    }
    
    // 2. Get saved destination
    let dest = match socket_tracker.get_dest(pid, sockfd) {
        Some(d) => d,
        None => return Ok(()),
    };
    
    // 3. Restore original address in child's memory
    let addr_ptr = regs.arg1() as *mut c_void;
    memory::write_sockaddr(pid, addr_ptr, &dest)?;
    
    // 4. Initiate proxy connection (async)
    proxy_handler.connect(dest);
    
    Ok(())
}
```

---

## 4. Core Data Structures

### 4.1 Configuration

```rust
/// Runtime configuration
#[derive(Debug)]
pub struct Config {
    /// Parsed proxy environment
    pub proxy_env: ProxyEnv,
    
    /// Enable IPv6 proxying
    pub ipv6_enabled: bool,
    
    /// Verbosity level
    pub verbose: bool,
    
    /// Debug mode
    pub debug: bool,
    
    /// Command to execute
    pub command: Vec<String>,
}

impl Config {
    pub fn from_args_and_env(args: Args) -> Result<Self> {
        Ok(Config {
            proxy_env: ProxyEnv::from_env(),
            ipv6_enabled: args.ipv6 || std::env::var("PROXEC_IPV6").is_ok(),
            verbose: args.verbose,
            debug: args.debug,
            command: args.command,
        })
    }
}
```

### 4.2 Socket Tracking

```rust
/// Socket identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SocketKey {
    pub pid: Pid,
    pub fd: RawFd,
}

/// Socket information
#[derive(Debug)]
pub struct SocketInfo {
    pub key: SocketKey,
    pub domain: AddressFamily,
    pub sock_type: SocketType,
    pub dest: Option<DestAddress>,
    pub should_fail: Option<i32>,
}

/// Socket tracker
pub struct SocketTracker {
    sockets: HashMap<SocketKey, SocketInfo>,
}

impl SocketTracker {
    pub fn new() -> Self {
        Self { sockets: HashMap::new() }
    }
    
    pub fn insert(&mut self, info: SocketInfo) {
        self.sockets.insert(info.key.clone(), info);
    }
    
    pub fn get(&self, key: &SocketKey) -> Option<&SocketInfo> {
        self.sockets.get(key)
    }
    
    pub fn set_should_fail(&mut self, key: &SocketKey, errno: i32) {
        if let Some(info) = self.sockets.get_mut(key) {
            info.should_fail = Some(errno);
        }
    }
    
    pub fn take_should_fail(&mut self, key: &SocketKey) -> Option<i32> {
        self.sockets.get_mut(key).and_then(|i| i.should_fail.take())
    }
    
    pub fn cleanup_process(&mut self, pid: Pid) {
        self.sockets.retain(|k, _| k.pid != pid);
    }
}
```

### 4.3 Destination Address

```rust
#[derive(Debug, Clone)]
pub enum DestAddress {
    IPv4(SocketAddrV4),
    IPv6(SocketAddrV6),
}

impl DestAddress {
    pub fn family(&self) -> AddressFamily {
        match self {
            Self::IPv4(_) => AddressFamily::Inet,
            Self::IPv6(_) => AddressFamily::Inet6,
        }
    }
    
    pub fn port(&self) -> u16 {
        match self {
            Self::IPv4(a) => a.port(),
            Self::IPv6(a) => a.port(),
        }
    }
    
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::IPv4(a) => Some(IpAddr::V4(*a.ip())),
            Self::IPv6(a) => Some(IpAddr::V6(*a.ip())),
        }
    }
    
    pub fn host(&self) -> &str {
        // For IP addresses, return string representation
        // Note: we don't have hostname here, only IP
        match self {
            Self::IPv4(a) => a.ip().to_string().leak(),
            Self::IPv6(a) => a.ip().to_string().leak(),
        }
    }
    
    pub fn is_local(&self) -> bool {
        match self {
            Self::IPv4(a) => a.ip().is_loopback(),
            Self::IPv6(a) => a.ip().is_loopback(),
        }
    }
    
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::IPv6(_))
    }
    
    /// Format for HTTP CONNECT request
    pub fn to_connect_string(&self) -> String {
        match self {
            Self::IPv4(a) => format!("{}:{}", a.ip(), a.port()),
            Self::IPv6(a) => format!("[{}]:{}", a.ip(), a.port()),
        }
    }
}
```

---

## 5. Proxy Protocol Implementation

### 5.1 HTTP CONNECT

```rust
pub async fn http_connect(
    proxy: &ProxyUrl,
    dest: &DestAddress,
) -> Result<TcpStream, ProxyError> {
    // Connect to proxy
    let mut stream = TcpStream::connect(
        format!("{}:{}", proxy.host, proxy.port)
    ).await?;
    
    // Build CONNECT request
    let dest_str = dest.to_connect_string();
    let mut request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        dest_str, dest_str
    );
    
    // Add authentication if configured
    if let Some(auth) = &proxy.auth {
        let creds = base64::encode(format!("{}:{}", auth.user, auth.pass));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", creds));
    }
    
    request.push_str("\r\n");
    
    // Send request
    stream.write_all(request.as_bytes()).await?;
    
    // Read response
    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).await?;
    let response_str = String::from_utf8_lossy(&response[..n]);
    
    // Parse response
    if !response_str.starts_with("HTTP/1.") {
        return Err(ProxyError::InvalidResponse);
    }
    
    let status: &str = response_str
        .lines()
        .next()
        .unwrap_or("");
    
    if !status.contains("200") {
        return Err(ProxyError::ConnectRejected(status.to_string()));
    }
    
    Ok(stream)
}
```

### 5.2 SOCKS5

```rust
pub async fn socks5_connect(
    proxy: &ProxyUrl,
    dest: &DestAddress,
    dns_through_proxy: bool,
) -> Result<TcpStream, ProxyError> {
    let mut stream = TcpStream::connect(
        format!("{}:{}", proxy.host, proxy.port)
    ).await?;
    
    // 1. Greeting
    let greeting = if proxy.auth.is_some() {
        vec![0x05, 0x02, 0x00, 0x02] // SOCKS5, 2 methods: none, user/pass
    } else {
        vec![0x05, 0x01, 0x00] // SOCKS5, 1 method: none
    };
    stream.write_all(&greeting).await?;
    
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    
    if response[0] != 0x05 {
        return Err(ProxyError::InvalidResponse);
    }
    
    // 2. Authentication (if required)
    match response[1] {
        0x00 => {}, // No auth
        0x02 => {
            if let Some(auth) = &proxy.auth {
                socks5_auth(&mut stream, &auth.user, &auth.pass).await?;
            } else {
                return Err(ProxyError::AuthRequired);
            }
        }
        _ => return Err(ProxyError::NoAcceptableMethod),
    }
    
    // 3. Connect request
    let mut request = vec![0x05, 0x01, 0x00]; // VER, CONNECT, RSV
    
    match dest {
        DestAddress::IPv4(addr) => {
            request.push(0x01); // ATYP = IPv4
            request.extend_from_slice(&addr.ip().octets());
        }
        DestAddress::IPv6(addr) => {
            request.push(0x04); // ATYP = IPv6
            request.extend_from_slice(&addr.ip().octets());
        }
    }
    
    request.extend_from_slice(&dest.port().to_be_bytes());
    stream.write_all(&request).await?;
    
    // 4. Read response
    let mut response = [0u8; 10];
    stream.read_exact(&mut response).await?;
    
    if response[1] != 0x00 {
        return Err(ProxyError::Socks5Failed(response[1]));
    }
    
    Ok(stream)
}
```

---

## 6. ptrace Implementation

### 6.1 Architecture Abstraction

```rust
// src/tracer/arch/mod.rs
mod x86_64;
mod aarch64;

#[cfg(target_arch = "x86_64")]
use x86_64 as arch;

#[cfg(target_arch = "aarch64")]
use aarch64 as arch;

pub use arch::*;
```

### 6.2 x86_64 Implementation

```rust
// src/tracer/arch/x86_64.rs
use nix::unistd::Pid;
use nix::sys::ptrace;
use std::mem::offset_of;

pub const SYS_SOCKET: i64 = 41;
pub const SYS_CONNECT: i64 = 42;
pub const SYS_CLOSE: i64 = 3;
pub const SYS_CLONE: i64 = 56;

pub fn get_syscall_nr(regs: &libc::user_regs_struct) -> i64 {
    regs.orig_rax as i64
}

pub fn get_syscall_arg(regs: &libc::user_regs_struct, n: usize) -> u64 {
    match n {
        0 => regs.rdi,
        1 => regs.rsi,
        2 => regs.rdx,
        3 => regs.r10,
        4 => regs.r8,
        5 => regs.r9,
        _ => panic!("invalid syscall arg index"),
    }
}

pub fn get_return_value(regs: &libc::user_regs_struct) -> i64 {
    regs.rax as i64
}

pub fn set_return_value(pid: Pid, val: i64) -> Result<()> {
    let mut regs = get_regs(pid)?;
    regs.rax = val as u64;
    set_regs(pid, &regs)
}

pub fn get_regs(pid: Pid) -> Result<libc::user_regs_struct> {
    ptrace::getregs(pid)
        .map_err(|e| Error::Ptrace(e))
}

pub fn set_regs(pid: Pid, regs: &libc::user_regs_struct) -> Result<()> {
    ptrace::setregs(pid, regs)
        .map_err(|e| Error::Ptrace(e))
}
```

### 6.3 Memory Operations

```rust
// src/tracer/memory.rs
use nix::unistd::Pid;
use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};

/// Read sockaddr from child process memory
pub fn read_sockaddr(pid: Pid, addr: *const libc::c_void) -> Result<DestAddress> {
    let mut buf = [0u8; 28]; // sizeof(sockaddr_in6)
    
    // Try process_vm_readv first (faster)
    let local = &mut [IoSliceMut::new(&mut buf)];
    let remote = [RemoteIoVec {
        base: addr as usize,
        len: 28,
    }];
    
    process_vm_readv(pid, local, &remote)?;
    
    // Parse address family
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    
    match family as i32 {
        libc::AF_INET => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Ok(DestAddress::IPv4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip_bytes: [u8; 16] = buf[8..24].try_into().unwrap();
            Ok(DestAddress::IPv6(SocketAddrV6::new(
                Ipv6Addr::from(ip_bytes),
                port,
                0, 0,
            )))
        }
        _ => Err(Error::UnknownAddressFamily(family)),
    }
}
```

---

## 7. Error Handling

### 7.1 Error Types

```rust
// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("no proxy configured")]
    NoProxy,
    
    #[error("invalid proxy URL: {0}")]
    InvalidProxyUrl(String),
    
    #[error("proxy connection failed: {0}")]
    ProxyConnect(#[source] std::io::Error),
    
    #[error("ptrace error: {0}")]
    Ptrace(#[source] nix::Error),
    
    #[error("exec failed: {0}")]
    Exec(#[source] std::io::Error),
    
    #[error("unknown address family: {0}")]
    UnknownAddressFamily(u16),
}

impl Error {
    /// Return POSIX exit code
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NoProxy => 0,  // Not an error, just pass through
            Self::InvalidProxyUrl(_) => 2,
            Self::ProxyConnect(_) => 69,  // EX_UNAVAILABLE
            Self::Ptrace(_) => 77,        // EX_NOPERM
            Self::Exec(_) => 126,
            _ => 1,
        }
    }
}
```

---

## 8. Signal Handling

```rust
use nix::sys::signal::{self, SigHandler, Signal};

fn setup_signal_handlers() {
    unsafe {
        signal::sigaction(
            Signal::SIGINT,
            &signal::SigAction::new(
                SigHandler::Handler(handle_sigint),
                signal::SaFlags::empty(),
                signal::SigSet::empty(),
            ),
        ).ok();
        
        signal::sigaction(
            Signal::SIGTERM,
            &signal::SigAction::new(
                SigHandler::Handler(handle_sigterm),
                signal::SaFlags::empty(),
                signal::SigSet::empty(),
            ),
        ).ok();
    }
}

extern "C" fn handle_sigint(_: i32) {
    // Forward SIGINT to child process
    if let Some(child_pid) = CHILD_PID.get() {
        let _ = signal::kill(*child_pid, Signal::SIGINT);
    }
}

extern "C" fn handle_sigterm(_: i32) {
    // Forward SIGTERM to child process
    if let Some(child_pid) = CHILD_PID.get() {
        let _ = signal::kill(*child_pid, Signal::SIGTERM);
    }
}
```

---

## 9. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4.x | CLI parsing (minimal features) |
| `tokio` | 1.x | Async runtime |
| `nix` | 0.27 | ptrace, signals |
| `libc` | 0.2 | Low-level bindings |
| `thiserror` | 1.x | Error types |
| `tracing` | 0.1 | Logging |
| `url` | 2.x | URL parsing |
| `base64` | 0.21 | HTTP auth encoding |

---

## 10. File Structure

```
proxec/
├── Cargo.toml
├── Makefile
├── README.md
├── COPYING                  # GPL-2.0 license
│
├── src/
│   ├── main.rs             # Entry point
│   ├── lib.rs              # Library root
│   ├── cli.rs              # Argument parsing
│   ├── env.rs              # Environment parsing
│   ├── error.rs            # Error types
│   │
│   ├── tracer/
│   │   ├── mod.rs
│   │   ├── ptrace.rs       # ptrace wrapper
│   │   ├── syscall.rs      # Syscall handling
│   │   ├── memory.rs       # Memory operations
│   │   └── arch/
│   │       ├── mod.rs
│   │       ├── x86_64.rs
│   │       └── aarch64.rs
│   │
│   ├── proxy/
│   │   ├── mod.rs
│   │   ├── http.rs         # HTTP CONNECT
│   │   ├── socks5.rs       # SOCKS5
│   │   └── selector.rs     # Proxy selection
│   │
│   └── socket/
│       ├── mod.rs
│       ├── tracker.rs      # Socket state
│       └── types.rs        # Types
│
└── tests/
    ├── integration/
    └── fixtures/
```
