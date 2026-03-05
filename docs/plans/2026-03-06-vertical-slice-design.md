# Vertical Slice Design - 2026-03-06

## Overview

Implement a minimal working end-to-end flow for proxec:

```bash
./target/debug/proxec --proxy http://127.0.0.1:8080 curl http://ifconfig.me
# Should show proxy's IP, not real IP
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        proxec (parent)                          │
│                                                                 │
│  Main Thread                Tokio Runtime                       │
│  ┌──────────────┐          ┌────────────────────────┐          │
│  │  1. Parse CLI│          │  Local Proxy Server    │          │
│  │  2. Bind :0  │─────────►│  (127.0.0.1:随机端口)   │          │
│  │  3. Fork     │          │                        │          │
│  │  4. Trace    │          │  接收 → 查表 → 代理 → 转发│          │
│  └──────────────┘          └────────────────────────┘          │
│         │                           │                          │
│         └───────────┬───────────────┘                          │
│                     │                                          │
│            ┌────────▼────────┐                                 │
│            │  SocketTracker  │  (Arc<Mutex<...>>)              │
│            │                 │                                 │
│            │  (pid,fd)→dest  │                                 │
│            └─────────────────┘                                 │
└─────────────────────────────────────────────────────────────────┘
                      │
                      │ ptrace
                      ▼
              ┌───────────────┐
              │ Child Process │
              │  (e.g. curl)  │
              └───────────────┘
```

## Key Design Decisions

### 1. Embedded Local Server (not fd injection)

- Bind to `127.0.0.1:0` for automatic port allocation
- Relay traffic through HTTP CONNECT to real proxy
- Proven approach from graftcp
- Compatible with kernel 4.8+ (fd injection needs 5.6+)

### 2. Destination Lookup via /proc

When local proxy receives connection:
1. Get child's (remote_ip, remote_port) from accept()
2. Look up inode in `/proc/net/tcp` by (local:port, remote:port)
3. Find (pid, fd) owning that inode via `/proc/<pid>/fd/`
4. Look up dest from SocketTracker by (pid, fd)

### 3. Concurrency Model

```rust
fn main() {
    let rt = tokio::runtime::Runtime::new()?;
    let tracker = Arc::new(Mutex::new(SocketTracker::new()));
    let local_addr = bind_local_proxy(&rt, tracker.clone());

    // tracer blocks on main thread
    tracer::run(child_pid, tracker, local_addr);
}
```

## Module Structure (Slice 1)

```
src/
├── main.rs           # Entry + concurrency orchestration
├── lib.rs
├── cli.rs            # Minimal CLI (--proxy, command, args)
├── error.rs          # Error enum
│
├── tracer/
│   ├── mod.rs
│   ├── ptrace.rs     # fork + ptrace setup
│   ├── syscall.rs    # syscall handling
│   └── arch_x86_64.rs # x86_64 only (slice 1)
│
├── proxy/
│   ├── mod.rs
│   ├── local.rs      # Local proxy server
│   └── http.rs       # HTTP CONNECT
│
└── socket/
    └── tracker.rs    # State management
```

## Implementation Steps

### Step 1: Fork + Trace
- `main.rs` + `tracer/ptrace.rs`
- Goal: `proxec ls` runs and exits

### Step 2: Intercept connect
- `tracer/syscall.rs` + `tracer/arch_x86_64.rs`
- Goal: `proxec curl http://example.com` prints "connect intercepted"

### Step 3: Read destination address
- Read sockaddr from child memory
- Goal: Prints "connect to 93.184.216.34:80"

### Step 4: Local proxy + HTTP CONNECT
- `proxy/local.rs` + `proxy/http.rs`
- Goal: `proxec curl http://ifconfig.me` shows proxy IP

## Out of Scope (Slice 1)

- Environment variable parsing (`http_proxy`, etc.)
- SOCKS5 protocol
- IPv6 handling
- `no_proxy` bypass logic
- Multi-process handling (forked children)
- aarch64 support
