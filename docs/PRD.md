# proxec - Product Requirements Document

## 1. Overview

### 1.1 Purpose

`proxec` is a single-binary tool that transparently proxies TCP connections of any dynamically linked Linux program through an HTTP or SOCKS5 proxy. It uses `ptrace(2)` to intercept socket system calls without requiring any modification to the target program.

### 1.2 Philosophy

**Follow POSIX/GNU conventions:**
- Use standard environment variables (`http_proxy`, `https_proxy`, `all_proxy`, `no_proxy`)
- Follow GNU coding standards for CLI behavior
- Silent operation by default (no output on success)
- Proper exit codes following POSIX conventions
- Support `--help` and `--version` as standard options
- No unnecessary output or prompts

### 1.3 Target Users

- System administrators
- Security professionals
- Developers in restricted network environments
- Users who need to route specific programs through proxies

---

## 2. Core Functionality

### 2.1 Basic Usage

```bash
# Set environment variables (standard POSIX way)
export http_proxy=http://192.168.1.1:8080
export https_proxy=http://192.168.1.1:8080
proxec curl https://example.com

# Or inline
http_proxy=http://proxy:8080 proxec wget https://example.com

# SOCKS5 proxy via all_proxy
all_proxy=socks5://127.0.0.1:1080 proxec chromium

# With authentication (standard format)
http_proxy=http://user:pass@proxy:8080 proxec curl https://example.com

# Enable IPv6 (disabled by default)
PROXEC_IPV6=1 proxec curl https://ipv6.google.com

# Verbose mode (like curl -v, wget --verbose)
proxec -v curl https://example.com

# Debug mode
proxec -d curl https://example.com
```

### 2.2 Environment Variables (POSIX Standard)

`proxec` follows standard Unix proxy environment variable conventions:

| Variable | Purpose | Example |
|----------|---------|---------|
| `http_proxy` | Proxy for HTTP requests | `http://proxy:8080` |
| `HTTP_PROXY` | Same as `http_proxy` (uppercase variant) | `http://proxy:8080` |
| `https_proxy` | Proxy for HTTPS requests | `http://proxy:8080` |
| `HTTPS_PROXY` | Same as `https_proxy` | `http://proxy:8080` |
| `all_proxy` | Proxy for all protocols | `socks5://proxy:1080` |
| `ALL_PROXY` | Same as `all_proxy` | `socks5://proxy:1080` |
| `no_proxy` | Addresses to bypass proxy | `localhost,127.0.0.1,.local` |
| `NO_PROXY` | Same as `no_proxy` | `localhost,127.0.0.1` |

**Precedence order:**
1. `https_proxy` / `HTTPS_PROXY` for HTTPS connections
2. `http_proxy` / `HTTP_PROXY` for HTTP connections
3. `all_proxy` / `ALL_PROXY` as fallback for any protocol

### 2.3 Proxy URL Format

Following standard conventions:

```
[protocol://][user:password@]host[:port]
```

| Format | Description |
|--------|-------------|
| `http://proxy:8080` | HTTP proxy on port 8080 |
| `http://user:pass@proxy:8080` | HTTP proxy with authentication |
| `socks5://proxy:1080` | SOCKS5 proxy |
| `socks5h://proxy:1080` | SOCKS5 proxy with DNS resolution through proxy |
| `proxy:8080` | Default to HTTP proxy (port required) |

### 2.4 IPv6 Handling

**Default behavior:** IPv6 connections fail with `EAFNOSUPPORT`, forcing programs to fall back to IPv4.

**Rationale:** Most proxy servers and network environments lack IPv6 connectivity. Forcing IPv6 failure ensures reliable operation.

**Enable IPv6:**
```bash
PROXEC_IPV6=1 proxec curl https://ipv6.google.com
```

---

## 3. Command Line Interface

### 3.1 Synopsis

```
proxec [OPTIONS] COMMAND [ARG ...]
```

### 3.2 Options (POSIX/GNU Style)

```
Usage: proxec [OPTION]... COMMAND [ARG]...

Transparently proxy TCP connections through HTTP/SOCKS5 proxy.

Options:
  -v, --verbose           verbose operation
  -q, --quiet             suppress all non-error output
  -d, --debug             debug output (implies -v)
  -6, --ipv6              enable IPv6 proxying
  -4, --ipv4-only         force IPv4 only (default behavior)
  -h, --help              display this help and exit
  -V, --version           output version information and exit

Environment Variables:
  http_proxy, HTTP_PROXY    HTTP proxy URL
  https_proxy, HTTPS_PROXY  HTTPS proxy URL  
  all_proxy, ALL_PROXY      fallback proxy for all protocols
  no_proxy, NO_PROXY        bypass proxy for these addresses
  PROXEC_IPV6               set to "1" to enable IPv6 by default
  PROXEC_DEBUG              set to "1" for debug output

Examples:
  http_proxy=http://proxy:8080 proxec curl https://example.com
  all_proxy=socks5://127.0.0.1:1080 proxec wget https://example.com
  proxec -v curl https://ifconfig.me

Report bugs to: https://github.com/proxec/proxec/issues
```

### 3.3 Exit Codes (POSIX Standard)

| Code | Meaning | POSIX Reference |
|------|---------|-----------------|
| 0 | Success | |
| 1 | General error | |
| 2 | Misuse of shell command | |
| 126 | Command not executable | |
| 127 | Command not found | |
| 128+N | Signal N received | |
| 130 | Interrupted (Ctrl+C) | 128 + SIGINT(2) |

`proxec`-specific codes (64-78 reserved for custom codes per sysexits.h):

| Code | Meaning |
|------|---------|
| 69 | Service unavailable (proxy connection failed) |
| 77 | Permission denied (ptrace not allowed) |

### 3.4 Behavior (GNU Standards)

**Silent Operation:**
- No output on successful execution (like `cp`, `mv`)
- Errors go to stderr
- Exit code indicates success/failure

**Signal Handling:**
- Forward signals to child process
- Handle SIGINT, SIGTERM, SIGHUP gracefully
- Cleanup on exit

**Standard Streams:**
- stdin: passed through to child
- stdout: passed through from child
- stderr: proxec errors + child stderr

---

## 4. Proxy Behavior Details

### 4.1 Address Bypass (no_proxy)

The `no_proxy` variable specifies addresses that should bypass the proxy:

```
no_proxy=localhost,127.0.0.1,::1,.example.com,192.168.0.0/16
```

Supported formats:
- Hostname: `localhost`
- IP address: `127.0.0.1`
- Domain suffix: `.example.com` (matches `*.example.com`)
- CIDR: `192.168.0.0/16`

### 4.2 Protocol Selection

```
Target: http://example.com:80
  1. Check no_proxy → bypass if matches
  2. Use http_proxy if set
  3. Use HTTP_PROXY if http_proxy not set
  4. Use all_proxy as fallback
  5. Direct connection if no proxy configured

Target: https://example.com:443
  1. Check no_proxy → bypass if matches
  2. Use https_proxy if set
  3. Use HTTPS_PROXY if https_proxy not set
  4. Use all_proxy as fallback
  5. Direct connection if no proxy configured

Target: other protocols
  1. Check no_proxy
  2. Use all_proxy
  3. Direct connection
```

### 4.3 Authentication

For HTTP proxies:
```
http_proxy=http://user:password@proxy:8080
```

For SOCKS5 proxies:
```
all_proxy=socks5://user:password@proxy:1080
```

---

## 5. Non-Goals

The following are explicitly out of scope:

1. **Command-line proxy configuration** - Use environment variables only
2. **Built-in proxy server** - Use dedicated proxy software
3. **Configuration files** - Environment variables are sufficient
4. **GUI interface** - CLI only
5. **macOS/Windows support** - Linux only
6. **UDP proxying** - TCP only (ptrace limitation)
7. **Static binary support** - Dynamic linking only

---

## 6. Comparison with Similar Tools

### 6.1 vs graftcp

| Feature | graftcp | proxec |
|---------|---------|--------|
| Architecture | Client-Server (2 processes) | Single binary |
| Configuration | Custom parameters | Standard env vars |
| IPv6 | Enabled by default | Disabled by default |
| POSIX compliance | Custom | Full compliance |

### 6.2 vs proxychains

| Feature | proxychains | proxec |
|---------|-------------|--------|
| Mechanism | LD_PRELOAD | ptrace |
| Static binaries | No | No |
| Proxy chains | Yes | No |
| Works with setuid | No | Yes |

### 6.3 vs tsocks

| Feature | tsocks | proxec |
|---------|--------|--------|
| Mechanism | LD_PRELOAD | ptrace |
| Configuration | Config file | Environment vars |
| Works with setuid | No | Yes |

---

## 7. Success Metrics

1. **Correctness**: All TCP connections go through the specified proxy
2. **Transparency**: Target programs work without modification
3. **Reliability**: No crashes or deadlocks under normal use
4. **Performance**: < 10% overhead compared to direct connection
5. **POSIX Compliance**: Follows standard Unix conventions
6. **Usability**: Works with existing proxy configurations

---

## 8. Name Candidates

| Name | Meaning | Typing | Reason |
|------|---------|--------|--------|
| **proxec** | proxy + exec | 6 chars | Clear, memorable, likely unique |
| **tprox** | transparent proxy | 5 chars | Short, clear |
| **pwrap** | proxy wrapper | 5 chars | Very short |

**Recommendation:** `proxec`

---

## 9. References

- [GNU Coding Standards](https://www.gnu.org/prep/standards/)
- [POSIX Utility Conventions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html)
- [GNU Program Arguments](https://www.gnu.org/software/libc/manual/html_node/Argument-Syntax.html)
- [sysexits.h](https://man7.org/linux/man-pages/man3/sysexits.h.3head.html)
- [RFC 7231 - HTTP/1.1: CONNECT](https://tools.ietf.org/html/rfc7231)
- [RFC 1928 - SOCKS5](https://tools.ietf.org/html/rfc1928)
