# proxec - Transparent Proxy Executor

Transparently proxy TCP connections of any program through HTTP/SOCKS5 proxy.

## Features

- Single binary, no dependencies
- Uses standard environment variables (`http_proxy`, `all_proxy`, etc.)
- IPv6 disabled by default for reliability
- Silent operation (POSIX compliant)
- Works with setuid binaries (unlike LD_PRELOAD solutions)

## Usage

```bash
# Set proxy via environment variables (standard Unix way)
export http_proxy=http://192.168.1.1:8080
export https_proxy=http://192.168.1.1:8080
proxec curl https://example.com

# Or inline
http_proxy=http://proxy:8080 proxec wget https://example.com

# SOCKS5 proxy
all_proxy=socks5://127.0.0.1:1080 proxec chromium

# With authentication
http_proxy=http://user:pass@proxy:8080 proxec curl https://ifconfig.me
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `http_proxy` / `HTTP_PROXY` | Proxy for HTTP |
| `https_proxy` / `HTTPS_PROXY` | Proxy for HTTPS |
| `all_proxy` / `ALL_PROXY` | Proxy for all protocols |
| `no_proxy` / `NO_PROXY` | Bypass list |
| `PROXEC_IPV6` | Set to "1" to enable IPv6 |

## Options

```
Usage: proxec [OPTION]... COMMAND [ARG]...

Options:
  -v, --verbose     verbose operation
  -q, --quiet       suppress non-error output
  -d, --debug       debug output
  -6, --ipv6        enable IPv6 proxying
  -h, --help        display help and exit
  -V, --version     output version and exit
```

## Installation

```bash
make
sudo make install
```

## Requirements

- Linux x86_64 or aarch64
- Kernel 4.8+ recommended

## License

GPL-2.0-only

## See Also

- [Documentation](docs/)
- [Contributing](CONTRIBUTING.md)
