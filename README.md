# proxec - Transparent Proxy Executor

Transparently proxy TCP connections of any program through HTTP/SOCKS5 proxy.

## Features

- Single binary, no dependencies
- Explicit upstream proxy via `--proxy`
- Optional `--no-proxy` bypass rules for loopback/LAN/IP ranges and concrete hostnames
- IPv6 disabled by default for reliability
- Silent operation (POSIX compliant)
- Works with setuid binaries (unlike LD_PRELOAD solutions)

## Usage

```bash
# SOCKS5 proxy
proxec --proxy socks://127.0.0.1:1080 chromium

# With authentication
proxec --proxy http://user:pass@proxy:8080 curl https://ifconfig.me

# Bypass local and LAN targets
proxec --proxy socks://127.0.0.1:1080 --no-proxy 127.0.0.1,192.168.0.0/16 curl http://192.168.1.10
```

## Notes

- `proxec` ignores standard proxy environment variables like `http_proxy` and `all_proxy`.
- If they are present, `proxec` prints a warning and still uses only `--proxy`.
- `--no-proxy` supports IPs, CIDR ranges, `localhost`, `*`, and concrete hostnames such as `jira.internal`.
- Concrete hostnames are resolved once at startup and matched by their resolved IPs.
- Domain suffix patterns like `.example.com` are not supported yet and trigger a warning.
- Startup hostname resolution is best-effort: DNS changes, rotating records, and app-specific resolvers can diverge from what `proxec` saw at launch.

## Environment Variables

| Variable | Purpose |
|----------|---------|
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
