# proxec

**Dead simple transparent proxying for Linux apps that were never built for proxies.**

`proxec` is a Linux-native wrapper that intercepts TCP connections and pushes them through an HTTP CONNECT or SOCKS5 proxy without TUN devices, without desktop-wide hacks, and without asking the target app to support proxy settings.

It is the practical answer for apps like:

- `antigravity`
- Electron / Chromium apps
- closed-source launchers
- GUI tools with no proxy UI
- binaries that ignore `http_proxy`

## Why It Grabs Attention

- **Dead simple**: one binary, one command, no TUN setup
- **Linux-native**: built around `ptrace` and syscall interception
- **Perfect TUN replacement for many app-proxying jobs**: no routing tables, no fake system-wide VPN layer, no per-app proxy support required
- **Works where env vars do not**: targets can be completely unaware of proxies
- **Built for messy real apps**: handles Electron/Chromium-style process trees and teardown better than toy wrappers
- **MIT licensed**

## What It Looks Like

```bash
proxec --proxy socks://127.0.0.1:21089 antigravity
```

```bash
proxec --proxy http://127.0.0.1:8080 curl https://example.com
```

```bash
proxec \
  --proxy socks://127.0.0.1:21089 \
  --no-proxy localhost,127.0.0.1,192.168.0.0/16,jira.internal \
  --disable-ipv6 \
  antigravity
```

## Why Not TUN

TUN mode is powerful, but for this problem it is often the wrong hammer.

With `proxec` you do not need:

- kernel routing changes
- policy routing rules
- fake system-wide VPN behavior
- a full traffic capture stack just to proxy one process

If your real goal is "run this one Linux app through this one proxy", `proxec` is often the cleaner path.

## Features

- transparent TCP proxying through HTTP CONNECT and SOCKS5
- Linux-native `ptrace`-based interception
- explicit upstream proxy via `--proxy`
- `--no-proxy` bypass rules for IPs, CIDRs, `localhost`, `*`, and startup-resolved concrete hostnames
- optional IPv4-forcing behavior via `--disable-ipv6`
- process-tree aware tracing for multi-process apps
- structured shutdown and teardown recovery for complex Chromium/Electron exits
- no dependency on TUN/TAP, LD_PRELOAD, or desktop proxy support

## Examples

### Proxy a GUI app with no native proxy settings

```bash
proxec --proxy socks://127.0.0.1:21089 antigravity
```

### Proxy Chromium through SOCKS5

```bash
proxec --proxy socks://127.0.0.1:1080 chromium
```

### Proxy `curl` through HTTP CONNECT

```bash
proxec --proxy http://127.0.0.1:8080 curl https://ifconfig.me
```

### Keep local and LAN services direct

```bash
proxec \
  --proxy socks://127.0.0.1:21089 \
  --no-proxy localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
  antigravity
```

## Important Behavior

- `proxec` ignores standard proxy environment variables such as `http_proxy`, `https_proxy`, `all_proxy`, and `no_proxy`
- if those variables are present, `proxec` prints a warning and still uses only `--proxy`
- concrete hostnames in `--no-proxy` are resolved once at startup and then matched by IP
- domain suffix patterns like `.example.com` are not supported yet and trigger a warning
- complex GUI apps can produce noisy multi-process teardown; `proxec` includes recovery logic to avoid hanging forever when ptrace teardown enters an abnormal state

## Installation

```bash
cargo build --release
install -Dm755 target/release/proxec /usr/local/bin/proxec
```

## Development

```bash
cargo test
cargo build --release
make dist
```

## Release Artifacts

GitHub Actions is configured to:

- run CI on pushes and pull requests
- build a Linux release tarball on version tags
- publish release assets automatically on tag push

See [docs/RELEASING.md](docs/RELEASING.md).

## License

MIT. See [LICENSE](LICENSE).
