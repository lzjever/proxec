# Changelog

All notable changes documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Initial implementation

### Changed
- Ignore system proxy environment variables at runtime and warn when they are present
- Add `--no-proxy` support for IPs, CIDRs, and startup-resolved concrete hostnames
- Improve traced socket lookup performance by caching socket inode to destination mappings

### Fixed
- Terminate traced process groups on `SIGINT`/`SIGTERM`/`SIGHUP`
- Exit when the traced process set becomes empty
- Recover from `waitpid(__WALL)` teardown anomalies such as `EINVAL` by draining residual traced tasks instead of hanging

## [0.1.0] - YYYY-MM-DD

### Added
- Initial release
- HTTP CONNECT proxy support
- SOCKS5 proxy support
- Standard environment variable support
- IPv6 support (disabled by default)
