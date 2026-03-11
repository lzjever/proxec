# Changelog

All notable changes documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.1.0] - 2026-03-11

### Added
- Dead-simple Linux-native transparent proxying through HTTP CONNECT and SOCKS5
- `--proxy` based upstream configuration for apps that do not support proxies
- `--no-proxy` bypass rules for IPs, CIDRs, `localhost`, `*`, and startup-resolved concrete hostnames
- IPv4 fallback mode via `--disable-ipv6`
- Release packaging script and GitHub Actions CI/release workflows

### Changed
- Ignore system proxy environment variables at runtime and warn when they are present
- Improve traced socket lookup performance by caching socket inode to destination mappings
- Rewrite project README and release docs for first public release

### Fixed
- Terminate traced process groups on `SIGINT`, `SIGTERM`, and `SIGHUP`
- Exit when the traced process set becomes empty
- Recover from ptrace teardown anomalies such as `waitpid(__WALL)` returning `EINVAL`
- Restrict residual force-drain behavior to abnormal teardown states instead of normal Chromium/Electron startup patterns
