// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! proxec entry point.

use proxec::cli;
use proxec::env;
use proxec::error::{Error, Result};
use proxec::no_proxy::NoProxy;
use proxec::proxy::{local, ProxyConfig};
use proxec::socket::SocketTracker;
use proxec::tracer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

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

    let no_proxy = NoProxy::parse(&args.no_proxy)?;
    if !no_proxy.unsupported_suffix_patterns().is_empty() {
        tracing::warn!(
            patterns = %no_proxy.unsupported_suffix_patterns().join(", "),
            "Ignoring no-proxy domain suffix patterns; only concrete hostnames can be resolved at startup"
        );
    }
    if !no_proxy.unresolved_hostnames().is_empty() {
        tracing::warn!(
            hostnames = %no_proxy.unresolved_hostnames().join(", "),
            "Some no-proxy hostnames could not be resolved at startup and will not bypass the proxy"
        );
    }

    let ignored_proxy_env = env::clear_proxy_env();
    if ignored_proxy_env.has_ignored_vars() {
        tracing::warn!(
            ignored = %ignored_proxy_env.ignored_vars().join(", "),
            "Ignoring system proxy environment variables; only --proxy is used"
        );
    }

    // Parse proxy URL
    let proxy = ProxyConfig::parse(&args.proxy)?;
    let proxy_addr = proxy.addr;

    tracing::info!("Using proxy: {} ({:?})", proxy_addr, proxy.protocol);

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
        if let Err(e) = local::run(local_listener, tracker_clone, proxy).await {
            tracing::error!("Local proxy error: {}", e);
        }
    });

    let use_seccomp = tracer::is_available();
    tracing::info!(
        "Tracing mode: {}",
        if use_seccomp {
            "seccomp-bpf + ptrace syscall exit"
        } else {
            "full ptrace syscall tracing"
        }
    );

    // Fork and exec child process
    let child_pid = tracer::fork_exec(&args.command, &args.args, use_seccomp)?;
    tracing::info!(
        "Started child process: {} (pid {})",
        args.command,
        child_pid
    );

    // Run tracer loop (blocking)
    let disable_ipv6 = args.disable_ipv6 && !args.allow_ipv6_compat;
    let exit_code = tracer::run(
        child_pid,
        tracker,
        local_addr,
        proxy_addr,
        no_proxy,
        disable_ipv6,
        use_seccomp,
    )?;

    tracing::info!("Child exited with code {}", exit_code);

    std::process::exit(exit_code);
}
