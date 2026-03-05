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
