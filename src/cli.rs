// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Command-line argument parsing.

use clap::{ArgAction, Parser};

#[derive(Parser, Debug)]
#[command(
    name = "proxec",
    author,
    version,
    about = "Transparently proxy TCP connections through HTTP/SOCKS5",
    long_about = None
)]
pub struct Args {
    /// Proxy URL (e.g., http://127.0.0.1:8080 or socks://127.0.0.1:1080)
    #[arg(short = 'x', long = "proxy")]
    pub proxy: String,

    /// Disable IPv6 connections and force applications to fall back to IPv4.
    #[arg(long = "disable-ipv6")]
    pub disable_ipv6: bool,

    /// Comma-separated targets that should bypass the proxy.
    #[arg(long = "no-proxy", value_name = "RULES", value_delimiter = ',', action = ArgAction::Append)]
    pub no_proxy: Vec<String>,

    /// Deprecated compatibility flag. IPv6 is allowed by default.
    #[arg(long = "allow-ipv6", hide = true)]
    pub allow_ipv6_compat: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Debug output
    #[arg(short, long)]
    pub debug: bool,

    /// Command to execute
    #[arg(required = true)]
    pub command: String,

    /// Arguments for the command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn parse() -> Args {
    Args::parse()
}
