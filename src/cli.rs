// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Command-line argument parsing.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "proxec",
    author,
    version,
    about = "Transparently proxy TCP connections through HTTP/SOCKS5",
    long_about = None
)]
pub struct Args {
    /// Proxy URL (e.g., http://127.0.0.1:8080)
    #[arg(short = 'x', long = "proxy")]
    pub proxy: String,

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
