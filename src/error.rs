// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Error types with POSIX exit codes.

use std::ffi::NulError;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("no proxy configured")]
    NoProxy,

    #[error("invalid proxy URL: {0}")]
    InvalidProxyUrl(String),

    #[error("fork failed: {0}")]
    Fork(#[source] nix::Error),

    #[error("ptrace error: {0}")]
    Ptrace(#[source] nix::Error),

    #[error("exec failed: {0}")]
    Exec(#[source] io::Error),

    #[error("wait failed: {0}")]
    Wait(#[source] nix::Error),

    #[error("failed to read child memory: {0}")]
    MemoryRead(#[source] nix::Error),

    #[error("failed to write child memory: {0}")]
    MemoryWrite(#[source] nix::Error),

    #[error("unknown address family: {0}")]
    UnknownAddressFamily(u16),

    #[error("proxy connection failed: {0}")]
    ProxyConnect(#[source] io::Error),

    #[error("HTTP proxy error: {0}")]
    HttpProxy(String),

    #[error("SOCKS5 proxy error: {0}")]
    SocksProxy(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("nul byte in string: {0}")]
    NulByte(#[from] NulError),
}

impl Error {
    /// Return POSIX exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NoProxy => 0,
            Self::InvalidProxyUrl(_) => 2,
            Self::ProxyConnect(_) => 69,  // EX_UNAVAILABLE
            Self::Ptrace(_) => 77,        // EX_NOPERM
            Self::Exec(_) => 126,
            _ => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
