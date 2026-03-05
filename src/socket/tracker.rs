// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Socket state tracking.

use nix::unistd::Pid;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Key to identify a socket in a process.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SocketKey {
    pub pid: Pid,
    pub fd: i32,
}

impl SocketKey {
    pub fn new(pid: Pid, fd: i32) -> Self {
        Self { pid, fd }
    }
}

/// Information about an intercepted socket.
#[derive(Debug, Clone)]
pub struct SocketInfo {
    /// Original destination address.
    pub dest: SocketAddr,
}

/// Thread-safe socket tracker.
pub struct SocketTracker {
    /// Mapping from (pid, fd) to socket info.
    sockets: HashMap<SocketKey, SocketInfo>,
}

impl SocketTracker {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
        }
    }

    /// Store socket info for a pending connection.
    pub fn insert(&mut self, key: SocketKey, info: SocketInfo) {
        self.sockets.insert(key, info);
    }

    /// Get socket info.
    pub fn get(&self, key: &SocketKey) -> Option<&SocketInfo> {
        self.sockets.get(key)
    }

    /// Remove and return socket info.
    pub fn remove(&mut self, key: &SocketKey) -> Option<SocketInfo> {
        self.sockets.remove(key)
    }

    /// Clean up all sockets for a process.
    pub fn cleanup_process(&mut self, pid: Pid) {
        self.sockets.retain(|k, _| k.pid != pid);
    }

    /// Get iterator over all sockets.
    pub fn sockets(&self) -> impl Iterator<Item = (&SocketKey, &SocketInfo)> {
        self.sockets.iter()
    }
}

impl Default for SocketTracker {
    fn default() -> Self {
        Self::new()
    }
}
