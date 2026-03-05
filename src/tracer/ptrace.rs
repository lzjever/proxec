// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! ptrace setup and child process management.

use crate::error::{Error, Result};
use nix::sys::ptrace;
use nix::unistd::{fork, Pid};
use std::ffi::CString;

/// Fork and exec a child process with ptrace enabled.
pub fn fork_exec(command: &str, args: &[String]) -> Result<Pid> {
    match unsafe { fork() }.map_err(Error::Fork)? {
        nix::unistd::ForkResult::Parent { child } => {
            tracing::debug!("Forked child process: {child}");
            Ok(child)
        }
        nix::unistd::ForkResult::Child => {
            // Child process
            ptrace::traceme().expect("ptrace TRACEME failed");

            // Stop ourselves so parent can set options
            nix::sys::signal::raise(nix::sys::signal::SIGSTOP)
                .expect("raise SIGSTOP failed");

            // Build argument vector
            let c_cmd = CString::new(command).unwrap();
            let c_args: Vec<CString> = std::iter::once(c_cmd.clone())
                .chain(args.iter().map(|s| CString::new(s.as_str()).unwrap()))
                .collect();

            // Exec the target program
            nix::unistd::execvp(&c_cmd, &c_args)
                .expect("execvp failed");

            unreachable!()
        }
    }
}
