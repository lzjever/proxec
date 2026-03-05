// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Syscall handling and trace loop.

use crate::error::{Error, Result};
use crate::socket::{SocketInfo, SocketKey, SocketTracker};
use crate::tracer::{
    get_regs, get_syscall_arg, get_syscall_nr, read_sockaddr, write_sockaddr,
};
use crate::tracer::arch_x86_64::syscall::CONNECT;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// State for tracking whether we're entering or exiting a syscall.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SyscallState {
    Entering,
    Exiting,
}

/// Run the trace loop.
pub fn run(
    child_pid: Pid,
    tracker: Arc<Mutex<SocketTracker>>,
    local_addr: SocketAddr,
) -> Result<i32> {
    let mut state = SyscallState::Entering;
    let mut exit_code = 0;

    loop {
        let status = waitpid(child_pid, None).map_err(Error::Wait)?;

        match status {
            WaitStatus::Exited(pid, code) => {
                tracing::debug!("Process {pid} exited with code {code}");
                exit_code = code;
                break;
            }
            WaitStatus::Signaled(pid, sig, _) => {
                tracing::debug!("Process {pid} killed by signal {sig}");
                exit_code = 128 + sig as i32;
                break;
            }
            WaitStatus::Stopped(pid, Signal::SIGSTOP) => {
                // Initial stop - set ptrace options
                ptrace::setoptions(
                    pid,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK,
                )
                .map_err(Error::Ptrace)?;
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::PtraceSyscall(pid) => {
                handle_syscall(pid, &mut state, &tracker, &local_addr)?;
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::Stopped(pid, sig) => {
                // Deliver signal to child
                ptrace::syscall(pid, sig).map_err(Error::Ptrace)?;
            }
            _ => {
                tracing::debug!("Unexpected wait status: {:?}", status);
                ptrace::syscall(child_pid, None).map_err(Error::Ptrace)?;
            }
        }
    }

    Ok(exit_code)
}

fn handle_syscall(
    pid: Pid,
    state: &mut SyscallState,
    tracker: &Arc<Mutex<SocketTracker>>,
    local_addr: &SocketAddr,
) -> Result<()> {
    let regs = get_regs(pid)?;
    let syscall_nr = get_syscall_nr(&regs);

    match state {
        SyscallState::Entering => {
            if syscall_nr == CONNECT {
                handle_connect_enter(pid, &regs, tracker, local_addr)?;
            }
            *state = SyscallState::Exiting;
        }
        SyscallState::Exiting => {
            *state = SyscallState::Entering;
        }
    }

    Ok(())
}

fn handle_connect_enter(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
    local_addr: &SocketAddr,
) -> Result<()> {
    let sockfd = get_syscall_arg(regs, 0) as i32;
    let addr_ptr = get_syscall_arg(regs, 1);
    let addrlen = get_syscall_arg(regs, 2);

    // Read the destination address
    let dest = match read_sockaddr(pid, addr_ptr, addrlen) {
        Ok(addr) => addr,
        Err(Error::UnknownAddressFamily(_)) => {
            // Not IPv4/IPv6, let it pass through
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    tracing::debug!("connect({sockfd}, {dest})");

    // Store the original destination
    let key = SocketKey::new(pid, sockfd);
    let info = SocketInfo { dest };
    tracker.lock().unwrap().insert(key, info);

    // Rewrite the address to point to our local proxy
    write_sockaddr(pid, addr_ptr, local_addr)?;

    tracing::debug!("redirected to {local_addr}");

    Ok(())
}
