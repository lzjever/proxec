// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Syscall handling and trace loop.

use crate::error::{Error, Result};
use crate::socket::{SocketInfo, SocketKey, SocketTracker};
use crate::tracer::{get_regs, get_syscall_arg, get_syscall_nr, write_sockaddr};
use crate::tracer::arch_x86_64::syscall::CONNECT;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
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
    // Track syscall state per thread
    let mut thread_states: HashMap<i32, SyscallState> = HashMap::new();
    let mut exit_code = 0;

    loop {
        // Wait for any child (including cloned threads)
        match waitpid(Pid::from_raw(-1), None).map_err(Error::Wait)? {
            WaitStatus::Exited(pid, code) => {
                tracing::debug!("Process {pid} exited with code {code}");
                thread_states.remove(&pid.as_raw());
                if pid == child_pid {
                    exit_code = code;
                    break;
                }
                // Cloned thread exited, continue waiting
            }
            WaitStatus::Signaled(pid, sig, _) => {
                tracing::debug!("Process {pid} killed by signal {sig}");
                thread_states.remove(&pid.as_raw());
                if pid == child_pid {
                    exit_code = 128 + sig as i32;
                    break;
                }
                // Cloned thread killed, continue waiting
            }
            WaitStatus::PtraceSyscall(pid) => {
                let state = thread_states.entry(pid.as_raw()).or_insert(SyscallState::Entering);
                handle_syscall(pid, state, &tracker, &local_addr)?;
                // Continue tracing
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::PtraceEvent(pid, _sig, event) => {
                // Ptrace events (EXEC, CLONE, FORK, etc.) - just continue
                tracing::debug!("PtraceEvent for pid {pid}, event={event}, continuing");
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::Stopped(pid, Signal::SIGSTOP) => {
                // Initial stop after exec - set ptrace options
                tracing::debug!("Initial SIGSTOP for pid {pid}");
                ptrace::setoptions(
                    pid,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEEXEC
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_TRACESYSGOOD,
                )
                .map_err(Error::Ptrace)?;
                // Continue tracing
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                // SIGTRAP from exec or other ptrace events - don't deliver, just continue
                tracing::debug!("SIGTRAP for pid {pid}, continuing");
                ptrace::syscall(pid, None).map_err(Error::Ptrace)?;
            }
            WaitStatus::Stopped(pid, sig) => {
                // Deliver signal to child
                tracing::debug!("Delivering signal {:?} to pid {}", sig, pid);
                ptrace::syscall(pid, sig).map_err(Error::Ptrace)?;
            }
            _other => {
                tracing::debug!("Unexpected wait status");
                // Continue anyway - just be safe
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
    let dest = match crate::tracer::memory::read_sockaddr(pid, addr_ptr, addrlen) {
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
