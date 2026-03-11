// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Syscall handling and trace loop.
//!
//! With seccomp-bpf (kernel >= 4.8), uses seccomp filtering which is
//! inherited by all child processes automatically, making multi-process
//! tracing reliable.
//!
//! Without seccomp-bpf, falls back to PTRACE_SYSCALL mode.

use crate::error::{Error, Result};
use crate::no_proxy::NoProxy;
use crate::socket::{probe_socket_is_stream, read_socket_inode, SocketInfo, SocketTracker};
use crate::tracer::{
    get_ptrace_event_msg, get_regs, get_return_value, get_syscall_arg, get_syscall_nr, set_regs,
    set_return_value, set_syscall_arg, write_sockaddr,
};
use crate::tracer::arch_x86_64::syscall::{CLONE, CLONE3, CLOSE, CONNECT, SOCKET};
use nix::sys::ptrace;
use nix::sys::signal::{self, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SHUTDOWN_SIGNAL: AtomicI32 = AtomicI32::new(0);
static SHUTDOWN_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq)]
enum SyscallPhase {
    Entering,
    Exiting,
}

#[derive(Debug, Clone, Copy)]
struct ThreadState {
    phase: SyscallPhase,
    forced_connect_errno: Option<i32>,
    pending_connect_restore: Option<PendingConnectRestore>,
}

#[derive(Debug, Clone, Copy)]
struct PendingConnectRestore {
    addr_ptr: u64,
    dest: SocketAddr,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            phase: SyscallPhase::Entering,
            forced_connect_errno: None,
            pending_connect_restore: None,
        }
    }
}

#[derive(Default, Debug)]
struct TraceStats {
    connect_seen: u64,
    connect_unknown_family_skipped: u64,
    connect_non_stream_skipped: u64,
    connect_stream_probed: u64,
    connect_ipv6_blocked: u64,
    connect_loopback_skipped: u64,
    connect_unspecified_skipped: u64,
    connect_port0_skipped: u64,
    connect_upstream_skipped: u64,
    connect_rewritten: u64,
    socket_enter_seen: u64,
    socket_exit_seen: u64,
}

#[derive(Debug, Clone, Copy)]
struct ShutdownState {
    signal: Signal,
    started_at: Instant,
    escalated: bool,
}

extern "C" fn handle_shutdown_signal(sig: i32) {
    if SHUTDOWN_SIGNAL.load(Ordering::SeqCst) == 0 {
        SHUTDOWN_SIGNAL.store(sig, Ordering::SeqCst);
    }
    SHUTDOWN_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn install_shutdown_handlers() -> Result<()> {
    let action = SigAction::new(
        SigHandler::Handler(handle_shutdown_signal),
        signal::SaFlags::empty(),
        SigSet::empty(),
    );
    for sig in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        unsafe {
            signal::sigaction(sig, &action).map_err(Error::Ptrace)?;
        }
    }
    SHUTDOWN_SIGNAL.store(0, Ordering::SeqCst);
    SHUTDOWN_COUNT.store(0, Ordering::SeqCst);
    Ok(())
}

fn pending_shutdown_signal() -> Option<Signal> {
    match SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        0 => None,
        libc::SIGINT => Some(Signal::SIGINT),
        libc::SIGTERM => Some(Signal::SIGTERM),
        libc::SIGHUP => Some(Signal::SIGHUP),
        _ => Some(Signal::SIGTERM),
    }
}

fn terminate_active_tracees(
    active_pids: &mut std::collections::HashSet<i32>,
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
    use_seccomp: bool,
    signal: Signal,
) {
    let pids: Vec<i32> = active_pids.iter().copied().collect();
    for raw_pid in pids {
        let pid = Pid::from_raw(raw_pid);
        let _ = signal::kill(pid, signal);
        let result = if use_seccomp {
            ptrace::cont(pid, Some(signal))
        } else {
            ptrace::syscall(pid, Some(signal))
        };
        match result {
            Ok(()) => {}
            Err(err) if is_esrch_nix(&err) => {
                cleanup_dead_tracee(pid, thread_states, tracker, active_pids);
            }
            Err(_) => {}
        }
    }
}

fn kill_active_tracees(
    active_pids: &mut std::collections::HashSet<i32>,
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
) {
    let pids: Vec<i32> = active_pids.iter().copied().collect();
    for raw_pid in pids {
        let pid = Pid::from_raw(raw_pid);
        let _ = signal::kill(pid, Signal::SIGKILL);
        let result = ptrace::kill(pid);
        match result {
            Ok(()) => {}
            Err(err) if is_esrch_nix(&err) => {
                cleanup_dead_tracee(pid, thread_states, tracker, active_pids);
            }
            Err(_) => {}
        }
    }
}

fn begin_shutdown(
    pgid: Pid,
    signal: Signal,
    active_pids: &mut std::collections::HashSet<i32>,
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
    use_seccomp: bool,
) {
    tracing::warn!(
        "Received {}; terminating traced process group {}",
        signal.as_str(),
        pgid
    );
    let _ = signal::killpg(pgid, Signal::SIGTERM);
    terminate_active_tracees(active_pids, thread_states, tracker, use_seccomp, Signal::SIGTERM);
}

fn escalate_shutdown(
    pgid: Pid,
    active_pids: &mut std::collections::HashSet<i32>,
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
) {
    tracing::warn!("Shutdown timeout exceeded; force-killing process group {}", pgid);
    let _ = signal::killpg(pgid, Signal::SIGKILL);
    kill_active_tracees(active_pids, thread_states, tracker);
}

fn update_shutdown_state(
    shutdown: &mut Option<ShutdownState>,
    pgid: Pid,
    exit_code: &mut i32,
    active_pids: &mut std::collections::HashSet<i32>,
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
    use_seccomp: bool,
) {
    let Some(signal) = pending_shutdown_signal() else {
        return;
    };

    if shutdown.is_none() {
        begin_shutdown(
            pgid,
            signal,
            active_pids,
            thread_states,
            tracker,
            use_seccomp,
        );
        *exit_code = 128 + signal as i32;
        *shutdown = Some(ShutdownState {
            signal,
            started_at: Instant::now(),
            escalated: false,
        });
        return;
    }

    let Some(state) = shutdown.as_mut() else {
        return;
    };
    if !state.escalated
        && (SHUTDOWN_COUNT.load(Ordering::SeqCst) > 1 || state.started_at.elapsed() >= Duration::from_secs(2))
    {
        escalate_shutdown(pgid, active_pids, thread_states, tracker);
        state.escalated = true;
    }
}

fn ptrace_options(use_seccomp: bool) -> ptrace::Options {
    let mut options = ptrace::Options::PTRACE_O_TRACECLONE
        | ptrace::Options::PTRACE_O_TRACEEXEC
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK
        | ptrace::Options::PTRACE_O_TRACESYSGOOD;
    if use_seccomp {
        options |= ptrace::Options::PTRACE_O_TRACESECCOMP;
    }
    options
}

/// Helper to set ptrace options for a new process.
fn setup_ptrace_options(pid: Pid, use_seccomp: bool) {
    let options = ptrace_options(use_seccomp);

    match ptrace::setoptions(pid, options) {
        Ok(()) => {
            tracing::debug!("Set ptrace options for pid {pid}");
        }
        Err(e) => {
            tracing::warn!("Failed to set ptrace options for pid {pid}: {e}");
        }
    }
}

fn cleanup_dead_tracee(
    pid: Pid,
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
    active_pids: &mut std::collections::HashSet<i32>,
) {
    thread_states.remove(&pid.as_raw());
    tracker.lock().unwrap().cleanup_process(pid);
    active_pids.remove(&pid.as_raw());
}

fn prune_gone_tracees(
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
    active_pids: &mut std::collections::HashSet<i32>,
) {
    let gone: Vec<i32> = active_pids
        .iter()
        .copied()
        .filter(|pid| std::fs::metadata(format!("/proc/{pid}")).is_err())
        .collect();

    for raw_pid in gone {
        cleanup_dead_tracee(Pid::from_raw(raw_pid), thread_states, tracker, active_pids);
    }
}

fn is_esrch_io(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::ESRCH)
}

fn is_esrch_nix(err: &nix::errno::Errno) -> bool {
    *err == nix::errno::Errno::ESRCH
}

fn wait_for_tracee() -> std::result::Result<WaitStatus, nix::errno::Errno> {
    waitpid(
        Pid::from_raw(-1),
        Some(WaitPidFlag::__WALL | WaitPidFlag::WSTOPPED),
    )
}

fn poll_known_tracees(
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
    active_pids: &mut std::collections::HashSet<i32>,
) {
    let pids: Vec<i32> = active_pids.iter().copied().collect();
    for raw_pid in pids {
        let pid = Pid::from_raw(raw_pid);
        match waitpid(
            pid,
            Some(WaitPidFlag::__WALL | WaitPidFlag::WSTOPPED | WaitPidFlag::WNOHANG),
        ) {
            Ok(WaitStatus::StillAlive) => {}
            Ok(WaitStatus::Exited(done_pid, _)) | Ok(WaitStatus::Signaled(done_pid, _, _)) => {
                cleanup_dead_tracee(done_pid, thread_states, tracker, active_pids);
            }
            Ok(_) => {}
            Err(err) if err == nix::errno::Errno::ECHILD || err == nix::errno::Errno::ESRCH => {
                cleanup_dead_tracee(pid, thread_states, tracker, active_pids);
            }
            Err(_) => {}
        }
    }
}

fn resume_tracee(
    pid: Pid,
    sig: Option<Signal>,
    use_seccomp: bool,
    thread_states: &mut std::collections::HashMap<i32, ThreadState>,
    tracker: &Arc<Mutex<SocketTracker>>,
    active_pids: &mut std::collections::HashSet<i32>,
) -> Result<()> {
    let should_trace_exit = thread_states
        .get(&pid.as_raw())
        .map(|state| state.phase == SyscallPhase::Exiting)
        .unwrap_or(false);
    let resume = if use_seccomp && !should_trace_exit {
        ptrace::cont(pid, sig)
    } else {
        ptrace::syscall(pid, sig)
    };

    match resume {
        Ok(()) => Ok(()),
        Err(err) if is_esrch_nix(&err) => {
            tracing::debug!("Tracee {pid} disappeared before resume");
            cleanup_dead_tracee(pid, thread_states, tracker, active_pids);
            Ok(())
        }
        Err(err) => Err(Error::Ptrace(err)),
    }
}

/// Run the trace loop.
///
/// Continues tracing until ALL descendant processes have exited.
/// This is important for programs like Electron apps where the main process
/// exits but child processes continue running.
pub fn run(
    child_pid: Pid,
    tracker: Arc<Mutex<SocketTracker>>,
    local_addr: SocketAddr,
    proxy_addr: SocketAddr,
    no_proxy: NoProxy,
    disable_ipv6: bool,
    use_seccomp: bool,
) -> Result<i32> {
    install_shutdown_handlers()?;
    let mut thread_states: std::collections::HashMap<i32, ThreadState> = std::collections::HashMap::new();
    let mut stats = TraceStats::default();
    let mut shutdown: Option<ShutdownState> = None;
    let mut main_exited = false;
    let process_group = child_pid;
    // Track all active traced processes
    let mut active_pids: std::collections::HashSet<i32> = std::collections::HashSet::new();
    active_pids.insert(child_pid.as_raw());

    tracing::info!(
        "Using {} for syscall interception",
        if use_seccomp {
            "seccomp-bpf filtered tracing"
        } else {
            "PTRACE_SYSCALL mode"
        }
    );

    let mut exit_code = 0;

    loop {
        prune_gone_tracees(&mut thread_states, &tracker, &mut active_pids);
        if active_pids.is_empty() {
            tracing::debug!("All traced processes have exited");
            break;
        }
        update_shutdown_state(
            &mut shutdown,
            process_group,
            &mut exit_code,
            &mut active_pids,
            &mut thread_states,
            &tracker,
            use_seccomp,
        );
        // Wait for any traced task, including clone()-created threads.
        match wait_for_tracee() {
            Ok(WaitStatus::Exited(pid, code)) => {
                tracing::debug!("Process {pid} exited with code {code}");
                cleanup_dead_tracee(pid, &mut thread_states, &tracker, &mut active_pids);

                if pid == child_pid {
                    exit_code = code;
                    main_exited = true;
                    // Don't break! Continue tracing other descendants
                    tracing::debug!("Main process exited, but continuing to trace {} remaining processes", active_pids.len());
                }

                // Check if all processes have exited
                if active_pids.is_empty() {
                    tracing::debug!("All traced processes have exited");
                    break;
                }
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                tracing::debug!("Process {pid} killed by signal {sig}");
                cleanup_dead_tracee(pid, &mut thread_states, &tracker, &mut active_pids);

                if pid == child_pid {
                    exit_code = 128 + sig as i32;
                    main_exited = true;
                    tracing::debug!("Main process killed, but continuing to trace {} remaining processes", active_pids.len());
                }

                if active_pids.is_empty() {
                    tracing::debug!("All traced processes have exited");
                    break;
                }
            }
            Ok(WaitStatus::PtraceEvent(pid, _sig, event)) => {
                // Check if this is a new process we haven't seen
                let is_new = !active_pids.contains(&pid.as_raw());
                if is_new {
                    tracing::info!("New traced process from PtraceEvent: {pid} (event={event})");
                    active_pids.insert(pid.as_raw());
                    // set ptrace options for the new process - this is crucial!
                    // Without PTRACE_O_TRACESECCOMP, seccomp events won't be reported
                    setup_ptrace_options(pid, use_seccomp);
                }
                if event == libc::PTRACE_EVENT_SECCOMP as i32 {
                    let state = thread_states.entry(pid.as_raw()).or_default();
                    if let Err(err) = handle_syscall_enter(
                        pid,
                        &get_regs(pid)?,
                        &tracker,
                        &local_addr,
                        &proxy_addr,
                        &no_proxy,
                        disable_ipv6,
                        state,
                        &mut stats,
                    ) {
                        if matches!(&err, Error::Io(io_err) if is_esrch_io(io_err)) {
                            tracing::debug!("Tracee {pid} disappeared during seccomp handling");
                            cleanup_dead_tracee(pid, &mut thread_states, &tracker, &mut active_pids);
                            continue;
                        }
                        return Err(err);
                    }
                    state.phase = SyscallPhase::Exiting;
                } else if event == libc::PTRACE_EVENT_FORK as i32
                    || event == libc::PTRACE_EVENT_VFORK as i32
                    || event == libc::PTRACE_EVENT_CLONE as i32
                {
                    // Other ptrace events (EXEC, CLONE, FORK, VFORK)
                    // For clone/fork events, get the new child PID and set options for it too
                    // Get the new child's PID using PTRACE_GETEVENTMSG
                    let child_pid = get_ptrace_event_msg(pid)?;
                    let child_pid = Pid::from_raw(child_pid as i32);
                    if !active_pids.contains(&child_pid.as_raw()) {
                        tracing::info!("New child process from fork/clone: {child_pid} (parent={pid})");
                        active_pids.insert(child_pid.as_raw());
                        // The child will get a SIGSTOP, we'll set options then
                    }
                }
                tracing::trace!("PtraceEvent for pid {pid}, event={event}");
                resume_tracee(
                    pid,
                    None,
                    use_seccomp,
                    &mut thread_states,
                    &tracker,
                    &mut active_pids,
                )?;
            }
            Ok(WaitStatus::PtraceSyscall(pid)) => {
                // New process we haven't seen? Add to tracking
                if !active_pids.contains(&pid.as_raw()) {
                    tracing::debug!("New traced process from syscall: {pid}");
                    active_pids.insert(pid.as_raw());
                }

                let state = thread_states
                    .entry(pid.as_raw())
                    .or_default();
                if let Err(err) = handle_syscall_ptrace(
                    pid,
                    state,
                    &tracker,
                    &local_addr,
                    &proxy_addr,
                    &no_proxy,
                    disable_ipv6,
                    &mut stats,
                ) {
                    if matches!(&err, Error::Io(io_err) if is_esrch_io(io_err)) {
                        tracing::debug!("Tracee {pid} disappeared during syscall handling");
                        cleanup_dead_tracee(pid, &mut thread_states, &tracker, &mut active_pids);
                        continue;
                    }
                    return Err(err);
                }
                resume_tracee(
                    pid,
                    None,
                    use_seccomp,
                    &mut thread_states,
                    &tracker,
                    &mut active_pids,
                )?;
            }
            Ok(WaitStatus::Stopped(pid, Signal::SIGSTOP)) => {
                // New process/thread
                let is_new = !active_pids.contains(&pid.as_raw());
                if is_new {
                    tracing::debug!("New traced process from SIGSTOP: {pid}");
                    active_pids.insert(pid.as_raw());
                }

                // For the initial child, set ptrace options
                // With seccomp, children inherit the filter automatically
                if is_new || pid == child_pid {
                    tracing::debug!("Setting ptrace options for pid {pid}");
                    if let Err(e) = ptrace::setoptions(
                        pid,
                        ptrace_options(use_seccomp),
                    ) {
                        tracing::warn!("Failed to set ptrace options for pid {pid}: {e}");
                    }
                }

                resume_tracee(
                    pid,
                    None,
                    use_seccomp,
                    &mut thread_states,
                    &tracker,
                    &mut active_pids,
                )?;
            }
            Ok(WaitStatus::Stopped(pid, Signal::SIGTRAP)) => {
                // SIGTRAP from exec or other ptrace events - don't deliver, just continue
                tracing::trace!("SIGTRAP for pid {pid}");
                resume_tracee(
                    pid,
                    None,
                    use_seccomp,
                    &mut thread_states,
                    &tracker,
                    &mut active_pids,
                )?;
            }
            Ok(WaitStatus::Stopped(pid, sig)) => {
                let inject_signal = match ptrace::getsiginfo(pid) {
                    Ok(_) => true,
                    Err(err) if is_esrch_nix(&err) => {
                        tracing::debug!("Tracee {pid} disappeared before getsiginfo");
                        cleanup_dead_tracee(pid, &mut thread_states, &tracker, &mut active_pids);
                        continue;
                    }
                    Err(_) => false,
                };

                if inject_signal {
                    tracing::debug!("Delivering signal {:?} to pid {}", sig, pid);
                    resume_tracee(
                        pid,
                        Some(sig),
                        use_seccomp,
                        &mut thread_states,
                        &tracker,
                        &mut active_pids,
                    )?;
                } else {
                    tracing::trace!("Suppressing non-delivery stop {:?} for pid {}", sig, pid);
                    resume_tracee(
                        pid,
                        None,
                        use_seccomp,
                        &mut thread_states,
                        &tracker,
                        &mut active_pids,
                    )?;
                }
            }
            Ok(other) => {
                tracing::debug!("Unexpected wait status: {:?}", other);
                // Continue anyway - just be safe
                if !active_pids.is_empty() {
                    if let Some(&first_pid) = active_pids.iter().next() {
                        let _ = resume_tracee(
                            Pid::from_raw(first_pid),
                            None,
                            use_seccomp,
                            &mut thread_states,
                            &tracker,
                            &mut active_pids,
                        );
                    }
                }
            }
            Err(e) => {
                if e == nix::errno::Errno::EINTR {
                    prune_gone_tracees(&mut thread_states, &tracker, &mut active_pids);
                    if active_pids.is_empty() {
                        break;
                    }
                    update_shutdown_state(
                        &mut shutdown,
                        process_group,
                        &mut exit_code,
                        &mut active_pids,
                        &mut thread_states,
                        &tracker,
                        use_seccomp,
                    );
                    continue;
                }
                if e == nix::errno::Errno::ECHILD {
                    tracing::debug!("No more children to trace (ECHILD)");
                    break;
                }
                if e == nix::errno::Errno::EINVAL {
                    poll_known_tracees(&mut thread_states, &tracker, &mut active_pids);
                    prune_gone_tracees(&mut thread_states, &tracker, &mut active_pids);
                    if active_pids.is_empty() {
                        tracing::debug!("All traced processes have exited after EINVAL recovery");
                        break;
                    }
                    if main_exited {
                        tracing::warn!(
                            "Main tracee has exited but waitpid still returned EINVAL with {} residual tracees; force-draining leftovers",
                            active_pids.len()
                        );
                        kill_active_tracees(&mut active_pids, &mut thread_states, &tracker);
                        poll_known_tracees(&mut thread_states, &tracker, &mut active_pids);
                        prune_gone_tracees(&mut thread_states, &tracker, &mut active_pids);
                        if active_pids.is_empty() {
                            tracing::debug!("All residual tracees were drained after EINVAL recovery");
                            break;
                        }
                    }
                    tracing::warn!(
                        "waitpid returned EINVAL with {} active tracees; retrying",
                        active_pids.len()
                    );
                    continue;
                }
                return Err(Error::Wait(e));
            }
        }
    }

    if let Some(state) = shutdown {
        tracing::info!(
            "Shutdown completed after {}; traced process group {} exited",
            state.signal.as_str(),
            process_group
        );
    }

    tracing::info!(
        "Trace summary: connect_seen={}, unknown_family_skipped={}, non_stream_skipped={}, stream_probed={}, ipv6_blocked={}, loopback_skipped={}, unspecified_skipped={}, port0_skipped={}, upstream_skipped={}, rewritten={}, socket_enter={}, socket_exit={}",
        stats.connect_seen,
        stats.connect_unknown_family_skipped,
        stats.connect_non_stream_skipped,
        stats.connect_stream_probed,
        stats.connect_ipv6_blocked,
        stats.connect_loopback_skipped,
        stats.connect_unspecified_skipped,
        stats.connect_port0_skipped,
        stats.connect_upstream_skipped,
        stats.connect_rewritten,
        stats.socket_enter_seen,
        stats.socket_exit_seen
    );

    Ok(exit_code)
}

/// Handle syscall in PTRACE_SYSCALL mode (need to track enter/exit state).
fn handle_syscall_ptrace(
    pid: Pid,
    state: &mut ThreadState,
    tracker: &Arc<Mutex<SocketTracker>>,
    local_addr: &SocketAddr,
    proxy_addr: &SocketAddr,
    no_proxy: &NoProxy,
    disable_ipv6: bool,
    stats: &mut TraceStats,
) -> Result<()> {
    let regs = get_regs(pid)?;
    match state.phase {
        SyscallPhase::Entering => {
            handle_syscall_enter(pid, &regs, tracker, local_addr, proxy_addr, no_proxy, disable_ipv6, state, stats)?;
            state.phase = SyscallPhase::Exiting;
        }
        SyscallPhase::Exiting => {
            handle_syscall_exit(pid, &regs, tracker, state, stats)?;
            state.phase = SyscallPhase::Entering;
        }
    }

    Ok(())
}

fn handle_syscall_enter(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
    local_addr: &SocketAddr,
    proxy_addr: &SocketAddr,
    no_proxy: &NoProxy,
    disable_ipv6: bool,
    state: &mut ThreadState,
    stats: &mut TraceStats,
) -> Result<()> {
    let syscall_nr = get_syscall_nr(regs);
    match syscall_nr {
        SOCKET => {
            handle_socket_enter(pid, regs, tracker, stats)?;
        }
        CONNECT => {
            handle_connect_enter(pid, regs, tracker, local_addr, proxy_addr, no_proxy, disable_ipv6, state, stats)?;
        }
        CLOSE => {
            handle_close_enter(pid, regs, tracker)?;
        }
        CLONE => {
            handle_clone_enter(pid, regs)?;
        }
        CLONE3 => {
            handle_clone3_enter(pid, regs)?;
        }
        _ => {
            tracing::trace!("syscall entry {} from pid {}", syscall_nr, pid);
        }
    }
    Ok(())
}

fn handle_syscall_exit(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
    state: &mut ThreadState,
    stats: &mut TraceStats,
) -> Result<()> {
    if get_syscall_nr(regs) == SOCKET {
        handle_socket_exit(pid, regs, tracker, stats);
    }
    if let Some(restore) = state.pending_connect_restore.take() {
        write_sockaddr(pid, restore.addr_ptr, &restore.dest)?;
    }
    if let Some(errno) = state.forced_connect_errno.take() {
        let mut regs = *regs;
        set_return_value(&mut regs, -(errno as i64));
        set_regs(pid, &regs).map_err(|_| Error::Ptrace(nix::errno::Errno::last()))?;
    }
    Ok(())
}

fn handle_connect_enter(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
    local_addr: &SocketAddr,
    proxy_addr: &SocketAddr,
    no_proxy: &NoProxy,
    disable_ipv6: bool,
    state: &mut ThreadState,
    stats: &mut TraceStats,
) -> Result<()> {
    stats.connect_seen += 1;
    state.pending_connect_restore = None;
    let sockfd = get_syscall_arg(regs, 0) as i32;
    let addr_ptr = get_syscall_arg(regs, 1);
    let addrlen = get_syscall_arg(regs, 2);

    tracing::trace!(
        "connect entry raw pid={pid} fd={sockfd} addr_ptr=0x{addr_ptr:x} addrlen={addrlen}"
    );

    // Read the destination address
    let dest = match crate::tracer::memory::read_sockaddr(pid, addr_ptr, addrlen) {
        Ok(addr) => addr,
        Err(Error::UnknownAddressFamily(_)) => {
            // Not IPv4/IPv6, let it pass through
            stats.connect_unknown_family_skipped += 1;
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    tracing::debug!("connect candidate (pid={pid}, fd={sockfd}, dest={dest})");

    if dest.ip().is_loopback() {
        stats.connect_loopback_skipped += 1;
        tracing::trace!("Skipping loopback connect (pid={pid}, fd={sockfd}, dest={dest})");
        return Ok(());
    }
    if dest.ip().is_unspecified() {
        stats.connect_unspecified_skipped += 1;
        tracing::trace!("Skipping unspecified connect target (pid={pid}, fd={sockfd}, dest={dest})");
        return Ok(());
    }
    if dest.port() == 0 {
        stats.connect_port0_skipped += 1;
        tracing::trace!("Skipping connect with port 0 (pid={pid}, fd={sockfd}, dest={dest})");
        return Ok(());
    }
    if no_proxy.should_bypass(&dest) {
        tracing::debug!("Bypassing proxy due to --no-proxy rule (pid={pid}, fd={sockfd}, dest={dest})");
        return Ok(());
    }
    if matches!(dest, SocketAddr::V6(_)) && disable_ipv6 {
        stats.connect_ipv6_blocked += 1;
        state.forced_connect_errno = Some(libc::EAFNOSUPPORT);
        tracing::debug!("Blocked IPv6 connect to force IPv4 fallback (pid={pid}, fd={sockfd}, dest={dest})");
        return Ok(());
    }

    let mut tracker_guard = tracker.lock().unwrap();
    let is_tracked_stream = tracker_guard.is_stream_socket_fd(pid, sockfd);
    drop(tracker_guard);

    if !is_tracked_stream {
        match probe_socket_is_stream(pid, sockfd) {
            Ok(true) => {
                stats.connect_stream_probed += 1;
                let mut tracker_guard = tracker.lock().unwrap();
                tracker_guard.mark_stream_socket_fd(pid, sockfd);
                drop(tracker_guard);
                tracing::debug!("Recovered stream socket via fd probe (pid={pid}, fd={sockfd}, dest={dest})");
            }
            Ok(false) => {
                stats.connect_non_stream_skipped += 1;
                tracing::debug!("Skipping non-stream socket connect (pid={pid}, fd={sockfd}, dest={dest})");
                return Ok(());
            }
            Err(err) => {
                stats.connect_non_stream_skipped += 1;
                tracing::debug!(
                    "Skipping untracked connect after fd probe failure (pid={pid}, fd={sockfd}, dest={dest}, err={err})"
                );
                return Ok(());
            }
        }
    }
    if dest == *proxy_addr {
        stats.connect_upstream_skipped += 1;
        tracing::trace!("Skipping upstream proxy connect (pid={pid}, fd={sockfd}, dest={dest})");
        return Ok(());
    }

    tracing::debug!("Preparing to rewrite connect (pid={pid}, fd={sockfd}, dest={dest}, local={local_addr})");

    // Store the original destination keyed by socket inode (primary) and PID (fallback).
    let info = SocketInfo { dest };
    let mut tracker_guard = tracker.lock().unwrap();
    tracker_guard.insert_dest(pid, sockfd, info);
    if let Some(inode) = read_socket_inode(pid, sockfd) {
        tracker_guard.bind_inode(pid, sockfd, inode);
    }
    drop(tracker_guard);
    tracing::debug!("Stored destination mapping (pid={pid}, fd={sockfd}, dest={dest})");

    // Rewrite the address to point to our local proxy
    match write_sockaddr(pid, addr_ptr, local_addr) {
        Ok(()) => {
            tracing::debug!("Rewrote sockaddr in tracee memory (pid={pid}, fd={sockfd}, local={local_addr})");
        }
        Err(err) => {
            tracing::error!(
                "Failed to rewrite sockaddr (pid={pid}, fd={sockfd}, dest={dest}, local={local_addr}): {err}"
            );
            return Err(err);
        }
    }
    state.pending_connect_restore = Some(PendingConnectRestore { addr_ptr, dest });

    stats.connect_rewritten += 1;
    tracing::debug!("redirected to {local_addr}");

    Ok(())
}

fn handle_socket_enter(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
    stats: &mut TraceStats,
) -> Result<()> {
    stats.socket_enter_seen += 1;
    let domain = get_syscall_arg(regs, 0) as i32;
    let sock_type = get_syscall_arg(regs, 1) as i32;
    tracker.lock().unwrap().socket_enter(pid, domain, sock_type);
    Ok(())
}

fn handle_socket_exit(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
    stats: &mut TraceStats,
) {
    stats.socket_exit_seen += 1;
    let ret_fd = get_return_value(regs) as i32;
    tracker.lock().unwrap().socket_exit(pid, ret_fd);
}

fn handle_close_enter(
    pid: Pid,
    regs: &libc::user_regs_struct,
    tracker: &Arc<Mutex<SocketTracker>>,
) -> Result<()> {
    let fd = get_syscall_arg(regs, 0) as i32;
    tracker.lock().unwrap().close_enter(pid, fd);
    Ok(())
}


/// Handle clone() syscall - remove CLONE_UNTRACED flag to ensure child is traced.
///
/// This is crucial for programs like Electron/Chromium that use CLONE_UNTRACED
/// to spawn processes that shouldn't be traced. By removing this flag, we ensure
/// all child processes are properly traced.
fn handle_clone_enter(pid: Pid, regs: &libc::user_regs_struct) -> Result<()> {
    let flags = get_syscall_arg(regs, 0) as libc::c_ulong;

    // Clone flags we care about
    const CLONE_UNTRACED: libc::c_ulong = 0x00800000;
    const CLONE_THREAD: libc::c_ulong = 0x00010000;

    // Always log clone flags for debugging
    tracing::debug!(
        "clone() from pid {pid}: flags=0x{:x} (CLONE_UNTRACED={}, CLONE_THREAD={})",
        flags,
        flags & CLONE_UNTRACED != 0,
        flags & CLONE_THREAD != 0
    );

    if flags & CLONE_UNTRACED != 0 {
        let new_flags = flags & !CLONE_UNTRACED;
        tracing::info!(
            "clone() from pid {pid}: removing CLONE_UNTRACED (0x{:x} -> 0x{:x})",
            flags, new_flags
        );

        // Modify the flags argument
        let mut regs = *regs;
        set_syscall_arg(&mut regs, 0, new_flags as u64);
        set_regs(pid, &regs).map_err(|e| {
            tracing::warn!("Failed to set registers for pid {pid}: {}", e);
            Error::Ptrace(nix::errno::Errno::last())
        })?;
    }

    Ok(())
}

/// Handle clone3() syscall - remove CLONE_UNTRACED from struct clone_args::flags.
fn handle_clone3_enter(pid: Pid, regs: &libc::user_regs_struct) -> Result<()> {
    let clone_args_ptr = get_syscall_arg(regs, 0);
    if clone_args_ptr == 0 {
        return Ok(());
    }

    // clone_args::flags is the first u64 field in the struct.
    let flags = crate::tracer::memory::read_u64(pid, clone_args_ptr)?;
    const CLONE_UNTRACED: u64 = 0x00800000;
    const CLONE_THREAD: u64 = 0x00010000;

    tracing::debug!(
        "clone3() from pid {pid}: flags=0x{:x} (CLONE_UNTRACED={}, CLONE_THREAD={})",
        flags,
        flags & CLONE_UNTRACED != 0,
        flags & CLONE_THREAD != 0
    );

    if flags & CLONE_UNTRACED != 0 {
        let new_flags = flags & !CLONE_UNTRACED;
        tracing::info!(
            "clone3() from pid {pid}: removing CLONE_UNTRACED (0x{:x} -> 0x{:x})",
            flags, new_flags
        );
        crate::tracer::memory::write_u64(pid, clone_args_ptr, new_flags)?;
    }

    Ok(())
}
