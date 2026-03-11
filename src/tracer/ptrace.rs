// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! ptrace setup and child process management.

use crate::error::{Error, Result};
use crate::tracer::seccomp;
use nix::sys::ptrace;
use nix::unistd::setpgid;
use nix::unistd::{fork, Pid};
use std::ffi::CString;

/// Get the message from a ptrace event (e.g., new child PID from CLONE/FORK).
pub fn get_ptrace_event_msg(pid: Pid) -> Result<u64> {
    // PTRACE_GETEVENTMSG = 0
    #[cfg(target_os = "linux")]
    let mut msg: u64 = 0;
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &mut msg as *mut u64 as *mut libc::c_void,
        )
    };
    if result == -1 {
        return Err(Error::Ptrace(nix::errno::Errno::last()));
    }
    Ok(msg)
}

/// Fork and exec a child process with ptrace enabled.
///
/// With seccomp-bpf support (kernel >= 4.8), installs a filter
/// that is inherited by all child processes automatically.
pub fn fork_exec(command: &str, args: &[String], use_seccomp: bool) -> Result<Pid> {
    match unsafe { fork() }.map_err(Error::Fork)? {
        nix::unistd::ForkResult::Parent { child } => {
            tracing::debug!("Forked child process: {child}");
            Ok(child)
        }
        nix::unistd::ForkResult::Child => {
            // Child process
            setpgid(Pid::from_raw(0), Pid::from_raw(0)).expect("setpgid failed");
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            }

            ptrace::traceme().expect("ptrace TRACEME failed");

            // Stop ourselves so parent can set options
            nix::sys::signal::raise(nix::sys::signal::SIGSTOP).expect("raise SIGSTOP failed");

            if use_seccomp {
                if let Err(err) = seccomp::install_filter() {
                    eprintln!("proxec: install seccomp failed: {err}");
                    std::process::exit(127);
                }
            }

            // Build argument vector
            let c_cmd = CString::new(command).unwrap();
            let c_args: Vec<CString> = std::iter::once(c_cmd.clone())
                .chain(args.iter().map(|s| CString::new(s.as_str()).unwrap()))
                .collect();

            // Exec the target program
            let _ = nix::unistd::execvp(&c_cmd, &c_args);

            // If execvp returns, it failed
            eprintln!("proxec: execvp failed: {}", std::io::Error::last_os_error());
            std::process::exit(127);
        }
    }
}
