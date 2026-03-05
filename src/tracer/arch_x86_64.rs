// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! x86_64 architecture-specific definitions.

use nix::unistd::Pid;

/// Syscall numbers for x86_64.
pub mod syscall {
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const CLOSE: i64 = 3;
    pub const CLONE: i64 = 56;
    pub const GETSOCKNAME: i64 = 51;
}

/// Get syscall number from registers.
pub fn get_syscall_nr(regs: &libc::user_regs_struct) -> i64 {
    regs.orig_rax as i64
}

/// Get syscall argument by index (0-5).
pub fn get_syscall_arg(regs: &libc::user_regs_struct, n: usize) -> u64 {
    match n {
        0 => regs.rdi,
        1 => regs.rsi,
        2 => regs.rdx,
        3 => regs.r10,
        4 => regs.r8,
        5 => regs.r9,
        _ => panic!("invalid syscall argument index: {n}"),
    }
}

/// Get syscall return value.
pub fn get_return_value(regs: &libc::user_regs_struct) -> i64 {
    regs.rax as i64
}

/// Set syscall return value.
pub fn set_return_value(
    pid: Pid,
    regs: &mut libc::user_regs_struct,
    val: i64,
) {
    regs.rax = val as u64;
}

/// Read registers from traced process.
pub fn get_regs(pid: Pid) -> std::io::Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut _ as *mut libc::c_void,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(regs)
}

/// Write registers to traced process.
pub fn set_regs(pid: Pid, regs: &libc::user_regs_struct) -> std::io::Result<()> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const _ as *mut libc::c_void,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
