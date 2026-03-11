// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! seccomp-bpf filter for syscall interception.
//!
//! Using seccomp-bpf is more efficient and reliable than PTRACE_SYSCALL
//! for multi-process tracing because the filter is inherited by child
//! processes automatically.

use std::io;

/// Syscall numbers for x86_64
mod sys {
    pub const CLOSE: u32 = 3;
    pub const SOCKET: u32 = 41;
    pub const CONNECT: u32 = 42;
    pub const CLONE: u32 = 56;
    pub const CLONE3: u32 = 435;
}

/// Socket families
mod af {
    pub const INET: u32 = 2;
    pub const INET6: u32 = 10;
}

/// Socket types
mod sock {
    pub const STREAM: u32 = 1;
}

/// Clone flags
mod clone_flags {
    pub const CLONE_UNTRACED: u32 = 0x00800000;
}

/// BPF instruction wrapper
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program wrapper
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// BPF instruction macros
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x20;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Install seccomp filter to trace connect(), socket(), close(), and clone() syscalls.
///
/// This must be called in the child process BEFORE exec.
/// The filter is inherited by all child processes automatically.
pub fn install_filter() -> io::Result<()> {
    // Filter that traces:
    // - close()
    // - connect()
    // - clone3() (so we can clear CLONE_UNTRACED from clone_args.flags)
    // - clone() only when CLONE_UNTRACED is set
    // - socket(AF_INET/AF_INET6, SOCK_STREAM, ...)
    let filter: &[SockFilter] = &[
        // Load syscall number
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0), // offsetof(seccomp_data, nr)

        // Fast path syscalls
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, sys::CLOSE, 12, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, sys::CONNECT, 11, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, sys::CLONE3, 10, 0),

        // clone() with CLONE_UNTRACED
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, sys::CLONE, 2, 0),

        // socket() checks, otherwise allow
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, sys::SOCKET, 3, 0),
        bpf_stmt(BPF_RET | BPF_K, 0x7fff0000), // SECCOMP_RET_ALLOW

        // clone flags
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16), // offsetof(seccomp_data, args[0])
        bpf_jump(BPF_JMP | BPF_JSET | BPF_K, clone_flags::CLONE_UNTRACED, 5, 6),

        // socket domain/type
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16), // offsetof(seccomp_data, args[0])
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, af::INET, 1, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, af::INET6, 0, 3),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 20), // offsetof(seccomp_data, args[1])
        bpf_jump(BPF_JMP | BPF_JSET | BPF_K, sock::STREAM, 0, 1),

        // Trace / allow
        bpf_stmt(BPF_RET | BPF_K, 0x7ff00000), // SECCOMP_RET_TRACE
        bpf_stmt(BPF_RET | BPF_K, 0x7fff0000), // SECCOMP_RET_ALLOW
    ];
    
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    
    // PR_SET_NO_NEW_PRIVS = 38
    // PR_SET_SECCOMP = 22
    // SECCOMP_MODE_FILTER = 2
    unsafe {
        // First, set no_new_privs to allow unprivileged seccomp
        if libc::prctl(38, 1, 0, 0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Then, install the filter
        if libc::prctl(22, 2, &prog, 0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    
    tracing::debug!("seccomp-bpf filter installed");
    Ok(())
}

/// Check if seccomp-bpf is available (kernel >= 4.8)
pub fn is_available() -> bool {
    // Use libc::uname to get kernel version
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) < 0 {
            return true; // Default to true if we can't check
        }
        
        // Release is a fixed-size array of i8 (c_char)
        let release = &uts.release;
        let release_str: String = release
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        
        let parts: Vec<&str> = release_str.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                return major > 4 || (major == 4 && minor >= 8);
            }
        }
    }
    // Default to true on modern systems
    true
}
