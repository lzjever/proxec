// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! ptrace-based syscall interception.

mod arch_x86_64;
mod memory;
mod ptrace;
mod syscall;

pub use arch_x86_64::*;
pub use memory::*;
pub use ptrace::*;
pub use syscall::*;
