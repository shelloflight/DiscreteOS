//! User mode: ring-3 processes that reach the kernel only through handles.
//!
//! - `syscall`: the handle-based syscall ABI (docs/abi.md), dispatched from syscall.asm
//! - `uaccess`: copy_from_user / copy_to_user (checked ranges, SMAP, fault fixup)
//! - `thread`:  user threads (a kernel thread per user thread; kill, exit, faults)
//! - `exception`: faults and forwarded syscalls to in-process handlers or supervisors
//! - `ipc`:     channel, port and async-wait syscalls
//! - `elf`:     strict ELF64 parser for `.dx` executables
//! - `loader`:  spawn: process + image + stack + startup handles
//! - `boot`:    the embedded programs and the first process, `init`

pub mod boot;
pub mod elf;
pub mod exception;
pub mod ipc;
pub mod loader;
pub mod syscall;
pub mod thread;
pub mod uaccess;

#[cfg(ktest_fuzz)]
pub mod tests;
