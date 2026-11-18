//! User threads: a kernel thread per user thread, which enters ring 3 and comes back through
//! syscalls, interrupts and faults (thread.h).
//!
//! The Rust state of a user thread (`UserThread`) is boxed and owned by its C thread
//! (`thread->user`). It holds the process (so the process and its address space outlive every
//! thread running in it), the thread object, and the thread-quota charge. It is dropped by
//! `dkrnl_uthread_finish` (called by `uthread_exit`, after the thread has left the address
//! space), never on an unwinding path: a thread only exits from places where no Rust frame
//! holds anything (the syscall dispatcher's top level, the C fault and interrupt paths).

use alloc::boxed::Box;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicU64};

use super::super::object::quota::{Charge, Res};
use super::super::object::{KRef, KResult, Process, Status, ThreadObj};
use crate::ffi::{self, USER_TOP};

pub struct UserThread {
    pub proc: KRef<Process>,
    pub obj: KRef<ThreadObj>,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
    /// Stop with a START exception before the first instruction (user/exception.rs).
    start_exception: bool,
    _charge: Charge,
    /// In-process exception handler (`thread_set_exception_handler`): entry point and stack top
    /// (0: none), and whether it is running now (user/exception.rs).
    pub handler_entry: AtomicU64,
    pub handler_stack: AtomicU64,
    pub in_handler: AtomicBool,
}

/// The calling user thread's state, during a syscall (None in a kernel thread).
pub fn current() -> Option<&'static UserThread> {
    // SAFETY: plain read of the current thread's pointer.
    let p = unsafe { ffi::thread_user_state() }.cast::<UserThread>();
    // SAFETY: set by `start` to a live box, which only this thread drops (when it exits).
    (!p.is_null()).then(|| unsafe { &*p })
}

extern "C" fn uthread_main(_arg: *mut c_void) -> c_int {
    let u = current().expect("user thread without state");
    let (entry, stack, a0, a1) = (u.entry, u.stack, u.arg0, u.arg1);
    if u.start_exception {
        super::exception::start_trap(u, entry, stack, a0, a1);
    }
    // SAFETY: into ring 3; never returns. Nothing on this Rust frame needs dropping.
    unsafe { ffi::user_enter(entry, stack, a0, a1) }
}

/// Start a user thread in `proc` at `entry` with `stack` (both user addresses; a bad one only
/// faults the new thread). RDI = arg0, RSI = arg1.
pub fn start(
    proc: &KRef<Process>,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
    start_exception: bool,
) -> KResult<KRef<ThreadObj>> {
    let obj = ThreadObj::new(proc.name())?;
    start_with(proc, obj.clone(), entry, stack, arg0, arg1, start_exception)?;
    Ok(obj)
}

/// `start` with a thread object made in advance (the loader puts its handle in the startup block).
pub fn start_with(
    proc: &KRef<Process>,
    obj: KRef<ThreadObj>,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
    start_exception: bool,
) -> KResult<()> {
    if entry >= USER_TOP || !(ffi::USER_BASE..USER_TOP).contains(&stack) {
        return Err(Status::InvalidArgs);
    }
    if proc.is_dead() {
        return Err(Status::BadState);
    }
    let charge = Charge::new(proc.account(), Res::Threads, 1)?;
    let state = crate::thread::try_box(UserThread {
        proc: proc.clone(),
        obj,
        entry,
        stack,
        arg0,
        arg1,
        start_exception,
        _charge: charge,
        handler_entry: AtomicU64::new(0),
        handler_stack: AtomicU64::new(0),
        in_handler: AtomicBool::new(false),
    })
    .ok_or(Status::NoMemory)?;
    let state = Box::into_raw(state);
    let aspace = proc.root_vmar().aspace().raw();
    let mut name = [0u8; 24];
    let n = proc.name().len().min(23);
    name[..n].copy_from_slice(&proc.name().as_bytes()[..n]);
    let r = proc.add_thread(|| {
        // SAFETY: the box is valid; the thread reads its state only through `current()`. The
        // name is copied by thread_create_user.
        let t = unsafe {
            ffi::thread_create_user(name.as_ptr().cast(), uthread_main, core::ptr::null_mut(), aspace, state.cast())
        };
        (!t.is_null()).then_some(t)
    });
    if let Err(e) = r {
        // SAFETY: no thread was created, so the box is still ours.
        drop(unsafe { Box::from_raw(state) });
        return Err(e);
    }
    Ok(())
}

/// `uthread_exit`: the thread has left its address space; drop its state and do the
/// bookkeeping. `code` is `UTHREAD_EXIT_KILLED` when the process died under it.
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_uthread_finish(user: *mut c_void, code: c_int) {
    // SAFETY: the box created by `start`, handed back exactly once by uthread_exit.
    let u = unsafe { Box::from_raw(user.cast::<UserThread>()) };
    let code = if code == ffi::UTHREAD_EXIT_KILLED { u.proc.pending_exit_code() } else { code };
    let UserThread { proc, obj, _charge, .. } = *u;
    // SAFETY: plain read; the exiting thread is the current one.
    let raw = unsafe { ffi::thread_current() };
    drop(_charge); // the thread quota is free before anyone sees TERMINATED
    obj.finish(code);
    proc.thread_gone(raw, code);
}

/// Name and koid of the current thread's process, for crash reports.
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_user_print_current() {
    match current() {
        Some(u) => crate::kprint!("user fault: process '{}' (koid {})", u.proc.name(), u.proc.header.koid),
        None => crate::kprint!("user fault: (no process)"),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_user_kill_current(code: c_int) {
    if let Some(u) = current() {
        u.proc.kill_with(code);
    }
}
