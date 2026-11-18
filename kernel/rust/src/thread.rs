//! Kernel threads from Rust: `spawn` a closure, `join` it for its exit code (thread.h).
//!
//! A `JoinHandle` that is dropped without `join` detaches the thread (the reaper frees it when it
//! exits), so a thread is never leaked and never freed twice.

use alloc::alloc::Layout;
use alloc::boxed::Box;
use core::ffi::{CStr, c_int, c_void};

use crate::ffi::{self, RawThread};

pub use crate::ffi::prio;

pub struct JoinHandle {
    raw: *mut RawThread,
}

// SAFETY: a thread handle may be joined or detached from any thread; the C side locks.
unsafe impl Send for JoinHandle {}

extern "C" fn trampoline<F: FnOnce() -> i32>(arg: *mut c_void) -> c_int {
    // SAFETY: `arg` is the Box<F> leaked by `spawn`; this is its only consumer.
    let f = unsafe { Box::from_raw(arg.cast::<F>()) };
    f()
}

/// `Box::new` that reports out-of-memory instead of aborting (`Box::try_new` is unstable).
pub fn try_box<F>(f: F) -> Option<Box<F>> {
    let layout = Layout::new::<F>();
    if layout.size() == 0 {
        return Some(Box::new(f)); // zero-sized: no allocation
    }
    // SAFETY: non-zero size.
    let p = unsafe { alloc::alloc::alloc(layout) }.cast::<F>();
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is a fresh global-allocator block with F's layout, which is what Box expects.
    unsafe {
        p.write(f);
        Some(Box::from_raw(p))
    }
}

/// Start `f` on a new kernel thread with priority `prio` (see `prio`). `None` when out of memory
/// (the closure is dropped).
pub fn spawn<F>(name: &'static CStr, prio: u32, f: F) -> Option<JoinHandle>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    let arg = Box::into_raw(try_box(f)?);
    // SAFETY: `trampoline::<F>` matches `arg`'s type; the name is a static C string.
    let raw = unsafe { ffi::thread_create(name.as_ptr(), trampoline::<F>, arg.cast(), prio) };
    if raw.is_null() {
        // SAFETY: the thread was not created, so the box is still ours.
        drop(unsafe { Box::from_raw(arg) });
        return None;
    }
    Some(JoinHandle { raw })
}

impl JoinHandle {
    /// Wait for the thread to finish and return its exit code (the closure's result).
    pub fn join(self) -> i32 {
        let raw = self.raw;
        core::mem::forget(self);
        // SAFETY: `raw` is a live thread that has been neither joined nor detached.
        unsafe { ffi::thread_join(raw) }
    }
}

impl Drop for JoinHandle {
    fn drop(&mut self) {
        // SAFETY: as in `join`.
        unsafe { ffi::thread_detach(self.raw) }
    }
}

pub fn yield_now() {
    // SAFETY: no preconditions beyond being a thread (checked by C).
    unsafe { ffi::thread_yield() }
}

pub fn sleep_ns(ns: u64) {
    // SAFETY: as above.
    unsafe { ffi::thread_sleep_ns(ns) }
}
