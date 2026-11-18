//! The C binding of libd (feature `capi`; declarations in user/include/libd.h). The same heap,
//! threads and locks as the Rust side, behind plain C functions.
//!
//! C's `free` does not say how large a block was, so every C allocation carries a 16-byte header
//! with its size in front of the pointer handed out (which keeps 16-byte alignment).

use alloc::alloc::{alloc, dealloc, realloc};
use core::alloc::Layout;
use core::ffi::c_void;

use crate::sync::RawMutex;
use crate::{Startup, heap, sys, thread};

const HDR: usize = 16;

fn layout(size: usize) -> Option<Layout> {
    Layout::from_size_align(size.checked_add(HDR)?, HDR).ok()
}

/// Set up the runtime for a C program: `name` (a string literal) prefixes error reports.
/// 0, or `DOS_ERR_INVALID_ARGS` if `s` is not the kernel's startup block.
///
/// # Safety
/// `s` is the startup block the program got at its entry; `name` is a NUL-terminated string that
/// lives for the whole program.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_init(s: *const Startup, name: *const u8) -> i64 {
    let name: &'static str = if name.is_null() {
        "c"
    } else {
        // SAFETY: the caller passes a NUL-terminated, program-lifetime string.
        let n = unsafe { core::ffi::CStr::from_ptr(name.cast()) };
        n.to_str().unwrap_or("c")
    };
    // SAFETY: forwarded caller guarantee.
    if unsafe { crate::init(s, name) } { 0 } else { sys::ERR_INVALID_ARGS }
}

#[unsafe(no_mangle)]
pub extern "C" fn libd_malloc(size: usize) -> *mut c_void {
    let Some(l) = layout(size) else { return core::ptr::null_mut() };
    // SAFETY: the layout is at least HDR bytes.
    let p = unsafe { alloc(l) };
    if p.is_null() {
        return p.cast();
    }
    // SAFETY: the block is at least HDR bytes and 16-aligned.
    unsafe {
        p.cast::<usize>().write(size);
        p.add(HDR).cast()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn libd_calloc(n: usize, size: usize) -> *mut c_void {
    let Some(total) = n.checked_mul(size) else { return core::ptr::null_mut() };
    let p = libd_malloc(total);
    if !p.is_null() {
        // SAFETY: `total` bytes were just allocated at `p`.
        unsafe { core::ptr::write_bytes(p.cast::<u8>(), 0, total) };
    }
    p
}

/// # Safety
/// `p` is NULL or a live pointer from `libd_malloc`/`calloc`/`realloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: caller guarantee: the header precedes `p` and holds the size it was made with.
    unsafe {
        let b = p.cast::<u8>().sub(HDR);
        let size = b.cast::<usize>().read();
        if let Some(l) = layout(size) {
            dealloc(b, l);
        }
    }
}

/// # Safety
/// As `libd_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_realloc(p: *mut c_void, size: usize) -> *mut c_void {
    if p.is_null() {
        return libd_malloc(size);
    }
    let Some(nl) = layout(size) else { return core::ptr::null_mut() };
    // SAFETY: caller guarantee (see libd_free); the old layout is the one it was allocated with.
    unsafe {
        let b = p.cast::<u8>().sub(HDR);
        let old = b.cast::<usize>().read();
        let Some(ol) = layout(old) else { return core::ptr::null_mut() };
        let q = realloc(b, ol, nl.size());
        if q.is_null() {
            return q.cast(); // the old block is untouched (C semantics)
        }
        q.cast::<usize>().write(size);
        q.add(HDR).cast()
    }
}

/// Heap statistics (`struct libd_heap_stats`).
///
/// # Safety
/// `out` points at writable memory for the structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_heap_stats(out: *mut heap::Stats) {
    // SAFETY: caller guarantee.
    unsafe { out.write(heap::stats()) }
}

// ---- threads -----------------------------------------------------------------------------------

/// What C sees as `libd_thread_t`: a boxed join handle.
type CJoin = thread::JoinHandle<i64>;

struct SendPtr(*mut c_void);
// SAFETY: the C caller hands the argument to the new thread; what it points at is its business.
unsafe impl Send for SendPtr {}

/// Start `entry(arg)` on a new thread with a `stack` byte stack (0: the default). On success
/// `*out` is the thread, to be passed to `libd_thread_join` exactly once. Returns 0 or a status.
///
/// # Safety
/// `out` is writable; `entry` is a valid function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_thread_spawn(entry: extern "C" fn(*mut c_void) -> i64, arg: *mut c_void, stack: usize, out: *mut *mut c_void) -> i64 {
    let a = SendPtr(arg);
    let mut b = thread::Builder::new();
    if stack != 0 {
        b = b.stack_size(stack as u64);
    }
    let j = match b.spawn(move || {
        let a = a;
        entry(a.0)
    }) {
        Ok(j) => j,
        Err(e) => return e,
    };
    // One small block for the handle; on failure the thread runs detached and is reaped later.
    let l = Layout::new::<CJoin>();
    // SAFETY: non-zero layout.
    let p = unsafe { alloc(l) }.cast::<CJoin>();
    if p.is_null() {
        drop(j);
        return sys::ERR_NO_MEMORY;
    }
    // SAFETY: fresh block of the right layout; `out` is writable (caller guarantee).
    unsafe {
        p.write(j);
        out.write(p.cast());
    }
    0
}

/// Wait for a thread from `libd_thread_spawn`; its entry's return value into `*result` (if not
/// NULL). Returns 0, or the thread's exit code if it ended without returning.
///
/// # Safety
/// `t` came from `libd_thread_spawn` and is joined only once; `result` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_thread_join(t: *mut c_void, result: *mut i64) -> i64 {
    let p = t.cast::<CJoin>();
    // SAFETY: caller guarantee: a live, unjoined handle made by libd_thread_spawn.
    let j = unsafe { p.read() };
    // SAFETY: the block was allocated with this layout; its value was moved out above.
    unsafe { dealloc(p.cast(), Layout::new::<CJoin>()) };
    match j.join() {
        Ok(v) => {
            if !result.is_null() {
                // SAFETY: caller guarantee.
                unsafe { result.write(v) };
            }
            0
        }
        Err(code) => i64::from(code),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn libd_thread_id() -> u64 {
    thread::current_id()
}

#[unsafe(no_mangle)]
pub extern "C" fn libd_sleep_ns(ns: u64) {
    thread::sleep(ns);
}

// ---- mutexes -------------------------------------------------------------------------------------

/// # Safety
/// `m` points at a `libd_mutex_t` (zero-initialised or `LIBD_MUTEX_INIT`), not moved while used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_mutex_lock(m: *const RawMutex) {
    // SAFETY: caller guarantee.
    unsafe { (*m).lock() }
}

/// # Safety
/// As `libd_mutex_lock`, and the caller holds the mutex.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_mutex_unlock(m: *const RawMutex) {
    // SAFETY: caller guarantee.
    unsafe { (*m).unlock() }
}

/// 1 if the mutex was taken, 0 if it is held.
///
/// # Safety
/// As `libd_mutex_lock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_mutex_trylock(m: *const RawMutex) -> i32 {
    // SAFETY: caller guarantee.
    i32::from(unsafe { (*m).try_lock() })
}

/// Release the kernel event behind a mutex that is no longer used.
///
/// # Safety
/// As `libd_mutex_lock`; nobody holds or waits on it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn libd_mutex_destroy(m: *const RawMutex) {
    // SAFETY: caller guarantee.
    unsafe { (*m).destroy() }
}
