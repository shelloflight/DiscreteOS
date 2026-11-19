//! Threads (feature `alloc`).
//!
//! Each thread runs on its own stack: a VMO mapped inside a reserved region with one unmapped
//! **guard page** below and one above, so an overflow faults (the kernel reports the process as
//! faulted) instead of silently writing over a neighbouring mapping. The top of the stack holds
//! the thread control block (`Tcb`), and the thread's FS base points at it: `current_id()` is one
//! memory read, and the FS base is the anchor for thread-local data.
//!
//! Stacks are committed eagerly by the kernel (no demand paging yet), so the default is a modest
//! 64 KiB (`Builder::stack_size` for more). The kernel has no call to give a reserved region back,
//! so when a thread ends its stack pages are unmapped (memory returned) and the empty region is
//! kept for the next thread with the same stack size: address space stays bounded by the peak
//! number of threads.
//!
//! A `JoinHandle` that is dropped detaches its thread; finished detached threads are reclaimed
//! (handle closed, stack recycled) on the next `spawn` or `reap`.
//!
//! Every allocation is fallible: out of memory, handles or threads is an `Err`, never a panic.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering, fence};

use crate::handle::Owned;
use crate::sync::Mutex;
use crate::sys;

pub use crate::handle::sleep;
pub use crate::sys::yield_now;

pub const DEFAULT_STACK: u64 = 64 * 1024;
pub const MIN_STACK: u64 = 16 * 1024;
pub const MAX_STACK: u64 = 64 * 1024 * 1024;

/// Thread control block, at the top of each stack (and in `.bss` for the first thread); the FS
/// base points at it. Layout fixed (libd.h documents FS:0 = this block, FS:8 = id).
#[repr(C, align(64))]
pub struct Tcb {
    pub self_ptr: u64,
    pub id: u64,
    pub stack_lo: u64,
    pub stack_hi: u64,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(2);

struct MainTcb(UnsafeCell<Tcb>);
// SAFETY: written once by `init_main` before any other thread exists, read-only afterwards.
unsafe impl Sync for MainTcb {}
static MAIN: MainTcb = MainTcb(UnsafeCell::new(Tcb { self_ptr: 0, id: 1, stack_lo: 0, stack_hi: 0 }));

/// Give the first thread its TCB (called by `crate::init`).
pub(crate) fn init_main(stack_lo: u64, stack_hi: u64) {
    let t = MAIN.0.get();
    // SAFETY: the only thread so far; nobody reads MAIN before its FS base is set below.
    unsafe {
        (*t).self_ptr = t as u64;
        (*t).stack_lo = stack_lo;
        (*t).stack_hi = stack_hi;
    }
    sys::thread_set_base(sys::BASE_FS, t as u64);
}

/// The calling thread's id: 1 for the first thread, then 2, 3, ... in creation order. Valid in
/// threads started by libd and in the first thread after `crate::init` (threads made with the
/// raw `thread_create` have no TCB and fault here).
#[inline]
pub fn current_id() -> u64 {
    let id: u64;
    // SAFETY: FS:8 is the `id` field of this thread's TCB (see above); a plain load.
    unsafe { core::arch::asm!("mov {}, fs:[8]", out(reg) id, options(nostack, readonly, preserves_flags)) };
    id
}

/// The calling thread's TCB (same rule as `current_id`).
pub fn current() -> &'static Tcb {
    let p: u64;
    // SAFETY: as in `current_id`; FS:0 holds the TCB's own address, valid for the thread's life.
    unsafe {
        core::arch::asm!("mov {}, fs:[0]", out(reg) p, options(nostack, readonly, preserves_flags));
        &*(p as *const Tcb)
    }
}

// ---- stacks ---------------------------------------------------------------------------------------

struct Stack {
    region: Owned,
    base: u64, // region base; the stack is [base + PAGE, base + PAGE + size)
    size: u64,
    mapped: bool,
}

impl Stack {
    fn lo(&self) -> u64 {
        self.base + sys::PAGE
    }
    fn hi(&self) -> u64 {
        self.lo() + self.size
    }
}

/// Cap on cached empty stack regions; any excess (or on OOM) is destroyed with `vmar_destroy`.
const MAX_CACHED_STACKS: usize = 16;

/// Empty reserved regions of finished threads, for reuse.
static FREE_STACKS: Mutex<Vec<Stack>> = Mutex::new(Vec::new());

fn stack_new(size: u64) -> Result<Stack, i64> {
    let reuse = {
        let mut free = FREE_STACKS.lock();
        free.iter().position(|s| s.size == size).map(|i| free.swap_remove(i))
    };
    let mut s = match reuse {
        Some(s) => s,
        None => {
            let (region, base) = sys::vmar_allocate(crate::root_vmar(), sys::ANY, size + 2 * sys::PAGE, sys::RIGHTS_SAME)?;
            Stack { region: Owned::from_raw(region), base, size, mapped: false }
        }
    };
    let vmo = match sys::vmo_create(size) {
        Ok(v) => Owned::from_raw(v), // the mapping keeps the VMO alive once this handle closes
        Err(e) => {
            stack_free(s);
            return Err(e);
        }
    };
    match sys::vmar_map(s.region.raw(), sys::PAGE, vmo.raw(), 0, size, sys::RIGHT_READ | sys::RIGHT_WRITE) {
        Ok(_) => {
            s.mapped = true;
            Ok(s)
        }
        Err(e) => {
            stack_free(s);
            Err(e)
        }
    }
}

/// Unmap the stack (its memory goes back) and keep up to `MAX_CACHED_STACKS` empty regions for
/// reuse; excess regions are destroyed with `vmar_destroy` so virtual address space is reclaimed.
fn stack_free(mut s: Stack) {
    if s.mapped {
        sys::vmar_unmap(s.region.raw(), s.lo(), s.size);
        s.mapped = false;
    }
    let mut free = FREE_STACKS.lock();
    if free.len() < MAX_CACHED_STACKS && free.try_reserve(1).is_ok() {
        free.push(s);
    } else {
        drop(free);
        sys::vmar_destroy(s.region.raw());
    }
}

// ---- spawn and join ---------------------------------------------------------------------------------

/// The start of every thread's shared block: how to run it and how to free it (type-erased).
#[repr(C)]
struct Hdr {
    run: unsafe fn(*mut Hdr),
    free: unsafe fn(*mut Hdr),
    tcb: u64,
}

/// One allocation per thread, shared by the thread and its joiner. The thread takes `f` and
/// writes `result` before it exits; the joiner (or `reap`, for a detached thread) reads the
/// result and frees the block only after the kernel reported the thread ended, so the two never
/// touch it at the same time.
#[repr(C)]
struct Inner<F, T> {
    hdr: Hdr,
    f: Option<F>,
    result: Option<T>,
}

unsafe fn run<F: FnOnce() -> T, T>(h: *mut Hdr) {
    let i = h.cast::<Inner<F, T>>();
    // SAFETY: `h` is this thread's live block (see `Inner`); only this thread touches it now.
    unsafe {
        if let Some(f) = (*i).f.take() {
            (*i).result = Some(f());
        }
    }
}

unsafe fn free<F, T>(h: *mut Hdr) {
    // SAFETY: called once, after the thread ended (or never started), on a block from `spawn`.
    unsafe {
        core::ptr::drop_in_place(h.cast::<Inner<F, T>>());
        alloc::alloc::dealloc(h.cast(), core::alloc::Layout::new::<Inner<F, T>>());
    }
}

#[unsafe(naked)]
extern "C" fn thread_entry() -> ! {
    core::arch::naked_asm!("xor ebp, ebp", "and rsp, -16", "call {m}", "ud2", m = sym thread_main)
}

extern "C" fn thread_main(h: *mut Hdr) -> ! {
    // SAFETY: `spawn` passed its block as the thread's argument; it lives until we have exited.
    unsafe {
        sys::thread_set_base(sys::BASE_FS, (*h).tcb);
        ((*h).run)(h);
    }
    sys::thread_exit(0)
}

/// Thread options.
pub struct Builder {
    stack: u64,
}

impl Default for Builder {
    fn default() -> Self {
        Builder { stack: DEFAULT_STACK }
    }
}

impl Builder {
    pub fn new() -> Builder {
        Builder::default()
    }

    /// Stack size in bytes (rounded up to pages, at least `MIN_STACK`, at most `MAX_STACK`).
    pub fn stack_size(mut self, bytes: u64) -> Builder {
        self.stack = bytes.clamp(MIN_STACK, MAX_STACK).div_ceil(sys::PAGE) * sys::PAGE;
        self
    }

    pub fn spawn<F, T>(self, f: F) -> Result<JoinHandle<T>, i64>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        reap();
        let layout = core::alloc::Layout::new::<Inner<F, T>>();
        // SAFETY: the layout is not zero-sized (it holds a `Hdr`).
        let h = unsafe { alloc::alloc::alloc(layout) }.cast::<Inner<F, T>>();
        if h.is_null() {
            return Err(sys::ERR_NO_MEMORY);
        }
        let stack = match stack_new(self.stack) {
            Ok(s) => s,
            Err(e) => {
                // SAFETY: allocated above with this layout, never initialised.
                unsafe { alloc::alloc::dealloc(h.cast(), layout) };
                return Err(e);
            }
        };
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let tcb = (stack.hi() - core::mem::size_of::<Tcb>() as u64) & !63;
        // SAFETY: the TCB lies inside the stack mapping just made (read/write, ours, unused);
        // `h` is a fresh allocation of the right layout.
        unsafe {
            (tcb as *mut Tcb).write(Tcb { self_ptr: tcb, id, stack_lo: stack.lo(), stack_hi: stack.hi() });
            h.write(Inner { hdr: Hdr { run: run::<F, T>, free: free::<F, T>, tcb }, f: Some(f), result: None });
        }
        let block = Block(h.cast());
        let proc = crate::startup_handle(sys::TAG_PROC_SELF);
        match sys::thread_create(proc, thread_entry as *const () as u64, tcb, h as u64) {
            Ok(t) => {
                // SAFETY: a field address inside the live block (no reference is made).
                let result = unsafe { &raw mut (*h).result };
                Ok(JoinHandle { thread: Some(Owned::from_raw(t)), stack: Some(stack), block: Some(block), result, id })
            }
            Err(e) => {
                drop(block); // the thread never started: free it now
                stack_free(stack);
                Err(e)
            }
        }
    }
}

/// Start `f` on a new thread with the default stack.
pub fn spawn<F, T>(f: F) -> Result<JoinHandle<T>, i64>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Builder::new().spawn(f)
}

/// A thread's shared block, freed on drop (only once its thread can no longer touch it).
struct Block(*mut Hdr);
// SAFETY: moved between threads only after its thread ended (join, reap) or before it started.
unsafe impl Send for Block {}

impl Drop for Block {
    fn drop(&mut self) {
        // SAFETY: the block is live; see the type's comment for why nobody else uses it now.
        unsafe { ((*self.0).free)(self.0) }
    }
}

pub struct JoinHandle<T> {
    thread: Option<Owned>,
    stack: Option<Stack>,
    block: Option<Block>,
    result: *mut Option<T>,
    id: u64,
}

// SAFETY: `result` points into the thread's block, read only after the thread ended.
unsafe impl<T: Send> Send for JoinHandle<T> {}

impl<T> JoinHandle<T> {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The raw thread handle (for waiting on it together with other objects).
    pub fn handle(&self) -> sys::Handle {
        self.thread.as_ref().map_or(0, Owned::raw)
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| t.wait(sys::TERMINATED, 0).is_ok())
    }

    /// Wait for the thread: its closure's value, or `Err(exit code)` if it ended without
    /// returning (it called `thread_exit` itself).
    pub fn join(mut self) -> Result<T, i32> {
        let Some(t) = self.thread.take() else { return Err(sys::ERR_BAD_STATE as i32) };
        let _ = t.wait(sys::TERMINATED, sys::WAIT_FOREVER);
        fence(Ordering::Acquire);
        let code = sys::thread_exit_code(t.raw()) as i32;
        drop(t);
        if let Some(s) = self.stack.take() {
            stack_free(s);
        }
        // SAFETY: the thread has ended; the block is still ours (freed with `self`).
        let v = unsafe { (*self.result).take() };
        v.ok_or(code)
    }
}

impl<T> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        let (Some(thread), Some(stack), Some(block)) = (self.thread.take(), self.stack.take(), self.block.take()) else {
            return; // joined: the block is freed with `self.block`
        };
        let mut d = DETACHED.lock();
        if d.try_reserve(1).is_ok() {
            d.push(Detached { thread, stack, _block: block });
        } else {
            // Out of memory: keep everything forever rather than free memory still in use.
            core::mem::forget((thread, stack, block));
        }
    }
}

/// A detached thread that may still run. Field order: the block is freed last.
struct Detached {
    thread: Owned,
    stack: Stack,
    _block: Block,
}

static DETACHED: Mutex<Vec<Detached>> = Mutex::new(Vec::new());

/// Reclaim detached threads that have ended. Returns how many are still running.
pub fn reap() -> usize {
    let mut done: Vec<Detached> = Vec::new();
    let left = {
        let mut d = DETACHED.lock();
        let mut i = 0;
        while i < d.len() {
            if d[i].thread.wait(sys::TERMINATED, 0).is_ok() && done.try_reserve(1).is_ok() {
                done.push(d.swap_remove(i));
            } else {
                i += 1;
            }
        }
        d.len()
    };
    for t in done {
        let Detached { thread, stack, _block } = t;
        drop(thread);
        stack_free(stack);
    }
    left
}

/// Empty stack regions kept for reuse (tests, statistics).
pub fn cached_stacks() -> usize {
    FREE_STACKS.lock().len()
}
