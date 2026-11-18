//! The heap for ring-3 Rust programs (feature `alloc`), safe for many threads. Small blocks (up to
//! 2 KiB) come from size-class free lists carved out of 64 KiB arenas; larger ones get their own
//! VMO mapping, unmapped again on free (a VMO lives as long as it is mapped, so no handle is kept).
//!
//! One lock. It is held for a few instructions (a list push or pop, a bump), so contention is
//! short; a waiter that spins too long yields, so it never burns its time slice against a holder
//! that was preempted. Arenas are mapped outside the lock.
//!
//! Secure: a freed small block is filled with 0xDD before it goes back on its free list (stale
//! data does not leak to the next owner, and a use after free reads garbage, not old secrets).
//! Fast: `realloc` stays in place when the new size fits the block's size class or page count.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sys;

const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
const ARENA: u64 = 64 * 1024;
/// Spins before a contended lock yields the CPU.
const SPINS: u32 = 64;

struct Free {
    next: *mut Free,
}

struct State {
    free: [*mut Free; CLASSES.len()],
    /// Unused tail of the current arena.
    bump: u64,
    end: u64,
}

/// Heap statistics (`stats`): what is allocated right now, and the arenas behind small blocks.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Bytes handed out and not freed (small blocks counted at their class size, large ones at
    /// their page-rounded size).
    pub bytes: u64,
    /// Blocks handed out and not freed.
    pub blocks: u64,
    /// Large blocks (own mapping) among them.
    pub large: u64,
    /// 64 KiB arenas mapped for small blocks (never returned).
    pub arenas: u64,
}

pub struct Heap {
    lock: AtomicBool,
    st: core::cell::UnsafeCell<State>,
    bytes: AtomicU64,
    blocks: AtomicU64,
    large: AtomicU64,
    arenas: AtomicU64,
}

// SAFETY: every access to `st` happens with `lock` held; the counters are atomics.
unsafe impl Sync for Heap {}

impl Heap {
    pub const fn new() -> Heap {
        Heap {
            lock: AtomicBool::new(false),
            st: core::cell::UnsafeCell::new(State { free: [null_mut(); CLASSES.len()], bump: 0, end: 0 }),
            bytes: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            large: AtomicU64::new(0),
            arenas: AtomicU64::new(0),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let mut spins = 0;
        while self.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            spins += 1;
            if spins >= SPINS {
                sys::yield_now();
                spins = 0;
            } else {
                core::hint::spin_loop();
            }
        }
        // SAFETY: the lock is held, so this is the only reference.
        let r = f(unsafe { &mut *self.st.get() });
        self.lock.store(false, Ordering::Release);
        r
    }

    fn count(&self, bytes: u64, large: bool) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.blocks.fetch_add(1, Ordering::Relaxed);
        if large {
            self.large.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn uncount(&self, bytes: u64, large: bool) {
        self.bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.blocks.fetch_sub(1, Ordering::Relaxed);
        if large {
            self.large.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn stats(&self) -> Stats {
        Stats {
            bytes: self.bytes.load(Ordering::Relaxed),
            blocks: self.blocks.load(Ordering::Relaxed),
            large: self.large.load(Ordering::Relaxed),
            arenas: self.arenas.load(Ordering::Relaxed),
        }
    }

    /// A small block of class `c` from the free list or the current arena (null: none left).
    fn take(&self, c: usize) -> *mut u8 {
        let size = CLASSES[c] as u64;
        self.with(|s| {
            let head = s.free[c];
            if !head.is_null() {
                // SAFETY: a block on the free list is ours and holds a `Free` link.
                s.free[c] = unsafe { (*head).next };
                return head.cast();
            }
            let at = s.bump.div_ceil(size) * size;
            if at + size > s.end {
                return null_mut();
            }
            s.bump = at + size;
            at as *mut u8
        })
    }

    fn small(&self, c: usize) -> *mut u8 {
        let p = self.take(c);
        if !p.is_null() {
            return p;
        }
        // Map a new arena without holding the lock, then install it (the tail of the old one is
        // given up; several threads may map one each, the losers' arenas still serve later).
        let a = map(ARENA);
        if a == 0 {
            return null_mut();
        }
        self.arenas.fetch_add(1, Ordering::Relaxed);
        let size = CLASSES[c] as u64;
        self.with(|s| {
            (s.bump, s.end) = (a + size, a + ARENA);
        });
        a as *mut u8
    }
}

impl Default for Heap {
    fn default() -> Self {
        Heap::new()
    }
}

fn class(l: &Layout) -> Option<usize> {
    let need = l.size().max(l.align());
    CLASSES.iter().position(|&c| c >= need)
}

fn pages(size: usize) -> u64 {
    size.div_ceil(sys::PAGE as usize) as u64 * sys::PAGE
}

fn map(len: u64) -> u64 {
    let Ok(vmo) = sys::vmo_create(len) else { return 0 };
    let addr = sys::vmar_map(crate::root_vmar(), sys::ANY, vmo, 0, len, sys::RIGHT_READ | sys::RIGHT_WRITE);
    sys::handle_close(vmo); // the mapping keeps the VMO alive
    addr.unwrap_or(0)
}

// SAFETY: blocks are handed out once and only reused after `dealloc`; arenas and large
// mappings are page aligned, and a size class is a power of two that is at least the alignment,
// so every block is aligned (arenas are carved in class-size steps from a page boundary).
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        match class(&l) {
            Some(c) => {
                let p = self.small(c);
                if !p.is_null() {
                    self.count(CLASSES[c] as u64, false);
                }
                p
            }
            None => {
                if l.align() > sys::PAGE as usize {
                    return null_mut();
                }
                let len = pages(l.size());
                let p = map(len) as *mut u8;
                if !p.is_null() {
                    self.count(len, true);
                }
                p
            }
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        match class(&l) {
            Some(c) => {
                // SAFETY: `p` is a live block of this class (GlobalAlloc contract).
                unsafe { core::ptr::write_bytes(p, 0xDD, CLASSES[c]) };
                self.with(|s| {
                    let f = p.cast::<Free>();
                    // SAFETY: as above; the block is now ours to link.
                    unsafe { (*f).next = s.free[c] };
                    s.free[c] = f;
                });
                self.uncount(CLASSES[c] as u64, false);
            }
            None => {
                let len = pages(l.size());
                sys::vmar_unmap(crate::root_vmar(), p as u64, len);
                self.uncount(len, true);
            }
        }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller guarantees `l.align()` is valid and `new_size` does not overflow it.
        let nl = unsafe { Layout::from_size_align_unchecked(new_size, l.align()) };
        let same = match (class(&l), class(&nl)) {
            (Some(a), Some(b)) => a == b,
            (None, None) => pages(l.size()) == pages(new_size),
            _ => false,
        };
        if same {
            return p;
        }
        // SAFETY: GlobalAlloc contract, forwarded.
        let q = unsafe { self.alloc(nl) };
        if !q.is_null() {
            // SAFETY: both blocks are live and at least min(old, new) bytes long; they are distinct.
            unsafe {
                core::ptr::copy_nonoverlapping(p, q, l.size().min(new_size));
                self.dealloc(p, l);
            }
        }
        q
    }
}

#[global_allocator]
static HEAP: Heap = Heap::new();

/// What the heap holds right now (leak checks, tests).
pub fn stats() -> Stats {
    HEAP.stats()
}
