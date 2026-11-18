//! Locks for threads of one process.
//!
//! `RawMutex` is a futex-style lock: one atomic compare-and-swap to take it and one swap to drop
//! it when nobody waits, no syscall. A contended waiter sleeps on a kernel event that the mutex
//! creates the first time it is contended; the holder signals it on unlock. If the event cannot be
//! created (out of handles or memory) waiters yield instead: slower, never an error.
//!
//! State: 0 free, 1 held, 2 held and maybe waited on. A waiter always sets 2 before it sleeps and
//! clears the event before it re-checks, so a wake-up is never lost: whoever holds the lock after
//! that check will see 2 and signal.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::sys;

const FREE: u32 = 0;
const HELD: u32 = 1;
const CONTENDED: u32 = 2;
/// The event could not be created: waiters yield.
const NO_EVENT: u32 = u32::MAX;

/// Tests only: make event creation look failed (proves the yielding fallback).
#[doc(hidden)]
pub static FAIL_EVENTS: AtomicBool = AtomicBool::new(false);
/// How often a lock had to wait (sleep or yield) in this process.
static WAITS: AtomicU64 = AtomicU64::new(0);

/// Contended waits so far (all mutexes of this process).
pub fn contended_waits() -> u64 {
    WAITS.load(Ordering::Relaxed)
}

/// The lock itself, without data (also the layout of `libd_mutex_t` in libd.h).
#[repr(C)]
#[derive(Default)]
pub struct RawMutex {
    state: AtomicU32,
    event: AtomicU32,
}

impl RawMutex {
    pub const fn new() -> RawMutex {
        RawMutex { state: AtomicU32::new(FREE), event: AtomicU32::new(0) }
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        self.state.compare_exchange(FREE, HELD, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    #[inline]
    pub fn lock(&self) {
        if !self.try_lock() {
            self.lock_slow();
        }
    }

    #[cold]
    fn lock_slow(&self) {
        // Spin briefly: most holders are done within a few hundred cycles.
        for _ in 0..100 {
            core::hint::spin_loop();
            if self.state.load(Ordering::Relaxed) == FREE && self.try_lock() {
                return;
            }
        }
        WAITS.fetch_add(1, Ordering::Relaxed);
        let ev = self.event();
        while self.state.swap(CONTENDED, Ordering::Acquire) != FREE {
            if ev == NO_EVENT {
                sys::yield_now();
            } else {
                let _ = sys::object_wait(ev, sys::SIGNALED, sys::WAIT_FOREVER);
                sys::event_signal(ev, sys::SIGNALED, 0);
            }
        }
    }

    #[inline]
    pub fn unlock(&self) {
        if self.state.swap(FREE, Ordering::Release) == CONTENDED {
            let ev = self.event.load(Ordering::Acquire);
            if ev != 0 && ev != NO_EVENT {
                sys::event_signal(ev, 0, sys::SIGNALED);
            }
        }
    }

    /// The wake-up event, created on first use (or `NO_EVENT`).
    fn event(&self) -> u32 {
        let ev = self.event.load(Ordering::Acquire);
        if ev != 0 {
            return ev;
        }
        let new = if FAIL_EVENTS.load(Ordering::Relaxed) { Err(sys::ERR_NO_MEMORY) } else { sys::event_create() };
        let new = new.unwrap_or(NO_EVENT);
        match self.event.compare_exchange(0, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => new,
            Err(won) => {
                if new != NO_EVENT {
                    sys::handle_close(new);
                }
                won
            }
        }
    }

    /// Close the event (the mutex must be free and unused from now on, or used again from scratch).
    pub fn destroy(&self) {
        let ev = self.event.swap(0, Ordering::AcqRel);
        if ev != 0 && ev != NO_EVENT {
            sys::handle_close(ev);
        }
    }
}

impl Drop for RawMutex {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// A mutex owning its data.
pub struct Mutex<T: ?Sized> {
    raw: RawMutex,
    data: UnsafeCell<T>,
}

// SAFETY: the data is only reached through a guard, and only one guard exists at a time.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
// SAFETY: as above.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(v: T) -> Mutex<T> {
        Mutex { raw: RawMutex::new(), data: UnsafeCell::new(v) }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.raw.lock();
        MutexGuard { m: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.raw.try_lock().then_some(MutexGuard { m: self })
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Mutex::new(T::default())
    }
}

pub struct MutexGuard<'a, T: ?Sized> {
    m: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock.
        unsafe { &*self.m.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock, and `&mut self` makes this the only reference.
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.m.raw.unlock();
    }
}

/// Run something exactly once, however many threads ask at the same time.
pub struct Once {
    state: AtomicU32,
}

impl Once {
    pub const fn new() -> Once {
        Once { state: AtomicU32::new(0) }
    }

    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2
    }

    /// Run `f` if nobody has yet; others wait (yielding) until it is done.
    pub fn call_once(&self, f: impl FnOnce()) {
        if self.is_completed() {
            return;
        }
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire).is_ok() {
            f();
            self.state.store(2, Ordering::Release);
            return;
        }
        while !self.is_completed() {
            sys::yield_now();
        }
    }
}

impl Default for Once {
    fn default() -> Self {
        Once::new()
    }
}
