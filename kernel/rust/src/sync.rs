//! Synchronisation over the C primitives.
//!
//! `SpinLock<T>`: the kernel's C spinlock (same struct, same lock-order checking and self-deadlock
//! detection) wrapped around the data it protects. Always IRQ-safe: interrupts are off while held.
//! `Mutex<T>`, `Semaphore`, `Event`: the sleeping primitives of wait.h.

use core::cell::UnsafeCell;
use core::ffi::CStr;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::ffi::{self, RawEvent, RawMutex, RawSem, RawSpinlock, RawWaitq, WAIT_FOREVER};

pub struct SpinLock<T> {
    raw: UnsafeCell<RawSpinlock>,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialised by the lock; T moves between contexts, so it must be Send.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: as above.
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// `rank` is the lock-order class (`ffi::rank`); locks are taken in increasing rank.
    pub const fn new(name: &'static CStr, rank: u32, data: T) -> Self {
        SpinLock {
            raw: UnsafeCell::new(RawSpinlock::new(name, rank)),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        // SAFETY: `raw` is a valid, initialised spinlock that lives as long as `self`.
        let flags = unsafe { ffi::spin_lock_irqsave(self.raw.get()) };
        SpinGuard {
            lock: self,
            flags,
            _not_send: PhantomData,
        }
    }

    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        let mut flags = 0u64;
        // SAFETY: as in `lock`; `flags` is a valid out-pointer.
        if unsafe { ffi::spin_trylock_irqsave(self.raw.get(), &mut flags) } {
            Some(SpinGuard {
                lock: self,
                flags,
                _not_send: PhantomData,
            })
        } else {
            None
        }
    }
}

/// Held lock. Dropping it unlocks and restores the interrupt flag. Not `Send`: a lock is released
/// on the CPU that took it.
pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
    flags: u64,
    _not_send: PhantomData<*const ()>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves the lock is held, so no one else accesses `data`.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and `&mut self` makes this the only reference.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: this guard took the lock with these flags.
        unsafe { ffi::spin_unlock_irqrestore(self.lock.raw.get(), self.flags) }
    }
}

// ---- sleeping primitives (wait.h) -------------------------------------------------------------
// These block the calling thread, so they may only be used from threads (never from interrupt
// handlers, never while holding a SpinLock); the C side checks and panics with names.

/// Sleeping mutual exclusion around `T` (`struct kmutex`): FIFO hand-off, owner checked.
pub struct Mutex<T> {
    raw: UnsafeCell<RawMutex>,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialised by the mutex; T moves between threads, so it must be Send.
unsafe impl<T: Send> Sync for Mutex<T> {}
// SAFETY: as above.
unsafe impl<T: Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(name: &'static CStr, data: T) -> Self {
        Mutex {
            raw: UnsafeCell::new(RawMutex {
                wq: RawWaitq::new(name),
                owner: core::ptr::null_mut(),
            }),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        // SAFETY: `raw` is a valid, initialised kmutex that lives as long as `self` (and cannot move
        // while borrowed by a waiter).
        unsafe { ffi::kmutex_lock(self.raw.get()) };
        MutexGuard {
            lock: self,
            _not_send: PhantomData,
        }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        // SAFETY: as in `lock`.
        if unsafe { ffi::kmutex_trylock(self.raw.get()) } {
            Some(MutexGuard {
                lock: self,
                _not_send: PhantomData,
            })
        } else {
            None
        }
    }
}

/// Held mutex. Not `Send`: the owning thread must unlock it.
pub struct MutexGuard<'a, T> {
    lock: &'a Mutex<T>,
    _not_send: PhantomData<*const ()>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves this thread owns the mutex.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and `&mut self` makes this the only reference.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: this thread owns the mutex (guard exists).
        unsafe { ffi::kmutex_unlock(self.lock.raw.get()) }
    }
}

/// Counting semaphore (`struct ksem`). `up` is safe from interrupt handlers.
pub struct Semaphore {
    raw: UnsafeCell<RawSem>,
}

// SAFETY: all state is behind the C wait-queue lock.
unsafe impl Sync for Semaphore {}
// SAFETY: as above.
unsafe impl Send for Semaphore {}

impl Semaphore {
    pub const fn new(name: &'static CStr, count: i64) -> Self {
        Semaphore {
            raw: UnsafeCell::new(RawSem {
                wq: RawWaitq::new(name),
                count,
            }),
        }
    }

    pub fn down(&self) {
        self.down_timeout(WAIT_FOREVER);
    }

    /// False on timeout (`0` polls without blocking).
    pub fn down_timeout(&self, timeout_ns: u64) -> bool {
        // SAFETY: valid, initialised ksem living as long as `self`.
        unsafe { ffi::ksem_down_timeout(self.raw.get(), timeout_ns) }
    }

    pub fn up(&self) {
        // SAFETY: as above.
        unsafe { ffi::ksem_up(self.raw.get()) }
    }
}

/// Event (`struct kevent`): manual-reset wakes everyone and stays signaled; auto-reset wakes one.
pub struct Event {
    raw: UnsafeCell<RawEvent>,
}

// SAFETY: all state is behind the C wait-queue lock.
unsafe impl Sync for Event {}
// SAFETY: as above.
unsafe impl Send for Event {}

impl Event {
    pub const fn new(name: &'static CStr, auto_reset: bool) -> Self {
        Event {
            raw: UnsafeCell::new(RawEvent {
                wq: RawWaitq::new(name),
                signaled: 0,
                auto_reset: auto_reset as u32,
            }),
        }
    }

    pub fn wait(&self) {
        self.wait_timeout(WAIT_FOREVER);
    }

    /// False on timeout (`0` polls without blocking).
    pub fn wait_timeout(&self, timeout_ns: u64) -> bool {
        // SAFETY: valid, initialised kevent living as long as `self`.
        unsafe { ffi::kevent_wait(self.raw.get(), timeout_ns) }
    }

    pub fn signal(&self) {
        // SAFETY: as above.
        unsafe { ffi::kevent_signal(self.raw.get()) }
    }

    pub fn reset(&self) {
        // SAFETY: as above.
        unsafe { ffi::kevent_reset(self.raw.get()) }
    }
}
