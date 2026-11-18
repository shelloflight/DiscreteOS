//! Object signals: a small bit set (`super::sig`) plus a wait queue. Waiters block until any bit
//! of their mask is set, or their timeout passes. Setting bits is IRQ-safe (timer callbacks do it).
//!
//! Async waits: a port can *observe* an object's signals (`observe`). The observer is a
//! one-shot node: when one of its bits becomes set (or is set already), it is unlinked and handed
//! to its port, which posts a completion. Nodes are allocated before the wait-queue lock is taken
//! and handed over after it is dropped, so nothing allocates, frees or posts under it.
//!
//! Condition waits (`wait_for`): for waits whose condition is not a signal bit (a channel call's
//! reply, an exception's resolution). The condition is an atomic flag the waker sets *before*
//! calling `wake`, and the waiter tests it under the wait-queue lock, so a wake-up is never lost.

use core::cell::UnsafeCell;
use core::ffi::CStr;
use core::sync::atomic::{AtomicU32, Ordering};

use alloc::boxed::Box;

use super::port::{self, AsyncWait};
use super::{KResult, Status};
use crate::ffi::{self, RawWaitq, WAIT_FOREVER};

pub struct Signals {
    wq: UnsafeCell<RawWaitq>,
    bits: AtomicU32,
    /// Singly linked list of pending async waits (owned boxes), under the wait-queue lock.
    observers: UnsafeCell<*mut AsyncWait>,
}

// SAFETY: `bits` changes only under the wait-queue lock (reads may be lock-free); `observers` is
// only touched under the wait-queue lock (or in Drop, when no one else can reach the object); the
// wait queue itself is the C waitq, which is built for concurrent use.
unsafe impl Sync for Signals {}
// SAFETY: as above.
unsafe impl Send for Signals {}

/// Absolute deadline for a relative timeout (0 = none).
pub fn deadline(timeout_ns: u64) -> u64 {
    if timeout_ns == WAIT_FOREVER {
        0
    } else {
        ffi::now_ns().saturating_add(timeout_ns).max(1)
    }
}

impl Signals {
    pub const fn new(name: &'static CStr) -> Signals {
        Signals {
            wq: UnsafeCell::new(RawWaitq::new(name)),
            bits: AtomicU32::new(0),
            observers: UnsafeCell::new(core::ptr::null_mut()),
        }
    }

    pub fn get(&self) -> u32 {
        self.bits.load(Ordering::Acquire)
    }

    /// Clear `clear`, then set `set`; wakes the waiters if any bit became set.
    pub fn update(&self, clear: u32, set: u32) {
        self.update_with(clear, set, false);
    }

    /// `update`, waking the waiters on this CPU: the caller is about to block (a channel call),
    /// so the woken thread runs here next, without an IPI (synchronous IPC fast path).
    pub fn update_sync(&self, clear: u32, set: u32) {
        self.update_with(clear, set, true);
    }

    fn update_with(&self, clear: u32, set: u32, sync: bool) {
        // Nothing would change (only setting bits that are set): no lock, no wake-up. A clear
        // can only happen under the lock, after which a later set takes the slow path.
        if clear == 0 && self.bits.load(Ordering::Acquire) & set == set {
            return;
        }
        let wq = self.wq.get();
        let mut fired: *mut AsyncWait = core::ptr::null_mut();
        let new;
        // SAFETY: `wq` is a valid, initialised waitq that lives (and stays put) as long as `self`:
        // signals are embedded in objects behind a KRef, which never move. `observers` is only
        // touched under its lock.
        unsafe {
            let flags = ffi::spin_lock_irqsave(&raw mut (*wq).lock);
            let old = self.bits.load(Ordering::Relaxed);
            new = (old & !clear) | set;
            self.bits.store(new, Ordering::Release);
            if new & !old != 0 {
                if sync {
                    ffi::waitq_wake_all_sync(wq);
                } else {
                    ffi::waitq_wake_all(wq);
                }
                // Unlink the observers this satisfies (keeping the others in order).
                let mut link: *mut *mut AsyncWait = self.observers.get();
                while !(*link).is_null() {
                    let n = *link;
                    if (*n).mask & new != 0 {
                        *link = (*n).next;
                        (*n).next = fired;
                        fired = n;
                    } else {
                        link = &raw mut (*n).next;
                    }
                }
            }
            ffi::spin_unlock_irqrestore(&raw mut (*wq).lock, flags);
        }
        Self::fire_all(fired, new);
    }

    fn fire_all(mut list: *mut AsyncWait, bits: u32) {
        while !list.is_null() {
            // SAFETY: every node on the list is a leaked Box we unlinked above; we own it now.
            let node = unsafe { Box::from_raw(list) };
            list = node.next;
            port::fire(node, bits);
        }
    }

    /// Register a one-shot async wait. If one of its bits is set already it fires at once.
    pub fn observe(&self, mut node: Box<AsyncWait>) {
        let wq = self.wq.get();
        // SAFETY: as in `update_with`.
        let fire_now = unsafe {
            let flags = ffi::spin_lock_irqsave(&raw mut (*wq).lock);
            let cur = self.bits.load(Ordering::Relaxed);
            let now = cur & node.mask != 0;
            if !now {
                node.next = *self.observers.get();
                *self.observers.get() = Box::into_raw(node);
                ffi::spin_unlock_irqrestore(&raw mut (*wq).lock, flags);
                return;
            }
            ffi::spin_unlock_irqrestore(&raw mut (*wq).lock, flags);
            cur
        };
        port::fire(node, fire_now);
    }

    /// Remove the async waits of `port` with `key`; returns how many were removed.
    pub fn cancel(&self, port: usize, key: u64) -> u32 {
        let wq = self.wq.get();
        let mut removed: *mut AsyncWait = core::ptr::null_mut();
        let mut n = 0;
        // SAFETY: as in `update_with`.
        unsafe {
            let flags = ffi::spin_lock_irqsave(&raw mut (*wq).lock);
            let mut link: *mut *mut AsyncWait = self.observers.get();
            while !(*link).is_null() {
                let o = *link;
                if (*o).key == key && (*o).port_id() == port {
                    *link = (*o).next;
                    (*o).next = removed;
                    removed = o;
                    n += 1;
                } else {
                    link = &raw mut (*o).next;
                }
            }
            ffi::spin_unlock_irqrestore(&raw mut (*wq).lock, flags);
        }
        drop_list(removed);
        n
    }

    /// Wake every waiter without changing the bits (`wait_for` waiters re-test their condition).
    pub fn wake(&self, sync: bool) {
        let wq = self.wq.get();
        // SAFETY: as in `update_with`.
        unsafe {
            let flags = ffi::spin_lock_irqsave(&raw mut (*wq).lock);
            if sync {
                ffi::waitq_wake_all_sync(wq);
            } else {
                ffi::waitq_wake_all(wq);
            }
            ffi::spin_unlock_irqrestore(&raw mut (*wq).lock, flags);
        }
    }

    /// Wait until any bit of `mask` is set; returns the bits seen. `timeout_ns`: relative,
    /// `WAIT_FOREVER`, or 0 to poll. Thread context only (checked by the C side).
    pub fn wait(&self, mask: u32, timeout_ns: u64) -> KResult<u32> {
        let cur = self.get();
        if cur & mask != 0 {
            return Ok(cur);
        }
        if timeout_ns == 0 {
            return Err(Status::TimedOut);
        }
        match self.wait_cond(|| self.bits.load(Ordering::Relaxed) & mask != 0, deadline(timeout_ns)) {
            Ok(()) => Ok(self.get()),
            Err(Status::TimedOut) => {
                let cur = self.get();
                if cur & mask != 0 { Ok(cur) } else { Err(Status::TimedOut) }
            }
            Err(e) => Err(e),
        }
    }

    /// Wait until `cond()` is true (tested under the wait-queue lock; wakers set the condition
    /// first, then call `wake` or `update`). `deadline_ns`: absolute, 0 = none. Interruptible: a
    /// killed user thread stops waiting with `BadState`.
    pub fn wait_for(&self, cond: impl Fn() -> bool, deadline_ns: u64) -> KResult<()> {
        if cond() {
            return Ok(());
        }
        self.wait_cond(cond, deadline_ns)
    }

    fn wait_cond(&self, cond: impl Fn() -> bool, deadline_ns: u64) -> KResult<()> {
        let wq = self.wq.get();
        // SAFETY: `wq` stays valid while we wait (the caller holds a reference to the object).
        if !unsafe { ffi::thread_wait_intr_begin(wq) } {
            return Err(Status::BadState);
        }
        let r = loop {
            // SAFETY: as in `update_with`. waitq_wait is called with the lock held and releases it.
            unsafe {
                let flags = ffi::spin_lock_irqsave(&raw mut (*wq).lock);
                if cond() {
                    ffi::spin_unlock_irqrestore(&raw mut (*wq).lock, flags);
                    break Ok(());
                }
                match ffi::waitq_wait(wq, flags, deadline_ns) {
                    ffi::WAIT_OK => {}
                    ffi::WAIT_INTERRUPTED => break Err(Status::BadState),
                    _ => break if cond() { Ok(()) } else { Err(Status::TimedOut) },
                }
            }
        };
        // SAFETY: ends the wait published above.
        unsafe { ffi::thread_wait_intr_end() };
        r
    }
}

fn drop_list(mut list: *mut AsyncWait) {
    while !list.is_null() {
        // SAFETY: a list of leaked boxes we own (unlinked under the lock).
        let node = unsafe { Box::from_raw(list) };
        list = node.next;
        drop(node);
    }
}

impl Drop for Signals {
    /// The object is gone: its pending async waits are cancelled (no completion is posted).
    fn drop(&mut self) {
        drop_list(*self.observers.get_mut());
    }
}
