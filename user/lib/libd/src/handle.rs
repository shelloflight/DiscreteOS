//! Owned handles: a handle that is closed when its owner goes away, so no path (early return, `?`,
//! panic-free error handling) can leak one. Raw `Handle` values stay available for the ABI calls
//! that move handles (`into_raw`), and for code that manages them by hand.

use crate::sys::{self, Handle};

/// A handle this program owns; closed on drop. `Owned::default()` holds none (value 0).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Owned(Handle);

impl Owned {
    /// Take ownership of `h` (0 is allowed and means "none").
    pub const fn from_raw(h: Handle) -> Owned {
        Owned(h)
    }

    pub const fn raw(&self) -> Handle {
        self.0
    }

    pub const fn is_valid(&self) -> bool {
        self.0 != 0
    }

    /// Give up ownership without closing (the handle is moved somewhere, e.g. into a message).
    pub fn into_raw(self) -> Handle {
        let h = self.0;
        core::mem::forget(self);
        h
    }

    /// A second handle to the same object with `rights` (a subset, or `RIGHTS_SAME`).
    pub fn dup(&self, rights: u32) -> Result<Owned, i64> {
        sys::handle_duplicate(self.0, rights).map(Owned)
    }

    /// This handle narrowed to `rights`; the old value is gone (even on error).
    pub fn replace(self, rights: u32) -> Result<Owned, i64> {
        sys::handle_replace(self.into_raw(), rights).map(Owned)
    }

    /// Signals seen, or `Err(TIMED_OUT)`.
    pub fn wait(&self, mask: u32, timeout: u64) -> Result<u32, i64> {
        sys::object_wait(self.0, mask, timeout)
    }

    pub fn info(&self) -> Result<sys::Info, i64> {
        sys::object_info(self.0)
    }

    /// The object's name into `buf`: its length.
    pub fn name(&self, buf: &mut [u8]) -> i64 {
        sys::object_name(self.0, buf)
    }

    /// Close now and report the result (drop closes too, ignoring it).
    pub fn close(self) -> i64 {
        sys::handle_close(self.into_raw())
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if self.0 != 0 {
            sys::handle_close(self.0);
        }
    }
}

/// A kernel event: one `SIGNALED` bit that stays set until cleared.
#[derive(Debug)]
pub struct Event(pub Owned);

impl Event {
    pub fn new() -> Result<Event, i64> {
        sys::event_create().map(|h| Event(Owned(h)))
    }
    pub fn signal(&self) -> i64 {
        sys::event_signal(self.0.raw(), 0, sys::SIGNALED)
    }
    pub fn clear(&self) -> i64 {
        sys::event_signal(self.0.raw(), sys::SIGNALED, 0)
    }
    /// True if it was (or became) signaled within `timeout` ns.
    pub fn wait(&self, timeout: u64) -> bool {
        self.0.wait(sys::SIGNALED, timeout).is_ok()
    }
}

/// A one-shot kernel timer: `SIGNALED` when it fires.
#[derive(Debug)]
pub struct Timer(pub Owned);

impl Timer {
    pub fn new() -> Result<Timer, i64> {
        sys::timer_create().map(|h| Timer(Owned(h)))
    }
    pub fn set(&self, delay_ns: u64) -> i64 {
        sys::timer_set(self.0.raw(), delay_ns)
    }
    pub fn cancel(&self) -> bool {
        sys::timer_cancel(self.0.raw()) == 1
    }
    pub fn wait(&self) -> bool {
        self.0.wait(sys::SIGNALED, sys::WAIT_FOREVER).is_ok()
    }
}

/// Sleep for `ns` nanoseconds (a timer; falls back to yielding until the clock passes if no timer
/// can be created, so out of handles or memory never ends the program).
pub fn sleep(ns: u64) {
    if let Ok(t) = Timer::new()
        && t.set(ns) == 0
        && t.wait()
    {
        return;
    }
    let end = sys::clock_ns().saturating_add(ns);
    while sys::clock_ns() < end {
        sys::yield_now();
    }
}
