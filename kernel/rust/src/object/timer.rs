//! Timer: a one-shot deadline that sets `SIGNALED` when it passes. Built on the kernel's
//! tickless timers (`struct ktimer`, fires on the CPU that set it, microsecond resolution).

use core::cell::UnsafeCell;
use core::ffi::c_void;

use super::signals::Signals;
use super::{Header, KRef, KResult, ObjType, Status, sig};
use crate::ffi::{self, RawKtimer};
use crate::sync::Mutex;

pub struct TimerObj {
    pub header: Header,
    pub signals: Signals,
    raw: UnsafeCell<RawKtimer>,
    ctl: Mutex<()>, // set/cancel one at a time (a ktimer must not be started from two CPUs at once)
}

// SAFETY: `raw` is only touched by the C timer code, under `ctl` (or in Drop, when no one else can
// reach the object); the callback only reads `signals`, which is Sync.
unsafe impl Sync for TimerObj {}
// SAFETY: as above.
unsafe impl Send for TimerObj {}

extern "C" fn fire(_t: *mut RawKtimer, ctx: *mut c_void) {
    // SAFETY: ctx is the TimerObj that armed this timer; it cancels the timer (synchronously)
    // before it can be freed, so it is alive while the callback runs.
    let t = unsafe { &*(ctx as *const TimerObj) };
    t.signals.update(0, sig::SIGNALED);
}

impl TimerObj {
    pub fn create() -> KResult<KRef<TimerObj>> {
        KRef::try_new(TimerObj {
            header: Header::new(ObjType::Timer),
            signals: Signals::new(c"timer"),
            raw: UnsafeCell::new(RawKtimer::new()),
            ctl: Mutex::new(c"timer.ctl", ()),
        })
        .map_err(|_| Status::NoMemory)
    }

    /// (Re)arm: clears `SIGNALED`, which is set again `delay_ns` from now.
    pub fn set(&self, delay_ns: u64) {
        let _g = self.ctl.lock();
        // SAFETY: `raw` lives as long as self (behind a KRef, never moves); `ctl` serialises
        // starts and cancels; ctx stays valid until Drop cancels the timer.
        unsafe {
            ffi::timer_cancel_sync(self.raw.get());
            self.signals.update(sig::SIGNALED, 0);
            ffi::timer_start_oneshot(self.raw.get(), delay_ns, fire, self as *const _ as *mut c_void);
        }
    }

    /// Disarm (a deadline that already passed stays signaled). True if it was still pending.
    pub fn cancel(&self) -> bool {
        let _g = self.ctl.lock();
        // SAFETY: as in `set`.
        unsafe { ffi::timer_cancel_sync(self.raw.get()) }
    }
}

impl Drop for TimerObj {
    fn drop(&mut self) {
        // SAFETY: after this the callback can no longer run or be running, so freeing is safe.
        unsafe { ffi::timer_cancel_sync(self.raw.get()) };
    }
}
