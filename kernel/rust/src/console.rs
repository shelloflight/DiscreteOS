//! `kprint!` / `kprintln!`: formatted output on the kernel console (VGA + serial), like kprintf.
//! A whole message is written under the console lock, and it is captured into the kernel log.

use core::fmt::{self, Write};

use crate::{ffi, klog};

/// Writes straight to the console. The caller holds the console lock.
pub(crate) struct Raw;

impl Raw {
    pub(crate) fn write_bytes(&mut self, b: &[u8]) {
        // SAFETY: valid byte slice; the caller holds the console lock (or the kernel is panicking).
        unsafe { ffi::console_write_locked(b.as_ptr(), b.len()) }
    }
}

impl Write for Raw {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

struct Captured;

impl Write for Captured {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Raw.write_bytes(s.as_bytes());
        klog::capture(s.as_bytes());
        Ok(())
    }
}

/// Runs `f` with the console lock held (bypassed while panicking, like the C side).
pub(crate) fn with_console<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: plain C calls; the lock is released below with the returned flags.
    let flags = unsafe { ffi::console_lock() };
    let r = f();
    // SAFETY: pairs with console_lock above.
    unsafe { ffi::console_unlock(flags) };
    r
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    with_console(|| {
        let _ = Captured.write_fmt(args);
    });
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { $crate::console::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($($arg:tt)*) => { $crate::console::_print(format_args!("{}\n", format_args!($($arg)*))) };
}
