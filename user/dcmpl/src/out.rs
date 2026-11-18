//! Output to the debug log (the LOG startup handle): `println!` formats into a small buffer and
//! writes it with one log_write per line (lines are not interleaved with other processes').

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::sys;

static LOG: AtomicU32 = AtomicU32::new(0);

pub fn set_log(h: sys::Handle) {
    LOG.store(h, Ordering::Relaxed);
}

pub fn log() -> sys::Handle {
    LOG.load(Ordering::Relaxed)
}

pub struct Out {
    buf: [u8; 512],
    n: usize,
}

impl Out {
    pub const fn new() -> Out {
        Out { buf: [0; 512], n: 0 }
    }
    pub fn flush(&mut self) {
        if self.n > 0 && log() != 0 {
            sys::log_write(log(), &self.buf[..self.n]);
        }
        self.n = 0;
    }
}

impl Default for Out {
    fn default() -> Self {
        Out::new()
    }
}

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.n == self.buf.len() {
                self.flush();
            }
            self.buf[self.n] = b;
            self.n += 1;
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments<'_>) {
    let mut o = Out::new();
    let _ = o.write_fmt(args);
    o.flush();
}

#[macro_export]
macro_rules! println {
    ($($t:tt)*) => { $crate::out::print(format_args!("{}\n", format_args!($($t)*))) };
}
