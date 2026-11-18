//! Debug log: the right to write text to the kernel console (and the kernel log ring).
//!
//! There is no ambient console access: the kernel hands `init` one Log handle (`WRITE`), and
//! whoever holds a handle may pass a copy on. Text is sanitized: control characters other than
//! newline, tab and backspace (console echo) become '?', so a program cannot send terminal escape
//! sequences through it.

use super::{Header, KRef, KResult, ObjType, Status};

pub struct LogObj {
    pub header: Header,
}

/// Longest text one `log_write` prints.
pub const MAX_WRITE: usize = 512;

impl LogObj {
    pub fn create() -> KResult<KRef<LogObj>> {
        KRef::try_new(LogObj {
            header: Header::new(ObjType::Log),
        })
        .map_err(|_| Status::NoMemory)
    }

    /// Record `text` in the kernel log as process `koid` (`name`) at `level`, and show it.
    pub fn write(&self, level: core::ffi::c_int, koid: u32, name: &[u8], text: &mut [u8]) {
        for b in text.iter_mut() {
            if (*b < 0x20 && !matches!(*b, b'\n' | b'\t' | 0x08)) || *b == 0x7F {
                *b = b'?';
            }
        }
        // Valid UTF-8 is kept as is; anything else byte by byte as ASCII ('?' for the rest).
        if core::str::from_utf8(text).is_err() {
            for b in text.iter_mut() {
                if !b.is_ascii() {
                    *b = b'?';
                }
            }
        }
        crate::klog::write_program(level, koid, name, text);
    }
}
