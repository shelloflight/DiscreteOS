//! Kernel log: a fixed ring of timestamped, leveled records (see kernel/include/klog.h).
//!
//! - Fixed-size slots (no allocation; usable from the first instruction of kmain and from IRQs).
//! - Monotonic sequence numbers: a reader that fell behind skips to the oldest surviving record
//!   and can tell how many it missed.
//! - kprintf/kprintln output is captured line by line, so the ring holds the whole boot log.
//! - While the kernel is panicking every path only *tries* the lock, so logging can never hang
//!   the panic report.

use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::fmt::Write;
use core::ops::{Deref, DerefMut};

use crate::console::{self, Raw};
use crate::ffi::{self, KLOG_DEBUG, KLOG_ERROR, KLOG_INFO, KLOG_WARN, rank};
use crate::sync::{SpinGuard, SpinLock};

pub const MSG_MAX: usize = 120;
pub const SOURCE_MAX: usize = 24;
pub const SLOTS: usize = 512; // 512 x 176 B = 88 KiB

/// Where a record came from.
pub const ORIGIN_KERNEL: u8 = 0;
/// A program's `log_write` / `log_record`: `koid` and `source` name the process.
pub const ORIGIN_PROGRAM: u8 = 1;
/// `flags`: the text did not end with a newline (the next record of this process continues it).
pub const FLAG_CONTINUES: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KlogEntry {
    pub seq: u64,
    pub time_us: u64,
    pub level: u8,
    pub len: u8,
    pub origin: u8,
    pub flags: u8,
    pub koid: u32,
    /// The writing process's name (programs; empty for the kernel), set by the kernel: a program
    /// cannot write under another's name.
    pub source: [u8; SOURCE_MAX],
    pub text: [u8; MSG_MAX],
    pub reserved: [u8; 8],
}
const _: () = assert!(core::mem::size_of::<KlogEntry>() == 176);

impl KlogEntry {
    const EMPTY: KlogEntry = KlogEntry {
        seq: 0,
        time_us: 0,
        level: 0,
        len: 0,
        origin: ORIGIN_KERNEL,
        flags: 0,
        koid: 0,
        source: [0; SOURCE_MAX],
        text: [0; MSG_MAX],
        reserved: [0; 8],
    };

    pub fn text(&self) -> &[u8] {
        &self.text[..usize::from(self.len).min(MSG_MAX)]
    }
}

struct Ring {
    slots: [KlogEntry; SLOTS],
    next_seq: u64,
    line: [u8; MSG_MAX], // kprintf line being assembled
    line_len: usize,
    line_time: u64,
}

impl Ring {
    fn oldest(&self) -> u64 {
        self.next_seq.saturating_sub(SLOTS as u64)
    }

    fn push(&mut self, level: u8, time_us: u64, text: &[u8]) {
        self.push_from(level, time_us, None, 0, text);
    }

    /// One record per `MSG_MAX` bytes; `from`: (process koid, name) for program records.
    /// `flags` go on the last record (the earlier ones continue into the next).
    fn push_from(&mut self, level: u8, time_us: u64, from: Option<(u32, &[u8])>, flags: u8, text: &[u8]) {
        let mut chunks = text.chunks(MSG_MAX).peekable();
        // An empty message still gets a record.
        let empty: &[u8] = &[];
        let mut first = true;
        while first || chunks.peek().is_some() {
            let chunk = chunks.next().unwrap_or(empty);
            first = false;
            let seq = self.next_seq;
            let e = &mut self.slots[(seq % SLOTS as u64) as usize];
            e.seq = seq;
            e.time_us = time_us;
            e.level = level;
            e.len = chunk.len() as u8; // chunk.len() <= MSG_MAX < 256
            e.text[..chunk.len()].copy_from_slice(chunk);
            e.flags = if chunks.peek().is_some() { FLAG_CONTINUES } else { flags };
            match from {
                Some((koid, name)) => {
                    e.origin = ORIGIN_PROGRAM;
                    e.koid = koid;
                    let n = name.len().min(SOURCE_MAX);
                    e.source = [0; SOURCE_MAX];
                    e.source[..n].copy_from_slice(&name[..n]);
                }
                None => {
                    e.origin = ORIGIN_KERNEL;
                    e.koid = 0;
                    e.source = [0; SOURCE_MAX];
                }
            }
            self.next_seq = seq + 1;
        }
    }

    fn commit_line(&mut self) {
        let (n, t) = (self.line_len, self.line_time);
        let line = self.line;
        self.push(KLOG_INFO as u8, t, &line[..n]);
        self.line_len = 0;
    }

    fn capture(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                b'\r' => {}
                b'\n' => self.commit_line(),
                _ => {
                    if self.line_len == 0 {
                        self.line_time = ffi::now_ns() / 1000;
                    }
                    self.line[self.line_len] = b;
                    self.line_len += 1;
                    if self.line_len == MSG_MAX {
                        self.commit_line();
                    }
                }
            }
        }
    }

    fn read(&self, seq: u64) -> Option<KlogEntry> {
        let s = seq.max(self.oldest());
        (s < self.next_seq).then(|| self.slots[(s % SLOTS as u64) as usize])
    }
}

// The ring is all zeros initially, so it lives in .bss (72 KiB that are not stored in the kernel
// image). The lock is a separate static: its name pointer would otherwise drag the ring into .data.
struct RingCell(UnsafeCell<Ring>);
// SAFETY: the ring is only reached through `RingGuard`, which holds `LOCK`.
unsafe impl Sync for RingCell {}

static RING: RingCell = RingCell(UnsafeCell::new(Ring {
    slots: [KlogEntry::EMPTY; SLOTS],
    next_seq: 0,
    line: [0; MSG_MAX],
    line_len: 0,
    line_time: 0,
}));
static LOCK: SpinLock<()> = SpinLock::new(c"klog", rank::KLOG, ());

struct RingGuard(#[allow(dead_code)] SpinGuard<'static, ()>);

impl Deref for RingGuard {
    type Target = Ring;
    fn deref(&self) -> &Ring {
        // SAFETY: this guard holds LOCK, which serialises all access to RING.
        unsafe { &*RING.0.get() }
    }
}

impl DerefMut for RingGuard {
    fn deref_mut(&mut self) -> &mut Ring {
        // SAFETY: as above; `&mut self` makes this the only reference.
        unsafe { &mut *RING.0.get() }
    }
}

fn ring() -> Option<RingGuard> {
    let g = if ffi::panicking() {
        LOCK.try_lock()
    } else {
        Some(LOCK.lock())
    };
    g.map(RingGuard)
}

/// Highest level that is echoed to the console.
const CONSOLE_LEVEL: c_int = if cfg!(ktest) { KLOG_DEBUG } else { KLOG_INFO };

fn level_name(level: c_int) -> &'static str {
    match level {
        KLOG_ERROR => "error",
        KLOG_WARN => "warn",
        KLOG_INFO => "info",
        _ => "debug",
    }
}

/// Record a message and echo it to the console as `[    s.micros] level: text`.
pub fn write(level: c_int, text: &[u8]) {
    let level = level.clamp(KLOG_ERROR, KLOG_DEBUG);
    let time_us = ffi::now_ns() / 1000;
    if let Some(mut r) = ring() {
        r.push(level as u8, time_us, text);
    }
    if level <= CONSOLE_LEVEL {
        console::with_console(|| {
            let mut out = Raw;
            let _ = write!(
                out,
                "[{:5}.{:06}] {}: ",
                time_us / 1_000_000,
                time_us % 1_000_000,
                level_name(level)
            );
            out.write_bytes(text);
            out.write_bytes(b"\n");
        });
    }
}

/// A program's text (`log_write`, `log_record`): one record per line, attributed to the
/// process (koid and name, as the kernel knows them); a last line without a newline is marked
/// `FLAG_CONTINUES`. Echoed to the console as written (debug records only in test builds), but
/// not captured a second time.
pub fn write_program(level: c_int, koid: u32, name: &[u8], text: &[u8]) {
    let level = level.clamp(KLOG_ERROR, KLOG_DEBUG);
    let time_us = ffi::now_ns() / 1000;
    if let Some(mut r) = ring() {
        let mut rest = text;
        while !rest.is_empty() {
            let (line, flags, next) = match rest.iter().position(|&c| c == b'\n') {
                Some(i) => (&rest[..i], 0, &rest[i + 1..]),
                None => (rest, FLAG_CONTINUES, &rest[rest.len()..]),
            };
            r.push_from(level as u8, time_us, Some((koid, name)), flags, line);
            rest = next;
        }
    }
    if level <= CONSOLE_LEVEL {
        console::with_console(|| Raw.write_bytes(text));
    }
}

/// Replace kernel addresses in `text` (runs of hex digits, with or without `0x`, whose value
/// lies in the kernel half, 0xFFFF800000000000 and up) with `[kaddr]`: what a reader in user
/// space gets, so the log never tells it where the kernel is (KASLR). Returns the new length.
pub fn filter_kernel_addresses(text: &mut [u8; MSG_MAX], len: usize) -> usize {
    const MARK: &[u8] = b"[kaddr]";
    let src = *text;
    let src = &src[..len.min(MSG_MAX)];
    let mut out = 0;
    let mut i = 0;
    while i < src.len() {
        let prefixed = src[i] == b'0' && src.get(i + 1).is_some_and(|&c| c == b'x' || c == b'X');
        let start = if prefixed { i + 2 } else { i };
        let digits = src[start.min(src.len())..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
        // A run starts a token: not in the middle of a longer word.
        let at_boundary = i == 0 || !src[i - 1].is_ascii_alphanumeric();
        if at_boundary && digits >= 9 {
            let run = &src[start..start + digits];
            // The value of the last 16 digits (longer runs are not addresses but may hide one).
            let tail = &run[run.len().saturating_sub(16)..];
            let v = tail.iter().fold(0u64, |a, &c| (a << 4) | u64::from((c as char).to_digit(16).unwrap_or(0)));
            if digits >= 16 && v >= 0xFFFF_8000_0000_0000 || digits > 16 {
                text[out..out + MARK.len()].copy_from_slice(MARK);
                out += MARK.len();
                i = start + digits;
                continue;
            }
        }
        text[out] = src[i];
        out += 1;
        i += 1;
    }
    out
}

/// Console text printed by kprintf/kprintln (already on screen): split into INFO records.
pub fn capture(bytes: &[u8]) {
    if let Some(mut r) = ring() {
        r.capture(bytes);
    }
}

/// First record with sequence >= `seq`, if any.
pub fn read(seq: u64) -> Option<KlogEntry> {
    ring()?.read(seq)
}

/// Records lost to overwrites so far.
pub fn dropped() -> u64 {
    ring().map_or(0, |r| r.oldest())
}

/// Sequence number the next record will get.
pub fn next_seq() -> u64 {
    ring().map_or(0, |r| r.next_seq)
}

/// Formatted logging from Rust: `klog!(KLOG_WARN, "x = {}", x)`.
#[macro_export]
macro_rules! klog {
    ($level:expr, $($arg:tt)*) => {{
        let mut b = $crate::fmtbuf::FmtBuf::<{ $crate::klog::MSG_MAX }>::new();
        let _ = core::fmt::Write::write_fmt(&mut b, format_args!($($arg)*));
        $crate::klog::write($level, b.as_bytes());
    }};
}

// ---- C interface (klog.h) -------------------------------------------------------------

/// # Safety
/// `s` must point to `n` readable bytes (or be NULL).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn klog_write(level: c_int, s: *const u8, n: usize) {
    if s.is_null() {
        return;
    }
    // SAFETY: caller contract.
    write(level, unsafe { core::slice::from_raw_parts(s, n) });
}

/// # Safety
/// `s` must point to `n` readable bytes (or be NULL).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn klog_capture(s: *const u8, n: usize) {
    if s.is_null() {
        return;
    }
    // SAFETY: caller contract.
    capture(unsafe { core::slice::from_raw_parts(s, n) });
}

/// # Safety
/// `seq` and `out` must be valid, writable pointers (NULL returns false).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn klog_read(seq: *mut u64, out: *mut KlogEntry) -> bool {
    if seq.is_null() || out.is_null() {
        return false;
    }
    // SAFETY: caller contract.
    unsafe {
        match read(*seq) {
            Some(e) => {
                out.write(e);
                *seq = e.seq + 1;
                true
            }
            None => false,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn klog_dropped() -> u64 {
    dropped()
}
