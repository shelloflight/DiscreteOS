//! The log service's protocol (docs/services.md).
//!
//! The log service gathers every record of the kernel log (kernel lines, and program output with
//! the writing process's name, set by the kernel) into one stream of **records**, not text lines:
//! each has a sequence number, a monotonic time, a level, an origin and a source. Kernel addresses
//! never reach it (the kernel filters them). Per-service levels come from the manifests: the
//! service manager tells the log service each service's level (`svc::LOG_LEVEL`), and records
//! below it are not kept.
//!
//! Readers connect to the `log.read` endpoint and call `READ`: `a` = the first sequence number
//! wanted, `b` = how many at most (1..=`MAX_PER_READ`), plus `WAIT` in `b` to wait until there is
//! at least one. The reply carries `Record`s; `a` = the sequence number to ask for next, `status` =
//! how many records were lost before the first one returned (a reader that fell behind).

use crate::proto::{HEADER, Header};
use crate::sys::{self, Handle};

/// Reader -> log service (a call).
pub const READ: u32 = 400;
/// In `READ`'s `b`: wait (up to the call's timeout) until a record is there.
pub const WAIT: u64 = 1 << 32;
pub const MAX_PER_READ: usize = 32;

pub const TEXT: usize = 120;
pub const SOURCE: usize = 24;

/// One record (wire format, `SIZE` bytes, little-endian).
#[derive(Clone, Copy)]
pub struct Record {
    pub seq: u64,
    /// Monotonic, microseconds since kernel entry.
    pub time_us: u64,
    /// `sys::LOG_*`.
    pub level: u8,
    /// `sys::KLOG_ORIGIN_*`.
    pub origin: u8,
    /// `sys::KLOG_CONTINUES`: the text goes on in the next record from this source.
    pub flags: u8,
    pub len: u8,
    pub koid: u32,
    pub source: [u8; SOURCE],
    pub text: [u8; TEXT],
}

pub const SIZE: usize = 8 + 8 + 4 + 4 + SOURCE + TEXT;

impl Default for Record {
    fn default() -> Self {
        Record { seq: 0, time_us: 0, level: 0, origin: 0, flags: 0, len: 0, koid: 0, source: [0; SOURCE], text: [0; TEXT] }
    }
}

impl Record {
    pub fn text(&self) -> &[u8] {
        &self.text[..usize::from(self.len).min(TEXT)]
    }
    /// `kernel` for kernel records, else the process name.
    pub fn source(&self) -> &[u8] {
        if self.origin == sys::KLOG_ORIGIN_KERNEL {
            return b"kernel";
        }
        let n = self.source.iter().position(|&c| c == 0).unwrap_or(SOURCE);
        &self.source[..n]
    }

    pub fn put(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.seq.to_le_bytes());
        b[8..16].copy_from_slice(&self.time_us.to_le_bytes());
        b[16] = self.level;
        b[17] = self.origin;
        b[18] = self.flags;
        b[19] = self.len;
        b[20..24].copy_from_slice(&self.koid.to_le_bytes());
        b[24..24 + SOURCE].copy_from_slice(&self.source);
        b[24 + SOURCE..SIZE].copy_from_slice(&self.text);
    }

    pub fn get(b: &[u8]) -> Option<Record> {
        if b.len() < SIZE {
            return None;
        }
        let u = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default());
        let mut r = Record {
            seq: u(0),
            time_us: u(8),
            level: b[16],
            origin: b[17],
            flags: b[18],
            len: b[19].min(TEXT as u8),
            koid: u32::from_le_bytes(b[20..24].try_into().unwrap_or_default()),
            ..Record::default()
        };
        r.source.copy_from_slice(&b[24..24 + SOURCE]);
        r.text.copy_from_slice(&b[24 + SOURCE..SIZE]);
        Some(r)
    }
}

/// A reader's view of one `READ`: the records, the sequence number to ask for next, and how many
/// were lost before them.
pub struct Batch {
    pub records: [Record; MAX_PER_READ],
    pub count: usize,
    pub next: u64,
    pub lost: u64,
}

/// `READ` over `ch` (a `log.read` channel).
pub fn read(ch: Handle, from: u64, max: usize, wait: bool, timeout_ns: u64) -> Result<Batch, i64> {
    let max = max.clamp(1, MAX_PER_READ);
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: READ, status: 0, a: from, b: max as u64 | if wait { WAIT } else { 0 } }.put(&mut req);
    let mut rep = [0u8; HEADER + MAX_PER_READ * SIZE];
    let n = sys::channel_call(ch, &req, &mut rep, timeout_ns)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.op != READ || h.status < 0 {
        return Err(if h.status < 0 { i64::from(h.status) } else { sys::ERR_INVALID_ARGS });
    }
    let mut b = Batch { records: [Record::default(); MAX_PER_READ], count: 0, next: h.a, lost: h.status as u64 };
    let mut at = HEADER;
    while at + SIZE <= n && b.count < MAX_PER_READ {
        if let Some(r) = Record::get(&rep[at..at + SIZE]) {
            b.records[b.count] = r;
            b.count += 1;
        }
        at += SIZE;
    }
    Ok(b)
}
