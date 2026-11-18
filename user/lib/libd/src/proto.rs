//! Device manager <-> driver protocol, over the channel the manager gives each driver
//! (startup tag `TAG_CONTROL`). Every message starts with a 32-byte header; requests from the
//! manager are `channel_call`s (the kernel puts its transaction id in `txid`) and the driver
//! answers with the same `txid`. Messages the driver sends on its own (READY, KEY) have txid 0.
//! Payload (block data) follows the header.
//!
//! Block drivers also announce each disk they serve (`DISK`, one per unit). The
//! manager then attaches a channel per disk (`BLK_ATTACH`, carrying the channel), which it hands
//! to the storage service: block I/O does not pass through the manager. Requests on an attached
//! channel name no unit (the channel is the disk); on the control channel they address unit 0.

pub const TAG_CONTROL: u32 = crate::sys::TAG_USER;

/// Driver -> manager: initialised; `a` = capacity in sectors (block) or 0.
pub const READY: u32 = 1;
/// Driver -> manager: a key; `a` = the character.
pub const KEY: u32 = 2;
/// Device manager -> each client of its `input` endpoint: a key typed. `a` = the character
/// (US layout; `\n` Enter, 0x08 Backspace), `b` = which input device (an index); payload: the
/// driver's name (`ps2`, `xhci`, `virtio-input`).
pub const INPUT_KEY: u32 = 410;
/// Manager -> block driver: read `b` sectors from `a`; reply carries the data.
pub const BLK_READ: u32 = 10;
/// Manager -> block driver: write `b` sectors at `a` (data in the payload).
pub const BLK_WRITE: u32 = 11;
/// Manager -> driver: report counters; reply `a` = interrupts handled, `b` = requests done.
pub const STATS: u32 = 12;
/// -> block driver: make everything written so far durable (device cache flushed).
pub const BLK_FLUSH: u32 = 13;
/// Driver -> manager: unit `a` is a disk of `b` sectors; payload = a short model name.
pub const DISK: u32 = 3;
/// Manager -> block driver: serve unit `a` on the channel this message carries (no reply).
pub const BLK_ATTACH: u32 = 14;
/// Manager -> driver (tests): fault on purpose (restart test).
pub const TEST_CRASH: u32 = 20;
/// Manager -> block driver (tests): point a request at memory the device was not given (the
/// kernel image's physical address); reply `status` = what the device reported.
pub const TEST_DMA_ESCAPE: u32 = 21;

pub const HEADER: usize = 32;
pub const SECTOR: usize = 512;
/// Largest transfer in one message (fits a channel message with the header).
pub const MAX_SECTORS: u64 = 64;

#[derive(Clone, Copy, Default, Debug)]
pub struct Header {
    pub txid: u32,
    pub op: u32,
    pub status: i32,
    pub a: u64,
    pub b: u64,
}

impl Header {
    pub fn put(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.txid.to_le_bytes());
        buf[4..8].copy_from_slice(&self.op.to_le_bytes());
        buf[8..12].copy_from_slice(&self.status.to_le_bytes());
        buf[12..16].copy_from_slice(&[0; 4]);
        buf[16..24].copy_from_slice(&self.a.to_le_bytes());
        buf[24..32].copy_from_slice(&self.b.to_le_bytes());
    }

    /// Parse a message (untrusted: from the other process). None if it is too short.
    pub fn get(buf: &[u8]) -> Option<Header> {
        if buf.len() < HEADER {
            return None;
        }
        let u32_at = |i: usize| u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let u64_at = |i: usize| u64::from(u32_at(i)) | u64::from(u32_at(i + 4)) << 32;
        Some(Header { txid: u32_at(0), op: u32_at(4), status: u32_at(8) as i32, a: u64_at(16), b: u64_at(24) })
    }
}

/// Driver status for a failed request (the device reported an error).
pub const ERR_IO: i32 = -105;

/// Send an unsolicited message (txid 0).
pub fn send(ch: crate::Handle, op: u32, a: u64, b: u64) -> i64 {
    let mut buf = [0u8; HEADER];
    Header { txid: 0, op, status: 0, a, b }.put(&mut buf);
    crate::sys::channel_write(ch, &buf)
}
