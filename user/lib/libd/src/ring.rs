//! Reusable shared-memory submission/completion I/O ring over a VMO (`libd::ring`).
//!
//! Layout inside a page-aligned VMO (minimum 2 pages):
//! - Page 0 (`0..4096`):
//!   - `0..32`: immutable configuration header (`magic`, `version`, `sq_entries`, `cq_entries`,
//!     `sq_off`, `cq_off`, `data_off`, `data_len`)
//!   - `64..72`: producer-owned atomics (`sq_tail`, `cq_head`) on their own cache line
//!   - `128..136`: consumer-owned atomics (`sq_head`, `cq_tail`) on their own cache line
//!   - `256..`: `Sqe[sq_entries]` (32 B each) followed by `Cqe[cq_entries]` (16 B each)
//! - Page 1+ (`data_off..data_off + data_len`): zero-copy payload data buffer.
//!
//! Security: `IoRing::attach` validates the VMO size and configuration header once and caches
//! the validated geometry in private fields, so a peer mutating header words later cannot induce
//! out-of-bounds reads or writes.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::sys::{self, Handle};

pub const MAGIC: u32 = 0x5249_4E47; // "RING"
pub const VERSION: u32 = 1;
pub const MAX_ENTRIES: u32 = 64;
pub const SQ_OFF: u32 = 256;
pub const DATA_OFF: u32 = 4096;

// Header word offsets (bytes) in Page 0.
const H_MAGIC: usize = 0;
const H_VERSION: usize = 4;
const H_SQ_ENTRIES: usize = 8;
const H_CQ_ENTRIES: usize = 12;
const H_SQ_OFF: usize = 16;
const H_CQ_OFF: usize = 20;
const H_DATA_OFF: usize = 24;
const H_DATA_LEN: usize = 28;
const H_SQ_TAIL: usize = 64;
const H_CQ_HEAD: usize = 68;
const H_SQ_HEAD: usize = 128;
const H_CQ_TAIL: usize = 132;

/// One submission queue entry (32 bytes, protocol-defined `op`/`a`/`b` + slice in the data buffer).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sqe {
    pub id: u32,
    pub op: u32,
    pub a: u64,
    pub b: u64,
    pub buf_off: u32,
    pub buf_len: u32,
}
const _: () = assert!(core::mem::size_of::<Sqe>() == 32);

/// One completion queue entry (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Cqe {
    pub id: u32,
    pub status: i32,
    pub a: u64,
}
const _: () = assert!(core::mem::size_of::<Cqe>() == 16);

/// A mapped shared-memory I/O ring (unmaps and closes its VMO on drop).
pub struct IoRing {
    vmo: Handle,
    addr: u64,
    map_len: u64,
    sq_entries: u32,
    cq_entries: u32,
    sq_off: u32,
    cq_off: u32,
    data_off: u32,
    data_len: u32,
}

impl IoRing {
    /// Create a new ring VMO with `entries` SQ and CQ slots (power of two, `1..=MAX_ENTRIES`)
    /// and a zero-copy data buffer of `data_len` bytes (rounded up to a whole number of pages).
    pub fn create(entries: u32, data_len: u32) -> Result<IoRing, i64> {
        if entries == 0 || entries > MAX_ENTRIES || !entries.is_power_of_two() || data_len == 0 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let data_len = data_len
            .checked_add(sys::PAGE as u32 - 1)
            .ok_or(sys::ERR_OUT_OF_RANGE)?
            & !(sys::PAGE as u32 - 1);
        let sq_off = SQ_OFF;
        let cq_off = sq_off + entries * (core::mem::size_of::<Sqe>() as u32);
        let cq_end = cq_off + entries * (core::mem::size_of::<Cqe>() as u32);
        if cq_end > DATA_OFF {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let map_len = u64::from(DATA_OFF) + u64::from(data_len);
        let vmo = sys::vmo_create(map_len)?;
        let addr = match sys::vmar_map(
            crate::root_vmar(),
            sys::ANY,
            vmo,
            0,
            map_len,
            sys::RIGHT_READ | sys::RIGHT_WRITE,
        ) {
            Ok(a) => a,
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let r = IoRing {
            vmo,
            addr,
            map_len,
            sq_entries: entries,
            cq_entries: entries,
            sq_off,
            cq_off,
            data_off: DATA_OFF,
            data_len,
        };
        r.word(H_SQ_ENTRIES).store(entries, Ordering::Relaxed);
        r.word(H_CQ_ENTRIES).store(entries, Ordering::Relaxed);
        r.word(H_SQ_OFF).store(sq_off, Ordering::Relaxed);
        r.word(H_CQ_OFF).store(cq_off, Ordering::Relaxed);
        r.word(H_DATA_OFF).store(DATA_OFF, Ordering::Relaxed);
        r.word(H_DATA_LEN).store(data_len, Ordering::Relaxed);
        r.word(H_SQ_HEAD).store(0, Ordering::Relaxed);
        r.word(H_SQ_TAIL).store(0, Ordering::Relaxed);
        r.word(H_CQ_HEAD).store(0, Ordering::Relaxed);
        r.word(H_CQ_TAIL).store(0, Ordering::Relaxed);
        r.word(H_VERSION).store(VERSION, Ordering::Relaxed);
        r.word(H_MAGIC).store(MAGIC, Ordering::Release);
        Ok(r)
    }

    /// Attach to an existing ring VMO received from a peer (takes ownership of `vmo` and closes
    /// it on error or drop). Validates header geometry before returning.
    pub fn attach(vmo: Handle) -> Result<IoRing, i64> {
        let map_len = match sys::vmo_size(vmo) {
            Ok(sz) if sz >= 2 * sys::PAGE => sz,
            Ok(_) => {
                sys::handle_close(vmo);
                return Err(sys::ERR_INVALID_ARGS);
            }
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let addr = match sys::vmar_map(
            crate::root_vmar(),
            sys::ANY,
            vmo,
            0,
            map_len,
            sys::RIGHT_READ | sys::RIGHT_WRITE,
        ) {
            Ok(a) => a,
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let mut r = IoRing {
            vmo,
            addr,
            map_len,
            sq_entries: 0,
            cq_entries: 0,
            sq_off: 0,
            cq_off: 0,
            data_off: 0,
            data_len: 0,
        };
        let magic = r.word(H_MAGIC).load(Ordering::Acquire);
        let version = r.word(H_VERSION).load(Ordering::Relaxed);
        let sq_entries = r.word(H_SQ_ENTRIES).load(Ordering::Relaxed);
        let cq_entries = r.word(H_CQ_ENTRIES).load(Ordering::Relaxed);
        let sq_off = r.word(H_SQ_OFF).load(Ordering::Relaxed);
        let cq_off = r.word(H_CQ_OFF).load(Ordering::Relaxed);
        let data_off = r.word(H_DATA_OFF).load(Ordering::Relaxed);
        let data_len = r.word(H_DATA_LEN).load(Ordering::Relaxed);

        let sq_bytes = sq_entries.checked_mul(core::mem::size_of::<Sqe>() as u32);
        let cq_bytes = cq_entries.checked_mul(core::mem::size_of::<Cqe>() as u32);
        let sq_end = sq_bytes.and_then(|b| sq_off.checked_add(b));
        let cq_end = cq_bytes.and_then(|b| cq_off.checked_add(b));
        let data_end = u64::from(data_off).checked_add(u64::from(data_len));

        let valid = magic == MAGIC
            && version == VERSION
            && sq_entries > 0
            && sq_entries <= MAX_ENTRIES
            && sq_entries.is_power_of_two()
            && cq_entries > 0
            && cq_entries <= MAX_ENTRIES
            && cq_entries.is_power_of_two()
            && sq_off >= SQ_OFF
            && sq_off.is_multiple_of(8)
            && cq_off.is_multiple_of(8)
            && sq_end.is_some_and(|e| e <= cq_off)
            && cq_end.is_some_and(|e| e <= data_off)
            && data_off >= DATA_OFF
            && data_off.is_multiple_of(sys::PAGE as u32)
            && data_len > 0
            && data_end.is_some_and(|e| e <= map_len);
        if !valid {
            drop(r); // unmaps and closes `vmo`
            return Err(sys::ERR_INVALID_ARGS);
        }
        r.sq_entries = sq_entries;
        r.cq_entries = cq_entries;
        r.sq_off = sq_off;
        r.cq_off = cq_off;
        r.data_off = data_off;
        r.data_len = data_len;
        Ok(r)
    }

    pub fn vmo(&self) -> Handle {
        self.vmo
    }

    pub fn data_len(&self) -> usize {
        self.data_len as usize
    }

    /// Borrow `[off, off + len)` inside the shared data buffer, or `None` if out of bounds.
    pub fn data(&self, off: u32, len: u32) -> Option<&[u8]> {
        let end = off.checked_add(len)?;
        if end > self.data_len {
            return None;
        }
        let p = (self.addr + u64::from(self.data_off) + u64::from(off)) as *const u8;
        // SAFETY: validated inside `[data_off, data_off + data_len) <= map_len`.
        Some(unsafe { core::slice::from_raw_parts(p, len as usize) })
    }

    /// Mutably borrow `[off, off + len)` inside the shared data buffer, or `None` if out of bounds.
    pub fn data_mut(&mut self, off: u32, len: u32) -> Option<&mut [u8]> {
        let end = off.checked_add(len)?;
        if end > self.data_len {
            return None;
        }
        let p = (self.addr + u64::from(self.data_off) + u64::from(off)) as *mut u8;
        // SAFETY: validated inside `[data_off, data_off + data_len) <= map_len`; `&mut self`
        // prevents local aliasing (peer synchronization is via SQ/CQ acquire/release).
        Some(unsafe { core::slice::from_raw_parts_mut(p, len as usize) })
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        // SAFETY: `off` is a fixed 4-byte-aligned header offset < 256 < map_len.
        unsafe { &*((self.addr + off as u64) as *const AtomicU32) }
    }

    fn sqe_ptr(&self, slot: u32) -> *mut Sqe {
        let idx = slot & (self.sq_entries - 1);
        (self.addr + u64::from(self.sq_off) + u64::from(idx) * (core::mem::size_of::<Sqe>() as u64)) as *mut Sqe
    }

    fn cqe_ptr(&self, slot: u32) -> *mut Cqe {
        let idx = slot & (self.cq_entries - 1);
        (self.addr + u64::from(self.cq_off) + u64::from(idx) * (core::mem::size_of::<Cqe>() as u64)) as *mut Cqe
    }

    /// Producer (client): enqueue one submission entry. Returns `false` if the SQ is full.
    pub fn push_sq(&self, sqe: Sqe) -> bool {
        let tail = self.word(H_SQ_TAIL).load(Ordering::Relaxed);
        let head = self.word(H_SQ_HEAD).load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= self.sq_entries {
            return false;
        }
        // SAFETY: validated slot inside the mapped SQ array; producer owns `tail`.
        unsafe { self.sqe_ptr(tail).write_volatile(sqe) };
        self.word(H_SQ_TAIL).store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Consumer (server/driver): dequeue one submission entry, if any.
    pub fn pop_sq(&self) -> Option<Sqe> {
        let head = self.word(H_SQ_HEAD).load(Ordering::Relaxed);
        let tail = self.word(H_SQ_TAIL).load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: validated slot inside the mapped SQ array; Acquire load orders against producer write.
        let sqe = unsafe { self.sqe_ptr(head).read_volatile() };
        self.word(H_SQ_HEAD).store(head.wrapping_add(1), Ordering::Release);
        Some(sqe)
    }

    /// Consumer (server/driver): enqueue one completion entry. Returns `false` if the CQ is full.
    pub fn push_cq(&self, cqe: Cqe) -> bool {
        let tail = self.word(H_CQ_TAIL).load(Ordering::Relaxed);
        let head = self.word(H_CQ_HEAD).load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= self.cq_entries {
            return false;
        }
        // SAFETY: validated slot inside the mapped CQ array; consumer owns `cq_tail`.
        unsafe { self.cqe_ptr(tail).write_volatile(cqe) };
        self.word(H_CQ_TAIL).store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Producer (client): dequeue one completion entry, if any.
    pub fn pop_cq(&self) -> Option<Cqe> {
        let head = self.word(H_CQ_HEAD).load(Ordering::Relaxed);
        let tail = self.word(H_CQ_TAIL).load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: validated slot inside the mapped CQ array; Acquire load orders against consumer write.
        let cqe = unsafe { self.cqe_ptr(head).read_volatile() };
        self.word(H_CQ_HEAD).store(head.wrapping_add(1), Ordering::Release);
        Some(cqe)
    }
}

impl Drop for IoRing {
    fn drop(&mut self) {
        sys::vmar_unmap(crate::root_vmar(), self.addr, self.map_len);
        sys::handle_close(self.vmo);
    }
}
