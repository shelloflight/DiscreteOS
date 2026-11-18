//! Port: shared-memory submission and completion rings, and async waits.
//!
//! A port owns a VMO that the program maps read-write. It holds a header and two rings:
//!
//! - **submission queue** (SQ): the program writes entries (`Sqe`: a syscall number, its six
//!   arguments, a user value) and advances `sq_tail`; `port_enter` runs them in order;
//! - **completion queue** (CQ): the kernel writes `Cqe`s (user value + result) and advances
//!   `cq_tail`; the program reads them and advances `cq_head`, without a syscall.
//!
//! Async waits (`object_wait_async`) post a completion when an object's signals match: a port is
//! the D-OS wait set. Completions that do not fit go to a kernel overflow list (in order) and are
//! moved into the ring as soon as there is room, so none is ever lost; the overflow is bounded by
//! the number of async waits a port may have pending.
//!
//! The shared memory is hostile: the kernel keeps its own copies of the indices it owns
//! (`sq_head`, `cq_tail`), reads the program's (`sq_tail`, `cq_head`) once per use, and never
//! writes a CQ entry the program has not consumed. A program that corrupts its header only
//! confuses itself.
//!
//! Header layout (u32 unless noted, offsets in bytes): 0 sq_head, 4 sq_tail, 8 sq_mask,
//! 12 cq_head, 16 cq_tail, 20 cq_mask, 24 overflow, 28 flags, 32 sq_off (u64), 40 cq_off (u64).

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};

use super::quota::{Account, Charge, Res};
use super::signals::Signals;
use super::vmo::WriteRef;
use super::{Header, KRef, KResult, ObjType, Status, Vmo, sig};
use crate::ffi::rank;
use crate::sync::SpinLock;

pub const SQE_SIZE: u64 = 64;
pub const CQE_SIZE: u64 = 16;
pub const HEADER_SIZE: u64 = 4096;
pub const MAX_ENTRIES: u32 = 4096;
/// Async waits a port may have pending (each is one completion it may have to hold).
pub const MAX_WAITS: u32 = 4096;
/// Kernel memory charged per async wait.
const WAIT_CHARGE: u64 = 128;

const H_SQ_HEAD: u64 = 0;
const H_SQ_TAIL: u64 = 4;
const H_SQ_MASK: u64 = 8;
const H_CQ_HEAD: u64 = 12;
const H_CQ_TAIL: u64 = 16;
const H_CQ_MASK: u64 = 20;
const H_OVERFLOW: u64 = 24;
const H_SQ_OFF: u64 = 32;
const H_CQ_OFF: u64 = 40;

/// A submission entry, as copied out of the ring.
#[derive(Clone, Copy, Default)]
pub struct Sqe {
    pub op: u32,
    pub flags: u32,
    pub user_data: u64,
    pub args: [u64; 6],
}

/// One pending async wait: posts (key, signals) to its port when its object's signals match
/// `mask`. Owned by the object's `Signals` while pending, then by the port while it waits in
/// the overflow list.
pub struct AsyncWait {
    pub(super) next: *mut AsyncWait,
    pub(super) mask: u32,
    pub(super) key: u64,
    bits: u32,
    port: Option<KRef<PortCore>>,
    port_id: usize,
    _charge: Charge,
}

// SAFETY: a node is owned by exactly one list at a time and only touched under that list's lock.
unsafe impl Send for AsyncWait {}

impl AsyncWait {
    pub(super) fn port_id(&self) -> usize {
        self.port_id
    }
}

impl Drop for AsyncWait {
    fn drop(&mut self) {
        if let Some(p) = &self.port {
            p.waits.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// An async wait fired with `bits`: post it to its port (or park it in the overflow list).
/// The node keeps counting against the port's `MAX_WAITS` until the port frees it.
pub(super) fn fire(mut node: Box<AsyncWait>, bits: u32) {
    node.bits = bits;
    let Some(port) = node.port.take() else { return };
    port.post_wait(node);
    // `port` may be the last reference here: the port goes, with whatever it still held.
}

struct Inner {
    sq_head: u32,
    cq_tail: u32,
    /// CQ slots promised to `port_enter` callers (results not written yet).
    reserved: u32,
    /// Overflow list (FIFO): fired async waits that did not fit into the ring.
    ov_head: *mut AsyncWait,
    ov_tail: *mut AsyncWait,
    ov_len: u32,
}

// SAFETY: the raw list is owned by `Inner` and only touched under the port lock.
unsafe impl Send for Inner {}

/// The part of a port that async waits keep alive (never refers to any waited-on object, so
/// pending waits cannot form reference cycles).
pub struct PortCore {
    pub signals: Signals,
    ring: WriteRef,
    sq_entries: u32,
    cq_entries: u32,
    sq_off: u64,
    cq_off: u64,
    waits: AtomicU32,
    inner: SpinLock<Inner>,
}

pub struct PortObj {
    pub header: Header,
    pub core: KRef<PortCore>,
}

impl PortObj {
    /// `entries` SQ entries (a power of two, 1..=MAX_ENTRIES); the CQ gets twice as many.
    /// Returns the port and its ring VMO (to be mapped by the program).
    pub fn create(acct: &KRef<Account>, entries: u32) -> KResult<(KRef<PortObj>, KRef<Vmo>)> {
        if entries == 0 || entries > MAX_ENTRIES || !entries.is_power_of_two() {
            return Err(Status::InvalidArgs);
        }
        let sq_off = HEADER_SIZE;
        let cq_off = sq_off + u64::from(entries) * SQE_SIZE;
        let size = cq_off + 2 * u64::from(entries) * CQE_SIZE;
        let vmo = Vmo::create_named(acct, size, "port")?;
        let ring = Vmo::write_ref(&vmo)?;
        vmo.atomic_u32(H_SQ_MASK).store(entries - 1, Ordering::Relaxed);
        vmo.atomic_u32(H_CQ_MASK).store(2 * entries - 1, Ordering::Relaxed);
        vmo.atomic_u64(H_SQ_OFF).store(sq_off, Ordering::Relaxed);
        vmo.atomic_u64(H_CQ_OFF).store(cq_off, Ordering::Release);
        let core = KRef::try_new(PortCore {
            signals: Signals::new(c"port"),
            ring,
            sq_entries: entries,
            cq_entries: 2 * entries,
            sq_off,
            cq_off,
            waits: AtomicU32::new(0),
            inner: SpinLock::new(
                c"port",
                rank::PORT,
                Inner {
                    sq_head: 0,
                    cq_tail: 0,
                    reserved: 0,
                    ov_head: core::ptr::null_mut(),
                    ov_tail: core::ptr::null_mut(),
                    ov_len: 0,
                },
            ),
        })
        .map_err(|_| Status::NoMemory)?;
        let port = KRef::try_new(PortObj { header: Header::new(ObjType::Port), core }).map_err(|_| Status::NoMemory)?;
        Ok((port, vmo))
    }
}

impl PortCore {
    fn vmo(&self) -> &Vmo {
        self.ring.vmo()
    }

    fn word(&self, off: u64) -> &AtomicU32 {
        self.vmo().atomic_u32(off)
    }

    /// Unique id (for cancelling async waits).
    pub fn id(this: &KRef<PortCore>) -> usize {
        KRef::addr(this)
    }

    pub fn cq_entries(&self) -> u32 {
        self.cq_entries
    }

    /// Entries in the CQ the program has not consumed yet (a corrupted head counts as full).
    fn cq_used(&self, inner: &Inner) -> u32 {
        let head = self.word(H_CQ_HEAD).load(Ordering::Acquire);
        let used = inner.cq_tail.wrapping_sub(head);
        used.min(self.cq_entries)
    }

    /// Write one CQE at the tail (space checked by the caller) and publish it.
    fn push_cqe(&self, inner: &mut Inner, user_data: u64, result: i64) {
        let idx = u64::from(inner.cq_tail & (self.cq_entries - 1));
        let off = self.cq_off + idx * CQE_SIZE;
        self.vmo().atomic_u64(off).store(user_data, Ordering::Relaxed);
        self.vmo().atomic_u64(off + 8).store(result as u64, Ordering::Relaxed);
        inner.cq_tail = inner.cq_tail.wrapping_add(1);
        self.word(H_CQ_TAIL).store(inner.cq_tail, Ordering::Release);
    }

    /// Move overflowed completions into the ring while there is room. Returns how many moved
    /// (their nodes go to `freed`, to be dropped after unlocking).
    fn flush(&self, inner: &mut Inner, freed: &mut *mut AsyncWait) -> u32 {
        let mut moved = 0;
        while !inner.ov_head.is_null() && self.cq_used(inner) + inner.reserved < self.cq_entries {
            let n = inner.ov_head;
            // SAFETY: nodes on the overflow list are leaked boxes owned by this list.
            let (key, bits) = unsafe {
                inner.ov_head = (*n).next;
                (*n).next = *freed;
                *freed = n;
                ((*n).key, (*n).bits)
            };
            if inner.ov_head.is_null() {
                inner.ov_tail = core::ptr::null_mut();
            }
            inner.ov_len -= 1;
            self.push_cqe(inner, key, i64::from(bits));
            moved += 1;
        }
        self.word(H_OVERFLOW).store(inner.ov_len, Ordering::Release);
        moved
    }

    fn post_wait(&self, node: Box<AsyncWait>) {
        let mut freed: *mut AsyncWait = core::ptr::null_mut();
        let posted = {
            let mut g = self.inner.lock();
            self.flush(&mut g, &mut freed);
            if g.ov_head.is_null() && self.cq_used(&g) + g.reserved < self.cq_entries {
                self.push_cqe(&mut g, node.key, i64::from(node.bits));
                true
            } else {
                let raw = Box::into_raw(node);
                if g.ov_tail.is_null() {
                    g.ov_head = raw;
                } else {
                    // SAFETY: the tail is a node owned by this list.
                    unsafe { (*g.ov_tail).next = raw };
                }
                g.ov_tail = raw;
                g.ov_len += 1;
                self.word(H_OVERFLOW).store(g.ov_len, Ordering::Release);
                // `node` is now owned by the list.
                return self.after_post(freed, false);
            }
        };
        // `node` was copied into the ring: free it outside the lock.
        self.after_post(freed, posted);
    }

    fn after_post(&self, freed: *mut AsyncWait, posted: bool) {
        self.free_nodes(freed);
        if posted {
            self.waits.fetch_sub(1, Ordering::Relaxed); // the node itself (copied into the ring)
            self.signals.update(0, sig::READABLE);
        }
    }

    /// Free nodes this port owned (fired async waits), giving back their `MAX_WAITS` slots.
    fn free_nodes(&self, mut list: *mut AsyncWait) {
        while !list.is_null() {
            // SAFETY: a list of leaked boxes owned by this port.
            let node = unsafe { Box::from_raw(list) };
            list = node.next;
            self.waits.fetch_sub(1, Ordering::Relaxed);
            drop(node);
        }
    }

    /// Move overflowed completions into the ring as far as it has room (`port_enter`).
    pub fn sync(&self) {
        let mut freed: *mut AsyncWait = core::ptr::null_mut();
        let moved = {
            let mut g = self.inner.lock();
            self.flush(&mut g, &mut freed)
        };
        self.free_nodes(freed);
        if moved > 0 {
            self.signals.update(0, sig::READABLE);
        }
    }

    /// Take up to `out.len()` SQEs (copied out of the ring) and reserve a CQ slot for each
    /// result, in one lock hold. 0: the SQ is empty or the CQ has no free slot. A corrupted tail
    /// (more entries than the ring holds) is `BadState`.
    pub fn claim(&self, out: &mut [Sqe]) -> KResult<usize> {
        let mut freed: *mut AsyncWait = core::ptr::null_mut();
        let r = {
            let mut g = self.inner.lock();
            self.flush(&mut g, &mut freed);
            let tail = self.word(H_SQ_TAIL).load(Ordering::Acquire);
            let pending = tail.wrapping_sub(g.sq_head);
            if pending > self.sq_entries {
                Err(Status::BadState)
            } else if !g.ov_head.is_null() {
                Ok(0) // overflowed completions first: no new results until they fit
            } else {
                let room = self.cq_entries - (self.cq_used(&g) + g.reserved).min(self.cq_entries);
                let n = (pending.min(room) as usize).min(out.len());
                let v = self.vmo();
                for sqe in out.iter_mut().take(n) {
                    let idx = u64::from(g.sq_head & (self.sq_entries - 1));
                    let off = self.sq_off + idx * SQE_SIZE;
                    let w0 = v.atomic_u64(off).load(Ordering::Relaxed);
                    sqe.op = w0 as u32;
                    sqe.flags = (w0 >> 32) as u32;
                    sqe.user_data = v.atomic_u64(off + 8).load(Ordering::Relaxed);
                    for (i, a) in sqe.args.iter_mut().enumerate() {
                        *a = v.atomic_u64(off + 16 + 8 * i as u64).load(Ordering::Relaxed);
                    }
                    g.sq_head = g.sq_head.wrapping_add(1);
                }
                self.word(H_SQ_HEAD).store(g.sq_head, Ordering::Release);
                g.reserved += n as u32;
                Ok(n)
            }
        };
        self.free_nodes(freed);
        r
    }

    /// Post the results of claimed SQEs into their reserved slots (one lock, one wake-up).
    pub fn complete(&self, results: &[(u64, i64)]) {
        if results.is_empty() {
            return;
        }
        {
            let mut g = self.inner.lock();
            crate::kassert!(g.reserved as usize >= results.len());
            g.reserved -= results.len() as u32;
            for &(ud, r) in results {
                self.push_cqe(&mut g, ud, r);
            }
        }
        self.signals.update(0, sig::READABLE);
    }

    /// Wait until at least `min` completions are in the ring (or the deadline passes).
    pub fn wait_completions(&self, min: u32, deadline_ns: u64) -> KResult<()> {
        if min > self.cq_entries {
            return Err(Status::InvalidArgs);
        }
        loop {
            let mut freed: *mut AsyncWait = core::ptr::null_mut();
            let ready = {
                let mut g = self.inner.lock();
                self.flush(&mut g, &mut freed);
                let ready = self.cq_used(&g) >= min;
                if !ready {
                    // Cleared under the port lock: a completion posted after this sets it again.
                    self.signals.update(sig::READABLE, 0);
                }
                ready
            };
            self.free_nodes(freed);
            if ready {
                return Ok(());
            }
            if deadline_ns != 0 && crate::ffi::now_ns() >= deadline_ns {
                return Err(Status::TimedOut);
            }
            let left = if deadline_ns == 0 {
                crate::ffi::WAIT_FOREVER
            } else {
                deadline_ns.saturating_sub(crate::ffi::now_ns()).max(1)
            };
            match self.signals.wait(sig::READABLE, left) {
                Ok(_) | Err(Status::TimedOut) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for PortCore {
    fn drop(&mut self) {
        let head = core::mem::replace(&mut self.inner.lock().ov_head, core::ptr::null_mut());
        self.free_nodes(head);
    }
}

/// A new async wait for `port`, charged to `acct`. `NoResources` when the port has too many.
pub fn new_wait(port: &KRef<PortCore>, acct: &KRef<Account>, mask: u32, key: u64) -> KResult<Box<AsyncWait>> {
    if port.waits.fetch_add(1, Ordering::Relaxed) >= MAX_WAITS {
        port.waits.fetch_sub(1, Ordering::Relaxed);
        return Err(Status::NoResources);
    }
    let charge = match Charge::new(acct, Res::Memory, WAIT_CHARGE) {
        Ok(c) => c,
        Err(e) => {
            port.waits.fetch_sub(1, Ordering::Relaxed);
            return Err(e);
        }
    };
    let node = AsyncWait {
        next: core::ptr::null_mut(),
        mask,
        key,
        bits: 0,
        port: Some(port.clone()),
        port_id: PortCore::id(port),
        _charge: charge,
    };
    // On failure the node drops, giving back the count and the charge.
    crate::thread::try_box(node).ok_or(Status::NoMemory)
}
