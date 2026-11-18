//! Channel: a pair of endpoints. A message written into one end is queued at the other;
//! a message carries bytes and handles (moving a handle through a channel is how a capability is
//! delegated).
//!
//! - Messages: at most `MAX_BYTES` bytes and `MAX_HANDLES` handles; the memory is charged to the
//!   sender's quota until the message is read or dropped.
//! - Queues: at most `MAX_QUEUE` messages wait at an endpoint; a write to a full queue is
//!   `ShouldWait` and the writer's `WRITABLE` signal is clear until the reader makes room.
//! - Signals: `READABLE` (a message waits), `WRITABLE` (the peer's queue has room), `PEER_CLOSED`
//!   (the other end is gone: writes fail, reads drain what is left, then fail).
//! - Calls (`call`): synchronous request/reply. The kernel gives the request a transaction id (its
//!   first 4 bytes) and routes the reply, the first message coming back with that id, straight to
//!   the waiting caller instead of the queue. Both directions wake the other side on this CPU
//!   (`update_sync`), reserved for it until the waker blocks (the scheduler's handoff window:
//!   idle CPUs may not take it), so a call is a direct switch to the server and back, with no IPI.
//! - Cycles: a channel cannot carry its own endpoint or its peer (refused at write). Longer cycles
//!   through several channels (A's end queued in B, B's end queued in A, every outside handle
//!   closed) are found and broken by [`collect_cycles`], which runs whenever a process exits
//!   (before it, such cycles outlived their processes).
//!
//! Locking: each endpoint's queue has one lock (rank OBJECT); the two are never held together.
//! Signals of both ends are updated under the queue lock that decides them, so `WRITABLE` and
//! `READABLE` always agree with the queue.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::quota::{Account, Charge, Res};
use super::signals::{self, Signals};
use super::{Header, KRef, KResult, ObjType, Object, Rights, Status, sig};
use crate::ffi::rank;
use crate::sync::SpinLock;

pub const MAX_BYTES: usize = 64 * 1024;
pub const MAX_HANDLES: usize = 64;
pub const MAX_QUEUE: usize = 256;
/// Fixed kernel cost charged per message (header) and per handle it carries.
const MSG_OVERHEAD: u64 = 64;
const HANDLE_OVERHEAD: u64 = 32;
/// Kernel transaction ids have the top bit set (programs use the others for their own ids).
const TXID_BIT: u32 = 0x8000_0000;

pub struct Message {
    pub data: Vec<u8>,
    pub handles: Vec<(Object, Rights)>,
    _charge: Charge,
}

impl Message {
    /// A message charged to `acct` (the sender). `data` and `handles` are taken as they are.
    pub fn new(acct: &KRef<Account>, data: Vec<u8>, handles: Vec<(Object, Rights)>) -> KResult<Message> {
        if data.len() > MAX_BYTES || handles.len() > MAX_HANDLES {
            return Err(Status::InvalidArgs);
        }
        let cost = MSG_OVERHEAD + data.len() as u64 + HANDLE_OVERHEAD * handles.len() as u64;
        let charge = Charge::new(acct, Res::Memory, cost)?;
        Ok(Message { data, handles, _charge: charge })
    }

    fn txid(&self) -> Option<u32> {
        let b = self.data.get(..4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

struct Call {
    txid: u32,
    done: KRef<AtomicBool>,
    reply: Option<Message>,
    /// The CPU the caller sent from, and the one the reply was written on (statistics).
    cpu: u32,
    reply_cpu: u32,
}

unsafe extern "C" {
    fn sched_cpu_id() -> u32;
}

fn cpu_id() -> u32 {
    // SAFETY: reads this CPU's id (GS-relative); no other effect.
    unsafe { sched_cpu_id() }
}

struct Queue {
    msgs: VecDeque<Message>,
    calls: Vec<Call>,
    next_txid: u32,
    /// The endpoint that reads this queue is gone: refuse writes.
    closed: bool,
}

/// One end's incoming side: its queue and its signals.
struct Endpoint {
    signals: Signals,
    q: SpinLock<Queue>,
    /// The endpoint writing into this queue is gone (reads fail once the queue is empty).
    peer_gone: AtomicBool,
}

impl Endpoint {
    fn new() -> KResult<KRef<Endpoint>> {
        KRef::try_new(Endpoint {
            signals: Signals::new(c"channel"),
            q: SpinLock::new(
                c"channel",
                rank::OBJECT,
                Queue { msgs: VecDeque::new(), calls: Vec::new(), next_txid: 0, closed: false },
            ),
            peer_gone: AtomicBool::new(false),
        })
        .map_err(|_| Status::NoMemory)
    }
}

pub struct ChannelObj {
    pub header: Header,
    /// Where messages for this end arrive (and its signals).
    me: KRef<Endpoint>,
    /// Where this end's messages go.
    peer: KRef<Endpoint>,
}

/// Message too big for the reader's buffers: what it would need.
#[derive(Clone, Copy, Debug)]
pub struct Needed {
    pub bytes: u32,
    pub handles: u32,
}

pub enum ReadError {
    Status(Status),
    TooSmall(Needed),
}

impl From<Status> for ReadError {
    fn from(s: Status) -> Self {
        ReadError::Status(s)
    }
}

static CALLS: AtomicU32 = AtomicU32::new(0);
/// Calls whose server ran, or whose caller resumed, on another CPU than the call was made on.
static CALLS_MOVED: AtomicU32 = AtomicU32::new(0);

// ---- cycle collection -------------------------------------------------------------------------
//
// Every live channel end is in REGISTRY (by value address; `Drop` takes itself out first, under
// the registry lock, so a listed address is always allocated while the lock is held).
// TRANSFERS changes whenever a message carrying handles enters or leaves a queue.
//
// `collect_cycles` (trial deletion, as in reference-counting garbage collectors):
//  1. take a reference to every listed end (skipping ends already being destroyed);
//  2. under each end's queue lock, list the channel ends inside its queued messages;
//  3. read every reference count; if TRANSFERS moved since step 2 began, start again (the
//     snapshot was not consistent);
//  4. an end is *externally* held if it has more references than (ours + its appearances in
//     queues): a handle table, a syscall in progress, a port wait, a call reply, a queue of an
//     end created after step 1. Every such end is a root;
//  5. everything readable from a root is reachable (holding an end lets you read its queue);
//  6. the rest can never be read by anyone: their queues are emptied, which drops the ends they
//     hold, and the cycle falls apart through the normal reference counts.
// Anything uncertain counts as external, so a mistake can only keep garbage, never free a live
// end. Reply messages of pending calls are not scanned (counted external: their caller is alive).

static REGISTRY: SpinLock<Vec<usize>> = SpinLock::new(c"channels", rank::CHANNELS, Vec::new());
static TRANSFERS: AtomicU64 = AtomicU64::new(0);
static COLLECTED: AtomicU64 = AtomicU64::new(0);

/// Channel ends found in unreachable cycles since boot.
pub fn collected() -> u64 {
    COLLECTED.load(Ordering::Relaxed)
}

fn register(c: &KRef<ChannelObj>) -> KResult<()> {
    let mut r = REGISTRY.lock();
    r.try_reserve(1).map_err(|_| Status::NoMemory)?;
    r.push(KRef::value_addr(c));
    Ok(())
}

/// A message with handles entered or left a queue (call with the queue lock held).
fn moved(m: &Message) {
    if !m.handles.is_empty() {
        TRANSFERS.fetch_add(1, Ordering::SeqCst);
    }
}

/// Find and break channel cycles nobody can read any more. Returns how many channel ends were
/// unreachable (each is freed once its queue's references are gone).
pub fn collect_cycles() -> usize {
    for _ in 0..8 {
        if let Some(n) = try_collect() {
            return n;
        }
    }
    0 // traffic kept moving handles: the next process exit tries again
}

fn try_collect() -> Option<usize> {
    let mut nodes: Vec<KRef<ChannelObj>> = Vec::new();
    {
        let r = REGISTRY.lock();
        nodes.try_reserve_exact(r.len()).ok()?;
        for &a in r.iter() {
            // SAFETY: listed addresses stay allocated while the registry lock is held (Drop
            // unlists itself under it before the memory can go).
            if let Some(k) = unsafe { KRef::<ChannelObj>::try_from_value_addr(a) } {
                nodes.push(k);
            }
        }
    }
    if nodes.is_empty() {
        return Some(0);
    }
    nodes.sort_unstable_by_key(KRef::value_addr);
    let index = |c: &KRef<ChannelObj>| nodes.binary_search_by_key(&KRef::value_addr(c), KRef::value_addr).ok();

    let before = TRANSFERS.load(Ordering::SeqCst);
    let mut inside = Vec::new(); // appearances of each node in some node's queue
    inside.try_reserve_exact(nodes.len()).ok()?;
    inside.resize(nodes.len(), 0usize);
    let mut edges: Vec<(usize, usize)> = Vec::new(); // (reader, held)
    for (i, n) in nodes.iter().enumerate() {
        let q = n.me.q.lock();
        for m in q.msgs.iter() {
            for (o, _) in m.handles.iter() {
                if let Object::Channel(c) = o
                    && let Some(j) = index(c)
                {
                    if edges.try_reserve(1).is_err() {
                        return Some(0); // out of memory: collect nothing this time
                    }
                    edges.push((i, j));
                    inside[j] += 1;
                }
            }
        }
    }
    let mut reachable = Vec::new();
    reachable.try_reserve_exact(nodes.len()).ok()?;
    for (i, n) in nodes.iter().enumerate() {
        let refs = KRef::ref_count(n);
        // ours (1) + the queue appearances; anything beyond is held from outside
        if refs < 1 + inside[i] {
            return None; // counts moved under us
        }
        reachable.push(refs > 1 + inside[i]);
    }
    if TRANSFERS.load(Ordering::SeqCst) != before {
        return None;
    }
    // Everything readable from a reachable end is reachable.
    let mut changed = true;
    while changed {
        changed = false;
        for &(from, to) in edges.iter() {
            if reachable[from] && !reachable[to] {
                reachable[to] = true;
                changed = true;
            }
        }
    }
    let mut dead = 0;
    let mut drained: Vec<VecDeque<Message>> = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        if reachable[i] {
            continue;
        }
        dead += 1;
        let mut q = n.me.q.lock();
        let msgs = core::mem::take(&mut q.msgs);
        if msgs.iter().any(|m| !m.handles.is_empty()) {
            TRANSFERS.fetch_add(1, Ordering::SeqCst);
        }
        drop(q);
        if drained.try_reserve(1).is_ok() {
            drained.push(msgs);
        } else {
            drop(msgs); // (no lock held here)
        }
    }
    drop(drained); // closes the handles they carried: the cycle's own references
    drop(nodes); // our references: the unreachable ends go now
    COLLECTED.fetch_add(dead as u64, Ordering::Relaxed);
    Some(dead)
}

impl ChannelObj {
    /// A new channel: its two ends.
    pub fn create() -> KResult<(KRef<ChannelObj>, KRef<ChannelObj>)> {
        let a = Endpoint::new()?;
        let b = Endpoint::new()?;
        a.signals.update(0, sig::WRITABLE);
        b.signals.update(0, sig::WRITABLE);
        let ea = KRef::try_new(ChannelObj { header: Header::new(ObjType::Channel), me: a.clone(), peer: b.clone() })
            .map_err(|_| Status::NoMemory)?;
        let eb = KRef::try_new(ChannelObj { header: Header::new(ObjType::Channel), me: b, peer: a })
            .map_err(|_| Status::NoMemory)?;
        register(&ea)?;
        register(&eb)?;
        Ok((ea, eb))
    }

    pub fn signals(&self) -> &Signals {
        &self.me.signals
    }

    pub fn peer_closed(&self) -> bool {
        self.me.peer_gone.load(Ordering::Acquire)
    }

    /// Is `obj` this channel's own end or its peer (which it must not carry)?
    pub fn is_self_or_peer(&self, obj: &Object) -> bool {
        match obj {
            Object::Channel(c) => KRef::ptr_eq(&c.me, &self.me) || KRef::ptr_eq(&c.me, &self.peer),
            _ => false,
        }
    }

    /// Queue a message at the peer. On failure the message comes back (the caller decides
    /// whether its handles are closed or kept).
    pub fn write(&self, msg: Message) -> Result<(), (Status, Message)> {
        self.write_with(msg, false)
    }

    fn write_with(&self, msg: Message, sync: bool) -> Result<(), (Status, Message)> {
        let mut q = self.peer.q.lock();
        if q.closed {
            return Err((Status::PeerClosed, msg));
        }
        // A reply to a call waiting at the peer goes straight to the caller.
        if let Some(t) = msg.txid().filter(|t| t & TXID_BIT != 0)
            && let Some(c) = q.calls.iter_mut().find(|c| c.txid == t && c.reply.is_none()) {
                moved(&msg);
                c.reply = Some(msg);
                c.reply_cpu = cpu_id();
                c.done.store(true, Ordering::Release);
                self.peer.signals.wake(true); // the server goes back to read: run the caller here
                return Ok(());
            }
        if q.msgs.len() >= MAX_QUEUE {
            return Err((Status::ShouldWait, msg));
        }
        if q.msgs.try_reserve(1).is_err() {
            return Err((Status::NoMemory, msg));
        }
        moved(&msg);
        q.msgs.push_back(msg);
        if q.msgs.len() >= MAX_QUEUE {
            self.me.signals.update(sig::WRITABLE, 0);
        }
        if sync {
            self.peer.signals.update_sync(0, sig::READABLE);
        } else {
            self.peer.signals.update(0, sig::READABLE);
        }
        Ok(())
    }

    /// Take the next message if it fits (`cap_bytes`, `cap_handles`). Does not wait.
    pub fn read(&self, cap_bytes: usize, cap_handles: usize) -> Result<Message, ReadError> {
        let mut q = self.me.q.lock();
        let Some(front) = q.msgs.front() else {
            return Err(if self.peer_closed() { Status::PeerClosed } else { Status::ShouldWait }.into());
        };
        if front.data.len() > cap_bytes || front.handles.len() > cap_handles {
            return Err(ReadError::TooSmall(Needed { bytes: front.data.len() as u32, handles: front.handles.len() as u32 }));
        }
        let was_full = q.msgs.len() >= MAX_QUEUE;
        let m = q.msgs.pop_front().unwrap_or_else(|| unreachable!());
        moved(&m);
        if q.msgs.is_empty() {
            self.me.signals.update(sig::READABLE, 0);
        }
        if was_full {
            self.peer.signals.update(0, sig::WRITABLE);
        }
        Ok(m)
    }

    /// Put a message back at the front (a read that could not hand its handles over).
    pub fn unread(&self, m: Message) {
        let mut q = self.me.q.lock();
        // A slot was just freed by the read, so this does not allocate; if it ever must and
        // cannot, the message is dropped (its handles closed): fail closed, never duplicate.
        moved(&m);
        if q.msgs.try_reserve(1).is_ok() {
            q.msgs.push_front(m);
            self.me.signals.update(0, sig::READABLE);
        } else {
            drop(q);
            drop(m);
        }
    }

    /// Wait until a message is waiting or the peer is gone. `timeout_ns`: relative (0 = poll).
    pub fn wait_readable(&self, timeout_ns: u64) -> KResult<()> {
        self.me.signals.wait(sig::READABLE | sig::PEER_CLOSED, timeout_ns).map(|_| ())
    }

    /// Synchronous call: send `msg` (at least 4 bytes; the first 4 become the transaction id) and
    /// wait for the reply. `timeout_ns` relative (`WAIT_FOREVER` for none).
    pub fn call(&self, mut msg: Message, timeout_ns: u64) -> Result<Message, (Status, Option<Message>)> {
        if msg.data.len() < 4 {
            return Err((Status::InvalidArgs, Some(msg)));
        }
        let done = match KRef::try_new(AtomicBool::new(false)) {
            Ok(d) => d,
            Err(_) => return Err((Status::NoMemory, Some(msg))),
        };
        let txid = {
            let mut q = self.me.q.lock();
            if q.calls.try_reserve(1).is_err() {
                return Err((Status::NoMemory, Some(msg)));
            }
            let t = TXID_BIT | (q.next_txid & !TXID_BIT);
            q.next_txid = q.next_txid.wrapping_add(1);
            q.calls.push(Call { txid: t, done: done.clone(), reply: None, cpu: cpu_id(), reply_cpu: u32::MAX });
            t
        };
        msg.data[..4].copy_from_slice(&txid.to_le_bytes());
        if let Err((e, m)) = self.write_with(msg, true) {
            self.take_call(txid, false);
            return Err((e, Some(m)));
        }
        CALLS.fetch_add(1, Ordering::Relaxed);
        let deadline = signals::deadline(timeout_ns);
        let r = self.me.signals.wait_for(
            || done.load(Ordering::Acquire) || self.me.peer_gone.load(Ordering::Acquire),
            deadline,
        );
        let reply = self.take_call(txid, true);
        match (reply, r) {
            (Some(m), _) => Ok(m),
            (None, Err(e)) => Err((e, None)),
            (None, Ok(())) => Err((Status::PeerClosed, None)),
        }
    }

    /// Remove a call slot; its reply, if one came.
    /// Remove a call slot; its reply, if one came. `count`: a finished call (statistics).
    fn take_call(&self, txid: u32, count: bool) -> Option<Message> {
        let mut q = self.me.q.lock();
        let i = q.calls.iter().position(|c| c.txid == txid)?;
        let c = q.calls.swap_remove(i);
        if count && c.reply.is_some() && (c.reply_cpu != c.cpu || cpu_id() != c.cpu) {
            CALLS_MOVED.fetch_add(1, Ordering::Relaxed);
        }
        c.reply
    }

    /// Messages waiting at this end (inspection, tests).
    pub fn pending(&self) -> usize {
        self.me.q.lock().msgs.len()
    }
}

/// Number of channel calls made since boot (inspection).
pub fn calls_made() -> u32 {
    CALLS.load(Ordering::Relaxed)
}

/// Channel calls since boot, and how many of them involved another CPU (the server ran there, or
/// the caller resumed there): the benchmark image reports it.
///
/// # Safety
/// `calls` and `moved` must be valid, writable pointers (or NULL: nothing is written).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn channel_call_stats(calls: *mut u64, moved: *mut u64) {
    if calls.is_null() || moved.is_null() {
        return;
    }
    // SAFETY: the caller passes two valid, writable pointers (checked for NULL above).
    unsafe {
        *calls = u64::from(CALLS.load(Ordering::Relaxed));
        *moved = u64::from(CALLS_MOVED.load(Ordering::Relaxed));
    }
}

impl Drop for ChannelObj {
    fn drop(&mut self) {
        // Out of the registry first (cycle collection may be looking at this address).
        {
            let me = self as *const ChannelObj as usize;
            let mut r = REGISTRY.lock();
            if let Some(i) = r.iter().position(|&a| a == me) {
                r.swap_remove(i);
            }
        }
        // Nobody reads this end any more: refuse new messages, drop the queued ones (closing
        // their handles) outside the lock.
        let (msgs, calls) = {
            let mut q = self.me.q.lock();
            q.closed = true;
            if q.msgs.iter().any(|m| !m.handles.is_empty()) {
                TRANSFERS.fetch_add(1, Ordering::SeqCst);
            }
            (core::mem::take(&mut q.msgs), core::mem::take(&mut q.calls))
        };
        drop(msgs);
        drop(calls);
        // The peer: its reads drain what is left, its calls stop waiting, it sees PEER_CLOSED.
        {
            let _q = self.peer.q.lock();
            self.peer.peer_gone.store(true, Ordering::Release);
            self.peer.signals.update(sig::WRITABLE, sig::PEER_CLOSED);
        }
    }
}
