//! `objects` test case (KTEST_OBJECTS): kernel objects, handles, rights and quotas.
//!
//! - rights enforcement on every operation; rights never grow (duplicate/replace/grant)
//! - handle values: not plain indices, closed values stay invalid, double close fails,
//!   handles of one process mean nothing in another
//! - quotas: handles, memory, threads; hierarchical (a child is bounded by its parent)
//! - lifetimes: kill closes everything, mappings keep VMOs alive, no leaks at the end
//! - out of memory: a scenario touching every object type is run with its 1st, 2nd, ... n-th
//!   allocation failing (fault injection) until it succeeds; each run must fail cleanly with
//!   `NoMemory` and leave no leak behind (heap allocations, VMO frames, objects, quotas). Since
//!   It also covers channels (messages with handles), ports (rings, async waits fired and
//!   pending), exceptions and exception channels too.
//! - multi-core: threads on every CPU share one handle table

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::process::Usage;
use super::vmar::USER_BASE;
use super::*;
use crate::ffi::{self, fault};
use crate::thread::{prio, sleep_ns, spawn};

struct T {
    failures: u32,
}

impl T {
    #[track_caller]
    fn check(&mut self, ok: bool, what: &str) {
        if !ok {
            let l = core::panic::Location::caller();
            crate::kprintln!("  FAIL {}:{}: {}", l.file(), l.line(), what);
            self.failures += 1;
        }
    }
}

macro_rules! check {
    ($t:expr, $c:expr) => {
        $t.check($c, stringify!($c))
    };
}

const R: Rights = Rights::READ;
const W: Rights = Rights::WRITE;
const X: Rights = Rights::EXECUTE;
const MS: u64 = 1_000_000;

/// A fresh test process (child of the kernel process) and the kernel's handle to it.
fn new_proc(name: &str, limits: Limits) -> KRef<Process> {
    match Process::new(Some(kernel_process()), name, limits) {
        Ok(p) => p,
        Err(e) => panic!("cannot create test process: {}", e.name()),
    }
}

/// A process that holds a MANAGE handle to itself (what spawn() hands out).
fn self_handle(p: &KRef<Process>) -> Handle {
    p.add(Object::Process(p.clone()), default_rights(ObjType::Process))
        .expect("self handle")
}

fn rights(t: &mut T) {
    let p = new_proc("rights", Limits::DEFAULT);
    let ev = p.event_create().unwrap();
    let (ty, _, r) = p.object_info(ev).unwrap();
    check!(t, ty == ObjType::Event && r == default_rights(ObjType::Event));

    // Wait-only duplicate: can wait, cannot signal, cannot duplicate further, cannot transfer.
    let wait_only = p.handle_duplicate(ev, Rights::WAIT).unwrap();
    check!(t, p.event_signal(wait_only, 0, sig::SIGNALED) == Err(Status::AccessDenied));
    check!(t, p.handle_duplicate(wait_only, Rights::WAIT) == Err(Status::AccessDenied));
    check!(t, p.object_wait(wait_only, sig::SIGNALED, 0) == Err(Status::TimedOut));
    p.event_signal(ev, 0, sig::SIGNALED).unwrap();
    check!(t, p.object_wait(wait_only, sig::SIGNALED, 0) == Ok(sig::SIGNALED));
    check!(t, p.event_signal(ev, 0, sig::TERMINATED) == Err(Status::InvalidArgs)); // not user-settable

    // Rights never grow: asking for more than the source has fails, SAME keeps them.
    let sig_dup = p.handle_duplicate(ev, Rights::SIGNAL | Rights::DUPLICATE).unwrap();
    check!(t, p.handle_duplicate(sig_dup, Rights::SIGNAL | Rights::WAIT) == Err(Status::AccessDenied));
    let same = p.handle_duplicate(sig_dup, Rights::SAME).unwrap();
    check!(t, p.object_info(same).unwrap().2 == (Rights::SIGNAL | Rights::DUPLICATE));
    check!(t, p.handle_replace(same, Rights::ALL) == Err(Status::AccessDenied));
    check!(t, p.object_info(same).is_ok()); // a failed replace leaves the handle as it was
    let fewer = p.handle_replace(same, Rights::SIGNAL).unwrap();
    check!(t, p.object_info(same) == Err(Status::BadHandle)); // replaced: old value is gone
    check!(t, p.object_info(fewer).unwrap().2 == Rights::SIGNAL);
    check!(t, p.handle_duplicate(ev, Rights(1 << 20)) == Err(Status::AccessDenied)); // unknown bits

    // Type checks: an event is not a VMO.
    check!(t, p.vmo_size(ev) == Err(Status::WrongType));
    check!(t, p.timer_set(ev, MS) == Err(Status::WrongType));

    // VMO rights: read-only handle cannot write or be mapped writable; nothing maps executable.
    let vmo = p.vmo_create(3 * 4096).unwrap();
    let ro = p.handle_duplicate(vmo, Rights::READ | Rights::MAP).unwrap();
    let mut buf = [0u8; 8];
    check!(t, p.vmo_read(ro, 0, &mut buf).is_ok());
    check!(t, p.vmo_write(ro, 0, b"x") == Err(Status::AccessDenied));
    let (cp, vmar) = p_create_child(t, &p);
    let _ = cp;
    check!(t, p.vmar_map(vmar, None, ro, 0, 4096, R | W) == Err(Status::AccessDenied));
    check!(t, p.vmar_map(vmar, None, ro, 0, 4096, R).is_ok());
    check!(t, p.vmar_map(vmar, None, vmo, 0, 4096, R | X) == Err(Status::AccessDenied)); // no EXECUTE right
    check!(t, p.vmar_map(vmar, None, vmo, 0, 4096, W | X) == Err(Status::AccessDenied));
    let no_map = p.handle_duplicate(vmo, Rights::READ | Rights::WRITE).unwrap();
    check!(t, p.vmar_map(vmar, None, no_map, 0, 4096, R) == Err(Status::AccessDenied));
    let vmar_ro = p.handle_duplicate(vmar, Rights::MAP | Rights::READ).unwrap();
    check!(t, p.vmar_map(vmar_ro, None, vmo, 0, 4096, R | W) == Err(Status::AccessDenied));

    // W^X at the region level even with every right (a hypothetical executable VMO).
    let (r, _) = p.get_vmar(vmar, Rights::NONE).unwrap();
    let (v, _) = p.get_vmo(vmo, Rights::NONE).unwrap();
    check!(t, r.map(None, v.clone(), 0, 4096, W | X) == Err(Status::InvalidArgs));
    drop((r, v));

    // Transfer needs TRANSFER on the handle and MANAGE on the destination process.
    let q = new_proc("rights.dest", Limits::DEFAULT);
    let q_full = p.add(Object::Process(q.clone()), default_rights(ObjType::Process)).unwrap();
    let q_nomanage = p.handle_duplicate(q_full, Rights::INSPECT).unwrap();
    let no_xfer = p.handle_duplicate(ev, Rights::WAIT | Rights::DUPLICATE).unwrap();
    check!(t, p.handle_grant(no_xfer, Rights::SAME, q_full) == Err(Status::AccessDenied));
    check!(t, p.object_info(no_xfer).is_ok()); // refused before anything moved
    check!(t, p.handle_grant(ev, Rights::SAME, q_nomanage) == Err(Status::AccessDenied));
    let xfer = p.handle_duplicate(ev, Rights::TRANSFER | Rights::WAIT | Rights::SIGNAL).unwrap();
    let in_q = p.handle_grant(xfer, Rights::WAIT, q_full).unwrap();
    check!(t, p.object_info(xfer) == Err(Status::BadHandle)); // moved, not copied
    check!(t, q.object_info(in_q).map(|i| i.2) == Ok(Rights::WAIT)); // reduced on the way
    check!(t, q.event_signal(in_q, sig::SIGNALED, 0) == Err(Status::AccessDenied));
    // Handles are per process: p's handle values mean nothing in q (and vice versa).
    check!(t, q.object_info(ev) == Err(Status::BadHandle));

    // Process control needs MANAGE; quota inspection needs INSPECT.
    check!(t, p.process_kill(q_nomanage) == Err(Status::AccessDenied));
    check!(t, p.process_quota(q_nomanage).is_ok());
    let q_waitonly = p.handle_duplicate(q_full, Rights::WAIT).unwrap();
    check!(t, p.process_quota(q_waitonly) == Err(Status::AccessDenied));
    check!(t, p.process_create(q_nomanage, "x", Limits::DEFAULT) == Err(Status::AccessDenied));

    // No ambient authority: a fresh process holds no handles at all, so it can reach nothing.
    let (child_h, _) = p.process_create(q_full, "empty", Limits::DEFAULT).unwrap();
    let (child, _) = p.get_process(child_h, Rights::NONE).unwrap();
    check!(t, child.handle_count() == 0);
    check!(t, child.thread_create(Handle(1), c"x", || 0) == Err(Status::BadHandle));
    child.kill();
    drop(child);

    q.kill();
    p.kill();
}

/// A child process of `p` (through a self handle); returns (child handle, child root VMAR handle).
fn p_create_child(t: &mut T, p: &KRef<Process>) -> (Handle, Handle) {
    let me = self_handle(p);
    let r = p.process_create(me, "child", Limits::DEFAULT);
    check!(t, r.is_ok());
    r.unwrap()
}

fn handles(t: &mut T) {
    let p = new_proc("handles", Limits::DEFAULT);
    let a = p.event_create().unwrap();
    let b = p.event_create().unwrap();
    // Not plain indices: consecutive handles are far apart and never small.
    check!(t, a != Handle::INVALID && b != Handle::INVALID);
    check!(t, a.0 > 16 && b.0 > 16 && a.0.abs_diff(b.0) > 1);

    // Closed handles stay invalid; double close fails; the slot is reused with a new value.
    p.handle_close(a).unwrap();
    check!(t, p.handle_close(a) == Err(Status::BadHandle));
    check!(t, p.object_info(a) == Err(Status::BadHandle));
    let mut seen_old = false;
    for _ in 0..1000 {
        let h = p.event_create().unwrap();
        seen_old |= h == a;
        p.handle_close(h).unwrap();
        check!(t, p.object_info(h) == Err(Status::BadHandle));
    }
    check!(t, !seen_old);
    check!(t, p.object_info(Handle::INVALID) == Err(Status::BadHandle));
    check!(t, p.object_info(Handle(0xDEAD_BEEF)) == Err(Status::BadHandle));
    check!(t, p.handle_count() == 1);

    // Many handles: all distinct, all valid, and the table grows and shrinks cleanly.
    let mut hs = Vec::new();
    for _ in 0..500 {
        hs.push(p.handle_duplicate(b, Rights::SAME).unwrap());
    }
    let mut sorted = hs.clone();
    sorted.sort_unstable_by_key(|h| h.0);
    sorted.dedup();
    check!(t, sorted.len() == 500 && !sorted.contains(&b));
    check!(t, hs.iter().all(|&h| p.object_info(h).is_ok()));
    check!(t, p.handle_count() == 501 && p.usage().handles == 501);
    for h in hs {
        p.handle_close(h).unwrap();
    }
    check!(t, p.handle_count() == 1);

    // The object lives as long as any handle (or other reference) does.
    let ev_live = live(ObjType::Event);
    let c = p.handle_duplicate(b, Rights::SAME).unwrap();
    p.handle_close(b).unwrap();
    check!(t, live(ObjType::Event) == ev_live);
    p.handle_close(c).unwrap();
    check!(t, live(ObjType::Event) == ev_live - 1);
    p.kill();
}

fn quotas(t: &mut T) {
    // Handles.
    let lim = Limits {
        memory: 8 * 4096,
        handles: 16,
        threads: 2,
    };
    let p = new_proc("quota", lim);
    let mut hs = Vec::new();
    loop {
        match p.event_create() {
            Ok(h) => hs.push(h),
            Err(e) => {
                check!(t, e == Status::NoResources);
                break;
            }
        }
    }
    check!(t, hs.len() == 16 && p.usage().handles == 16);
    check!(t, p.handle_duplicate(hs[0], Rights::SAME) == Err(Status::NoResources));
    p.handle_close(hs.pop().unwrap()).unwrap();
    check!(t, p.event_create().map(|h| hs.push(h)).is_ok());
    for h in hs.drain(..) {
        p.handle_close(h).unwrap();
    }
    check!(t, p.usage() == Usage { memory: 0, handles: 0, threads: 0 });

    // Memory: 8 pages.
    check!(t, p.vmo_create(9 * 4096) == Err(Status::NoResources));
    let v1 = p.vmo_create(4 * 4096).unwrap();
    let v2 = p.vmo_create(3 * 4096 + 1).unwrap(); // rounds up to 4 pages
    check!(t, p.usage().memory == 8 * 4096);
    check!(t, p.vmo_create(1) == Err(Status::NoResources));
    check!(t, p.vmo_size(v2) == Ok(4 * 4096));
    p.handle_close(v1).unwrap();
    check!(t, p.usage().memory == 4 * 4096);
    check!(t, p.vmo_create(0) == Err(Status::InvalidArgs));
    check!(t, p.vmo_create(u64::MAX) == Err(Status::InvalidArgs));
    p.handle_close(v2).unwrap();

    // Hierarchical: a grandchild asking for more than its parent has is still bounded by it.
    let me = self_handle(&p);
    let (ch, _) = p.process_create(me, "grandchild", Limits::UNLIMITED).unwrap();
    let (c, _) = p.get_process(ch, Rights::NONE).unwrap();
    check!(t, c.vmo_create(9 * 4096) == Err(Status::NoResources));
    let cv = c.vmo_create(6 * 4096).unwrap();
    check!(t, p.usage().memory == 6 * 4096 && c.usage().memory == 6 * 4096);
    check!(t, p.vmo_create(3 * 4096) == Err(Status::NoResources)); // the child used it up
    // p holds: me, ch, the child's VMAR = 3 handles of 16; the child's handles count too.
    let used = p.usage().handles;
    check!(t, used == 4); // 3 in p + 1 in the child
    c.handle_close(cv).unwrap();
    check!(t, p.usage().memory == 0);

    // Threads: 2 at a time.
    static GATE: AtomicU32 = AtomicU32::new(0);
    let mk = |p: &Process| {
        p.thread_create(me, c"quota.thread", || {
            while GATE.load(Ordering::Acquire) == 0 {
                sleep_ns(MS);
            }
            42
        })
    };
    let t1 = mk(&p).unwrap();
    let t2 = mk(&p).unwrap();
    check!(t, mk(&p) == Err(Status::NoResources));
    check!(t, p.usage().threads == 2);
    check!(t, p.thread_exit_code(t1) == Err(Status::BadState)); // still running
    GATE.store(1, Ordering::Release);
    check!(t, p.object_wait(t1, sig::TERMINATED, 1000 * MS).is_ok());
    check!(t, p.object_wait(t2, sig::TERMINATED, 1000 * MS).is_ok());
    check!(t, p.thread_exit_code(t1) == Ok(42) && p.thread_exit_code(t2) == Ok(42));
    check!(t, p.usage().threads == 0);
    let t3 = mk(&p).unwrap(); // room again
    check!(t, p.object_wait(t3, sig::TERMINATED, 1000 * MS).is_ok());

    drop(c);
    p.kill();
    check!(t, p.usage() == Usage { memory: 0, handles: 0, threads: 0 });
}

/// Channel cycles: two channels each holding the other's end, every outside
/// reference gone, are collected; a cycle still held from outside is left alone.
fn cycles(t: &mut T) {
    use super::channel::{Message, collect_cycles};
    let acct = kernel_process().account();
    let carry = |via: &KRef<ChannelObj>, end: &KRef<ChannelObj>| {
        let mut hs = Vec::new();
        hs.try_reserve_exact(1).unwrap();
        hs.push((Object::Channel(end.clone()), default_rights(ObjType::Channel)));
        via.write(Message::new(acct, Vec::new(), hs).unwrap()).is_ok()
    };
    let ch0 = live(ObjType::Channel);
    // a2's queue holds b2, b2's queue holds a2; the writing ends close.
    let make = || {
        let (a1, a2) = ChannelObj::create().unwrap();
        let (b1, b2) = ChannelObj::create().unwrap();
        let ok = carry(&a1, &b2) && carry(&b1, &a2);
        (ok, a2, b2)
    };
    let (ok, a2, b2) = make();
    check!(t, ok);
    // Held from outside (a2): nothing in it may go, nor b2 (readable through a2).
    drop(b2);
    collect_cycles();
    check!(t, live(ObjType::Channel) == ch0 + 2);
    check!(t, a2.pending() == 1);
    // Now nobody outside holds either: both go.
    drop(a2);
    check!(t, live(ObjType::Channel) == ch0 + 2); // plain reference counting cannot free them
    collect_cycles();
    check!(t, live(ObjType::Channel) == ch0);
    // A longer ring of three, plus a message with no handles.
    let (x1, x2) = ChannelObj::create().unwrap();
    let (y1, y2) = ChannelObj::create().unwrap();
    let (z1, z2) = ChannelObj::create().unwrap();
    check!(t, carry(&x1, &y2) && carry(&y1, &z2) && carry(&z1, &x2));
    check!(t, x1.write(Message::new(acct, Vec::new(), Vec::new()).unwrap()).is_ok());
    drop((x1, x2, y1, y2, z1, z2));
    collect_cycles();
    check!(t, live(ObjType::Channel) == ch0);
}

fn lifetimes(t: &mut T) {
    let frames0 = vmo::committed_frames();
    let p = new_proc("life", Limits::DEFAULT);
    let me = self_handle(&p);
    let (ch, cvmar) = p.process_create(me, "victim", Limits::DEFAULT).unwrap();
    let (c, _) = p.get_process(ch, Rights::NONE).unwrap();

    // VMO contents across page boundaries; bounds.
    let v = p.vmo_create(2 * 4096).unwrap();
    let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    check!(t, p.vmo_write(v, 4096 - 100, &data).is_ok());
    let mut back = [0u8; 300];
    check!(t, p.vmo_read(v, 4096 - 100, &mut back).is_ok() && back[..] == data[..]);
    check!(t, p.vmo_read(v, 2 * 4096 - 1, &mut back) == Err(Status::OutOfRange));
    check!(t, p.vmo_write(v, u64::MAX, b"x") == Err(Status::OutOfRange));
    let mut fresh = [1u8; 16];
    check!(t, p.vmo_read(v, 0, &mut fresh).is_ok() && fresh == [0; 16]); // zeroed pages

    // VMAR placement, overlap, alignment, unmap; a mapping keeps the VMO alive.
    let a1 = p.vmar_map(cvmar, None, v, 0, 2 * 4096, R | W).unwrap();
    check!(t, a1 >= USER_BASE && a1.is_multiple_of(4096) && a1 < super::vmar::USER_TOP); // at the random hint
    let off1 = a1 - USER_BASE;
    check!(t, p.vmar_map(cvmar, Some(off1), v, 0, 4096, R) == Err(Status::NoSpace));
    check!(t, p.vmar_map(cvmar, Some(off1 + 4096), v, 0, 4096, R) == Err(Status::NoSpace));
    check!(t, p.vmar_map(cvmar, Some(123), v, 0, 4096, R) == Err(Status::InvalidArgs));
    check!(t, p.vmar_map(cvmar, None, v, 4096, 2 * 4096, R) == Err(Status::OutOfRange));
    check!(t, p.vmar_map(cvmar, None, v, 0, 0, R) == Err(Status::InvalidArgs));
    let a2 = p.vmar_map(cvmar, Some(0x10_0000), v, 4096, 4096, R).unwrap();
    check!(t, a2 == USER_BASE + 0x10_0000);
    let (sub, sub_base) = p.vmar_allocate(cvmar, None, 0x4000, Rights::MAP | R).unwrap();
    check!(t, sub_base == a1 + 2 * 4096); // packed: first fit from the hint, after the first mapping
    check!(t, p.vmar_map(sub, None, v, 0, 4096, R | W) == Err(Status::AccessDenied));
    check!(t, p.vmar_map(sub, None, v, 0, 0x8000, R) == Err(Status::OutOfRange)); // bigger than the VMO
    let a3 = p.vmar_map(sub, None, v, 0, 4096, R).unwrap();
    check!(t, a3 == sub_base);
    check!(t, p.vmar_unmap(cvmar, a1, 4096) == Err(Status::InvalidArgs)); // partial unmap
    check!(t, p.vmar_unmap(cvmar, a1, 2 * 4096) == Ok(1));
    let (r, _) = p.get_vmar(cvmar, Rights::NONE).unwrap();
    check!(t, r.counts() == (1, 1) && r.perms_at(a2) == Some(R) && r.perms_at(a1).is_none());
    p.handle_close(v).unwrap(); // only the mappings keep it now
    check!(t, vmo::committed_frames() == frames0 + 2);

    // Kill: every handle in the child is closed, its address space torn down, TERMINATED set.
    let cev = c.event_create().unwrap();
    let ctm = c.timer_create().unwrap();
    c.timer_set(ctm, 1000 * MS).unwrap();
    let cvmo = c.vmo_create(4096).unwrap();
    check!(t, c.handle_count() == 3);
    check!(t, p.object_wait(ch, sig::TERMINATED, 0) == Err(Status::TimedOut));
    p.process_kill(ch).unwrap();
    check!(t, p.object_wait(ch, sig::TERMINATED, 0) == Ok(sig::TERMINATED));
    check!(t, c.handle_count() == 0 && c.usage() == Usage { memory: 0, handles: 0, threads: 0 });
    check!(t, c.object_info(cev) == Err(Status::BadHandle));
    check!(t, c.event_create() == Err(Status::BadState));
    check!(t, c.vmo_create(4096) == Err(Status::BadState));
    check!(t, r.counts() == (0, 0)); // root VMAR emptied
    let _ = cvmo;
    check!(t, vmo::committed_frames() == frames0);

    // Lazy VMO commit (demand paging) and child vmar_destroy.
    let (ch2, cvmar2) = p.process_create(me, "lazy", Limits::DEFAULT).unwrap();
    let lz = p.vmo_create(8 * 4096).unwrap();
    check!(t, vmo::committed_frames() == frames0); // 0 frames committed on creation
    let mut zbuf = [0xAAu8; 32];
    check!(t, p.vmo_read(lz, 5 * 4096, &mut zbuf).is_ok() && zbuf == [0; 32]);
    check!(t, vmo::committed_frames() == frames0); // reading zeros commits nothing
    check!(t, p.vmo_write(lz, 3 * 4096, b"lazy").is_ok());
    check!(t, vmo::committed_frames() == frames0 + 1); // only page 3 committed
    let (sub2, sub2_base) = p.vmar_allocate(cvmar2, Some(0x20_0000), 16 * 4096, Rights::SAME).unwrap();
    let lva = p.vmar_map(sub2, Some(0), lz, 0, 8 * 4096, R | W).unwrap();
    let (r2, _) = p.get_vmar(cvmar2, Rights::NONE).unwrap();
    check!(t, r2.aspace().translate(lva).is_none()); // page 0 not committed yet
    check!(t, r2.aspace().translate(lva + 3 * 4096).is_some()); // page 3 eagerly mapped
    check!(t, r2.fault(lva + 5 * 4096, true, false)); // demand-fault page 5
    check!(t, r2.aspace().translate(lva + 5 * 4096).is_some());
    check!(t, vmo::committed_frames() == frames0 + 2);
    check!(t, !r2.fault(lva + 6 * 4096, false, true)); // exec fault on RW mapping refused
    check!(t, !r2.fault(lva + 10 * 4096, false, false)); // unmapped gap refused
    check!(t, p.vmar_destroy(cvmar2) == Err(Status::InvalidArgs)); // root VMAR cannot be destroyed
    check!(t, p.vmar_destroy(sub2).is_ok());
    check!(t, p.vmar_destroy(sub2) == Err(Status::BadState)); // double destroy refused
    check!(t, p.vmar_map(sub2, None, lz, 0, 4096, R) == Err(Status::BadState));
    // Address range freed by vmar_destroy can be re-allocated immediately at the exact same offset.
    let (sub3, sub3_base) = p.vmar_allocate(cvmar2, Some(0x20_0000), 16 * 4096, Rights::SAME).unwrap();
    check!(t, sub3_base == sub2_base);
    check!(t, p.vmar_destroy(sub3).is_ok());
    p.handle_close(sub2).unwrap();
    p.handle_close(sub3).unwrap();
    p.handle_close(lz).unwrap();
    check!(t, vmo::committed_frames() == frames0);
    p.process_kill(ch2).unwrap();
    drop(r2);
    // Granting into a dead process is refused (and consumes the handle).
    let e = p.event_create().unwrap();
    check!(t, p.handle_grant(e, Rights::SAME, ch) == Err(Status::BadState));
    check!(t, p.object_info(e) == Err(Status::BadHandle));
    drop((r, c));

    // Event wake-up across threads; timer fires; timer cancel.
    let ev = p.event_create().unwrap();
    let waiter_ev = p.handle_duplicate(ev, Rights::WAIT).unwrap();
    let pp = p.clone();
    let w = spawn(c"obj.waiter", prio::NORMAL, move || {
        match pp.object_wait(waiter_ev, sig::SIGNALED, 2000 * MS) {
            Ok(s) if s & sig::SIGNALED != 0 => 1,
            _ => 0,
        }
    })
    .unwrap();
    sleep_ns(2 * MS);
    p.event_signal(ev, 0, sig::SIGNALED).unwrap();
    check!(t, w.join() == 1);
    let tm = p.timer_create().unwrap();
    let t0 = ffi::now_ns();
    p.timer_set(tm, 3 * MS).unwrap();
    check!(t, p.object_wait(tm, sig::SIGNALED, 1000 * MS).is_ok());
    check!(t, ffi::now_ns() - t0 >= 3 * MS);
    p.timer_set(tm, 1000 * MS).unwrap(); // re-arm clears SIGNALED
    check!(t, p.object_wait(tm, sig::SIGNALED, 0) == Err(Status::TimedOut));
    check!(t, p.timer_cancel(tm) == Ok(true));
    check!(t, p.object_wait(tm, sig::SIGNALED, 5 * MS) == Err(Status::TimedOut));
    p.timer_set(tm, 1000 * MS).unwrap();
    p.handle_close(tm).unwrap(); // closing an armed timer cancels it (no callback on freed memory)
    let vmo_h = p.vmo_create(4096).unwrap();
    check!(t, p.object_wait(vmo_h, sig::SIGNALED, 0) == Err(Status::WrongType));
    p.kill();
}

/// Touches every object type and most operations; any step may fail with NoMemory.
fn scenario(k: &Process) -> KResult<()> {
    let me = k.add(Object::Process(new_proc_ref()?), default_rights(ObjType::Process))?;
    let (ch, vmar) = k.process_create(me, "oom", Limits::DEFAULT)?;
    let v = k.vmo_create(3 * 4096)?;
    k.vmo_write(v, 4000, b"fault injection")?;
    k.vmar_map(vmar, None, v, 0, 2 * 4096, R | W)?;
    let (sub, _) = k.vmar_allocate(vmar, None, 0x8000, Rights::SAME)?;
    k.vmar_map(sub, None, v, 4096, 4096, R)?;
    k.vmar_destroy(sub)?;
    let e = k.event_create()?;
    let e2 = k.handle_duplicate(e, Rights::WAIT | Rights::TRANSFER)?;
    k.handle_grant(e2, Rights::SAME, ch)?;
    let tm = k.timer_create()?;
    k.timer_set(tm, 1000 * MS)?;
    let mut hs = Vec::new();
    for _ in 0..40 {
        // grows the handle table a few times
        hs.try_reserve(1).map_err(|_| Status::NoMemory)?;
        hs.push(k.handle_duplicate(e, Rights::SAME)?);
    }
    let (_, c_vmar) = k.process_create(ch, "oom.grandchild", Limits::DEFAULT)?;
    k.vmar_allocate(c_vmar, None, 0x4000, Rights::SAME)?;
    ipc_scenario(k, me)
}

/// IPC objects, under the same fault injection.
fn ipc_scenario(k: &Process, me: Handle) -> KResult<()> {
    use super::channel::Message;
    use super::exception::{ExcCore, Info, Regs};
    let (a, b) = ChannelObj::create()?;
    k.add(Object::Channel(a.clone()), default_rights(ObjType::Channel))?;
    k.add(Object::Channel(b.clone()), default_rights(ObjType::Channel))?;
    // A message carrying an event handle, read back into the table.
    let e = k.event_create()?;
    let (eobj, er) = k.take(e)?;
    let mut data = Vec::new();
    data.try_reserve_exact(16).map_err(|_| Status::NoMemory)?;
    data.extend_from_slice(b"fault injection!");
    let mut hs = Vec::new();
    hs.try_reserve_exact(1).map_err(|_| Status::NoMemory)?;
    hs.push((eobj, er));
    a.write(Message::new(k.account(), data, hs)?).map_err(|(e, _)| e)?;
    let m = b.read(64, 4).map_err(|_| Status::BadState)?;
    for (obj, r) in &m.handles {
        k.add(obj.clone(), *r)?;
    }
    drop(m);
    // A port with an async wait that fires (a message arrives) and one left pending.
    let (port, vmo) = PortObj::create(k.account(), 8)?;
    k.add(Object::Port(port.clone()), default_rights(ObjType::Port))?;
    k.add(Object::Vmo(vmo), default_rights(ObjType::Vmo))?;
    b.signals().observe(super::port::new_wait(&port.core, k.account(), sig::READABLE, 1)?);
    a.write(Message::new(k.account(), Vec::new(), Vec::new())?).map_err(|(e, _)| e)?;
    let e2 = k.event_create()?;
    let (ev, _) = k.get_event(e2, Rights::NONE)?;
    ev.signals.observe(super::port::new_wait(&port.core, k.account(), sig::SIGNALED, 2)?);
    // An exception object and an exception channel.
    let core = ExcCore::new(Info::default(), Regs::default())?;
    k.add(Object::Exception(ExceptionObj::new(core)?), default_rights(ObjType::Exception))?;
    let (pc, _) = k.process_create(me, "oom.exc", Limits::DEFAULT)?;
    let (p, _) = k.get_process(pc, Rights::MANAGE)?;
    let sup = p.create_exception_channel()?;
    k.add(Object::Channel(sup), default_rights(ObjType::Channel))?;
    Ok(())
}

fn new_proc_ref() -> KResult<KRef<Process>> {
    Process::new(Some(kernel_process()), "oom.root", Limits::DEFAULT)
}

fn out_of_memory(t: &mut T) {
    sleep_ns(20 * MS); // let the reaper finish earlier threads (heap accounting must be quiet)
    let mut runs = 0u64;
    let mut ok = false;
    for n in 1..5000u64 {
        let heap0 = unsafe_heap_live();
        let objs0 = live_all();
        let frames0 = vmo::committed_frames();
        let quota0 = kernel_process().usage();
        let k = new_proc("oom.caller", Limits::DEFAULT);
        let heap_k = unsafe_heap_live();
        // SAFETY: plain calls into the fault-injection hooks of this thread.
        unsafe { fault::fault_inject_arm(fault::ALL, n) };
        let r = scenario(&k);
        // SAFETY: as above.
        let fired = unsafe { fault::fault_inject_disarm() };
        runs += 1;
        // Clean up: kill every process the scenario reached (through k's handles), then k.
        k.kill();
        drop(k);
        if fired {
            if r != Err(Status::NoMemory) {
                crate::kprintln!("  allocation {}: scenario returned {:?}, want NoMemory", n, r.err());
                t.failures += 1;
            }
        } else {
            if r.is_err() {
                crate::kprintln!("  scenario failed without an injected fault: {:?}", r.err());
                t.failures += 1;
            }
            ok = true;
        }
        let heap1 = unsafe_heap_live();
        let leak = heap1 != heap0
            || live_all() != objs0
            || vmo::committed_frames() != frames0
            || kernel_process().usage() != quota0;
        if leak {
            crate::kprintln!(
                "  allocation {}: leak: heap {} -> {} (caller {}), objects {:?} -> {:?}, frames {} -> {}, quota {:?} -> {:?}",
                n,
                heap0,
                heap1,
                heap_k - heap0,
                objs0,
                live_all(),
                frames0,
                vmo::committed_frames(),
                quota0,
                kernel_process().usage()
            );
            t.failures += 1;
            return;
        }
        if ok {
            break;
        }
    }
    check!(t, ok);
    crate::kprintln!(
        "  out of memory: {} allocation failure points, each failed cleanly with no leak",
        runs - 1
    );
}

fn unsafe_heap_live() -> u64 {
    // SAFETY: reads a counter under the heap lock.
    unsafe { ffi::heap_live_allocs() }
}

fn smp_stress(t: &mut T) {
    // One process, one handle table, threads on every CPU duplicating, signalling, waiting,
    // creating and closing at once.
    let p = new_proc("stress", Limits::DEFAULT);
    let ev = p.event_create().unwrap();
    let base = p.handle_count();
    let errors = alloc::sync::Arc::new(AtomicU32::new(0));
    let mut workers = Vec::new();
    for i in 0..8u64 {
        let p = p.clone();
        let errors = errors.clone();
        workers.push(
            spawn(c"obj.stress", prio::NORMAL, move || {
                let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ (i + 1);
                let mut mine: Vec<Handle> = Vec::new();
                for _ in 0..3000 {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    let r = match s % 6 {
                        0 | 1 => p.handle_duplicate(ev, Rights::SAME).map(|h| mine.push(h)),
                        2 => match mine.pop() {
                            Some(h) => p.handle_close(h),
                            None => Ok(()),
                        },
                        3 => p.event_signal(ev, 0, sig::SIGNALED),
                        4 => p.object_wait(ev, sig::SIGNALED, 0).map(drop).or_else(|e| {
                            if e == Status::TimedOut { Ok(()) } else { Err(e) }
                        }),
                        _ => p.vmo_create(4096).and_then(|h| p.handle_close(h)),
                    };
                    if r.is_err() {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let n = mine.len() as i32;
                for h in mine {
                    if p.handle_close(h).is_err() {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                n
            })
            .unwrap(),
        );
    }
    let total: i32 = workers.into_iter().map(|w| w.join()).sum();
    check!(t, errors.load(Ordering::Relaxed) == 0);
    check!(t, total > 0 && p.handle_count() == base);
    check!(t, p.usage().handles == u64::from(base) && p.usage().memory == 0);
    p.kill();
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_objects_test() -> u32 {
    let mut t = T { failures: 0 };
    let objs0 = live_all();
    let frames0 = vmo::committed_frames();
    let k0 = kernel_process().usage();

    rights(&mut t);
    crate::kprintln!("  rights: enforced on every operation, never gained");
    handles(&mut t);
    crate::kprintln!("  handles: unguessable values, closed values stay invalid");
    quotas(&mut t);
    crate::kprintln!("  quotas: handles, memory, threads, hierarchical");
    lifetimes(&mut t);
    crate::kprintln!("  lifetimes: kill, mappings, events, timers");
    cycles(&mut t);
    crate::kprintln!("  cycles: unreachable channel cycles collected, held ones kept");
    out_of_memory(&mut t);
    smp_stress(&mut t);
    crate::kprintln!("  smp: 8 threads sharing one handle table");

    sleep_ns(20 * MS); // detached test threads drop their last object references as they exit
    check!(t, live_all() == objs0);
    check!(t, vmo::committed_frames() == frames0);
    check!(t, kernel_process().usage() == k0);
    print_summary();
    if t.failures == 0 {
        crate::kprintln!("KTEST objects: PASSED");
    } else {
        crate::kprintln!("KTEST objects: FAILED ({})", t.failures);
    }
    t.failures
}
