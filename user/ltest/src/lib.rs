//! libd tests (`ltest.dx`). init runs it (`run ltest`, test case `libd`) with the log and copies
//! of the program VMOs. Exit 0: every check passed.
//!
//! - abi: the kernel speaks at least the ABI libd was built for; every status has a name
//! - handles: owned handles close on drop (handle quota back to where it was), rights narrow
//! - heap: four threads allocate, fill, check and free at once; everything comes back
//! - threads: results, distinct ids, a TCB at each thread's FS base inside its own stack,
//!   `thread_exit` seen by `join`, stacks recycled, the thread quota back to one
//! - mutex: four threads x 100 000 increments, exact; again with the event fallback (yielding)
//! - once, detached threads (reclaimed), channels (call to a server thread, handles carried,
//!   unclaimed handles closed)
//! - stack guard: a child whose thread overflows its stack faults in the guard page right below
//!   it (checked through the child's exception channel)
//! - the C API: ctest.dx
//! - benchmarks: thread spawn+join, uncontended mutex, small allocation
//!
//! Arguments: none (the tests), `overflow` (the stack-guard child), or `svc-grants`,
//! `svc-quota`, `svc-crash`, `svc-log` (services of the service manager's test run) and
//! `svc-time` (the clock across a reboot), all in src/svc.rs.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use libd::sync::{Mutex, Once};
use libd::sys::{self, Handle, SpawnHandle};
use libd::{Channel, Event, Owned, Startup, heap, println, thread};

mod app;
mod awmi;
mod identity;
mod svc;

libd::entry!(_start, main);

macro_rules! check {
    ($c:expr, $($t:tt)*) => {
        if !$c {
            println!("ltest: FAIL: {} (line {})", format_args!($($t)*), line!());
            return false;
        }
    };
}

fn handles_used() -> u64 {
    sys::process_quota(libd::startup_handle(sys::TAG_PROC_SELF)).map_or(0, |q| q.used.handles)
}

fn threads_used() -> u64 {
    sys::process_quota(libd::startup_handle(sys::TAG_PROC_SELF)).map_or(0, |q| q.used.threads)
}

fn test_abi() -> bool {
    let v = sys::abi_version();
    check!(v >= i64::from(sys::ABI_VERSION), "kernel ABI v{} older than libd's v{}", v, sys::ABI_VERSION);
    check!(sys::status(sys::ERR_NOT_SIGNED) == "NOT_SIGNED" && sys::status(sys::ERR_BAD_ADDRESS) == "BAD_ADDRESS", "status names");
    check!(sys::status(-18) == "?" && sys::status(1) == "?", "unknown status names");
    // ABI v14: kernel ChaCha20 CSPRNG (`SYS_GET_RANDOM`)
    let mut r1 = [0u8; 32];
    let mut r2 = [0u8; 32];
    check!(sys::get_random(&mut r1, 0).is_ok() && sys::get_random(&mut r2, 0).is_ok(), "get_random failed");
    check!(r1 != [0u8; 32] && r2 != [0u8; 32] && r1 != r2, "get_random non-random output");
    check!(sys::sc(sys::nr::GET_RANDOM, 0xDEAD_BEEF, 32, 0, 0, 0, 0) == sys::ERR_BAD_ADDRESS, "get_random bad addr");
    check!(sys::sc(sys::nr::GET_RANDOM, r1.as_mut_ptr() as u64, 8192, 0, 0, 0, 0) == sys::ERR_INVALID_ARGS, "get_random oversize");
    println!("ltest: abi: kernel v{}, libd v{}, {} syscalls bound, 18 status names, csprng ok", v, sys::ABI_VERSION, sys::nr::COUNT);
    true
}

fn test_handles() -> bool {
    let base = handles_used();
    {
        let mut evs = Vec::new();
        for _ in 0..100 {
            match Event::new() {
                Ok(e) => evs.push(e),
                Err(e) => {
                    println!("ltest: FAIL: event_create: {}", sys::status(e));
                    return false;
                }
            }
        }
        check!(handles_used() == base + 100, "100 events: {} handles, expected {}", handles_used(), base + 100);
        let w = evs[0].0.dup(sys::RIGHT_WAIT).unwrap_or_default();
        check!(w.info().map(|i| i.rights) == Ok(sys::RIGHT_WAIT), "dup narrowed to WAIT");
        check!(w.dup(sys::RIGHT_WAIT).is_err(), "a handle without DUPLICATE cannot be duplicated");
        let e = evs.pop().map(|e| e.0).unwrap_or_default();
        let r = e.replace(sys::RIGHT_SIGNAL | sys::RIGHT_WAIT).unwrap_or_default();
        check!(sys::event_signal(r.raw(), 0, sys::SIGNALED) == 0 && r.wait(sys::SIGNALED, 0).is_ok(), "replaced handle works");
        let raw = r.into_raw();
        check!(sys::handle_close(raw) == 0, "into_raw keeps the handle open");
    }
    check!(handles_used() == base, "after drop: {} handles, expected {}", handles_used(), base);
    println!("ltest: handles: 100 owned handles closed on drop, rights narrowed by dup/replace");
    true
}

fn pattern(seed: u64, i: usize) -> u8 {
    (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8 ^ i as u8
}

fn heap_worker(seed: u64) -> bool {
    let mut x = seed | 1;
    let mut live: Vec<(Vec<u8>, u64)> = Vec::new();
    for round in 0..4000u64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let size = if x.is_multiple_of(16) { 2048 + (x >> 8) as usize % 30000 } else { 1 + (x >> 8) as usize % 1500 };
        let tag = seed * 100_000 + round;
        let v: Vec<u8> = (0..size).map(|i| pattern(tag, i)).collect();
        live.push((v, tag));
        if live.len() > 64 || x.is_multiple_of(3) {
            let (v, tag) = live.swap_remove((x >> 20) as usize % live.len());
            if v.iter().enumerate().any(|(i, &b)| b != pattern(tag, i)) {
                return false;
            }
        }
    }
    live.iter().all(|(v, tag)| v.iter().enumerate().all(|(i, &b)| b == pattern(*tag, i)))
}

fn test_heap() -> bool {
    // Warm up: four threads leave four empty stack regions in libd's cache (a small vector that is
    // kept), so the baseline below already includes it.
    let warm: Vec<_> = (0..4).filter_map(|_| thread::spawn(|| ()).ok()).collect();
    for j in warm {
        let _ = j.join();
    }
    let before = heap::stats();
    let mut js = Vec::new();
    for t in 0..4u64 {
        match thread::spawn(move || heap_worker(t + 1)) {
            Ok(j) => js.push(j),
            Err(e) => {
                println!("ltest: FAIL: spawn: {}", sys::status(e));
                return false;
            }
        }
    }
    let ok = js.into_iter().all(|j| j.join() == Ok(true));
    check!(ok, "heap workers saw their data change");
    // In-place realloc within a size class.
    let mut v: Vec<u8> = Vec::with_capacity(40);
    v.extend_from_slice(&[1; 40]);
    let p = v.as_ptr();
    v.reserve_exact(20); // 60 bytes: still the 64-byte class
    check!(v.as_ptr() == p, "realloc within a size class moved the block");
    drop(v);
    let after = heap::stats();
    check!(after.bytes == before.bytes && after.blocks == before.blocks && after.large == before.large, "heap not back: {:?} vs {:?}", after, before);
    println!("ltest: heap: 4 threads x 4000 checked allocations (small and large), all returned; {} arenas", after.arenas);
    true
}

fn test_threads() -> bool {
    check!(thread::current_id() == 1, "first thread id {}", thread::current_id());
    let mut js = Vec::new();
    for i in 0..16u64 {
        let data: Vec<u64> = (0..100).map(|k| k * i).collect();
        let j = thread::spawn(move || {
            let t = thread::current();
            let fs = sys::thread_get_base(sys::BASE_FS).unwrap_or(0);
            let here = &t as *const _ as u64; // a local: on this thread's stack
            let ok = fs == t.self_ptr && here >= t.stack_lo && here < t.stack_hi && fs < t.stack_hi && fs >= t.stack_lo;
            (data.iter().sum::<u64>(), thread::current_id(), ok)
        });
        match j {
            Ok(j) => js.push(j),
            Err(e) => {
                println!("ltest: FAIL: spawn {}: {}", i, sys::status(e));
                return false;
            }
        }
    }
    let mut ids = Vec::new();
    for (i, j) in js.into_iter().enumerate() {
        let id = j.id();
        match j.join() {
            Ok((sum, tid, ok)) => {
                check!(sum == 4950 * i as u64, "thread {} result {}", i, sum);
                check!(tid == id && tid > 1, "thread {} id {} vs {}", i, tid, id);
                check!(ok, "thread {}: TCB not at the FS base inside its own stack", i);
                check!(!ids.contains(&tid), "duplicate id {}", tid);
                ids.push(tid);
            }
            Err(c) => {
                println!("ltest: FAIL: thread {} ended with {}", i, c);
                return false;
            }
        }
    }
    let cached = thread::cached_stacks();
    check!(cached >= 16, "{} stacks kept for reuse", cached);
    let j = thread::spawn(|| -> u32 { sys::thread_exit(42) });
    check!(j.map(|j| j.join()) == Ok(Err(42)), "thread_exit(42) seen by join");
    check!(thread::cached_stacks() == cached, "stack reused");
    let big = thread::Builder::new().stack_size(1 << 20).spawn(|| {
        let mut buf = [0u8; 512 * 1024]; // needs the bigger stack
        core::hint::black_box(&mut buf);
        buf[1000] = 7;
        buf[1000]
    });
    check!(big.map(|j| j.join()) == Ok(Ok(7)), "1 MiB stack");
    check!(threads_used() == 1, "{} threads left", threads_used());
    println!("ltest: threads: 16 threads, results and ids, TCB at FS inside each stack, thread_exit seen, {} stacks recycled", cached);
    true
}

fn test_mutex() -> bool {
    for fallback in [false, true] {
        libd::sync::FAIL_EVENTS.store(fallback, Ordering::Relaxed);
        let n = if fallback { 20_000 } else { 100_000 };
        let m = Arc::new(Mutex::new(0u64));
        let waits = libd::sync::contended_waits();
        let mut js = Vec::new();
        for _ in 0..4 {
            let m = m.clone();
            match thread::spawn(move || {
                for _ in 0..n {
                    *m.lock() += 1;
                }
            }) {
                Ok(j) => js.push(j),
                Err(e) => {
                    println!("ltest: FAIL: spawn: {}", sys::status(e));
                    return false;
                }
            }
        }
        for j in js {
            check!(j.join().is_ok(), "mutex worker");
        }
        let total = *m.lock();
        check!(total == 4 * n, "count {} expected {}", total, 4 * n);
        let waited = libd::sync::contended_waits() - waits;
        println!("ltest: mutex: 4 threads x {} increments exact ({}), {} contended waits{}", n, total, waited,
                 if fallback { " (no kernel event: yielding)" } else { "" });
    }
    libd::sync::FAIL_EVENTS.store(false, Ordering::Relaxed);
    true
}

fn test_once_detached() -> bool {
    static ONCE: Once = Once::new();
    static RUNS: AtomicU64 = AtomicU64::new(0);
    let mut js = Vec::new();
    for _ in 0..8 {
        if let Ok(j) = thread::spawn(|| ONCE.call_once(|| {
            RUNS.fetch_add(1, Ordering::Relaxed);
        })) {
            js.push(j);
        }
    }
    check!(js.len() == 8, "spawned {}", js.len());
    for j in js {
        let _ = j.join();
    }
    check!(RUNS.load(Ordering::Relaxed) == 1 && ONCE.is_completed(), "once ran {} times", RUNS.load(Ordering::Relaxed));
    static DONE: AtomicU64 = AtomicU64::new(0);
    for _ in 0..8 {
        check!(thread::spawn(|| {
            thread::sleep(1_000_000);
            DONE.fetch_add(1, Ordering::Relaxed);
        })
        .is_ok(), "detached spawn");
    }
    let end = sys::clock_ns() + 5_000_000_000;
    while thread::reap() > 0 && sys::clock_ns() < end {
        thread::sleep(1_000_000);
    }
    check!(thread::reap() == 0 && DONE.load(Ordering::Relaxed) == 8, "detached threads not reclaimed");
    check!(threads_used() == 1, "{} threads left", threads_used());
    println!("ltest: once: one run from 8 threads; detached: 8 threads ran and were reclaimed");
    true
}

fn test_channels() -> bool {
    let base = handles_used();
    let Ok((client, server)) = Channel::pair() else {
        println!("ltest: FAIL: channel pair");
        return false;
    };
    let srv = thread::spawn(move || -> bool {
        let mut buf = [0u8; 64];
        let Ok((n, mut hs)) = server.read(&mut buf, sys::WAIT_FOREVER) else { return false };
        let Some(ev) = hs.take(0) else { return false };
        if n != 8 || &buf[4..8] != b"ping" || sys::event_signal(ev.raw(), 0, sys::SIGNALED) != 0 {
            return false;
        }
        let mut reply = [0u8; 8];
        reply[..4].copy_from_slice(&buf[..4]); // the transaction id
        reply[4..].copy_from_slice(b"pong");
        server.write(&reply, [ev]).is_ok()
    });
    let Ok(srv) = srv else {
        println!("ltest: FAIL: server thread");
        return false;
    };
    let Ok(ev) = Event::new() else { return false };
    let mut buf = [0u8; 64];
    let sent = ev.0.dup(sys::RIGHTS_SAME).unwrap_or_default();
    let r = client.call(b"\0\0\0\0ping", [sent], &mut buf, 5_000_000_000);
    let Ok((n, mut hs)) = r else {
        println!("ltest: FAIL: call: {}", sys::status(r.err().unwrap_or(0)));
        return false;
    };
    check!(n == 8 && &buf[4..8] == b"pong", "reply {:?}", &buf[..n]);
    check!(hs.len() == 1 && hs.take(0).is_some(), "handle carried back");
    check!(ev.wait(0), "the server signalled the event it was sent");
    check!(srv.join() == Ok(true), "server thread");
    // Handles nobody takes are closed with the message.
    let (a, b) = match Channel::pair() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let three: Vec<Owned> = (0..3).filter_map(|_| Event::new().ok().map(|e| e.0)).collect();
    check!(a.write(b"x", three).is_ok(), "write 3 handles");
    {
        let Ok((_, mut hs)) = b.read(&mut buf, 0) else { return false };
        check!(hs.len() == 3, "{} handles arrived", hs.len());
        let _kept = hs.take(1);
    }
    drop((a, b, client, ev));
    check!(handles_used() == base, "handles after channels: {} vs {}", handles_used(), base);
    println!("ltest: channels: call to a server thread with a handle each way, unclaimed handles closed, none leaked");
    true
}

#[inline(never)]
fn recurse(n: u64) -> u64 {
    let mut buf = [0u8; 256];
    core::hint::black_box(&mut buf);
    if core::hint::black_box(n) == u64::MAX {
        return 0;
    }
    buf[0] = n as u8;
    recurse(n + 1) + u64::from(buf[1])
}

/// The child: tell the parent where this thread's stack starts, then overflow it.
fn overflow_child() -> i32 {
    let ch = libd::startup_handle(sys::TAG_USER);
    let j = thread::spawn(move || {
        let lo = thread::current().stack_lo;
        sys::channel_write(ch, &lo.to_le_bytes());
        recurse(0)
    });
    match j {
        Ok(j) => {
            let _ = j.join();
            println!("ltest: FAIL: the overflowing thread returned");
            1
        }
        Err(_) => 2,
    }
}

fn spawn_program(name: &[u8], args: &[u8], extra: Option<Handle>, exc: Option<&mut Handle>) -> Result<Handle, i64> {
    let image = libd::find_program(name).ok_or(sys::ERR_BAD_HANDLE)?;
    let log = sys::handle_duplicate(libd::startup_handle(sys::TAG_LOG), sys::RIGHTS_SAME)?;
    let mut hs = [SpawnHandle { handle: log, rights: sys::RIGHTS_SAME, tag: sys::TAG_LOG, reserved: 0 }, SpawnHandle::default()];
    let mut n = 1;
    if let Some(h) = extra {
        hs[1] = SpawnHandle { handle: h, rights: sys::RIGHTS_SAME, tag: sys::TAG_USER, reserved: 0 };
        n = 2;
    }
    let limits = sys::Limits { memory: 16 << 20, handles: 256, threads: 16 };
    let pname = &name[..name.len() - 3]; // without ".dx"
    let mut exc_h: Handle = 0;
    let s = sys::Spawn {
        parent: libd::startup_handle(sys::TAG_PROC_SELF),
        image,
        name: pname.as_ptr() as u64,
        name_len: pname.len() as u64,
        args: args.as_ptr() as u64,
        args_len: args.len() as u64,
        handles: hs.as_ptr() as u64,
        nhandles: n,
        flags: if exc.is_some() { sys::SPAWN_EXCEPTION_CHANNEL } else { 0 },
        limits: &limits as *const sys::Limits as u64,
        exception_channel: &mut exc_h as *mut Handle as u64,
    };
    let p = sys::spawn_raw(&s)?;
    if let Some(e) = exc {
        *e = exc_h;
    }
    Ok(p)
}

fn test_guard() -> bool {
    let Ok((mine, theirs)) = sys::channel_pair() else { return false };
    let (mine, mut exc) = (Owned::from_raw(mine), 0);
    let child = match spawn_program(b"ltest.dx", b"overflow", Some(theirs), Some(&mut exc)) {
        Ok(p) => Owned::from_raw(p),
        Err(e) => {
            println!("ltest: FAIL: spawn the overflow child: {}", sys::status(e));
            return false;
        }
    };
    let exc = Channel(Owned::from_raw(exc));
    let mut lo = [0u8; 8];
    check!(sys::channel_read(mine.raw(), &mut lo, 5_000_000_000) == Ok(8), "the child's stack address");
    let lo = u64::from_le_bytes(lo);
    let mut buf = [0u8; core::mem::size_of::<sys::ExceptionMsg>()];
    let r = exc.read(&mut buf, 5_000_000_000);
    let Ok((n, mut hs)) = r else {
        println!("ltest: FAIL: no exception from the child: {}", sys::status(r.err().unwrap_or(0)));
        return false;
    };
    check!(n == buf.len(), "exception message size {}", n);
    // SAFETY: `buf` holds a whole `ExceptionMsg` written by the kernel (plain integers).
    let m: sys::ExceptionMsg = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast()) };
    let Some(e) = hs.take(0) else { return false };
    let in_guard = m.cr2 >= lo - sys::PAGE && m.cr2 < lo;
    sys::exception_resume(e.raw(), sys::EXC_KILL, sys::EXIT_FAULT);
    let _ = child.wait(sys::TERMINATED, sys::WAIT_FOREVER);
    let code = sys::process_exit_code(child.raw()) as i32;
    check!(m.kind == sys::EXC_FAULT && m.vector == 14, "exception kind {} vector {}", m.kind, m.vector);
    check!(in_guard, "fault at {:#x}, stack starts at {:#x}: not the guard page", m.cr2, lo);
    check!(code == sys::EXIT_FAULT, "child exit code {:#x}", code);
    println!("ltest: stack guard: overflow faulted at {:#x}, in the guard page below the stack at {:#x}", m.cr2, lo);
    true
}

fn test_ctest() -> bool {
    let p = match spawn_program(b"ctest.dx", b"", None, None) {
        Ok(p) => Owned::from_raw(p),
        Err(e) => {
            println!("ltest: FAIL: spawn ctest: {}", sys::status(e));
            return false;
        }
    };
    let _ = p.wait(sys::TERMINATED, sys::WAIT_FOREVER);
    let code = sys::process_exit_code(p.raw());
    check!(code == 0, "ctest exited with {}", code);
    println!("ltest: C API: ctest passed");
    true
}

fn test_ring() -> bool {
    use libd::ring::{Cqe, IoRing, Sqe};
    check!(IoRing::create(0, 4096).is_err(), "ring: 0 entries refused");
    check!(IoRing::create(3, 4096).is_err(), "ring: non-power-of-two refused");
    check!(IoRing::create(16, 0).is_err(), "ring: 0 data_len refused");
    let mut producer = match IoRing::create(8, 128 * 1024) {
        Ok(r) => r,
        Err(e) => {
            println!("ltest: FAIL: IoRing::create returned {}", e);
            return false;
        }
    };
    let dup = match sys::handle_duplicate(producer.vmo(), sys::RIGHTS_SAME) {
        Ok(h) => h,
        Err(e) => {
            println!("ltest: FAIL: duplicate ring vmo returned {}", e);
            return false;
        }
    };
    let mut consumer = match IoRing::attach(dup) {
        Ok(r) => r,
        Err(e) => {
            println!("ltest: FAIL: IoRing::attach returned {}", e);
            return false;
        }
    };
    check!(consumer.data_len() == 128 * 1024, "ring data_len");
    check!(consumer.data(128 * 1024, 1).is_none(), "ring data bounds");
    // Fill SQ to capacity (8), verify 9th is refused, drain and wrap around twice.
    for round in 0..3u32 {
        for i in 0..8u32 {
            let off = i * 8192;
            let pat = (round * 16 + i) as u8;
            producer.data_mut(off, 4096).unwrap().fill(pat);
            check!(
                producer.push_sq(Sqe { id: round * 100 + i, op: 1, a: u64::from(i), b: 8, buf_off: off, buf_len: 4096 }),
                "push_sq"
            );
        }
        check!(!producer.push_sq(Sqe::default()), "SQ full refused");
        for i in 0..8u32 {
            let sqe = consumer.pop_sq().unwrap();
            let pat = (round * 16 + i) as u8;
            check!(sqe.id == round * 100 + i && consumer.data(sqe.buf_off, 1).unwrap()[0] == pat, "sqe + zero-copy data");
            consumer.data_mut(sqe.buf_off, 1).unwrap()[0] = pat ^ 0xFF;
            check!(consumer.push_cq(Cqe { id: sqe.id, status: 0, a: sqe.b }), "push_cq");
        }
        check!(consumer.pop_sq().is_none(), "SQ empty");
        for i in 0..8u32 {
            let cqe = producer.pop_cq().unwrap();
            let pat = (round * 16 + i) as u8;
            check!(cqe.id == round * 100 + i && cqe.status == 0 && producer.data(i * 8192, 1).unwrap()[0] == (pat ^ 0xFF), "cqe + reply data");
        }
        check!(producer.pop_cq().is_none(), "CQ empty");
    }
    // Hostile header: invalid magic/size rejected by attach.
    let bad = sys::vmo_create(8192).unwrap();
    check!(matches!(IoRing::attach(bad), Err(sys::ERR_INVALID_ARGS)), "hostile ring VMO rejected");
    println!("ltest: ring: shared-memory SQ/CQ wrap-around, 128 KiB zero-copy buffer, hostile VMO rejected");
    true
}

fn bench() {
    const SPAWNS: u64 = 200;
    let t0 = sys::clock_ns();
    for _ in 0..SPAWNS {
        if let Ok(j) = thread::spawn(|| 1u8) {
            let _ = j.join();
        }
    }
    let spawn_ns = (sys::clock_ns() - t0) / SPAWNS;
    const LOCKS: u64 = 1_000_000;
    let m = Mutex::new(0u64);
    let t0 = sys::clock_ns();
    for _ in 0..LOCKS {
        *core::hint::black_box(&m).lock() += 1;
    }
    let lock_ns = (sys::clock_ns() - t0) * 1000 / LOCKS;
    const ALLOCS: u64 = 1_000_000;
    let t0 = sys::clock_ns();
    for i in 0..ALLOCS {
        let b = alloc::boxed::Box::new([i; 8]); // 64 bytes
        core::hint::black_box(&b);
    }
    let alloc_ns = (sys::clock_ns() - t0) * 1000 / ALLOCS;
    println!("BENCH libd: thread spawn+join (64 KiB stack): {} ns", spawn_ns);
    println!("BENCH libd: mutex lock+unlock (uncontended): {}.{:03} ns", lock_ns / 1000, lock_ns % 1000);
    println!("BENCH libd: Box alloc+free 64 B: {}.{:03} ns", alloc_ns / 1000, alloc_ns % 1000);
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block the kernel passed to the entry point.
    if !unsafe { libd::init(s, "ltest") } {
        return 1;
    }
    let a = libd::args();
    if a.starts_with(b"overflow") {
        return overflow_child();
    } else if a.starts_with(b"svc-grants") {
        return svc::grants();
    } else if a.starts_with(b"svc-quota") {
        return svc::quota();
    } else if a.starts_with(b"svc-crash") {
        return svc::crash();
    } else if a.starts_with(b"svc-log") {
        return svc::log_read();
    } else if a.starts_with(b"svc-time") {
        return svc::time();
    } else if a.starts_with(b"svc-audio-ungranted") {
        return svc::audio_ungranted();
    } else if a.starts_with(b"svc-audio-playonly") {
        return svc::audio_playonly();
    } else if a.starts_with(b"svc-audio-full") {
        return svc::audio_full();
    } else if a.starts_with(b"svc-net-ungranted") {
        return svc::net_ungranted();
    } else if a.starts_with(b"svc-net-full") {
        return svc::net_full();
    } else if a.starts_with(b"svc-gpu-ungranted") {
        return svc::gpu_ungranted();
    } else if a.starts_with(b"svc-gpu-queryonly") {
        return svc::gpu_queryonly();
    } else if a.starts_with(b"svc-gpu-full") {
        return svc::gpu_full();
    } else if a.starts_with(b"svc-awmi-ungranted") {
        return awmi::ungranted();
    } else if a.starts_with(b"svc-awmi-full") {
        return awmi::full();
    } else if a.starts_with(b"svc-awmi-a") {
        return awmi::client("svc-awmi-a", 0x00D0_3030, b"Alpha", None, b'a');
    } else if a.starts_with(b"svc-awmi-b") {
        return awmi::client("svc-awmi-b", 0x0030_C050, b"Beta", Some(b"system: fake"), b'b');
    } else if a.starts_with(b"svc-id-ungranted") {
        return identity::ungranted();
    } else if a.starts_with(b"svc-id-full") {
        return identity::full();
    } else if a.starts_with(b"svc-app-ungranted") {
        return app::ungranted();
    } else if a.starts_with(b"svc-app-full") {
        return app::full();
    }
    let ok = test_abi()
        && test_handles()
        && test_heap()
        && test_threads()
        && test_mutex()
        && test_once_detached()
        && test_channels()
        && test_ring()
        && test_guard()
        && test_ctest();
    if !ok {
        println!("ltest: FAILED");
        return 1;
    }
    bench();
    println!("ltest: PASSED");
    0
}
