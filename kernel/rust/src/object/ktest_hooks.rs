//! Object-layer hooks for the C-driven `bench` and `soak` test cases.

use core::sync::atomic::{AtomicPtr, Ordering};

use super::*;

static BENCH: AtomicPtr<Process> = AtomicPtr::new(core::ptr::null_mut());
static mut BENCH_EVENT: Handle = Handle::INVALID;

fn bench_proc() -> &'static Process {
    let p = BENCH.load(Ordering::Acquire);
    crate::kassert!(!p.is_null());
    // SAFETY: set once by rust_bench_objects_init from a leaked KRef (never freed).
    unsafe { &*p }
}

fn bench_event() -> Handle {
    // SAFETY: written once before any benchmark runs, only read afterwards.
    unsafe { BENCH_EVENT }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_bench_objects_init() {
    let p = Process::new(Some(kernel_process()), "bench", Limits::DEFAULT).expect("bench process");
    let ev = p.event_create().expect("bench event");
    // SAFETY: single-threaded setup, before any reader.
    unsafe { BENCH_EVENT = ev };
    BENCH.store(&*p as *const Process as *mut Process, Ordering::Release);
    core::mem::forget(p);
}

/// Handle lookup with a rights check (what every syscall starts with).
#[unsafe(no_mangle)]
pub extern "C" fn rust_bench_handle_lookup(_ctx: *mut core::ffi::c_void) {
    let r = bench_proc().get_event(bench_event(), Rights::WAIT);
    core::hint::black_box(r.is_ok());
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_bench_handle_dup_close(_ctx: *mut core::ffi::c_void) {
    let p = bench_proc();
    let h = p.handle_duplicate(bench_event(), Rights::WAIT).expect("dup");
    p.handle_close(h).expect("close");
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_bench_event_signal_wait(_ctx: *mut core::ffi::c_void) {
    let p = bench_proc();
    p.event_signal(bench_event(), 0, sig::SIGNALED).expect("signal");
    p.object_wait(bench_event(), sig::SIGNALED, 0).expect("wait");
    p.event_signal(bench_event(), sig::SIGNALED, 0).expect("clear");
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_bench_vmo_create_close(_ctx: *mut core::ffi::c_void) {
    let p = bench_proc();
    let h = p.vmo_create(4096).expect("vmo");
    p.handle_close(h).expect("close");
}

/// Live kernel objects of all types (soak leak check).
#[unsafe(no_mangle)]
pub extern "C" fn rust_objects_live() -> u64 {
    live_all().iter().sum()
}

/// Soak: random object traffic in a throwaway process tree; false on an unexpected error.
#[unsafe(no_mangle)]
pub extern "C" fn rust_soak_objects(seed: u64) -> bool {
    let mut s = seed | 1;
    let mut rnd = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let Ok(p) = Process::new(Some(kernel_process()), "soak", Limits::DEFAULT) else {
        return true; // out of memory is allowed; it is not a failure
    };
    let me = match p.add(Object::Process(p.clone()), default_rights(ObjType::Process)) {
        Ok(h) => h,
        Err(_) => {
            p.kill();
            return true;
        }
    };
    let mut hs = [Handle::INVALID; 16];
    let mut ok = true;
    for _ in 0..64 {
        let slot = (rnd() % 16) as usize;
        let r: KResult<()> = match rnd() % 8 {
            0 => p.event_create().map(|h| hs[slot] = h),
            1 => p.vmo_create((rnd() % 4 + 1) * 4096).map(|h| hs[slot] = h),
            2 => p.timer_create().and_then(|h| {
                hs[slot] = h;
                p.timer_set(h, rnd() % 200_000)
            }),
            3 => p.handle_duplicate(hs[(rnd() % 16) as usize], Rights::SAME).map(|h| hs[slot] = h),
            4 => p.handle_close(hs[slot]),
            5 => p.object_wait(hs[slot], sig::SIGNALED, rnd() % 100_000).map(drop),
            6 => p.process_create(me, "soak.child", Limits::DEFAULT).map(|(h, _)| hs[slot] = h),
            _ => p.thread_create(me, c"soak.obj", || 0).map(|h| hs[slot] = h),
        };
        // Errors from random handles (closed, wrong type, no WAIT on a VMO, timeouts) are expected;
        // anything else is a bug.
        if let Err(e) = r {
            ok &= matches!(
                e,
                Status::BadHandle
                    | Status::WrongType
                    | Status::TimedOut
                    | Status::NoMemory
                    | Status::NoResources
            );
        }
    }
    p.kill();
    ok
}
