//! The C side of the kernel, as seen from Rust. Hand-written: the surface is small and every
//! declaration mirrors a header in `kernel/include/` (named next to it). Keep both in sync;
//! layouts shared by value are checked by size assertions on both sides.

use core::ffi::{CStr, c_char, c_int, c_void};

/// `spinlock_t` (spinlock.h).
#[repr(C)]
pub struct RawSpinlock {
    pub locked: u32,
    pub owner: u32,
    pub rank: u32,
    pub reserved: u32,
    pub name: *const c_char,
}
const _: () = assert!(core::mem::size_of::<RawSpinlock>() == 24);

impl RawSpinlock {
    /// `SPINLOCK_INIT(name, rank)`.
    pub const fn new(name: &'static CStr, rank: u32) -> Self {
        RawSpinlock {
            locked: 0,
            owner: 0,
            rank,
            reserved: 0,
            name: name.as_ptr(),
        }
    }
}

/// `struct waitq` (wait.h).
#[repr(C)]
pub struct RawWaitq {
    pub lock: RawSpinlock,
    pub head: *mut c_void,
    pub tail: *mut c_void,
}
const _: () = assert!(core::mem::size_of::<RawWaitq>() == 40);

impl RawWaitq {
    /// `WAITQ_INIT(name)`.
    pub const fn new(name: &'static CStr) -> Self {
        RawWaitq {
            lock: RawSpinlock::new(name, rank::WAITQ),
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        }
    }
}

/// `struct kmutex` (wait.h).
#[repr(C)]
pub struct RawMutex {
    pub wq: RawWaitq,
    pub owner: *mut c_void,
}
const _: () = assert!(core::mem::size_of::<RawMutex>() == 48);

/// `struct ksem` (wait.h).
#[repr(C)]
pub struct RawSem {
    pub wq: RawWaitq,
    pub count: i64,
}
const _: () = assert!(core::mem::size_of::<RawSem>() == 48);

/// `struct kevent` (wait.h).
#[repr(C)]
pub struct RawEvent {
    pub wq: RawWaitq,
    pub signaled: u32,
    pub auto_reset: u32,
}
const _: () = assert!(core::mem::size_of::<RawEvent>() == 48);

/// `struct thread` (thread.h): opaque, only handled by pointer.
#[repr(C)]
pub struct RawThread {
    _opaque: [u8; 0],
}

pub type ThreadFn = extern "C" fn(arg: *mut c_void) -> c_int;

/// `struct ktimer` (ktime.h).
#[repr(C)]
pub struct RawKtimer {
    pub next: *mut c_void,
    pub deadline_ns: u64,
    pub period_ns: u64,
    pub f: Option<KtimerFn>,
    pub ctx: *mut c_void,
    pub base: *mut c_void,
    pub pending: bool,
    pub queued: bool,
}
const _: () = assert!(core::mem::size_of::<RawKtimer>() == 56);

impl Default for RawKtimer {
    fn default() -> Self {
        Self::new()
    }
}

impl RawKtimer {
    pub const fn new() -> Self {
        RawKtimer {
            next: core::ptr::null_mut(),
            deadline_ns: 0,
            period_ns: 0,
            f: None,
            ctx: core::ptr::null_mut(),
            base: core::ptr::null_mut(),
            pending: false,
            queued: false,
        }
    }
}

pub type KtimerFn = extern "C" fn(t: *mut RawKtimer, ctx: *mut c_void);

unsafe extern "C" {
    // bootinfo.h: the wall-clock time the UEFI loader captured (32-byte record), if any
    pub fn boot_time_record(out: *mut u8) -> bool;

    // spinlock.h
    pub fn spin_lock_irqsave(l: *mut RawSpinlock) -> u64;
    pub fn spin_unlock_irqrestore(l: *mut RawSpinlock, flags: u64);
    pub fn spin_trylock_irqsave(l: *mut RawSpinlock, flags: *mut u64) -> bool;

    // wait.h
    pub fn waitq_wait(wq: *mut RawWaitq, flags: u64, deadline_ns: u64) -> c_int;
    pub fn waitq_wake_all(wq: *mut RawWaitq) -> u32;
    pub fn waitq_wake_all_sync(wq: *mut RawWaitq) -> u32;
    pub fn kmutex_lock(m: *mut RawMutex);
    pub fn kmutex_trylock(m: *mut RawMutex) -> bool;
    pub fn kmutex_unlock(m: *mut RawMutex);
    pub fn ksem_down_timeout(s: *mut RawSem, timeout_ns: u64) -> bool;
    pub fn ksem_up(s: *mut RawSem);
    pub fn kevent_wait(e: *mut RawEvent, timeout_ns: u64) -> bool;
    pub fn kevent_signal(e: *mut RawEvent);
    pub fn kevent_reset(e: *mut RawEvent);

    // thread.h
    pub fn thread_create(
        name: *const c_char,
        f: ThreadFn,
        arg: *mut c_void,
        prio: u32,
    ) -> *mut RawThread;
    pub fn thread_join(t: *mut RawThread) -> c_int;
    pub fn thread_detach(t: *mut RawThread);
    pub fn thread_yield();
    pub fn thread_sleep_ns(ns: u64);

    // console.h
    pub fn console_lock() -> u64;
    pub fn console_unlock(flags: u64);
    pub fn console_write_locked(s: *const u8, n: usize);
    pub fn console_display(out: *mut ConsoleDisplay) -> bool;
    pub fn console_release_screen();

    // mm.h
    pub fn kmalloc(size: usize) -> *mut u8;
    pub fn kfree(p: *mut u8);
    pub fn pmm_alloc_zeroed() -> u64;
    pub fn pmm_alloc_contig_zeroed(frames: u64) -> u64;
    pub fn pmm_free(pa: u64);
    pub fn pmm_free_frames() -> u64;
    pub fn heap_live_allocs() -> u64;

    // cpu.h
    pub fn cpu_random64() -> u64;

    // ktime.h (timers)
    pub fn timer_start_oneshot(t: *mut RawKtimer, delay_ns: u64, f: KtimerFn, ctx: *mut c_void);
    pub fn timer_cancel_sync(t: *mut RawKtimer) -> bool;

    // panic.h
    pub fn panic_in_progress() -> bool;
    pub fn rust_panic(
        file: *const u8,
        file_len: usize,
        line: u32,
        msg: *const u8,
        msg_len: usize,
    ) -> !;

    // ktime.h
    pub fn time_ns() -> u64;

    // mm.h (user address spaces)
    pub fn uspace_create() -> *mut RawUspace;
    pub fn uspace_destroy(a: *mut RawUspace);
    pub fn uspace_free_tables(a: *mut RawUspace) -> u64;
    pub fn uspace_map(
        a: *mut RawUspace,
        va: u64,
        frames: *const u64,
        pages: u64,
        flags: u32,
        new_tables: *mut u64,
    ) -> bool;
    pub fn uspace_unmap(a: *mut RawUspace, va: u64, pages: u64);
    pub fn uspace_translate(a: *mut RawUspace, va: u64) -> u64;
    pub fn uspace_tables_needed(va: u64, pages: u64) -> u64;

    // thread.h (user threads)
    pub fn thread_create_user(
        name: *const c_char,
        f: ThreadFn,
        arg: *mut c_void,
        a: *mut RawUspace,
        user: *mut c_void,
        ussp: u64,
    ) -> *mut RawThread;
    pub fn user_enter(rip: u64, rsp: u64, arg0: u64, arg1: u64) -> !;
    pub fn user_enter_frame(f: *const crate::user::syscall::Frame) -> !;
    pub fn uthread_exit(code: c_int) -> !;
    pub fn thread_kill(t: *mut RawThread);
    pub fn thread_wait_intr_begin(wq: *mut RawWaitq) -> bool;
    pub fn thread_wait_intr_end();
    pub fn thread_user_state() -> *mut c_void;
    pub fn thread_current() -> *mut RawThread;
    pub fn thread_tid_of(t: *mut RawThread) -> u32;
    pub fn thread_kill_pending() -> bool;
    pub fn uthread_get_base(which: u32) -> u64;
    pub fn uthread_set_base(which: u32, value: u64);
    pub fn uthread_get_ssp() -> u64;
    pub fn uthread_set_ssp(ssp: u64);
    /// CET shadow stacks in use (cet.h); user shadow stacks are available exactly then.
    pub static cet_ss: bool;

    // user.h
    pub fn user_copy(dst: *mut u8, src: *const u8, n: u64) -> u64;

    // profile.h: latency histograms (recorded only while the profiler is on)
    pub static profile_active: u32;
    pub static mut lat_syscall: RawLatHist;
    pub fn lat_record(h: *mut RawLatHist, ns: u64);

    // ktest.c: called by init's watcher once init has exited (test builds)
    #[cfg(ktest)]
    pub fn ktest_after_init(code: c_int);

    // Device framework: acpi.h, mm.h, arch.h, apic.h
    pub fn acpi_find_table(sig: *const u8, len: *mut u32) -> *const u8;
    pub fn acpi_find_table_nth(sig: *const u8, n: u32, len: *mut u32) -> *const u8;
    pub fn acpi_table_at(phys: u64, len: *mut u32) -> *const u8;
    pub fn acpi_mmio_map(pa: u64, len: u32) -> *mut u8;
    pub fn ioapic_route_sci(irq: u8, vector: u8) -> bool;
    pub fn power_set_s5(typ_a: u8, typ_b: u8);
    /// `struct cpupm_desc` (dev/cpupm.rs) or NULL; copied before it returns (cpupm.h).
    pub fn cpupm_configure(d: *const c_void);
    pub fn vmm_map_phys(pa: u64, size: u64, flags: u32) -> *mut u8;
    pub fn pmm_range_is_ram(pa: u64, len: u64) -> bool;
    pub fn irq_vector_alloc() -> c_int;
    pub fn irq_vector_free(vector: c_int);
    pub fn ioapic_route_isa_irq(irq: u8, vector: u8) -> bool;
    pub fn ioapic_mask_isa_irq(irq: u8);
    pub fn irq_target_apic() -> u32;
    pub fn ioapic_reroute();
    pub fn ioapic_ids(out: *mut u8, max: u32) -> u32;
    pub fn ioapic_routed(id: u8, out: *mut u16, max: u32) -> u32;
    pub fn lapic_x2apic() -> bool;

    // console / kernel image (programs embedded by build.ps1, programs.asm)
    pub static user_program_table: [RawProgram; 0];
    pub static user_program_count: u64;
}

/// `struct lat_hist` (profile.h): only handled by pointer.
#[repr(C)]
pub struct RawLatHist {
    _opaque: [u8; 0],
}

/// The profiler is on (profile.h `profile_active`): latency histograms record.
pub fn profiling() -> bool {
    // SAFETY: a plain u32 the C side flips atomically; a stale read only skips or adds a sample.
    unsafe { core::ptr::read_volatile(&raw const profile_active) != 0 }
}

/// `struct uspace` (mm.h): only handled by pointer; `tables` is read for quota accounting.
#[repr(C)]
pub struct RawUspace {
    pub lock: RawSpinlock,
    pub pml4: u64,
    pub tables: u64,
    pub cpus: u64,
    pub upml4: u64,
    pub id: u64,
}

/// One embedded user program (programs.asm, generated by build.ps1).
#[repr(C)]
pub struct RawProgram {
    pub name: *const c_char,
    pub data: *const u8,
    pub len: u64,
}

/// `struct console_display` (console.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ConsoleDisplay {
    pub base: u64,
    pub size: u64,
    pub kind: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
    pub reserved: [u8; 5],
}
const _: () = assert!(core::mem::size_of::<ConsoleDisplay>() == 40);

/// `USER_BASE` / `USER_TOP` (mm.h).
pub const USER_BASE: u64 = 0x20_0000;
pub const USER_TOP: u64 = 0x0000_7FFF_FFFF_0000;
/// `VMM_W` / `VMM_X` (mm.h).
pub const VMM_W: u32 = 1 << 0;
pub const VMM_X: u32 = 1 << 1;
pub const VMM_UC: u32 = 1 << 2;
pub const VMM_WC: u32 = 1 << 3;
pub const VMM_SHSTK: u32 = 1 << 4;
/// `WAIT_INTERRUPTED` (thread.h).
pub const WAIT_INTERRUPTED: c_int = 2;
/// `UTHREAD_EXIT_KILLED`, `DOS_EXIT_*` (user.h).
pub const UTHREAD_EXIT_KILLED: c_int = i32::MIN;
pub const EXIT_KILLED: i32 = 0x8000_0001_u32 as i32;
pub const EXIT_FAULT: i32 = 0x8000_0002_u32 as i32;

/// Kernel log levels (klog.h).
pub const KLOG_ERROR: c_int = 0;
pub const KLOG_WARN: c_int = 1;
pub const KLOG_INFO: c_int = 2;
pub const KLOG_DEBUG: c_int = 3;

/// `WAIT_FOREVER`, `WAIT_OK` (thread.h).
pub const WAIT_FOREVER: u64 = u64::MAX;
pub const WAIT_OK: c_int = 0;

unsafe extern "C" {
    /// `kernel_layout` (mm.h); only its first field, the direct map's base, is read here.
    static kernel_layout: u64;
}

/// `PHYSMAP_BASE` (mm.h): physical memory is reachable at physmap_base() + pa. The base is chosen
/// at boot (KASLR, kernel/mm/kaslr.c) before any Rust code runs and is read-only afterwards.
#[inline]
pub fn physmap_base() -> u64 {
    // SAFETY: written once by kaslr_init before the VMM is active (no Rust runs before), then
    // mapped read-only; a plain read of an initialized u64.
    unsafe { core::ptr::read(&raw const kernel_layout) }
}

/// Fault injection (fault.h, test builds only): make the `nth` matching allocation of the calling
/// thread fail.
#[cfg(ktest)]
pub mod fault {
    pub const KMALLOC: u32 = 1 << 0;
    pub const PMM: u32 = 1 << 1;
    pub const ALL: u32 = KMALLOC | PMM;
    unsafe extern "C" {
        pub fn fault_inject_arm(kinds: u32, nth: u64);
        /// Disarm; true if the injected failure happened.
        pub fn fault_inject_disarm() -> bool;
    }
}

// Test-only kernel actions requested from user mode (ktest.c): prove SMAP and SMEP fire.
#[cfg(ktest)]
unsafe extern "C" {
    pub fn ktest_user_smap(user_ptr: u64);
    pub fn ktest_user_smep(user_ptr: u64);
}

// Power control (power.h).
unsafe extern "C" {
    pub fn power_off_supported() -> bool;
    pub fn power_off();
    pub fn power_reboot() -> !;
}

/// Lock ranks (spinlock.h `LOCK_RANK_*`).
pub mod rank {
    pub const TEST: u32 = 5;
    /// The registry of live channel ends (`LOCK_RANK_CHANNELS`): channel queue locks nest inside it.
    pub const CHANNELS: u32 = 6;
    pub const OBJECT: u32 = 8;
    /// Process thread lists: taken alone, then thread/wait-queue locks under it.
    pub const PROC_THREADS: u32 = 9;
    /// A port's rings (`LOCK_RANK_PORT`): taken from signal callbacks, under no wait-queue lock.
    pub const PORT: u32 = 33;
    /// A device's state (`LOCK_RANK_DEVICE`): may allocate and take the IOMMU and PCI locks.
    pub const DEVICE: u32 = 7;
    /// An IOMMU unit's tables and registers (`LOCK_RANK_IOMMU`): may take the PMM lock.
    pub const IOMMU: u32 = 25;
    /// Legacy PCI configuration ports 0xCF8/0xCFC (`LOCK_RANK_PCI`).
    pub const PCI: u32 = 26;
    pub const WAITQ: u32 = 35;
    pub const KLOG: u32 = 60;
}

/// Thread priorities (thread.h `THREAD_PRIO_*`).
pub mod prio {
    pub const LOW: u32 = 8;
    pub const NORMAL: u32 = 16;
    pub const HIGH: u32 = 24;
}

/// True once the kernel is panicking (locks become best effort).
pub fn panicking() -> bool {
    // SAFETY: reads a C flag; no preconditions.
    unsafe { panic_in_progress() }
}

/// Monotonic time since kernel entry, in nanoseconds (0 before TSC calibration).
pub fn now_ns() -> u64 {
    // SAFETY: pure read of the TSC and a calibration constant.
    unsafe { time_ns() }
}
