//! ACPI in the kernel: the AML namespace, the SCI and the power button (docs/acpi.md).
//!
//! The interpreter (`kernel/aml`) runs on one kernel thread, `acpi`, on a private 128 KiB stack
//! (heap pages with unmapped guard pages on both sides; the interpreter recurses and kernel
//! stacks are 16 KiB). The thread loads the DSDT and every SSDT, tells the firmware the interrupt
//! model (`\_PIC(1)`), runs `_REG`, `_STA` and `_INI`, hands `\_S5` to the power code, and then
//! serves:
//!
//! - the SCI: the interrupt handler only masks what fired (PM1 fixed events, GPEs) and wakes the
//!   thread, which runs the `_Lxx`/`_Exx` methods, handles the fixed power button and re-enables
//!   (a GPE that fires more than `STORM` times a second stays off: a storm cannot take a CPU);
//! - `Notify(<power button>, 0x80)` and the fixed power button: signal the power-button event
//!   init holds (startup tag POWER_BUTTON), which shuts down cleanly;
//! - `dkrnl_acpi_prepare_sleep`: `\_TTS` and `\_PTS` before power-off.
//!
//! Firmware code runs in ring 0, so the hardware handler limits it: no SystemMemory access to
//! usable RAM (only MMIO, reserved and ACPI NVS ranges), the I/O ports of the PIC, PIT, DMA
//! controllers, RTC/CMOS and PCI configuration mechanism are ignored (ACPICA's list, as on
//! Windows), PCI configuration only through the kernel's own accessors, and every evaluation has
//! the interpreter's budgets.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use aml::{Handler, Interpreter, Object, Refused};

use crate::dev::pci;
use crate::ffi;
use crate::kprintln;
use crate::object::KRef;
use crate::object::event::EventObj;
use crate::sync::Event;

const STACK: usize = 128 * 1024;
/// Stack kept free below the deepest AML frame: interrupts and the kernel calls the handler makes.
const STACK_RESERVE: u64 = 16 * 1024;
/// A GPE firing more often than this in one second stays disabled.
const STORM: u32 = 200;

static STACK_LO: AtomicU64 = AtomicU64::new(0);
static STACK_MIN_LEFT: AtomicU64 = AtomicU64::new(u64::MAX);

static READY: Event = Event::new(c"acpi.ready", false);
static WORK: Event = Event::new(c"acpi.work", true);
static DONE: Event = Event::new(c"acpi.done", true);
static LOADED: AtomicBool = AtomicBool::new(false);
static SLEEP_REQ: AtomicU32 = AtomicU32::new(0);
/// TPM start requests (`tpm_start`): 1 = asked, then the answer: 2 done, 3 refused.
static TPM_REQ: AtomicU32 = AtomicU32::new(0);
static TPM_DONE: Event = Event::new(c"acpi.tpm", true);

/// The SCI's registers (I/O ports), set before the SCI is routed.
static SCI_VECTOR: AtomicU32 = AtomicU32::new(0);
static PM1: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2]; // event block port | half-length << 16
static GPE: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2]; // block port | half-length << 16 | base << 24
static PENDING_PM1: AtomicU32 = AtomicU32::new(0);
static PENDING_GPE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static SCI_COUNT: AtomicU64 = AtomicU64::new(0);

static POWER_BUTTON: AtomicPtr<KRef<EventObj>> = AtomicPtr::new(core::ptr::null_mut());

const PWRBTN: u32 = 1 << 8;

// FADT offsets (ACPI 6.5, table 5.9).
const F_FIRMWARE_CTRL: usize = 36;
const F_DSDT: usize = 40;
const F_SCI_INT: usize = 46;
const F_PM1A_EVT: usize = 56;
const F_PM1B_EVT: usize = 60;
const F_PM1A_CNT: usize = 64;
const F_GPE0: usize = 80;
const F_GPE1: usize = 84;
const F_PM1_EVT_LEN: usize = 88;
const F_GPE0_LEN: usize = 92;
const F_GPE1_LEN: usize = 93;
const F_GPE1_BASE: usize = 94;
const F_FLAGS: usize = 112;
const F_X_FIRMWARE_CTRL: usize = 132;
const F_X_DSDT: usize = 140;
const FLAG_PWR_BUTTON: u32 = 1 << 4; // set: the power button is a control-method device
const FLAG_HW_REDUCED: u32 = 1 << 20;

fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: port I/O on a port the caller checked; no memory is touched.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags)) }
    v
}

fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: as in `inb`.
    unsafe { core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nostack, preserves_flags)) }
    v
}

fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: as in `inb`.
    unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nostack, preserves_flags)) }
    v
}

fn outb(port: u16, v: u8) {
    // SAFETY: as in `inb`.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nostack, preserves_flags)) }
}

fn outw(port: u16, v: u16) {
    // SAFETY: as in `inb`.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nostack, preserves_flags)) }
}

fn outl(port: u16, v: u32) {
    // SAFETY: as in `inb`.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nostack, preserves_flags)) }
}

/// I/O ports AML may not touch (ACPICA's protected ranges; Windows refuses the same): the
/// kernel and its drivers own these devices. Accesses are dropped (reads give 0), not failed.
const PROTECTED: &[(u16, u16)] = &[
    (0x0000, 0x000F), // DMA controller 1
    (0x0020, 0x0021), // PIC 1
    (0x0040, 0x0043), // PIT 1
    (0x0048, 0x004B), // PIT 2
    (0x0070, 0x0071), // RTC / CMOS (the clock service)
    (0x0074, 0x0076), // extended CMOS
    (0x0081, 0x0083), // DMA page registers
    (0x0087, 0x0087),
    (0x0089, 0x008B),
    (0x008F, 0x008F),
    (0x0090, 0x0091), // arbitration control
    (0x0093, 0x0094),
    (0x0096, 0x0097),
    (0x00A0, 0x00A1), // PIC 2
    (0x00C0, 0x00DF), // DMA controller 2
    (0x04D0, 0x04D1), // ELCR (interrupt trigger modes)
    (0x0CF8, 0x0CFF), // PCI configuration mechanism (AML uses PCI_Config regions instead)
];

fn protected(port: u16, width: u8) -> bool {
    let end = u32::from(port) + u32::from(width) - 1;
    PROTECTED.iter().any(|&(lo, hi)| u32::from(port) <= u32::from(hi) && end >= u32::from(lo))
}

fn stack_pointer() -> u64 {
    let sp: u64;
    // SAFETY: reads RSP.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags)) }
    sp
}

struct Kernel {
    notifies: Vec<(String, u64)>,
    warned: u32,
    facs: u64,
    pm1a_cnt: u16,
    debug_lines: u32,
}

impl Kernel {
    fn warn(&mut self, what: core::fmt::Arguments<'_>) {
        if self.warned < 16 {
            self.warned += 1;
            kprintln!("ACPI: AML {}", what);
        }
    }

    fn lock_word(&self) -> Option<&'static AtomicU32> {
        if self.facs == 0 {
            return None;
        }
        // SAFETY: the FACS global lock dword (offset 16), mapped uncached outside usable RAM by
        // acpi_mmio_map; firmware updates it only with locked instructions, as we do.
        let p = unsafe { ffi::acpi_mmio_map(self.facs + 16, 4) };
        if p.is_null() || !(p as usize).is_multiple_of(4) {
            return None;
        }
        // SAFETY: as above; the mapping stays (the direct map is never torn down).
        Some(unsafe { &*(p as *const AtomicU32) })
    }
}

impl Handler for Kernel {
    fn read_io(&mut self, port: u16, width: u8) -> Result<u64, Refused> {
        if u32::from(port) + u32::from(width) > 0x1_0000 {
            return Err(Refused);
        }
        if protected(port, width) {
            self.warn(format_args!("read of protected port {:#x} ignored", port));
            return Ok(0);
        }
        Ok(match width {
            1 => u64::from(inb(port)),
            2 => u64::from(inw(port)),
            4 => u64::from(inl(port)),
            _ => return Err(Refused),
        })
    }

    fn write_io(&mut self, port: u16, width: u8, value: u64) -> Result<(), Refused> {
        if u32::from(port) + u32::from(width) > 0x1_0000 {
            return Err(Refused);
        }
        if protected(port, width) {
            self.warn(format_args!("write of protected port {:#x} ignored", port));
            return Ok(());
        }
        match width {
            1 => outb(port, value as u8),
            2 => outw(port, value as u16),
            4 => outl(port, value as u32),
            _ => return Err(Refused),
        }
        Ok(())
    }

    fn read_mem(&mut self, addr: u64, width: u8) -> Result<u64, Refused> {
        if !addr.is_multiple_of(u64::from(width)) {
            return Err(Refused);
        }
        // SAFETY: acpi_mmio_map refuses usable RAM and addresses outside the direct map.
        let p = unsafe { ffi::acpi_mmio_map(addr, u32::from(width)) };
        if p.is_null() {
            self.warn(format_args!("read of memory {:#x} refused (RAM or out of range)", addr));
            return Err(Refused);
        }
        // SAFETY: an aligned access to the uncached mapping just made for `width` bytes.
        unsafe {
            Ok(match width {
                1 => u64::from(core::ptr::read_volatile(p)),
                2 => u64::from(core::ptr::read_volatile(p as *const u16)),
                4 => u64::from(core::ptr::read_volatile(p as *const u32)),
                _ => core::ptr::read_volatile(p as *const u64),
            })
        }
    }

    fn write_mem(&mut self, addr: u64, width: u8, value: u64) -> Result<(), Refused> {
        if !addr.is_multiple_of(u64::from(width)) {
            return Err(Refused);
        }
        // SAFETY: as in `read_mem`.
        let p = unsafe { ffi::acpi_mmio_map(addr, u32::from(width)) };
        if p.is_null() {
            self.warn(format_args!("write of memory {:#x} refused (RAM or out of range)", addr));
            return Err(Refused);
        }
        // SAFETY: as in `read_mem`.
        unsafe {
            match width {
                1 => core::ptr::write_volatile(p, value as u8),
                2 => core::ptr::write_volatile(p as *mut u16, value as u16),
                4 => core::ptr::write_volatile(p as *mut u32, value as u32),
                _ => core::ptr::write_volatile(p as *mut u64, value),
            }
        }
        Ok(())
    }

    fn read_pci(&mut self, a: (u16, u8, u8, u8), offset: u16, width: u8) -> Result<u64, Refused> {
        if a.0 != 0 || !matches!(width, 1 | 2 | 4) || !offset.is_multiple_of(u16::from(width)) || offset + u16::from(width) > pci::config_size() {
            return Err(Refused);
        }
        Ok(u64::from(pci::read(pci::Bdf::new(a.1, a.2, a.3), offset, width)))
    }

    fn write_pci(&mut self, a: (u16, u8, u8, u8), offset: u16, width: u8, value: u64) -> Result<(), Refused> {
        if a.0 != 0 || !matches!(width, 1 | 2 | 4) || !offset.is_multiple_of(u16::from(width)) || offset + u16::from(width) > pci::config_size() {
            return Err(Refused);
        }
        pci::write(pci::Bdf::new(a.1, a.2, a.3), offset, width, value as u32);
        Ok(())
    }

    fn stall_us(&mut self, us: u64) {
        let end = ffi::now_ns().saturating_add(us.saturating_mul(1000));
        while ffi::now_ns() < end {
            core::hint::spin_loop();
        }
    }

    fn sleep_ms(&mut self, ms: u64) {
        // SAFETY: plain call from a kernel thread.
        unsafe { ffi::thread_sleep_ns(ms.saturating_mul(1_000_000)) }
    }

    fn timer(&mut self) -> u64 {
        ffi::now_ns() / 100
    }

    fn notify(&mut self, path: &str, value: u64) {
        if self.notifies.len() < 64 {
            self.notifies.push((String::from(path), value));
        }
    }

    fn debug(&mut self, text: &str) {
        if self.debug_lines < 32 {
            self.debug_lines += 1;
            kprintln!("ACPI: AML debug: {}", text);
        }
    }

    fn acquire_global_lock(&mut self) -> bool {
        let Some(lock) = self.lock_word() else { return true };
        for _ in 0..1000 {
            let mut old = lock.load(Ordering::Acquire);
            let new = loop {
                // Owned (bit 1) set; pending (bit 0) set too if it was owned already.
                let new = ((old & !1) | 2) + ((old >> 1) & 1);
                match lock.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => break new,
                    Err(x) => old = x,
                }
            };
            if new < 3 {
                return true;
            }
            self.sleep_ms(1);
        }
        self.warn(format_args!("global lock not acquired in 1 s"));
        false
    }

    fn release_global_lock(&mut self) {
        let Some(lock) = self.lock_word() else { return };
        let mut old = lock.load(Ordering::Acquire);
        while let Err(x) = lock.compare_exchange(old, old & !3, Ordering::AcqRel, Ordering::Acquire) {
            old = x;
        }
        if old & 1 != 0 && self.pm1a_cnt != 0 {
            // The firmware waits for it: GBL_RLS in PM1 control.
            outw(self.pm1a_cnt, inw(self.pm1a_cnt) | 1 << 2);
        }
    }

    fn stack_ok(&mut self) -> bool {
        let lo = STACK_LO.load(Ordering::Relaxed);
        let sp = stack_pointer();
        if lo == 0 || sp < lo || sp > lo + STACK as u64 {
            return false; // not on the AML stack: refuse to nest
        }
        let left = sp - lo;
        STACK_MIN_LEFT.fetch_min(left, Ordering::Relaxed);
        left > STACK_RESERVE
    }
}

fn rd<const N: usize>(t: &[u8], off: usize) -> u64 {
    t.get(off..off + N).map_or(0, |b| b.iter().rev().fold(0u64, |v, &x| v << 8 | u64::from(x)))
}

/// A table by signature as a byte slice (validated by the C side: mapped, length-bounded,
/// checksummed).
fn table(sig: &[u8; 4], n: u32) -> Option<&'static [u8]> {
    let mut len = 0u32;
    // SAFETY: valid signature pointer and out-parameter.
    let p = unsafe { ffi::acpi_find_table_nth(sig.as_ptr(), n, &mut len) };
    // SAFETY: the C side mapped `len` bytes read-only for the kernel's lifetime.
    (!p.is_null() && len >= 36).then(|| unsafe { core::slice::from_raw_parts(p, len as usize) })
}

fn table_at(phys: u64) -> Option<&'static [u8]> {
    let mut len = 0u32;
    // SAFETY: as in `table`.
    let p = unsafe { ffi::acpi_table_at(phys, &mut len) };
    // SAFETY: as in `table`.
    (!p.is_null() && len >= 36).then(|| unsafe { core::slice::from_raw_parts(p, len as usize) })
}

/// The power-button event init gets (startup tag POWER_BUTTON); created on first use.
pub fn power_button_event() -> Option<KRef<EventObj>> {
    let p = POWER_BUTTON.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: set once from a leaked box that is never freed.
    Some(unsafe { &*p }.clone())
}

fn power_button_pressed(how: &str) {
    kprintln!("ACPI: power button pressed ({})", how);
    if let Some(e) = power_button_event() {
        e.signals.update(0, crate::object::sig::SIGNALED);
    }
}

/// Start the ACPI thread and wait (bounded) until the namespace is loaded and initialised.
pub fn init() {
    if let Ok(e) = EventObj::create() {
        POWER_BUTTON.store(alloc::boxed::Box::into_raw(alloc::boxed::Box::new(e)), Ordering::Release);
    }
    let started = crate::thread::spawn(c"acpi", ffi::prio::HIGH, || {
        // A guarded private stack (large heap allocations sit between unmapped pages).
        let layout = core::alloc::Layout::from_size_align(STACK, 4096).expect("stack layout");
        // SAFETY: non-zero size; freed never (the thread runs for ever).
        let lo = unsafe { alloc::alloc::alloc(layout) } as u64;
        if lo == 0 {
            kprintln!("ACPI: no memory for the AML stack; AML not loaded");
            READY.signal();
            return 1;
        }
        STACK_LO.store(lo, Ordering::Release);
        let top = (lo + STACK as u64) & !15;
        // SAFETY: switches to the new stack (16-byte aligned top) and calls the worker, which
        // never returns; r12 (callee-saved) keeps the old stack pointer in case it ever did.
        unsafe {
            core::arch::asm!(
                "mov r12, rsp",
                "mov rsp, {top}",
                "call {f}",
                "mov rsp, r12",
                top = in(reg) top,
                f = sym worker,
                out("r12") _,
                clobber_abi("C"),
            );
        }
        0
    });
    if started.is_none() {
        kprintln!("ACPI: cannot start the ACPI thread; AML not loaded");
        return;
    }
    if !READY.wait_timeout(20_000_000_000) {
        kprintln!("ACPI: AML initialisation still running after 20 s; boot goes on");
    }
}

/// `dkrnl_acpi_prepare_sleep`: `\_TTS(state)`, `\_PTS(state)` on the ACPI thread (bounded wait).
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_acpi_prepare_sleep(state: u32) {
    let rflags: u64;
    // SAFETY: reads RFLAGS.
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) rflags) };
    if !LOADED.load(Ordering::Acquire) || ffi::panicking() || rflags & (1 << 9) == 0 {
        return; // not loaded, or a context that must not block (panic, kdb)
    }
    SLEEP_REQ.store(state.min(5) + 1, Ordering::Release);
    WORK.signal();
    if !DONE.wait_timeout(3_000_000_000) {
        kprintln!("ACPI: \\_PTS({}) did not finish in 3 s", state);
    }
}

/// Start the command in the TPM's CRB buffer the ACPI way (TPM2 table start method 2 or 8): the
/// TPM device's `_DSM` (UUID 6BBF6CAB-5463-4714-B7CD-F0203C0368D4, revision 1, function 1), run
/// on the ACPI thread. Returns when the method has returned (it waits for the firmware TPM).
/// Callers are serialised by the measurement lock, the TPM's only user.
pub fn tpm_start() -> Result<(), &'static str> {
    if !LOADED.load(Ordering::Acquire) {
        return Err("AML not loaded");
    }
    TPM_REQ.store(1, Ordering::Release);
    WORK.signal();
    if !TPM_DONE.wait_timeout(10_000_000_000) {
        return Err("TPM start method did not return in 10 s");
    }
    match TPM_REQ.swap(0, Ordering::AcqRel) {
        2 => Ok(()),
        _ => Err("TPM start method failed"),
    }
}

/// The TPM start `_DSM` UUID in its ACPI buffer form (the first three fields little-endian).
const TPM_START_UUID: [u8; 16] = [0xAB, 0x6C, 0xBF, 0x6B, 0x63, 0x54, 0x14, 0x47, 0xB7, 0xCD, 0xF0, 0x20, 0x3C, 0x03, 0x68, 0xD4];

/// Called from `dkrnl_dev_irq` for every device vector: true if it was the SCI.
pub fn sci_irq(vector: u32) -> bool {
    let v = SCI_VECTOR.load(Ordering::Acquire);
    if v == 0 || v != vector {
        return false;
    }
    SCI_COUNT.fetch_add(1, Ordering::Relaxed);
    // Mask whatever fired (level-triggered sources would fire again at once); the thread acts and
    // re-enables.
    for blk in &PM1 {
        let b = blk.load(Ordering::Relaxed);
        if b == 0 {
            continue;
        }
        let (port, half) = ((b & 0xFFFF) as u16, (b >> 16) as u16);
        let sts = u32::from(inw(port));
        let en = u32::from(inw(port + half));
        let p = sts & en;
        if p != 0 {
            outw(port + half, (en & !p) as u16);
            PENDING_PM1.fetch_or(p, Ordering::AcqRel);
        }
    }
    for blk in &GPE {
        let b = blk.load(Ordering::Relaxed);
        if b == 0 {
            continue;
        }
        let (port, half, base) = ((b & 0xFFFF) as u16, ((b >> 16) & 0xFF) as u16, (b >> 24) as usize);
        for i in 0..half {
            let sts = inb(port + i);
            let en = inb(port + half + i);
            let p = sts & en;
            if p != 0 {
                outb(port + half + i, en & !p);
                let gpe = base + usize::from(i) * 8;
                for bit in 0..8 {
                    if p & (1 << bit) != 0 {
                        let n = gpe + bit;
                        PENDING_GPE[(n / 64) & 3].fetch_or(1 << (n % 64), Ordering::AcqRel);
                    }
                }
            }
        }
    }
    WORK.signal();
    true
}

struct Gpe {
    port: u16,
    half: u16,
    base: usize,
}

struct State {
    aml: Interpreter<Kernel>,
    gpes: Vec<Gpe>,
    pm1: Vec<(u16, u16)>,
    /// Power-button devices (PNP0C0C) by path.
    buttons: Vec<String>,
    fixed_button: bool,
    /// Per-GPE: (events this second, disabled for good).
    counts: Vec<(u32, bool)>,
    window: u64,
    /// The TPM device's `_DSM` (MSFT0101), looked up on the first start request.
    tpm_dsm: Option<Option<aml::NodeId>>,
}

impl State {
    fn gpe_bits(&self, n: usize) -> Option<(u16, u8)> {
        for g in &self.gpes {
            let cnt = usize::from(g.half) * 8;
            if n >= g.base && n < g.base + cnt {
                let i = n - g.base;
                return Some((g.port + (i / 8) as u16, 1 << (i % 8)));
            }
        }
        None
    }

    fn gpe_method(&self, n: usize) -> Option<(aml::NodeId, bool)> {
        let gpe = self.aml.find("\\_GPE")?;
        let hex = |d: usize| b"0123456789ABCDEF"[d & 15] as char;
        for (c, edge) in [('L', false), ('E', true)] {
            let mut name = String::from("_");
            name.push(c);
            name.push(hex(n >> 4));
            name.push(hex(n));
            if let Some(m) = self.aml.child(gpe, &name) {
                return Some((m, edge));
            }
        }
        None
    }

    fn set_gpe_enable(&self, n: usize, on: bool) {
        let Some((sts_port, bit)) = self.gpe_bits(n) else { return };
        let g = self.gpes.iter().find(|g| sts_port >= g.port && sts_port < g.port + g.half);
        let Some(g) = g else { return };
        let en_port = sts_port + g.half;
        let v = inb(en_port);
        outb(en_port, if on { v | bit } else { v & !bit });
    }

    fn handle_notifies(&mut self) {
        let list = core::mem::take(&mut self.aml.handler().notifies);
        for (path, value) in list {
            if value == 0x80 && self.buttons.contains(&path) {
                power_button_pressed("control method");
            } else {
                kprintln!("ACPI: Notify({}, {:#x})", path, value);
            }
        }
    }

    fn run_gpe(&mut self, n: usize) {
        let now = ffi::now_ns();
        if now.saturating_sub(self.window) > 1_000_000_000 {
            self.window = now;
            for c in self.counts.iter_mut() {
                c.0 = 0;
            }
        }
        if n >= self.counts.len() || self.counts[n].1 {
            return;
        }
        self.counts[n].0 += 1;
        let Some((sts, bit)) = self.gpe_bits(n) else { return };
        let method = self.gpe_method(n);
        let edge = method.is_some_and(|m| m.1);
        if edge {
            outb(sts, bit);
        }
        if let Some((m, _)) = method
            && let Err(e) = self.aml.evaluate_node(m, Vec::new())
        {
            kprintln!("ACPI: GPE {:#x}: {}: {}", n, self.aml.path(m), e);
        }
        if !edge {
            outb(sts, bit);
        }
        self.handle_notifies();
        if self.counts[n].0 > STORM {
            self.counts[n].1 = true;
            kprintln!("ACPI: GPE {:#x} fired more than {} times in a second: left disabled", n, STORM);
        } else if method.is_some() {
            self.set_gpe_enable(n, true);
        }
    }

    fn run_pm1(&mut self, pending: u32) {
        for &(port, _) in &self.pm1 {
            outw(port, (pending & PWRBTN) as u16); // write 1 to clear
        }
        if pending & PWRBTN != 0 {
            power_button_pressed("fixed");
        }
        for &(port, half) in &self.pm1 {
            let en = inw(port + half);
            outw(port + half, en | (pending & PWRBTN) as u16);
        }
    }

    fn tpm_start(&mut self) -> bool {
        let dsm = *self.tpm_dsm.get_or_insert_with(|| {
            let dev = self.aml.find_devices(&["MSFT0101"]).into_iter().next()?;
            self.aml.child(dev, "_DSM")
        });
        let Some(dsm) = dsm else {
            kprintln!("ACPI: TPM start: no MSFT0101 device with a _DSM");
            return false;
        };
        let args = alloc::vec![Object::buffer(&TPM_START_UUID), Object::int(1), Object::int(1), Object::package(Vec::new())];
        let r = self.aml.evaluate_node(dsm, args);
        self.handle_notifies();
        match r {
            Ok(Object::Integer(0)) => true,
            Ok(o) => {
                kprintln!("ACPI: TPM start _DSM returned {}", o.type_name());
                false
            }
            Err(e) => {
                kprintln!("ACPI: TPM start _DSM: {}", e);
                false
            }
        }
    }

    fn prepare_sleep(&mut self, s: u32) {
        for name in ["\\_TTS", "\\_PTS"] {
            if self.aml.find(name).is_some()
                && let Err(e) = self.aml.evaluate(name, alloc::vec![Object::Integer(u64::from(s))])
            {
                kprintln!("ACPI: {}({}): {}", name, s, e);
            }
        }
        self.handle_notifies();
    }
}

/// GPE numbers named in `_PRW` (wake events): not enabled at run time.
fn wake_gpes(aml: &mut Interpreter<Kernel>) -> Vec<u64> {
    let mut out = Vec::new();
    let nodes = aml.namespace().walk(aml::ROOT);
    for n in nodes {
        if aml.namespace().node(n).name != *b"_PRW" {
            continue;
        }
        let Ok(Object::Package(p)) = aml.evaluate_node(n, Vec::new()) else { continue };
        let first = p.borrow().first().cloned();
        if let Some(Object::Integer(g)) = first {
            out.push(g);
        }
    }
    out
}

fn load(fadt: &[u8]) -> Interpreter<Kernel> {
    let facs = match rd::<8>(fadt, F_X_FIRMWARE_CTRL) {
        0 => rd::<4>(fadt, F_FIRMWARE_CTRL),
        x => x,
    };
    let k = Kernel { notifies: Vec::new(), warned: 0, facs, pm1a_cnt: rd::<4>(fadt, F_PM1A_CNT) as u16, debug_lines: 0 };
    let mut aml = Interpreter::new(k);
    let start = ffi::now_ns();
    let dsdt = match rd::<8>(fadt, F_X_DSDT) {
        0 => rd::<4>(fadt, F_DSDT),
        x => x,
    };
    let mut bytes = 0usize;
    let mut ssdts = 0u32;
    match table_at(dsdt) {
        Some(t) if t.starts_with(b"DSDT") => {
            bytes += t.len();
            if let Err(e) = aml.load_table(t) {
                kprintln!("ACPI: DSDT: {}", e);
            }
        }
        _ => kprintln!("ACPI: no DSDT"),
    }
    while let Some(t) = table(b"SSDT", ssdts) {
        bytes += t.len();
        ssdts += 1;
        if let Err(e) = aml.load_table(t) {
            kprintln!("ACPI: SSDT {}: {}", ssdts, e);
        }
    }
    let ms = (ffi::now_ns() - start) / 1_000_000;
    kprintln!(
        "ACPI: AML: DSDT + {} SSDT(s), {} KiB, {} objects in {} ms; {} definition(s) skipped",
        ssdts,
        bytes / 1024,
        aml.namespace().len(),
        ms,
        aml.stats.load_errors
    );
    for (p, e) in aml.stats.errors.drain(..).take(4) {
        kprintln!("ACPI:   {}: {}", p, e);
    }
    aml
}

extern "C" fn worker() {
    let Some(fadt) = table(b"FACP", 0) else {
        kprintln!("ACPI: no FADT; AML not loaded");
        READY.signal();
        idle();
    };
    let mut aml = load(fadt);

    // The interrupt model, then the firmware's own initialisation (ACPI 6.5, 5.8.1 and 6.5.1).
    if aml.find("\\_PIC").is_some()
        && let Err(e) = aml.evaluate("\\_PIC", alloc::vec![Object::Integer(1)])
    {
        kprintln!("ACPI: \\_PIC(1): {}", e);
    }
    let start = ffi::now_ns();
    let r = aml.initialize();
    kprintln!(
        "ACPI: AML: {} devices ({} present), {} _INI and {} _REG run, {} failed, {} ms",
        r.devices,
        r.present,
        r.inits,
        r.regs,
        r.failures,
        (ffi::now_ns() - start) / 1_000_000
    );
    for (p, e) in aml.stats.errors.drain(..).take(4) {
        kprintln!("ACPI:   {}: {}", p, e);
    }
    kprintln!("ACPI: AML stack: deepest use {} KiB of {} KiB", stats().1 / 1024, STACK / 1024);
    match aml.sleep_type(5) {
        // SAFETY: plain call.
        Some((a, b)) => unsafe { ffi::power_set_s5(a, b) },
        None => kprintln!("ACPI: no \\_S5 in the namespace"),
    }

    let flags = rd::<4>(fadt, F_FLAGS) as u32;
    let buttons: Vec<String> = aml.find_devices(&["PNP0C0C"]).into_iter().map(|n| aml.path(n)).collect();
    let mut st = State {
        aml,
        gpes: Vec::new(),
        pm1: Vec::new(),
        buttons,
        fixed_button: flags & FLAG_PWR_BUTTON == 0 && flags & FLAG_HW_REDUCED == 0,
        counts: Vec::new(),
        window: 0,
        tpm_dsm: None,
    };
    sci_setup(&mut st, fadt, flags);
    LOADED.store(true, Ordering::Release);
    READY.signal();
    serve(st);
}

fn idle() -> ! {
    loop {
        WORK.wait();
        if SLEEP_REQ.swap(0, Ordering::AcqRel) != 0 {
            DONE.signal();
        }
        if TPM_REQ.compare_exchange(1, 3, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            TPM_DONE.signal();
        }
    }
}

fn sci_setup(st: &mut State, fadt: &[u8], flags: u32) {
    let sci = rd::<2>(fadt, F_SCI_INT) as u8;
    if flags & FLAG_HW_REDUCED != 0 || sci == 0 {
        kprintln!("ACPI: no SCI (hardware-reduced ACPI): no power button or GPE events");
        return;
    }
    let evt_len = rd::<1>(fadt, F_PM1_EVT_LEN) as u16;
    for off in [F_PM1A_EVT, F_PM1B_EVT] {
        let port = rd::<4>(fadt, off);
        if port != 0 && port + u64::from(evt_len) <= 0x1_0000 && evt_len >= 4 {
            st.pm1.push((port as u16, evt_len / 2));
        }
    }
    let blocks = [(F_GPE0, F_GPE0_LEN, 0usize), (F_GPE1, F_GPE1_LEN, rd::<1>(fadt, F_GPE1_BASE) as usize)];
    for (off, loff, base) in blocks {
        let port = rd::<4>(fadt, off);
        let len = rd::<1>(fadt, loff) as u16;
        if port != 0 && len >= 2 && port + u64::from(len) <= 0x1_0000 {
            st.gpes.push(Gpe { port: port as u16, half: len / 2, base });
        }
    }
    let ngpe = st.gpes.iter().map(|g| g.base + usize::from(g.half) * 8).max().unwrap_or(0);
    st.counts = alloc::vec![(0, false); ngpe.min(256)];

    // Everything off and cleared, then: the fixed power button and the GPEs that have methods
    // and are not wake-only (`_PRW`).
    for &(port, half) in &st.pm1 {
        outw(port + half, 0);
        outw(port, 0xFFFF);
    }
    for g in &st.gpes {
        for i in 0..g.half {
            outb(g.port + g.half + i, 0);
            outb(g.port + i, 0xFF);
        }
    }
    let wake = wake_gpes(&mut st.aml);
    let mut enabled = 0;
    for n in 0..st.counts.len() {
        if st.gpe_method(n).is_some() && !wake.contains(&(n as u64)) {
            st.set_gpe_enable(n, true);
            enabled += 1;
        }
    }
    if st.fixed_button {
        for &(port, half) in &st.pm1 {
            outw(port + half, inw(port + half) | PWRBTN as u16);
        }
    }
    for (i, &(port, half)) in st.pm1.iter().take(2).enumerate() {
        PM1[i].store(u32::from(port) | u32::from(half) << 16, Ordering::Release);
    }
    for (i, g) in st.gpes.iter().take(2).enumerate() {
        GPE[i].store(u32::from(g.port) | u32::from(g.half) << 16 | (g.base as u32 & 0xFF) << 24, Ordering::Release);
    }
    // SAFETY: plain call; returns a free device vector or -1.
    let vector = unsafe { ffi::irq_vector_alloc() };
    // SAFETY: plain call; routes the SCI to the vector on the boot CPU.
    if vector < 0 || !unsafe { ffi::ioapic_route_sci(sci, vector as u8) } {
        kprintln!("ACPI: SCI (IRQ {}) could not be routed: no power button or GPE events", sci);
        return;
    }
    SCI_VECTOR.store(vector as u32, Ordering::Release);
    kprintln!(
        "ACPI: SCI on IRQ {}; power button: {}{}; {} GPE(s) enabled, {} wake-only",
        sci,
        if st.fixed_button { "fixed" } else { "control method" },
        if st.buttons.is_empty() { String::new() } else { alloc::format!(" ({})", st.buttons.join(", ")) },
        enabled,
        wake.len()
    );
}

fn serve(mut st: State) -> ! {
    loop {
        WORK.wait_timeout(1_000_000_000);
        let s = SLEEP_REQ.swap(0, Ordering::AcqRel);
        if s != 0 {
            st.prepare_sleep(s - 1);
            DONE.signal();
        }
        if TPM_REQ.load(Ordering::Acquire) == 1 {
            let ok = st.tpm_start();
            TPM_REQ.store(if ok { 2 } else { 3 }, Ordering::Release);
            TPM_DONE.signal();
        }
        let pm1 = PENDING_PM1.swap(0, Ordering::AcqRel);
        if pm1 != 0 {
            st.run_pm1(pm1);
        }
        for (w, pending) in PENDING_GPE.iter().enumerate() {
            let mut bits = pending.swap(0, Ordering::AcqRel);
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                st.run_gpe(w * 64 + b);
            }
        }
    }
}

/// For the kernel debugger and tests: SCI count and the deepest AML stack use seen.
pub fn stats() -> (u64, u64) {
    let left = STACK_MIN_LEFT.load(Ordering::Relaxed);
    (SCI_COUNT.load(Ordering::Relaxed), if left == u64::MAX { 0 } else { STACK as u64 - left })
}
