//! IOMMU: DMA remapping. Every device that does DMA does it through its own address
//! space (a *domain*): the kernel maps exactly the pages a driver pinned for it (`PinObj`), with
//! the device's access (read and/or write). Everything else is blocked and reported, because
//! remapping is on for every device from boot (default deny): a device without a domain can reach
//! nothing at all.
//!
//! Backends: `vtd`, Intel VT-d (ACPI DMAR), register-based invalidation; `amdvi`, AMD-Vi (ACPI
//! IVRS), a device table shared by every IOMMU and invalidation through each one's command buffer.
//! The front is backend-neutral: the first backend whose table the firmware provides is used.
//!
//! Unmapping always waits until the hardware can no longer use the old translations (IOTLB
//! invalidated and the invalidation completed), so a page is never freed while a device could
//! still reach it.
//!
//! Firmware-reserved ranges (VT-d RMRR, AMD-Vi IVMD): memory the firmware says a device keeps
//! using (legacy USB emulation, a graphics core's stolen memory). Each present device such a range
//! names gets its domain at boot with the range identity mapped (and nothing else); its driver
//! later inherits that domain, and the range is never handed out as a device address. A range is
//! refused (logged) if it overlaps usable RAM or the first MiB, lies above 512 GiB or is larger
//! than 1 GiB.
//!
//! Interrupt remapping: an MSI is a memory write, so without it any device that can DMA could raise
//! any vector. With it, every interrupt a device sends goes through an entry the kernel made for
//! that device and vector (entry index = vector: every device interrupt goes to the boot CPU and
//! each vector has one owner); anything else is blocked and reported. I/O APIC pins go through it
//! too (the C side asks `dkrnl_ir_ioapic` for each pin). It is all or nothing: if the firmware
//! does not name every I/O APIC in use, it stays off and the boot log says so.

pub mod amdvi;
pub mod vtd;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use super::pci::{self, Bdf};
use crate::ffi::{self, rank};
use crate::object::{KResult, Status};
use crate::sync::SpinLock;

pub(super) const PAGE: u64 = 4096;

/// Where device addresses start: page 0 and the first 64 KiB stay unmapped, so a zero or small
/// DMA address (an uninitialised descriptor) faults instead of reaching a real buffer.
pub const IOVA_BASE: u64 = 0x1_0000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Backend {
    Vtd = 1,
    AmdVi = 2,
}

static BACKEND: AtomicU8 = AtomicU8::new(0);
static FAULTS: AtomicU64 = AtomicU64::new(0);

/// A device's DMA address space.
pub struct Domain {
    pub(super) backend: Backend,
    pub(super) unit: usize,
    pub did: u16,
    pub(super) root: u64, // physical address of the top page table
    pub(super) levels: u32,
    pub limit: u64, // first device address past the domain
    pub(super) tables: u64,
}

/// A firmware-reserved range (RMRR / IVMD): devices `first..=last` may reach `start..end` (page
/// aligned, `end` exclusive, `start < end`) with the given access.
#[derive(Clone, Copy)]
pub struct Reserved {
    pub first: u16,
    pub last: u16,
    pub start: u64,
    pub end: u64,
    pub write: bool,
    pub kind: &'static str,
}

impl Reserved {
    /// A range from the firmware's `base` and inclusive `last_byte`, rounded out to pages.
    pub(super) fn new(first: u16, last: u16, base: u64, last_byte: u64, write: bool, kind: &'static str) -> Option<Reserved> {
        let end = last_byte.checked_add(1)?.checked_next_multiple_of(PAGE)?;
        let start = base & !(PAGE - 1);
        (first <= last && start < end).then_some(Reserved { first, last, start, end, write, kind })
    }
}

const MAX_RESERVED: usize = 64;
const RESERVED_MAX_BYTES: u64 = 1 << 30;

/// The ranges kept (checked), and the domains made for them at boot until a driver takes one.
static RESERVED: SpinLock<Vec<Reserved>> = SpinLock::new(c"iommu.reserved", rank::IOMMU, Vec::new());
static BOOT_DOMAINS: SpinLock<Vec<(Bdf, Domain)>> = SpinLock::new(c"iommu.boot", rank::IOMMU, Vec::new());

/// DMA remapping is on.
pub fn enabled() -> bool {
    BACKEND.load(Ordering::Acquire) != 0
}

pub(super) fn set_backend(b: Backend) {
    BACKEND.store(b as u8, Ordering::Release);
}

/// Faults per requester id, for `device_info` (a small table: device -> count).
const FAULT_SLOTS: usize = 64;
static FAULT_SID: [AtomicU64; FAULT_SLOTS] = [const { AtomicU64::new(u64::MAX) }; FAULT_SLOTS];
static FAULT_COUNT: [AtomicU64; FAULT_SLOTS] = [const { AtomicU64::new(0) }; FAULT_SLOTS];

/// DMA faults recorded for a device so far.
pub fn faults_of(bdf: Bdf) -> u64 {
    (0..FAULT_SLOTS)
        .find(|&i| FAULT_SID[i].load(Ordering::Acquire) == u64::from(bdf.0))
        .map_or(0, |i| FAULT_COUNT[i].load(Ordering::Relaxed))
}

/// Count a blocked DMA (interrupt context); returns the total so far (for rate-limited reports).
pub(super) fn count_fault(sid: u16) -> u64 {
    let n = FAULTS.fetch_add(1, Ordering::Relaxed) + 1;
    for i in 0..FAULT_SLOTS {
        let cur = FAULT_SID[i].load(Ordering::Acquire);
        let mine = cur == u64::from(sid)
            || (cur == u64::MAX
                && match FAULT_SID[i].compare_exchange(u64::MAX, u64::from(sid), Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => true,
                    Err(now) => now == u64::from(sid),
                });
        if mine {
            FAULT_COUNT[i].fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
    n
}

// ---- interrupt remapping ------------------------------------------------------------------------

/// The backend remapping interrupts (`Backend` value), 0 = off.
static IR: AtomicU8 = AtomicU8::new(0);

/// Interrupts are remapped.
pub fn ir_enabled() -> bool {
    IR.load(Ordering::Acquire) != 0
}

/// A backend's bring-up finished (its state is published): log the outcome and, if on, move the
/// I/O APIC pins routed so far to the new format.
pub(super) fn ir_result(b: Backend, r: Result<&'static str, &'static str>) {
    match r {
        Ok(how) => {
            IR.store(b as u8, Ordering::Release);
            // SAFETY: plain call; re-routes every routed pin through `dkrnl_ir_ioapic`.
            unsafe { ffi::ioapic_reroute() };
            crate::kprintln!("IOMMU: interrupt remapping on ({}): a device can raise only its own interrupts", how);
        }
        Err(why) => crate::kprintln!("IOMMU: interrupt remapping off ({}): a device could forge interrupts", why),
    }
}

/// The MSI address and data for `bdf`'s interrupt on `vector`, after installing its remapping
/// entry (if remapping is on).
pub fn msi_message(bdf: Bdf, vector: u32) -> KResult<(u64, u32)> {
    match IR.load(Ordering::Acquire) {
        1 => vtd::ir_msi(bdf.0, vector),
        2 => amdvi::ir_msi(bdf.0, vector).map(|()| super::irq::msi_message(vector)),
        _ => Ok(super::irq::msi_message(vector)),
    }
}

/// The interrupt on `vector` (a PCI device's, or an I/O APIC pin's if `bdf` is None) is gone:
/// remove its remapping entry.
pub fn ir_release(bdf: Option<Bdf>, vector: u32) {
    match IR.load(Ordering::Acquire) {
        1 => vtd::ir_clear(vector),
        2 => amdvi::ir_clear(bdf.map(|b| b.0), vector),
        _ => {}
    }
}

/// Called by apic.c for every I/O APIC pin it unmasks: installs the pin's remapping entry and
/// returns the pin's high dword; -1 when remapping is off, -2 to refuse the route.
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_ir_ioapic(id: u8, vector: u8, level: bool) -> i64 {
    match IR.load(Ordering::Acquire) {
        1 => vtd::ir_ioapic(id, vector, level).map_or(-2, i64::from),
        2 => amdvi::ir_ioapic(id, vector).map_or(-2, i64::from),
        _ => -1,
    }
}

/// Test images (ktest.c): which backend remaps interrupts (1 VT-d, 2 AMD-Vi, 0 none).
#[cfg(ktest_drivers)]
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_ir_backend() -> u32 {
    u32::from(IR.load(Ordering::Acquire))
}

/// A blocked interrupt request (interrupt context). `reason`: the VT-d fault reason, 0 on AMD-Vi.
pub(super) fn report_irq(sid: u16, index: u32, reason: u32) {
    if count_fault(sid) <= 32 {
        if reason != 0 {
            crate::kprintln!("IOMMU: blocked interrupt from {} (entry {}, fault reason {:#x})", Bdf(sid), index, reason);
        } else {
            crate::kprintln!("IOMMU: blocked interrupt from {} (no remapping entry for it)", Bdf(sid));
        }
    }
}

pub(super) fn report(sid: u16, addr: u64, write: Option<bool>, why: &str) {
    if count_fault(sid) <= 32 {
        crate::kprintln!(
            "IOMMU: blocked DMA {} by {} at {:#x} ({})",
            match write {
                Some(true) => "write",
                Some(false) => "read",
                None => "access",
            },
            Bdf(sid),
            addr & !0xFFF,
            why
        );
    }
}

pub(super) fn alloc_table() -> KResult<u64> {
    // SAFETY: plain PMM call; 0 means out of memory.
    let pa = unsafe { ffi::pmm_alloc_zeroed() };
    if pa == 0 { Err(Status::NoMemory) } else { Ok(pa) }
}

pub(super) fn table(pa: u64) -> *mut u64 {
    (ffi::physmap_base() + pa) as *mut u64
}

/// Find and enable the DMA remapping hardware, then give the devices in `funcs` that a
/// firmware-reserved range names their domains. Returns a status line for the boot log.
pub fn init(funcs: &[pci::Function]) -> &'static str {
    let (status, ranges, max_did) = if let Some(r) = vtd::init() {
        r
    } else if let Some(r) = amdvi::init() {
        r
    } else {
        return "none (no DMAR or IVRS table): device DMA is NOT confined, drivers are trusted with all memory";
    };
    if enabled() {
        reserve(funcs, ranges, max_did);
    }
    status
}

/// Keep the firmware ranges that may be mapped and identity map them for the present devices.
#[allow(unused_mut)]
fn reserve(funcs: &[pci::Function], mut ranges: Vec<Reserved>, max_did: u16) {
    // Test images: a range for the first virtio-blk device (in the PCI hole, not RAM), so the
    // drivers test shows a reserved range surviving its driver taking the device over.
    #[cfg(ktest_drivers)]
    if let Some(f) = funcs.iter().find(|f| f.vendor == 0x1AF4 && f.device == 0x1042)
        && let Some(r) = Reserved::new(f.bdf.0, f.bdf.0, 0xC000_0000, 0xC000_FFFF, true, "test range")
        && ranges.try_reserve(1).is_ok()
    {
        ranges.push(r);
    }
    let mut kept = Vec::new();
    for r in ranges.iter().take(MAX_RESERVED) {
        let why = if r.end - r.start > RESERVED_MAX_BYTES {
            Some("larger than 1 GiB")
        } else if r.end > 1 << 39 {
            Some("above 512 GiB")
        // SAFETY: plain query of the boot memory map.
        } else if unsafe { ffi::pmm_range_is_ram(r.start, r.end - r.start) } {
            Some("overlaps usable RAM or the first MiB")
        } else {
            None
        };
        match why {
            Some(w) => crate::kprintln!("IOMMU: {} {:#x}-{:#x} refused: {}", r.kind, r.start, r.end - 1, w),
            None => {
                if kept.try_reserve(1).is_ok() {
                    kept.push(*r);
                }
            }
        }
    }
    if ranges.len() > MAX_RESERVED {
        crate::kprintln!("IOMMU: {} firmware range(s) past the first {} ignored", ranges.len() - MAX_RESERVED, MAX_RESERVED);
    }
    let covers = |r: &Reserved, b: Bdf| r.first <= b.0 && b.0 <= r.last;
    let mut boot = Vec::new();
    let mut did = max_did;
    for f in funcs {
        if kernel_owned(f.bdf) || !kept.iter().any(|r| covers(r, f.bdf)) {
            continue;
        }
        // Domain ids from the top: drivers' domains use small ones (device index + 1; the
        // platform devices after the PCI functions take a few more).
        if usize::from(did) <= funcs.len() + 32 || boot.try_reserve(1).is_err() {
            crate::kprintln!("IOMMU: no domain id left for {}'s firmware ranges", f.bdf);
            continue;
        }
        let Ok(mut d) = backend_create(f.bdf, did) else {
            crate::kprintln!("IOMMU: no domain for {}'s firmware ranges", f.bdf);
            continue;
        };
        did -= 1;
        for r in kept.iter().filter(|r| covers(r, f.bdf)) {
            let (s, e) = (r.start, r.end - 1);
            match identity_map(&mut d, r) {
                Ok(()) => crate::kprintln!(
                    "IOMMU: {} {:#x}-{:#x} identity mapped for {}{}",
                    r.kind,
                    s,
                    e,
                    f.bdf,
                    if r.write { "" } else { " (read-only)" }
                ),
                Err(_) => crate::kprintln!("IOMMU: {} {:#x}-{:#x} for {}: out of memory, not mapped", r.kind, s, e, f.bdf),
            }
        }
        boot.push((f.bdf, d));
    }
    // The old (empty) vectors are dropped after the locks: no heap use under an IOMMU-rank lock.
    let _old = core::mem::replace(&mut *RESERVED.lock(), kept);
    let _old_boot = core::mem::replace(&mut *BOOT_DOMAINS.lock(), boot);
}

fn identity_map(d: &mut Domain, r: &Reserved) -> KResult<()> {
    let mut frames = [0u64; 64];
    let mut at = r.start;
    while at < r.end {
        let n = ((r.end - at) / PAGE).min(frames.len() as u64) as usize;
        for (i, f) in frames[..n].iter_mut().enumerate() {
            *f = at + i as u64 * PAGE;
        }
        map(d, at, &frames[..n], r.write)?;
        at += n as u64 * PAGE;
    }
    Ok(())
}

/// The firmware-reserved ranges of `bdf` as (start, pages), sorted: its driver's device address
/// allocator never hands them out.
pub fn reserved_of(bdf: Bdf) -> KResult<Vec<(u64, u64)>> {
    // Copied out first: the heap may not be used under an IOMMU-rank lock.
    let mut buf = [(0u64, 0u64); MAX_RESERVED];
    let mut n = 0;
    for r in RESERVED.lock().iter().filter(|r| r.first <= bdf.0 && bdf.0 <= r.last).take(MAX_RESERVED) {
        buf[n] = (r.start, (r.end - r.start) / PAGE);
        n += 1;
    }
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Status::NoMemory)?;
    v.extend_from_slice(&buf[..n]);
    v.sort_unstable_by_key(|&(s, _)| s);
    Ok(v)
}

/// Create the domain of a device. `did` must be unique per device (>= 1). A device with
/// firmware-reserved ranges gets the domain made for it at boot (its own id, ranges mapped).
pub fn domain_create(bdf: Bdf, did: u16) -> KResult<Domain> {
    let boot = {
        let mut g = BOOT_DOMAINS.lock();
        g.iter().position(|(b, _)| *b == bdf).map(|i| g.swap_remove(i).1)
    };
    if let Some(d) = boot {
        #[cfg(ktest_drivers)]
        check_reserved(bdf, &d);
        return Ok(d);
    }
    backend_create(bdf, did)
}

/// Test images: the boot domain a driver takes over still maps its reserved ranges.
#[cfg(ktest_drivers)]
fn check_reserved(bdf: Bdf, d: &Domain) {
    let Ok(ranges) = reserved_of(bdf) else { return };
    for (s, n) in ranges {
        let last = s + (n - 1) * PAGE;
        let ok = [s, last].iter().all(|&a| match d.backend {
            Backend::Vtd => vtd::lookup(d, a) == Some((a, true)),
            Backend::AmdVi => amdvi::lookup(d, a) == Some((a, true)),
        });
        if ok {
            crate::kprintln!("IOMMU: test: firmware range {:#x}-{:#x} kept in {}'s domain", s, last + PAGE - 1, bdf);
        } else {
            crate::kprintln!("IOMMU: test: FAIL: firmware range at {:#x} lost in {}'s domain", s, bdf);
        }
    }
}

fn backend_create(bdf: Bdf, did: u16) -> KResult<Domain> {
    match BACKEND.load(Ordering::Acquire) {
        1 => vtd::domain_create(bdf, did),
        2 => amdvi::domain_create(bdf, did),
        _ => Err(Status::NotSupported),
    }
}

/// Map `frames` at `iova` (device may read; may write if `write`). On error nothing stays mapped.
pub fn map(d: &mut Domain, iova: u64, frames: &[u64], write: bool) -> KResult<()> {
    match d.backend {
        Backend::Vtd => vtd::map(d, iova, frames, write),
        Backend::AmdVi => amdvi::map(d, iova, frames, write),
    }
}

/// Unmap and wait until no device can use the translations any more (the pages may be freed).
pub fn unmap(d: &mut Domain, iova: u64, pages: u64) {
    match d.backend {
        Backend::Vtd => vtd::unmap(d, iova, pages),
        Backend::AmdVi => amdvi::unmap(d, iova, pages),
    }
}

/// A device vector fired: is it an IOMMU's fault interrupt? (interrupt context)
pub fn fault_irq(vector: u32) -> bool {
    vtd::fault_irq(vector) || amdvi::fault_irq(vector)
}

/// Is `bdf` part of the IOMMU itself (kernel-owned, never handed to a driver)?
pub fn kernel_owned(bdf: Bdf) -> bool {
    amdvi::kernel_owned(bdf)
}

/// Re-program the active IOMMU backend after ACPI S3 sleep (called with interrupts off).
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_iommu_resume() {
    match BACKEND.load(Ordering::Acquire) {
        1 => vtd::resume(),
        2 => amdvi::resume(),
        _ => {}
    }
}
