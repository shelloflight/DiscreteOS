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
//! Not done yet: interrupt remapping (an MSI is still a plain memory write a device
//! could forge), RMRR / IVMD identity maps (firmware-owned DMA such as legacy USB emulation;
//! nothing needs them yet), queued invalidation on VT-d.

pub mod amdvi;
pub mod vtd;

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use super::pci::Bdf;
use crate::ffi;
use crate::object::{KResult, Status};

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

/// Find and enable the DMA remapping hardware. Returns a status line for the boot log.
pub fn init() -> &'static str {
    if let Some(s) = vtd::init() {
        return s;
    }
    if let Some(s) = amdvi::init() {
        return s;
    }
    "none (no DMAR or IVRS table): device DMA is NOT confined, drivers are trusted with all memory"
}

/// Create the domain of a device. `did` must be unique per device (>= 1).
pub fn domain_create(bdf: Bdf, did: u16) -> KResult<Domain> {
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
