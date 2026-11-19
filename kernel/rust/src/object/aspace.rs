//! A process's address space: the page tables behind its VMARs (`struct uspace`, vmm.c).
//!
//! Every VMAR of a process shares one `AddressSpace`. Page tables are charged to the process's
//! memory quota: a mapping first reserves the most tables it could need, and the part the C side
//! did not allocate is refunded right after. Tables stay (charged) until the address space goes
//! away, so a process cannot make the kernel allocate unbounded page-table memory for free.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use super::quota::{Account, Res};
use super::vmar::Vmar;
use super::{KRef, KResult, Status};
use crate::ffi::{self, RawUspace, rank};
use crate::sync::SpinLock;

const PAGE: u64 = 4096;

pub struct AddressSpace {
    raw: NonNull<RawUspace>,
    acct: KRef<Account>,
    charged: AtomicU64, // page tables charged to `acct`
    /// Weak link to the root VMAR (`KRef::value_addr`, 0 once dropped) so `vmar_destroy` can
    /// remove any child region from its parent without a reference cycle.
    root_vmar: SpinLock<usize>,
}

// SAFETY: the C side locks the address space internally; the pointer is owned by this object.
unsafe impl Send for AddressSpace {}
// SAFETY: as above.
unsafe impl Sync for AddressSpace {}

impl AddressSpace {
    pub fn new(acct: &KRef<Account>) -> KResult<KRef<AddressSpace>> {
        // SAFETY: plain allocation call; NULL means out of memory.
        let raw = NonNull::new(unsafe { ffi::uspace_create() }).ok_or(Status::NoMemory)?;
        KRef::try_new(AddressSpace {
            raw,
            acct: acct.clone(),
            charged: AtomicU64::new(0),
            root_vmar: SpinLock::new(c"aspace.root", rank::PORT, 0),
        })
        .map_err(|a| {
            drop(a); // Drop destroys the uspace
            Status::NoMemory
        })
    }

    pub fn set_root(&self, value_addr: usize) {
        *self.root_vmar.lock() = value_addr;
    }

    pub fn clear_root(&self) {
        *self.root_vmar.lock() = 0;
    }

    pub fn root_vmar(&self) -> Option<KRef<Vmar>> {
        let addr = *self.root_vmar.lock();
        if addr == 0 {
            return None;
        }
        // SAFETY: `addr` was set by `Vmar::new_root` and cleared by `Vmar::drop` under `root_vmar`,
        // so the allocation stays live while we hold the lock; `try_from_value_addr` checks refs != 0.
        unsafe { KRef::try_from_value_addr(addr) }
    }

    pub fn raw(&self) -> *mut RawUspace {
        self.raw.as_ptr()
    }

    /// Map `frames` (one per page) at `va` with `VMM_W`/`VMM_X` flags.
    pub fn map(&self, va: u64, frames: &[u64], flags: u32) -> KResult<()> {
        let pages = frames.len() as u64;
        // SAFETY: pure arithmetic.
        let worst = unsafe { ffi::uspace_tables_needed(va, pages) };
        self.acct.charge(Res::Memory, worst * PAGE)?;
        let mut new = 0u64;
        // SAFETY: `frames` holds `pages` valid frame addresses owned by a VMO that the caller keeps
        // mapped (alive) until it unmaps them; the range was checked and reserved by the VMAR.
        let ok = unsafe { ffi::uspace_map(self.raw(), va, frames.as_ptr(), pages, flags, &mut new) };
        crate::kassert!(new <= worst);
        self.acct.uncharge(Res::Memory, (worst - new) * PAGE);
        self.charged.fetch_add(new, Ordering::Relaxed);
        if ok { Ok(()) } else { Err(Status::NoMemory) }
    }

    /// Map a single demand-faulted page `pa` at `va`.
    pub fn map_page(&self, va: u64, pa: u64, flags: u32) -> KResult<()> {
        // SAFETY: pure arithmetic.
        let worst = unsafe { ffi::uspace_tables_needed(va, 1) };
        self.acct.charge(Res::Memory, worst * PAGE)?;
        let mut new = 0u64;
        // SAFETY: `pa` is a valid frame owned by a VMO that the caller holds under the VMAR lock.
        let ok = unsafe { ffi::uspace_map_page(self.raw(), va, pa, flags, &mut new) };
        crate::kassert!(new <= worst);
        self.acct.uncharge(Res::Memory, (worst - new) * PAGE);
        self.charged.fetch_add(new, Ordering::Relaxed);
        if ok { Ok(()) } else { Err(Status::NoMemory) }
    }

    pub fn unmap(&self, va: u64, len: u64) {
        // SAFETY: the range was mapped by `map` (or is empty); the C side shoots it down on every
        // CPU before returning, so the caller may free the frames afterwards.
        unsafe { ffi::uspace_unmap(self.raw(), va, len / PAGE) }
    }

    /// Physical address behind `va`, if mapped (tests, inspection).
    pub fn translate(&self, va: u64) -> Option<u64> {
        // SAFETY: read-only walk under the address space's lock.
        let pa = unsafe { ffi::uspace_translate(self.raw(), va) };
        (pa != u64::MAX).then_some(pa)
    }

    /// Give every page table back (and its quota charge): the process is dead, its address
    /// space empty, and its last thread has left it.
    pub fn free_tables(&self) {
        // SAFETY: as documented: no CPU has it loaded (checked in C), nothing is mapped.
        let n = unsafe { ffi::uspace_free_tables(self.raw()) };
        let charged = self.charged.swap(0, Ordering::Relaxed);
        crate::kassert!(n == charged);
        self.acct.uncharge(Res::Memory, charged * PAGE);
    }

    /// Page tables in use (charged to the quota).
    pub fn tables(&self) -> u64 {
        self.charged.load(Ordering::Relaxed)
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // SAFETY: the last reference: every VMAR (and so every mapping) of this address space is
        // gone, and no thread runs in it any more (user threads hold their process, and leave the
        // address space before dropping it).
        unsafe { ffi::uspace_destroy(self.raw()) };
        self.acct.uncharge(Res::Memory, self.charged.load(Ordering::Relaxed) * PAGE);
    }
}
