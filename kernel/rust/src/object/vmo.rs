//! Virtual memory object (VMO): a set of physical pages that can be read, written and mapped.
//!
//! Virtual capacity is charged to the creating process's memory quota upfront (so quotas stay
//! exact and cannot be oversubscribed), while physical RAM frames are allocated lazily on first
//! write, DMA pin, port/shadow-stack commit, or user-mode demand page fault. Uncommitted pages
//! read as zero without consuming physical memory; committed frames return to the PMM when the
//! last reference (handle or mapping) is dropped.
//!
//! W^X across aliases: a VMO counts its *writers* (writable mappings, writes in
//! progress, kernel users such as a port's rings). Sealing (`seal`) succeeds only with no writer
//! and is permanent: afterwards nothing can write it, through any handle or mapping. Only a sealed
//! VMO can be made executable, so code is never writable anywhere, not even through another
//! mapping of the same pages.
//!
//! Device VMOs (`create_device`): the pages of a device's MMIO BAR, for a user-space
//! driver to map. Their frames are device memory, not RAM: never freed, never counted as committed,
//! always mapped uncached, never readable or writable through the kernel (`read`, `write`, the
//! direct map would be the wrong memory type), never executable and never DMA targets. Pages a
//! driver must not reach (the MSI-X table, which the kernel owns) are backed by a private zero page.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

use super::quota::{Account, Charge, Res};
use super::{Header, KRef, KResult, Name, ObjType, Status};
use crate::ffi;

/// Lock-free write-once name (0 = empty, 1 = writing, 2 = initialized).
struct OnceName {
    state: AtomicU8,
    value: UnsafeCell<Name>,
}

// SAFETY: `value` is only mutated during the exclusive 0 -> 1 transition and only read after
// observing state == 2 with Acquire ordering.
unsafe impl Sync for OnceName {}

impl OnceName {
    fn new(s: &str) -> Self {
        let init = if s.is_empty() { 0 } else { 2 };
        OnceName { state: AtomicU8::new(init), value: UnsafeCell::new(Name::new(s)) }
    }

    fn as_str(&self) -> &str {
        if self.state.load(Ordering::Acquire) != 2 {
            return "";
        }
        // SAFETY: state == 2 with Acquire guarantees `value` is initialized and never mutated again.
        unsafe { (*self.value.get()).as_str() }
    }

    fn set_once(&self, s: &str) {
        if s.is_empty() {
            return;
        }
        if self.state.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            // SAFETY: exclusive writer for the 0 -> 1 -> 2 transition.
            unsafe { *self.value.get() = Name::new(s) };
            self.state.store(2, Ordering::Release);
        }
    }
}

/// Upper bound for one VMO (1 GiB): keeps the frame list allocation bounded.
pub const MAX_SIZE: u64 = 1 << 30;
const PAGE: u64 = 4096;

/// Shared read-only zero page for reading uncommitted VMO pages without allocating RAM.
static ZERO_PAGE: [u8; PAGE as usize] = [0; PAGE as usize];

static FRAMES: AtomicU64 = AtomicU64::new(0);

/// Physical frames currently held by all VMOs (leak checks, inspection).
pub fn committed_frames() -> u64 {
    FRAMES.load(Ordering::Relaxed)
}

pub struct Vmo {
    pub header: Header,
    size: u64,
    /// Physical address of each page, or `0` if not yet committed. Populated monotonically via
    /// atomic CAS (once non-zero, a frame stays owned until `Vmo::drop`), so reads need no lock.
    frames: Vec<AtomicU64>,
    executable: AtomicBool,
    /// Why it may run as a program (`security::Trust`); set once, after sealing.
    trust: AtomicU8,
    /// `SEALED` bit + number of writers (see the module comment).
    wstate: AtomicU64,
    name: OnceName,
    /// Device memory (MMIO): `frames` are not RAM and are not owned, except `dummy`.
    device: bool,
    /// Device memory mapped write-combining (the display) instead of uncached.
    wc: bool,
    /// The zero page standing in for hidden device pages (0 = none); owned and freed.
    dummy: u64,
    _charge: Charge,
}

impl Vmo {
    /// `size` in bytes (rounded up to whole pages), charged to `acct`.
    pub fn create(acct: &KRef<Account>, size: u64) -> KResult<KRef<Vmo>> {
        Self::create_named(acct, size, "")
    }

    pub fn create_named(acct: &KRef<Account>, size: u64, name: &str) -> KResult<KRef<Vmo>> {
        if size == 0 || size > MAX_SIZE {
            return Err(Status::InvalidArgs);
        }
        let pages = size.div_ceil(PAGE);
        let charge = Charge::new(acct, Res::Memory, pages * PAGE)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(pages as usize)
            .map_err(|_| Status::NoMemory)?;
        for _ in 0..pages {
            frames.push(AtomicU64::new(0));
        }
        let vmo = Vmo {
            header: Header::new(ObjType::Vmo),
            size: pages * PAGE,
            frames,
            executable: AtomicBool::new(false),
            trust: AtomicU8::new(0),
            wstate: AtomicU64::new(0),
            name: OnceName::new(name),
            device: false,
            wc: false,
            dummy: 0,
            _charge: charge,
        };
        KRef::try_new(vmo).map_err(|_| Status::NoMemory)
    }

    /// A device VMO over `pages` pages of MMIO starting at `phys` (page aligned). Page `i` is
    /// hidden (backed by a private zero page) when `hide(i)`. One page is charged to `acct` (the
    /// frame list and the zero page); the device memory itself is not RAM and is not charged.
    pub fn create_device(acct: &KRef<Account>, phys: u64, pages: u64, name: &str, wc: bool, hide: impl Fn(u64) -> bool) -> KResult<KRef<Vmo>> {
        if pages == 0 || pages > MAX_SIZE / PAGE || !phys.is_multiple_of(PAGE) {
            return Err(Status::InvalidArgs);
        }
        let charge = Charge::new(acct, Res::Memory, PAGE)?;
        let mut frames = Vec::new();
        frames.try_reserve_exact(pages as usize).map_err(|_| Status::NoMemory)?;
        let mut vmo = Vmo {
            header: Header::new(ObjType::Vmo),
            size: pages * PAGE,
            frames,
            executable: AtomicBool::new(false),
            trust: AtomicU8::new(0),
            wstate: AtomicU64::new(0),
            name: OnceName::new(name),
            device: true,
            wc,
            dummy: 0,
            _charge: charge,
        };
        for i in 0..pages {
            if hide(i) {
                if vmo.dummy == 0 {
                    // SAFETY: plain PMM call; 0 means out of memory.
                    vmo.dummy = unsafe { ffi::pmm_alloc_zeroed() };
                    if vmo.dummy == 0 {
                        return Err(Status::NoMemory);
                    }
                }
                vmo.frames.push(AtomicU64::new(vmo.dummy));
            } else {
                vmo.frames.push(AtomicU64::new(phys + i * PAGE));
            }
        }
        KRef::try_new(vmo).map_err(|_| Status::NoMemory)
    }

    /// Device memory (MMIO): mapped uncached, never accessed through the kernel, never DMA'd to.
    pub fn is_device(&self) -> bool {
        self.device
    }

    /// Device memory to be mapped write-combining (the display).
    pub fn is_write_combining(&self) -> bool {
        self.wc
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// May this VMO be mapped executable? Only the kernel's program loader marks VMOs executable
    /// (`user::loader`), and handles to VMOs never carry `EXECUTE`.
    pub fn executable(&self) -> bool {
        self.executable.load(Ordering::Acquire)
    }

    /// Seal the VMO and allow executable mappings of it (program loader, `vmo_make_executable`).
    /// Fails with `BadState` while anything can still write it.
    pub(crate) fn make_executable(&self) -> KResult<()> {
        if self.device {
            return Err(Status::NotSupported);
        }
        self.seal()?;
        self.executable.store(true, Ordering::Release);
        Ok(())
    }

    /// Make the VMO read-only for ever. `BadState` while it has a writer (a writable mapping, a
    /// write in progress, a kernel user). Sealing a sealed VMO is fine.
    pub fn seal(&self) -> KResult<()> {
        match self.wstate.compare_exchange(0, SEALED, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(s) if s & SEALED != 0 => Ok(()),
            Err(_) => Err(Status::BadState),
        }
    }

    pub fn sealed(&self) -> bool {
        self.wstate.load(Ordering::Acquire) & SEALED != 0
    }

    /// Why the kernel lets this VMO run as a program (code signing).
    pub fn trust(&self) -> crate::security::Trust {
        crate::security::Trust::from_u8(self.trust.load(Ordering::Acquire))
    }

    /// Record the trust decision. Only for sealed VMOs (their contents can no longer change), and
    /// only the first decision counts.
    pub(crate) fn set_trust(&self, t: crate::security::Trust) {
        crate::kassert!(self.sealed());
        let _ = self.trust.compare_exchange(0, t as u8, Ordering::AcqRel, Ordering::Acquire);
    }

    fn add_writer(&self) -> KResult<()> {
        let mut cur = self.wstate.load(Ordering::Relaxed);
        loop {
            if cur & SEALED != 0 {
                return Err(Status::AccessDenied);
            }
            match self.wstate.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Ok(()),
                Err(c) => cur = c,
            }
        }
    }

    fn drop_writer(&self) {
        let old = self.wstate.fetch_sub(1, Ordering::AcqRel);
        crate::kassert!(old & !SEALED != 0);
    }

    /// A lasting writer (a writable mapping, a port's rings): `AccessDenied` once sealed.
    pub fn write_ref(this: &KRef<Vmo>) -> KResult<WriteRef> {
        this.add_writer()?;
        Ok(WriteRef(this.clone()))
    }

    /// Shared-memory word at `off` (4-aligned, inside the VMO), reached through the direct map.
    /// For the rings of a port, which commits all pages eagerly.
    pub fn atomic_u32(&self, off: u64) -> &AtomicU32 {
        crate::kassert!(off.is_multiple_of(4) && off + 4 <= self.size);
        let pa = self.frames[(off / PAGE) as usize].load(Ordering::Acquire);
        crate::kassert!(pa != 0);
        let va = (ffi::physmap_base() + pa + off % PAGE) as *const AtomicU32;
        // SAFETY: an aligned word inside a frame this VMO owns (it lives as long as `self`); the
        // page is never freed while the VMO exists. Concurrent access from user space is fine
        // for an atomic.
        unsafe { &*va }
    }

    /// Shared-memory u64 at `off` (8-aligned), see `atomic_u32`.
    pub fn atomic_u64(&self, off: u64) -> &AtomicU64 {
        crate::kassert!(off.is_multiple_of(8) && off + 8 <= self.size);
        let pa = self.frames[(off / PAGE) as usize].load(Ordering::Acquire);
        crate::kassert!(pa != 0);
        let va = (ffi::physmap_base() + pa + off % PAGE) as *const AtomicU64;
        // SAFETY: as in `atomic_u32`.
        unsafe { &*va }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Record a verified name (code signing, `vmo_verify`) if the VMO was created unnamed.
    pub(crate) fn set_name_once(&self, s: &str) {
        self.name.set_once(s);
    }

    /// Physical address of page `idx`, or `0` if not yet committed.
    pub fn frame_at(&self, idx: usize) -> u64 {
        self.frames[idx].load(Ordering::Acquire)
    }

    /// Commit page `idx` if not already backed by RAM, returning its physical address.
    pub fn ensure_page(&self, idx: usize) -> KResult<u64> {
        let pa = self.frames[idx].load(Ordering::Acquire);
        if pa != 0 {
            return Ok(pa);
        }
        crate::kassert!(!self.device);
        // SAFETY: plain PMM call; 0 means out of memory.
        let fresh = unsafe { ffi::pmm_alloc_zeroed() };
        if fresh == 0 {
            return Err(Status::NoMemory);
        }
        match self.frames[idx].compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                FRAMES.fetch_add(1, Ordering::Relaxed);
                Ok(fresh)
            }
            Err(existing) => {
                // SAFETY: `fresh` was just allocated by us and never published.
                unsafe { ffi::pmm_free(fresh) };
                Ok(existing)
            }
        }
    }

    /// Commit all pages in `[off, off + len)` (page-aligned) and append their physical addresses
    /// to `out`.
    pub fn commit_range(&self, off: u64, len: u64, out: &mut Vec<u64>) -> KResult<()> {
        let first = (off / PAGE) as usize;
        let count = (len / PAGE) as usize;
        out.try_reserve_exact(count).map_err(|_| Status::NoMemory)?;
        for i in 0..count {
            out.push(self.ensure_page(first + i)?);
        }
        Ok(())
    }

    /// Commit every page of this VMO eagerly (ports, shadow stacks).
    pub fn commit_all(&self) -> KResult<()> {
        for i in 0..self.frames.len() {
            self.ensure_page(i)?;
        }
        Ok(())
    }

    fn check(&self, off: u64, len: usize) -> KResult<()> {
        if self.device {
            return Err(Status::NotSupported); // MMIO is only reachable through a mapping
        }
        let end = off.checked_add(len as u64).ok_or(Status::OutOfRange)?;
        if end > self.size {
            return Err(Status::OutOfRange);
        }
        Ok(())
    }

    /// Visit the pages covering [off, off+len) for reading: `Some(ptr)` for a committed page,
    /// `None` for an uncommitted (zero) page.
    fn read_chunks(&self, off: u64, len: usize, mut f: impl FnMut(Option<*const u8>, usize, usize)) {
        let mut done = 0usize;
        while done < len {
            let pos = off + done as u64;
            let in_page = (pos % PAGE) as usize;
            let n = (PAGE as usize - in_page).min(len - done);
            let pa = self.frames[(pos / PAGE) as usize].load(Ordering::Acquire);
            let ptr = if pa != 0 {
                Some(((ffi::physmap_base() + pa) as *const u8).wrapping_add(in_page))
            } else {
                None
            };
            f(ptr, n, done);
            done += n;
        }
    }

    /// Visit the pages covering [off, off+len) for writing, committing each touched page on demand.
    fn write_chunks(&self, off: u64, len: usize, mut f: impl FnMut(*mut u8, usize, usize) -> KResult<()>) -> KResult<()> {
        let mut done = 0usize;
        while done < len {
            let pos = off + done as u64;
            let in_page = (pos % PAGE) as usize;
            let n = (PAGE as usize - in_page).min(len - done);
            let pa = self.ensure_page((pos / PAGE) as usize)?;
            let va = ((ffi::physmap_base() + pa) as *mut u8).wrapping_add(in_page);
            f(va, n, done)?;
            done += n;
        }
        Ok(())
    }

    pub fn read(&self, off: u64, buf: &mut [u8]) -> KResult<()> {
        self.check(off, buf.len())?;
        let dst = buf.as_mut_ptr();
        self.read_chunks(off, buf.len(), |src, n, at| match src {
            // SAFETY: `src..src+n` lies inside one frame owned by this VMO (bounds checked above),
            // reached through the direct map; `dst+at..+n` lies inside `buf`.
            Some(s) => unsafe { core::ptr::copy_nonoverlapping(s, dst.add(at), n) },
            // SAFETY: `dst+at..+n` lies inside `buf`.
            None => unsafe { core::ptr::write_bytes(dst.add(at), 0, n) },
        });
        Ok(())
    }

    pub fn write(&self, off: u64, data: &[u8]) -> KResult<()> {
        self.check(off, data.len())?;
        let _w = WriteGuard::new(self)?;
        let src = data.as_ptr();
        self.write_chunks(off, data.len(), |dst, n, at| {
            // SAFETY: `dst..dst+n` lies inside one committed frame of this VMO; `src+at..+n` in `data`.
            unsafe { core::ptr::copy_nonoverlapping(src.add(at), dst, n) };
            Ok(())
        })
    }
}

impl Vmo {
    /// Copy [off, off+len) to user memory at `user` (syscalls: no bounce buffer).
    pub fn read_to_user(&self, off: u64, user: u64, len: u64) -> KResult<()> {
        let n = usize::try_from(len).map_err(|_| Status::OutOfRange)?;
        self.check(off, n)?;
        crate::user::uaccess::check(user, len)?;
        let mut res = Ok(());
        self.read_chunks(off, n, |src, c, at| {
            if res.is_ok() {
                let s = src.unwrap_or(ZERO_PAGE.as_ptr());
                // SAFETY: `s..s+c` lies in a frame of this VMO or `ZERO_PAGE` (`c <= PAGE`);
                // the user range was checked to lie below USER_TOP, and user_copy survives faults.
                res = unsafe { crate::user::uaccess::copy_to_user_raw(user + at as u64, s, c) };
            }
        });
        res
    }

    /// Copy `len` bytes from user memory at `user` into [off, off+len).
    pub fn write_from_user(&self, off: u64, user: u64, len: u64) -> KResult<()> {
        let n = usize::try_from(len).map_err(|_| Status::OutOfRange)?;
        self.check(off, n)?;
        crate::user::uaccess::check(user, len)?;
        let _w = WriteGuard::new(self)?;
        self.write_chunks(off, n, |dst, c, at| {
            // SAFETY: as in `read_to_user`, with the direction reversed.
            unsafe { crate::user::uaccess::copy_from_user_raw(dst, user + at as u64, c) }
        })
    }
}

const SEALED: u64 = 1 << 63;

/// A writer for the lifetime of the value (keeps the VMO alive too).
pub struct WriteRef(KRef<Vmo>);

impl WriteRef {
    pub fn vmo(&self) -> &KRef<Vmo> {
        &self.0
    }
}

impl Drop for WriteRef {
    fn drop(&mut self) {
        self.0.drop_writer();
    }
}

/// A write in progress.
struct WriteGuard<'a>(&'a Vmo);

impl<'a> WriteGuard<'a> {
    fn new(v: &'a Vmo) -> KResult<Self> {
        v.add_writer()?;
        Ok(WriteGuard(v))
    }
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        self.0.drop_writer();
    }
}

impl Drop for Vmo {
    fn drop(&mut self) {
        if self.device {
            if self.dummy != 0 {
                // SAFETY: the zero page was allocated for this VMO; its mappings are gone.
                unsafe { ffi::pmm_free(self.dummy) };
            }
            return; // the other frames are device memory, not ours
        }
        let mut freed = 0u64;
        for slot in &mut self.frames {
            let pa = *slot.get_mut();
            if pa != 0 {
                // SAFETY: each committed frame was allocated for this VMO and nothing else refers
                // to it now (mappings hold a reference to the VMO, so they are gone too).
                unsafe { ffi::pmm_free(pa) };
                freed += 1;
            }
        }
        if freed != 0 {
            FRAMES.fetch_sub(freed, Ordering::Relaxed);
        }
    }
}
