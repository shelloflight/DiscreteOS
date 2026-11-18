//! Intel VT-d backend (see `iommu`): root table (one entry per bus) -> context tables (one entry
//! per device/function: domain id, page-table root, address width) -> second-level page tables
//! (x86-like, 3 or 4 levels, R/W bits). Register-based invalidation of the context cache and the
//! IOTLB, globally or per domain, waited for synchronously.
//!
//! The DMAR table is firmware data: every structure is bounds-checked. Units are matched to
//! devices by their device scopes (single-level paths) or INCLUDE_PCI_ALL.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{Backend, Domain, PAGE, alloc_table, report, set_backend, table};
use crate::dev::pci::Bdf;
use crate::ffi::{self, rank};
use crate::object::{KResult, Status};
use crate::sync::SpinLock;

// Registers
const VER: u64 = 0x00;
const CAP: u64 = 0x08;
const ECAP: u64 = 0x10;
const GCMD: u64 = 0x18;
const GSTS: u64 = 0x1C;
const RTADDR: u64 = 0x20;
const CCMD: u64 = 0x28;
const FSTS: u64 = 0x34;
const FECTL: u64 = 0x38;
const FEDATA: u64 = 0x3C;
const FEADDR: u64 = 0x40;
const FEUADDR: u64 = 0x44;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GCMD_WBF: u32 = 1 << 27;
const GSTS_TES: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;
const GSTS_WBFS: u32 = 1 << 27;
/// GSTS bits that are one-shot commands, not state: never written back to GCMD.
const GCMD_KEEP: u32 = 0x96FF_FFFF;

const PTE_R: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_ADDR: u64 = 0x000F_FFFF_FFFF_F000;

struct Unit {
    regs: u64, // virtual address of the register page
    cap: u64,
    ecap: u64,
    levels: u32,  // 3 (39-bit) or 4 (48-bit)
    root: u64,    // physical address of the root table
    include_all: bool,
    scopes: Vec<Bdf>,
    fault_regs: u64, // offset of the first fault recording register
    nfr: u32,
}

impl Unit {
    fn r32(&self, off: u64) -> u32 {
        // SAFETY: an aligned register inside the unit's mapped register page.
        unsafe { core::ptr::read_volatile((self.regs + off) as *const u32) }
    }
    fn w32(&self, off: u64, v: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.regs + off) as *mut u32, v) }
    }
    fn r64(&self, off: u64) -> u64 {
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile((self.regs + off) as *const u64) }
    }
    fn w64(&self, off: u64, v: u64) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.regs + off) as *mut u64, v) }
    }

    fn coherent(&self) -> bool {
        self.ecap & 1 != 0
    }

    /// Make a table write visible to a non-coherent page walker.
    fn flush(&self, va: u64) {
        if !self.coherent() {
            // SAFETY: flushes one cache line of kernel memory (the direct map).
            unsafe { core::arch::asm!("clflush [{}]", in(reg) va, options(nostack, preserves_flags)) }
        }
    }

    fn wait(&self, what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..10_000_000u32 {
            if done() {
                return;
            }
            core::hint::spin_loop();
        }
        panic!("IOMMU: unit at {:#x} did not complete {}", self.regs, what);
    }

    fn command(&self, bit: u32, status: u32, set: bool) {
        let cur = self.r32(GSTS) & GCMD_KEEP;
        self.w32(GCMD, if set { cur | bit } else { cur & !bit });
        self.wait("a command", || (self.r32(GSTS) & status != 0) == set);
    }

    fn flush_write_buffer(&self) {
        if self.cap & (1 << 4) != 0 {
            let cur = self.r32(GSTS) & GCMD_KEEP;
            self.w32(GCMD, cur | GCMD_WBF);
            self.wait("a write-buffer flush", || self.r32(GSTS) & GSTS_WBFS == 0);
        }
    }

    fn iotlb_reg(&self) -> u64 {
        ((self.ecap >> 8) & 0x3FF) * 16 + 8
    }

    fn invalidate_context(&self) {
        self.flush_write_buffer();
        self.w64(CCMD, 1 << 63 | 1 << 61); // ICC, global
        self.wait("a context-cache invalidation", || self.r64(CCMD) & (1 << 63) == 0);
    }

    /// IOTLB: per domain (`did`), or everything (`None`). Drains reads and writes if supported.
    fn invalidate_iotlb(&self, did: Option<u16>) {
        self.flush_write_buffer();
        let drain = (if self.cap & (1 << 55) != 0 { 1u64 << 49 } else { 0 }) | if self.cap & (1 << 54) != 0 { 1 << 48 } else { 0 };
        let cmd = match did {
            Some(d) => 1u64 << 63 | 2 << 60 | u64::from(d) << 32 | drain,
            None => 1u64 << 63 | 1 << 60 | drain,
        };
        let r = self.iotlb_reg();
        self.w64(r, cmd);
        self.wait("an IOTLB invalidation", || self.r64(r) & (1 << 63) == 0);
    }

    fn covers(&self, bdf: Bdf) -> bool {
        self.scopes.contains(&bdf)
    }
}

struct State {
    units: Vec<Unit>,
}

static STATE: SpinLock<Option<State>> = SpinLock::new(c"iommu.vtd", rank::IOMMU, None);
static FAULT_VECTOR: AtomicU64 = AtomicU64::new(0);

// ---- DMAR ---------------------------------------------------------------------------------------

struct Drhd {
    base: u64,
    include_all: bool,
    scopes: Vec<Bdf>,
}

fn parse_dmar() -> Option<(u8, Vec<Drhd>, u32)> {
    let mut len = 0u32;
    // SAFETY: the C side returns a validated, mapped table of `len` bytes or NULL.
    let t = unsafe { ffi::acpi_find_table(b"DMAR".as_ptr(), &mut len) };
    if t.is_null() {
        return None;
    }
    // SAFETY: `len` bytes at `t` are mapped read-only for ever (firmware table).
    parse_dmar_bytes(unsafe { core::slice::from_raw_parts(t, len as usize) })
}

/// Fuzzing (ktest fuzz): parse `b` as a DMAR table and check what bring-up relies on. 0 = fine.
#[cfg(ktest_fuzz)]
pub fn fuzz_dmar(b: &[u8]) -> u32 {
    let Some((haw, units, _)) = parse_dmar_bytes(b) else { return 0 };
    if haw == 0 {
        return 1;
    }
    for u in &units {
        if u.base == 0 || u.base % PAGE != 0 || u.scopes.len() > b.len() / 8 {
            return 2;
        }
    }
    0
}

/// The DMAR table's bytes (untrusted): host address width, remapping units, RMRR count.
fn parse_dmar_bytes(b: &[u8]) -> Option<(u8, Vec<Drhd>, u32)> {
    if b.len() < 48 {
        return None;
    }
    let haw = b[36].saturating_add(1);
    let mut units = Vec::new();
    let mut rmrr = 0u32;
    let mut off = 48usize;
    while off + 4 <= b.len() {
        let ty = u16::from_le_bytes([b[off], b[off + 1]]);
        let l = usize::from(u16::from_le_bytes([b[off + 2], b[off + 3]]));
        if l < 4 || off + l > b.len() {
            break;
        }
        let s = &b[off..off + l];
        match ty {
            0 if l >= 16 => {
                let seg = u16::from_le_bytes([s[6], s[7]]);
                let base = u64::from_le_bytes(s[8..16].try_into().ok()?);
                let mut scopes = Vec::new();
                let mut p = 16;
                while p + 6 <= l {
                    let (sty, sl) = (s[p], usize::from(s[p + 1]));
                    if sl < 6 || p + sl > l {
                        break;
                    }
                    // Endpoint (1) or bridge (2) with a single-level path: start bus, (dev, fn).
                    if (sty == 1 || sty == 2) && sl == 8 && scopes.try_reserve(1).is_ok() {
                        scopes.push(Bdf::new(s[p + 5], s[p + 6], s[p + 7]));
                    }
                    p += sl;
                }
                if seg == 0 && base != 0 && base % PAGE == 0 && units.try_reserve(1).is_ok() {
                    units.push(Drhd { base, include_all: s[4] & 1 != 0, scopes });
                }
            }
            1 => rmrr += 1,
            _ => {}
        }
        off += l;
    }
    Some((haw, units, rmrr))
}

fn bring_up(d: &Drhd) -> Result<Unit, &'static str> {
    if d.base >= 1 << 46 {
        return Err("register base out of range");
    }
    // SAFETY: maps the unit's register page (device memory) uncached into the direct map.
    let regs = unsafe { ffi::vmm_map_phys(d.base, PAGE, ffi::VMM_W | ffi::VMM_UC) } as u64;
    let mut u = Unit { regs, cap: 0, ecap: 0, levels: 0, root: 0, include_all: d.include_all, scopes: Vec::new(), fault_regs: 0, nfr: 0 };
    if u.r32(VER) == 0xFFFF_FFFF {
        return Err("no unit at the register base");
    }
    u.cap = u.r64(CAP);
    u.ecap = u.r64(ECAP);
    let sagaw = (u.cap >> 8) & 0x1F;
    u.levels = if sagaw & 4 != 0 {
        4
    } else if sagaw & 2 != 0 {
        3
    } else {
        return Err("no supported address width (needs 3- or 4-level tables)");
    };
    u.fault_regs = ((u.cap >> 24) & 0x3FF) * 16;
    u.nfr = ((u.cap >> 40) & 0xFF) as u32 + 1;
    if u.fault_regs == 0 || u.fault_regs + u64::from(u.nfr) * 16 > PAGE || u.iotlb_reg() + 8 > PAGE {
        return Err("register layout outside the register page");
    }
    if u.r32(GSTS) & GSTS_TES != 0 {
        u.command(GCMD_TE, GSTS_TES, false); // firmware left it on: start from a clean state
    }
    u.root = alloc_table().map_err(|_| "out of memory")?;
    u.scopes = d.scopes.to_vec();
    u.w64(RTADDR, u.root);
    u.command(GCMD_SRTP, GSTS_RTPS, true);
    u.invalidate_context();
    u.invalidate_iotlb(None);
    Ok(u)
}

fn setup_faults(u: &Unit, vector: u32) {
    // SAFETY: plain read of the boot CPU's APIC id.
    let apic = unsafe { ffi::irq_target_apic() };
    u.w32(FEDATA, vector);
    u.w32(FEADDR, 0xFEE0_0000 | (apic << 12));
    u.w32(FEUADDR, 0);
    u.w32(FSTS, 0x7F); // clear stale overflow / pending bits (RW1C)
    u.w32(FECTL, 0); // unmask
}

/// Find and enable every DMA remapping unit. None without a DMAR table, else a status line.
pub fn init() -> Option<&'static str> {
    let (haw, drhds, rmrr) = parse_dmar()?;
    let mut units = Vec::new();
    for d in &drhds {
        match bring_up(d) {
            Ok(u) => {
                if units.try_reserve(1).is_ok() {
                    units.push(u);
                }
            }
            Err(e) => crate::kprintln!("IOMMU: unit at {:#x} unusable: {}", d.base, e),
        }
    }
    if units.is_empty() {
        return Some("no usable VT-d unit: device DMA is NOT confined, drivers are trusted with all memory");
    }
    // SAFETY: plain call; -1 when no vector is free.
    let v = unsafe { ffi::irq_vector_alloc() };
    if v >= 0 {
        FAULT_VECTOR.store(v as u64, Ordering::Release);
        for u in &units {
            setup_faults(u, v as u32);
        }
    }
    for u in &units {
        u.command(GCMD_TE, GSTS_TES, true);
    }
    let n = units.len();
    let levels = units[0].levels;
    *STATE.lock() = Some(State { units });
    set_backend(Backend::Vtd);
    crate::kprintln!(
        "IOMMU: Intel VT-d, {} unit(s), host address width {}, {}-level tables ({}-bit device addresses), {} RMRR(s) ignored",
        n,
        haw,
        levels,
        if levels == 4 { 48 } else { 39 },
        rmrr
    );
    Some("DMA remapping on for every device (default deny, faults reported)")
}

/// Create the domain of a device (its context entry, an empty page table). `did` must be unique.
pub fn domain_create(bdf: Bdf, did: u16) -> KResult<Domain> {
    let mut g = STATE.lock();
    let st = g.as_mut().ok_or(Status::NotSupported)?;
    let ui = st
        .units
        .iter()
        .position(|u| u.covers(bdf))
        .or_else(|| st.units.iter().position(|u| u.include_all))
        .ok_or(Status::NotSupported)?;
    let u = &st.units[ui];
    let nd = u.cap & 7;
    if u64::from(did) >= 1u64 << (4 + 2 * nd) || did == 0 {
        return Err(Status::NoResources);
    }
    let root_pa = alloc_table()?;
    // Root entry for the bus -> context table.
    let re = table(u.root).wrapping_add(usize::from(bdf.bus()) * 2);
    // SAFETY: `re` is entry `bus` (16 bytes) of the unit's root table page.
    let mut ctx = unsafe { core::ptr::read_volatile(re) };
    let mut new_ctx = false;
    if ctx & 1 == 0 {
        let pa = match alloc_table() {
            Ok(pa) => pa,
            Err(e) => {
                // SAFETY: the page was allocated above and is referenced nowhere.
                unsafe { ffi::pmm_free(root_pa) };
                return Err(e);
            }
        };
        ctx = pa | 1;
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(re, ctx) };
        u.flush(re as u64);
        new_ctx = true;
    }
    let ce = table(ctx & PTE_ADDR).wrapping_add(usize::from(bdf.0 & 0xFF) * 2);
    let aw: u64 = if u.levels == 4 { 2 } else { 1 };
    // SAFETY: entry devfn (16 bytes) of the bus's context table; the high word first, so the entry
    // only becomes present (low word, bit 0) once complete.
    unsafe {
        core::ptr::write_volatile(ce.wrapping_add(1), aw | u64::from(did) << 8);
        core::ptr::write_volatile(ce, root_pa | 1); // present, translation type 00: untranslated only
    }
    u.flush(ce as u64);
    // Non-present -> present needs no invalidation unless the unit caches non-present entries.
    if u.cap & (1 << 7) != 0 || new_ctx {
        u.invalidate_context();
        u.invalidate_iotlb(None);
    }
    Ok(Domain {
        backend: Backend::Vtd,
        unit: ui,
        did,
        root: root_pa,
        levels: u.levels,
        limit: if u.levels == 4 { 1 << 48 } else { 1 << 39 },
        tables: 1,
    })
}

/// Leaf entry for `iova`, creating page tables on the way.
fn walk(d: &mut Domain, u: &Unit, iova: u64) -> KResult<*mut u64> {
    let mut t = d.root;
    for level in (2..=d.levels).rev() {
        let e = table(t).wrapping_add(((iova >> (12 + 9 * (level - 1))) & 511) as usize);
        // SAFETY: an entry of a page table this domain owns (direct map).
        let v = unsafe { core::ptr::read_volatile(e) };
        t = if v & (PTE_R | PTE_W) != 0 {
            v & PTE_ADDR
        } else {
            let pa = alloc_table()?;
            d.tables += 1;
            // SAFETY: as above; non-leaf entries allow both, the leaf decides.
            unsafe { core::ptr::write_volatile(e, pa | PTE_R | PTE_W) };
            u.flush(e as u64);
            pa
        };
    }
    Ok(table(t).wrapping_add(((iova >> 12) & 511) as usize))
}

/// Map `frames` at `iova` (device may read; may write if `write`). On error nothing stays mapped.
pub fn map(d: &mut Domain, iova: u64, frames: &[u64], write: bool) -> KResult<()> {
    let g = STATE.lock();
    let st = g.as_ref().ok_or(Status::NotSupported)?;
    let u = &st.units[d.unit];
    let bits = PTE_R | if write { PTE_W } else { 0 };
    for (i, &pa) in frames.iter().enumerate() {
        let at = iova + i as u64 * PAGE;
        match walk(d, u, at) {
            Ok(e) => {
                // SAFETY: a leaf entry of this domain's tables.
                unsafe { core::ptr::write_volatile(e, pa | bits) };
                u.flush(e as u64);
            }
            Err(err) => {
                clear(d, u, iova, i as u64);
                u.invalidate_iotlb(Some(d.did));
                return Err(err);
            }
        }
    }
    if u.cap & (1 << 7) != 0 {
        u.invalidate_iotlb(Some(d.did)); // caching mode: non-present entries may be cached
    } else {
        u.flush_write_buffer();
    }
    Ok(())
}

fn clear(d: &mut Domain, u: &Unit, iova: u64, pages: u64) {
    for i in 0..pages {
        if let Ok(e) = walk(d, u, iova + i * PAGE) {
            // SAFETY: a leaf entry of this domain's tables (the walk only finds existing tables
            // for mapped addresses, so it allocates nothing here).
            unsafe { core::ptr::write_volatile(e, 0) };
            u.flush(e as u64);
        }
    }
}

/// Unmap and wait until no device can use the translations any more (the pages may be freed).
pub fn unmap(d: &mut Domain, iova: u64, pages: u64) {
    let g = STATE.lock();
    let Some(st) = g.as_ref() else { return };
    let u = &st.units[d.unit];
    clear(d, u, iova, pages);
    u.invalidate_iotlb(Some(d.did));
}

/// The fault vector fired: report and clear every recorded fault (interrupt context).
pub fn fault_irq(vector: u32) -> bool {
    if FAULT_VECTOR.load(Ordering::Acquire) != u64::from(vector) || vector == 0 {
        return false;
    }
    // Interrupts are off wherever the lock is held, so on this CPU nobody holds it now.
    let g = STATE.lock();
    let Some(st) = g.as_ref() else { return true };
    for u in &st.units {
        let fsts = u.r32(FSTS);
        if fsts & 2 != 0 {
            for i in 0..u.nfr {
                let off = u.fault_regs + u64::from(i) * 16;
                let hi = u.r64(off + 8);
                if hi & (1 << 63) == 0 {
                    continue;
                }
                let lo = u.r64(off);
                let sid = hi as u16;
                let reason = (hi >> 32) & 0xFF;
                let read = hi & (1 << 62) != 0;
                let mut why = crate::fmtbuf::FmtBuf::<48>::new();
                let _ = core::fmt::Write::write_fmt(
                    &mut why,
                    format_args!(
                        "fault reason {:#x}{}",
                        reason,
                        if matches!(reason, 2 | 5 | 6) { ": not mapped for this device" } else { "" }
                    ),
                );
                report(sid, lo, Some(!read), core::str::from_utf8(why.as_bytes()).unwrap_or("?"));
                u.w64(off + 8, 1 << 63); // clear F (RW1C)
            }
        }
        u.w32(FSTS, fsts & 0x7D); // overflow and other RW1C bits; PPF clears with the records
    }
    true
}
