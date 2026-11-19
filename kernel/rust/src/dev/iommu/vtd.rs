//! Intel VT-d backend (see `iommu`): root table (one entry per bus) -> context tables (one entry
//! per device/function: domain id, page-table root, address width) -> second-level page tables
//! (x86-like, 3 or 4 levels, R/W bits). Invalidation of the context cache and the IOTLB, globally
//! or per domain, waited for synchronously: through the registers, or through the invalidation
//! queue once interrupt remapping is on (it needs the queue, and the two may not be mixed).
//!
//! Interrupt remapping: one table of 256 entries shared by every unit, indexed by vector (every
//! device interrupt goes to the boot CPU and each vector has one owner). Each entry checks the
//! requester id (source-id verification), so a device can only raise the vectors bound to it;
//! compatibility-format interrupts (the plain MSI writes of before) are blocked. MSIs use the
//! remappable format; I/O APIC pins too, with their source ids from the DMAR's I/O APIC scopes.
//!
//! The DMAR table is firmware data: every structure is bounds-checked. Units are matched to
//! devices by their device scopes (single-level paths) or INCLUDE_PCI_ALL. RMRRs (endpoint scopes
//! with single-level paths) become firmware-reserved ranges, read/write.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::{Backend, Domain, PAGE, Reserved, alloc_table, report, report_irq, set_backend, table};
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
const IQH: u64 = 0x80;
const IQT: u64 = 0x88;
const IQA: u64 = 0x90;
const IRTA: u64 = 0xB8;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GCMD_WBF: u32 = 1 << 27;
const GCMD_QIE: u32 = 1 << 26;
const GCMD_IRE: u32 = 1 << 25;
const GCMD_SIRTP: u32 = 1 << 24;
const GCMD_CFI: u32 = 1 << 23;
const GSTS_TES: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;
const GSTS_WBFS: u32 = 1 << 27;
const GSTS_QIES: u32 = 1 << 26;
const GSTS_IRES: u32 = 1 << 25;
const GSTS_IRTPS: u32 = 1 << 24;
const GSTS_CFIS: u32 = 1 << 23;

const ECAP_QI: u64 = 1 << 1;
const ECAP_IR: u64 = 1 << 3;
const ECAP_EIM: u64 = 1 << 4;
const FSTS_IQE: u32 = 1 << 4;

/// Invalidation queue: one page of 256 descriptors (128-bit).
const QI_LEN: u32 = 256;
const IRTE_COUNT: usize = 256;
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
    qi: u64,          // physical address of the invalidation queue (0: register-based)
    qwait: u64,       // physical address of the queue's wait-status word
    qtail: AtomicU32, // next free descriptor
    qseq: AtomicU32,
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

    /// Queue one descriptor (the queue is drained after every batch, so it never fills).
    fn qi_push(&self, d0: u64, d1: u64) {
        let t = self.qtail.load(Ordering::Relaxed);
        let p = table(self.qi).wrapping_add(t as usize * 2);
        // SAFETY: descriptor `t` of this unit's queue page; the hardware reads it only once the
        // tail register moves past it.
        unsafe {
            core::ptr::write_volatile(p, d0);
            core::ptr::write_volatile(p.wrapping_add(1), d1);
        }
        self.qtail.store((t + 1) % QI_LEN, Ordering::Relaxed);
    }

    /// Start the queued descriptors and wait until all of them have completed.
    fn qi_sync(&self) {
        let seq = self.qseq.load(Ordering::Relaxed).wrapping_add(1);
        self.qseq.store(seq, Ordering::Relaxed);
        // Invalidation wait: status write (SW) of `seq` to the wait word.
        self.qi_push(0x5 | 1 << 5 | u64::from(seq) << 32, self.qwait);
        core::sync::atomic::fence(Ordering::SeqCst); // table and descriptor writes before the tail
        self.w64(IQT, u64::from(self.qtail.load(Ordering::Relaxed)) << 4);
        let word = table(self.qwait) as *const u32;
        for _ in 0..10_000_000u32 {
            // SAFETY: the unit's wait-status word (direct map), written by the hardware.
            if unsafe { core::ptr::read_volatile(word) } == seq {
                return;
            }
            if self.r32(FSTS) & FSTS_IQE != 0 {
                panic!("IOMMU: VT-d unit at {:#x} rejected an invalidation descriptor (head {:#x})", self.regs, self.r64(IQH));
            }
            core::hint::spin_loop();
        }
        panic!("IOMMU: VT-d unit at {:#x} did not complete its invalidation queue", self.regs);
    }

    fn invalidate_context(&self) {
        self.flush_write_buffer();
        if self.qi != 0 {
            self.qi_push(0x1 | 1 << 4, 0); // context cache, global
            self.qi_sync();
            return;
        }
        self.w64(CCMD, 1 << 63 | 1 << 61); // ICC, global
        self.wait("a context-cache invalidation", || self.r64(CCMD) & (1 << 63) == 0);
    }

    /// Interrupt entry cache: one entry, or all (`None`). Queue only.
    fn invalidate_iec(&self, index: Option<u16>) {
        let d0 = match index {
            Some(i) => 0x4 | 1 << 4 | u64::from(i) << 32,
            None => 0x4,
        };
        self.qi_push(d0, 0);
        self.qi_sync();
    }

    /// IOTLB: per domain (`did`), or everything (`None`). Drains reads and writes if supported.
    fn invalidate_iotlb(&self, did: Option<u16>) {
        self.flush_write_buffer();
        if self.qi != 0 {
            let drain = (if self.cap & (1 << 55) != 0 { 1u64 << 7 } else { 0 }) | if self.cap & (1 << 54) != 0 { 1 << 6 } else { 0 };
            let d0 = match did {
                Some(d) => 0x2 | 2 << 4 | drain | u64::from(d) << 16,
                None => 0x2 | 1 << 4 | drain,
            };
            self.qi_push(d0, 0);
            self.qi_sync();
            return;
        }
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
    /// Interrupt remapping: the shared table (0: off), the destination field every entry uses,
    /// and the I/O APICs' source ids (id, requester id).
    irt: u64,
    dest: u64,
    ioapics: [(u8, u16); 8],
    nioapic: usize,
}

static STATE: SpinLock<Option<State>> = SpinLock::new(c"iommu.vtd", rank::IOMMU, None);
static FAULT_VECTOR: AtomicU64 = AtomicU64::new(0);

// ---- DMAR ---------------------------------------------------------------------------------------

struct Drhd {
    base: u64,
    include_all: bool,
    scopes: Vec<Bdf>,
    ioapics: Vec<(u8, Bdf)>, // I/O APIC scopes: (I/O APIC id, its requester id)
}

struct Dmar {
    haw: u8,
    intr_remap: bool, // the firmware says interrupt remapping is supported (flags bit 0)
    units: Vec<Drhd>,
    rmrrs: Vec<Reserved>,
}

fn parse_dmar() -> Option<Dmar> {
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
    let Some(Dmar { haw, units, rmrrs, .. }) = parse_dmar_bytes(b) else { return 0 };
    if haw == 0 {
        return 1;
    }
    for u in &units {
        if u.base == 0 || u.base % PAGE != 0 || u.scopes.len() + u.ioapics.len() > b.len() / 8 {
            return 2;
        }
    }
    if rmrrs.len() > b.len() / 8 || rmrrs.iter().any(|r| r.first != r.last || r.start >= r.end || (r.start | r.end) % PAGE != 0) {
        return 3;
    }
    0
}

/// The DMAR table's bytes (untrusted): host address width, remapping units, RMRRs (one range per
/// device in scope).
fn parse_dmar_bytes(b: &[u8]) -> Option<Dmar> {
    if b.len() < 48 {
        return None;
    }
    let haw = b[36].saturating_add(1);
    let mut units = Vec::new();
    let mut rmrrs: Vec<Reserved> = Vec::new();
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
                let mut ioapics = Vec::new();
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
                    // I/O APIC (3): enumeration id = its APIC id.
                    if sty == 3 && sl == 8 && ioapics.len() < 8 && ioapics.try_reserve(1).is_ok() {
                        ioapics.push((s[p + 4], Bdf::new(s[p + 5], s[p + 6], s[p + 7])));
                    }
                    p += sl;
                }
                if seg == 0 && base != 0 && base % PAGE == 0 && units.try_reserve(1).is_ok() {
                    units.push(Drhd { base, include_all: s[4] & 1 != 0, scopes, ioapics });
                }
            }
            1 if l >= 24 => {
                let seg = u16::from_le_bytes([s[6], s[7]]);
                let base = u64::from_le_bytes(s[8..16].try_into().ok()?);
                let limit = u64::from_le_bytes(s[16..24].try_into().ok()?);
                let mut p = 24;
                while seg == 0 && p + 6 <= l {
                    let (sty, sl) = (s[p], usize::from(s[p + 1]));
                    if sl < 6 || p + sl > l {
                        break;
                    }
                    if sty == 1
                        && sl == 8
                        && rmrrs.len() < 256
                        && let Some(r) = Reserved::new(0, 0, base, limit, true, "RMRR")
                        && rmrrs.try_reserve(1).is_ok()
                    {
                        let id = Bdf::new(s[p + 5], s[p + 6], s[p + 7]).0;
                        rmrrs.push(Reserved { first: id, last: id, ..r });
                    }
                    p += sl;
                }
            }
            _ => {}
        }
        off += l;
    }
    Some(Dmar { haw, intr_remap: b[37] & 1 != 0, units, rmrrs })
}

fn bring_up(d: &Drhd) -> Result<Unit, &'static str> {
    if d.base >= 1 << 46 {
        return Err("register base out of range");
    }
    // SAFETY: maps the unit's register page (device memory) uncached into the direct map.
    let regs = unsafe { ffi::vmm_map_phys(d.base, PAGE, ffi::VMM_W | ffi::VMM_UC) } as u64;
    let mut u = Unit {
        regs,
        cap: 0,
        ecap: 0,
        levels: 0,
        root: 0,
        include_all: d.include_all,
        scopes: Vec::new(),
        fault_regs: 0,
        nfr: 0,
        qi: 0,
        qwait: 0,
        qtail: AtomicU32::new(0),
        qseq: AtomicU32::new(0),
    };
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
    // Whatever the firmware left on goes first: translation, interrupt remapping, the queue
    // (register-based invalidation is not allowed while it is on).
    if u.r32(GSTS) & GSTS_TES != 0 {
        u.command(GCMD_TE, GSTS_TES, false);
    }
    if u.r32(GSTS) & GSTS_IRES != 0 {
        u.command(GCMD_IRE, GSTS_IRES, false);
    }
    if u.r32(GSTS) & GSTS_QIES != 0 {
        u.command(GCMD_QIE, GSTS_QIES, false);
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

/// Find and enable every DMA remapping unit. None without a DMAR table, else a status line, the
/// RMRRs and the highest domain id every unit supports.
pub fn init() -> Option<(&'static str, Vec<Reserved>, u16)> {
    let Dmar { haw, intr_remap, units: drhds, rmrrs } = parse_dmar()?;
    let none = |s| Some((s, Vec::new(), 0));
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
        return none("no usable VT-d unit: device DMA is NOT confined, drivers are trusted with all memory");
    }
    let max_did = units.iter().map(|u| (1u32 << (4 + 2 * (u.cap & 7).min(6))) - 1).min().unwrap_or(0).min(0xFFFF) as u16;
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
    let mut st = State { units, irt: 0, dest: 0, ioapics: [(0, 0); 8], nioapic: 0 };
    let ir = ir_enable(&mut st, &drhds, intr_remap);
    *STATE.lock() = Some(st);
    set_backend(Backend::Vtd);
    crate::kprintln!(
        "IOMMU: Intel VT-d, {} unit(s), host address width {}, {}-level tables ({}-bit device addresses), {} RMRR device range(s)",
        n,
        haw,
        levels,
        if levels == 4 { 48 } else { 39 },
        rmrrs.len()
    );
    super::ir_result(Backend::Vtd, ir);
    Some(("DMA remapping on for every device (default deny, faults reported)", rmrrs, max_did))
}

// ---- interrupt remapping ------------------------------------------------------------------------

/// Switch interrupt remapping on for every unit (all or none): the queue, the table, then IRE with
/// compatibility-format interrupts blocked. Ok: a description; Err: why it stays off.
fn ir_enable(st: &mut State, drhds: &[Drhd], intr_remap: bool) -> Result<&'static str, &'static str> {
    if !intr_remap {
        return Err("the DMAR does not offer it");
    }
    if st.units.iter().any(|u| u.ecap & (ECAP_IR | ECAP_QI) != ECAP_IR | ECAP_QI) {
        return Err("a unit has no interrupt remapping or invalidation queue");
    }
    // Every I/O APIC in use needs its source id, else its interrupts could not be verified.
    let mut ids = [0u8; 8];
    // SAFETY: writes at most 8 ids into `ids`.
    let nids = unsafe { ffi::ioapic_ids(ids.as_mut_ptr(), 8) } as usize;
    for &id in &ids[..nids.min(8)] {
        let Some(sid) = drhds.iter().flat_map(|d| d.ioapics.iter()).find(|(i, _)| *i == id).map(|(_, b)| b.0) else {
            return Err("an I/O APIC in use is missing from the DMAR");
        };
        st.ioapics[st.nioapic] = (id, sid);
        st.nioapic += 1;
    }
    // SAFETY: plain reads.
    let (x2apic, apic) = unsafe { (ffi::lapic_x2apic(), ffi::irq_target_apic()) };
    let eime = x2apic && st.units.iter().all(|u| u.ecap & ECAP_EIM != 0);
    if !eime && apic > 0xFF {
        return Err("the boot CPU's APIC id needs the extended (x2APIC) format");
    }
    st.dest = if eime { u64::from(apic) << 32 } else { u64::from(apic & 0xFF) << 40 };
    // Every page first, so a shortage leaves every unit as it was (register-based, IR off).
    let mut pages = [0u64; 1 + 2 * 16];
    let need = 1 + 2 * st.units.len();
    if need > pages.len() {
        return Err("too many units");
    }
    for i in 0..need {
        match alloc_table() {
            Ok(pa) => pages[i] = pa,
            Err(_) => {
                for &pa in &pages[..i] {
                    // SAFETY: pages allocated just above and referenced nowhere.
                    unsafe { ffi::pmm_free(pa) };
                }
                return Err("out of memory");
            }
        }
    }
    st.irt = pages[0];
    for (i, u) in st.units.iter_mut().enumerate() {
        u.qi = pages[1 + 2 * i];
        u.qwait = pages[2 + 2 * i];
    }
    // The pins routed so far (the serial port's) get their entries before IRE: only the moment
    // between IRE and `ioapic_reroute` rewriting them in remappable format is left uncovered.
    for &(id, sid) in &st.ioapics[..st.nioapic] {
        let mut routed = [0u16; 256];
        // SAFETY: writes at most 256 entries into `routed`.
        let n = unsafe { ffi::ioapic_routed(id, routed.as_mut_ptr(), 256) } as usize;
        for &r in &routed[..n.min(256)] {
            irte_fill(st, r as u8, sid, r & 0x100 != 0);
        }
    }
    for u in &mut st.units {
        u.w64(IQT, 0);
        u.w64(IQA, u.qi); // one page (QS 0), 128-bit descriptors
        u.command(GCMD_QIE, GSTS_QIES, true);
        u.w64(IRTA, st.irt | u64::from(eime) << 11 | 7); // 2^(7+1) = 256 entries
        u.command(GCMD_SIRTP, GSTS_IRTPS, true);
        u.invalidate_iec(None);
        if u.r32(GSTS) & GSTS_CFIS != 0 {
            u.command(GCMD_CFI, GSTS_CFIS, false);
        }
        u.command(GCMD_IRE, GSTS_IRES, true);
    }
    Ok(if eime { "x2APIC destinations" } else { "xAPIC destinations" })
}

/// Point entry `vector` at the boot CPU for requester `sid` only (`level`: level-triggered).
fn irte_write(st: &State, vector: u8, sid: u16, level: bool) {
    let e = irte_fill(st, vector, sid, level);
    irte_done(st, e, vector);
}

/// Write entry `vector` without invalidating (the caller does, or remapping is not on yet).
fn irte_fill(st: &State, vector: u8, sid: u16, level: bool) -> *mut u64 {
    let e = table(st.irt).wrapping_add(usize::from(vector) * 2);
    // SAFETY: entry `vector` (16 bytes) of the shared table. Not present while it changes; the
    // low quad (with P) goes last.
    unsafe {
        core::ptr::write_volatile(e, 0);
        core::ptr::write_volatile(e.wrapping_add(1), u64::from(sid) | 1 << 18); // SVT 01: all 16 bits of the SID
        core::ptr::write_volatile(e, 1 | u64::from(level) << 4 | u64::from(vector) << 16 | st.dest);
    }
    for u in &st.units {
        u.flush(e as u64);
    }
    e
}

fn irte_done(st: &State, e: *mut u64, vector: u8) {
    for u in &st.units {
        u.flush(e as u64);
        u.invalidate_iec(Some(u16::from(vector)));
    }
}

/// Install the entry for a device's MSI on `vector`; returns its MSI address and data
/// (remappable format, handle = vector).
pub fn ir_msi(sid: u16, vector: u32) -> KResult<(u64, u32)> {
    let g = STATE.lock();
    let st = g.as_ref().ok_or(Status::NotSupported)?;
    if st.irt == 0 || vector as usize >= IRTE_COUNT {
        return Err(Status::NotSupported);
    }
    irte_write(st, vector as u8, sid, false);
    Ok((0xFEE0_0000 | u64::from(vector) << 5 | 1 << 4, 0))
}

/// Install the entry for an I/O APIC pin; returns the pin's high dword (remappable format).
pub fn ir_ioapic(id: u8, vector: u8, level: bool) -> Option<u32> {
    let g = STATE.lock();
    let st = g.as_ref()?;
    let sid = st.ioapics[..st.nioapic].iter().find(|(i, _)| *i == id)?.1;
    irte_write(st, vector, sid, level);
    Some(1 << 16 | u32::from(vector) << 17) // format 1, handle[14:0] = vector
}

/// Remove the entry of `vector`.
pub fn ir_clear(vector: u32) {
    let g = STATE.lock();
    let Some(st) = g.as_ref() else { return };
    if st.irt == 0 || vector as usize >= IRTE_COUNT {
        return;
    }
    let e = table(st.irt).wrapping_add(vector as usize * 2);
    // SAFETY: entry `vector` of the shared table: not present.
    unsafe { core::ptr::write_volatile(e, 0) };
    irte_done(st, e, vector as u8);
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

/// Test images: what `iova` translates to in `d` (frame, writable), without allocating.
#[cfg(ktest_drivers)]
pub fn lookup(d: &Domain, iova: u64) -> Option<(u64, bool)> {
    let _g = STATE.lock();
    let mut t = d.root;
    for level in (1..=d.levels).rev() {
        // SAFETY: an entry of a page table this domain owns (direct map), read under the lock.
        let v = unsafe { core::ptr::read_volatile(table(t).wrapping_add(((iova >> (12 + 9 * (level - 1))) & 511) as usize)) };
        if v & (PTE_R | PTE_W) == 0 {
            return None;
        }
        if level == 1 {
            return Some((v & PTE_ADDR, v & PTE_W != 0));
        }
        t = v & PTE_ADDR;
    }
    None
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
                if (0x20..0x30).contains(&reason) {
                    // Interrupt remapping fault: the handle is in bits 63:48 of the low quad.
                    report_irq(sid, (lo >> 48) as u32, reason as u32);
                    u.w64(off + 8, 1 << 63);
                    continue;
                }
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
