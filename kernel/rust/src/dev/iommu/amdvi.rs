//! AMD-Vi backend (see `iommu`): one device table shared by every IOMMU (one 256-bit entry per
//! requester id: domain id, page-table root, paging mode, read/write permission) -> host page
//! tables in the AMD "v1" format (4 levels, 48-bit device addresses, a next-level field per entry
//! and R/W permission at every level). Each IOMMU has a command buffer (device-table and page
//! invalidations, completion waits polled from memory) and an event log, drained by an MSI from
//! the IOMMU's own PCI function.
//!
//! Default deny: every one of the 65 536 device table entries is valid, translates with 4-level
//! paging through one shared, empty top-level table and grants no permission, so a device
//! without a domain reaches nothing and each attempt is logged as an IO page fault. (Paging off,
//! `Mode` 0, would also deny on real hardware but is emulated as passthrough by QEMU.) A domain
//! gets its own root and read/write permission; only pinned pages are mapped. Every entry is
//! invalidated once at bring-up, so no cached firmware state survives.
//!
//! The IVRS table is firmware data: every structure is bounds-checked. IOMMUs are matched to
//! devices by their IVHD device entries (select, range, alias, extended); a device no IVHD names
//! goes to the IOMMU that names "all", else the first one. The IOMMU's own PCI function is
//! kernel-owned (never handed to a driver). IVMD blocks (all devices, one, a range) with the unity
//! or exclusion flag become firmware-reserved ranges (an exclusion range is identity mapped too,
//! as Linux does; never through the exclusion registers).
//!
//! Interrupt remapping (when every I/O APIC in use is named by an IVHD special entry): every device
//! table entry has `IV` set and `IntCtl` 00, so an interrupt from a device without a table is
//! aborted. A device that binds an interrupt gets its own table (256 32-bit entries, indexed by
//! the MSI data = vector), so it can only raise its own vectors; each I/O APIC has one too (the
//! pin's vector field is the index, so the pins need no change). The IOMMU's own function forwards
//! its interrupts unmapped (they are the IOMMU's, not a driver's).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{Backend, Domain, PAGE, Reserved, alloc_table, report, report_irq, set_backend, table};
use crate::dev::pci::{self, Bdf};
use crate::ffi::{self, rank};
use crate::object::{KResult, Status};
use crate::sync::SpinLock;

// Registers (MMIO, 16 KiB at the IVHD base)
const DEV_TABLE: u64 = 0x0000;
const CMD_BASE: u64 = 0x0008;
const EVT_BASE: u64 = 0x0010;
const CONTROL: u64 = 0x0018;
const EXT_FEATURES: u64 = 0x0030;
const CMD_HEAD: u64 = 0x2000;
const CMD_TAIL: u64 = 0x2008;
const EVT_HEAD: u64 = 0x2010;
const EVT_TAIL: u64 = 0x2018;
const STATUS: u64 = 0x2020;
const MMIO_SIZE: u64 = 0x4000;

const CTL_EN: u64 = 1 << 0;
const CTL_EVT_LOG: u64 = 1 << 2;
const CTL_EVT_INT: u64 = 1 << 3;
const CTL_CMD_BUF: u64 = 1 << 12;

const ST_EVT_OVERFLOW: u64 = 1 << 0;
const ST_EVT_INT: u64 = 1 << 1;
const ST_COMP_INT: u64 = 1 << 2;

const EFR_IA: u64 = 1 << 6; // INVALIDATE_IOMMU_ALL supported

/// Command buffer and event log: one page each, 256 entries of 16 bytes (length code 8).
const RING_LEN_CODE: u64 = 8;
const RING_BYTES: u32 = 4096;

// Device table entry, quad 0
const DTE_V: u64 = 1 << 0;
const DTE_TV: u64 = 1 << 1;
const DTE_MODE_SHIFT: u32 = 9;
const DTE_IR: u64 = 1 << 61;
const DTE_IW: u64 = 1 << 62;
// Device table entry, quad 2 (interrupts)
const DTE_IV: u64 = 1 << 0;
const DTE_INT_LEN_256: u64 = 8 << 1; // 2^8 entries
const DTE_INT_ADDR: u64 = 0x000F_FFFF_FFFF_FFC0;
const DTE_INTCTL_PASS: u64 = 1 << 60;
const DTE_INTCTL_REMAP: u64 = 2 << 60;
const DTE_INTCTL_MASK: u64 = 3 << 60;
/// Every device ID (bus 0-255): 65 536 entries of 32 bytes = 2 MiB, 512 pages.
const DEVTAB_PAGES: u64 = 512;
const DEVTAB_ENTRIES: usize = 65_536;

// Page-table entries (PTE and PDE)
const PTE_PR: u64 = 1 << 0;
const PTE_NEXT_SHIFT: u32 = 9;
const PTE_IR: u64 = 1 << 61;
const PTE_IW: u64 = 1 << 62;
const PTE_ADDR: u64 = 0x000F_FFFF_FFFF_F000;

const LEVELS: u32 = 4;

// Commands (opcode in bits 63:60 of the first quad)
const CMD_COMPLETION_WAIT: u64 = 0x1 << 60;
const CMD_INVAL_DEVTAB: u64 = 0x2 << 60;
const CMD_INVAL_PAGES: u64 = 0x3 << 60;
const CMD_INVAL_INTTAB: u64 = 0x5 << 60;
const CMD_INVAL_ALL: u64 = 0x8 << 60;

struct Unit {
    regs: u64, // virtual address of the register block
    base: u64,
    func: Bdf, // the IOMMU's own PCI function (kernel-owned)
    efr: u64,
    np_cache: bool, // may cache non-present entries: invalidate after a map too
    all: bool,
    ranges: Vec<(u16, u16)>,
    cmd: u64,  // physical address of the command buffer
    tail: u32, // next command slot (bytes)
    evt: u64,  // physical address of the event log
    wait: u64, // physical address of the completion-wait word
    seq: u64,
}

impl Unit {
    fn r64(&self, off: u64) -> u64 {
        // SAFETY: an aligned register inside the unit's mapped register block.
        unsafe { core::ptr::read_volatile((self.regs + off) as *const u64) }
    }
    fn w64(&self, off: u64, v: u64) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.regs + off) as *mut u64, v) }
    }

    fn covers(&self, id: u16) -> bool {
        self.ranges.iter().any(|&(s, e)| s <= id && id <= e)
    }

    /// Queue one command (16 bytes) without starting it.
    fn push(&mut self, c0: u64, c1: u64) {
        let next = (self.tail + 16) % RING_BYTES;
        for _ in 0..10_000_000u32 {
            if self.r64(CMD_HEAD) as u32 & (RING_BYTES - 1) != next {
                break;
            }
            core::hint::spin_loop();
        }
        let p = table(self.cmd).wrapping_add(self.tail as usize / 8);
        // SAFETY: slot `tail` of this unit's command buffer page; the hardware reads it only once
        // the tail register moves past it.
        unsafe {
            core::ptr::write_volatile(p, c0);
            core::ptr::write_volatile(p.wrapping_add(1), c1);
        }
        self.tail = next;
    }

    /// Start the queued commands and wait until all of them have completed.
    fn sync(&mut self) {
        self.seq += 1;
        let seq = self.seq;
        // COMPLETION_WAIT, store `seq` at the wait word (S = bit 0) once everything before is done.
        self.push(self.wait | CMD_COMPLETION_WAIT | 1, seq);
        core::sync::atomic::fence(Ordering::SeqCst); // table and command writes before the tail
        self.w64(CMD_TAIL, u64::from(self.tail));
        let word = table(self.wait);
        for _ in 0..10_000_000u32 {
            // SAFETY: the unit's completion-wait word (direct map), written by the hardware.
            if unsafe { core::ptr::read_volatile(word) } == seq {
                return;
            }
            core::hint::spin_loop();
        }
        panic!("IOMMU: AMD-Vi unit at {:#x} did not complete its commands", self.base);
    }

    fn inval_devtab(&mut self, id: u16) {
        self.push(CMD_INVAL_DEVTAB | u64::from(id), 0);
    }

    fn inval_inttab(&mut self, id: u16) {
        self.push(CMD_INVAL_INTTAB | u64::from(id), 0);
    }

    /// Every cached translation of domain `did` (S = 1 and the all-ones address: the whole space;
    /// PDE = 1: directory entries too).
    fn inval_domain(&mut self, did: u16) {
        self.push(CMD_INVAL_PAGES | u64::from(did) << 32, 0x7FFF_FFFF_FFFF_F000 | 0b11);
    }
}

struct State {
    units: Vec<Unit>,
    devtab: u64, // physical address of the shared device table
    /// Interrupt remapping: on, the boot CPU's APIC id, the I/O APICs (id, device id).
    ir: bool,
    dest: u8,
    ioapics: [(u8, u16); 8],
    nioapic: usize,
}

static STATE: SpinLock<Option<State>> = SpinLock::new(c"iommu.amdvi", rank::IOMMU, None);
static FAULT_VECTOR: AtomicU64 = AtomicU64::new(0);
/// The IOMMUs' own PCI functions (bdf + 1, 0 = none), readable without the lock.
static OWNED: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

// ---- IVRS ---------------------------------------------------------------------------------------

struct Ivhd {
    base: u64,
    func: u16,
    cap: u16,
    all: bool,
    no_translation: bool,
    ranges: Vec<(u16, u16)>,
    ioapics: Vec<(u8, u16)>, // special entries: (I/O APIC id, its device id)
}

fn parse_ivrs() -> Option<(Vec<Ivhd>, Vec<Reserved>)> {
    let mut len = 0u32;
    // SAFETY: the C side returns a validated, mapped table of `len` bytes or NULL.
    let t = unsafe { ffi::acpi_find_table(b"IVRS".as_ptr(), &mut len) };
    if t.is_null() {
        return None;
    }
    // SAFETY: `len` bytes at `t` are mapped read-only for ever (firmware table).
    parse_ivrs_bytes(unsafe { core::slice::from_raw_parts(t, len as usize) })
}

/// Fuzzing (ktest fuzz): parse `b` as an IVRS table and check what bring-up relies on. 0 = fine.
#[cfg(ktest_fuzz)]
pub fn fuzz_ivrs(b: &[u8]) -> u32 {
    let Some((units, ivmds)) = parse_ivrs_bytes(b) else { return 0 };
    if ivmds.len() > b.len() / 32 || ivmds.iter().any(|r| r.first > r.last || r.start >= r.end || (r.start | r.end) % PAGE != 0) {
        return 4;
    }
    for (i, u) in units.iter().enumerate() {
        if u.base == 0 || u.base % MMIO_SIZE != 0 || u.base >= 1 << 46 {
            return 1;
        }
        if u.ranges.len() + u.ioapics.len() > b.len() / 4 || u.ranges.iter().any(|&(s, e)| s > e) {
            return 2;
        }
        if units[..i].iter().any(|o| o.base == u.base) {
            return 3;
        }
    }
    0
}

/// Device entries of one IVHD block (`e`: the bytes after its header). Ranges are inclusive.
fn parse_entries(e: &[u8], all: &mut bool, ranges: &mut Vec<(u16, u16)>, ioapics: &mut Vec<(u8, u16)>) {
    let mut p = 0usize;
    let mut start: Option<u16> = None;
    while p + 4 <= e.len() {
        let ty = e[p];
        let id = u16::from_le_bytes([e[p + 1], e[p + 2]]);
        let size = match ty {
            0..=0x3F => 4,
            0x40..=0x7F => 8,
            // ACPI HID device: 22 bytes, then a UID of the length in byte 21.
            0xF0 if p + 22 <= e.len() => 22 + usize::from(e[p + 21]),
            _ => break, // unknown variable-length entry: its size is unknown, stop here
        };
        if p + size > e.len() {
            break;
        }
        let mut add = |r: (u16, u16)| {
            if r.0 <= r.1 && ranges.len() < 1024 && ranges.try_reserve(1).is_ok() {
                ranges.push(r);
            }
        };
        match ty {
            1 => *all = true,
            2 | 0x42 | 0x46 => add((id, id)),
            3 | 0x43 | 0x47 => start = Some(id),
            4 => {
                if let Some(s) = start.take() {
                    add((s, id));
                }
            }
            // Special device: handle (byte 4), device id (5-6), variety (7; 1 = I/O APIC).
            0x48 if e[p + 7] == 1 && ioapics.len() < 8 && ioapics.try_reserve(1).is_ok() => {
                ioapics.push((e[p + 4], u16::from_le_bytes([e[p + 5], e[p + 6]])));
            }
            _ => {} // padding, special devices (IOAPIC/HPET), ACPI devices: no PCI requester id
        }
        p += size;
    }
}

/// The IVRS table's bytes (untrusted): the IOMMUs (one per register base), the IVMD ranges.
fn parse_ivrs_bytes(b: &[u8]) -> Option<(Vec<Ivhd>, Vec<Reserved>)> {
    if b.len() < 48 {
        return None;
    }
    let mut units: Vec<Ivhd> = Vec::new();
    let mut ivmds: Vec<Reserved> = Vec::new();
    let mut off = 48usize;
    while off + 4 <= b.len() {
        let ty = b[off];
        let l = usize::from(u16::from_le_bytes([b[off + 2], b[off + 3]]));
        if l < 4 || off + l > b.len() {
            break;
        }
        let s = &b[off..off + l];
        match ty {
            0x10 | 0x11 | 0x40 => {
                let hdr = if ty == 0x10 { 24 } else { 40 };
                if l >= hdr {
                    let func = u16::from_le_bytes([s[4], s[5]]);
                    let cap = u16::from_le_bytes([s[6], s[7]]);
                    let base = u64::from_le_bytes(s[8..16].try_into().ok()?);
                    let seg = u16::from_le_bytes([s[16], s[17]]);
                    let attrs = u32::from_le_bytes(s[20..24].try_into().ok()?);
                    // Firmware lists one IOMMU several times (types 10h and 11h): the first wins.
                    let dup = units.iter().any(|u| u.base == base);
                    if seg == 0 && base != 0 && base % MMIO_SIZE == 0 && base < 1 << 46 && !dup && units.len() < 8 {
                        let mut u = Ivhd {
                            base,
                            func,
                            cap,
                            all: false,
                            no_translation: ty != 0x10 && attrs & 1 != 0, // HATDis
                            ranges: Vec::new(),
                            ioapics: Vec::new(),
                        };
                        parse_entries(&s[hdr..], &mut u.all, &mut u.ranges, &mut u.ioapics);
                        if units.try_reserve(1).is_ok() {
                            units.push(u);
                        }
                    }
                }
            }
            0x20..=0x22 if l >= 32 => {
                // Flags: unity (0), read (1), write (2), exclusion range (3).
                let flags = s[1];
                let id = u16::from_le_bytes([s[4], s[5]]);
                let (first, last) = match ty {
                    0x20 => (0, u16::MAX),
                    0x21 => (id, id),
                    _ => (id, u16::from_le_bytes([s[6], s[7]])),
                };
                let start = u64::from_le_bytes(s[16..24].try_into().ok()?);
                let len = u64::from_le_bytes(s[24..32].try_into().ok()?);
                let excl = flags & 8 != 0;
                let usable = excl || (flags & 1 != 0 && flags & 6 != 0);
                if usable
                    && len != 0
                    && ivmds.len() < 256
                    && let Some(last_byte) = start.checked_add(len - 1)
                    && let Some(r) = Reserved::new(first, last, start, last_byte, excl || flags & 4 != 0, "IVMD")
                    && ivmds.try_reserve(1).is_ok()
                {
                    ivmds.push(r);
                }
            }
            _ => {}
        }
        off += l;
    }
    Some((units, ivmds))
}

// ---- bring-up -----------------------------------------------------------------------------------

/// Point the IOMMU's MSI capability at `vector` (boot CPU) and let the function master the bus.
fn setup_msi(func: Bdf, vector: u32) -> bool {
    let (addr, data) = crate::dev::irq::msi_message(vector);
    let mut p = pci::read(func, 0x34, 1) as u16 & 0xFC;
    for _ in 0..48 {
        if p < 0x40 {
            return false;
        }
        let id = pci::read(func, p, 1) as u8;
        if id == 0x05 {
            let ctl = pci::read(func, p + 2, 2) as u16;
            pci::write(func, p + 4, 4, addr as u32);
            let data_off = if ctl & (1 << 7) != 0 {
                pci::write(func, p + 8, 4, (addr >> 32) as u32);
                p + 12
            } else {
                p + 8
            };
            pci::write(func, data_off, 2, data);
            pci::write(func, p + 2, 2, u32::from((ctl & !(7 << 4)) | 1)); // one vector, enabled
            let cmd = pci::read(func, 0x04, 2);
            pci::write(func, 0x04, 2, cmd | 1 << 2); // bus master: its MSI is a memory write
            return true;
        }
        p = pci::read(func, p + 1, 1) as u16 & 0xFC;
    }
    false
}

fn bring_up(d: &Ivhd, devtab: u64) -> Result<Unit, &'static str> {
    if d.no_translation {
        return Err("host address translation disabled by the firmware (HATDis)");
    }
    // SAFETY: maps the unit's register block (device memory) uncached into the direct map.
    let regs = unsafe { ffi::vmm_map_phys(d.base, MMIO_SIZE, ffi::VMM_W | ffi::VMM_UC) } as u64;
    let mut u = Unit {
        regs,
        base: d.base,
        func: Bdf(d.func),
        efr: 0,
        np_cache: false,
        all: d.all,
        ranges: Vec::new(),
        cmd: 0,
        tail: 0,
        evt: 0,
        wait: 0,
        seq: 0,
    };
    if u.r64(STATUS) == u64::MAX {
        return Err("no unit at the register base");
    }
    let caph = pci::read(u.func, d.cap & 0xFC, 4);
    if caph & 0xFF != 0x0F {
        return Err("no IOMMU capability at the IVHD's offset");
    }
    u.np_cache = caph & (1 << 26) != 0;
    u.efr = if caph & (1 << 27) != 0 { u.r64(EXT_FEATURES) } else { 0 };
    if (u.efr >> 10) & 3 == 3 {
        return Err("no host page tables (HATS reserved)");
    }
    if u.r64(CONTROL) & CTL_EN != 0 {
        u.w64(CONTROL, 0); // firmware left it on: start from a clean state
    }
    u.cmd = alloc_table().map_err(|_| "out of memory")?;
    u.evt = alloc_table().map_err(|_| "out of memory")?;
    u.wait = alloc_table().map_err(|_| "out of memory")?;
    u.ranges = d.ranges.to_vec();
    u.w64(DEV_TABLE, devtab | (DEVTAB_PAGES - 1));
    u.w64(CMD_BASE, u.cmd | RING_LEN_CODE << 56);
    u.w64(CMD_HEAD, 0);
    u.w64(CMD_TAIL, 0);
    u.w64(STATUS, ST_EVT_OVERFLOW | ST_EVT_INT | ST_COMP_INT); // RW1C
    u.w64(EVT_BASE, u.evt | RING_LEN_CODE << 56);
    u.w64(EVT_HEAD, 0);
    u.w64(EVT_TAIL, 0);
    Ok(u)
}

/// Find and enable every AMD-Vi IOMMU. None without an IVRS table, else a status line, the IVMD
/// ranges and the highest domain id.
pub fn init() -> Option<(&'static str, Vec<Reserved>, u16)> {
    let (ivhds, ivmds) = parse_ivrs()?;
    let none = |s| Some((s, Vec::new(), 0));
    if ivhds.is_empty() {
        return none("IVRS lists no usable AMD-Vi unit: device DMA is NOT confined, drivers are trusted with all memory");
    }
    // SAFETY: plain PMM call; 0 when no 2 MiB run is free.
    let devtab = unsafe { ffi::pmm_alloc_contig_zeroed(DEVTAB_PAGES) };
    if devtab == 0 {
        return none("no memory for the AMD-Vi device table: device DMA is NOT confined, drivers are trusted with all memory");
    }
    // Default deny: valid, translated through an empty table, no permission (quad 0); with
    // interrupt remapping, interrupts aborted (quad 2: IV, IntCtl 00).
    let Ok(empty) = alloc_table() else {
        return none("no memory for the AMD-Vi tables: device DMA is NOT confined, drivers are trusted with all memory");
    };
    let mut ir = ir_plan(&ivhds);
    let deny = empty | u64::from(LEVELS) << DTE_MODE_SHIFT | DTE_TV | DTE_V;
    let deny_int = if ir.is_ok() { DTE_IV } else { 0 };
    let dt = table(devtab);
    for i in 0..DEVTAB_ENTRIES {
        // SAFETY: entry i (4 quads) of the device table just allocated (direct map).
        unsafe {
            core::ptr::write_volatile(dt.wrapping_add(i * 4), deny);
            core::ptr::write_volatile(dt.wrapping_add(i * 4 + 2), deny_int);
        }
    }
    if let Ok(plan) = &ir {
        for d in &ivhds {
            // SAFETY: quad 2 of the IOMMU function's own entry.
            unsafe { core::ptr::write_volatile(dt.wrapping_add(usize::from(d.func) * 4 + 2), DTE_IV | DTE_INTCTL_PASS) };
        }
        for &(id, dev) in &plan.ioapics[..plan.n] {
            let Ok(t) = alloc_table() else {
                ir = Err("out of memory");
                break;
            };
            // The pins routed so far (the serial port's) get their entries now, before the IOMMU
            // is enabled: their interrupts are never refused in between (the pins stay as they are).
            let mut routed = [0u16; 256];
            // SAFETY: writes at most 256 entries into `routed`.
            let n = unsafe { ffi::ioapic_routed(id, routed.as_mut_ptr(), 256) } as usize;
            for &r in &routed[..n.min(256)] {
                // SAFETY: entry `vector` of the new table (direct map, not in use yet).
                unsafe { core::ptr::write_volatile((table(t) as *mut u32).wrapping_add(usize::from(r & 0xFF)), irte(plan.dest, r as u8)) };
            }
            // SAFETY: quad 2 of the I/O APIC's entry: its interrupt table.
            unsafe { core::ptr::write_volatile(dt.wrapping_add(usize::from(dev) * 4 + 2), int_entry(t)) };
        }
        if ir.is_err() {
            for i in 0..DEVTAB_ENTRIES {
                // SAFETY: as above: interrupts back to unmapped (remapping stays off).
                unsafe { core::ptr::write_volatile(dt.wrapping_add(i * 4 + 2), 0) };
            }
        }
    }
    let mut units = Vec::new();
    for d in &ivhds {
        match bring_up(d, devtab) {
            Ok(u) => {
                if units.try_reserve(1).is_ok() {
                    units.push(u);
                }
            }
            Err(e) => crate::kprintln!("IOMMU: AMD-Vi unit at {:#x} unusable: {}", d.base, e),
        }
    }
    if units.is_empty() {
        // Nothing points at the table: give it back.
        for i in 0..DEVTAB_PAGES {
            // SAFETY: frames of the device table allocated above, referenced by no unit.
            unsafe { ffi::pmm_free(devtab + i * PAGE) };
        }
        return none("no usable AMD-Vi unit: device DMA is NOT confined, drivers are trusted with all memory");
    }
    // SAFETY: plain call; -1 when no vector is free.
    let v = unsafe { ffi::irq_vector_alloc() };
    let mut msi = 0;
    for (i, u) in units.iter().enumerate() {
        OWNED[i].store(u64::from(u.func.0) + 1, Ordering::Release);
        if v >= 0 && setup_msi(u.func, v as u32) {
            msi += 1;
        }
    }
    if v >= 0 {
        FAULT_VECTOR.store(v as u64, Ordering::Release);
    }
    for u in &mut units {
        let int = if msi > 0 { CTL_EVT_INT } else { 0 };
        u.w64(CONTROL, CTL_EN | CTL_CMD_BUF | CTL_EVT_LOG | int);
        // Whatever the firmware left in the caches goes: every device table entry, then all.
        for id in 0..=u16::MAX {
            u.inval_devtab(id);
            if ir.is_ok() {
                u.inval_inttab(id);
            }
            if id % 64 == 63 {
                u.sync();
            }
        }
        if u.efr & EFR_IA != 0 {
            u.push(CMD_INVAL_ALL, 0);
        }
        u.sync();
    }
    let n = units.len();
    let (ioapics, nioapic, dest) = match &ir {
        Ok(p) => (p.ioapics, p.n, p.dest),
        Err(_) => ([(0, 0); 8], 0, 0),
    };
    *STATE.lock() = Some(State { units, devtab, ir: ir.is_ok(), dest, ioapics, nioapic });
    set_backend(Backend::AmdVi);
    crate::kprintln!(
        "IOMMU: AMD-Vi, {} unit(s), {}-level tables (48-bit device addresses), event log{}, {} IVMD range(s)",
        n,
        LEVELS,
        if msi > 0 { " with interrupt" } else { " (no interrupt: faults not reported)" },
        ivmds.len()
    );
    super::ir_result(Backend::AmdVi, ir.map(|_| "32-bit entries, xAPIC destinations"));
    Some(("DMA remapping on for every device (default deny, faults reported)", ivmds, u16::MAX))
}

// ---- interrupt remapping ------------------------------------------------------------------------

struct IrPlan {
    ioapics: [(u8, u16); 8],
    n: usize,
    dest: u8,
}

/// Can interrupts be remapped? Every I/O APIC in use must have its device id in the IVRS, and the
/// boot CPU's APIC id must fit the 32-bit entry's 8-bit destination.
fn ir_plan(ivhds: &[Ivhd]) -> Result<IrPlan, &'static str> {
    // SAFETY: plain read.
    let apic = unsafe { ffi::irq_target_apic() };
    if apic > 0xFF {
        return Err("the boot CPU's APIC id needs the 128-bit entry format");
    }
    let mut ids = [0u8; 8];
    // SAFETY: writes at most 8 ids into `ids`.
    let nids = unsafe { ffi::ioapic_ids(ids.as_mut_ptr(), 8) } as usize;
    let mut plan = IrPlan { ioapics: [(0, 0); 8], n: 0, dest: apic as u8 };
    for &id in &ids[..nids.min(8)] {
        let Some(dev) = ivhds.iter().flat_map(|d| d.ioapics.iter()).find(|(i, _)| *i == id).map(|(_, d)| *d) else {
            return Err("an I/O APIC in use is missing from the IVRS");
        };
        plan.ioapics[plan.n] = (id, dev);
        plan.n += 1;
    }
    Ok(plan)
}

/// Quad 2 of a device table entry that remaps through table `t` (256 entries).
fn int_entry(t: u64) -> u64 {
    DTE_IV | DTE_INT_LEN_256 | (t & DTE_INT_ADDR) | DTE_INTCTL_REMAP
}

/// A 32-bit interrupt table entry: RemapEn, fixed delivery, physical destination `dest`.
fn irte(dest: u8, vector: u8) -> u32 {
    1 | u32::from(dest) << 8 | u32::from(vector) << 16
}

/// Point entry `vector` of device `dev`'s table at the boot CPU (creating the table).
fn ir_set_locked(st: &mut State, dev: u16, vector: u8) -> KResult<()> {
    let e = dte(st, Bdf(dev)).wrapping_add(2);
    // SAFETY: quad 2 of entry `dev` of the device table.
    let q2 = unsafe { core::ptr::read_volatile(e) };
    let t = if q2 & DTE_INTCTL_MASK == DTE_INTCTL_REMAP {
        q2 & DTE_INT_ADDR
    } else {
        let t = alloc_table()?;
        // SAFETY: as above; one 64-bit store switches the entry from abort to the new table.
        unsafe { core::ptr::write_volatile(e, int_entry(t)) };
        t
    };
    let slot = (table(t) as *mut u32).wrapping_add(usize::from(vector));
    // SAFETY: entry `vector` of the device's interrupt table (direct map).
    unsafe { core::ptr::write_volatile(slot, irte(st.dest, vector)) };
    ir_flush(st, dev);
    Ok(())
}

fn ir_flush(st: &mut State, dev: u16) {
    for u in &mut st.units {
        u.inval_devtab(dev);
        u.inval_inttab(dev);
        u.sync();
    }
}

/// Install the entry for a device's MSI on `vector` (the MSI data is the index: the message is
/// the usual one).
pub fn ir_msi(dev: u16, vector: u32) -> KResult<()> {
    let mut g = STATE.lock();
    let st = g.as_mut().ok_or(Status::NotSupported)?;
    if !st.ir || vector > 0xFF {
        return Err(Status::NotSupported);
    }
    ir_set_locked(st, dev, vector as u8)
}

/// Install the entry for an I/O APIC pin; returns the pin's high dword (unchanged format).
pub fn ir_ioapic(id: u8, vector: u8) -> Option<u32> {
    let mut g = STATE.lock();
    let st = g.as_mut()?;
    let dev = st.ioapics[..st.nioapic].iter().find(|(i, _)| *i == id)?.1;
    ir_set_locked(st, dev, vector).ok()?;
    Some(u32::from(st.dest) << 24)
}

/// Remove entry `vector` of device `dev` (None: of every I/O APIC).
pub fn ir_clear(dev: Option<u16>, vector: u32) {
    let mut g = STATE.lock();
    let Some(st) = g.as_mut() else { return };
    if !st.ir || vector > 0xFF {
        return;
    }
    let mut devs = [0u16; 8];
    let n = match dev {
        Some(d) => {
            devs[0] = d;
            1
        }
        None => {
            for (i, &(_, d)) in st.ioapics[..st.nioapic].iter().enumerate() {
                devs[i] = d;
            }
            st.nioapic
        }
    };
    for &d in &devs[..n] {
        // SAFETY: quad 2 of entry `d`.
        let q2 = unsafe { core::ptr::read_volatile(dte(st, Bdf(d)).wrapping_add(2)) };
        if q2 & DTE_INTCTL_MASK == DTE_INTCTL_REMAP {
            // SAFETY: entry `vector` of that device's interrupt table: not remapped any more.
            unsafe { core::ptr::write_volatile((table(q2 & DTE_INT_ADDR) as *mut u32).wrapping_add(vector as usize), 0) };
            ir_flush(st, d);
        }
    }
}

/// Is `bdf` an IOMMU's own PCI function (kept by the kernel, never given to a driver)?
pub fn kernel_owned(bdf: Bdf) -> bool {
    OWNED.iter().any(|o| o.load(Ordering::Acquire) == u64::from(bdf.0) + 1)
}

fn unit_of(st: &State, bdf: Bdf) -> usize {
    st.units
        .iter()
        .position(|u| u.covers(bdf.0))
        .or_else(|| st.units.iter().position(|u| u.all))
        .unwrap_or(0)
}

fn dte(st: &State, bdf: Bdf) -> *mut u64 {
    table(st.devtab).wrapping_add(usize::from(bdf.0) * 4)
}

/// Create the domain of a device (its device table entry, an empty page table). `did` must be
/// unique.
pub fn domain_create(bdf: Bdf, did: u16) -> KResult<Domain> {
    let mut g = STATE.lock();
    let st = g.as_mut().ok_or(Status::NotSupported)?;
    if did == 0 {
        return Err(Status::NoResources);
    }
    let root = alloc_table()?;
    let ui = unit_of(st, bdf);
    let e = dte(st, bdf);
    // SAFETY: entry `bdf` of the device table (4 quads). The domain id goes in first; the entry
    // stays deny-all until quad 0 switches paging on with the new root.
    unsafe {
        core::ptr::write_volatile(e.wrapping_add(1), u64::from(did));
        core::ptr::write_volatile(
            e,
            root | u64::from(LEVELS) << DTE_MODE_SHIFT | DTE_IR | DTE_IW | DTE_TV | DTE_V,
        );
    }
    let u = &mut st.units[ui];
    u.inval_devtab(bdf.0);
    u.inval_domain(did);
    u.sync();
    Ok(Domain { backend: Backend::AmdVi, unit: ui, did, root, levels: LEVELS, limit: 1 << 48, tables: 1 })
}

/// Test images: what `iova` translates to in `d` (frame, writable), without allocating.
#[cfg(ktest_drivers)]
pub fn lookup(d: &Domain, iova: u64) -> Option<(u64, bool)> {
    let _g = STATE.lock();
    let mut t = d.root;
    for level in (1..=d.levels).rev() {
        // SAFETY: an entry of a page table this domain owns (direct map), read under the lock.
        let v = unsafe { core::ptr::read_volatile(table(t).wrapping_add(((iova >> (12 + 9 * (level - 1))) & 511) as usize)) };
        if v & PTE_PR == 0 {
            return None;
        }
        if level == 1 {
            return Some((v & PTE_ADDR, v & PTE_IW != 0));
        }
        t = v & PTE_ADDR;
    }
    None
}

/// Leaf entry for `iova`, creating page tables on the way.
fn walk(d: &mut Domain, iova: u64) -> KResult<*mut u64> {
    let mut t = d.root;
    for level in (2..=d.levels).rev() {
        let e = table(t).wrapping_add(((iova >> (12 + 9 * (level - 1))) & 511) as usize);
        // SAFETY: an entry of a page table this domain owns (direct map).
        let v = unsafe { core::ptr::read_volatile(e) };
        t = if v & PTE_PR != 0 {
            v & PTE_ADDR
        } else {
            let pa = alloc_table()?;
            d.tables += 1;
            // SAFETY: as above. A directory entry names the next level and allows both; the
            // leaf decides (permissions are ANDed down the walk).
            unsafe {
                core::ptr::write_volatile(e, pa | u64::from(level - 1) << PTE_NEXT_SHIFT | PTE_IR | PTE_IW | PTE_PR)
            };
            pa
        };
    }
    Ok(table(t).wrapping_add(((iova >> 12) & 511) as usize))
}

fn clear(d: &mut Domain, iova: u64, pages: u64) {
    for i in 0..pages {
        if let Ok(e) = walk(d, iova + i * PAGE) {
            // SAFETY: a leaf entry of this domain's tables (mapped addresses have their tables).
            unsafe { core::ptr::write_volatile(e, 0) };
        }
    }
}

/// Map `frames` at `iova` (device may read; may write if `write`). On error nothing stays mapped.
pub fn map(d: &mut Domain, iova: u64, frames: &[u64], write: bool) -> KResult<()> {
    let mut g = STATE.lock();
    let st = g.as_mut().ok_or(Status::NotSupported)?;
    let bits = PTE_PR | PTE_IR | if write { PTE_IW } else { 0 };
    for (i, &pa) in frames.iter().enumerate() {
        match walk(d, iova + i as u64 * PAGE) {
            // SAFETY: a leaf entry (next level 0: a 4 KiB page) of this domain's tables.
            Ok(e) => unsafe { core::ptr::write_volatile(e, pa | bits) },
            Err(err) => {
                clear(d, iova, i as u64);
                let u = &mut st.units[d.unit];
                u.inval_domain(d.did);
                u.sync();
                return Err(err);
            }
        }
    }
    let u = &mut st.units[d.unit];
    if u.np_cache {
        u.inval_domain(d.did); // the unit may have cached the entries as not present
        u.sync();
    } else {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    Ok(())
}

/// Unmap and wait until no device can use the translations any more (the pages may be freed).
pub fn unmap(d: &mut Domain, iova: u64, pages: u64) {
    let mut g = STATE.lock();
    let Some(st) = g.as_mut() else { return };
    clear(d, iova, pages);
    let u = &mut st.units[d.unit];
    u.inval_domain(d.did);
    u.sync();
}

/// Re-program every AMD-Vi unit after ACPI S3 sleep (interrupts off, no allocation).
pub fn resume() {
    let mut g = STATE.lock();
    let Some(st) = g.as_mut() else { return };
    let v = FAULT_VECTOR.load(Ordering::Acquire);
    let devtab = st.devtab;
    let ir = st.ir;
    for u in &mut st.units {
        u.w64(CONTROL, 0);
        u.tail = 0;
        u.seq = 0;
        // SAFETY: this unit's completion-wait word in the direct map.
        unsafe { core::ptr::write_volatile(table(u.wait), 0) };
        u.w64(DEV_TABLE, devtab | (DEVTAB_PAGES - 1));
        u.w64(CMD_BASE, u.cmd | RING_LEN_CODE << 56);
        u.w64(CMD_HEAD, 0);
        u.w64(CMD_TAIL, 0);
        u.w64(STATUS, ST_EVT_OVERFLOW | ST_EVT_INT | ST_COMP_INT);
        u.w64(EVT_BASE, u.evt | RING_LEN_CODE << 56);
        u.w64(EVT_HEAD, 0);
        u.w64(EVT_TAIL, 0);
        let msi_ok = v != 0 && setup_msi(u.func, v as u32);
        let int = if msi_ok { CTL_EVT_INT } else { 0 };
        u.w64(CONTROL, CTL_EN | CTL_CMD_BUF | CTL_EVT_LOG | int);
        if u.efr & EFR_IA != 0 {
            u.push(CMD_INVAL_ALL, 0);
            u.sync();
        } else {
            for id in 0..=u16::MAX {
                u.inval_devtab(id);
                if ir {
                    u.inval_inttab(id);
                }
                if id % 64 == 63 {
                    u.sync();
                }
            }
            u.sync();
        }
    }
}

/// The event-log vector fired: report every logged event and clear it (interrupt context).
pub fn fault_irq(vector: u32) -> bool {
    if FAULT_VECTOR.load(Ordering::Acquire) != u64::from(vector) || vector == 0 {
        return false;
    }
    // Interrupts are off wherever the lock is held, so on this CPU nobody holds it now.
    let g = STATE.lock();
    let Some(st) = g.as_ref() else { return true };
    for u in &st.units {
        let status = u.r64(STATUS);
        if status & ST_EVT_OVERFLOW == 0 {
            u.w64(STATUS, status & (ST_EVT_INT | ST_COMP_INT)); // before draining: none is missed
        }
        let mut head = u.r64(EVT_HEAD) as u32 & (RING_BYTES - 1);
        let tail = u.r64(EVT_TAIL) as u32 & (RING_BYTES - 1);
        for _ in 0..RING_BYTES / 16 {
            if head == tail {
                break;
            }
            let p = table(u.evt).wrapping_add(head as usize / 8);
            // SAFETY: entry `head` of this unit's event log (written by the hardware before it
            // moved the tail past it).
            let (q0, q1) = unsafe { (core::ptr::read_volatile(p), core::ptr::read_volatile(p.wrapping_add(1))) };
            let id = q0 as u16;
            match q0 >> 60 {
                2 => {
                    // IO_PAGE_FAULT for an interrupt request (I, bit 51, at an MSI address): a
                    // blocked interrupt. (QEMU sets I on every page fault and drops the address.)
                    if q0 & (1 << 51) != 0 && q1 >> 20 == 0xFEE {
                        report_irq(id, q1 as u32, 0);
                        head = (head + 16) % RING_BYTES;
                        continue;
                    }
                    // IO_PAGE_FAULT. RW (bit 53) is meaningful for a present page (PR, bit 52).
                    let write = if q0 & (1 << 52) != 0 { Some(q0 & (1 << 53) != 0) } else { None };
                    report(id, q1, write, "IO page fault: not mapped for this device");
                }
                code => {
                    if super::count_fault(id) <= 32 {
                        crate::kprintln!("IOMMU: AMD-Vi event {} for {} at {:#x}", code, Bdf(id), q1);
                    }
                }
            }
            head = (head + 16) % RING_BYTES;
        }
        u.w64(EVT_HEAD, u64::from(head));
        if status & ST_EVT_OVERFLOW != 0 {
            // The log stopped: restart it empty (events lost meanwhile are counted as one).
            crate::kprintln!("IOMMU: AMD-Vi event log overflowed; restarted");
            let ctl = u.r64(CONTROL);
            u.w64(CONTROL, ctl & !CTL_EVT_LOG);
            u.w64(STATUS, ST_EVT_OVERFLOW | ST_EVT_INT);
            u.w64(EVT_BASE, u.evt | RING_LEN_CODE << 56);
            u.w64(EVT_HEAD, 0);
            u.w64(EVT_TAIL, 0);
            u.w64(CONTROL, ctl);
        }
    }
    true
}
