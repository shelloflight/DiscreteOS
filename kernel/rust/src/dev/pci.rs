//! PCI / PCIe: configuration access, enumeration, BARs and capabilities.
//!
//! Configuration space is reached through ECAM (the ACPI MCFG table: memory-mapped, 4 KiB per
//! function, extended space included) when the firmware describes it, else through the legacy
//! 0xCF8/0xCFC ports (256 bytes per function). Enumeration starts at the MCFG's first bus and
//! follows PCI-to-PCI bridges, so only buses that exist are mapped and scanned.
//!
//! Everything read from configuration space is untrusted input: BAR sizes, capability pointers and
//! the capability list are bounds-checked and the walks are bounded, so a hostile or broken
//! device can make a function unusable but never confuse the kernel.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ffi::{self, rank};
use crate::sync::SpinLock;

/// Functions the kernel keeps track of (each becomes a device object). A desktop board has 50 or
/// more (the first real-hardware boot); 64 dropped the last ones silently. Beyond the
/// limit the rest are counted and reported, never silently lost.
pub const MAX_FUNCTIONS: usize = 512;

/// Functions found past MAX_FUNCTIONS (reported at boot).
pub static DROPPED: AtomicU32 = AtomicU32::new(0);

/// Bus/device/function (`bus << 8 | dev << 3 | func`), the requester id an IOMMU sees.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bdf(pub u16);

impl Bdf {
    pub fn new(bus: u8, dev: u8, func: u8) -> Bdf {
        Bdf(u16::from(bus) << 8 | u16::from(dev & 31) << 3 | u16::from(func & 7))
    }
    pub fn bus(self) -> u8 {
        (self.0 >> 8) as u8
    }
    pub fn dev(self) -> u8 {
        ((self.0 >> 3) & 31) as u8
    }
    pub fn func(self) -> u8 {
        (self.0 & 7) as u8
    }
}

impl core::fmt::Display for Bdf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus(), self.dev(), self.func())
    }
}

// ---- configuration access -----------------------------------------------------------------------

/// ECAM (fixed at enumeration; 0 = legacy ports). Bus windows are mapped on first use; the
/// mapping is idempotent, so the bits need no lock (and the VMM lock ranks below the PCI lock).
static ECAM_PHYS: AtomicU64 = AtomicU64::new(0);
static ECAM_BUSES: AtomicU32 = AtomicU32::new(0); // start | end << 8
static ECAM_MAPPED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static LEGACY: SpinLock<()> = SpinLock::new(c"pci.cf8", rank::PCI, ());

struct SavedFunc {
    bdf: Bdf,
    regs: [u32; 16],
}

struct SavedState {
    funcs: Vec<SavedFunc>,
    q35_pciexbar: (u32, u32),
    ich9_pm: (u32, u32),
}

static SAVED: SpinLock<SavedState> = SpinLock::new(
    c"pci.saved",
    rank::DEVICE,
    SavedState { funcs: Vec::new(), q35_pciexbar: (0, 0), ich9_pm: (0, 0) },
);

fn legacy_read32(bdf: Bdf, off: u16) -> u32 {
    let _g = LEGACY.lock();
    outl(0xCF8, 0x8000_0000 | u32::from(bdf.0) << 8 | u32::from(off & 0xFC));
    inl(0xCFC)
}

fn legacy_write32(bdf: Bdf, off: u16, val: u32) {
    let _g = LEGACY.lock();
    outl(0xCF8, 0x8000_0000 | u32::from(bdf.0) << 8 | u32::from(off & 0xFC));
    outl(0xCFC, val);
}

/// The configuration space size of every function: 4096 with ECAM, 256 without.
pub fn config_size() -> u16 {
    if ECAM_PHYS.load(Ordering::Acquire) != 0 { 4096 } else { 256 }
}

fn outl(port: u16, v: u32) {
    // SAFETY: port I/O to the PCI configuration ports (serialised by LEGACY).
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nostack, preserves_flags)) }
}
fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: as above.
    unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nostack, preserves_flags)) }
    v
}

/// Virtual address of a function's ECAM window (mapping its bus on first use), or None.
fn ecam_addr(bdf: Bdf, off: u16) -> Option<u64> {
    let phys = ECAM_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return None;
    }
    let buses = ECAM_BUSES.load(Ordering::Relaxed);
    let (start, end) = (buses as u8, (buses >> 8) as u8);
    let bus = bdf.bus();
    if bus < start || bus > end {
        return None;
    }
    let base = phys + (u64::from(bus - start) << 20);
    let bit = 1u64 << (bus % 64);
    let word = &ECAM_MAPPED[usize::from(bus / 64)];
    if word.load(Ordering::Acquire) & bit == 0 {
        // SAFETY: maps device memory described by the firmware into the direct map (uncached).
        let va = unsafe { ffi::vmm_map_phys(base, 1 << 20, ffi::VMM_W | ffi::VMM_UC) };
        crate::kassert!(va as u64 == ffi::physmap_base() + base);
        word.fetch_or(bit, Ordering::Release);
    }
    Some(ffi::physmap_base() + base + (u64::from(bdf.0 & 0xFF) << 12) + u64::from(off))
}

/// Read `size` (1, 2, 4) bytes at `off` (aligned to `size`, inside `config_size()`).
pub fn read(bdf: Bdf, off: u16, size: u8) -> u32 {
    crate::kassert!(matches!(size, 1 | 2 | 4) && off.is_multiple_of(u16::from(size)) && off < config_size());
    if let Some(va) = ecam_addr(bdf, off) {
        // SAFETY: an aligned access inside the function's mapped 4 KiB ECAM window.
        unsafe {
            return match size {
                1 => u32::from(core::ptr::read_volatile(va as *const u8)),
                2 => u32::from(core::ptr::read_volatile(va as *const u16)),
                _ => core::ptr::read_volatile(va as *const u32),
            };
        }
    }
    let _g = LEGACY.lock();
    outl(0xCF8, 0x8000_0000 | u32::from(bdf.0) << 8 | u32::from(off & 0xFC));
    let v = inl(0xCFC) >> ((off & 3) * 8);
    match size {
        1 => v & 0xFF,
        2 => v & 0xFFFF,
        _ => v,
    }
}

pub fn write(bdf: Bdf, off: u16, size: u8, val: u32) {
    crate::kassert!(matches!(size, 1 | 2 | 4) && off.is_multiple_of(u16::from(size)) && off < config_size());
    if let Some(va) = ecam_addr(bdf, off) {
        // SAFETY: as in `read`.
        unsafe {
            match size {
                1 => core::ptr::write_volatile(va as *mut u8, val as u8),
                2 => core::ptr::write_volatile(va as *mut u16, val as u16),
                _ => core::ptr::write_volatile(va as *mut u32, val),
            }
        }
        return;
    }
    let _g = LEGACY.lock();
    let addr = 0x8000_0000 | u32::from(bdf.0) << 8 | u32::from(off & 0xFC);
    outl(0xCF8, addr);
    let v = if size == 4 {
        val
    } else {
        let shift = (off & 3) * 8;
        let mask = if size == 1 { 0xFFu32 } else { 0xFFFF } << shift;
        (inl(0xCFC) & !mask) | ((val << shift) & mask)
    };
    outl(0xCF8, addr);
    outl(0xCFC, v);
}

// ---- functions ------------------------------------------------------------------------------------

pub const CMD_IO: u16 = 1 << 0;
pub const CMD_MEMORY: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;
pub const CMD_INTX_DISABLE: u16 = 1 << 10;

pub const CAP_PM: u8 = 0x01;
pub const CAP_MSI: u8 = 0x05;
pub const CAP_VENDOR: u8 = 0x09;
pub const CAP_PCIE: u8 = 0x10;
pub const CAP_MSIX: u8 = 0x11;

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum BarKind {
    #[default]
    None,
    Memory,
    Io,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Bar {
    pub kind: BarKind,
    pub addr: u64,
    pub size: u64,
    pub is64: bool,
    pub prefetch: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Cap {
    pub id: u8,
    pub off: u8,
    pub len: u8,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Msix {
    pub cap: u8,
    pub count: u16,
    pub table_bar: u8,
    pub table_off: u32,
    pub pba_bar: u8,
    pub pba_off: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Msi {
    pub cap: u8,
    pub is64: bool,
    pub masking: bool,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub bdf: Bdf,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub progif: u8,
    pub revision: u8,
    pub header: u8,
    pub bars: [Bar; 6],
    pub caps: Vec<Cap>,
    pub msi: Option<Msi>,
    pub msix: Option<Msix>,
}

impl Function {
    /// Does [off, off + size) touch a capability structure of one of `ids`?
    pub fn in_cap(&self, off: u16, size: u16, ids: &[u8]) -> bool {
        self.caps.iter().any(|c| {
            ids.contains(&c.id) && off < u16::from(c.off) + u16::from(c.len) && u16::from(c.off) < off + size
        })
    }

    pub fn kind_name(&self) -> &'static str {
        match (self.vendor, self.device) {
            (0x1AF4, 0x1041) => return "virtio-net",
            (0x1AF4, 0x1042) => return "virtio-blk",
            (0x1AF4, 0x1050) => return "virtio-gpu",
            (0x1AF4, 0x1052) => return "virtio-input",
            (0x1AF4, 0x1059) => return "virtio-snd",
            _ => {}
        }
        if self.class == 0x03 {
            match self.vendor {
                0x1002 => return "AMD GPU",
                0x8086 => return "Intel GPU",
                0x10DE => return "NVIDIA GPU",
                _ => return "display",
            }
        }
        match (self.class, self.subclass) {
            (0x01, 0x00) => "SCSI storage",
            (0x01, 0x01) => "IDE",
            (0x01, 0x06) => "SATA (AHCI)",
            (0x01, 0x08) => "NVMe",
            (0x01, _) => "storage",
            (0x02, _) => "network",
            (0x03, _) => "display",
            (0x06, 0x00) => "host bridge",
            (0x06, 0x01) => "ISA bridge",
            (0x06, 0x04) => "PCI bridge",
            (0x06, _) => "bridge",
            (0x08, _) => "system peripheral",
            (0x09, _) => "input",
            (0x0C, 0x03) => "USB",
            (0x0C, 0x05) => "SMBus",
            _ if self.vendor == 0x1AF4 => "virtio",
            _ => "device",
        }
    }
}

/// Capability length (bytes the kernel protects for the IDs it owns or restricts).
fn cap_len(bdf: Bdf, id: u8, off: u8) -> u8 {
    match id {
        CAP_PM => 8,
        CAP_MSIX => 12,
        CAP_PCIE => 60,
        CAP_MSI => {
            let ctl = read(bdf, u16::from(off) + 2, 2) as u16;
            10 + if ctl & (1 << 7) != 0 { 4 } else { 0 } + if ctl & (1 << 8) != 0 { 10 } else { 0 }
        }
        CAP_VENDOR => read(bdf, u16::from(off) + 2, 1) as u8,
        _ => 4,
    }
}

fn read_caps(bdf: Bdf) -> Vec<Cap> {
    let mut caps = Vec::new();
    let status = read(bdf, 0x06, 2);
    if status & (1 << 4) == 0 {
        return caps;
    }
    let mut ptr = (read(bdf, 0x34, 1) & 0xFC) as u8;
    // At most 48 capabilities fit in 0x40..0x100; a loop or a pointer into the header ends the walk.
    for _ in 0..48 {
        if ptr < 0x40 {
            break;
        }
        let id = read(bdf, u16::from(ptr), 1) as u8;
        let next = (read(bdf, u16::from(ptr) + 1, 1) & 0xFC) as u8;
        let len = cap_len(bdf, id, ptr).min(0u8.wrapping_sub(ptr)); // never past 0x100
        if caps.try_reserve(1).is_err() {
            break;
        }
        caps.push(Cap { id, off: ptr, len });
        ptr = next;
    }
    caps
}

/// Decode a PCI memory BAR's `(addr, size)` from its saved register values and all-1s probe masks.
/// Handles 64-bit Resizable BARs >= 4 GiB where `mask_lo & 0xFFFF_FFF0 == 0` and `mask_hi != 0`.
pub const fn decode_mem_bar(orig_lo: u32, orig_hi: u32, mask_lo: u32, mask_hi: u32, is64: bool) -> Option<(u64, u64)> {
    let lo = mask_lo & 0xFFFF_FFF0;
    let mut mask = lo as u64;
    let mut addr = (orig_lo & 0xFFFF_FFF0) as u64;
    if is64 {
        mask |= (mask_hi as u64) << 32;
        addr |= (orig_hi as u64) << 32;
    } else {
        mask |= 0xFFFF_FFFF_0000_0000;
    }
    let present = if is64 { mask != 0 } else { lo != 0 };
    let size = (!mask).wrapping_add(1);
    if present && size != 0 && size.is_power_of_two() {
        Some((addr, size))
    } else {
        None
    }
}

/// Size the BARs of a type-0 header (decode is off while sizing, then restored).
fn read_bars(bdf: Bdf, count: usize) -> [Bar; 6] {
    let mut bars = [Bar::default(); 6];
    let cmd = read(bdf, 0x04, 2) as u16;
    write(bdf, 0x04, 2, u32::from(cmd & !(CMD_IO | CMD_MEMORY)));
    let mut i = 0;
    while i < count {
        let off = 0x10 + 4 * i as u16;
        let orig = read(bdf, off, 4);
        if orig & 1 != 0 {
            write(bdf, off, 4, 0xFFFF_FFFF);
            let mask = read(bdf, off, 4) & 0xFFFF_FFFC;
            write(bdf, off, 4, orig);
            let size = u64::from((!mask).wrapping_add(1) & 0xFFFF);
            if mask != 0 && size != 0 {
                bars[i] = Bar { kind: BarKind::Io, addr: u64::from(orig & 0xFFFC), size, is64: false, prefetch: false };
            }
            i += 1;
            continue;
        }
        let is64 = (orig >> 1) & 3 == 2 && i + 1 < count;
        write(bdf, off, 4, 0xFFFF_FFFF);
        let mask_lo = read(bdf, off, 4);
        write(bdf, off, 4, orig);
        let (orig_hi, mask_hi) = if is64 {
            let orig_hi = read(bdf, off + 4, 4);
            write(bdf, off + 4, 4, 0xFFFF_FFFF);
            let hi = read(bdf, off + 4, 4);
            write(bdf, off + 4, 4, orig_hi);
            (orig_hi, hi)
        } else {
            (0, 0)
        };
        if let Some((addr, size)) = decode_mem_bar(orig, orig_hi, mask_lo, mask_hi, is64) {
            bars[i] = Bar { kind: BarKind::Memory, addr, size, is64, prefetch: orig & 8 != 0 };
        }
        i += if is64 { 2 } else { 1 };
    }
    write(bdf, 0x04, 2, u32::from(cmd));
    bars
}

fn probe(bdf: Bdf) -> Option<Function> {
    let id = read(bdf, 0x00, 4);
    let vendor = id as u16;
    if vendor == 0xFFFF || vendor == 0 {
        return None;
    }
    let class = read(bdf, 0x08, 4);
    let header = read(bdf, 0x0E, 1) as u8 & 0x7F;
    let bars = match header {
        0 => read_bars(bdf, 6),
        1 => read_bars(bdf, 2),
        _ => [Bar::default(); 6],
    };
    let caps = read_caps(bdf);
    let msi = caps.iter().find(|c| c.id == CAP_MSI).map(|c| {
        let ctl = read(bdf, u16::from(c.off) + 2, 2);
        Msi { cap: c.off, is64: ctl & (1 << 7) != 0, masking: ctl & (1 << 8) != 0 }
    });
    let msix = caps.iter().find(|c| c.id == CAP_MSIX).map(|c| {
        let ctl = read(bdf, u16::from(c.off) + 2, 2);
        let t = read(bdf, u16::from(c.off) + 4, 4);
        let p = read(bdf, u16::from(c.off) + 8, 4);
        Msix {
            cap: c.off,
            count: (ctl as u16 & 0x7FF) + 1,
            table_bar: (t & 7) as u8,
            table_off: t & !7,
            pba_bar: (p & 7) as u8,
            pba_off: p & !7,
        }
    });
    Some(Function {
        bdf,
        vendor,
        device: (id >> 16) as u16,
        class: (class >> 24) as u8,
        subclass: (class >> 16) as u8,
        progif: (class >> 8) as u8,
        revision: class as u8,
        header,
        bars,
        caps,
        msi,
        msix,
    })
}

fn scan_bus(bus: u8, seen: &mut [u64; 4], out: &mut Vec<Function>) {
    if seen[usize::from(bus / 64)] & (1 << (bus % 64)) != 0 {
        return; // a bridge loop (hostile or broken firmware)
    }
    seen[usize::from(bus / 64)] |= 1 << (bus % 64);
    for dev in 0..32u8 {
        let multi = read(Bdf::new(bus, dev, 0), 0x0E, 1) & 0x80 != 0;
        for func in 0..if multi { 8 } else { 1 } {
            let Some(f) = probe(Bdf::new(bus, dev, func)) else { continue };
            let bridge = f.header == 1;
            let secondary = read(f.bdf, 0x19, 1) as u8;
            if out.len() >= MAX_FUNCTIONS || out.try_reserve(1).is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            out.push(f);
            if bridge && secondary > bus {
                scan_bus(secondary, seen, out);
            }
        }
    }
}

/// MCFG: base address allocation structures at offset 44, 16 bytes each. Segment 0 only.
fn parse_mcfg() -> Option<(u64, u8, u8)> {
    let mut len = 0u32;
    // SAFETY: the C side returns a validated, mapped table of `len` bytes or NULL.
    let t = unsafe { ffi::acpi_find_table(b"MCFG".as_ptr(), &mut len) };
    if t.is_null() {
        return None;
    }
    // SAFETY: `len` bytes at `t` are mapped read-only for ever (firmware table).
    parse_mcfg_bytes(unsafe { core::slice::from_raw_parts(t, len as usize) })
}

/// The MCFG table's bytes (untrusted; also the fuzzing entry point): ECAM base and bus range of
/// segment 0.
pub fn parse_mcfg_bytes(b: &[u8]) -> Option<(u64, u8, u8)> {
    let mut off = 44;
    while off + 16 <= b.len() {
        let base = u64::from_le_bytes(b[off..off + 8].try_into().ok()?);
        let seg = u16::from_le_bytes([b[off + 8], b[off + 9]]);
        let (start, end) = (b[off + 10], b[off + 11]);
        if seg == 0 && base != 0 && base % (1 << 20) == 0 && start <= end && base < (1u64 << 46) {
            return Some((base, start, end));
        }
        off += 16;
    }
    None
}

/// Find every function. Returns them and a description of the access method.
pub fn enumerate() -> (Vec<Function>, &'static str, u64, u8, u8) {
    let (method, base, start, end) = match parse_mcfg() {
        Some((base, start, end)) => {
            ECAM_BUSES.store(u32::from(start) | u32::from(end) << 8, Ordering::Relaxed);
            ECAM_PHYS.store(base, Ordering::Release);
            ("ECAM", base, start, end)
        }
        None => ("legacy ports", 0, 0, 255),
    };
    let mut out = Vec::new();
    let mut seen = [0u64; 4];
    scan_bus(start, &mut seen, &mut out);
    // Record every enumerated function for S3 config-space save/restore.
    let mut saved = Vec::new();
    for f in &out {
        if saved.try_reserve(1).is_ok() {
            saved.push(SavedFunc { bdf: f.bdf, regs: [0; 16] });
        }
    }
    SAVED.lock().funcs = saved;
    (out, method, base, start, end)
}

/// Save every enumerated PCI function's standard 64-byte config header before ACPI S3 sleep.
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_pci_suspend() {
    let mut g = SAVED.lock();
    // On Intel Q35 (8086:29c0), save PCIEXBAR (0x60..0x68) in case firmware does not restore ECAM.
    if legacy_read32(Bdf(0), 0x00) == 0x29C0_8086 {
        g.q35_pciexbar = (legacy_read32(Bdf(0), 0x60), legacy_read32(Bdf(0), 0x64));
    }
    // On Intel ICH9 LPC (8086:2918 at 00:1f.0), save PMBASE (0x40) and ACPI_CNTL (0x44).
    let lpc = Bdf::new(0, 0x1F, 0);
    if legacy_read32(lpc, 0x00) == 0x2918_8086 {
        g.ich9_pm = (legacy_read32(lpc, 0x40), legacy_read32(lpc, 0x44));
    }
    for f in &mut g.funcs {
        for i in 0..16u16 {
            f.regs[usize::from(i)] = read(f.bdf, i * 4, 4);
        }
    }
}

/// Restore PCI configuration headers after ACPI S3 wake (interrupts off, no allocation).
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_pci_resume() {
    let g = SAVED.lock();
    // Re-enable Q35 ECAM if firmware reset PCIEXBAR during S3.
    if g.q35_pciexbar != (0, 0)
        && (legacy_read32(Bdf(0), 0x60) != g.q35_pciexbar.0 || legacy_read32(Bdf(0), 0x64) != g.q35_pciexbar.1)
    {
        legacy_write32(Bdf(0), 0x64, g.q35_pciexbar.1);
        legacy_write32(Bdf(0), 0x60, g.q35_pciexbar.0);
    }
    // Re-enable ICH9 ACPI PM I/O decode (PM1/GPE registers) if firmware reset it during S3.
    let lpc = Bdf::new(0, 0x1F, 0);
    if g.ich9_pm != (0, 0)
        && (legacy_read32(lpc, 0x40) != g.ich9_pm.0 || legacy_read32(lpc, 0x44) != g.ich9_pm.1)
    {
        legacy_write32(lpc, 0x40, g.ich9_pm.0);
        legacy_write32(lpc, 0x44, g.ich9_pm.1);
    }
    // Enumeration order visits parent bridges before downstream devices.
    for f in &g.funcs {
        write(f.bdf, 0x04, 2, 0);
        for off in [0x0Cu16, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x30, 0x3C] {
            write(f.bdf, off, 4, f.regs[usize::from(off / 4)]);
        }
        write(f.bdf, 0x04, 2, f.regs[1] & 0xFFFF);
    }
}
