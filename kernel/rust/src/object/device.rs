//! Device objects: what a user-space driver gets instead of kernel code.
//!
//! - `DeviceObj`: one PCI function (or a legacy platform device such as the PS/2 controller),
//!   created by the kernel at boot and handed to init, which passes it to the device manager,
//!   which grants it to the driver it starts. Through it a driver may read configuration space
//!   and write the parts that are safe (`config_write`), map its MMIO BARs (`bar_vmo`: a device
//!   VMO, uncached, with the MSI-X table hidden), use its I/O ports (`io_read`/`io_write`), get
//!   interrupt objects (`interrupt`) and give the device access to memory (`dma_map`).
//! - `InterruptObj`: one interrupt source (an MSI-X entry, MSI, or an ISA line) bound to a vector.
//!   It is `SIGNALED` when the interrupt fires; `ack` clears it. Wait first, ack, then look at
//!   the device: an interrupt after the ack signals again, so none is lost.
//! - `PinObj`: pages of a VMO the device may reach by DMA, at device addresses in the device's own
//!   IOMMU domain. Closing the last handle unmaps them and waits for the IOMMU before the pages
//!   can go; a driver that dies loses every pin with its handles, so a device can never reach
//!   memory of a dead driver (or anything else) afterwards.
//!
//! The kernel keeps what would let a driver escape its device: BAR registers, the MSI/MSI-X
//! capabilities and table, power management, the PCIe capability and extended configuration
//! space are read-only to drivers; bus mastering can be turned on, but DMA only reaches pinned
//! pages (when an IOMMU is present; without one the boot log says that DMA is not confined).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::quota::Account;
use super::signals::Signals;
use super::vmo::WriteRef;
use super::{Header, KRef, KResult, Name, ObjType, Status, Vmo, sig};
use crate::dev::iommu::{self, Domain, IOVA_BASE};
use crate::dev::irq;
use crate::dev::pci::{self, Bar, BarKind, Bdf, Function};
use crate::ffi::{self, rank};
use crate::sync::SpinLock;

const PAGE: u64 = 4096;
/// Largest DMA pin (pages).
pub const MAX_PIN_PAGES: u64 = 16384;
/// MSI-X entries a driver may bind (the first 64; more are refused).
pub const MAX_MSIX: u16 = 64;

/// A legacy device on fixed ports and ISA interrupt lines, or the screen.
#[derive(Clone, Copy, Default)]
pub struct Platform {
    pub io: [(u16, u16); 2], // (base, length)
    pub irqs: [u8; 2],
    pub nirqs: u8,
    /// Memory window (physical base, bytes), mapped as BAR 0 (the display's framebuffer or VGA
    /// text buffer); (0, 0) for none.
    pub mem: (u64, u64),
    /// The screen's layout, for the display device (`display_info`).
    pub display: Option<Display>,
}

/// The screen the kernel used for its console, handed to user space (the terminal).
#[derive(Clone, Copy, Default)]
pub struct Display {
    /// 1 = RGB32 framebuffer (sizes in pixels), 2 = VGA text (sizes in cells).
    pub kind: u32,
    pub width: u32,
    pub height: u32,
    /// Bytes per line.
    pub pitch: u32,
    /// Bit positions of red, green and blue in a pixel (RGB32).
    pub shifts: [u8; 3],
}

pub enum Kind {
    Pci(Function),
    Platform(Platform),
}

struct State {
    domain: Option<Domain>,
    /// Device address ranges in use (start, pages), sorted by start.
    iova: Vec<(u64, u64)>,
    msix_table: u64, // kernel virtual address of the MSI-X table (0 until first use)
    msix_bound: u64, // entries bound to interrupt objects
    msi_bound: bool,
    isa_bound: u8,
    pins: u64,
}

pub struct DeviceObj {
    pub header: Header,
    name: Name,
    /// Unique small id: the IOMMU domain id is `index + 1`.
    index: u16,
    pub kind: Kind,
    st: SpinLock<State>,
}

impl DeviceObj {
    pub fn new(index: u16, name: &str, kind: Kind) -> KResult<KRef<DeviceObj>> {
        KRef::try_new(DeviceObj {
            header: Header::new(ObjType::Device),
            name: Name::new(name),
            index,
            kind,
            st: SpinLock::new(
                c"device",
                rank::DEVICE,
                State { domain: None, iova: Vec::new(), msix_table: 0, msix_bound: 0, msi_bound: false, isa_bound: 0, pins: 0 },
            ),
        })
        .map_err(|_| Status::NoMemory)
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn pci(&self) -> Option<&Function> {
        match &self.kind {
            Kind::Pci(f) => Some(f),
            Kind::Platform(_) => None,
        }
    }

    pub fn bdf(&self) -> Option<Bdf> {
        self.pci().map(|f| f.bdf)
    }

    pub fn live_pins(&self) -> u64 {
        self.st.lock().pins
    }

    // ---- configuration space ----------------------------------------------------------------

    fn cfg_args(&self, off: u64, size: u64) -> KResult<(&Function, u16, u8)> {
        let f = self.pci().ok_or(Status::NotSupported)?;
        if !matches!(size, 1 | 2 | 4) || !off.is_multiple_of(size) || off + size > u64::from(pci::config_size()) {
            return Err(Status::InvalidArgs);
        }
        Ok((f, off as u16, size as u8))
    }

    pub fn config_read(&self, off: u64, size: u64) -> KResult<u32> {
        let (f, off, size) = self.cfg_args(off, size)?;
        Ok(pci::read(f.bdf, off, size))
    }

    /// Writes a driver may do: the command register's decode and bus-master bits (INTx stays
    /// disabled: interrupts are MSI/MSI-X), and the device-specific part of the 256-byte space
    /// outside the capabilities the kernel owns (PM, MSI, PCIe, MSI-X). Everything else is
    /// `ACCESS_DENIED`.
    pub fn config_write(&self, off: u64, size: u64, val: u64) -> KResult<()> {
        let (f, off, size) = self.cfg_args(off, size)?;
        let val = val as u32;
        let _g = self.st.lock(); // serialised with the kernel's own MSI programming
        if off == 0x04 && size == 2 {
            let allowed = pci::CMD_IO | pci::CMD_MEMORY | pci::CMD_BUS_MASTER;
            let cur = pci::read(f.bdf, 0x04, 2) as u16;
            let new = (cur & !allowed) | (val as u16 & allowed) | pci::CMD_INTX_DISABLE;
            pci::write(f.bdf, 0x04, 2, u32::from(new));
            return Ok(());
        }
        if off < 0x40 || u32::from(off) + u32::from(size) > 0x100 {
            return Err(Status::AccessDenied);
        }
        if f.in_cap(off, u16::from(size), &[pci::CAP_PM, pci::CAP_MSI, pci::CAP_PCIE, pci::CAP_MSIX]) {
            return Err(Status::AccessDenied);
        }
        pci::write(f.bdf, off, size, val);
        Ok(())
    }

    // ---- BARs ----------------------------------------------------------------------------

    fn bar(&self, i: u64) -> KResult<Bar> {
        if let Kind::Platform(p) = &self.kind {
            // A platform device's memory window is BAR 0 (its I/O windows are separate).
            return match p.mem {
                (addr, size) if i == 0 && size != 0 => Ok(Bar { kind: BarKind::Memory, addr, size, ..Bar::default() }),
                _ => Err(Status::NotSupported),
            };
        }
        let f = self.pci().ok_or(Status::NotSupported)?;
        let b = *f.bars.get(usize::try_from(i).map_err(|_| Status::InvalidArgs)?).ok_or(Status::InvalidArgs)?;
        if b.kind == BarKind::None {
            return Err(Status::NotSupported);
        }
        Ok(b)
    }

    /// A device VMO over memory BAR `i`, charged to `acct`. The pages holding the MSI-X table or
    /// PBA are hidden (zero page): only the kernel programs interrupts.
    pub fn bar_vmo(&self, i: u64, acct: &KRef<Account>) -> KResult<KRef<Vmo>> {
        let b = self.bar(i)?;
        if b.kind != BarKind::Memory {
            return Err(Status::WrongType); // I/O BAR: io_read / io_write
        }
        let start = b.addr & !(PAGE - 1);
        let end = b.addr.checked_add(b.size).ok_or(Status::BadState)?.div_ceil(PAGE) * PAGE;
        // A BAR must not overlap RAM (a misprogrammed BAR would hand out kernel memory), and a
        // page must not be shared with another device's BAR.
        // The one exception: VGA text memory, in the legacy video window below 1 MiB (which the
        // RAM check refuses as a whole); never anything else there.
        let vga_text = matches!(&self.kind, Kind::Platform(p) if p.display.is_some_and(|d| d.kind == 2)) && start >= 0xA_0000 && end <= 0xC_0000;
        // SAFETY: plain query of the boot memory map.
        if b.addr == 0 || (!vga_text && unsafe { ffi::pmm_range_is_ram(start, end - start) }) {
            return Err(Status::AccessDenied);
        }
        if let Kind::Platform(p) = &self.kind {
            // The screen: its framebuffer usually lies inside the graphics card's BAR (that PCI
            // function gets no driver). Mapped write-combining; from now on the kernel writes its
            // console to serial only (a panic takes the screen back).
            let display = p.display.is_some();
            let v = Vmo::create_device(acct, start, (end - start) / PAGE, self.name(), display, |_| false)?;
            if display {
                // SAFETY: plain call; takes the console lock.
                unsafe { ffi::console_release_screen() };
            }
            return Ok(v);
        }
        if crate::dev::page_shared(self, start, end) {
            return Err(Status::AccessDenied);
        }
        let f = self.pci().ok_or(Status::NotSupported)?;
        let hidden = |page: u64| -> bool {
            let Some(m) = f.msix else { return false };
            let pa = start + page * PAGE;
            let overlaps = |bar: u8, off: u32, len: u64| {
                u64::from(bar) == i && {
                    let s = (b.addr + u64::from(off)) & !(PAGE - 1);
                    let e = (b.addr + u64::from(off) + len).div_ceil(PAGE) * PAGE;
                    pa >= s && pa < e
                }
            };
            overlaps(m.table_bar, m.table_off, u64::from(m.count) * 16)
                || overlaps(m.pba_bar, m.pba_off, u64::from(m.count).div_ceil(64) * 8)
        };
        let mut nm = crate::fmtbuf::FmtBuf::<32>::new();
        let _ = core::fmt::Write::write_fmt(&mut nm, format_args!("{}.bar{}", self.name(), i));
        Vmo::create_device(acct, start, (end - start) / PAGE, core::str::from_utf8(nm.as_bytes()).unwrap_or("bar"), false, hidden)
    }

    fn io_port(&self, bar: u64, off: u64, size: u64) -> KResult<u16> {
        if !matches!(size, 1 | 2 | 4) || !off.is_multiple_of(size) {
            return Err(Status::InvalidArgs);
        }
        let (base, len) = match &self.kind {
            Kind::Pci(_) => {
                let b = self.bar(bar)?;
                if b.kind != BarKind::Io {
                    return Err(Status::WrongType);
                }
                (b.addr, b.size)
            }
            Kind::Platform(p) => {
                let (b, l) = *p.io.get(usize::try_from(bar).map_err(|_| Status::InvalidArgs)?).ok_or(Status::InvalidArgs)?;
                if l == 0 {
                    return Err(Status::NotSupported);
                }
                (u64::from(b), u64::from(l))
            }
        };
        if off.checked_add(size).is_none_or(|e| e > len) || base + off + size > 0x1_0000 {
            return Err(Status::OutOfRange);
        }
        Ok((base + off) as u16)
    }

    pub fn io_read(&self, bar: u64, off: u64, size: u64) -> KResult<u32> {
        let port = self.io_port(bar, off, size)?;
        let v: u32;
        // SAFETY: port I/O inside a range that belongs to this device (checked above).
        unsafe {
            match size {
                1 => {
                    let b: u8;
                    core::arch::asm!("in al, dx", in("dx") port, out("al") b, options(nostack, preserves_flags));
                    v = u32::from(b);
                }
                2 => {
                    let w: u16;
                    core::arch::asm!("in ax, dx", in("dx") port, out("ax") w, options(nostack, preserves_flags));
                    v = u32::from(w);
                }
                _ => core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nostack, preserves_flags)),
            }
        }
        Ok(v)
    }

    pub fn io_write(&self, bar: u64, off: u64, size: u64, val: u64) -> KResult<()> {
        let port = self.io_port(bar, off, size)?;
        // SAFETY: as in `io_read`.
        unsafe {
            match size {
                1 => core::arch::asm!("out dx, al", in("dx") port, in("al") val as u8, options(nostack, preserves_flags)),
                2 => core::arch::asm!("out dx, ax", in("dx") port, in("ax") val as u16, options(nostack, preserves_flags)),
                _ => core::arch::asm!("out dx, eax", in("dx") port, in("eax") val as u32, options(nostack, preserves_flags)),
            }
        }
        Ok(())
    }

    // ---- interrupts ------------------------------------------------------------------------

    /// Interrupt sources: MSI-X entries if the function has MSI-X, else MSI (index 0); a platform
    /// device's ISA lines.
    pub fn irq_count(&self) -> u16 {
        match &self.kind {
            Kind::Pci(f) => match (f.msix, f.msi) {
                (Some(m), _) => m.count.min(MAX_MSIX),
                (None, Some(_)) => 1,
                _ => 0,
            },
            Kind::Platform(p) => u16::from(p.nirqs),
        }
    }

    fn msix_table(&self, st: &mut State, f: &Function) -> KResult<u64> {
        if st.msix_table != 0 {
            return Ok(st.msix_table);
        }
        let m = f.msix.ok_or(Status::NotSupported)?;
        let b = *f.bars.get(usize::from(m.table_bar)).ok_or(Status::BadState)?;
        if b.kind != BarKind::Memory || u64::from(m.table_off) + u64::from(m.count) * 16 > b.size {
            return Err(Status::BadState);
        }
        let pa = b.addr + u64::from(m.table_off);
        // SAFETY: pa (inside the device's BAR, checked) is not RAM (bar_vmo's check applies to
        // the BAR as a whole; checked again here for the table).
        if unsafe { ffi::pmm_range_is_ram(pa, u64::from(m.count) * 16) } {
            return Err(Status::BadState);
        }
        // SAFETY: maps the device's MSI-X table (device memory) uncached into the direct map.
        let va = unsafe { ffi::vmm_map_phys(pa, u64::from(m.count) * 16, ffi::VMM_W | ffi::VMM_UC) } as u64;
        // Every entry masked, then MSI-X on (MSI off, INTx off).
        for e in 0..u64::from(m.count) {
            // SAFETY: entry `e` of the mapped table.
            unsafe { core::ptr::write_volatile((va + e * 16 + 12) as *mut u32, 1) };
        }
        if let Some(msi) = f.msi {
            let c = pci::read(f.bdf, u16::from(msi.cap) + 2, 2);
            pci::write(f.bdf, u16::from(msi.cap) + 2, 2, c & !1);
        }
        let cmd = pci::read(f.bdf, 0x04, 2) as u16;
        pci::write(f.bdf, 0x04, 2, u32::from(cmd | pci::CMD_INTX_DISABLE));
        let c = pci::read(f.bdf, u16::from(m.cap) + 2, 2) as u16;
        pci::write(f.bdf, u16::from(m.cap) + 2, 2, u32::from((c | 1 << 15) & !(1 << 14)));
        st.msix_table = va;
        Ok(va)
    }

    /// Bind interrupt source `index` to a new interrupt object. `BadState` if it is bound already.
    pub fn interrupt(this: &KRef<DeviceObj>, index: u64) -> KResult<KRef<InterruptObj>> {
        if index >= u64::from(this.irq_count()) {
            return Err(Status::OutOfRange);
        }
        let src = match &this.kind {
            Kind::Pci(f) if f.msix.is_some() => Src::Msix(index as u16),
            Kind::Pci(_) => Src::Msi,
            Kind::Platform(p) => Src::Isa(p.irqs[index as usize]),
        };
        // Claim the source first, so two objects can never own it.
        {
            let mut st = this.st.lock();
            match src {
                Src::Msix(i) if st.msix_bound & (1 << i) != 0 => return Err(Status::BadState),
                Src::Msi if st.msi_bound => return Err(Status::BadState),
                Src::Isa(_) if st.isa_bound & (1 << index) != 0 => return Err(Status::BadState),
                Src::Msix(i) => st.msix_bound |= 1 << i,
                Src::Msi => st.msi_bound = true,
                Src::Isa(_) => st.isa_bound |= 1 << index,
            }
        }
        // SAFETY: plain call; -1 when no vector is free.
        let v = unsafe { ffi::irq_vector_alloc() };
        if v < 0 {
            this.release_source(src, index);
            return Err(Status::NoResources);
        }
        let obj = match KRef::try_new(InterruptObj {
            header: Header::new(ObjType::Interrupt),
            signals: Signals::new(c"interrupt"),
            dev: this.clone(),
            vector: v as u32,
            src,
            index: index as u8,
            fired: AtomicU64::new(0),
            enabled: core::sync::atomic::AtomicBool::new(false),
        }) {
            Ok(o) => o,
            Err(_) => return Err(Status::NoMemory), // the dropped value frees the vector, releases the source
        };
        irq::bind(obj.vector, &*obj);
        obj.enabled.store(true, Ordering::Release); // from here on Drop undoes the binding
        if let Err(e) = this.enable_source(src, obj.vector) {
            drop(obj); // unbinds, frees the vector, releases the source
            return Err(e);
        }
        Ok(obj)
    }

    fn enable_source(&self, src: Src, vector: u32) -> KResult<()> {
        match (src, &self.kind) {
            (Src::Msix(i), Kind::Pci(f)) => {
                // Remapping entry first (IOMMU lock), then the device's table (device lock).
                let (addr, data) = iommu::msi_message(f.bdf, vector)?;
                let mut st = self.st.lock();
                let t = self.msix_table(&mut st, f)? + u64::from(i) * 16;
                // SAFETY: entry `i` (< count, checked by `interrupt`) of the mapped table.
                unsafe {
                    core::ptr::write_volatile(t as *mut u32, addr as u32);
                    core::ptr::write_volatile((t + 4) as *mut u32, (addr >> 32) as u32);
                    core::ptr::write_volatile((t + 8) as *mut u32, data);
                    core::ptr::write_volatile((t + 12) as *mut u32, 0); // unmask
                }
            }
            (Src::Msi, Kind::Pci(f)) => {
                let (addr, data) = iommu::msi_message(f.bdf, vector)?;
                let _g = self.st.lock();
                let m = f.msi.ok_or(Status::NotSupported)?;
                let c = u16::from(m.cap);
                pci::write(f.bdf, c + 4, 4, addr as u32);
                if m.is64 {
                    pci::write(f.bdf, c + 8, 4, (addr >> 32) as u32);
                    pci::write(f.bdf, c + 12, 2, data);
                } else {
                    pci::write(f.bdf, c + 8, 2, data);
                }
                let cmd = pci::read(f.bdf, 0x04, 2) as u16;
                pci::write(f.bdf, 0x04, 2, u32::from(cmd | pci::CMD_INTX_DISABLE));
                let ctl = pci::read(f.bdf, c + 2, 2);
                pci::write(f.bdf, c + 2, 2, (ctl & !(7 << 4)) | 1); // one vector, enabled
            }
            (Src::Isa(line), Kind::Platform(_)) => {
                // SAFETY: routes an ISA line of this device to its own vector on the boot CPU.
                if !unsafe { ffi::ioapic_route_isa_irq(line, vector as u8) } {
                    return Err(Status::NotSupported);
                }
            }
            _ => return Err(Status::BadState),
        }
        Ok(())
    }

    fn disable_source(&self, src: Src) {
        match (src, &self.kind) {
            (Src::Msix(i), Kind::Pci(_)) => {
                let st = self.st.lock();
                if st.msix_table != 0 {
                    // SAFETY: entry `i` of the mapped table: masked.
                    unsafe { core::ptr::write_volatile((st.msix_table + u64::from(i) * 16 + 12) as *mut u32, 1) };
                }
            }
            (Src::Msi, Kind::Pci(f)) => {
                let _g = self.st.lock();
                if let Some(m) = f.msi {
                    let ctl = pci::read(f.bdf, u16::from(m.cap) + 2, 2);
                    pci::write(f.bdf, u16::from(m.cap) + 2, 2, ctl & !1);
                }
            }
            // SAFETY: masks the line again.
            (Src::Isa(line), _) => unsafe { ffi::ioapic_mask_isa_irq(line) },
            _ => {}
        }
    }

    fn release_source(&self, src: Src, index: u64) {
        let mut st = self.st.lock();
        match src {
            Src::Msix(i) => st.msix_bound &= !(1 << i),
            Src::Msi => st.msi_bound = false,
            Src::Isa(_) => st.isa_bound &= !(1 << index),
        }
    }

    // ---- DMA -------------------------------------------------------------------------------

    /// First-fit device address range for `pages` pages.
    fn iova_alloc(st: &mut State, pages: u64, limit: u64) -> KResult<u64> {
        let mut at = IOVA_BASE;
        let mut pos = st.iova.len();
        for (i, &(s, n)) in st.iova.iter().enumerate() {
            if at + pages * PAGE <= s {
                pos = i;
                break;
            }
            at = at.max(s + n * PAGE + PAGE); // one unmapped guard page between pins
        }
        if at.checked_add(pages * PAGE).is_none_or(|e| e > limit) {
            return Err(Status::NoSpace);
        }
        st.iova.try_reserve(1).map_err(|_| Status::NoMemory)?;
        st.iova.insert(pos, (at, pages));
        Ok(at)
    }

    /// Let the device reach `len` bytes of `vmo` from `off` (page aligned): read them if
    /// `dev_read`, write them if `dev_write`. Returns the pin and the device address of each page.
    pub fn dma_map(
        this: &KRef<DeviceObj>,
        vmo: KRef<Vmo>,
        off: u64,
        len: u64,
        dev_read: bool,
        dev_write: bool,
        addrs: &mut Vec<u64>,
    ) -> KResult<KRef<PinObj>> {
        let f = this.pci().ok_or(Status::NotSupported)?;
        if len == 0 || !off.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) || len / PAGE > MAX_PIN_PAGES || !(dev_read || dev_write) {
            return Err(Status::InvalidArgs);
        }
        if vmo.is_device() {
            return Err(Status::NotSupported); // no device-to-device DMA through pins
        }
        let end = off.checked_add(len).ok_or(Status::OutOfRange)?;
        if end > vmo.size() {
            return Err(Status::OutOfRange);
        }
        // A device that writes is a writer: sealed (code) VMOs can never be DMA targets.
        let writer = if dev_write { Some(Vmo::write_ref(&vmo)?) } else { None };
        let pages = len / PAGE;
        let first = (off / PAGE) as usize;
        addrs.try_reserve_exact(pages as usize).map_err(|_| Status::NoMemory)?;
        let frames = &vmo.frames()[first..first + pages as usize];
        let iova = if iommu::enabled() {
            let mut st = this.st.lock();
            if st.domain.is_none() {
                // Firmware-reserved ranges stay identity mapped: never handed out (no pins yet).
                let reserved = iommu::reserved_of(f.bdf)?;
                st.iova.try_reserve(reserved.len()).map_err(|_| Status::NoMemory)?;
                st.domain = Some(iommu::domain_create(f.bdf, this.index + 1)?);
                st.iova.extend_from_slice(&reserved);
            }
            let limit = st.domain.as_ref().map_or(0, |d| d.limit);
            let at = Self::iova_alloc(&mut st, pages, limit)?;
            let State { domain, iova, .. } = &mut *st;
            let d = domain.as_mut().ok_or(Status::BadState)?;
            if let Err(e) = iommu::map(d, at, frames, dev_write) {
                iova.retain(|&(s, _)| s != at);
                return Err(e);
            }
            st.pins += 1;
            for i in 0..pages {
                addrs.push(at + i * PAGE);
            }
            at
        } else {
            this.st.lock().pins += 1;
            addrs.extend_from_slice(frames); // capacity reserved: no IOMMU, physical addresses
            0
        };
        let pin = PinObj {
            header: Header::new(ObjType::Pin),
            dev: this.clone(),
            _vmo: vmo,
            _writer: writer,
            iova,
            pages,
        };
        KRef::try_new(pin).map_err(|_| Status::NoMemory) // a failed allocation drops `pin`: unmapped
    }

    fn dma_unmap(&self, iova: u64, pages: u64) {
        let mut st = self.st.lock();
        st.pins -= 1;
        if iova == 0 {
            return;
        }
        if let Some(d) = st.domain.as_mut() {
            iommu::unmap(d, iova, pages);
        }
        st.iova.retain(|&(s, _)| s != iova);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Src {
    Msix(u16),
    Msi,
    Isa(u8),
}

pub struct InterruptObj {
    pub header: Header,
    pub signals: Signals,
    dev: KRef<DeviceObj>,
    vector: u32,
    src: Src,
    index: u8,
    fired: AtomicU64,
    enabled: core::sync::atomic::AtomicBool,
}

impl InterruptObj {
    /// Interrupt context (irq.rs).
    pub fn fire(&self) {
        self.fired.fetch_add(1, Ordering::Relaxed);
        self.signals.update(0, sig::SIGNALED);
    }

    /// Clear `SIGNALED`; returns how often the interrupt fired so far.
    pub fn ack(&self) -> u64 {
        self.signals.update(sig::SIGNALED, 0);
        self.fired.load(Ordering::Relaxed)
    }

    pub fn fired(&self) -> u64 {
        self.fired.load(Ordering::Relaxed)
    }
}

impl Drop for InterruptObj {
    fn drop(&mut self) {
        if self.enabled.load(Ordering::Acquire) {
            self.dev.disable_source(self.src);
            iommu::ir_release(self.dev.pci().map(|f| f.bdf), self.vector);
            irq::unbind(self.vector);
        }
        // SAFETY: the vector was allocated for this object and nothing delivers to it any more.
        unsafe { ffi::irq_vector_free(self.vector as i32) };
        self.dev.release_source(self.src, u64::from(self.index));
    }
}

pub struct PinObj {
    pub header: Header,
    dev: KRef<DeviceObj>,
    /// Keeps the pages alive while the device may reach them (dropped after `drop` unmapped).
    _vmo: KRef<Vmo>,
    _writer: Option<WriteRef>,
    iova: u64,
    pages: u64,
}

impl PinObj {
    pub fn pages(&self) -> u64 {
        self.pages
    }
}

impl Drop for PinObj {
    fn drop(&mut self) {
        // Unmapped and invalidated before `vmo` (and with it the pages) can go.
        self.dev.dma_unmap(self.iova, self.pages);
    }
}
