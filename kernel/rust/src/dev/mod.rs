//! Device framework, kernel side. Drivers are user-space processes (`.ddrv`); the
//! kernel only finds devices, confines them and hands out capabilities:
//!
//! - `pci`: configuration access (ECAM from ACPI MCFG, or legacy ports), enumeration, BARs and
//!   capabilities;
//! - `iommu`: DMA remapping (Intel VT-d or AMD-Vi), a domain per device, default deny;
//! - `irq`: device vectors -> interrupt objects (MSI, MSI-X, ISA lines);
//! - `object::device`: the Device, Interrupt and Pin objects drivers use.
//!
//! At boot every PCI function (and the legacy PS/2 controller, as a platform device) becomes a
//! `DeviceObj`. They all go to init (startup tag DEVICE) and nowhere else: init passes them to the
//! device manager, which grants each to the driver it starts for it.

#[cfg(ktest_fuzz)]
pub mod acpi_fuzz;
pub mod iommu;
pub mod irq;
pub mod pci;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::object::device::{DeviceObj, Kind, Platform};
use crate::object::KRef;

static DEVICES: AtomicPtr<Vec<KRef<DeviceObj>>> = AtomicPtr::new(core::ptr::null_mut());

/// Every device found at boot (fixed afterwards).
pub fn devices() -> &'static [KRef<DeviceObj>] {
    let p = DEVICES.load(Ordering::Acquire);
    if p.is_null() {
        return &[];
    }
    // SAFETY: set once by `init` from a leaked box that is never freed or changed.
    unsafe { &*p }
}

/// Does [start, end) of physical memory hold a BAR of a device other than `me`?
pub fn page_shared(me: &DeviceObj, start: u64, end: u64) -> bool {
    devices().iter().filter(|d| !core::ptr::eq(&***d, me)).any(|d| {
        d.pci().is_some_and(|f| {
            f.bars.iter().any(|b| b.kind == pci::BarKind::Memory && b.addr < end && start < b.addr.saturating_add(b.size))
        })
    })
}

fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: reads a status port; harmless on any PC.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags)) }
    v
}

/// Called once from dkrnl_init (after ACPI, the VMM and the object layer are up).
pub fn init() {
    let (funcs, method, base, start, end) = pci::enumerate();
    if base != 0 {
        crate::kprintln!("PCI: {} at {:#x} (segment 0, buses {}-{}), {} functions", method, base, start, end, funcs.len());
        let dropped = pci::DROPPED.load(core::sync::atomic::Ordering::Relaxed);
        if dropped > 0 {
            crate::kprintln!("PCI: {} more functions not used: the limit is {}", dropped, pci::MAX_FUNCTIONS);
        }
    } else {
        crate::kprintln!("PCI: {} (no MCFG), {} functions", method, funcs.len());
    }
    // The IOMMU first: an AMD-Vi unit is itself a PCI function, which the kernel keeps.
    let status = iommu::init();
    crate::kprintln!("IOMMU: {}", status);
    let mut devs: Vec<KRef<DeviceObj>> = Vec::new();
    for f in funcs {
        let irq = match (f.msix, f.msi) {
            (Some(m), _) => {
                let mut b = crate::fmtbuf::FmtBuf::<16>::new();
                let _ = core::fmt::Write::write_fmt(&mut b, format_args!("MSI-X x{}", m.count));
                b
            }
            (None, Some(_)) => {
                let mut b = crate::fmtbuf::FmtBuf::<16>::new();
                let _ = core::fmt::Write::write_str(&mut b, "MSI");
                b
            }
            _ => crate::fmtbuf::FmtBuf::<16>::new(),
        };
        crate::kprintln!(
            "  PCI {} {:04x}:{:04x} class {:02x}.{:02x} {} {}",
            f.bdf,
            f.vendor,
            f.device,
            f.class,
            f.subclass,
            f.kind_name(),
            core::str::from_utf8(irq.as_bytes()).unwrap_or("")
        );
        if iommu::kernel_owned(f.bdf) {
            crate::kprintln!("    (the IOMMU itself: kept by the kernel)");
            continue;
        }
        let mut name = crate::fmtbuf::FmtBuf::<16>::new();
        let _ = core::fmt::Write::write_fmt(&mut name, format_args!("pci-{}", f.bdf));
        let idx = devs.len() as u16;
        match DeviceObj::new(idx, core::str::from_utf8(name.as_bytes()).unwrap_or("pci"), Kind::Pci(f)) {
            Ok(d) if devs.try_reserve(1).is_ok() => devs.push(d),
            _ => crate::kprintln!("PCI: out of memory, device skipped"),
        }
    }
    // The 8042 PS/2 controller: data port 0x60, command/status 0x64, keyboard IRQ 1, mouse 12.
    if inb(0x64) != 0xFF {
        let p = Platform { io: [(0x60, 1), (0x64, 1)], irqs: [1, 12], nirqs: 2 };
        let idx = devs.len() as u16;
        if let Ok(d) = DeviceObj::new(idx, "ps2", Kind::Platform(p))
            && devs.try_reserve(1).is_ok()
        {
            devs.push(d);
        }
    }
    let n = devs.len();
    let leaked = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(devs));
    DEVICES.store(leaked, Ordering::Release);
    crate::kprintln!("Devices: {} for user-space drivers (handed to init)", n);
}
