//! AHCI (SATA) driver (`ahci.ddrv`). Every port with a SATA disk is a unit. One
//! command at a time (slot 0), 48-bit LBA DMA reads and writes, FLUSH CACHE EXT; one MSI for
//! the controller. Command lists, received FISes, command tables and the data buffer are pinned
//! for the device: with the IOMMU it reaches nothing else.
//!
//! The controller is untrusted: register values are bounded before use, a command that does
//! not complete in time fails (the device manager can restart the driver, which resets the
//! controller).

use libd::proto::{self, MAX_SECTORS, SECTOR};
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Startup, println};

use crate::blkserve::{self, Disk, MAX_UNITS};

const CAP: u64 = 0x00;
const GHC: u64 = 0x04;
const IS: u64 = 0x08;
const PI: u64 = 0x0C;
const GHC_HR: u32 = 1 << 0;
const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31;

const P_CLB: u64 = 0x00;
const P_FB: u64 = 0x08;
const P_IS: u64 = 0x10;
const P_IE: u64 = 0x14;
const P_CMD: u64 = 0x18;
const P_TFD: u64 = 0x20;
const P_SIG: u64 = 0x24;
const P_SSTS: u64 = 0x28;
const P_SERR: u64 = 0x30;
const P_CI: u64 = 0x38;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const IS_TFES: u32 = 1 << 30;
const SIG_ATA: u32 = 0x0000_0101;

const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_EXT: u8 = 0xEA;
const ATA_IDENTIFY: u8 = 0xEC;

const DATA_PAGES: usize = (MAX_SECTORS as usize * SECTOR).div_ceil(4096);
const MS: u64 = 1_000_000;

struct Port {
    index: u32,
    mem: Dma, // command list at 0, received FIS at 1024, command table at 2048
    sectors: u64,
    model: [u8; 40],
    model_len: usize,
}

struct Ahci {
    abar: Mapping,
    irq: Handle,
    data: Dma,
    ports: [Option<Port>; MAX_UNITS],
    n: usize,
    done: u64,
    irqs: u64,
}

fn port_reg(p: u32, r: u64) -> u64 {
    0x100 + u64::from(p) * 0x80 + r
}

fn wait_until(mut f: impl FnMut() -> bool, ms: u64) -> bool {
    let deadline = sys::clock_ns() + ms * MS;
    while sys::clock_ns() < deadline {
        if f() {
            return true;
        }
        sys::yield_now();
    }
    f()
}

impl Ahci {
    fn r(&self, off: u64) -> u32 {
        self.abar.r32(off)
    }
    fn w(&self, off: u64, v: u32) {
        self.abar.w32(off, v)
    }

    /// Stop a port's command engine and FIS receive.
    fn stop(&self, p: u32) -> bool {
        let c = self.r(port_reg(p, P_CMD));
        self.w(port_reg(p, P_CMD), c & !(CMD_ST | CMD_FRE));
        wait_until(|| self.r(port_reg(p, P_CMD)) & (CMD_CR | CMD_FR) == 0, 500)
    }

    /// One command on port `unit`: ATA `cmd` for `count` sectors at `lba`; data through
    /// `self.data` (device -> memory unless `write`).
    fn command(&mut self, unit: usize, cmd: u8, lba: u64, count: u64, write: bool, bytes: usize) -> Result<(), i32> {
        let port = self.ports[unit].as_ref().ok_or(sys::ERR_INVALID_ARGS as i32)?;
        let p = port.index;
        let m = &port.mem.map;
        // Command header 0.
        let prds = bytes.div_ceil(4096);
        m.w32(0, 5 | if write { 1 << 6 } else { 0 } | (prds as u32) << 16);
        m.w32(4, 0);
        let table = port.mem.dev_addr(2048);
        m.w32(8, table as u32);
        m.w32(12, (table >> 32) as u32);
        // Command FIS (register, host to device).
        for i in 0..32 {
            m.w32(2048 + 4 * i, 0);
        }
        m.w8(2048, 0x27);
        m.w8(2049, 0x80);
        m.w8(2050, cmd);
        m.w8(2052, lba as u8);
        m.w8(2053, (lba >> 8) as u8);
        m.w8(2054, (lba >> 16) as u8);
        m.w8(2055, 0x40); // LBA mode
        m.w8(2056, (lba >> 24) as u8);
        m.w8(2057, (lba >> 32) as u8);
        m.w8(2058, (lba >> 40) as u8);
        m.w8(2060, count as u8);
        m.w8(2061, (count >> 8) as u8);
        // PRDT: one entry per page of the data buffer.
        for i in 0..prds {
            let o = 2048 + 0x80 + 16 * i as u64;
            let a = self.data.dev_addr(i as u64 * 4096);
            let len = (bytes - i * 4096).min(4096);
            m.w32(o, a as u32);
            m.w32(o + 4, (a >> 32) as u32);
            m.w32(o + 8, 0);
            m.w32(o + 12, (len as u32 - 1) | if i + 1 == prds { 1 << 31 } else { 0 });
        }
        self.w(port_reg(p, P_IS), !0);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.w(port_reg(p, P_CI), 1);
        let deadline = sys::clock_ns() + 5000 * MS;
        loop {
            let is = self.r(port_reg(p, P_IS));
            if is & IS_TFES != 0 {
                self.w(port_reg(p, P_IS), is);
                println!("ahci: port {}: task file error (TFD {:#x})", p, self.r(port_reg(p, P_TFD)));
                self.recover(p);
                return Err(proto::ERR_IO);
            }
            if self.r(port_reg(p, P_CI)) & 1 == 0 {
                break;
            }
            let now = sys::clock_ns();
            if now >= deadline {
                println!("ahci: port {}: command {:#x} timed out", p, cmd);
                self.recover(p);
                return Err(sys::ERR_TIMED_OUT as i32);
            }
            let _ = sys::object_wait(self.irq, sys::SIGNALED, (deadline - now).min(10 * MS));
            if let Ok(n) = sys::interrupt_ack(self.irq) {
                self.irqs = n;
            }
            let is = self.r(port_reg(p, P_IS));
            self.w(port_reg(p, P_IS), is & !IS_TFES);
            self.w(IS, 1 << p);
        }
        self.w(port_reg(p, P_IS), !0);
        self.w(IS, 1 << p);
        if self.r(port_reg(p, P_TFD)) & 0x01 != 0 {
            return Err(proto::ERR_IO);
        }
        self.done += 1;
        Ok(())
    }

    /// After an error: restart the port's command engine.
    fn recover(&self, p: u32) {
        self.stop(p);
        self.w(port_reg(p, P_SERR), !0);
        self.w(port_reg(p, P_IS), !0);
        let c = self.r(port_reg(p, P_CMD));
        self.w(port_reg(p, P_CMD), c | CMD_FRE);
        self.w(port_reg(p, P_CMD), c | CMD_FRE | CMD_ST);
    }
}

impl Disk for Ahci {
    fn units(&self) -> usize {
        self.n
    }
    fn capacity(&self, unit: usize) -> u64 {
        self.ports[unit].as_ref().map_or(0, |p| p.sectors)
    }
    fn model(&self, unit: usize) -> &[u8] {
        self.ports[unit].as_ref().map_or(&[], |p| &p.model[..p.model_len])
    }
    fn read(&mut self, unit: usize, lba: u64, count: u64, out: &mut [u8]) -> Result<(), i32> {
        self.command(unit, ATA_READ_DMA_EXT, lba, count, false, out.len())?;
        out.copy_from_slice(&self.data.map.bytes()[..out.len()]);
        Ok(())
    }
    fn write(&mut self, unit: usize, lba: u64, count: u64, data: &[u8]) -> Result<(), i32> {
        self.data.map.bytes_mut()[..data.len()].copy_from_slice(data);
        self.command(unit, ATA_WRITE_DMA_EXT, lba, count, true, data.len())
    }
    fn flush(&mut self, unit: usize) -> Result<(), i32> {
        self.command(unit, ATA_FLUSH_EXT, 0, 0, false, 0)
    }
    fn stats(&self) -> (u64, u64) {
        (self.irqs, self.done)
    }
}

fn open(dev: Handle) -> Result<Ahci, &'static str> {
    let info = sys::device_info(dev).map_err(|_| "device_info failed")?;
    if info.bar_kind[5] != 1 || info.bar_size[5] < 0x180 {
        return Err("no ABAR (BAR 5)");
    }
    sys::config_write(dev, 0x04, 2, 0x6).map_err(|_| "cannot enable the device")?;
    let vmo = sys::device_map_bar(dev, 5).map_err(|_| "cannot map the ABAR")?;
    let abar = Mapping::of(vmo, info.bar_size[5]).map_err(|_| "cannot map the ABAR")?;
    let irq = sys::device_interrupt(dev, 0).map_err(|_| "no interrupt")?;
    let data = Dma::new(dev, DATA_PAGES as u64 * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin the data buffer")?;
    let mut a = Ahci { abar, irq, data, ports: [const { None }; MAX_UNITS], n: 0, done: 0, irqs: 0 };
    // Reset the controller (whatever the firmware or a crashed instance left), AHCI mode on.
    a.w(GHC, GHC_AE);
    a.w(GHC, GHC_AE | GHC_HR);
    if !wait_until(|| a.r(GHC) & GHC_HR == 0, 1000) {
        return Err("controller reset timed out");
    }
    a.w(GHC, GHC_AE);
    let ports = a.r(PI);
    let nports = (a.r(CAP) & 0x1F) + 1;
    let max_port_reg = port_reg(nports.min(32), 0);
    if max_port_reg > info.bar_size[5] {
        return Err("ABAR smaller than its ports");
    }
    for p in 0..nports.min(32) {
        if ports & 1 << p == 0 || a.n == MAX_UNITS {
            continue;
        }
        if !a.stop(p) {
            println!("ahci: port {} does not stop", p);
            continue;
        }
        let ssts = a.r(port_reg(p, P_SSTS));
        if ssts & 0xF != 3 {
            continue; // no device (or no PHY communication)
        }
        let Ok(mem) = Dma::new(dev, 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else { return Err("cannot pin port memory") };
        let (clb, fb) = (mem.dev_addr(0), mem.dev_addr(1024));
        a.w(port_reg(p, P_CLB), clb as u32);
        a.w(port_reg(p, P_CLB) + 4, (clb >> 32) as u32);
        a.w(port_reg(p, P_FB), fb as u32);
        a.w(port_reg(p, P_FB) + 4, (fb >> 32) as u32);
        a.w(port_reg(p, P_SERR), !0);
        a.w(port_reg(p, P_IS), !0);
        let c = a.r(port_reg(p, P_CMD));
        a.w(port_reg(p, P_CMD), c | CMD_FRE);
        if !wait_until(|| a.r(port_reg(p, P_TFD)) & 0x88 == 0, 1000) {
            println!("ahci: port {}: device stays busy", p);
            continue;
        }
        if a.r(port_reg(p, P_SIG)) != SIG_ATA {
            continue; // ATAPI, port multiplier, ...: not a disk we drive
        }
        a.w(port_reg(p, P_CMD), c | CMD_FRE | CMD_ST);
        a.w(port_reg(p, P_IE), 1 | IS_TFES); // D2H register FIS, task file error
        let u = a.n;
        a.ports[u] = Some(Port { index: p, mem, sectors: 0, model: [0; 40], model_len: 0 });
        a.n += 1;
    }
    a.w(IS, !0);
    a.w(GHC, GHC_AE | GHC_IE);
    // Identify each disk.
    let mut keep = 0;
    for u in 0..a.n {
        if a.command(u, ATA_IDENTIFY, 0, 0, false, SECTOR).is_err() {
            a.ports[u] = None;
            continue;
        }
        let id = a.data.map.bytes();
        let w = |i: usize| u16::from_le_bytes([id[2 * i], id[2 * i + 1]]);
        let sectors = if w(83) & 1 << 10 != 0 {
            u64::from(w(100)) | u64::from(w(101)) << 16 | u64::from(w(102)) << 32 | u64::from(w(103)) << 48
        } else {
            u64::from(w(60)) | u64::from(w(61)) << 16
        };
        let mut model = [0u8; 40];
        for i in 0..20 {
            let x = w(27 + i);
            model[2 * i] = (x >> 8) as u8;
            model[2 * i + 1] = x as u8;
        }
        let len = model.iter().rposition(|&c| c != b' ' && c != 0).map_or(0, |i| i + 1);
        if let Some(mut port) = a.ports[u].take() {
            port.sectors = sectors.min(1 << 48);
            port.model = model;
            port.model_len = len;
            for c in &mut port.model[..len] {
                if !(0x20..0x7F).contains(c) {
                    *c = b'?';
                }
            }
            a.ports[keep] = Some(port);
            keep += 1;
        }
    }
    a.n = keep;
    Ok(a)
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "ahci") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ch = libd::startup_handle(proto::TAG_CONTROL);
    let mut a = match open(dev) {
        Ok(a) => a,
        Err(e) => {
            println!("ahci: {}", e);
            return 2;
        }
    };
    let info = sys::device_info(dev).unwrap_or_default();
    for p in a.ports.iter().take(a.n).flatten() {
        {
            println!(
                "ahci: port {}: {} sectors ({} MiB), \"{}\"",
                p.index,
                p.sectors,
                p.sectors / 2048,
                core::str::from_utf8(&p.model[..p.model_len]).unwrap_or("?")
            );
        }
    }
    println!(
        "ahci: {} disk(s) on {}, MSI, DMA {}",
        a.n,
        info.name(),
        if info.flags & sys::DEV_FLAG_IOMMU != 0 { "confined by the IOMMU" } else { "NOT confined (no IOMMU)" }
    );
    blkserve::serve("ahci", &mut a, ch)
}
