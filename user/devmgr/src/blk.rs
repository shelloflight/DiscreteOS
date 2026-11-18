//! virtio-blk driver (`virtio-blk.ddrv`). One request at a time: read or write up to
//! `MAX_SECTORS` sectors, through a request chain of header (device reads), data pages, status
//! byte (device writes); flush when the device has a write cache (VIRTIO_BLK_F_FLUSH).
//! Interrupt: MSI-X entry 0 (request queue 0). Requests come through `blkserve`.

use libd::proto::{self, Header, MAX_SECTORS, SECTOR};
use libd::sys::{self, Handle};
use libd::{Dma, Startup, println};

use crate::blkserve::{self, Disk, reply};
use crate::virtio::{DESC_NEXT, DESC_WRITE, STATUS_NEEDS_RESET, Virtio};

const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const F_FLUSH: u64 = 1 << 9;
const DATA_PAGES: usize = (MAX_SECTORS as usize * SECTOR).div_ceil(4096);
/// Physical address of the kernel image (the bootloader loads it at 1 MiB): the target of the
/// DMA test, which the IOMMU must block.
const KERNEL_PHYS: u64 = 0x10_0000;

struct Blk {
    v: Virtio,
    q: crate::virtio::Queue,
    req: Dma,  // header at 0 (16 bytes), status at 16
    data: Dma, // DATA_PAGES pages
    capacity: u64,
    flush: bool,
    done: u64,
    iommu: bool,
}

impl Blk {
    /// One request: `sectors` at `lba`; data moves through `self.data`. With `escape`, the data
    /// descriptor points at kernel memory instead (test only). Returns the device status byte.
    fn io(&mut self, ty: u32, lba: u64, sectors: u64, escape: bool, timeout: u64) -> Result<u8, &'static str> {
        let r = &self.req.map;
        r.w32(0, ty);
        r.w32(4, 0);
        r.w64(8, lba);
        r.w8(16, 0xFF);
        let q = &self.q;
        q.desc(0, self.req.dev_addr(0), 16, DESC_NEXT, 1);
        let bytes = sectors as usize * SECTOR;
        let write_flag = if ty == T_IN { DESC_WRITE } else { 0 };
        let mut d = 1u16;
        let mut done = 0usize;
        while done < bytes {
            let n = (bytes - done).min(4096 - done % 4096);
            let addr = if escape { KERNEL_PHYS + done as u64 } else { self.data.dev_addr(done as u64) };
            q.desc(d, addr, n as u32, write_flag | DESC_NEXT, d + 1);
            d += 1;
            done += n;
        }
        q.desc(d, self.req.dev_addr(16), 1, DESC_WRITE, 0);
        self.q.push(0);
        self.v.notify(&self.q);
        match self.q.wait(timeout) {
            Some((0, _)) => {
                self.done += 1;
                Ok(self.req.map.r8(16))
            }
            Some(_) => Err("device completed an unknown request"),
            None => Err("timed out"),
        }
    }

    fn status(r: Result<u8, &'static str>, what: &str) -> Result<(), i32> {
        match r {
            Ok(0) => Ok(()),
            Ok(_) => Err(proto::ERR_IO),
            Err(e) => {
                println!("virtio-blk: {} failed: {}", what, e);
                Err(sys::ERR_TIMED_OUT as i32)
            }
        }
    }
}

impl Disk for Blk {
    fn units(&self) -> usize {
        1
    }
    fn capacity(&self, _unit: usize) -> u64 {
        self.capacity
    }
    fn model(&self, _unit: usize) -> &[u8] {
        b"virtio-blk"
    }
    fn read(&mut self, _unit: usize, lba: u64, count: u64, out: &mut [u8]) -> Result<(), i32> {
        let r = self.io(T_IN, lba, count, false, 2_000_000_000);
        Self::status(r, "read")?;
        out.copy_from_slice(&self.data.map.bytes()[..out.len()]);
        Ok(())
    }
    fn write(&mut self, _unit: usize, lba: u64, count: u64, data: &[u8]) -> Result<(), i32> {
        self.data.map.bytes_mut()[..data.len()].copy_from_slice(data);
        let r = self.io(T_OUT, lba, count, false, 2_000_000_000);
        Self::status(r, "write")
    }
    fn flush(&mut self, _unit: usize) -> Result<(), i32> {
        if !self.flush {
            return Ok(()); // no write cache: every completed write is durable
        }
        let r = self.io(T_FLUSH, 0, 0, false, 5_000_000_000);
        Self::status(r, "flush")
    }
    fn stats(&self) -> (u64, u64) {
        (self.q.interrupts(), self.done)
    }
    fn control(&mut self, ch: Handle, h: &Header) -> Option<i32> {
        match h.op {
            proto::TEST_CRASH => {
                println!("virtio-blk: crashing on request (restart test)");
                // SAFETY: deliberately faults (test): a write to an unmapped address.
                unsafe { core::ptr::write_volatile(0x10 as *mut u32, 1) };
                None
            }
            proto::TEST_DMA_ESCAPE => {
                if !self.iommu {
                    reply(ch, h, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]);
                    return None; // without an IOMMU the device really would overwrite the kernel
                }
                println!("virtio-blk: DMA test: asking the device to write sector 0 to {:#x} (kernel memory)", KERNEL_PHYS);
                let st = self.io(T_IN, 0, 1, true, 300_000_000);
                let status = self.v.status();
                let code = match st {
                    Ok(0) => 0,
                    Ok(_) => -1,
                    Err(_) => sys::ERR_TIMED_OUT as i32,
                };
                reply(ch, h, code, u64::from(status), u64::from(status & STATUS_NEEDS_RESET != 0), &[]);
                Some(3) // the device needs a reset: the device manager restarts this driver
            }
            _ => {
                reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                None
            }
        }
    }
}

fn open(dev: Handle) -> Result<Blk, &'static str> {
    let (v, features) = Virtio::open_with(dev, F_FLUSH)?;
    let cfg = v.devcfg.ok_or("no device configuration")?;
    let capacity = u64::from(v.r32(cfg, 0)) | u64::from(v.r32(cfg, 4)) << 32;
    let q = v.queue(0)?;
    if usize::from(q.size) < DATA_PAGES + 2 {
        return Err("request queue too small for a full request chain");
    }
    let req = Dma::new(dev, 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin the request page")?;
    let data = Dma::new(dev, DATA_PAGES as u64 * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE)
        .map_err(|_| "cannot pin the data buffer")?;
    v.driver_ok();
    let info = sys::device_info(dev).unwrap_or_default();
    Ok(Blk { v, q, req, data, capacity, flush: features & F_FLUSH != 0, done: 0, iommu: info.flags & sys::DEV_FLAG_IOMMU != 0 })
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "virtio-blk") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ch = libd::startup_handle(proto::TAG_CONTROL);
    let mut b = match open(dev) {
        Ok(b) => b,
        Err(e) => {
            println!("virtio-blk: {}", e);
            return 2;
        }
    };
    let info = sys::device_info(dev).unwrap_or_default();
    println!(
        "virtio-blk: {} sectors ({} KiB) on {}, MSI-X, {}, DMA {}",
        b.capacity,
        b.capacity / 2,
        info.name(),
        if b.flush { "write cache (flush)" } else { "no write cache" },
        if b.iommu { "confined by the IOMMU" } else { "NOT confined (no IOMMU)" }
    );
    blkserve::serve("virtio-blk", &mut b, ch)
}
