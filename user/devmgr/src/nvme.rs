//! NVMe driver (`nvme.ddrv`). Namespace 1 is the unit. One admin queue pair and one
//! I/O queue pair (16 entries), one command at a time; PRP lists for transfers over two pages;
//! MSI-X entry 0 for both queues. Queues, identify data, PRP list and the data buffer are
//! pinned for the device (IOMMU-confined).
//!
//! The controller is untrusted: completions are matched by command id and phase, their queue
//! head checked, and a command that does not complete in time fails.

use libd::proto::{self, MAX_SECTORS, SECTOR};
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Startup, println};

use crate::blkserve::{self, Disk};

const REG_CAP: u64 = 0x00;
const REG_VS: u64 = 0x08;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;

const QSIZE: u16 = 16;
const DATA_PAGES: usize = (MAX_SECTORS as usize * SECTOR).div_ceil(4096);
const MS: u64 = 1_000_000;

// Pages of `mem`: admin SQ, admin CQ, I/O SQ, I/O CQ, identify, PRP list.
const PG_ASQ: u64 = 0;
const PG_ACQ: u64 = 1;
const PG_IOSQ: u64 = 2;
const PG_IOCQ: u64 = 3;
const PG_ID: u64 = 4;
const PG_PRP: u64 = 5;

struct Queue {
    sq: u64, // page index of the submission ring
    cq: u64,
    tail: u16,
    head: u16,
    phase: u32,
    qid: u64,
}

struct Nvme {
    bar: Mapping,
    mem: Dma,
    data: Dma,
    irq: Handle,
    stride: u64,
    admin: Queue,
    io: Queue,
    cid: u16,
    sectors: u64,
    model: [u8; 40],
    model_len: usize,
    done: u64,
    irqs: u64,
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

impl Nvme {
    fn r32(&self, o: u64) -> u32 {
        self.bar.r32(o)
    }
    fn w32(&self, o: u64, v: u32) {
        self.bar.w32(o, v)
    }
    fn w64(&self, o: u64, v: u64) {
        self.bar.w32(o, v as u32);
        self.bar.w32(o + 4, (v >> 32) as u32);
    }
    fn doorbell(&self, qid: u64, cq: bool, v: u16) {
        self.w32(0x1000 + (2 * qid + u64::from(cq)) * self.stride, u32::from(v));
    }

    /// Submit one command on `admin` or the I/O queue and wait for its completion: DW0 of it.
    fn submit(&mut self, admin: bool, cmd: &[u32; 16], timeout_ms: u64) -> Result<u32, i32> {
        self.cid = self.cid.wrapping_add(1);
        let cid = self.cid;
        let q = if admin { &mut self.admin } else { &mut self.io };
        let m = &self.mem.map;
        let base = q.sq * 4096 + u64::from(q.tail) * 64;
        for (i, &d) in cmd.iter().enumerate() {
            m.w32(base + 4 * i as u64, d);
        }
        m.w32(base, cmd[0] & 0xFFFF | u32::from(cid) << 16);
        q.tail = (q.tail + 1) % QSIZE;
        let (qid, tail) = (q.qid, q.tail);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.doorbell(qid, false, tail);
        let deadline = sys::clock_ns() + timeout_ms * MS;
        loop {
            let q = if admin { &mut self.admin } else { &mut self.io };
            let e = q.cq * 4096 + u64::from(q.head) * 16;
            let dw3 = self.mem.map.r32(e + 12);
            if (dw3 >> 16) & 1 == q.phase {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                let dw0 = self.mem.map.r32(e);
                let sq_head = self.mem.map.r32(e + 8) & 0xFFFF;
                q.head = (q.head + 1) % QSIZE;
                if q.head == 0 {
                    q.phase ^= 1;
                }
                let (qid, head) = (q.qid, q.head);
                self.doorbell(qid, true, head);
                if sq_head >= u32::from(QSIZE) || (dw3 & 0xFFFF) as u16 != cid {
                    println!("nvme: bad completion (command id {:#x}, queue head {})", dw3 & 0xFFFF, sq_head);
                    return Err(proto::ERR_IO);
                }
                let status = (dw3 >> 17) & 0x7FFF;
                if status != 0 {
                    println!("nvme: command {:#x} failed: status {:#x}", cmd[0] & 0xFF, status);
                    return Err(proto::ERR_IO);
                }
                self.done += 1;
                return Ok(dw0);
            }
            let now = sys::clock_ns();
            if now >= deadline {
                println!("nvme: command {:#x} timed out", cmd[0] & 0xFF);
                return Err(sys::ERR_TIMED_OUT as i32);
            }
            let _ = sys::object_wait(self.irq, sys::SIGNALED, (deadline - now).min(10 * MS));
            if let Ok(n) = sys::interrupt_ack(self.irq) {
                self.irqs = n;
            }
        }
    }

    /// A read or write of `count` sectors at `lba` through the data buffer.
    fn rw(&mut self, opcode: u32, lba: u64, count: u64) -> Result<(), i32> {
        let bytes = count as usize * SECTOR;
        let pages = bytes.div_ceil(4096);
        let mut c = [0u32; 16];
        c[0] = opcode;
        c[1] = 1; // namespace 1
        let prp1 = self.data.dev_addr(0);
        let prp2 = match pages {
            1 => 0,
            2 => self.data.dev_addr(4096),
            _ => {
                for i in 1..pages {
                    self.mem.map.w64(PG_PRP * 4096 + 8 * (i as u64 - 1), self.data.dev_addr(i as u64 * 4096));
                }
                self.mem.dev_addr(PG_PRP * 4096)
            }
        };
        c[6] = prp1 as u32;
        c[7] = (prp1 >> 32) as u32;
        c[8] = prp2 as u32;
        c[9] = (prp2 >> 32) as u32;
        c[10] = lba as u32;
        c[11] = (lba >> 32) as u32;
        c[12] = (count - 1) as u32;
        self.submit(false, &c, 5000).map(|_| ())
    }
}

impl Disk for Nvme {
    fn units(&self) -> usize {
        1
    }
    fn capacity(&self, _unit: usize) -> u64 {
        self.sectors
    }
    fn model(&self, _unit: usize) -> &[u8] {
        &self.model[..self.model_len]
    }
    fn read(&mut self, _unit: usize, lba: u64, count: u64, out: &mut [u8]) -> Result<(), i32> {
        self.rw(0x02, lba, count)?;
        out.copy_from_slice(&self.data.map.bytes()[..out.len()]);
        Ok(())
    }
    fn write(&mut self, _unit: usize, lba: u64, count: u64, data: &[u8]) -> Result<(), i32> {
        self.data.map.bytes_mut()[..data.len()].copy_from_slice(data);
        self.rw(0x01, lba, count)
    }
    fn flush(&mut self, _unit: usize) -> Result<(), i32> {
        let mut c = [0u32; 16];
        c[1] = 1;
        self.submit(false, &c, 10_000).map(|_| ())
    }
    fn stats(&self) -> (u64, u64) {
        (self.irqs, self.done)
    }
}

fn open(dev: Handle) -> Result<Nvme, &'static str> {
    let info = sys::device_info(dev).map_err(|_| "device_info failed")?;
    if info.bar_kind[0] != 1 || info.bar_size[0] < 0x2000 {
        return Err("BAR 0 is not a register window");
    }
    sys::config_write(dev, 0x04, 2, 0x6).map_err(|_| "cannot enable the device")?;
    let vmo = sys::device_map_bar(dev, 0).map_err(|_| "cannot map BAR 0")?;
    let bar = Mapping::of(vmo, info.bar_size[0]).map_err(|_| "cannot map BAR 0")?;
    let cap = u64::from(bar.r32(REG_CAP)) | u64::from(bar.r32(REG_CAP + 4)) << 32;
    let mqes = (cap & 0xFFFF) as u16;
    let stride = 4u64 << ((cap >> 32) & 0xF);
    let timeout = ((cap >> 24) & 0xFF).max(1) * 500;
    if mqes + 1 < QSIZE {
        return Err("queues too small");
    }
    if (cap >> 37) & 1 == 0 || (cap >> 48) & 0xF != 0 {
        return Err("no NVM command set or 4 KiB pages");
    }
    if 0x1000 + 4 * stride > info.bar_size[0] {
        return Err("doorbells outside BAR 0");
    }
    let mem = Dma::new(dev, 6 * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin queue memory")?;
    let data = Dma::new(dev, DATA_PAGES as u64 * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin the data buffer")?;
    let irq = sys::device_interrupt(dev, 0).map_err(|_| "no interrupt")?;
    let mut n = Nvme {
        bar,
        mem,
        data,
        irq,
        stride,
        admin: Queue { sq: PG_ASQ, cq: PG_ACQ, tail: 0, head: 0, phase: 1, qid: 0 },
        io: Queue { sq: PG_IOSQ, cq: PG_IOCQ, tail: 0, head: 0, phase: 1, qid: 1 },
        cid: 0,
        sectors: 0,
        model: [0; 40],
        model_len: 0,
        done: 0,
        irqs: 0,
    };
    // Disable (resets the controller and its queues), program the admin queue, enable.
    n.w32(REG_CC, 0);
    if !wait_until(|| n.r32(REG_CSTS) & 1 == 0, timeout) {
        return Err("controller did not stop");
    }
    n.w32(REG_AQA, u32::from(QSIZE - 1) << 16 | u32::from(QSIZE - 1));
    n.w64(REG_ASQ, n.mem.dev_addr(PG_ASQ * 4096));
    n.w64(REG_ACQ, n.mem.dev_addr(PG_ACQ * 4096));
    n.w32(REG_CC, 1 | 6 << 16 | 4 << 20);
    if !wait_until(|| n.r32(REG_CSTS) & 3 != 0, timeout) || n.r32(REG_CSTS) & 2 != 0 {
        return Err("controller did not become ready");
    }
    // Identify the controller and namespace 1.
    let idp = n.mem.dev_addr(PG_ID * 4096);
    let mut c = [0u32; 16];
    c[0] = 0x06;
    c[6] = idp as u32;
    c[7] = (idp >> 32) as u32;
    c[10] = 1;
    n.submit(true, &c, 2000).map_err(|_| "identify controller failed")?;
    let id = &n.mem.map.bytes()[(PG_ID * 4096) as usize..(PG_ID * 4096 + 4096) as usize];
    let mut model = [0u8; 40];
    model.copy_from_slice(&id[24..64]);
    let nn = u32::from_le_bytes([id[516], id[517], id[518], id[519]]);
    if nn == 0 {
        return Err("no namespaces");
    }
    c[1] = 1;
    c[10] = 0;
    n.submit(true, &c, 2000).map_err(|_| "identify namespace failed")?;
    let id = &n.mem.map.bytes()[(PG_ID * 4096) as usize..(PG_ID * 4096 + 4096) as usize];
    let nsze = u64::from_le_bytes(id[0..8].try_into().unwrap_or_default());
    let flbas = usize::from(id[26] & 0xF);
    let lbads = id[128 + 4 * flbas + 2];
    if lbads != 9 {
        return Err("namespace 1 does not use 512-byte sectors");
    }
    n.sectors = nsze.min(1 << 48);
    n.model_len = model.iter().rposition(|&c| c != b' ' && c != 0).map_or(0, |i| i + 1);
    for x in &mut model[..n.model_len] {
        if !(0x20..0x7F).contains(x) {
            *x = b'?';
        }
    }
    n.model = model;
    // The I/O queue pair: completion queue first (interrupts on, vector 0), then submissions.
    let cq = n.mem.dev_addr(PG_IOCQ * 4096);
    let mut c = [0u32; 16];
    c[0] = 0x05;
    c[6] = cq as u32;
    c[7] = (cq >> 32) as u32;
    c[10] = u32::from(QSIZE - 1) << 16 | 1;
    c[11] = 1 << 1 | 1;
    n.submit(true, &c, 2000).map_err(|_| "cannot create the I/O completion queue")?;
    let sq = n.mem.dev_addr(PG_IOSQ * 4096);
    let mut c = [0u32; 16];
    c[0] = 0x01;
    c[6] = sq as u32;
    c[7] = (sq >> 32) as u32;
    c[10] = u32::from(QSIZE - 1) << 16 | 1;
    c[11] = 1 << 16 | 1;
    n.submit(true, &c, 2000).map_err(|_| "cannot create the I/O submission queue")?;
    Ok(n)
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "nvme") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ch = libd::startup_handle(proto::TAG_CONTROL);
    let mut n = match open(dev) {
        Ok(n) => n,
        Err(e) => {
            println!("nvme: {}", e);
            return 2;
        }
    };
    let info = sys::device_info(dev).unwrap_or_default();
    let vs = n.r32(REG_VS);
    println!(
        "nvme: NVMe {}.{} \"{}\", namespace 1: {} sectors ({} MiB) on {}, MSI-X, DMA {}",
        vs >> 16,
        (vs >> 8) & 0xFF,
        core::str::from_utf8(&n.model[..n.model_len]).unwrap_or("?"),
        n.sectors,
        n.sectors / 2048,
        info.name(),
        if info.flags & sys::DEV_FLAG_IOMMU != 0 { "confined by the IOMMU" } else { "NOT confined (no IOMMU)" }
    );
    blkserve::serve("nvme", &mut n, ch)
}
