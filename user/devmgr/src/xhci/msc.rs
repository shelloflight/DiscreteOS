//! USB mass storage (bulk-only transport + SCSI) served through the shared block-driver loop.

use libd::handle::sleep;
use libd::proto::Header;
use libd::sys::{self, Handle};
use libd::Port;

use super::*;

/// A USB disk (bulk-only mass storage) being served.
pub(super) struct UsbDisk {
    /// Which of the `MAX_DISKS` (its pages, its unit number).
    pub(super) idx: usize,
    pub(super) id: Ident,
    pub(super) slot: u32,
    pub(super) loc: Loc,
    pub(super) iface: u8,
    pub(super) in_ep: u8,
    pub(super) out_ep: u8,
    pub(super) in_ring: Ring,
    pub(super) out_ring: Ring,
    pub(super) mps: u32,
    pub(super) tag: u32,
    pub(super) sectors: u64,
    pub(super) model: [u8; 40],
    pub(super) model_len: usize,
    /// The channel the device manager attached for this unit (0: none yet).
    pub(super) ch: Handle,
}

impl UsbDisk {
    fn in_dci(&self) -> u32 {
        u32::from(self.in_ep) * 2 + 1
    }
    fn out_dci(&self) -> u32 {
        u32::from(self.out_ep) * 2
    }
    fn page(&self, i: u64) -> u64 {
        PG_DISK + DISK_PAGES * self.idx as u64 + i
    }
}

impl Xhci {
    /// USB mass storage (bulk-only transport, SCSI): configure the bulk endpoints, then ask the
    /// device what it is and how big.
    pub(super) fn setup_storage(&mut self, slot: u32, loc: Loc, cfg_value: u8, id: Ident, f: Iface) -> Result<Found, &'static str> {
        let Some(idx) = self.disks.iter().position(Option::is_none) else {
            return Ok(Found::Other(id)); // MAX_DISKS served already
        };
        let ((ie, imps, _, iburst), (oe, omps, oburst)) = (f.ep_in.unwrap_or_default(), f.ep_out.unwrap_or_default());
        self.control(slot, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        let mut d = UsbDisk {
            idx,
            id,
            slot,
            loc,
            iface: f.num,
            in_ep: ie,
            out_ep: oe,
            in_ring: Ring::new(0),
            out_ring: Ring::new(0),
            mps: imps.min(omps),
            tag: 0,
            sectors: 0,
            model: [0; 40],
            model_len: 0,
            ch: 0,
        };
        d.in_ring = Ring::new(d.page(0));
        d.out_ring = Ring::new(d.page(1));
        self.clear_page(PG_IN);
        self.ep_ctx(d.in_dci(), 6, imps, 0, u32::from(iburst), d.page(0));
        self.ep_ctx(d.out_dci(), 2, omps, 0, u32::from(oburst), d.page(1));
        self.ctx_w(PG_IN, 0, 1, 1 | 1 << d.in_dci() | 1 << d.out_dci());
        self.slot_ctx(&loc, d.in_dci().max(d.out_dci()), 0, 0);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint (storage) failed")?;
        self.disk_init(&mut d)?;
        Ok(Found::Disk(d))
    }

    // ---- mass storage (bulk-only transport) -----------------------------------------------------

    /// One transfer on a bulk endpoint of `d`: `len` bytes at `off` of page `page` (several pages
    /// if `off` is 0), one TRB per page. Ok(bytes moved) or Err(completion code, 0 = timeout).
    fn bulk(&mut self, d: &mut UsbDisk, input: bool, page: u64, off: u64, len: u32) -> Result<u32, u32> {
        let (dci, mut ring) = if input {
            (d.in_dci(), core::mem::replace(&mut d.in_ring, Ring::new(0)))
        } else {
            (d.out_dci(), core::mem::replace(&mut d.out_ring, Ring::new(0)))
        };
        let r = self.bulk_on(d.slot, dci, &mut ring, page, off, len, d.mps);
        if input {
            d.in_ring = ring;
        } else {
            d.out_ring = ring;
        }
        if let Err(c) = r {
            self.last_cc = c;
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn bulk_on(&mut self, slot: u32, dci: u32, ring: &mut Ring, page: u64, off: u64, len: u32, mps: u32) -> Result<u32, u32> {
        let n = (len as usize).div_ceil(4096).clamp(1, DATA_PAGES as usize);
        let mut at = [0u64; DATA_PAGES as usize];
        let mut lens = [0u32; DATA_PAGES as usize];
        for k in 0..n {
            let l = (len - (k as u32) * 4096).min(4096);
            let last = k == n - 1;
            // TD Size: packets still to come after this TRB (at most 31).
            let left = len - (k as u32) * 4096 - l;
            let td = left.div_ceil(mps.max(1)).min(31);
            let ctl = T_NORMAL << 10 | TRB_ISP | if last { TRB_IOC } else { TRB_CH };
            lens[k] = l;
            at[k] = self.enqueue(ring, Trb { param: self.addr(page + k as u64, if k == 0 { off } else { 0 }), status: l | td << 17, control: ctl });
        }
        self.ring_doorbell(slot, dci);
        let last = at[n - 1];
        let e = self.wait_event(5000, |e| e.ty() == E_TRANSFER && e.slot() == slot && e.endpoint() == dci).ok_or(0u32)?;
        match e.code() {
            CC_SUCCESS if e.param == last => Ok(len),
            CC_SUCCESS | CC_SHORT => {
                let k = at[..n].iter().position(|&a| a == e.param).ok_or(0u32)?;
                let moved = (k as u32) * 4096 + lens[k].saturating_sub(e.status & 0xFF_FFFF);
                if e.param != last {
                    // The end of the TD may still report.
                    let _ = self.wait_event(20, |x| x.ty() == E_TRANSFER && x.slot() == slot && x.param == last);
                }
                Ok(moved)
            }
            c => Err(c),
        }
    }

    /// A halted (stalled) endpoint: reset it, move its dequeue pointer past what was queued, and
    /// clear the device's halt.
    fn clear_halt(&mut self, d: &mut UsbDisk, input: bool) {
        let (dci, ep, ring) = if input { (d.in_dci(), d.in_ep | 0x80, &d.in_ring) } else { (d.out_dci(), d.out_ep, &d.out_ring) };
        let deq = self.addr(ring.page, u64::from(ring.enq) * 16) | u64::from(ring.cycle);
        let _ = self.command(Trb { param: 0, status: 0, control: T_RESET_EP << 10 | dci << 16 | d.slot << 24 });
        let _ = self.command(Trb { param: deq, status: 0, control: T_SET_TR_DEQ << 10 | dci << 16 | d.slot << 24 });
        let _ = self.control(d.slot, [0x02, 1, 0, 0, ep, 0, 0, 0], 0);
    }

    /// Bulk-only reset recovery (BOT 5.3.4): the class reset, then both halts cleared.
    fn reset_recovery(&mut self, d: &mut UsbDisk) {
        let _ = self.control(d.slot, [0x21, 0xFF, 0, 0, d.iface, 0, 0, 0], 0);
        self.clear_halt(d, true);
        self.clear_halt(d, false);
    }

    /// One SCSI command through the bulk-only transport: CBW, data (`len` bytes in the disk's data
    /// pages, in or out), CSW. Ok(residue); Err when the command failed or the transport broke.
    fn bot(&mut self, d: &mut UsbDisk, cdb: &[u8], len: u32, input: bool) -> Result<u32, &'static str> {
        d.tag = d.tag.wrapping_add(1);
        let cmd = d.page(2);
        {
            let (m, base) = self.page(cmd);
            let m = &m.map;
            let o = base + CBW;
            m.w32(o, 0x4342_5355);
            m.w32(o + 4, d.tag);
            m.w32(o + 8, len);
            m.w8(o + 12, if input { 0x80 } else { 0 });
            m.w8(o + 13, 0); // LUN 0
            m.w8(o + 14, cdb.len().min(16) as u8);
            for i in 0..16u64 {
                m.w8(o + 15 + i, cdb.get(i as usize).copied().unwrap_or(0));
            }
        }
        if self.bulk(d, false, cmd, CBW, 31).is_err() {
            self.reset_recovery(d);
            return Err("command block refused");
        }
        if len > 0 {
            match self.bulk(d, input, d.page(3), 0, len) {
                Ok(_) => {}
                Err(CC_STALL) => self.clear_halt(d, input),
                Err(_) => {
                    self.reset_recovery(d);
                    return Err("data transfer failed");
                }
            }
        }
        let mut got = self.bulk(d, true, cmd, CSW, 13);
        if got == Err(CC_STALL) {
            self.clear_halt(d, true);
            got = self.bulk(d, true, cmd, CSW, 13);
        }
        if got != Ok(13) {
            self.reset_recovery(d);
            return Err("no command status");
        }
        let (m, base) = self.page(cmd);
        let o = base + CSW;
        let (sig, tag, residue, status) = (m.map.r32(o), m.map.r32(o + 4), m.map.r32(o + 8), m.map.r8(o + 12));
        if sig != 0x5342_5355 || tag != d.tag {
            self.reset_recovery(d);
            return Err("bad command status");
        }
        match status {
            0 => Ok(residue),
            1 => Err("command failed"),
            _ => {
                self.reset_recovery(d);
                Err("phase error")
            }
        }
    }

    /// INQUIRY, TEST UNIT READY (until ready, bounded), READ CAPACITY.
    fn disk_init(&mut self, d: &mut UsbDisk) -> Result<(), &'static str> {
        self.bot(d, &[0x12, 0, 0, 0, 36, 0], 36, true)?;
        let data = d.page(3);
        let mut model = [0u8; 40];
        let mut n = 0;
        let (m, base) = self.page(data);
        // Vendor (8-15) and product (16-31), spaces trimmed.
        for i in 8..32u64 {
            let c = m.map.r8(base + i);
            if i == 16 && n > 0 && model[n - 1] != b' ' {
                model[n] = b' ';
                n += 1;
            }
            if (b' '..=b'~').contains(&c) && !(c == b' ' && (n == 0 || model[n - 1] == b' ')) {
                model[n] = c;
                n += 1;
            }
        }
        while n > 0 && model[n - 1] == b' ' {
            n -= 1;
        }
        (d.model, d.model_len) = (model, n);
        let mut ready = false;
        for _ in 0..20 {
            if self.bot(d, &[0, 0, 0, 0, 0, 0], 0, false).is_ok() {
                ready = true;
                break;
            }
            let _ = self.bot(d, &[0x03, 0, 0, 0, 18, 0], 18, true); // REQUEST SENSE clears the condition
            sleep(100 * MS);
        }
        if !ready {
            return Err("medium not ready");
        }
        self.bot(d, &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8, true)?;
        let (m, base) = self.page(data);
        let be32 = |o: u64| u32::from_be_bytes([m.map.r8(base + o), m.map.r8(base + o + 1), m.map.r8(base + o + 2), m.map.r8(base + o + 3)]);
        let (mut last, mut bl) = (u64::from(be32(0)), be32(4));
        if last == 0xFFFF_FFFF {
            self.bot(d, &[0x9E, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0], 32, true)?;
            let (m, base) = self.page(data);
            let be32 = |o: u64| u32::from_be_bytes([m.map.r8(base + o), m.map.r8(base + o + 1), m.map.r8(base + o + 2), m.map.r8(base + o + 3)]);
            last = u64::from(be32(0)) << 32 | u64::from(be32(4));
            bl = be32(8);
        }
        if bl != 512 {
            return Err("sector size is not 512 bytes");
        }
        d.sectors = last.checked_add(1).ok_or("bad capacity")?;
        Ok(())
    }

    /// Read (`out`) or write (`data`) `count` sectors at `lba` on disk `unit`.
    fn disk_io(&mut self, unit: usize, lba: u64, count: u64, out: Option<&mut [u8]>, data: Option<&[u8]>) -> Result<(), i32> {
        let Some(mut d) = self.disks.get_mut(unit).and_then(Option::take) else { return Err(sys::ERR_BAD_STATE as i32) };
        let r = self.disk_io_on(&mut d, lba, count, out, data);
        self.disks[unit] = Some(d);
        self.requests += 1;
        r
    }

    fn disk_io_on(&mut self, d: &mut UsbDisk, lba: u64, count: u64, out: Option<&mut [u8]>, data: Option<&[u8]>) -> Result<(), i32> {
        let write = data.is_some();
        let bytes = count as usize * 512;
        if count == 0 || count > DATA_PAGES * 8 {
            return Err(sys::ERR_INVALID_ARGS as i32);
        }
        if let Some(src) = data {
            let base = (d.page(3) - PG_FUN) as usize * 4096;
            self.fun_mem.map.bytes_mut()[base..base + bytes].copy_from_slice(&src[..bytes]);
        }
        let mut cdb = [0u8; 16];
        let len = if lba + count <= 1 << 32 {
            cdb[0] = if write { 0x2A } else { 0x28 };
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            10
        } else {
            cdb[0] = if write { 0x8A } else { 0x88 };
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&(count as u32).to_be_bytes());
            16
        };
        match self.bot(d, &cdb[..len], bytes as u32, !write) {
            Ok(0) => {}
            Ok(_) => return Err(sys::ERR_OUT_OF_RANGE as i32), // short: the device did less
            Err(why) => {
                say!(self, "disk on port {}: {} at sector {} ({})", d.loc, if write { "write" } else { "read" }, lba, why);
                return Err(sys::ERR_BAD_STATE as i32);
            }
        }
        if let Some(out) = out {
            let base = (d.page(3) - PG_FUN) as usize * 4096;
            out[..bytes].copy_from_slice(&self.fun_mem.map.bytes()[base..base + bytes]);
        }
        Ok(())
    }

    fn disk_flush(&mut self, unit: usize) -> Result<(), i32> {
        let Some(mut d) = self.disks.get_mut(unit).and_then(Option::take) else { return Err(sys::ERR_BAD_STATE as i32) };
        // SYNCHRONIZE CACHE (10); a device without a cache may refuse it: not an error.
        let r = self.bot(&mut d, &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, false);
        self.disks[unit] = Some(d);
        match r {
            Ok(_) | Err("command failed") => Ok(()),
            Err(_) => Err(sys::ERR_BAD_STATE as i32),
        }
    }
}

/// The block-device view of the USB disks (blkserve.rs): unit = disk index.
struct UsbDisks<'a>(&'a mut Xhci);

impl crate::blkserve::Disk for UsbDisks<'_> {
    fn units(&self) -> usize {
        MAX_DISKS
    }
    fn capacity(&self, unit: usize) -> u64 {
        self.0.disks.get(unit).and_then(|d| d.as_ref()).map_or(0, |d| d.sectors)
    }
    fn model(&self, unit: usize) -> &[u8] {
        self.0.disks.get(unit).and_then(|d| d.as_ref()).map_or(&[], |d| &d.model[..d.model_len])
    }
    fn read(&mut self, unit: usize, lba: u64, count: u64, out: &mut [u8]) -> Result<(), i32> {
        self.0.disk_io(unit, lba, count, Some(out), None)
    }
    fn write(&mut self, unit: usize, lba: u64, count: u64, data: &[u8]) -> Result<(), i32> {
        self.0.disk_io(unit, lba, count, None, Some(data))
    }
    fn flush(&mut self, unit: usize) -> Result<(), i32> {
        self.0.disk_flush(unit)
    }
    fn stats(&self) -> (u64, u64) {
        (0, self.0.requests)
    }
}

/// Requests on disk `u`'s attached channel, until it is empty (then it is watched again) or
/// closed (the storage service let the disk go).
pub(super) fn serve_disk(x: &mut Xhci, u: usize, port: &Port, key: u64, msg: &mut [u8], data: &mut [u8]) {
    let Some(ch) = x.disks[u].as_ref().map(|d| d.ch).filter(|&c| c != 0) else { return };
    let writable = x.disk_rw[u];
    loop {
        let mut hs = [0 as Handle; 2];
        let (n, nh) = match sys::channel_read_h(ch, msg, &mut hs, 0) {
            Ok(v) => v,
            Err(sys::ERR_SHOULD_WAIT) => {
                port.arm(ch, sys::READABLE | sys::PEER_CLOSED, key);
                return;
            }
            Err(_) => {
                sys::handle_close(ch);
                if let Some(d) = x.disks[u].as_mut() {
                    d.ch = 0;
                }
                return;
            }
        };
        for &h in &hs[..nh] {
            sys::handle_close(h);
        }
        let Some(h) = Header::get(&msg[..n]) else { continue };
        crate::blkserve::block_op(&mut UsbDisks(x), ch, u, &h, &msg[..n], data, writable);
    }
}

