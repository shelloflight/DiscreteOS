//! The request loop every block driver shares. A driver implements `Disk` for its
//! hardware and calls `serve`: it announces its disks (READY with the number of units, then DISK
//! per unit), then serves
//! requests on its control channel (unit 0, for the device manager's tests) and on each channel
//! attached to a unit (BLK_ATTACH, from the device manager; the storage service holds the other
//! end). Requests are checked here before the hardware sees them: unit, range, size.
//!
//! Disks are read-only unless the device manager started the driver with the argument `rw`
//! (storage and driver tests only; docs/hardware.md). Writes and flushes are then refused here,
//! before any command reaches the hardware, so a real machine's disks cannot be changed by D-OS
//! whatever the layers above do.

use libd::proto::{self, HEADER, Header, MAX_SECTORS, SECTOR};
use libd::sys::{self, Handle};
use libd::{Port, println};

pub const MAX_UNITS: usize = 8;

pub trait Disk {
    fn units(&self) -> usize;
    fn capacity(&self, unit: usize) -> u64;
    /// A short model name for the DISK message.
    fn model(&self, unit: usize) -> &[u8];
    /// Read `count` sectors at `lba` into `out` (exactly count * 512 bytes).
    fn read(&mut self, unit: usize, lba: u64, count: u64, out: &mut [u8]) -> Result<(), i32>;
    fn write(&mut self, unit: usize, lba: u64, count: u64, data: &[u8]) -> Result<(), i32>;
    fn flush(&mut self, unit: usize) -> Result<(), i32>;
    /// (interrupts handled, requests done)
    fn stats(&self) -> (u64, u64);
    /// Driver-specific requests on the control channel (tests). `Some(code)` ends the driver
    /// with that exit code; None if the request was handled (or refused) here.
    fn control(&mut self, _ch: Handle, h: &Header) -> Option<i32> {
        reply(_ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
        None
    }
}

pub fn reply(ch: Handle, h: &Header, status: i32, a: u64, b: u64, payload: &[u8]) {
    let mut buf = [0u8; HEADER + MAX_SECTORS as usize * SECTOR];
    Header { txid: h.txid, op: h.op, status, a, b }.put(&mut buf);
    buf[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    sys::channel_write(ch, &buf[..HEADER + payload.len()]);
}

fn block_op(d: &mut impl Disk, ch: Handle, unit: usize, h: &Header, msg: &[u8], data: &mut [u8], writable: bool) {
    let cap = d.capacity(unit);
    if !writable && matches!(h.op, proto::BLK_WRITE | proto::BLK_FLUSH) {
        reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
        return;
    }
    let ok_range = |lba: u64, cnt: u64| cnt > 0 && cnt <= MAX_SECTORS && lba.checked_add(cnt).is_some_and(|e| e <= cap);
    match h.op {
        proto::BLK_READ if ok_range(h.a, h.b) => {
            let len = h.b as usize * SECTOR;
            match d.read(unit, h.a, h.b, &mut data[..len]) {
                Ok(()) => reply(ch, h, 0, 0, 0, &data[..len]),
                Err(e) => reply(ch, h, e, 0, 0, &[]),
            }
        }
        proto::BLK_WRITE if ok_range(h.a, h.b) && msg.len() == HEADER + h.b as usize * SECTOR => {
            let r = d.write(unit, h.a, h.b, &msg[HEADER..]);
            reply(ch, h, r.err().unwrap_or(0), 0, 0, &[]);
        }
        proto::BLK_FLUSH => {
            let r = d.flush(unit);
            reply(ch, h, r.err().unwrap_or(0), 0, 0, &[]);
        }
        proto::STATS => {
            let (i, n) = d.stats();
            reply(ch, h, 0, i, n, &[]);
        }
        _ => reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]),
    }
}

/// Announce the disks, then serve requests until the device manager goes away (exit 0) or the
/// driver must end (`control` returned an exit code).
pub fn serve(name: &str, d: &mut impl Disk, ctl: Handle) -> i32 {
    let units = d.units().min(MAX_UNITS);
    let writable = libd::args() == b"rw";
    // b: how many DISK messages follow (the device manager waits for them before it tells the
    // storage service the disks present at boot are all known).
    proto::send(ctl, proto::READY, if units > 0 { d.capacity(0) } else { 0 }, units as u64);
    for u in 0..units {
        let mut m = [0u8; HEADER + 40];
        Header { txid: 0, op: proto::DISK, status: 0, a: u as u64, b: d.capacity(u) }.put(&mut m);
        let model = d.model(u);
        let n = model.len().min(40);
        m[HEADER..HEADER + n].copy_from_slice(&model[..n]);
        sys::channel_write(ctl, &m[..HEADER + n]);
    }
    let Ok(port) = Port::new(16) else {
        println!("{}: cannot create a port", name);
        return 2;
    };
    let mut attached: [Handle; MAX_UNITS] = [0; MAX_UNITS];
    port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, 0);
    let mut msg = [0u8; HEADER + MAX_SECTORS as usize * SECTOR];
    let mut data = [0u8; MAX_SECTORS as usize * SECTOR];
    loop {
        let Some((key, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        let (ch, unit) = if key == 0 { (ctl, 0) } else { (attached[(key - 1) as usize % MAX_UNITS], (key - 1) as usize % MAX_UNITS) };
        if ch == 0 {
            continue;
        }
        // Drain the channel, then wait on it again.
        loop {
            let mut hs = [0 as Handle; 1];
            let (n, nh) = match sys::channel_read_h(ch, &mut msg, &mut hs, 0) {
                Ok(r) => r,
                Err(sys::ERR_SHOULD_WAIT) => {
                    port.arm(ch, sys::READABLE | sys::PEER_CLOSED, key);
                    break;
                }
                Err(_) if key == 0 => return 0, // the device manager is gone
                Err(_) => {
                    sys::handle_close(ch); // the storage service closed this disk
                    attached[unit] = 0;
                    break;
                }
            };
            let Some(h) = Header::get(&msg[..n]) else { continue };
            if key == 0 && h.op == proto::BLK_ATTACH {
                let u = h.a as usize;
                if nh == 1 && u < units {
                    if attached[u] != 0 {
                        sys::handle_close(attached[u]);
                    }
                    attached[u] = hs[0];
                    port.arm(hs[0], sys::READABLE | sys::PEER_CLOSED, u as u64 + 1);
                } else if nh == 1 {
                    sys::handle_close(hs[0]);
                }
                continue;
            }
            if nh > 0 {
                sys::handle_close(hs[0]); // requests carry no handles
            }
            if key == 0 && !matches!(h.op, proto::BLK_READ | proto::BLK_WRITE | proto::BLK_FLUSH | proto::STATS) {
                if let Some(code) = d.control(ch, &h) {
                    return code;
                }
                continue;
            }
            if unit >= units {
                reply(ch, &h, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                continue;
            }
            block_op(d, ch, unit, &h, &msg[..n], &mut data, writable);
        }
    }
}
