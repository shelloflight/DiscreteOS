//! Device manager (`devmgr.dx`) and the user-space drivers, one crate (Cargo.toml).
//!
//! The device manager gets every device handle from init (startup tag DEVICE) and the driver
//! programs (`.ddrv` PROGRAM VMOs). For each device it knows a driver for, it spawns the driver as
//! its own process with exactly three handles: the log, that one device, and a control channel.
//! When a driver dies it quiesces the device (decode and bus mastering off) and starts a new
//! instance, at most `MAX_RESTARTS` times; the rest of the system keeps running.
//!
//! Input drivers send characters; the device manager forwards each one to every client of its
//! `input` endpoint (`proto::INPUT_KEY`; the console service is one). It echoes nothing itself.
//!
//! Block drivers (virtio-blk, AHCI, NVMe) announce their disks. For each one the
//! device manager makes a channel, attaches one end to the driver (BLK_ATTACH) and hands the
//! other to the storage service (DISK_ADD, on the TAG_STORAGE channel from init): block I/O
//! then flows between those two directly. A restarted driver announces its disks again and the
//! storage service gets fresh channels under the same names.
//!
//! As a service (started by the service manager from its manifest), it gets the disks endpoint
//! `storaged.disks` and a control channel: svc::CONNECT replaces the storage channel when the
//! storage service was restarted (every known disk is handed over again), svc::CONNECT "input"
//! adds a client of its input endpoint, svc::SHUTDOWN stops the drivers and ends the device manager.
//!
//! Arguments: none (service: runs for ever), `rw` (the same with writable disks: storage tests), or
//! `test` (the driver tests: device ABI rules, block I/O, crash + restart, DMA blocked by the IOMMU,
//! interrupt delivery, keyboard input; exit 0 when everything passed). Without `rw` or `test`,
//! block drivers are started read-only (blkserve.rs): D-OS never writes a real machine's disks.

#![no_std]

mod ahci;
mod blk;
mod blkserve;
mod input;
mod keymap;
mod nvme;
mod ps2;
mod virtio;
mod xhci;

use libd::fs;
use libd::proto::{self, HEADER, Header, MAX_SECTORS, SECTOR};
use libd::svc;
use libd::sys::{self, DeviceInfo, Handle};
use libd::{Mapping, Port, Startup, println};

libd::entry!(_start, devmgr_main);
libd::entry!(ddrv_ps2, ps2::main);
libd::entry!(ddrv_virtio_blk, blk::main);
libd::entry!(ddrv_virtio_input, input::main);
libd::entry!(ddrv_ahci, ahci::main);
libd::entry!(ddrv_nvme, nvme::main);
libd::entry!(ddrv_xhci, xhci::main);

const MAX_DRIVERS: usize = 8;
const MAX_DISKS: usize = 16;
const MAX_INPUT_CLIENTS: usize = 8;
/// Port key of the control channel from the service manager.
const KEY_MGR: u64 = (MAX_DRIVERS as u64) << 8 | 3;

/// A disk a driver announced (kept to hand it over again to a restarted storage service).
#[derive(Clone, Copy)]
struct Disk {
    drv: usize,
    unit: u64,
    sectors: u64,
    model: [u8; 40],
    model_len: usize,
}

/// Formats into a byte buffer (no allocator).
struct Cursor<'a> {
    b: &'a mut [u8],
    n: usize,
}

impl core::fmt::Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let k = s.len().min(self.b.len() - self.n);
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}
const MAX_RESTARTS: u32 = 3;
const SEC: u64 = 1_000_000_000;

struct Driver {
    prog: &'static str,
    image: Handle,
    dev: Handle,
    info: DeviceInfo,
    proc: Handle,
    ch: Handle,
    ready: bool,
    starts: u32,
    gave_up: bool,
    capacity: u64,
    /// DISK messages announced by READY that have not arrived yet.
    disks_due: u64,
}

struct Mgr {
    drv: [Option<Driver>; MAX_DRIVERS],
    port: Port,
    line: [u8; 128],
    line_len: usize,
    /// The last complete line and which driver typed it (tests).
    last_line: [u8; 128],
    last_len: usize,
    last_from: &'static str,
    lines: u32,
    /// Channel to the storage service (0: none, e.g. `devmgr test`).
    storage: Handle,
    disks: u32,
    known: [Option<Disk>; MAX_DISKS],
    /// Control channel from the service manager (0: started without one).
    mgr: Handle,
    /// SHUTDOWN received.
    stop: bool,
    /// Clients of the input endpoint (the console service).
    input: [Handle; MAX_INPUT_CLIENTS],
    /// Block drivers may write (argument `rw` or `test`); otherwise they start read-only.
    writable: bool,
}

/// Which driver serves a device.
fn driver_for(i: &DeviceInfo) -> Option<&'static str> {
    match (i.kind, i.vendor, i.device) {
        (sys::DEV_KIND_PCI, 0x1AF4, 0x1042) => Some("virtio-blk"),
        (sys::DEV_KIND_PCI, 0x1AF4, 0x1052) => Some("virtio-input"),
        // By class: AHCI (01.06.01) and NVMe (01.08.02) are standard interfaces.
        _ if i.kind == sys::DEV_KIND_PCI && (i.class, i.subclass, i.progif) == (1, 6, 1) => Some("ahci"),
        _ if i.kind == sys::DEV_KIND_PCI && (i.class, i.subclass, i.progif) == (1, 8, 2) => Some("nvme"),
        // xHCI USB host controllers (0C.03.30): USB keyboards.
        _ if i.kind == sys::DEV_KIND_PCI && (i.class, i.subclass, i.progif) == (0x0C, 3, 0x30) => Some("xhci"),
        (sys::DEV_KIND_PLATFORM, _, _) if i.name() == "ps2" => Some("ps2"),
        _ => None,
    }
}

fn key_proc(i: usize) -> u64 {
    (i as u64) << 8 | 1
}
fn key_chan(i: usize) -> u64 {
    (i as u64) << 8 | 2
}

fn exit_text(code: i64) -> &'static str {
    match code as i32 {
        sys::EXIT_FAULT => " (FAULT)",
        sys::EXIT_KILLED => " (KILLED)",
        _ => "",
    }
}

impl Mgr {
    fn start(&mut self, i: usize) -> bool {
        let Some(d) = self.drv[i].as_mut() else { return false };
        let mut name = [0u8; 24];
        let n = d.prog.len().min(18);
        name[..n].copy_from_slice(&d.prog.as_bytes()[..n]);
        name[n..n + 5].copy_from_slice(b".ddrv");
        let (Ok(log), Ok(dev), Ok((mine, theirs))) = (
            sys::handle_duplicate(libd::startup_handle(sys::TAG_LOG), sys::RIGHTS_SAME),
            sys::handle_duplicate(d.dev, sys::RIGHTS_SAME),
            sys::channel_pair(),
        ) else {
            println!("devmgr: out of handles starting {}", d.prog);
            return false;
        };
        let hs = [
            sys::SpawnHandle { handle: log, rights: sys::RIGHTS_SAME, tag: sys::TAG_LOG, reserved: 0 },
            sys::SpawnHandle { handle: dev, rights: sys::RIGHTS_SAME, tag: sys::TAG_DEVICE, reserved: 0 },
            sys::SpawnHandle { handle: theirs, rights: sys::RIGHTS_SAME, tag: proto::TAG_CONTROL, reserved: 0 },
        ];
        let limits = sys::Limits { memory: 8 << 20, handles: 256, threads: 4 };
        let args: &[u8] = if self.writable { b"rw" } else { b"" };
        match sys::spawn(libd::startup_handle(sys::TAG_PROC_SELF), d.image, &name[..n + 5], args, &hs, &limits) {
            Ok(p) => {
                d.proc = p;
                d.ch = mine;
                d.ready = false;
                d.disks_due = 0;
                d.starts += 1;
                self.port.arm(p, sys::TERMINATED, key_proc(i));
                self.port.arm(mine, sys::READABLE | sys::PEER_CLOSED, key_chan(i));
                true
            }
            Err(e) => {
                println!("devmgr: cannot start {}.ddrv: {}", d.prog, sys::status(e));
                sys::handle_close(mine);
                false
            }
        }
    }

    /// Handle one event (or time out). Returns false on timeout.
    fn pump(&mut self, timeout: u64) -> bool {
        let Some((key, _)) = self.port.wait(timeout) else { return false };
        if key == KEY_MGR {
            self.manager();
            return true;
        }
        let i = (key >> 8) as usize;
        if i >= MAX_DRIVERS {
            return true;
        }
        match key & 0xFF {
            1 => self.died(i),
            2 => self.message(i),
            _ => {}
        }
        true
    }

    fn message(&mut self, i: usize) {
        let mut buf = [0u8; 256];
        loop {
            let Some(d) = self.drv[i].as_mut() else { return };
            if d.ch == 0 {
                return;
            }
            match sys::channel_read(d.ch, &mut buf, 0) {
                Ok(n) => {
                    let Some(h) = Header::get(&buf[..n as usize]) else { continue };
                    match h.op {
                        proto::READY => {
                            d.ready = true;
                            d.capacity = h.a;
                            d.disks_due = h.b.min(64);
                            println!("devmgr: {}.ddrv ready on {} (start {})", d.prog, d.info.name(), d.starts);
                        }
                        proto::KEY => {
                            let from = d.prog;
                            self.key(h.a as u32, from, i);
                        }
                        proto::DISK => {
                            d.disks_due = d.disks_due.saturating_sub(1);
                            let payload = &buf[HEADER..n as usize];
                            self.disk(i, h.a, h.b, payload);
                        }
                        _ => {}
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    let ch = d.ch;
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, key_chan(i));
                    return;
                }
                Err(_) => return, // peer closed: the process watch handles it
            }
        }
    }

    /// Messages from the service manager: a new storage channel (the storage service was
    /// restarted: hand every known disk over again), or the request to stop.
    fn manager(&mut self) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.mgr, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let handle = if nh > 0 { hs[0] } else { 0 };
                    match Header::get(&buf[..n]) {
                        Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"storaged.disks" && handle != 0 => {
                            if self.storage != 0 {
                                sys::handle_close(self.storage);
                            }
                            self.storage = handle;
                            let known = self.known;
                            let mut again = 0;
                            for k in known.iter().flatten() {
                                if self.drv[k.drv].as_ref().is_some_and(|d| d.ready) {
                                    self.disk(k.drv, k.unit, k.sectors, &k.model[..k.model_len]);
                                    again += 1;
                                }
                            }
                            proto::send(self.storage, fs::DISKS_SETTLED, again, 0);
                            println!("devmgr: storage service reconnected: {} disk(s) handed over again", again);
                        }
                        Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"input" && handle != 0 => {
                            // A dead client's slot is reused (its channel reports PEER_CLOSED).
                            let slot = self.input.iter().position(|&c| c == 0 || sys::object_wait(c, sys::PEER_CLOSED, 0).is_ok());
                            match slot {
                                Some(s) => {
                                    if self.input[s] != 0 {
                                        sys::handle_close(self.input[s]);
                                    }
                                    self.input[s] = handle;
                                }
                                None => {
                                    println!("devmgr: more than {} input clients: one refused", MAX_INPUT_CLIENTS);
                                    sys::handle_close(handle);
                                }
                            }
                        }
                        Some(h) if h.op == svc::SHUTDOWN => {
                            if handle != 0 {
                                sys::handle_close(handle);
                            }
                            self.stop = true;
                            return;
                        }
                        _ => {
                            if handle != 0 {
                                sys::handle_close(handle);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.mgr, sys::READABLE | sys::PEER_CLOSED, KEY_MGR);
                    return;
                }
                Err(_) => return, // the manager is gone: keep serving
            }
        }
    }

    /// A driver announced a disk: attach a channel to it and hand the other end to storage.
    fn disk(&mut self, i: usize, unit: u64, sectors: u64, model: &[u8]) {
        let Some(d) = self.drv[i].as_ref() else { return };
        let mut name = [0u8; 64];
        let mut w = Cursor { b: &mut name, n: 0 };
        let _ = core::fmt::write(&mut w, format_args!("{}:{}:{}", d.prog, d.info.name(), unit));
        let len = w.n;
        let mut rec = Disk { drv: i, unit, sectors, model: [0; 40], model_len: model.len().min(40) };
        rec.model[..rec.model_len].copy_from_slice(&model[..rec.model_len]);
        let slot = self.known.iter().position(|k| k.is_some_and(|k| k.drv == i && k.unit == unit));
        let first = slot.is_none();
        if let Some(s) = slot.or_else(|| self.known.iter().position(|k| k.is_none())) {
            self.known[s] = Some(rec);
        }
        if first {
            println!(
                "devmgr: {}.ddrv disk {}: {} sectors ({} MiB), {}",
                d.prog,
                unit,
                sectors,
                sectors / 2048,
                core::str::from_utf8(model).unwrap_or("?")
            );
        }
        if self.storage == 0 {
            return;
        }
        let Ok((mine, theirs)) = sys::channel_pair() else {
            println!("devmgr: out of handles attaching a disk");
            return;
        };
        let mut m = [0u8; HEADER];
        Header { txid: 0, op: proto::BLK_ATTACH, status: 0, a: unit, b: 0 }.put(&mut m);
        if sys::channel_write_h(d.ch, &m, &[sys::MsgHandle { handle: theirs, rights: sys::RIGHTS_SAME }]) < 0 {
            sys::handle_close(mine);
            return;
        }
        let mut msg = [0u8; HEADER + 64];
        Header { txid: 0, op: fs::DISK_ADD, status: 0, a: (i as u64) << 8 | unit, b: sectors }.put(&mut msg);
        msg[HEADER..HEADER + len].copy_from_slice(&name[..len]);
        if sys::channel_write_h(self.storage, &msg[..HEADER + len], &[sys::MsgHandle { handle: mine, rights: sys::RIGHTS_SAME }]) == 0 {
            self.disks += 1;
        }
    }

    /// A key from an input driver: to every client of the input endpoint. Lines are also
    /// assembled here (silently) for the driver tests.
    fn key(&mut self, k: u32, from: &'static str, dev: usize) {
        let mut msg = [0u8; HEADER + 24];
        Header { txid: 0, op: proto::INPUT_KEY, status: 0, a: u64::from(k), b: dev as u64 }.put(&mut msg);
        let n = from.len().min(24);
        msg[HEADER..HEADER + n].copy_from_slice(&from.as_bytes()[..n]);
        for ch in self.input.iter().copied().filter(|&c| c != 0) {
            sys::channel_write(ch, &msg[..HEADER + n]); // a full or closed client loses the key, never us
        }
        let Ok(c) = u8::try_from(k) else { return }; // a named key: not part of a line
        match c {
            b'\n' => {
                let l = &self.line[..self.line_len];
                self.last_line[..l.len()].copy_from_slice(l);
                self.last_len = l.len();
                self.last_from = from;
                self.lines += 1;
                self.line_len = 0;
            }
            0x08 if self.line_len > 0 => self.line_len -= 1,
            b' '..=b'~' if self.line_len < self.line.len() => {
                self.line[self.line_len] = c;
                self.line_len += 1;
            }
            _ => {}
        }
    }

    fn died(&mut self, i: usize) {
        let Some(d) = self.drv[i].as_mut() else { return };
        if d.proc == 0 {
            return;
        }
        let code = sys::process_exit_code(d.proc);
        sys::handle_close(d.proc);
        sys::handle_close(d.ch);
        d.proc = 0;
        d.ch = 0;
        d.ready = false;
        d.disks_due = 0;
        println!("devmgr: {}.ddrv exited with code {}{}", d.prog, code, exit_text(code));
        // Quiesce: no decode, no bus mastering, until the next instance has reset the device.
        if d.info.kind == sys::DEV_KIND_PCI {
            let _ = sys::config_write(d.dev, 0x04, 2, 0);
        }
        if d.starts > MAX_RESTARTS {
            d.gave_up = true;
            println!("devmgr: {}.ddrv keeps failing, given up after {} restarts", d.prog, MAX_RESTARTS);
            return;
        }
        println!("devmgr: restarting {}.ddrv (restart {} of {})", d.prog, d.starts, MAX_RESTARTS);
        self.start(i);
    }

    fn find(&self, prog: &str) -> Option<usize> {
        (0..MAX_DRIVERS).find(|&i| self.drv[i].as_ref().is_some_and(|d| d.prog == prog))
    }

    fn starts(&self, i: usize) -> u32 {
        self.drv[i].as_ref().map_or(0, |d| d.starts)
    }

    /// Wait until driver `i` is ready, in an instance started after `after` starts.
    fn wait_ready_after(&mut self, i: usize, after: u32, timeout: u64) -> bool {
        let deadline = sys::clock_ns() + timeout;
        while !self.drv[i].as_ref().is_some_and(|d| d.ready && d.starts > after) {
            let now = sys::clock_ns();
            if now >= deadline {
                return false;
            }
            self.pump(deadline - now);
        }
        true
    }

    fn wait_ready(&mut self, i: usize, timeout: u64) -> bool {
        let deadline = sys::clock_ns() + timeout;
        while !self.drv[i].as_ref().is_some_and(|d| d.ready) {
            let now = sys::clock_ns();
            if now >= deadline {
                return false;
            }
            self.pump(deadline - now);
        }
        true
    }

    fn call(&self, i: usize, op: u32, a: u64, b: u64, payload: &[u8], out: &mut [u8]) -> Result<(Header, usize), i64> {
        let d = self.drv[i].as_ref().ok_or(sys::ERR_BAD_STATE)?;
        let mut req = [0u8; HEADER + MAX_SECTORS as usize * SECTOR];
        Header { txid: 0, op, status: 0, a, b }.put(&mut req);
        req[HEADER..HEADER + payload.len()].copy_from_slice(payload);
        let n = sys::channel_call(d.ch, &req[..HEADER + payload.len()], out, 5 * SEC)? as usize;
        let h = Header::get(&out[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
        Ok((h, n))
    }
}

fn devmgr_main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "devmgr") } {
        return -1;
    }
    let test = libd::args().starts_with(b"test");
    let writable = test || libd::args() == b"rw";
    let Ok(port) = Port::new(64) else {
        println!("devmgr: cannot create a port");
        return 1;
    };
    let mut m = Mgr {
        drv: [const { None }; MAX_DRIVERS],
        port,
        line: [0; 128],
        line_len: 0,
        last_line: [0; 128],
        last_len: 0,
        last_from: "",
        lines: 0,
        // The storage endpoint from the service manager, or (tests) the tagged channel.
        storage: match svc::endpoint(b"storaged.disks") {
            0 => libd::startup_handle(fs::TAG_STORAGE),
            h => h,
        },
        disks: 0,
        known: [None; MAX_DISKS],
        mgr: libd::startup_handle(proto::TAG_CONTROL),
        stop: false,
        input: [0; MAX_INPUT_CLIENTS],
        writable,
    };
    if !writable {
        println!("devmgr: disks are read-only (block drivers refuse writes)");
    }
    if m.mgr != 0 {
        m.port.arm(m.mgr, sys::READABLE | sys::PEER_CLOSED, KEY_MGR);
    }
    // Bind drivers to devices.
    let mut ndev = 0;
    let mut n = 0;
    for (h, tag) in libd::startup_handles() {
        if tag != sys::TAG_DEVICE {
            continue;
        }
        ndev += 1;
        let Ok(info) = sys::device_info(h) else { continue };
        let Some(prog) = driver_for(&info) else { continue };
        let mut file = [0u8; 24];
        file[..prog.len()].copy_from_slice(prog.as_bytes());
        file[prog.len()..prog.len() + 5].copy_from_slice(b".ddrv");
        let Some(image) = libd::find_program(&file[..prog.len() + 5]) else {
            println!("devmgr: no driver program {}.ddrv", prog);
            continue;
        };
        if n < MAX_DRIVERS {
            m.drv[n] = Some(Driver { prog, image, dev: h, info, proc: 0, ch: 0, ready: false, starts: 0, gave_up: false, capacity: 0, disks_due: 0 });
            n += 1;
        }
    }
    println!("devmgr: {} devices, {} with a driver", ndev, n);
    if test && !abi_checks(&m) {
        return 1;
    }
    for i in 0..n {
        m.start(i);
    }
    if test {
        let ok = tests(&mut m);
        for d in m.drv.iter().flatten() {
            if d.proc != 0 {
                sys::process_kill(d.proc);
            }
        }
        println!("devmgr: test {}", if ok { "PASSED" } else { "FAILED" });
        return if ok { 0 } else { 1 };
    }
    // Once every driver started at boot is ready with all the disks its READY announced (or has
    // given up), tell the storage service, so it can report the volumes present at boot.
    let deadline = sys::clock_ns() + 10 * SEC;
    while sys::clock_ns() < deadline && !m.drv.iter().flatten().all(|d| (d.ready && d.disks_due == 0) || d.gave_up) {
        m.pump(deadline.saturating_sub(sys::clock_ns()).max(1));
    }
    while m.pump(0) {}
    if m.storage != 0 {
        proto::send(m.storage, fs::DISKS_SETTLED, u64::from(m.disks), 0);
    }
    println!("devmgr: running (drivers are restarted when they fail); keyboard input on the devmgr.input endpoint");
    while !m.stop {
        m.pump(sys::WAIT_FOREVER);
    }
    let mut n = 0;
    for d in m.drv.iter_mut().flatten() {
        if d.proc != 0 {
            sys::process_kill(d.proc);
            let _ = sys::object_wait(d.proc, sys::TERMINATED, 2 * SEC);
            n += 1;
        }
    }
    println!("devmgr: shutdown: {} driver(s) stopped", n);
    0
}

// ---- tests (`devmgr test`) -----------------------------------------------------------------

macro_rules! check {
    ($c:expr, $($t:tt)*) => {
        if !$c {
            println!("devmgr: test FAIL: {}", format_args!($($t)*));
            return false;
        }
    };
}

/// The device ABI rules, checked on the real devices before any driver runs.
fn abi_checks(m: &Mgr) -> bool {
    let Some(b) = m.drv.iter().flatten().find(|d| d.prog == "virtio-blk") else {
        println!("devmgr: test FAIL: no virtio-blk device");
        return false;
    };
    let dev = b.dev;
    // Configuration space: BARs, the header and the kernel's capabilities are read-only.
    check!(sys::config_write(dev, 0x10, 4, 0xFFFF_FFFF) == Err(sys::ERR_ACCESS_DENIED), "BAR write not refused");
    check!(sys::config_write(dev, 0x3C, 1, 5) == Err(sys::ERR_ACCESS_DENIED), "header write not refused");
    check!(sys::config_write(dev, 0x100, 4, 0) == Err(sys::ERR_ACCESS_DENIED), "extended-space write not refused");
    let mut msix = 0;
    let mut ptr = sys::config_read(dev, 0x34, 1).unwrap_or(0) & 0xFC;
    for _ in 0..48 {
        if ptr < 0x40 {
            break;
        }
        if sys::config_read(dev, ptr, 1) == Ok(0x11) {
            msix = ptr;
        }
        ptr = sys::config_read(dev, ptr + 1, 1).unwrap_or(0) & 0xFC;
    }
    check!(msix != 0, "virtio-blk has no MSI-X capability");
    check!(sys::config_write(dev, msix + 2, 2, 0xC000) == Err(sys::ERR_ACCESS_DENIED), "MSI-X control write not refused");
    check!(sys::config_read(dev, 0x1000, 4) == Err(sys::ERR_INVALID_ARGS), "config read past the end accepted");
    check!(sys::config_read(dev, 0x02, 4) == Err(sys::ERR_INVALID_ARGS), "unaligned config read accepted");
    // The MSI-X table is hidden: its page reads as zeros (the real one has every entry masked).
    let table = sys::config_read(dev, msix + 4, 4).unwrap_or(0);
    let (bir, off) = ((table & 7) as usize, table & !7);
    let vmo = sys::device_map_bar(dev, bir as u64);
    check!(vmo.is_ok(), "cannot map the MSI-X BAR: {:?}", vmo.err().map(sys::status));
    let map = Mapping::of(vmo.unwrap_or(0), b.info.bar_size[bir]);
    check!(map.is_ok(), "cannot map the MSI-X BAR");
    let map = map.unwrap_or(Mapping { vmo: 0, addr: 0, len: 0 });
    check!(map.r32(off + 12) == 0, "MSI-X table visible to a driver (vector control {:#x})", map.r32(off + 12));
    map.w32(off + 12, 0); // a write lands in the private zero page, not in the table
    // I/O and DMA rights.
    check!(sys::io_read(dev, bir as u64, 0, 4) == Err(sys::ERR_WRONG_TYPE), "port I/O on a memory BAR accepted");
    check!(sys::device_map_bar(dev, 6).is_err(), "BAR 6 accepted");
    let ro = sys::vmo_create(4096).and_then(|v| sys::handle_replace(v, sys::RIGHT_READ));
    let mut addr = [0u64; 1];
    check!(
        ro.is_ok_and(|v| sys::dma_map(dev, v, 0, 4096, sys::DMA_DEVICE_WRITE, &mut addr) == Err(sys::ERR_ACCESS_DENIED)),
        "device write access to a read-only VMO granted"
    );
    check!(
        sys::dma_map(dev, map.vmo, 0, 4096, sys::DMA_DEVICE_READ, &mut addr) == Err(sys::ERR_NOT_SUPPORTED),
        "DMA to device memory accepted"
    );
    check!(sys::device_interrupt(dev, 64).is_err(), "interrupt index out of range accepted");
    let irq = sys::device_interrupt(dev, 1);
    check!(irq.is_ok(), "no interrupt object");
    check!(sys::device_interrupt(dev, 1) == Err(sys::ERR_BAD_STATE), "interrupt source bound twice");
    sys::handle_close(irq.unwrap_or(0)); // unbinds it again
    let irq = sys::device_interrupt(dev, 1);
    check!(irq.is_ok(), "interrupt source not released by close");
    sys::handle_close(irq.unwrap_or(0));
    println!("devmgr: test: device ABI: config writes filtered, MSI-X table hidden, I/O, DMA and interrupt rules enforced");
    true
}

fn pattern(lba: u64, j: usize) -> u8 {
    (lba.wrapping_mul(13) as usize + j) as u8
}

fn blk_read_check(m: &Mgr, i: usize, lba: u64, count: u64) -> bool {
    let mut out = [0u8; HEADER + MAX_SECTORS as usize * SECTOR];
    let r = m.call(i, proto::BLK_READ, lba, count, &[], &mut out);
    check!(r.as_ref().is_ok_and(|(h, n)| h.status == 0 && *n == HEADER + count as usize * SECTOR), "block read failed: {:?}", r.map(|(h, _)| h.status));
    for s in 0..count {
        for j in 0..SECTOR {
            let got = out[HEADER + s as usize * SECTOR + j];
            check!(got == pattern(lba + s, j), "sector {} byte {}: {:#x}, expected {:#x}", lba + s, j, got, pattern(lba + s, j));
        }
    }
    true
}

fn tests(m: &mut Mgr) -> bool {
    let Some(b) = m.find("virtio-blk") else { return false };
    let Some(inp) = m.find("virtio-input") else {
        println!("devmgr: test FAIL: no virtio-input device");
        return false;
    };
    for i in 0..MAX_DRIVERS {
        if m.drv[i].is_some() {
            check!(m.wait_ready(i, 10 * SEC), "{}.ddrv did not get ready", m.drv[i].as_ref().map_or("?", |d| d.prog));
        }
    }
    // Block I/O: a known pattern (build.ps1 writes it), then write + read back.
    let cap = m.drv[b].as_ref().map_or(0, |d| d.capacity);
    check!(cap >= 256, "disk too small ({} sectors)", cap);
    let t0 = sys::clock_ns();
    if !blk_read_check(m, b, 0, MAX_SECTORS) {
        return false;
    }
    let us = (sys::clock_ns() - t0) / 1000;
    let mut data = [0u8; 8 * SECTOR];
    for (j, x) in data.iter_mut().enumerate() {
        *x = pattern(200 + (j / SECTOR) as u64, j % SECTOR);
    }
    let mut out = [0u8; HEADER + MAX_SECTORS as usize * SECTOR];
    let r = m.call(b, proto::BLK_WRITE, 200, 8, &data, &mut out);
    check!(r.is_ok_and(|(h, _)| h.status == 0), "block write failed");
    if !blk_read_check(m, b, 200, 8) {
        return false;
    }
    let r = m.call(b, proto::BLK_READ, cap, 1, &[], &mut out);
    check!(r.is_ok_and(|(h, _)| h.status != 0), "read past the end of the disk accepted");
    let stats = m.call(b, proto::STATS, 0, 0, &[], &mut out).map(|(h, _)| h.a).unwrap_or(0);
    check!(stats > 0, "no virtio-blk interrupt arrived");
    println!(
        "devmgr: test: virtio-blk: {} sectors, read 32 KiB in {} us (pattern OK), write + read back OK",
        cap, us
    );
    println!("devmgr: test: interrupt delivery: virtio-blk {} MSI-X interrupts", stats);

    // Crash + restart: the driver faults, a new instance serves I/O again.
    let before_start = m.starts(b);
    let r = m.call(b, proto::TEST_CRASH, 0, 0, &[], &mut out);
    check!(r.is_err(), "the crashing driver answered");
    check!(m.wait_ready_after(b, before_start, 10 * SEC), "virtio-blk.ddrv was not restarted");
    if !blk_read_check(m, b, 0, 8) {
        return false;
    }
    println!("devmgr: test: virtio-blk.ddrv crashed and was restarted; I/O works again");

    // DMA outside the driver's pins: the device is told to write to kernel memory.
    let dev = m.drv[b].as_ref().map_or(0, |d| d.dev);
    let before = sys::device_info(dev).map_or(0, |i| i.dma_faults);
    let iommu = sys::device_info(dev).is_ok_and(|i| i.flags & sys::DEV_FLAG_IOMMU != 0);
    check!(iommu, "no IOMMU: cannot test DMA confinement");
    let before_start = m.starts(b);
    let r = m.call(b, proto::TEST_DMA_ESCAPE, 0, 0, &[], &mut out);
    check!(r.is_ok(), "no answer to the DMA test");
    let after = sys::device_info(dev).map_or(0, |i| i.dma_faults);
    check!(after > before, "the IOMMU recorded no fault ({} -> {})", before, after);
    println!(
        "devmgr: test: DMA outside the driver's pins blocked by the IOMMU ({} fault(s)); device status {:#x}, request status {}",
        after - before,
        r.map_or(0, |(h, _)| h.a),
        r.map_or(0, |(h, _)| h.status)
    );
    check!(m.wait_ready_after(b, before_start, 10 * SEC), "virtio-blk.ddrv was not restarted after the DMA test");
    if !blk_read_check(m, b, 200, 8) {
        return false;
    }
    println!("devmgr: test: virtio-blk recovered after the DMA test (device reset by the new instance)");

    // Keyboard: the harness types a line once this appears.
    println!("devmgr: test: waiting for keys");
    let deadline = sys::clock_ns() + 30 * SEC;
    while m.lines == 0 && sys::clock_ns() < deadline {
        m.pump(SEC);
    }
    check!(m.lines > 0, "no line typed");
    check!(m.last_from == "virtio-input", "the line came from {}", m.last_from);
    println!(
        "devmgr: test: keyboard: '{}' typed on {}",
        core::str::from_utf8(&m.last_line[..m.last_len]).unwrap_or("?"),
        m.last_from
    );
    let irqs = m.call(inp, proto::STATS, 0, 0, &[], &mut out).map(|(h, _)| h.a).unwrap_or(0);
    check!(irqs > 0, "no virtio-input interrupt");
    println!("devmgr: test: interrupt delivery: virtio-input {} MSI-X interrupts", irqs);
    true
}
