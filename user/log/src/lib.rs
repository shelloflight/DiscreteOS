//! The log service (`log.dx`, docs/services.md).
//!
//! - Reads the kernel log with the KLOG resource (its manifest grant `kernel-log`): kernel lines and
//!   every program's output, each record attributed by the kernel to the process that wrote it.
//!   Kernel addresses are filtered by the kernel before they reach this process.
//! - Keeps the records it reads in one ring with its own sequence numbers. A program's records
//!   below its service's level (`log-level` in the manifest, sent by the service manager as
//!   `svc::LOG_LEVEL`) are not kept; processes without a level (drivers, programs run by hand)
//!   keep `info` and above.
//! - Serves `log::READ` on each `log.read` channel the manager hands it (`svc::CONNECT "read"`):
//!   records from a sequence number, with how many were lost before them; a reader may wait for
//!   the next record.
//!
//! The kernel ring is read every `POLL` (and at once after a full read): the kernel does not
//! signal new records (it logs from interrupt handlers, where waking a waiter is not allowed).

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use libd::log::{self as lp, Record};
use libd::proto::{self, HEADER, Header};
use libd::svc;
use libd::sys::{self, Handle, KlogEntry};
use libd::{Port, Startup, println};

libd::entry!(_start, main);

const RING: usize = 2048;
const POLL: u64 = 50_000_000;
const MAX_READERS: usize = 64;
const KEY_CTL: u64 = 1;
const KEY_READER: u64 = 0x100;

struct Waiter {
    reader: usize,
    txid: u32,
    from: u64,
    max: usize,
}

struct Log {
    klog: Handle,
    ctl: Handle,
    port: Port,
    /// The next kernel sequence number to read.
    kseq: u64,
    kernel_lost: u64,
    ring: Vec<Record>,
    /// Sequence number of the next record kept here.
    next: u64,
    levels: Vec<(String, u8)>,
    readers: Vec<Option<Handle>>,
    waiters: Vec<Waiter>,
    dropped_by_level: u64,
    stop: bool,
}

impl Log {
    fn level_of(&self, source: &[u8]) -> u8 {
        self.levels.iter().find(|(n, _)| n.as_bytes() == source).map_or(sys::LOG_INFO as u8, |(_, l)| *l)
    }

    fn oldest(&self) -> u64 {
        self.next.saturating_sub(RING as u64)
    }

    fn keep(&mut self, e: &KlogEntry) {
        if e.origin == sys::KLOG_ORIGIN_PROGRAM && e.level > self.level_of(e.source()) {
            self.dropped_by_level += 1;
            return;
        }
        let mut r = Record {
            seq: self.next,
            time_us: e.time_us,
            level: e.level,
            origin: e.origin,
            flags: e.flags,
            len: e.len.min(lp::TEXT as u8),
            koid: e.koid,
            ..Record::default()
        };
        r.source.copy_from_slice(&e.source);
        r.text[..usize::from(r.len)].copy_from_slice(e.text());
        let slot = (self.next % RING as u64) as usize;
        if self.ring.len() < RING {
            self.ring.push(r);
        } else {
            self.ring[slot] = r;
        }
        self.next += 1;
    }

    /// Read everything new from the kernel. True if anything was kept.
    fn pull(&mut self) -> bool {
        let before = self.next;
        let mut buf = [KlogEntry::default(); 64];
        while let Ok(n) = sys::klog_read(self.klog, self.kseq, &mut buf) {
            if n == 0 {
                break;
            }
            if buf[0].seq > self.kseq {
                self.kernel_lost += buf[0].seq - self.kseq;
            }
            for e in &buf[..n] {
                self.keep(e);
            }
            self.kseq = buf[n - 1].seq + 1;
            if n < buf.len() {
                break;
            }
        }
        self.next != before
    }

    /// Records `from..` (at most `max`): (reply bytes, next, lost).
    fn batch(&self, from: u64, max: usize, out: &mut Vec<u8>) -> (u64, u64) {
        let start = from.max(self.oldest());
        let lost = start - from.min(start);
        let end = self.next.min(start + max as u64);
        for s in start..end {
            let r = &self.ring[(s % RING as u64) as usize];
            let at = out.len();
            out.resize(at + lp::SIZE, 0);
            r.put(&mut out[at..]);
        }
        (end, lost)
    }

    fn reply(&self, ch: Handle, txid: u32, from: u64, max: usize) {
        let mut out = alloc::vec![0u8; HEADER];
        let (next, lost) = self.batch(from, max, &mut out);
        Header { txid, op: lp::READ, status: lost.min(i32::MAX as u64) as i32, a: next, b: 0 }.put(&mut out[..HEADER]);
        sys::channel_write(ch, &out);
    }

    fn serve(&mut self, i: usize) {
        let mut buf = [0u8; HEADER + 16];
        loop {
            let Some(Some(ch)) = self.readers.get(i).copied() else { return };
            match sys::channel_read(ch, &mut buf, 0) {
                Ok(n) => {
                    let Some(h) = Header::get(&buf[..n as usize]) else { continue };
                    if h.op != lp::READ {
                        continue;
                    }
                    let max = ((h.b & 0xFFFF_FFFF) as usize).clamp(1, lp::MAX_PER_READ);
                    if h.b & lp::WAIT != 0 && h.a >= self.next {
                        self.waiters.push(Waiter { reader: i, txid: h.txid, from: h.a, max });
                    } else {
                        self.reply(ch, h.txid, h.a, max);
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_READER + i as u64);
                    return;
                }
                Err(_) => {
                    // The reader is gone.
                    sys::handle_close(ch);
                    self.readers[i] = None;
                    self.waiters.retain(|w| w.reader != i);
                    return;
                }
            }
        }
    }

    fn wake_waiters(&mut self) {
        let ready: Vec<Waiter> = {
            let next = self.next;
            let (r, keep): (Vec<Waiter>, Vec<Waiter>) = core::mem::take(&mut self.waiters).into_iter().partition(|w| w.from < next);
            self.waiters = keep;
            r
        };
        for w in ready {
            if let Some(Some(ch)) = self.readers.get(w.reader).copied() {
                self.reply(ch, w.txid, w.from, w.max);
            }
        }
    }

    fn control(&mut self) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let handle = if nh > 0 { hs[0] } else { 0 };
                    let payload = &buf[HEADER..n];
                    match Header::get(&buf[..n]) {
                        Some(h) if h.op == svc::CONNECT && payload == b"read" && handle != 0 => {
                            let slot = self.readers.iter().position(|r| r.is_none()).or_else(|| (self.readers.len() < MAX_READERS).then(|| {
                                self.readers.push(None);
                                self.readers.len() - 1
                            }));
                            match slot {
                                Some(s) => {
                                    self.readers[s] = Some(handle);
                                    self.port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_READER + s as u64);
                                }
                                None => {
                                    println!("log: more than {} readers: one refused", MAX_READERS);
                                    sys::handle_close(handle);
                                }
                            }
                        }
                        Some(h) if h.op == svc::LOG_LEVEL && h.a <= u64::from(sys::LOG_DEBUG) => {
                            let name = String::from_utf8_lossy(payload).into_owned();
                            self.levels.retain(|(n, _)| *n != name);
                            self.levels.push((name, h.a as u8));
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
                    self.port.arm(self.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    return;
                }
                Err(_) => return, // the manager is gone: keep serving
            }
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "log") } {
        return 1;
    }
    let klog = libd::startup_handle(sys::TAG_KLOG);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    if klog == 0 {
        println!("log: no kernel log reader granted");
        return 1;
    }
    let Ok(port) = Port::new(128) else {
        println!("log: cannot create a port");
        return 1;
    };
    let mut l = Log {
        klog,
        ctl,
        port,
        kseq: 0,
        kernel_lost: 0,
        ring: Vec::with_capacity(RING),
        next: 0,
        levels: Vec::new(),
        readers: Vec::new(),
        waiters: Vec::new(),
        dropped_by_level: 0,
        stop: false,
    };
    if ctl != 0 {
        l.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    l.control(); // levels the manager sent before we started
    l.pull();
    println!("log: running: {} records kept so far ({} lost before this service started), up to {} kept", l.next, l.kernel_lost, RING);
    while !l.stop {
        if let Some((key, _)) = l.port.wait(POLL) {
            match key {
                KEY_CTL => l.control(),
                k if k >= KEY_READER => l.serve((k - KEY_READER) as usize),
                _ => {}
            }
        }
        if l.pull() {
            l.wake_waiters();
        }
    }
    println!("log: shutdown: {} records kept, {} below their service's level, {} lost in the kernel ring", l.next, l.dropped_by_level, l.kernel_lost);
    0
}
