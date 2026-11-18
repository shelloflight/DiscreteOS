//! The storage service (`storaged.dx`): block layer, partitions, filesystems and the
//! file service. Reference: docs/storage.md.
//!
//! - Disks arrive from the device manager (TAG_DISKS: DISK_ADD, each carrying a channel to the
//!   driver serving that disk). A disk whose driver restarts comes back under the same name; its
//!   channel is replaced and interrupted requests are retried, so filesystems never notice.
//! - Each disk's GPT is read (backup table if the primary is damaged); FAT32 partitions (EFI
//!   System, basic data) and DFS partitions are mounted as volumes, announced to init
//!   (TAG_CONTROL: VOLUME, carrying a channel to the volume's root with every right).
//! - Every open file or directory is a channel served here. Its rights are fixed when it is
//!   opened and only ever narrowed; paths are relative to it and cannot climb out of it. That is
//!   all a per-app namespace needs: a process can reach exactly the directories it was given.
//!
//! Arguments: none (read-only: every volume is mounted read-only and announced with read rights
//! only; docs/hardware.md), `test` (writable, with the TEST hooks: corruption, power cut, remount,
//! fsck), or `rocheck` (read-only, and each disk's driver is asked to write a sector it just read,
//! which it must refuse: the `readonly` test).

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use libd::fs::{self as fp, R_ADMIN, R_ALL, R_READ, R_WRITE};
use libd::proto::{self, HEADER, Header, MAX_SECTORS, SECTOR};
use libd::sys::{self, Handle, MsgHandle};
use libd::{Port, Startup, println};
use dosfs::dev::{BlockDev, CutDev, Part, SharedCut};
use dosfs::dfs::Dfs;
use dosfs::fat::Fat;
use dosfs::{Error, FileSystem, Ino, Kind, gpt};

libd::entry!(_start, main);

const KEY_DISKS: u64 = 1;
const KEY_CTL: u64 = 2;
const KEY_CONN: u64 = 0x100;
const MAX_CONNS: usize = 1024;
const SEC: u64 = 1_000_000_000;
/// Idle time after which dirty DFS volumes are committed.
const COMMIT_IDLE: u64 = 2 * SEC;

fn status(e: Error) -> i64 {
    match e {
        Error::Io => fp::ERR_IO,
        Error::Corrupt => fp::ERR_CORRUPT,
        Error::NotFound => fp::ERR_NOT_FOUND,
        Error::Exists => fp::ERR_EXISTS,
        Error::NotDir => fp::ERR_NOT_DIR,
        Error::IsDir => fp::ERR_IS_DIR,
        Error::NotEmpty => fp::ERR_NOT_EMPTY,
        Error::NoSpace => sys::ERR_NO_SPACE,
        Error::BadName => fp::ERR_BAD_NAME,
        Error::ReadOnly => fp::ERR_READ_ONLY,
        Error::TooBig => sys::ERR_OUT_OF_RANGE,
        Error::Unsupported => sys::ERR_NOT_SUPPORTED,
    }
}

// ---- the block layer ------------------------------------------------------------------------

/// A message from the device manager seen while waiting for a disk to come back.
struct Pending {
    msg: Vec<u8>,
    handle: Handle,
}

/// A disk served by a driver process, reached over the channel the device manager attached.
struct Remote {
    name: String,
    ch: Handle,
    sectors: u64,
    disks: Rc<Cell<Handle>>,
    pending: Rc<RefCell<Vec<Pending>>>,
    req: Vec<u8>,
    rep: Vec<u8>,
}

impl Remote {
    /// The driver went away: wait (up to 10 s) for the device manager to bring the disk back
    /// under the same name; anything else it sends meanwhile is kept for the main loop.
    fn reconnect(&mut self) -> bool {
        println!("storaged: {}: driver gone, waiting for it to come back", self.name);
        let deadline = sys::clock_ns() + 10 * SEC;
        let mut buf = vec![0u8; 512];
        while sys::clock_ns() < deadline {
            let mut hs = [0 as Handle; 1];
            let left = deadline.saturating_sub(sys::clock_ns()).max(1);
            match sys::channel_read_h(self.disks.get(), &mut buf, &mut hs, left) {
                Ok((n, nh)) => {
                    let h = Header::get(&buf[..n]);
                    let handle = if nh > 0 { hs[0] } else { 0 };
                    if let Some(h) = h
                        && h.op == fp::DISK_ADD
                        && &buf[HEADER..n] == self.name.as_bytes()
                        && handle != 0
                    {
                        sys::handle_close(self.ch);
                        self.ch = handle;
                        println!("storaged: {}: driver back, retrying", self.name);
                        return true;
                    }
                    self.pending.borrow_mut().push(Pending { msg: buf[..n].to_vec(), handle });
                }
                Err(sys::ERR_TIMED_OUT) => break,
                Err(_) => return false,
            }
        }
        false
    }

    fn call(&mut self, op: u32, lba: u64, count: u64, data: Option<&[u8]>, out: Option<&mut [u8]>) -> dosfs::Result<()> {
        let plen = data.map_or(0, |d| d.len());
        Header { txid: 0, op, status: 0, a: lba, b: count }.put(&mut self.req);
        if let Some(d) = data {
            self.req[HEADER..HEADER + plen].copy_from_slice(d);
        }
        for attempt in 0..2 {
            match sys::channel_call(self.ch, &self.req[..HEADER + plen], &mut self.rep, 10 * SEC) {
                Ok(n) => {
                    let h = Header::get(&self.rep[..n as usize]).ok_or(Error::Io)?;
                    if h.status != 0 {
                        return Err(Error::Io);
                    }
                    if let Some(o) = out {
                        if n as usize != HEADER + o.len() {
                            return Err(Error::Io);
                        }
                        o.copy_from_slice(&self.rep[HEADER..n as usize]);
                    }
                    return Ok(());
                }
                Err(sys::ERR_PEER_CLOSED | sys::ERR_BAD_HANDLE | sys::ERR_TIMED_OUT) if attempt == 0 => {
                    if !self.reconnect() {
                        return Err(Error::Io);
                    }
                }
                Err(_) => return Err(Error::Io),
            }
        }
        Err(Error::Io)
    }
}

impl BlockDev for Remote {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> dosfs::Result<()> {
        if !buf.len().is_multiple_of(SECTOR) || lba.checked_add((buf.len() / SECTOR) as u64).is_none_or(|e| e > self.sectors) {
            return Err(Error::Io);
        }
        for (i, c) in buf.chunks_mut(MAX_SECTORS as usize * SECTOR).enumerate() {
            let at = lba + (i as u64) * MAX_SECTORS;
            let n = (c.len() / SECTOR) as u64;
            self.call(proto::BLK_READ, at, n, None, Some(c))?;
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> dosfs::Result<()> {
        if !buf.len().is_multiple_of(SECTOR) || lba.checked_add((buf.len() / SECTOR) as u64).is_none_or(|e| e > self.sectors) {
            return Err(Error::Io);
        }
        for (i, c) in buf.chunks(MAX_SECTORS as usize * SECTOR).enumerate() {
            let at = lba + (i as u64) * MAX_SECTORS;
            self.call(proto::BLK_WRITE, at, (c.len() / SECTOR) as u64, Some(c), None)?;
        }
        Ok(())
    }
    fn flush(&mut self) -> dosfs::Result<()> {
        self.call(proto::BLK_FLUSH, 0, 0, None, None)
    }
}

/// A partition mounted read-only: writes and flushes fail before they reach the block layer.
struct RoDev(Part);

impl BlockDev for RoDev {
    fn sectors(&self) -> u64 {
        self.0.sectors()
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> dosfs::Result<()> {
        self.0.read(lba, buf)
    }
    fn write(&mut self, _lba: u64, _buf: &[u8]) -> dosfs::Result<()> {
        Err(Error::ReadOnly)
    }
    fn flush(&mut self) -> dosfs::Result<()> {
        Err(Error::ReadOnly)
    }
}

impl Remote {
    /// Read-only check: read `lba`, ask the driver to write the same bytes back (so even a driver
    /// that wrongly accepts changes nothing), and return the driver's status.
    fn probe_write(&mut self, lba: u64) -> i64 {
        let mut sector = vec![0u8; SECTOR];
        if self.call(proto::BLK_READ, lba, 1, None, Some(&mut sector)).is_err() {
            return fp::ERR_IO;
        }
        Header { txid: 0, op: proto::BLK_WRITE, status: 0, a: lba, b: 1 }.put(&mut self.req);
        self.req[HEADER..HEADER + SECTOR].copy_from_slice(&sector);
        match sys::channel_call(self.ch, &self.req[..HEADER + SECTOR], &mut self.rep, 10 * SEC) {
            Ok(n) => Header::get(&self.rep[..n as usize]).map_or(fp::ERR_IO, |h| h.status as i64),
            Err(e) => e,
        }
    }
}

// ---- volumes --------------------------------------------------------------------------------

// A handful of volumes per boot, each held for its lifetime: boxing the larger variant buys nothing.
#[allow(clippy::large_enum_variant)]
enum VolFs {
    Fat(Fat<Box<dyn BlockDev>>),
    Dfs(Dfs),
}

impl VolFs {
    fn fs(&mut self) -> &mut dyn FileSystem {
        match self {
            VolFs::Fat(f) => f,
            VolFs::Dfs(d) => d,
        }
    }
}

struct Volume {
    name: String,
    kind: u64,
    fs: Option<VolFs>,
    /// The power-cut simulator under the filesystem (test mode).
    cut: Option<Rc<RefCell<CutDev<Part>>>>,
    dirty: bool,
}

struct Disk {
    remote: Rc<RefCell<Remote>>,
}

struct Conn {
    ch: Handle,
    vol: usize,
    ino: Ino,
    kind: Kind,
    rights: u64,
}

struct Svc {
    port: Port,
    disks_ch: Rc<Cell<Handle>>,
    ctl: Handle,
    pending: Rc<RefCell<Vec<Pending>>>,
    disks: Vec<Disk>,
    vols: Vec<Volume>,
    conns: Vec<Option<Conn>>,
    test: bool,
    /// Volumes may be written (only with `test`): otherwise mounted read-only (RoDev, read rights).
    writable: bool,
    /// `rocheck`: ask each driver to write, expecting a refusal.
    rocheck: bool,
    announced: bool,
    buf: Vec<u8>,
    out: Vec<u8>,
}

fn kind_code(k: Kind) -> u64 {
    match k {
        Kind::File => fp::KIND_FILE,
        Kind::Dir => fp::KIND_DIR,
    }
}

fn kind_name(k: u64) -> &'static str {
    if k == fp::KIND_DFS { "DFS" } else { "FAT32" }
}

impl Svc {
    fn add_conn(&mut self, vol: usize, ino: Ino, kind: Kind, rights: u64) -> Result<Handle, i64> {
        let slot = match self.conns.iter().position(|c| c.is_none()) {
            Some(i) => i,
            None if self.conns.len() < MAX_CONNS => {
                self.conns.push(None);
                self.conns.len() - 1
            }
            None => return Err(sys::ERR_NO_RESOURCES),
        };
        let (mine, theirs) = sys::channel_pair()?;
        self.conns[slot] = Some(Conn { ch: mine, vol, ino, kind, rights });
        self.port.arm(mine, sys::READABLE | sys::PEER_CLOSED, KEY_CONN + slot as u64);
        Ok(theirs)
    }

    fn volume_name(&self, part: &gpt::Partition, kind: u64) -> String {
        let base: String = part.name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(24).collect();
        let base = if base.is_empty() { String::from(if kind == fp::KIND_DFS { "dfs" } else { "fat" }) } else { base };
        let mut name = base.clone();
        let mut n = 2;
        while self.vols.iter().any(|v| v.name == name) {
            name = alloc::format!("{}-{}", base, n);
            n += 1;
        }
        name
    }

    fn disk_added(&mut self, key: u64, sectors: u64, name: &[u8], ch: Handle) {
        let name = String::from(core::str::from_utf8(name).unwrap_or("?"));
        if let Some(d) = self.disks.iter().find(|d| d.remote.borrow().name == name) {
            let mut r = d.remote.borrow_mut();
            sys::handle_close(r.ch);
            r.ch = ch;
            println!("storaged: {}: reattached", name);
            return;
        }
        let _ = key;
        let remote = Rc::new(RefCell::new(Remote {
            name: name.clone(),
            ch,
            sectors,
            disks: self.disks_ch.clone(),
            pending: self.pending.clone(),
            req: vec![0u8; HEADER + MAX_SECTORS as usize * SECTOR],
            rep: vec![0u8; HEADER + MAX_SECTORS as usize * SECTOR],
        }));
        self.disks.push(Disk { remote: remote.clone() });
        if self.rocheck {
            let st = remote.borrow_mut().probe_write(0);
            if st == sys::ERR_ACCESS_DENIED {
                println!("storaged: read-only check: {}: the driver refused a raw write", name);
            } else {
                println!("storaged: read-only check FAILED: {}: a raw write returned {}", name, fp::status(st));
            }
        }
        let parts = gpt::read(&mut *remote.borrow_mut());
        let (parts, primary) = match parts {
            Ok(p) => p,
            Err(Error::NotFound) => {
                println!("storaged: disk {}: {} MiB, no partition table", name, sectors / 2048);
                return;
            }
            Err(e) => {
                println!("storaged: disk {}: partition table unusable ({:?})", name, e);
                return;
            }
        };
        println!(
            "storaged: disk {}: {} MiB, GPT with {} partition(s){}",
            name,
            sectors / 2048,
            parts.len(),
            if primary { "" } else { " (primary table damaged: backup used)" }
        );
        for p in &parts {
            let kind = if p.type_guid == gpt::TYPE_DFS {
                fp::KIND_DFS
            } else if p.type_guid == gpt::TYPE_ESP || p.type_guid == gpt::TYPE_BASIC_DATA {
                fp::KIND_FAT32
            } else {
                continue;
            };
            let shared: dosfs::dev::Shared = remote.clone();
            let part = Part { disk: shared, start: p.first, len: p.sectors() };
            let (dev, cut): (Box<dyn BlockDev>, _) = if self.test {
                let c = Rc::new(RefCell::new(CutDev::new(part)));
                (Box::new(SharedCut(c.clone())), Some(c))
            } else if !self.writable {
                (Box::new(RoDev(part)), None)
            } else {
                (Box::new(part), None)
            };
            // Windows uses the "basic data" type for NTFS and exFAT too: name them instead of
            // reporting a failed FAT32 mount (found on the first real-hardware boot).
            if kind == fp::KIND_FAT32 {
                let mut bs = [0u8; SECTOR];
                let pdisk: dosfs::dev::Shared = remote.clone();
                let mut probe = Part { disk: pdisk, start: p.first, len: p.sectors() };
                if probe.read(0, &mut bs).is_ok() {
                    let other = match &bs[3..11] {
                        b"NTFS    " => Some("NTFS"),
                        b"EXFAT   " => Some("exFAT"),
                        _ => None,
                    };
                    if let Some(fsname) = other {
                        println!("storaged: {} partition {} ('{}'): {}, not supported (left alone)", name, p.index, p.name, fsname);
                        continue;
                    }
                }
            }
            let vname = self.volume_name(p, kind);
            let fs = match mount(kind, dev) {
                Ok(fs) => fs,
                Err(e) => {
                    println!("storaged: {} partition {} ('{}'): cannot mount {}: {:?}", name, p.index, p.name, kind_name(kind), e);
                    continue;
                }
            };
            let mut v = Volume { name: vname, kind, fs: Some(fs), cut, dirty: false };
            let (info, extra) = match v.fs.as_mut() {
                Some(VolFs::Dfs(d)) => {
                    let i = d.info();
                    let s = d.snapshots().len();
                    let fb = d.fallbacks;
                    (i, alloc::format!(", generation {}, {} snapshot(s){}", i.generation, s, if fb > 0 { ", fell back past a damaged superblock" } else { "" }))
                }
                Some(VolFs::Fat(f)) => (f.info(), String::new()),
                None => continue,
            };
            println!(
                "storaged: volume '{}': {} on {} partition {}, {} MiB, {} MiB free{}{}",
                v.name,
                kind_name(kind),
                name,
                p.index,
                (info.total_blocks * info.block_size) >> 20,
                (info.free_blocks * info.block_size) >> 20,
                extra,
                if self.writable { "" } else { ", read-only" }
            );
            let vi = self.vols.len();
            let root = v.fs.as_mut().map_or(0, |f| f.fs().root());
            let vname = v.name.clone();
            self.vols.push(v);
            let rights = if self.writable { R_ALL } else { R_READ };   // read-only: no write or admin rights at all
            match self.add_conn(vi, root, Kind::Dir, rights) {
                Ok(h) => {
                    let mut m = [0u8; HEADER + 32];
                    Header { txid: 0, op: fp::VOLUME, status: 0, a: kind, b: 0 }.put(&mut m);
                    let n = vname.len().min(32);
                    m[HEADER..HEADER + n].copy_from_slice(&vname.as_bytes()[..n]);
                    sys::channel_write_h(self.ctl, &m[..HEADER + n], &[MsgHandle { handle: h, rights: sys::RIGHTS_SAME }]);
                }
                Err(e) => println!("storaged: cannot announce '{}': {}", vname, fp::status(e)),
            }
        }
    }

    fn disks_message(&mut self, msg: &[u8], handle: Handle) {
        let Some(h) = Header::get(msg) else {
            if handle != 0 {
                sys::handle_close(handle);
            }
            return;
        };
        match h.op {
            fp::DISK_ADD if handle != 0 => self.disk_added(h.a, h.b, &msg[HEADER..], handle),
            fp::DISKS_SETTLED => {
                if !self.announced {
                    self.announced = true;
                    proto::send(self.ctl, fp::VOLUMES_DONE, self.vols.len() as u64, 0);
                    println!("storaged: {} volume(s) on {} disk(s), file service ready", self.vols.len(), self.disks.len());
                }
            }
            _ => {
                if handle != 0 {
                    sys::handle_close(handle);
                }
            }
        }
    }

    /// Drain a channel of messages that may carry one handle.
    fn drain(&mut self, ch: Handle, key: u64) {
        loop {
            let mut hs = [0 as Handle; 1];
            let mut buf = core::mem::take(&mut self.buf);
            let r = sys::channel_read_h(ch, &mut buf, &mut hs, 0);
            match r {
                Ok((n, nh)) => {
                    let handle = if nh > 0 { hs[0] } else { 0 };
                    if key == KEY_DISKS {
                        self.disks_message(&buf[..n], handle);
                    } else if let Some(h) = Header::get(&buf[..n])
                        && h.op == fp::DISKS_LINK
                        && handle != 0
                    {
                        sys::handle_close(self.disks_ch.get());
                        self.disks_ch.set(handle);
                        self.port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_DISKS);
                    } else if handle != 0 {
                        sys::handle_close(handle);
                    }
                    self.buf = buf;
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.buf = buf;
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, key);
                    return;
                }
                Err(_) => {
                    self.buf = buf;
                    return; // the peer is gone: init or devmgr will relink
                }
            }
        }
    }

    fn conn_ready(&mut self, slot: usize) {
        loop {
            let Some(Some(c)) = self.conns.get(slot) else { return };
            let ch = c.ch;
            let mut hs = [0 as Handle; 1];
            let mut buf = core::mem::take(&mut self.buf);
            match sys::channel_read_h(ch, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    if nh > 0 {
                        sys::handle_close(hs[0]); // requests carry no handles
                    }
                    if let Some(h) = Header::get(&buf[..n]) {
                        self.request(slot, &h, &buf[HEADER..n]);
                    }
                    self.buf = buf;
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.buf = buf;
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CONN + slot as u64);
                    return;
                }
                Err(_) => {
                    self.buf = buf;
                    sys::handle_close(ch); // the client closed it
                    self.conns[slot] = None;
                    return;
                }
            }
        }
    }

    fn request(&mut self, slot: usize, h: &Header, payload: &[u8]) {
        let Some(c) = self.conns[slot].as_ref() else { return };
        let (ch, vi, ino, kind, rights) = (c.ch, c.vol, c.ino, c.kind, c.rights);
        let mut out = core::mem::take(&mut self.out);
        let r = self.handle(vi, ino, kind, rights, h, payload, &mut out);
        match r {
            Ok(Reply { a, b, len, handle }) => {
                fp::reply(ch, h.txid, h.op, 0, a, b, &out[..len], handle);
            }
            Err(e) => {
                fp::reply(ch, h.txid, h.op, e, 0, 0, &[], None);
            }
        }
        self.out = out;
    }

    #[allow(clippy::too_many_arguments)]
    fn handle(&mut self, vi: usize, ino: Ino, kind: Kind, rights: u64, h: &Header, p: &[u8], out: &mut [u8]) -> Result<Reply, i64> {
        let need = |r: u64| if rights & r == r { Ok(()) } else { Err(sys::ERR_ACCESS_DENIED) };
        let test = self.test;
        let vkind = self.vols.get(vi).map_or(0, |v| v.kind);
        match h.op {
            fp::OPEN => {
                if kind != Kind::Dir {
                    return Err(fp::ERR_NOT_DIR);
                }
                let want = h.b;
                if want & !R_ALL != 0 || want & !rights != 0 {
                    return Err(sys::ERR_ACCESS_DENIED); // never more than this handle has
                }
                let comps: Vec<&[u8]> = fp::components(p).ok_or(fp::ERR_BAD_NAME)?.collect();
                let flags = h.a;
                if flags & fp::O_TRUNCATE != 0 && want & R_WRITE == 0 {
                    return Err(sys::ERR_ACCESS_DENIED);
                }
                let fs = self.fs(vi)?;
                let mut cur = ino;
                for c in &comps[..comps.len() - 1] {
                    cur = fs.lookup(cur, c).map_err(status)?;
                    if fs.stat(cur).map_err(status)?.kind != Kind::Dir {
                        return Err(fp::ERR_NOT_DIR);
                    }
                }
                let last = comps[comps.len() - 1];
                let node = match fs.lookup(cur, last) {
                    Ok(n) => {
                        if flags & fp::O_CREATE != 0 && flags & fp::O_EXCL != 0 {
                            return Err(fp::ERR_EXISTS);
                        }
                        n
                    }
                    Err(Error::NotFound) if flags & fp::O_CREATE != 0 => {
                        if rights & R_WRITE == 0 {
                            return Err(sys::ERR_ACCESS_DENIED);
                        }
                        let k = if flags & fp::O_DIRECTORY != 0 { Kind::Dir } else { Kind::File };
                        fs.create(cur, last, k).map_err(status)?
                    }
                    Err(e) => return Err(status(e)),
                };
                let st = fs.stat(node).map_err(status)?;
                if flags & fp::O_DIRECTORY != 0 && st.kind != Kind::Dir {
                    return Err(fp::ERR_NOT_DIR);
                }
                let mut size = st.size;
                if flags & fp::O_TRUNCATE != 0 && st.kind == Kind::File && size > 0 {
                    fs.truncate(node, 0).map_err(status)?;
                    size = 0;
                }
                self.touch(vi, flags & (fp::O_CREATE | fp::O_TRUNCATE) != 0);
                let hd = self.add_conn(vi, node, st.kind, want)?;
                Ok(Reply { a: kind_code(st.kind), b: size, len: 0, handle: Some(hd) })
            }
            fp::READ => {
                need(R_READ)?;
                if kind != Kind::File {
                    return Err(fp::ERR_IS_DIR);
                }
                let n = (h.b as usize).min(fp::MAX_IO);
                let got = self.fs(vi)?.read(ino, h.a, &mut out[..n]).map_err(status)?;
                Ok(Reply { a: got as u64, b: 0, len: got, handle: None })
            }
            fp::WRITE => {
                need(R_WRITE)?;
                if kind != Kind::File {
                    return Err(fp::ERR_IS_DIR);
                }
                let n = self.fs(vi)?.write(ino, h.a, p).map_err(status)?;
                self.touch(vi, true);
                Ok(Reply { a: n as u64, b: 0, len: 0, handle: None })
            }
            fp::STAT => {
                let st = self.fs(vi)?.stat(ino).map_err(status)?;
                Ok(Reply { a: st.size, b: kind_code(st.kind) | rights << 8, len: 0, handle: None })
            }
            fp::READDIR => {
                need(R_READ)?;
                if kind != Kind::Dir {
                    return Err(fp::ERR_NOT_DIR);
                }
                let (es, next) = self.fs(vi)?.readdir(ino, h.a, 120).map_err(status)?;
                let mut len = 0;
                for e in &es {
                    let n = e.name.len().min(255);
                    out[len] = kind_code(e.kind) as u8;
                    out[len + 1] = n as u8;
                    out[len + 2..len + 2 + n].copy_from_slice(&e.name[..n]);
                    len += 2 + n;
                }
                Ok(Reply { a: next.unwrap_or(0), b: u64::from(next.is_none()), len, handle: None })
            }
            fp::UNLINK => {
                need(R_WRITE)?;
                if kind != Kind::Dir {
                    return Err(fp::ERR_NOT_DIR);
                }
                if !fp::valid_name(p) {
                    return Err(fp::ERR_BAD_NAME);
                }
                self.fs(vi)?.unlink(ino, p).map_err(status)?;
                self.touch(vi, true);
                Ok(Reply::none())
            }
            fp::TRUNCATE => {
                need(R_WRITE)?;
                if kind != Kind::File {
                    return Err(fp::ERR_IS_DIR);
                }
                self.fs(vi)?.truncate(ino, h.a).map_err(status)?;
                self.touch(vi, true);
                Ok(Reply::none())
            }
            fp::SYNC => {
                self.fs(vi)?.sync().map_err(status)?;
                if let Some(v) = self.vols.get_mut(vi) {
                    v.dirty = false;
                }
                Ok(Reply::none())
            }
            fp::CLONE => {
                if h.b & !rights != 0 || h.b & !R_ALL != 0 {
                    return Err(sys::ERR_ACCESS_DENIED);
                }
                let hd = self.add_conn(vi, ino, kind, h.b)?;
                Ok(Reply { a: 0, b: 0, len: 0, handle: Some(hd) })
            }
            fp::VOLINFO => {
                let i = self.fs(vi)?.info();
                out[0..8].copy_from_slice(&vkind.to_le_bytes());
                out[8..16].copy_from_slice(&i.block_size.to_le_bytes());
                out[16..24].copy_from_slice(&i.generation.to_le_bytes());
                Ok(Reply { a: i.total_blocks, b: i.free_blocks, len: 24, handle: None })
            }
            fp::SNAPSHOT | fp::SNAPSHOT_DELETE | fp::SNAPSHOT_OPEN => {
                need(if h.op == fp::SNAPSHOT_OPEN { R_READ } else { R_ADMIN })?;
                let d = self.dfs(vi)?;
                if ino != d.root() {
                    return Err(sys::ERR_INVALID_ARGS); // snapshots are of whole volumes
                }
                match h.op {
                    fp::SNAPSHOT => {
                        d.snapshot(p).map_err(status)?;
                        Ok(Reply::none())
                    }
                    fp::SNAPSHOT_DELETE => {
                        let freed = d.delete_snapshot(p).map_err(status)?;
                        Ok(Reply { a: freed, b: 0, len: 0, handle: None })
                    }
                    _ => {
                        let root = d.open_snapshot(p).map_err(status)?;
                        let hd = self.add_conn(vi, root, Kind::Dir, R_READ)?;
                        Ok(Reply { a: 0, b: 0, len: 0, handle: Some(hd) })
                    }
                }
            }
            fp::TEST if test => {
                need(R_ADMIN)?;
                self.test_hook(vi, ino, h.a, h.b)
            }
            _ => Err(sys::ERR_NOT_SUPPORTED),
        }
    }

    fn test_hook(&mut self, vi: usize, ino: Ino, what: u64, arg: u64) -> Result<Reply, i64> {
        let v = self.vols.get_mut(vi).ok_or(sys::ERR_BAD_STATE)?;
        match what {
            fp::TEST_POWERCUT => {
                let c = v.cut.as_ref().ok_or(sys::ERR_BAD_STATE)?;
                c.borrow_mut().arm(arg, arg.wrapping_mul(2654435761) | 1);
                println!("storaged: test: '{}': the power fails after {} more sectors", v.name, arg);
                Ok(Reply::none())
            }
            fp::TEST_REMOUNT => {
                let fs = v.fs.take().ok_or(sys::ERR_BAD_STATE)?;
                let dev: Box<dyn BlockDev> = match fs {
                    VolFs::Dfs(d) => d.into_dev(),
                    VolFs::Fat(f) => f.dev,
                };
                if let Some(c) = v.cut.as_ref() {
                    let lost = c.borrow().cut;
                    c.borrow_mut().restore();
                    println!("storaged: test: '{}': power restored{}, remounting", v.name, if lost { " (writes were lost)" } else { "" });
                }
                let kind = v.kind;
                match mount(kind, dev) {
                    Ok(mut f) => {
                        let (generation, fb) = match &mut f {
                            VolFs::Dfs(d) => (d.info().generation, u64::from(d.fallbacks)),
                            VolFs::Fat(_) => (0, 0),
                        };
                        v.fs = Some(f);
                        v.dirty = false;
                        Ok(Reply { a: generation, b: fb, len: 0, handle: None })
                    }
                    Err(e) => {
                        println!("storaged: test: '{}': remount failed: {:?}", v.name, e);
                        Err(status(e))
                    }
                }
            }
            _ => {
                let d = match v.fs.as_mut() {
                    Some(VolFs::Dfs(d)) => d,
                    _ => return Err(sys::ERR_NOT_SUPPORTED),
                };
                let r = match what {
                    fp::TEST_CORRUPT_DATA => d.corrupt_data(ino).map(|a| (a, 0)),
                    fp::TEST_CORRUPT_META => d.corrupt_meta(ino).map(|a| (a, 0)),
                    fp::TEST_CORRUPT_SUPER => d.corrupt_super().map(|g| (g, 0)),
                    fp::TEST_FSCK => match d.fsck() {
                        Ok(f) => {
                            if let Some((w, at)) = f.first {
                                println!("storaged: fsck '{}': {} error(s), first: {} ({})", v.name, f.errors, w, at);
                            }
                            Ok((f.errors, f.nodes + f.data_blocks))
                        }
                        Err(e) => Err(e),
                    },
                    _ => return Err(sys::ERR_INVALID_ARGS),
                };
                let (a, b) = r.map_err(status)?;
                Ok(Reply { a, b, len: 0, handle: None })
            }
        }
    }

    fn fs(&mut self, vi: usize) -> Result<&mut dyn FileSystem, i64> {
        self.vols.get_mut(vi).and_then(|v| v.fs.as_mut()).map(|f| f.fs()).ok_or(sys::ERR_BAD_STATE)
    }

    fn dfs(&mut self, vi: usize) -> Result<&mut Dfs, i64> {
        match self.vols.get_mut(vi).and_then(|v| v.fs.as_mut()) {
            Some(VolFs::Dfs(d)) => Ok(d),
            Some(_) => Err(sys::ERR_NOT_SUPPORTED),
            None => Err(sys::ERR_BAD_STATE),
        }
    }

    fn touch(&mut self, vi: usize, changed: bool) {
        if changed && let Some(v) = self.vols.get_mut(vi) {
            v.dirty = true;
        }
    }

    /// Commit volumes that have been written to (after the service has been idle a while).
    fn commit_idle(&mut self) {
        for v in self.vols.iter_mut().filter(|v| v.dirty) {
            if let Some(f) = v.fs.as_mut()
                && let Err(e) = f.fs().sync()
            {
                println!("storaged: '{}': background commit failed: {:?}", v.name, e);
            }
            v.dirty = false;
        }
    }
}

struct Reply {
    a: u64,
    b: u64,
    len: usize,
    handle: Option<Handle>,
}

impl Reply {
    fn none() -> Reply {
        Reply { a: 0, b: 0, len: 0, handle: None }
    }
}

fn mount(kind: u64, dev: Box<dyn BlockDev>) -> Result<VolFs, Error> {
    if kind == fp::KIND_DFS {
        Dfs::mount(dev).map(VolFs::Dfs).map_err(|(e, _)| e)
    } else {
        Fat::mount(dev).map(VolFs::Fat)
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "storaged") } {
        return -1;
    }
    let disks = libd::startup_handle(fp::TAG_DISKS);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let test = libd::args().starts_with(b"test");
    let rocheck = libd::args() == b"rocheck";
    let Ok(port) = Port::new(1024) else {
        println!("storaged: cannot create a port");
        return 1;
    };
    let mut svc = Svc {
        port,
        disks_ch: Rc::new(Cell::new(disks)),
        ctl,
        pending: Rc::new(RefCell::new(Vec::new())),
        disks: Vec::new(),
        vols: Vec::new(),
        conns: Vec::new(),
        test,
        writable: test,
        rocheck,
        announced: false,
        buf: vec![0u8; HEADER + fp::MAX_IO + 64],
        out: vec![0u8; fp::MAX_IO],
    };
    if disks != 0 {
        svc.port.arm(disks, sys::READABLE | sys::PEER_CLOSED, KEY_DISKS);
    }
    if ctl != 0 {
        svc.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    println!("storaged: running{}", if test { " (test hooks on)" } else { " (read-only: volumes are never written)" });
    loop {
        // Messages the block layer set aside while a disk was coming back.
        let pending: Vec<Pending> = core::mem::take(&mut *svc.pending.borrow_mut());
        for p in pending {
            svc.disks_message(&p.msg, p.handle);
        }
        let timeout = if svc.vols.iter().any(|v| v.dirty) { COMMIT_IDLE } else { sys::WAIT_FOREVER };
        let Some((key, _)) = svc.port.wait(timeout) else {
            svc.commit_idle();
            continue;
        };
        match key {
            KEY_DISKS => {
                let ch = svc.disks_ch.get();
                svc.drain(ch, KEY_DISKS);
            }
            KEY_CTL => svc.drain(ctl, KEY_CTL),
            k if k >= KEY_CONN => svc.conn_ready((k - KEY_CONN) as usize),
            _ => {}
        }
    }
}
