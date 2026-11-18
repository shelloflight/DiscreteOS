//! Files as handles: the storage service protocol, the file protocol and its client,
//! and per-app namespaces. Reference: docs/storage.md.
//!
//! Every open file or directory is a channel to the storage service (`storaged`). What the
//! holder may do is fixed by the service when the channel is opened (`R_READ`, `R_WRITE`,
//! `R_ADMIN`), never by the client: a handle to a directory reaches only that directory's
//! subtree (paths are relative, and `.` / `..` are not names), with at most its own rights.
//!
//! Messages use the driver protocol's 32-byte header (`proto::Header`): requests are
//! `channel_call`s, `op` names the request, `a` / `b` its arguments, the payload follows. A reply
//! has the same `op`, `status` (0 or a negative status below / from `sys`) and its results.

use crate::proto::{HEADER, Header};
use crate::sys::{self, Handle, MsgHandle};

// ---- storage service <-> system ------------------------------------------------------------

/// devmgr -> storaged (TAG_DISKS channel): a disk; `a` = key, `b` = sectors, payload = name;
/// carries the disk's block channel. The same name again means the driver was restarted: the
/// new channel replaces the old one.
pub const DISK_ADD: u32 = 100;
/// devmgr -> storaged: every driver started at boot has reported its disks.
pub const DISKS_SETTLED: u32 = 101;
/// storaged -> init (TAG_CONTROL channel): a mounted volume; `a` = FS kind, `b` = flags,
/// payload = name; carries a channel to its root directory with every right.
pub const VOLUME: u32 = 102;
/// storaged -> init: the volumes of every disk present at boot have been announced; `a` = count.
pub const VOLUMES_DONE: u32 = 103;
/// init -> storaged: a new disks channel (devmgr was restarted); carries it.
pub const DISKS_LINK: u32 = 104;

/// Startup tags.
pub const TAG_DISKS: u32 = sys::TAG_USER + 0x10; // storaged: disks from devmgr
pub const TAG_STORAGE: u32 = sys::TAG_USER + 0x11; // devmgr: disks to storaged
pub const TAG_NS_NAMES: u32 = sys::TAG_USER + 0xFF; // namespace: VMO of NUL-ended paths
pub const TAG_NS: u32 = sys::TAG_USER + 0x100; // namespace entry i: TAG_NS + i
pub const MAX_NS: usize = 32;

pub const KIND_FAT32: u64 = 1;
pub const KIND_DFS: u64 = 2;
pub const VOL_READ_ONLY: u64 = 1;

// ---- the file protocol --------------------------------------------------------------------

/// `a` = flags, `b` = rights wanted; payload = relative path. Reply: `a` = kind, `b` = size;
/// carries the new node's channel.
pub const OPEN: u32 = 200;
/// `a` = offset, `b` = length (<= MAX_IO). Reply payload = data (shorter at the end of file).
pub const READ: u32 = 201;
/// `a` = offset; payload = data (<= MAX_IO). Reply `a` = bytes written.
pub const WRITE: u32 = 202;
/// Reply: `a` = size, `b` = kind | rights << 8; payload = {created i64, modified i64} (D-OS
/// times, `libd::time`; 0 = unknown).
pub const STAT: u32 = 203;
/// `a` = cookie (0 = start). Reply payload = entries {kind u8, len u8, name}; `a` = next cookie,
/// `b` = 1 when the directory has no more entries.
pub const READDIR: u32 = 204;
/// payload = name (a direct child). Directories must be empty.
pub const UNLINK: u32 = 205;
/// `a` = new size.
pub const TRUNCATE: u32 = 206;
/// Make everything written on this volume durable (DFS: commit a generation).
pub const SYNC: u32 = 207;
/// `b` = rights (a subset). Reply carries a new channel to the same node.
pub const CLONE: u32 = 208;
/// Reply: `a` = total blocks, `b` = free blocks; payload = {kind u64, block size u64, generation u64}.
pub const VOLINFO: u32 = 209;
/// Volume root with R_ADMIN (DFS): payload = name; take a read-only snapshot of what is synced.
pub const SNAPSHOT: u32 = 210;
/// Volume root (DFS): payload = name. Reply carries a read-only channel to the snapshot's root.
pub const SNAPSHOT_OPEN: u32 = 211;
/// Volume root with R_ADMIN (DFS): payload = name; delete the snapshot and free its space.
pub const SNAPSHOT_DELETE: u32 = 212;
/// Directory with R_WRITE: payload = `from\0to`, two paths below this directory (so a move stays
/// inside what the caller was given). `a` = `RENAME_REPLACE` to replace an existing file `to`;
/// otherwise an existing `to` is refused (`ERR_EXISTS`). A directory cannot move into itself.
pub const RENAME: u32 = 213;
pub const RENAME_REPLACE: u64 = 1;
/// Test hooks (only when storaged runs with `test`; R_ADMIN): `a` = TEST_*, `b` = argument.
pub const TEST: u32 = 250;

pub const TEST_CORRUPT_DATA: u64 = 1; // flip a byte in this file's first data block on disk
pub const TEST_CORRUPT_META: u64 = 2; // flip a byte in the tree leaf holding this node
pub const TEST_CORRUPT_SUPER: u64 = 3; // flip a byte in the newest superblock
pub const TEST_POWERCUT: u64 = 4; // `b` = writes until the power fails (the rest are lost)
pub const TEST_REMOUNT: u64 = 5; // power back: forget everything in memory, mount again
pub const TEST_FSCK: u64 = 6; // check the whole volume; reply `a` = errors, `b` = blocks checked

pub const O_CREATE: u64 = 1;
pub const O_EXCL: u64 = 2;
pub const O_DIRECTORY: u64 = 4;
pub const O_TRUNCATE: u64 = 8;

pub const R_READ: u64 = 1;
pub const R_WRITE: u64 = 2;
pub const R_ADMIN: u64 = 4;
pub const R_ALL: u64 = R_READ | R_WRITE | R_ADMIN;

pub const KIND_FILE: u64 = 1;
pub const KIND_DIR: u64 = 2;

pub const MAX_IO: usize = 32 * 1024;
pub const MAX_PATH: usize = 1024;
pub const MAX_NAME: usize = 255;

pub const ERR_NOT_FOUND: i64 = -100;
pub const ERR_EXISTS: i64 = -101;
pub const ERR_NOT_DIR: i64 = -102;
pub const ERR_IS_DIR: i64 = -103;
pub const ERR_NOT_EMPTY: i64 = -104;
pub const ERR_IO: i64 = -105;
pub const ERR_CORRUPT: i64 = -106;
pub const ERR_BAD_NAME: i64 = -107;
pub const ERR_READ_ONLY: i64 = -108;

pub fn status(e: i64) -> &'static str {
    match e {
        ERR_NOT_FOUND => "NOT_FOUND",
        ERR_EXISTS => "EXISTS",
        ERR_NOT_DIR => "NOT_DIR",
        ERR_IS_DIR => "IS_DIR",
        ERR_NOT_EMPTY => "NOT_EMPTY",
        ERR_IO => "IO",
        ERR_CORRUPT => "CORRUPT",
        ERR_BAD_NAME => "BAD_NAME",
        ERR_READ_ONLY => "READ_ONLY",
        _ => sys::status(e),
    }
}

/// A status in words, for people (the shell and its tools).
pub fn message(e: i64) -> &'static str {
    match e {
        ERR_NOT_FOUND => "not found",
        ERR_EXISTS => "already exists",
        ERR_NOT_DIR => "is not a directory",
        ERR_IS_DIR => "is a directory",
        ERR_NOT_EMPTY => "is not empty",
        ERR_IO => "disk error",
        ERR_CORRUPT => "damaged (a checksum does not match)",
        ERR_BAD_NAME => "is not a valid name",
        ERR_READ_ONLY => "is read-only",
        sys::ERR_ACCESS_DENIED => "access denied (not granted)",
        sys::ERR_PEER_CLOSED => "the storage service is gone",
        sys::ERR_NO_RESOURCES | sys::ERR_NO_MEMORY => "out of resources",
        _ => status(e),
    }
}

/// A valid name: 1..=255 bytes, not `.` or `..`, no `/`, no NUL or other control bytes.
pub fn valid_name(n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= MAX_NAME && n != b"." && n != b".." && n.iter().all(|&c| c >= 0x20 && c != b'/' && c != 0x7F)
}

/// The components of a relative path, or None if any is invalid (absolute paths, empty
/// components, `.` and `..` are refused: a path never leaves the directory it starts from).
pub fn components(p: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
    if p.is_empty() || p.len() > MAX_PATH || !p.split(|&c| c == b'/').all(valid_name) {
        return None;
    }
    Some(p.split(|&c| c == b'/'))
}

// ---- client ---------------------------------------------------------------------------------

/// An open file or directory (a channel to the storage service). Closed on drop.
pub struct Node {
    pub ch: Handle,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    pub size: u64,
    pub kind: u64,
    pub rights: u64,
    /// D-OS times (`libd::time::Time`; 0 = unknown).
    pub created: i64,
    pub modified: i64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct VolInfo {
    pub total: u64,
    pub free: u64,
    pub kind: u64,
    pub block: u64,
    pub generation: u64,
}

type Res<T> = Result<T, i64>;

const BUF: usize = HEADER + MAX_IO;

impl Node {
    pub fn from(ch: Handle) -> Node {
        Node { ch }
    }

    /// Give up ownership (the handle is not closed).
    pub fn into_handle(self) -> Handle {
        let h = self.ch;
        core::mem::forget(self);
        h
    }

    /// One request: (reply header, payload length in `out`, handle if the reply carried one).
    fn call(&self, op: u32, a: u64, b: u64, payload: &[u8], out: &mut [u8]) -> Res<(Header, usize, Handle)> {
        let mut req = [0u8; BUF];
        if payload.len() > MAX_IO {
            return Err(sys::ERR_INVALID_ARGS);
        }
        Header { txid: 0, op, status: 0, a, b }.put(&mut req);
        req[HEADER..HEADER + payload.len()].copy_from_slice(payload);
        let mut rep = [0u8; BUF];
        let mut hs = [0 as Handle; 1];
        let (n, nh) = sys::channel_call_h(self.ch, &req[..HEADER + payload.len()], &[], &mut rep, &mut hs, 30_000_000_000)?;
        let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
        let got = if nh > 0 { hs[0] } else { 0 };
        if h.status != 0 {
            if got != 0 {
                sys::handle_close(got);
            }
            return Err(i64::from(h.status));
        }
        let len = (n - HEADER).min(out.len());
        out[..len].copy_from_slice(&rep[HEADER..HEADER + len]);
        Ok((h, len, got))
    }

    /// Open `path` below this directory: (node, kind, size).
    pub fn open(&self, path: &[u8], flags: u64, rights: u64) -> Res<(Node, u64, u64)> {
        let (h, _, ch) = self.call(OPEN, flags, rights, path, &mut [])?;
        if ch == 0 {
            return Err(sys::ERR_BAD_STATE);
        }
        Ok((Node { ch }, h.a, h.b))
    }

    pub fn read(&self, off: u64, buf: &mut [u8]) -> Res<usize> {
        let mut done = 0;
        while done < buf.len() {
            let n = (buf.len() - done).min(MAX_IO);
            let (_, got, _) = self.call(READ, off + done as u64, n as u64, &[], &mut buf[done..done + n])?;
            done += got;
            if got < n {
                break;
            }
        }
        Ok(done)
    }

    pub fn write(&self, off: u64, data: &[u8]) -> Res<usize> {
        let mut done = 0;
        while done < data.len() {
            let n = (data.len() - done).min(MAX_IO);
            let (h, _, _) = self.call(WRITE, off + done as u64, 0, &data[done..done + n], &mut [])?;
            done += h.a as usize;
            if (h.a as usize) < n {
                break;
            }
        }
        Ok(done)
    }

    pub fn stat(&self) -> Res<Stat> {
        let mut t = [0u8; 16];
        let (h, n, _) = self.call(STAT, 0, 0, &[], &mut t)?;
        let at = |i: usize| if n >= i + 8 { i64::from_le_bytes(t[i..i + 8].try_into().unwrap_or([0; 8])) } else { 0 };
        Ok(Stat { size: h.a, kind: h.b & 0xFF, rights: h.b >> 8, created: at(0), modified: at(8) })
    }

    /// Move `from` to `to`, both paths below this directory (R_WRITE). `replace`: an existing
    /// file `to` is replaced (atomically on DFS); otherwise it is refused (`ERR_EXISTS`).
    pub fn rename(&self, from: &[u8], to: &[u8], replace: bool) -> Res<()> {
        let mut p = [0u8; 2 * MAX_PATH + 1];
        if from.len() > MAX_PATH || to.len() > MAX_PATH {
            return Err(ERR_BAD_NAME);
        }
        p[..from.len()].copy_from_slice(from);
        p[from.len() + 1..from.len() + 1 + to.len()].copy_from_slice(to);
        let n = from.len() + 1 + to.len();
        self.call(RENAME, if replace { RENAME_REPLACE } else { 0 }, 0, &p[..n], &mut []).map(|_| ())
    }

    /// Entries from `cookie` on: `f(name, kind)` for each. Returns the next cookie, or None at
    /// the end.
    pub fn readdir(&self, cookie: u64, mut f: impl FnMut(&[u8], u64)) -> Res<Option<u64>> {
        let mut out = [0u8; MAX_IO];
        let (h, n, _) = self.call(READDIR, cookie, 0, &[], &mut out)?;
        let mut i = 0;
        while i + 2 <= n {
            let (kind, len) = (u64::from(out[i]), usize::from(out[i + 1]));
            if i + 2 + len > n {
                break;
            }
            f(&out[i + 2..i + 2 + len], kind);
            i += 2 + len;
        }
        Ok(if h.b == 1 { None } else { Some(h.a) })
    }

    /// Every entry: `f(name, kind)`.
    pub fn list(&self, mut f: impl FnMut(&[u8], u64)) -> Res<()> {
        let mut c = 0;
        loop {
            match self.readdir(c, &mut f)? {
                Some(n) => c = n,
                None => return Ok(()),
            }
        }
    }

    pub fn unlink(&self, name: &[u8]) -> Res<()> {
        self.call(UNLINK, 0, 0, name, &mut []).map(|_| ())
    }
    pub fn truncate(&self, size: u64) -> Res<()> {
        self.call(TRUNCATE, size, 0, &[], &mut []).map(|_| ())
    }
    pub fn sync(&self) -> Res<()> {
        self.call(SYNC, 0, 0, &[], &mut []).map(|_| ())
    }
    pub fn clone_with(&self, rights: u64) -> Res<Node> {
        let (_, _, ch) = self.call(CLONE, 0, rights, &[], &mut [])?;
        Ok(Node { ch })
    }
    pub fn volinfo(&self) -> Res<VolInfo> {
        let mut out = [0u8; 24];
        let (h, _, _) = self.call(VOLINFO, 0, 0, &[], &mut out)?;
        let g = |i: usize| u64::from_le_bytes(out[i..i + 8].try_into().unwrap_or([0; 8]));
        Ok(VolInfo { total: h.a, free: h.b, kind: g(0), block: g(8), generation: g(16) })
    }
    pub fn snapshot(&self, name: &[u8]) -> Res<()> {
        self.call(SNAPSHOT, 0, 0, name, &mut []).map(|_| ())
    }
    pub fn snapshot_open(&self, name: &[u8]) -> Res<Node> {
        let (_, _, ch) = self.call(SNAPSHOT_OPEN, 0, 0, name, &mut [])?;
        Ok(Node { ch })
    }
    pub fn snapshot_delete(&self, name: &[u8]) -> Res<()> {
        self.call(SNAPSHOT_DELETE, 0, 0, name, &mut []).map(|_| ())
    }
    /// A test hook (storaged in test mode only): reply (a, b).
    pub fn test(&self, what: u64, arg: u64) -> Res<(u64, u64)> {
        let (h, _, _) = self.call(TEST, what, arg, &[], &mut [])?;
        Ok((h.a, h.b))
    }

    /// Read a whole (small) file into `buf`: bytes read.
    pub fn read_all(&self, buf: &mut [u8]) -> Res<usize> {
        self.read(0, buf)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.ch != 0 {
            sys::handle_close(self.ch);
        }
    }
}

// ---- namespaces -----------------------------------------------------------------------------

/// This process's namespace: the directories its spawner granted, each under a path such as
/// `/data` (startup tags TAG_NS + i, names in the TAG_NS_NAMES VMO). Nothing else is reachable.
pub struct Namespace {
    names: [u8; 1024],
    len: usize,
}

impl Namespace {
    pub fn get() -> Namespace {
        let mut ns = Namespace { names: [0; 1024], len: 0 };
        let v = crate::startup_handle(TAG_NS_NAMES);
        if v != 0 {
            let size = sys::vmo_size(v).unwrap_or(0).min(1024) as usize;
            if sys::vmo_read(v, 0, &mut ns.names[..size]) == 0 {
                ns.len = size;
            }
        }
        ns
    }

    /// The entries: (path, handle).
    pub fn entries(&self) -> impl Iterator<Item = (&[u8], Handle)> {
        self.names[..self.len]
            .split(|&c| c == 0)
            .filter(|n| !n.is_empty())
            .enumerate()
            .take(MAX_NS)
            .map(|(i, n)| (n, crate::startup_handle(TAG_NS + i as u32)))
            .filter(|&(_, h)| h != 0)
    }

    /// The directory granted at exactly `path` (e.g. `/data`).
    pub fn dir(&self, path: &[u8]) -> Option<Handle> {
        self.entries().find(|&(n, _)| n == path).map(|(_, h)| h)
    }

    /// Resolve an absolute path through the namespace: (granted directory, relative rest).
    pub fn resolve<'a>(&self, path: &'a [u8]) -> Option<(Handle, &'a [u8])> {
        let mut best: Option<(Handle, usize)> = None;
        for (n, h) in self.entries() {
            if path.starts_with(n) && (path.len() == n.len() || path[n.len()] == b'/') && best.is_none_or(|(_, l)| n.len() > l) {
                best = Some((h, n.len()));
            }
        }
        best.map(|(h, l)| (h, if path.len() > l { &path[l + 1..] } else { &path[l..] }))
    }
}

/// Builds the namespace of a process to spawn: each entry moves a directory handle into it.
pub struct NsBuilder {
    names: [u8; 1024],
    len: usize,
    handles: [(Handle, u32); MAX_NS],
    n: usize,
}

impl Default for NsBuilder {
    fn default() -> Self {
        NsBuilder::new()
    }
}

impl NsBuilder {
    pub fn new() -> NsBuilder {
        NsBuilder { names: [0; 1024], len: 0, handles: [(0, 0); MAX_NS], n: 0 }
    }

    /// Grant `dir` (moved) at `path` (absolute, e.g. `/data`).
    pub fn add(&mut self, path: &[u8], dir: Node) -> bool {
        if self.n == MAX_NS || self.len + path.len() + 1 > self.names.len() || !path.starts_with(b"/") {
            return false;
        }
        self.names[self.len..self.len + path.len()].copy_from_slice(path);
        self.len += path.len() + 1;
        self.handles[self.n] = (dir.into_handle(), TAG_NS + self.n as u32);
        self.n += 1;
        true
    }

    /// The spawn handles (the names VMO first), written into `out`: how many.
    pub fn finish(&self, out: &mut [sys::SpawnHandle]) -> Res<usize> {
        if out.len() < self.n + 1 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let v = sys::vmo_create(self.len.max(1) as u64)?;
        let r = sys::vmo_write(v, 0, &self.names[..self.len]);
        if r < 0 {
            sys::handle_close(v);
            return Err(r);
        }
        out[0] = sys::SpawnHandle { handle: v, rights: sys::RIGHT_READ, tag: TAG_NS_NAMES, reserved: 0 };
        for i in 0..self.n {
            out[i + 1] = sys::SpawnHandle { handle: self.handles[i].0, rights: sys::RIGHTS_SAME, tag: self.handles[i].1, reserved: 0 };
        }
        Ok(self.n + 1)
    }
}

/// Reply helper for servers: header + payload, optionally carrying a handle.
#[allow(clippy::too_many_arguments)] // the wire format's fields, one each
pub fn reply(ch: Handle, txid: u32, op: u32, status: i64, a: u64, b: u64, payload: &[u8], handle: Option<Handle>) -> i64 {
    let mut buf = [0u8; BUF];
    let n = payload.len().min(MAX_IO);
    Header { txid, op, status: status as i32, a, b }.put(&mut buf);
    buf[HEADER..HEADER + n].copy_from_slice(&payload[..n]);
    match handle {
        Some(h) => sys::channel_write_h(ch, &buf[..HEADER + n], &[MsgHandle { handle: h, rights: sys::RIGHTS_SAME }]),
        None => sys::channel_write(ch, &buf[..HEADER + n]),
    }
}
