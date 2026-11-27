//! Linux file descriptors over the namespace, synthetic `/proc` & `/dev` views, and in-process
//! pipes. 0, 1, 2 are the console (standard input is empty, output goes to `out.rs`); the rest
//! are files/directories opened through `path.rs` (with optional `--prefix` resolution),
//! capability-scoped `/proc` & `/dev` views (`vfs.rs`), or in-process anonymous pipes (`pipe2`).

use alloc::collections::VecDeque;
use alloc::format;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use libd::fs::{self as fp, Node};
use libd::sys::{self, Regs};

use super::vfs;
use super::*;
use crate::{out, path};

pub struct PipeState {
    pub buf: VecDeque<u8>,
    pub writers: usize,
    pub readers: usize,
}

const PIPE_CAP: usize = 65536;

pub enum Kind {
    Stdin,
    Stdout,
    File { node: Node, dir: bool, write: bool, read: bool, path: Vec<u8> },
    SynthFile { data: Vec<u8>, path: Vec<u8> },
    SynthDir { entries: Vec<(Vec<u8>, u64)>, path: Vec<u8> },
    DevNull,
    DevZero,
    DevUrandom,
    DevFull,
    PipeRead(Rc<RefCell<PipeState>>),
    PipeWrite(Rc<RefCell<PipeState>>),
}

pub struct Open {
    pub kind: Kind,
    pub pos: u64,
    pub append: bool,
    pub nonblock: bool,
    /// getdents64: the directory's entries, read once, and how many were returned.
    pub listing: Option<Listing>,
}

impl Open {
    pub fn simple(kind: Kind) -> Open {
        Open { kind, pos: 0, append: false, nonblock: false, listing: None }
    }
    pub fn synth_file(data: Vec<u8>, path: Vec<u8>) -> Open {
        Open::simple(Kind::SynthFile { data, path })
    }
    pub fn synth_dir(entries: Vec<(Vec<u8>, u64)>, path: Vec<u8>) -> Open {
        Open::simple(Kind::SynthDir { entries, path })
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        match &self.kind {
            Kind::PipeRead(p) => {
                let mut g = p.borrow_mut();
                g.readers = g.readers.saturating_sub(1);
            }
            Kind::PipeWrite(p) => {
                let mut g = p.borrow_mut();
                g.writers = g.writers.saturating_sub(1);
            }
            _ => {}
        }
    }
}

/// A directory's entries (name, kind) and how many were returned.
pub type Listing = (Vec<(Vec<u8>, u64)>, usize);

pub struct Fds {
    fds: Vec<Option<Rc<RefCell<Open>>>>,
}

const MAX_FDS: usize = 1024;
const AT_FDCWD: i64 = -100;
const EPIPE: i64 = 32;

fn errno(e: i64) -> i64 {
    -match e {
        fp::ERR_NOT_FOUND => ENOENT,
        fp::ERR_EXISTS => EEXIST,
        fp::ERR_NOT_DIR => ENOTDIR,
        fp::ERR_IS_DIR => EISDIR,
        fp::ERR_NOT_EMPTY => ENOTEMPTY,
        fp::ERR_READ_ONLY => EROFS,
        fp::ERR_BAD_NAME => EINVAL,
        sys::ERR_ACCESS_DENIED => EACCES,
        sys::ERR_NO_SPACE => ENOSPC,
        sys::ERR_NO_MEMORY => ENOMEM,
        sys::ERR_NOT_SUPPORTED => EXDEV,
        _ => EIO,
    }
}

impl Fds {
    pub fn new() -> Fds {
        let o = |k| Some(Rc::new(RefCell::new(Open::simple(k))));
        Fds { fds: alloc::vec![o(Kind::Stdin), o(Kind::Stdout), o(Kind::Stdout)] }
    }
    pub fn get(&self, fd: u64) -> Option<Rc<RefCell<Open>>> {
        self.fds.get(fd as usize).cloned().flatten()
    }
    fn add_at(&mut self, o: Rc<RefCell<Open>>, min: usize) -> i64 {
        let i = (min..MAX_FDS).find(|&i| self.fds.get(i).is_none_or(Option::is_none));
        let Some(i) = i else { return -EMFILE };
        if i >= self.fds.len() {
            self.fds.resize(i + 1, None);
        }
        self.fds[i] = Some(o);
        i as i64
    }
    pub fn fd_path(&self, fd: u64) -> Option<Vec<u8>> {
        let o = self.get(fd)?;
        let o = o.borrow();
        Some(match &o.kind {
            Kind::Stdin => b"/dev/stdin".to_vec(),
            Kind::Stdout => if fd == 2 { b"/dev/stderr".to_vec() } else { b"/dev/stdout".to_vec() },
            Kind::File { path, .. } | Kind::SynthFile { path, .. } | Kind::SynthDir { path, .. } => path.clone(),
            Kind::DevNull => b"/dev/null".to_vec(),
            Kind::DevZero => b"/dev/zero".to_vec(),
            Kind::DevUrandom => b"/dev/urandom".to_vec(),
            Kind::DevFull => b"/dev/full".to_vec(),
            Kind::PipeRead(_) | Kind::PipeWrite(_) => format!("pipe:[{}]", fd).into_bytes(),
        })
    }
    pub fn fd_dir_entries(&self) -> Vec<(Vec<u8>, u64)> {
        let mut out = alloc::vec![(b".".to_vec(), fp::KIND_DIR), (b"..".to_vec(), fp::KIND_DIR)];
        for (i, slot) in self.fds.iter().enumerate() {
            if slot.is_some() {
                out.push((format!("{}", i).into_bytes(), fp::KIND_FILE));
            }
        }
        out
    }
    pub fn clone_fd_open(&self, fd: u64) -> Result<Open, i64> {
        let o = self.get(fd).ok_or(-ENOENT)?;
        let o = o.borrow();
        match &o.kind {
            Kind::Stdin => Ok(Open::simple(Kind::Stdin)),
            Kind::Stdout => Ok(Open::simple(Kind::Stdout)),
            Kind::DevNull => Ok(Open::simple(Kind::DevNull)),
            Kind::DevZero => Ok(Open::simple(Kind::DevZero)),
            Kind::DevUrandom => Ok(Open::simple(Kind::DevUrandom)),
            Kind::DevFull => Ok(Open::simple(Kind::DevFull)),
            Kind::SynthFile { data, path } => Ok(Open::synth_file(data.clone(), path.clone())),
            Kind::SynthDir { entries, path } => Ok(Open::synth_dir(entries.clone(), path.clone())),
            Kind::File { node, dir, write, read, path } => {
                let rights = fp::R_READ | if *write { fp::R_WRITE } else { 0 };
                let n = node.clone_with(rights).map_err(errno)?;
                Ok(Open {
                    kind: Kind::File { node: n, dir: *dir, write: *write, read: *read, path: path.clone() },
                    pos: 0,
                    append: o.append,
                    nonblock: o.nonblock,
                    listing: None,
                })
            }
            Kind::PipeRead(p) => {
                p.borrow_mut().readers += 1;
                Ok(Open::simple(Kind::PipeRead(Rc::clone(p))))
            }
            Kind::PipeWrite(p) => {
                p.borrow_mut().writers += 1;
                Ok(Open::simple(Kind::PipeWrite(Rc::clone(p))))
            }
        }
    }
}

/// The absolute path for `p` relative to `dirfd`.
fn resolve(s: &Server, dirfd: i64, p: &[u8]) -> Result<Vec<u8>, i64> {
    if p.is_empty() {
        return Err(-ENOENT);
    }
    if p.starts_with(b"/") || dirfd == AT_FDCWD {
        return Ok(path::absolute(p));
    }
    let o = s.fds.get(dirfd as u64).ok_or(-EBADF)?;
    let o = o.borrow();
    match &o.kind {
        Kind::File { dir: true, path, .. } | Kind::SynthDir { path, .. } => {
            let mut full = path.clone();
            full.push(b'/');
            full.extend_from_slice(p);
            Ok(path::absolute(&full))
        }
        _ => Err(-ENOTDIR),
    }
}

fn path_arg(s: &Server, dirfd: i64, addr: u64) -> Result<Vec<u8>, i64> {
    let p = s.mem.cstr(addr, fp::MAX_PATH).ok_or(-EFAULT)?;
    resolve(s, dirfd, &p)
}

/// Open an embedded `.so` library (for `utest` runs without mounted disks) when a read-only open
/// of `/lib64/<name>` or `/lib/<name>` or `/<name>` misses the namespace.
fn try_embedded_lib(abs: &[u8]) -> Option<Vec<u8>> {
    let leaf = abs.rsplit(|&c| c == b'/').next()?;
    if !leaf.contains(&b'.') || !(leaf.ends_with(b".so") || leaf.windows(4).any(|w| w == b".so.")) {
        return None;
    }
    let mut found = None;
    crate::programs(|h, name| {
        if found.is_none() && name.eq_ignore_ascii_case(leaf) {
            found = Some(h);
        }
    });
    let h = found?;
    crate::read_image(h, 16 << 20).ok()
}

fn open_real_or_lib(abs: &[u8], of: u64, rights: u64, write: bool) -> Result<Open, i64> {
    let mapped = path::map_linux_path(abs, !write);
    match path::open(&mapped, of, rights) {
        Ok((node, kind, _)) => {
            let dir = kind == fp::KIND_DIR;
            if dir && write {
                return Err(-EISDIR);
            }
            Ok(Open {
                kind: Kind::File { node, dir, write, read: true, path: abs.to_vec() },
                pos: 0,
                append: false,
                nonblock: false,
                listing: None,
            })
        }
        Err(e) => {
            if !write && (abs.starts_with(b"/lib/") || abs.starts_with(b"/lib64/") || abs.starts_with(b"/usr/lib/")) {
                // Also try `app_dir/<leaf>` (for sibling `.so` files in `/esp/DOS/APPS`, including
                // FAT32 uppercase names).
                if let (Some(ad), Some(leaf)) = (path::app_dir(), abs.rsplit(|&c| c == b'/').next()) {
                    let p = path::join_abs(ad.as_bytes(), leaf);
                    if let Ok((node, kind, _)) = path::open(&p, 0, fp::R_READ)
                        && kind != fp::KIND_DIR
                    {
                        return Ok(Open {
                            kind: Kind::File { node, dir: false, write: false, read: true, path: abs.to_vec() },
                            pos: 0,
                            append: false,
                            nonblock: false,
                            listing: None,
                        });
                    }
                    let upper: Vec<u8> = leaf.iter().map(u8::to_ascii_uppercase).collect();
                    let pu = path::join_abs(ad.as_bytes(), &upper);
                    if let Ok((node, kind, _)) = path::open(&pu, 0, fp::R_READ)
                        && kind != fp::KIND_DIR
                    {
                        return Ok(Open {
                            kind: Kind::File { node, dir: false, write: false, read: true, path: abs.to_vec() },
                            pos: 0,
                            append: false,
                            nonblock: false,
                            listing: None,
                        });
                    }
                }
                // Embedded `.so` VMO fallback (for `utest`).
                if let Some(bytes) = try_embedded_lib(abs) {
                    return Ok(Open::synth_file(bytes, abs.to_vec()));
                }
            }
            Err(errno(e))
        }
    }
}

fn open(s: &mut Server, dirfd: i64, addr: u64, flags: u64) -> i64 {
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_CREAT: u64 = 0x40;
    const O_EXCL: u64 = 0x80;
    const O_TRUNC: u64 = 0x200;
    const O_APPEND: u64 = 0x400;
    const O_NONBLOCK: u64 = 0x800;
    const O_DIRECTORY: u64 = 0x1_0000;
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if vfs::is_synthetic(&abs) {
        return match vfs::open(s, &abs, flags) {
            Ok(mut o) => {
                o.nonblock = flags & O_NONBLOCK != 0;
                s.fds.add_at(Rc::new(RefCell::new(o)), 0)
            }
            Err(e) => e,
        };
    }
    let acc = flags & 3;
    let write = acc == O_WRONLY || acc == O_RDWR;
    let mut of = 0;
    if flags & O_CREAT != 0 {
        of |= fp::O_CREATE;
    }
    if flags & O_EXCL != 0 {
        of |= fp::O_EXCL;
    }
    if flags & O_TRUNC != 0 && write {
        of |= fp::O_TRUNCATE;
    }
    if flags & O_DIRECTORY != 0 {
        of |= fp::O_DIRECTORY;
    }
    let rights = fp::R_READ | if write { fp::R_WRITE } else { 0 };
    match open_real_or_lib(&abs, of, rights, write) {
        Ok(mut o) => {
            if let Kind::File { dir, ref mut read, .. } = o.kind {
                if flags & O_DIRECTORY != 0 && !dir {
                    return -ENOTDIR;
                }
                *read = acc != O_WRONLY;
            }
            o.append = flags & O_APPEND != 0;
            o.nonblock = flags & O_NONBLOCK != 0;
            s.fds.add_at(Rc::new(RefCell::new(o)), 0)
        }
        Err(e) => e,
    }
}

/// `struct stat` (x86-64, 144 bytes).
pub fn stat_buf(kind: u64, size: u64, modified: i64, created: i64, ino: u64) -> [u8; 144] {
    let mut b = [0u8; 144];
    let mut put = |o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put(0, 0x0D05); // st_dev
    put(8, ino);
    put(16, 1); // st_nlink
    let mode: u32 = match kind {
        fp::KIND_DIR => 0o040_755,
        0 => 0o020_666, // character device
        _ => 0o100_644,
    };
    put(48, size);
    put(56, 4096);
    put(64, size.div_ceil(512));
    let unix = |t: i64| t.div_euclid(1_000_000_000) + UNIX_2000;
    put(72, unix(modified) as u64);
    put(88, unix(modified) as u64);
    put(104, unix(created) as u64);
    b[24..28].copy_from_slice(&mode.to_le_bytes());
    b[28..32].copy_from_slice(&1000u32.to_le_bytes());
    b[32..36].copy_from_slice(&1000u32.to_le_bytes());
    b
}

fn stat_node(n: &Node) -> Result<[u8; 144], i64> {
    let st = n.stat().map_err(errno)?;
    Ok(stat_buf(st.kind, st.size, st.modified, st.created, 2 + (n.ch as u64)))
}

fn fstat_bytes(s: &Server, fd: u64) -> Result<[u8; 144], i64> {
    let o = s.fds.get(fd).ok_or(-EBADF)?;
    match &o.borrow().kind {
        Kind::Stdin | Kind::Stdout | Kind::DevNull | Kind::DevZero | Kind::DevUrandom | Kind::DevFull => Ok(stat_buf(0, 0, 0, 0, 1)),
        Kind::PipeRead(_) | Kind::PipeWrite(_) => {
            let mut b = stat_buf(0, 0, 0, 0, 0x2000 + fd);
            b[24..28].copy_from_slice(&0o010_600u32.to_le_bytes()); // S_IFIFO
            Ok(b)
        }
        Kind::SynthFile { data, .. } => Ok(stat_buf(fp::KIND_FILE, data.len() as u64, 0, 0, 0x3000 + fd)),
        Kind::SynthDir { .. } => Ok(stat_buf(fp::KIND_DIR, 0, 0, 0, 0x3000 + fd)),
        Kind::File { node, .. } => stat_node(node),
    }
}

fn fstat(s: &Server, fd: u64, out: u64) -> i64 {
    match fstat_bytes(s, fd) {
        Ok(b) => if s.mem.write(out, &b) { 0 } else { -EFAULT },
        Err(e) => e,
    }
}

fn stat_path_bytes(s: &Server, dirfd: i64, addr: u64, flags: u64, lstat: bool) -> Result<[u8; 144], i64> {
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    if flags & AT_EMPTY_PATH != 0 && s.mem.cstr(addr, 1).is_some_and(|p| p.is_empty()) {
        return fstat_bytes(s, dirfd as u64);
    }
    let abs = path_arg(s, dirfd, addr)?;
    if vfs::is_synthetic(&abs) {
        return vfs::stat(s, &abs, lstat || (flags & AT_SYMLINK_NOFOLLOW != 0));
    }
    match open_real_or_lib(&abs, 0, fp::R_READ, false) {
        Ok(o) => match &o.kind {
            Kind::File { node, .. } => stat_node(node),
            Kind::SynthFile { data, .. } => Ok(stat_buf(fp::KIND_FILE, data.len() as u64, 0, 0, 0x6000)),
            _ => Err(-ENOENT),
        },
        Err(e) => Err(e),
    }
}

fn stat_path(s: &Server, dirfd: i64, addr: u64, out: u64, flags: u64, lstat: bool) -> i64 {
    match stat_path_bytes(s, dirfd, addr, flags, lstat) {
        Ok(b) => if s.mem.write(out, &b) { 0 } else { -EFAULT },
        Err(e) => e,
    }
}

/// `statx(dirfd, pathname, flags, mask, statxbuf)` -> 256-byte `struct statx`.
fn statx(s: &Server, dirfd: i64, addr: u64, flags: u64, out: u64) -> i64 {
    let st = match stat_path_bytes(s, dirfd, addr, flags, false) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let u32_at = |o: usize| u32::from_le_bytes(st[o..o + 4].try_into().unwrap_or([0; 4]));
    let u64_at = |o: usize| u64::from_le_bytes(st[o..o + 8].try_into().unwrap_or([0; 8]));
    let mut x = [0u8; 256];
    let mode = u32_at(24) as u16;
    let size = u64_at(48);
    let ino = u64_at(8);
    let mtime = u64_at(88);
    x[0..4].copy_from_slice(&0x07FFu32.to_le_bytes()); // STATX_BASIC_STATS
    x[4..8].copy_from_slice(&4096u32.to_le_bytes()); // stx_blksize
    x[16..20].copy_from_slice(&1u32.to_le_bytes()); // stx_nlink
    x[20..24].copy_from_slice(&1000u32.to_le_bytes()); // stx_uid
    x[24..28].copy_from_slice(&1000u32.to_le_bytes()); // stx_gid
    x[28..30].copy_from_slice(&mode.to_le_bytes()); // stx_mode
    x[32..40].copy_from_slice(&ino.to_le_bytes()); // stx_ino
    x[40..48].copy_from_slice(&size.to_le_bytes()); // stx_size
    x[48..56].copy_from_slice(&size.div_ceil(512).to_le_bytes()); // stx_blocks
    x[64..72].copy_from_slice(&mtime.to_le_bytes()); // stx_atime.tv_sec
    x[96..104].copy_from_slice(&mtime.to_le_bytes()); // stx_ctime.tv_sec
    x[112..120].copy_from_slice(&mtime.to_le_bytes()); // stx_mtime.tv_sec
    if s.mem.write(out, &x) { 0 } else { -EFAULT }
}

/// Read a file descriptor's bytes at `off` into D-CMPL's own buffer (mmap of a file).
pub fn read_at(s: &Server, fd: u64, off: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let o = s.fds.get(fd).ok_or(-EBADF)?;
    let o = o.borrow();
    match &o.kind {
        Kind::File { node, dir: false, read: true, .. } => node.read(off, buf).map_err(errno),
        Kind::SynthFile { data, .. } => {
            if off as usize >= data.len() {
                return Ok(0);
            }
            let n = (data.len() - off as usize).min(buf.len());
            buf[..n].copy_from_slice(&data[off as usize..off as usize + n]);
            Ok(n)
        }
        _ => Err(-EBADF),
    }
}

fn read(s: &Server, fd: u64, buf: u64, len: u64, at: Option<u64>) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    let mut o = o.borrow_mut();
    let pos = at.unwrap_or(o.pos);
    let n = len.min(1 << 20) as usize;
    let got = match &o.kind {
        Kind::Stdin | Kind::DevNull => return 0,
        Kind::Stdout | Kind::PipeWrite(_) => return -EBADF,
        Kind::File { dir: true, .. } | Kind::SynthDir { .. } => return -EISDIR,
        Kind::File { read: false, .. } => return -EBADF,
        Kind::DevZero | Kind::DevFull => {
            let b = alloc::vec![0u8; n];
            if !s.mem.write(buf, &b) {
                return -EFAULT;
            }
            return n as i64;
        }
        Kind::DevUrandom => {
            let mut b = alloc::vec![0u8; n];
            super::random_bytes(&mut b);
            if !s.mem.write(buf, &b) {
                return -EFAULT;
            }
            return n as i64;
        }
        Kind::PipeRead(p) => {
            if at.is_some() {
                return -ESPIPE;
            }
            let mut g = p.borrow_mut();
            if g.buf.is_empty() {
                return if g.writers == 0 { 0 } else { -EAGAIN };
            }
            let take = n.min(g.buf.len());
            let mut b = Vec::with_capacity(take);
            for _ in 0..take {
                if let Some(byte) = g.buf.pop_front() {
                    b.push(byte);
                }
            }
            if !s.mem.write(buf, &b) {
                return -EFAULT;
            }
            return b.len() as i64;
        }
        Kind::SynthFile { data, .. } => {
            if pos as usize >= data.len() {
                0
            } else {
                let take = (data.len() - pos as usize).min(n);
                if !s.mem.write(buf, &data[pos as usize..pos as usize + take]) {
                    return -EFAULT;
                }
                take
            }
        }
        Kind::File { node, .. } => {
            let mut b = alloc::vec![0u8; n];
            match node.read(pos, &mut b) {
                Ok(got) => {
                    if !s.mem.write(buf, &b[..got]) {
                        return -EFAULT;
                    }
                    got
                }
                Err(e) => return errno(e),
            }
        }
    };
    if at.is_none() {
        o.pos += got as u64;
    }
    got as i64
}

fn write(s: &Server, fd: u64, buf: u64, len: u64, at: Option<u64>) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    let n = len.min(1 << 20) as usize;
    let mut b = alloc::vec![0u8; n];
    if !s.mem.read(buf, &mut b) {
        return -EFAULT;
    }
    let mut o = o.borrow_mut();
    let append = o.append;
    let mut pos = at.unwrap_or(o.pos);
    let w = match &o.kind {
        Kind::Stdout => {
            out::write(&b);
            return n as i64;
        }
        Kind::DevNull | Kind::DevZero | Kind::DevUrandom => return n as i64,
        Kind::DevFull => return -ENOSPC,
        Kind::PipeWrite(p) => {
            if at.is_some() {
                return -ESPIPE;
            }
            let mut g = p.borrow_mut();
            if g.readers == 0 {
                return -EPIPE;
            }
            let space = PIPE_CAP.saturating_sub(g.buf.len());
            if space == 0 && !b.is_empty() {
                return -EAGAIN;
            }
            let take = b.len().min(space);
            g.buf.extend(&b[..take]);
            return take as i64;
        }
        Kind::Stdin | Kind::PipeRead(_) | Kind::SynthFile { .. } | Kind::SynthDir { .. } => return -EBADF,
        Kind::File { write: false, .. } | Kind::File { dir: true, .. } => return -EBADF,
        Kind::File { node, .. } => {
            if append && at.is_none() {
                pos = node.stat().map(|st| st.size).unwrap_or(pos);
            }
            match node.write(pos, &b) {
                Ok(w) => w,
                Err(e) => return errno(e),
            }
        }
    };
    if at.is_none() {
        o.pos = pos + w as u64;
    }
    w as i64
}

fn iov(s: &Server, fd: u64, iov: u64, cnt: u64, wr: bool) -> i64 {
    if cnt > 1024 {
        return -EINVAL;
    }
    let mut total = 0i64;
    for k in 0..cnt {
        let (Some(base), Some(len)) = (s.mem.u64(iov + 16 * k), s.mem.u64(iov + 16 * k + 8)) else { return -EFAULT };
        if len == 0 {
            continue;
        }
        let r = if wr { write(s, fd, base, len, None) } else { read(s, fd, base, len, None) };
        if r < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
        if (r as u64) < len {
            break;
        }
    }
    total
}

fn lseek(s: &Server, fd: u64, off: i64, whence: u64) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    let mut o = o.borrow_mut();
    let base = match (whence, &o.kind) {
        (_, Kind::Stdin | Kind::Stdout | Kind::PipeRead(_) | Kind::PipeWrite(_)) => return -ESPIPE,
        (_, Kind::DevNull | Kind::DevZero | Kind::DevUrandom | Kind::DevFull) => return 0,
        (0, _) => 0,
        (1, _) => o.pos as i64,
        (2, Kind::File { node, .. }) => match node.stat() {
            Ok(st) => st.size as i64,
            Err(e) => return errno(e),
        },
        (2, Kind::SynthFile { data, .. }) => data.len() as i64,
        _ => return -EINVAL,
    };
    match base.checked_add(off) {
        Some(n) if n >= 0 => {
            o.pos = n as u64;
            o.listing = None;
            n
        }
        _ => -EINVAL,
    }
}

fn getdents64(s: &Server, fd: u64, buf: u64, len: u64) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    let mut o = o.borrow_mut();
    if o.listing.is_none() {
        let v = match &o.kind {
            Kind::File { node, dir: true, .. } => {
                let mut v: Vec<(Vec<u8>, u64)> = alloc::vec![(b".".to_vec(), fp::KIND_DIR), (b"..".to_vec(), fp::KIND_DIR)];
                if let Err(e) = node.list(|n, k| v.push((n.to_vec(), k))) {
                    return errno(e);
                }
                v
            }
            Kind::SynthDir { entries, .. } => entries.clone(),
            _ => return -ENOTDIR,
        };
        o.listing = Some((v, 0));
    }
    let Some((v, next)) = o.listing.as_mut() else { return 0 };
    let mut out: Vec<u8> = Vec::new();
    while *next < v.len() {
        let (name, kind) = &v[*next];
        let reclen = (19 + name.len() + 1).div_ceil(8) * 8;
        if out.len() + reclen > len as usize {
            break;
        }
        let at = out.len();
        out.resize(at + reclen, 0);
        out[at..at + 8].copy_from_slice(&(*next as u64 + 1).to_le_bytes()); // d_ino
        out[at + 8..at + 16].copy_from_slice(&(*next as u64 + 1).to_le_bytes()); // d_off
        out[at + 16..at + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        out[at + 18] = if *kind == fp::KIND_DIR { 4 } else { 8 }; // DT_DIR, DT_REG
        out[at + 19..at + 19 + name.len()].copy_from_slice(name);
        *next += 1;
    }
    if out.is_empty() && *next < v.len() {
        return -EINVAL;
    }
    if s.mem.write(buf, &out) { out.len() as i64 } else { -EFAULT }
}

fn readlink_at(s: &Server, dirfd: i64, addr: u64, buf: u64, bufsz: u64) -> i64 {
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if !vfs::is_synthetic(&abs) {
        return -EINVAL;
    }
    match vfs::readlink(s, &abs) {
        Ok(target) => {
            let n = target.len().min(bufsz as usize);
            if s.mem.write(buf, &target[..n]) { n as i64 } else { -EFAULT }
        }
        Err(e) => e,
    }
}

fn pipe2(s: &mut Server, fds_ptr: u64, flags: u64) -> i64 {
    const O_NONBLOCK: u64 = 0x800;
    const O_CLOEXEC: u64 = 0x8_0000;
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return -EINVAL;
    }
    let st = Rc::new(RefCell::new(PipeState { buf: VecDeque::new(), writers: 1, readers: 1 }));
    let mut rd = Open::simple(Kind::PipeRead(Rc::clone(&st)));
    let mut wr = Open::simple(Kind::PipeWrite(st));
    rd.nonblock = flags & O_NONBLOCK != 0;
    wr.nonblock = flags & O_NONBLOCK != 0;
    let rfd = s.fds.add_at(Rc::new(RefCell::new(rd)), 0);
    if rfd < 0 {
        return rfd;
    }
    let wfd = s.fds.add_at(Rc::new(RefCell::new(wr)), 0);
    if wfd < 0 {
        s.fds.fds[rfd as usize] = None;
        return wfd;
    }
    let mut pair = [0u8; 8];
    pair[..4].copy_from_slice(&(rfd as i32).to_le_bytes());
    pair[4..8].copy_from_slice(&(wfd as i32).to_le_bytes());
    if !s.mem.write(fds_ptr, &pair) {
        s.fds.fds[rfd as usize] = None;
        s.fds.fds[wfd as usize] = None;
        return -EFAULT;
    }
    0
}

pub fn poll_once(s: &Server, fds_ptr: u64, nfds: u64) -> Result<i64, i64> {
    const POLLIN: i16 = 0x001;
    const POLLOUT: i16 = 0x004;
    const POLLHUP: i16 = 0x010;
    const POLLNVAL: i16 = 0x020;
    if nfds > 1024 {
        return Err(-EINVAL);
    }
    let mut ready = 0i64;
    for k in 0..nfds {
        let mut entry = [0u8; 8];
        if !s.mem.read(fds_ptr + 8 * k, &mut entry) {
            return Err(-EFAULT);
        }
        let fd = i32::from_le_bytes(entry[0..4].try_into().unwrap_or([0; 4]));
        let events = i16::from_le_bytes(entry[4..6].try_into().unwrap_or([0; 2]));
        let mut revents: i16 = 0;
        if fd >= 0 {
            match s.fds.get(fd as u64) {
                None => revents = POLLNVAL,
                Some(o) => match &o.borrow().kind {
                    Kind::PipeRead(p) => {
                        let g = p.borrow();
                        if !g.buf.is_empty() {
                            revents |= events & POLLIN;
                        }
                        if g.writers == 0 {
                            revents |= POLLHUP;
                        }
                    }
                    Kind::PipeWrite(p) => {
                        let g = p.borrow();
                        if g.readers == 0 {
                            revents |= POLLHUP;
                        } else if g.buf.len() < PIPE_CAP {
                            revents |= events & POLLOUT;
                        }
                    }
                    Kind::Stdin => {}
                    Kind::Stdout | Kind::DevNull | Kind::DevZero | Kind::DevUrandom | Kind::DevFull => {
                        revents |= events & (POLLIN | POLLOUT);
                    }
                    Kind::File { read, write, .. } => {
                        if *read {
                            revents |= events & POLLIN;
                        }
                        if *write {
                            revents |= events & POLLOUT;
                        }
                    }
                    Kind::SynthFile { .. } | Kind::SynthDir { .. } => {
                        revents |= events & POLLIN;
                    }
                },
            }
        }
        if revents != 0 {
            ready += 1;
        }
        entry[6..8].copy_from_slice(&revents.to_le_bytes());
        if !s.mem.write(fds_ptr + 8 * k, &entry) {
            return Err(-EFAULT);
        }
    }
    Ok(ready)
}

fn unlink(s: &Server, dirfd: i64, addr: u64, dir: bool) -> i64 {
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if vfs::is_synthetic(&abs) {
        return -EACCES;
    }
    let mapped = path::map_linux_path(&abs, false);
    if let Ok((_, kind, _)) = path::open(&mapped, 0, fp::R_READ) {
        if dir && kind != fp::KIND_DIR {
            return -ENOTDIR;
        }
        if !dir && kind == fp::KIND_DIR {
            return -EISDIR;
        }
    }
    match path::parent(&mapped, fp::R_READ | fp::R_WRITE).and_then(|(d, leaf)| d.unlink(&leaf)) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

fn mkdir(s: &Server, dirfd: i64, addr: u64) -> i64 {
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if vfs::is_synthetic(&abs) {
        return -EACCES;
    }
    let mapped = path::map_linux_path(&abs, false);
    match path::parent(&mapped, fp::R_READ | fp::R_WRITE).and_then(|(d, leaf)| d.open(&leaf, fp::O_CREATE | fp::O_EXCL | fp::O_DIRECTORY, fp::R_READ)) {
        Ok(_) => 0,
        Err(e) => errno(e),
    }
}

fn rename(s: &Server, d1: i64, a1: u64, d2: i64, a2: u64, flags: u64) -> i64 {
    let (from, to) = match (path_arg(s, d1, a1), path_arg(s, d2, a2)) {
        (Ok(f), Ok(t)) => (f, t),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if vfs::is_synthetic(&from) || vfs::is_synthetic(&to) {
        return -EACCES;
    }
    if flags & !1 != 0 {
        return -EINVAL;
    }
    let f = path::map_linux_path(&from, false);
    let t = path::map_linux_path(&to, false);
    match path::rename(&f, &t, flags & 1 == 0) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

fn truncate_fd(s: &Server, fd: u64, len: u64) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    let o = o.borrow();
    match &o.kind {
        Kind::File { node, write: true, .. } => node.truncate(len).map_or_else(errno, |_| 0),
        _ => -EINVAL,
    }
}

fn fcntl(s: &mut Server, fd: u64, cmd: u64, arg: u64) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    match cmd {
        0 | 1030 => s.fds.add_at(o, arg as usize), // F_DUPFD, F_DUPFD_CLOEXEC
        1 | 2 => 0,                                 // F_GETFD, F_SETFD
        3 => {
            let o = o.borrow();
            let acc = match &o.kind {
                Kind::Stdin | Kind::PipeRead(_) | Kind::SynthFile { .. } | Kind::SynthDir { .. } => 0,
                Kind::Stdout | Kind::PipeWrite(_) => 1,
                Kind::DevNull | Kind::DevZero | Kind::DevUrandom | Kind::DevFull => 2,
                Kind::File { read, write, .. } => match (read, write) {
                    (true, true) => 2,
                    (false, true) => 1,
                    _ => 0,
                },
            };
            acc | if o.append { 0x400 } else { 0 } | if o.nonblock { 0x800 } else { 0 }
        }
        4 => {
            let mut o = o.borrow_mut();
            o.append = arg & 0x400 != 0;
            o.nonblock = arg & 0x800 != 0;
            0
        }
        _ => -EINVAL,
    }
}

fn access_path(s: &Server, dirfd: i64, addr: u64) -> i64 {
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if vfs::is_synthetic(&abs) {
        return vfs::stat(s, &abs, false).map_or_else(|e| e, |_| 0);
    }
    open_real_or_lib(&abs, 0, fp::R_READ, false).map_or_else(|e| e, |_| 0)
}

pub fn syscall(s: &mut Server, nr: u64, r: &Regs) -> i64 {
    let (a0, a1, a2, a3, a4) = (r.rdi, r.rsi, r.rdx, r.r10, r.r8);
    match nr {
        0 => read(s, a0, a1, a2, None),
        1 => write(s, a0, a1, a2, None),
        17 => read(s, a0, a1, a2, Some(a3)),
        18 => write(s, a0, a1, a2, Some(a3)),
        19 => iov(s, a0, a1, a2, false),
        20 => iov(s, a0, a1, a2, true),
        2 => open(s, AT_FDCWD, a0, a1),
        257 => open(s, a0 as i64, a1, a2),
        3 => match s.fds.fds.get_mut(a0 as usize) {
            Some(slot @ Some(_)) => {
                *slot = None;
                0
            }
            _ => -EBADF,
        },
        4 => stat_path(s, AT_FDCWD, a0, a1, 0, false),
        6 => stat_path(s, AT_FDCWD, a0, a1, 0, true),
        5 => fstat(s, a0, a1),
        262 => stat_path(s, a0 as i64, a1, a2, a3, false),
        332 => statx(s, a0 as i64, a1, a2, a4),
        8 => lseek(s, a0, a1 as i64, a2),
        16 => match s.fds.get(a0) {
            Some(_) => -ENOTTY,
            None => -EBADF,
        },
        21 => access_path(s, AT_FDCWD, a0),
        269 | 439 => access_path(s, a0 as i64, a1),
        22 => pipe2(s, a0, 0),
        293 => pipe2(s, a0, a1),
        32 => match s.fds.get(a0) {
            Some(o) => s.fds.add_at(o, 0),
            None => -EBADF,
        },
        33 | 292 => {
            let Some(o) = s.fds.get(a0) else { return -EBADF };
            if a1 as usize >= MAX_FDS {
                return -EBADF;
            }
            if a0 == a1 {
                return if nr == 292 { -EINVAL } else { a1 as i64 };
            }
            if a1 as usize >= s.fds.fds.len() {
                s.fds.fds.resize(a1 as usize + 1, None);
            }
            s.fds.fds[a1 as usize] = Some(o);
            a1 as i64
        }
        72 => fcntl(s, a0, a1, a2),
        74 | 75 => match s.fds.get(a0) {
            Some(o) => match &o.borrow().kind {
                Kind::File { node, write: true, .. } => node.sync().map_or_else(errno, |_| 0),
                _ => 0,
            },
            None => -EBADF,
        },
        76 => match path_arg(s, AT_FDCWD, a0) {
            Ok(abs) => {
                let mapped = path::map_linux_path(&abs, false);
                match path::open(&mapped, 0, fp::R_READ | fp::R_WRITE) {
                    Ok((n, _, _)) => n.truncate(a1).map_or_else(errno, |_| 0),
                    Err(e) => errno(e),
                }
            }
            Err(e) => e,
        },
        77 => truncate_fd(s, a0, a1),
        79 => {
            let mut c = path::cwd().into_bytes();
            c.push(0);
            if (a1 as usize) < c.len() {
                -ERANGE
            } else if s.mem.write(a0, &c) {
                c.len() as i64
            } else {
                -EFAULT
            }
        }
        80 => match path_arg(s, AT_FDCWD, a0) {
            Ok(abs) => path::set_cwd(&path::map_linux_path(&abs, false)).map_or_else(errno, |_| 0),
            Err(e) => e,
        },
        81 => match s.fds.get(a0) {
            Some(o) => match &o.borrow().kind {
                Kind::File { dir: true, path, .. } => path::set_cwd(path).map_or_else(errno, |_| 0),
                _ => -ENOTDIR,
            },
            None => -EBADF,
        },
        82 => rename(s, AT_FDCWD, a0, AT_FDCWD, a1, 0),
        264 => rename(s, a0 as i64, a1, a2 as i64, a3, 0),
        316 => rename(s, a0 as i64, a1, a2 as i64, a3, a4),
        83 => mkdir(s, AT_FDCWD, a0),
        258 => mkdir(s, a0 as i64, a1),
        84 => unlink(s, AT_FDCWD, a0, true),
        87 => unlink(s, AT_FDCWD, a0, false),
        263 => unlink(s, a0 as i64, a1, a2 & 0x200 != 0),
        89 => readlink_at(s, AT_FDCWD, a0, a1, a2),
        267 => readlink_at(s, a0 as i64, a1, a2, a3),
        137 | 138 => {
            // statfs / fstatfs: synthetic 120-byte struct statfs
            let mut b = [0u8; 120];
            b[0..8].copy_from_slice(&0x0D05_0001u64.to_le_bytes()); // f_type
            b[8..16].copy_from_slice(&4096u64.to_le_bytes()); // f_bsize
            b[16..24].copy_from_slice(&32768u64.to_le_bytes()); // f_blocks
            b[24..32].copy_from_slice(&16384u64.to_le_bytes()); // f_bfree
            b[32..40].copy_from_slice(&16384u64.to_le_bytes()); // f_bavail
            b[64..72].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
            if s.mem.write(a1, &b) { 0 } else { -EFAULT }
        }
        217 => getdents64(s, a0, a1, a2),
        _ => -ENOSYS,
    }
}
