//! Linux file descriptors over the namespace: 0, 1, 2 are the console (standard input is empty,
//! output goes to `out.rs`), the rest are files and directories opened through `path.rs`. A
//! descriptor shares its offset with its `dup`s (one open file description). Paths: absolute, or
//! relative to the working directory or to a directory descriptor (`*at`). No symbolic links,
//! no pipes, no devices.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use libd::fs::{self as fp, Node};
use libd::sys::{self, Regs};

use super::*;
use crate::{out, path};

pub enum Kind {
    Stdin,
    Stdout,
    File { node: Node, dir: bool, write: bool, read: bool, path: Vec<u8> },
}

pub struct Open {
    pub kind: Kind,
    pub pos: u64,
    pub append: bool,
    /// getdents64: the directory's entries, read once, and how many were returned.
    pub listing: Option<Listing>,
}

/// A directory's entries (name, kind) and how many were returned.
pub type Listing = (Vec<(Vec<u8>, u64)>, usize);

pub struct Fds {
    fds: Vec<Option<Rc<RefCell<Open>>>>,
}

const MAX_FDS: usize = 1024;
const AT_FDCWD: i64 = -100;

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
        let o = |k| Some(Rc::new(RefCell::new(Open { kind: k, pos: 0, append: false, listing: None })));
        Fds { fds: alloc::vec![o(Kind::Stdin), o(Kind::Stdout), o(Kind::Stdout)] }
    }
    fn get(&self, fd: u64) -> Option<Rc<RefCell<Open>>> {
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
        Kind::File { dir: true, path, .. } => {
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

fn open(s: &mut Server, dirfd: i64, addr: u64, flags: u64) -> i64 {
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_CREAT: u64 = 0x40;
    const O_EXCL: u64 = 0x80;
    const O_TRUNC: u64 = 0x200;
    const O_APPEND: u64 = 0x400;
    const O_DIRECTORY: u64 = 0x1_0000;
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
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
    match path::open(&abs, of, rights) {
        Ok((node, kind, _)) => {
            let dir = kind == fp::KIND_DIR;
            if dir && write {
                return -EISDIR;
            }
            if flags & O_DIRECTORY != 0 && !dir {
                return -ENOTDIR;
            }
            let o = Open { kind: Kind::File { node, dir, write, read: acc != O_WRONLY, path: abs }, pos: 0, append: flags & O_APPEND != 0, listing: None };
            s.fds.add_at(Rc::new(RefCell::new(o)), 0)
        }
        Err(e) => errno(e),
    }
}

/// `struct stat` (x86-64, 144 bytes).
fn stat_buf(kind: u64, size: u64, modified: i64, created: i64, ino: u64) -> [u8; 144] {
    let mut b = [0u8; 144];
    let mut put = |o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put(0, 0x0D05); // st_dev
    put(8, ino);
    put(16, 1); // st_nlink
    let mode: u32 = match kind {
        fp::KIND_DIR => 0o040_755,
        0 => 0o020_620, // the console: a character device
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

fn fstat(s: &Server, fd: u64, out: u64) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    let b = match &o.borrow().kind {
        Kind::Stdin | Kind::Stdout => stat_buf(0, 0, 0, 0, 1),
        Kind::File { node, .. } => match stat_node(node) {
            Ok(b) => b,
            Err(e) => return e,
        },
    };
    if s.mem.write(out, &b) { 0 } else { -EFAULT }
}

fn stat_path(s: &Server, dirfd: i64, addr: u64, out: u64, flags: u64) -> i64 {
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & AT_EMPTY_PATH != 0 && s.mem.cstr(addr, 1).is_some_and(|p| p.is_empty()) {
        return fstat(s, dirfd as u64, out);
    }
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let b = match path::open(&abs, 0, fp::R_READ) {
        Ok((n, _, _)) => match stat_node(&n) {
            Ok(b) => b,
            Err(e) => return e,
        },
        Err(e) => return errno(e),
    };
    if s.mem.write(out, &b) { 0 } else { -EFAULT }
}

/// Read a file descriptor's bytes at `off` into D-CMPL's own buffer (mmap of a file).
pub fn read_at(s: &Server, fd: u64, off: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let o = s.fds.get(fd).ok_or(-EBADF)?;
    let o = o.borrow();
    match &o.kind {
        Kind::File { node, dir: false, read: true, .. } => node.read(off, buf).map_err(errno),
        _ => Err(-EBADF),
    }
}

fn read(s: &Server, fd: u64, buf: u64, len: u64, at: Option<u64>) -> i64 {
    let Some(o) = s.fds.get(fd) else { return -EBADF };
    let mut o = o.borrow_mut();
    let pos = at.unwrap_or(o.pos);
    let got = match &o.kind {
        Kind::Stdin => return 0,
        Kind::Stdout => return -EBADF,
        Kind::File { dir: true, .. } => return -EISDIR,
        Kind::File { read: false, .. } => return -EBADF,
        Kind::File { node, .. } => {
            let n = len.min(1 << 20) as usize;
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
        Kind::Stdin => return -EBADF,
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
        (_, Kind::Stdin | Kind::Stdout) => return -ESPIPE,
        (0, _) => 0,
        (1, _) => o.pos as i64,
        (2, Kind::File { node, .. }) => match node.stat() {
            Ok(st) => st.size as i64,
            Err(e) => return errno(e),
        },
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
    let Kind::File { node, dir: true, .. } = &o.kind else { return -ENOTDIR };
    if o.listing.is_none() {
        let mut v: Vec<(Vec<u8>, u64)> = alloc::vec![(b".".to_vec(), fp::KIND_DIR), (b"..".to_vec(), fp::KIND_DIR)];
        if let Err(e) = node.list(|n, k| v.push((n.to_vec(), k))) {
            return errno(e);
        }
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
        return -EINVAL; // the buffer cannot hold one entry
    }
    if s.mem.write(buf, &out) { out.len() as i64 } else { -EFAULT }
}

fn unlink(s: &Server, dirfd: i64, addr: u64, dir: bool) -> i64 {
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if let Ok((_, kind, _)) = path::open(&abs, 0, fp::R_READ) {
        if dir && kind != fp::KIND_DIR {
            return -ENOTDIR;
        }
        if !dir && kind == fp::KIND_DIR {
            return -EISDIR;
        }
    }
    match path::parent(&abs, fp::R_READ | fp::R_WRITE).and_then(|(d, leaf)| d.unlink(&leaf)) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

fn mkdir(s: &Server, dirfd: i64, addr: u64) -> i64 {
    let abs = match path_arg(s, dirfd, addr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match path::parent(&abs, fp::R_READ | fp::R_WRITE).and_then(|(d, leaf)| d.open(&leaf, fp::O_CREATE | fp::O_EXCL | fp::O_DIRECTORY, fp::R_READ)) {
        Ok(_) => 0,
        Err(e) => errno(e),
    }
}

fn rename(s: &Server, d1: i64, a1: u64, d2: i64, a2: u64, flags: u64) -> i64 {
    let (from, to) = match (path_arg(s, d1, a1), path_arg(s, d2, a2)) {
        (Ok(f), Ok(t)) => (f, t),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if flags & !1 != 0 {
        return -EINVAL; // RENAME_EXCHANGE, RENAME_WHITEOUT
    }
    match path::rename(&from, &to, flags & 1 == 0) {
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
        1 | 2 => 0,                                 // F_GETFD, F_SETFD (no exec: CLOEXEC means nothing)
        3 => {
            let o = o.borrow();
            let acc = match &o.kind {
                Kind::Stdin => 0,
                Kind::Stdout => 1,
                Kind::File { read, write, .. } => match (read, write) {
                    (true, true) => 2,
                    (false, true) => 1,
                    _ => 0,
                },
            };
            acc | if o.append { 0x400 } else { 0 }
        }
        4 => {
            o.borrow_mut().append = arg & 0x400 != 0;
            0
        }
        _ => -EINVAL,
    }
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
        4 | 6 => stat_path(s, AT_FDCWD, a0, a1, 0),
        5 => fstat(s, a0, a1),
        262 => stat_path(s, a0 as i64, a1, a2, a3),
        8 => lseek(s, a0, a1 as i64, a2),
        16 => match s.fds.get(a0) {
            Some(_) => -ENOTTY, // no terminals: isatty() is false
            None => -EBADF,
        },
        21 | 269 => {
            // access(path, mode), faccessat(dirfd, path, mode, flags)
            let (d, p) = if nr == 21 { (AT_FDCWD, a0) } else { (a0 as i64, a1) };
            match path_arg(s, d, p) {
                Ok(abs) => path::open(&abs, 0, fp::R_READ).map_or_else(errno, |_| 0),
                Err(e) => e,
            }
        }
        32 => match s.fds.get(a0) {
            Some(o) => s.fds.add_at(o, 0),
            None => -EBADF,
        },
        33 | 292 => {
            // dup2(old, new), dup3(old, new, flags)
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
            // fsync, fdatasync
            Some(o) => match &o.borrow().kind {
                Kind::File { node, write: true, .. } => node.sync().map_or_else(errno, |_| 0),
                _ => 0,
            },
            None => -EBADF,
        },
        76 => match path_arg(s, AT_FDCWD, a0) {
            // truncate(path, len)
            Ok(abs) => match path::open(&abs, 0, fp::R_READ | fp::R_WRITE) {
                Ok((n, _, _)) => n.truncate(a1).map_or_else(errno, |_| 0),
                Err(e) => errno(e),
            },
            Err(e) => e,
        },
        77 => truncate_fd(s, a0, a1),
        79 => {
            // getcwd(buf, size): the length including the NUL
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
            Ok(abs) => path::set_cwd(&abs).map_or_else(errno, |_| 0),
            Err(e) => e,
        },
        81 => match s.fds.get(a0) {
            // fchdir
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
        89 | 267 => -ENOENT, // readlink, readlinkat: no symbolic links
        217 => getdents64(s, a0, a1, a2),
        439 => {
            // faccessat2
            match path_arg(s, a0 as i64, a1) {
                Ok(abs) => path::open(&abs, 0, fp::R_READ).map_or_else(errno, |_| 0),
                Err(e) => e,
            }
        }
        _ => -ENOSYS,
    }
}
