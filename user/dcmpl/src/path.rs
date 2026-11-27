//! Paths of a foreign program, resolved through this process's namespace only.
//!
//! D-OS paths are absolute (`/data/notes/a.txt`) and reach nothing outside the namespace the
//! spawner granted. The working directory starts at the first namespace entry (the place `run`
//! was typed in). An optional explicit per-app namespace prefix (`--prefix <dir>`) scopes
//! Windows `C:\...` / `drive_c/...` paths and Linux root-relative library/runtime lookups
//! (`/lib64/...`, `/usr/lib/...`, `/etc/...`) inside that prefix while still refusing any access
//! outside the granted namespace handles.

use alloc::string::String;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

use libd::fs::{self as fp, Namespace, Node};
use libd::sync::Mutex;
use libd::sys;

static CWD: Mutex<String> = Mutex::new(String::new());
static PREFIX: Mutex<Option<String>> = Mutex::new(None);
static APP_DIR: Mutex<Option<String>> = Mutex::new(None);

pub fn init() {
    let ns = Namespace::get();
    let first = ns.entries().next().map(|(p, _)| String::from_utf8_lossy(p).into_owned());
    *CWD.lock() = first.unwrap_or_else(|| String::from("/"));
}

pub fn set_prefix(p: &[u8]) {
    if p.is_empty() {
        return;
    }
    let abs = absolute(p);
    *PREFIX.lock() = Some(String::from_utf8_lossy(&abs).into_owned());
}

pub fn prefix() -> Option<String> {
    PREFIX.lock().clone()
}

pub fn set_app_dir(p: &[u8]) {
    if p.is_empty() {
        return;
    }
    let abs = absolute(p);
    *APP_DIR.lock() = Some(String::from_utf8_lossy(&abs).into_owned());
}

pub fn app_dir() -> Option<String> {
    APP_DIR.lock().clone()
}

pub fn cwd() -> String {
    CWD.lock().clone()
}

/// Join two absolute/relative path components and normalize `.` / `..`.
pub fn join_abs(base: &[u8], rel: &[u8]) -> Vec<u8> {
    let mut full = Vec::with_capacity(base.len() + 1 + rel.len());
    full.extend_from_slice(base);
    full.push(b'/');
    full.extend_from_slice(rel);
    absolute(&full)
}

/// Map a Windows drive-rooted path (`rel`, starting with `/`) through the active prefix if one is
/// set. If `rel` already targets an explicitly granted namespace mount (e.g. `/data/...`), it is
/// kept as-is; otherwise under `--prefix <dir>`, `/foo` maps to `<prefix>/drive_c/foo` when
/// `<prefix>/drive_c` exists, else `<prefix>/foo`.
pub fn map_win_rooted(rel: &[u8]) -> Vec<u8> {
    let norm = absolute(rel);
    let ns = Namespace::get();
    if ns.resolve(&norm).is_some() {
        return norm;
    }
    if let Some(pfx) = prefix() {
        let drive_c = join_abs(pfx.as_bytes(), b"drive_c");
        let base = if open(&drive_c, fp::O_DIRECTORY, fp::R_READ).is_ok() {
            drive_c
        } else {
            pfx.into_bytes()
        };
        return join_abs(&base, norm.trim_ascii_start().strip_prefix(b"/").unwrap_or(&norm));
    }
    norm
}

/// Map an absolute Linux path through the active prefix if one is set: prefers `<prefix><abs>`
/// when `<prefix>` is active and the path is not already inside `<prefix>` or a direct namespace
/// hit for writing; for reads falls back to `<abs>`.
pub fn map_linux_path(abs: &[u8], prefer_prefix: bool) -> Vec<u8> {
    let norm = absolute(abs);
    if let Some(pfx) = prefix() {
        let pb = pfx.as_bytes();
        let already_in_pfx = norm.starts_with(pb) && (norm.len() == pb.len() || norm[pb.len()] == b'/');
        if !already_in_pfx {
            let under = join_abs(pb, norm.strip_prefix(b"/").unwrap_or(&norm));
            if prefer_prefix {
                if open(&under, 0, fp::R_READ).is_ok() {
                    return under;
                }
                if Namespace::get().resolve(&norm).is_none() {
                    return under;
                }
            } else if Namespace::get().resolve(&norm).is_none() {
                return under;
            }
        }
    }
    norm
}

/// Read an entire file from the namespace (at most `max` bytes).
pub fn read_file(abs: &[u8], max: usize) -> Result<Vec<u8>, i64> {
    let (node, kind, size) = open(abs, 0, fp::R_READ)?;
    if kind != fp::KIND_FILE {
        return Err(fp::ERR_IS_DIR);
    }
    let sz = usize::try_from(size).map_err(|_| sys::ERR_OUT_OF_RANGE)?;
    if sz == 0 || sz > max {
        return Err(sys::ERR_OUT_OF_RANGE);
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(sz).map_err(|_| sys::ERR_NO_MEMORY)?;
    buf.resize(sz, 0);
    let got = node.read(0, &mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// `p` made absolute against the working directory, `.` and `..` worked out (never above `/`).
pub fn absolute(p: &[u8]) -> Vec<u8> {
    let mut full: Vec<u8> = Vec::new();
    if !p.starts_with(b"/") {
        full.extend_from_slice(CWD.lock().as_bytes());
        full.push(b'/');
    }
    full.extend_from_slice(p);
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in full.split(|&c| c == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut s = Vec::new();
    for c in parts {
        s.push(b'/');
        s.extend_from_slice(c);
    }
    if s.is_empty() {
        s.push(b'/');
    }
    s
}

/// A node handle we hold, used without giving it up.
fn borrow(h: sys::Handle) -> ManuallyDrop<Node> {
    ManuallyDrop::new(Node::from(h))
}

/// Open absolute path `abs`: (node, kind, size). Outside the namespace: `ACCESS_DENIED`.
pub fn open(abs: &[u8], flags: u64, rights: u64) -> Result<(Node, u64, u64), i64> {
    let ns = Namespace::get();
    let (dir, rest) = ns.resolve(abs).ok_or(sys::ERR_ACCESS_DENIED)?;
    let d = borrow(dir);
    if rest.is_empty() {
        let n = d.clone_with(rights)?;
        let st = n.stat()?;
        return Ok((n, st.kind, st.size));
    }
    d.open(rest, flags, rights)
}

/// The directory holding `abs` (opened with `rights`) and the last name in it.
pub fn parent(abs: &[u8], rights: u64) -> Result<(Node, Vec<u8>), i64> {
    let ns = Namespace::get();
    let (dir, rest) = ns.resolve(abs).ok_or(sys::ERR_ACCESS_DENIED)?;
    if rest.is_empty() {
        return Err(sys::ERR_ACCESS_DENIED); // a granted directory itself is not removed or renamed
    }
    let d = borrow(dir);
    match rest.iter().rposition(|&c| c == b'/') {
        None => Ok((d.clone_with(rights)?, rest.to_vec())),
        Some(i) => {
            let (n, kind, _) = d.open(&rest[..i], fp::O_DIRECTORY, rights)?;
            if kind != fp::KIND_DIR {
                return Err(fp::ERR_NOT_DIR);
            }
            Ok((n, rest[i + 1..].to_vec()))
        }
    }
}

/// Change the working directory to `abs` (must be a directory in the namespace).
pub fn set_cwd(abs: &[u8]) -> Result<(), i64> {
    let (_, kind, _) = open(abs, fp::O_DIRECTORY, fp::R_READ)?;
    if kind != fp::KIND_DIR {
        return Err(fp::ERR_NOT_DIR);
    }
    *CWD.lock() = String::from_utf8_lossy(abs).into_owned();
    Ok(())
}

/// Rename `from` to `to` (absolute): both must be in the same granted directory.
pub fn rename(from: &[u8], to: &[u8], replace: bool) -> Result<(), i64> {
    let ns = Namespace::get();
    let (d1, r1) = ns.resolve(from).ok_or(sys::ERR_ACCESS_DENIED)?;
    let (d2, r2) = ns.resolve(to).ok_or(sys::ERR_ACCESS_DENIED)?;
    if d1 != d2 {
        return Err(sys::ERR_NOT_SUPPORTED); // across granted directories: copy and delete instead
    }
    if r1.is_empty() || r2.is_empty() {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    borrow(d1).rename(r1, r2, replace)
}
