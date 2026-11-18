//! Paths of a foreign program, resolved through this process's namespace only.
//!
//! D-OS paths are absolute (`/data/notes/a.txt`) and reach nothing outside the namespace the
//! spawner granted. The working directory starts at the first namespace entry (the place `run`
//! was typed in). Each personality maps its own syntax onto this first (Windows: `\` is `/`, a
//! drive letter is dropped; Linux: as it is).

use alloc::string::String;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

use libd::fs::{self as fp, Namespace, Node};
use libd::sync::Mutex;
use libd::sys;

static CWD: Mutex<String> = Mutex::new(String::new());

pub fn init() {
    let ns = Namespace::get();
    let first = ns.entries().next().map(|(p, _)| String::from_utf8_lossy(p).into_owned());
    *CWD.lock() = first.unwrap_or_else(|| String::from("/"));
}

pub fn cwd() -> String {
    CWD.lock().clone()
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
