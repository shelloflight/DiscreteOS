//! Linux memory calls, served by mapping VMOs into the program's address space (its root VMAR,
//! from `process_vmar`).
//!
//! - `mmap`: anonymous memory (zeroed), or a private copy of a file's bytes; MAP_FIXED replaces
//!   what was there; a hint is tried, then anywhere. Executable memory only from a file, sealed
//!   with VMEX before it is mapped and never writable (W^X: PROT_WRITE|PROT_EXEC is refused,
//!   EACCES). MAP_SHARED is a private copy too (no shared file mappings).
//! - `PROT_NONE` mappings are reservations (nothing behind them); `mprotect` to readable or
//!   writable maps fresh zeroed memory into them (the pattern of thread stacks with guard
//!   pages). Elsewhere `mprotect` cannot change a mapping (the ABI has no such call): requests
//!   without PROT_EXEC are accepted and not enforced, PROT_EXEC is refused.
//! - `brk`: a 1 GiB reservation made on first use; the break grows and shrinks page by page.

use alloc::vec::Vec;

use libd::sys::{self, Handle};

use super::{EACCES, EINVAL, ENOMEM, Server};
use crate::{PAGE, USER_BASE, USER_TOP};

const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const BRK_SPAN: u64 = 1 << 30;

#[derive(Default)]
pub struct Mm {
    /// PROT_NONE reservations: (base, length, region handle).
    regions: Vec<(u64, u64, Handle)>,
    /// brk: the reservation, its base, the break, and how far it is mapped.
    brk_region: Handle,
    brk_base: u64,
    brk: u64,
    brk_mapped: u64,
}

fn perms(prot: u64) -> u32 {
    let mut p = sys::RIGHT_READ; // nothing is write- or execute-only
    if prot & PROT_WRITE != 0 {
        p |= sys::RIGHT_WRITE;
    }
    if prot & PROT_EXEC != 0 {
        p |= sys::RIGHT_EXECUTE;
    }
    p
}

/// A VMO of `len` bytes: zeroed, or the file's bytes from `off`.
fn backing(s: &Server, len: u64, fd: i64, off: u64, prot: u64) -> Result<Handle, i64> {
    let v = sys::vmo_create(len).map_err(|_| -ENOMEM)?;
    if fd >= 0 {
        let mut buf = alloc::vec![0u8; 64 * 1024];
        let mut done = 0u64;
        while done < len {
            let want = ((len - done) as usize).min(buf.len());
            let got = match super::fs::read_at(s, fd as u64, off + done, &mut buf[..want]) {
                Ok(g) => g,
                Err(e) => {
                    sys::handle_close(v);
                    return Err(e);
                }
            };
            if got == 0 {
                break;
            }
            sys::vmo_write(v, done, &buf[..got]);
            done += got as u64;
        }
    }
    if prot & PROT_EXEC != 0 {
        if fd < 0 {
            sys::handle_close(v);
            return Err(-EACCES); // anonymous executable memory (a JIT) needs W then X: not yet
        }
        return sys::vmo_make_executable(v, s.vmex).map_err(|_| {
            sys::handle_close(v);
            -EACCES
        });
    }
    Ok(v)
}

pub fn mmap(s: &mut Server, addr: u64, len: u64, prot: u64, flags: u64, fd: i64, off: u64) -> i64 {
    if len == 0 || !off.is_multiple_of(PAGE) {
        return -EINVAL;
    }
    let len = match len.checked_add(PAGE - 1) {
        Some(l) => l & !(PAGE - 1),
        None => return -ENOMEM,
    };
    if prot & PROT_WRITE != 0 && prot & PROT_EXEC != 0 {
        return -EACCES; // W^X
    }
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    if fixed && (!addr.is_multiple_of(PAGE) || addr < USER_BASE || addr.saturating_add(len) > USER_TOP) {
        return -EINVAL;
    }
    let anon = flags & MAP_ANONYMOUS != 0;
    if prot == 0 && anon && !fixed {
        // A reservation: nothing behind it until mprotect.
        return match sys::vmar_allocate(s.vmar, sys::ANY, len, sys::RIGHTS_SAME) {
            Ok((h, base)) => {
                s.mm.regions.push((base, len, h));
                base as i64
            }
            Err(_) => -ENOMEM,
        };
    }
    let v = match backing(s, len, if anon { -1 } else { fd }, off, prot) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let p = perms(prot);
    // Inside a reservation: map into it.
    if let Some(&(base, rlen, h)) = s.mm.regions.iter().find(|&&(b, l, _)| addr >= b && addr + len <= b + l) {
        let _ = rlen;
        sys::vmar_unmap(h, addr, len);
        let r = sys::vmar_map(h, addr - base, v, 0, len, p);
        sys::handle_close(v);
        return r.map_or(-ENOMEM, |a| a as i64);
    }
    if flags & MAP_FIXED != 0 {
        sys::vmar_unmap(s.vmar, addr, len); // MAP_FIXED replaces what was there
    }
    let mut r = if addr != 0 && addr >= USER_BASE && addr.saturating_add(len) <= USER_TOP {
        sys::vmar_map(s.vmar, addr - USER_BASE, v, 0, len, p)
    } else {
        Err(sys::ERR_INVALID_ARGS)
    };
    if r.is_err() && !fixed {
        r = sys::vmar_map(s.vmar, sys::ANY, v, 0, len, p);
    }
    sys::handle_close(v);
    match r {
        Ok(a) => a as i64,
        Err(_) if flags & MAP_FIXED_NOREPLACE != 0 => -17, // EEXIST
        Err(_) => -ENOMEM,
    }
}

pub fn munmap(s: &mut Server, addr: u64, len: u64) -> i64 {
    if !addr.is_multiple_of(PAGE) || len == 0 {
        return -EINVAL;
    }
    let len = len.div_ceil(PAGE) * PAGE;
    if let Some(&(_, _, h)) = s.mm.regions.iter().find(|&&(b, l, _)| addr >= b && addr < b + l) {
        sys::vmar_unmap(h, addr, len);
        return 0; // the reservation stays (the ABI cannot release it)
    }
    sys::vmar_unmap(s.vmar, addr, len);
    0
}

pub fn mprotect(s: &mut Server, addr: u64, len: u64, prot: u64) -> i64 {
    if !addr.is_multiple_of(PAGE) {
        return -EINVAL;
    }
    let len = len.div_ceil(PAGE) * PAGE;
    if let Some(&(base, _, h)) = s.mm.regions.iter().find(|&&(b, l, _)| addr >= b && addr + len <= b + l) {
        if prot & PROT_EXEC != 0 {
            return -EACCES;
        }
        if prot == 0 {
            sys::vmar_unmap(h, addr, len);
            return 0;
        }
        let Ok(v) = sys::vmo_create(len) else { return -ENOMEM };
        sys::vmar_unmap(h, addr, len);
        let r = sys::vmar_map(h, addr - base, v, 0, len, perms(prot));
        sys::handle_close(v);
        return r.map_or(-ENOMEM, |_| 0);
    }
    if prot & PROT_EXEC != 0 && prot & PROT_WRITE != 0 {
        return -EACCES;
    }
    if prot & PROT_EXEC != 0 {
        return -EACCES; // making data executable: never
    }
    0
}

pub fn brk(s: &mut Server, want: u64) -> u64 {
    let m = &mut s.mm;
    if m.brk_region == 0 {
        match sys::vmar_allocate(s.vmar, sys::ANY, BRK_SPAN, sys::RIGHTS_SAME) {
            Ok((h, base)) => {
                m.brk_region = h;
                m.brk_base = base;
                m.brk = base;
                m.brk_mapped = base;
            }
            Err(_) => return 0,
        }
    }
    if want == 0 || want < m.brk_base || want > m.brk_base + BRK_SPAN {
        return m.brk;
    }
    let need = want.div_ceil(PAGE) * PAGE;
    if need > m.brk_mapped {
        let grow = need - m.brk_mapped;
        let Ok(v) = sys::vmo_create(grow) else { return m.brk };
        let r = sys::vmar_map(m.brk_region, m.brk_mapped - m.brk_base, v, 0, grow, sys::RIGHT_READ | sys::RIGHT_WRITE);
        sys::handle_close(v);
        if r.is_err() {
            return m.brk;
        }
        m.brk_mapped = need;
    } else if need < m.brk_mapped {
        sys::vmar_unmap(m.brk_region, need, m.brk_mapped - need);
        m.brk_mapped = need;
    }
    m.brk = want;
    want
}
