//! Linux memory calls, served by mapping VMOs into the program's address space (its root VMAR,
//! from `process_vmar`), with full VMA tracking for hardware-enforced `mprotect` (including
//! `PT_GNU_RELRO` RW -> RO transitions) and `/proc/self/maps`.
//!
//! - `mmap`: anonymous memory (zeroed), or a private copy of a file's bytes; `PROT_NONE`
//!   (anonymous or file-backed) creates a VMAR reservation for dynamic linkers and thread stacks;
//!   `MAP_FIXED` replaces overlapping ranges cleanly. Executable memory is allowed only from a
//!   file, sealed with VMEX before mapping and never writable (W^X: `PROT_WRITE | PROT_EXEC`
//!   refused with `-EACCES`).
//! - `mprotect`: remaps tracked VMOs in-place with updated permissions (e.g. `PT_GNU_RELRO`
//!   making GOT/dynamic tables read-only, or `PROT_NONE -> RW` in reservations); refuses
//!   `PROT_WRITE | PROT_EXEC` or making non-executable memory executable (`-EACCES`).
//! - `brk`: a 1 GiB reservation made on first use; grows and shrinks page by page.

use alloc::format;
use alloc::vec::Vec;

use libd::sys::{self, Handle};

use super::{EACCES, EINVAL, ENOMEM, Server};
use crate::{PAGE, USER_BASE, USER_TOP};

pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const BRK_SPAN: u64 = 1 << 30;

struct Vma {
    start: u64,
    len: u64,
    prot: u64,
    offset: u64,
    vmo: Handle,
    region: Handle,
    region_base: u64,
    name: Vec<u8>,
}

#[derive(Default)]
pub struct Mm {
    /// Sub-VMAR reservations (`PROT_NONE` or ELF image spans): (base, length, region handle).
    regions: Vec<(u64, u64, Handle)>,
    /// Mapped VMOs (tracked for `mprotect`, `munmap`, and `/proc/self/maps`).
    vmas: Vec<Vma>,
    /// brk: the reservation, its base, the break, and how far it is mapped.
    brk_region: Handle,
    brk_base: u64,
    brk: u64,
    brk_mapped: u64,
}

impl Drop for Mm {
    fn drop(&mut self) {
        for v in self.vmas.drain(..) {
            if v.vmo != 0 {
                sys::handle_close(v.vmo);
            }
        }
        for (_, _, h) in self.regions.drain(..) {
            if h != 0 {
                sys::handle_close(h);
            }
        }
        if self.brk_region != 0 {
            sys::handle_close(self.brk_region);
        }
    }
}

impl Mm {
    pub fn keep_region(&mut self, base: u64, len: u64, h: Handle) {
        self.regions.push((base, len, h));
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_vma(&mut self, start: u64, len: u64, prot: u64, offset: u64, vmo: Handle, region: Handle, region_base: u64, name: &[u8]) {
        self.vmas.push(Vma {
            start,
            len,
            prot,
            offset,
            vmo,
            region,
            region_base,
            name: name.to_vec(),
        });
        self.vmas.sort_by_key(|v| v.start);
    }

    /// Remove or trim any tracked VMA entries overlapping `[lo, hi)`.
    fn drop_vma_overlap(&mut self, lo: u64, hi: u64) {
        let mut i = 0;
        while i < self.vmas.len() {
            let v_lo = self.vmas[i].start;
            let v_hi = v_lo + self.vmas[i].len;
            if v_hi <= lo || v_lo >= hi {
                i += 1;
                continue;
            }
            if lo <= v_lo && hi >= v_hi {
                let v = self.vmas.remove(i);
                if v.vmo != 0 {
                    sys::handle_close(v.vmo);
                }
                continue;
            }
            // Partial trim (head or tail).
            if lo <= v_lo && hi < v_hi {
                let cut = hi - v_lo;
                self.vmas[i].start = hi;
                self.vmas[i].len -= cut;
                self.vmas[i].offset += cut;
            } else if lo > v_lo && hi >= v_hi {
                self.vmas[i].len = lo - v_lo;
            } else {
                // Middle punch: keep left half, clone handle for right half.
                let right_start = hi;
                let right_len = v_hi - hi;
                let right_off = self.vmas[i].offset + (hi - v_lo);
                let dup = if self.vmas[i].vmo != 0 {
                    sys::handle_duplicate(self.vmas[i].vmo, sys::RIGHTS_SAME).unwrap_or(0)
                } else {
                    0
                };
                let right = Vma {
                    start: right_start,
                    len: right_len,
                    prot: self.vmas[i].prot,
                    offset: right_off,
                    vmo: dup,
                    region: self.vmas[i].region,
                    region_base: self.vmas[i].region_base,
                    name: self.vmas[i].name.clone(),
                };
                self.vmas[i].len = lo - v_lo;
                self.vmas.insert(i + 1, right);
            }
            i += 1;
        }
    }

    /// Format `/proc/self/maps`.
    pub fn format_maps(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for v in &self.vmas {
            let r = if v.prot & PROT_READ != 0 { 'r' } else { '-' };
            let w = if v.prot & PROT_WRITE != 0 { 'w' } else { '-' };
            let x = if v.prot & PROT_EXEC != 0 { 'x' } else { '-' };
            let name = core::str::from_utf8(&v.name).unwrap_or("");
            let line = if name.is_empty() {
                format!("{:012x}-{:012x} {}{}{}p {:08x} 00:00 0\n", v.start, v.start + v.len, r, w, x, v.offset)
            } else {
                format!("{:012x}-{:012x} {}{}{}p {:08x} 00:00 0          {}\n", v.start, v.start + v.len, r, w, x, v.offset, name)
            };
            out.extend_from_slice(line.as_bytes());
        }
        if self.brk_mapped > self.brk_base {
            let line = format!("{:012x}-{:012x} rw-p 00000000 00:00 0          [heap]\n", self.brk_base, self.brk_mapped);
            out.extend_from_slice(line.as_bytes());
        }
        out
    }
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
fn backing(s: &Server, len: u64, fd: i64, off: u64, prot: u64) -> Result<(Handle, Vec<u8>), i64> {
    let v = sys::vmo_create(len).map_err(|_| -ENOMEM)?;
    let mut name = Vec::new();
    if fd >= 0 {
        name = s.fds.fd_path(fd as u64).unwrap_or_default();
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
            return Err(-EACCES); // anonymous executable memory (W^X): refused
        }
        let x = sys::vmo_make_executable(v, s.vmex).map_err(|_| {
            sys::handle_close(v);
            -EACCES
        })?;
        return Ok((x, name));
    }
    Ok((v, name))
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
    if prot == 0 && !fixed {
        // A PROT_NONE reservation (anonymous stack guard or dynamic linker `.so` span reserve).
        return match sys::vmar_allocate(s.vmar, sys::ANY, len, sys::RIGHTS_SAME) {
            Ok((h, base)) => {
                s.mm.regions.push((base, len, h));
                base as i64
            }
            Err(_) => -ENOMEM,
        };
    }
    let (v, name) = match backing(s, len, if anon { -1 } else { fd }, off, prot) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let p = perms(prot);
    // Inside an existing sub-VMAR reservation: map into it.
    if addr != 0
        && let Some(&(base, _rlen, h)) = s.mm.regions.iter().find(|&&(b, l, _)| addr >= b && addr + len <= b + l)
    {
        sys::vmar_unmap(h, addr, len);
        s.mm.drop_vma_overlap(addr, addr + len);
        let r = sys::vmar_map(h, addr - base, v, 0, len, p);
        match r {
            Ok(a) => {
                s.mm.record_vma(a, len, prot, if anon { 0 } else { off }, v, h, base, &name);
                return a as i64;
            }
            Err(_) => {
                sys::handle_close(v);
                return -ENOMEM;
            }
        }
    }
    if flags & MAP_FIXED != 0 {
        sys::vmar_unmap(s.vmar, addr, len);
        s.mm.drop_vma_overlap(addr, addr + len);
    }
    let mut r = if addr != 0 && addr >= USER_BASE && addr.saturating_add(len) <= USER_TOP {
        sys::vmar_map(s.vmar, addr - USER_BASE, v, 0, len, p)
    } else {
        Err(sys::ERR_INVALID_ARGS)
    };
    if r.is_err() && !fixed {
        r = sys::vmar_map(s.vmar, sys::ANY, v, 0, len, p);
    }
    match r {
        Ok(a) => {
            s.mm.record_vma(a, len, prot, if anon { 0 } else { off }, v, s.vmar, USER_BASE, &name);
            a as i64
        }
        Err(_) => {
            sys::handle_close(v);
            if flags & MAP_FIXED_NOREPLACE != 0 { -17 } else { -ENOMEM }
        }
    }
}

pub fn munmap(s: &mut Server, addr: u64, len: u64) -> i64 {
    if !addr.is_multiple_of(PAGE) || len == 0 {
        return -EINVAL;
    }
    let len = len.div_ceil(PAGE) * PAGE;
    s.mm.drop_vma_overlap(addr, addr.saturating_add(len));
    if let Some(&(_, _, h)) = s.mm.regions.iter().find(|&&(b, l, _)| addr >= b && addr < b + l) {
        sys::vmar_unmap(h, addr, len);
        return 0;
    }
    sys::vmar_unmap(s.vmar, addr, len);
    0
}

pub fn mprotect(s: &mut Server, addr: u64, len: u64, prot: u64) -> i64 {
    if !addr.is_multiple_of(PAGE) {
        return -EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let len = len.div_ceil(PAGE) * PAGE;
    if prot & PROT_EXEC != 0 && prot & PROT_WRITE != 0 {
        return -EACCES; // W^X
    }
    let lo = addr;
    let hi = addr.saturating_add(len);

    // 1. Check tracked VMAs covering `[lo, hi)` — remap existing VMOs in place (e.g. PT_GNU_RELRO
    //    making RW pages read-only, or unmapping on PROT_NONE).
    let hits: Vec<usize> = s.mm.vmas.iter().enumerate().filter_map(|(idx, v)| (v.start < hi && lo < v.start + v.len).then_some(idx)).collect();
    if !hits.is_empty() {
        for &idx in &hits {
            let v = &s.mm.vmas[idx];
            if prot & PROT_EXEC != 0 && v.prot & PROT_EXEC == 0 {
                return -EACCES; // data never becomes executable
            }
            if prot & PROT_WRITE != 0 && v.prot & PROT_EXEC != 0 {
                return -EACCES; // code never becomes writable
            }
        }
        // Remap each overlapped slice using its backing VMO.
        for &idx in &hits {
            let v = &s.mm.vmas[idx];
            let a = v.start.max(lo);
            let b = (v.start + v.len).min(hi);
            if v.vmo == 0 {
                continue;
            }
            sys::vmar_unmap(v.region, a, b - a);
            if prot != 0 {
                let vmo_off = a - v.start;
                if sys::vmar_map(v.region, a - v.region_base, v.vmo, vmo_off, b - a, perms(prot)).is_err() {
                    return -EACCES;
                }
            }
            if a == v.start && b == v.start + v.len {
                s.mm.vmas[idx].prot = prot;
            }
        }
        return 0;
    }

    // 2. Unmapped slice inside a `PROT_NONE` reservation (e.g. thread stack guard pages).
    if let Some(&(base, _, h)) = s.mm.regions.iter().find(|&&(b, l, _)| lo >= b && hi <= b + l) {
        if prot & PROT_EXEC != 0 {
            return -EACCES;
        }
        if prot == 0 {
            sys::vmar_unmap(h, lo, len);
            return 0;
        }
        let Ok(v) = sys::vmo_create(len) else { return -ENOMEM };
        sys::vmar_unmap(h, lo, len);
        let r = sys::vmar_map(h, lo - base, v, 0, len, perms(prot));
        match r {
            Ok(a) => {
                s.mm.record_vma(a, len, prot, 0, v, h, base, b"");
                return 0;
            }
            Err(_) => {
                sys::handle_close(v);
                return -ENOMEM;
            }
        }
    }

    if prot & PROT_EXEC != 0 {
        return -EACCES;
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
