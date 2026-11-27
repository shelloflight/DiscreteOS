//! User-space ELF64 parser & loader for D-CMPL's dynamic Linux personality (`PT_INTERP` /
//! `ld-linux.so`, `ET_EXEC` / `ET_DYN`, `PT_TLS`).
//!
//! Keeps `kernel/rust/src/user/elf.rs` completely strict for native D-OS `.dx` binaries: when a
//! Linux binary requires dynamic linking (`PT_INTERP`, `DT_NEEDED`, `PT_TLS`), D-CMPL spawns a
//! minimal 1-page static ELF64 bootstrap stub with `SPAWN_FORWARD | SPAWN_START_EXCEPTION`, and
//! on `EXC_START` (before any instruction executes) maps both the target executable and its
//! `PT_INTERP` interpreter into the child's `process_vmar`, sealing all executable segments with
//! `vmex` so W^X holds for every foreign binary and shared library.

use alloc::vec::Vec;

use libd::sys::{self, Handle};

use super::mem::{Mm, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::{PAGE, USER_BASE, USER_TOP};

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_E551;

const MAX_SEGS: usize = 16;
const MAX_PHNUM: usize = 64;
const MAX_IMAGE: usize = 64 << 20;

#[derive(Clone, Copy, Default)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    pub offset: u64,
    pub filesz: u64,
    pub flags: u32,
}

impl Segment {
    pub fn page_start(&self) -> u64 {
        self.vaddr & !(PAGE - 1)
    }
    pub fn page_end(&self) -> u64 {
        (self.vaddr + self.memsz).div_ceil(PAGE) * PAGE
    }
}

pub struct Elf64 {
    pub dynamic: bool,
    pub entry: u64,
    pub phdr_vaddr: u64,
    pub phnum: u64,
    pub lo: u64,
    pub hi: u64,
    pub segs: [Segment; MAX_SEGS],
    pub nseg: usize,
    pub interp: Option<Vec<u8>>,
    pub has_tls: bool,
    pub has_dynamic: bool,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap_or([0; 4]))
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]))
}

/// Parse and strictly validate an ELF64 x86-64 executable or shared object (`ET_EXEC`/`ET_DYN`).
pub fn parse(data: &[u8]) -> Result<Elf64, &'static str> {
    if data.len() < 64 || data.len() > MAX_IMAGE {
        return Err("ELF64 size out of range");
    }
    if data[0..4] != [0x7F, b'E', b'L', b'F'] || data[4] != 2 || data[5] != 1 || data[6] != 1 {
        return Err("not an ELF64 little-endian binary");
    }
    let e_type = u16_at(data, 16);
    let dynamic = match e_type {
        2 => false,
        3 => true,
        _ => return Err("not ET_EXEC or ET_DYN"),
    };
    if u16_at(data, 18) != 62 {
        return Err("not x86-64");
    }
    let entry = u64_at(data, 24);
    let phoff = u64_at(data, 32);
    let phentsize = u16_at(data, 54);
    let phnum = usize::from(u16_at(data, 56));
    if phentsize != 56 || phnum == 0 || phnum > MAX_PHNUM {
        return Err("bad program header table");
    }
    let ph_end = phoff.checked_add((phnum as u64) * 56).ok_or("phdr overflow")?;
    if ph_end as usize > data.len() {
        return Err("truncated program headers");
    }

    let mut segs = [Segment::default(); MAX_SEGS];
    let mut nseg = 0usize;
    let mut phdr_vaddr = 0u64;
    let mut interp: Option<Vec<u8>> = None;
    let mut has_tls = false;
    let mut has_dynamic = false;

    for i in 0..phnum {
        let p = &data[phoff as usize + i * 56..phoff as usize + (i + 1) * 56];
        let ty = u32_at(p, 0);
        let flags = u32_at(p, 4);
        let offset = u64_at(p, 8);
        let vaddr = u64_at(p, 16);
        let filesz = u64_at(p, 32);
        let memsz = u64_at(p, 40);
        match ty {
            PT_LOAD => {
                if memsz == 0 {
                    continue;
                }
                if nseg >= MAX_SEGS {
                    return Err("too many PT_LOAD segments");
                }
                if filesz > memsz {
                    return Err("PT_LOAD filesz > memsz");
                }
                let fend = offset.checked_add(filesz).ok_or("PT_LOAD file overflow")?;
                if fend as usize > data.len() {
                    return Err("PT_LOAD outside file");
                }
                if vaddr % PAGE != offset % PAGE {
                    return Err("PT_LOAD offset and vaddr not page-congruent");
                }
                let vend = vaddr.checked_add(memsz).ok_or("PT_LOAD vaddr overflow")?;
                if vend.checked_add(PAGE).is_none() {
                    return Err("PT_LOAD page overflow");
                }
                if flags & PF_W != 0 && flags & PF_X != 0 {
                    return Err("writable and executable PT_LOAD (W^X)");
                }
                segs[nseg] = Segment { vaddr, memsz, offset, filesz, flags };
                if phdr_vaddr == 0 && phoff >= offset && phoff - offset < filesz {
                    phdr_vaddr = vaddr + (phoff - offset);
                }
                nseg += 1;
            }
            PT_PHDR => phdr_vaddr = vaddr,
            PT_INTERP => {
                if filesz == 0 || filesz > 512 {
                    return Err("bad PT_INTERP size");
                }
                let fend = offset.checked_add(filesz).ok_or("PT_INTERP overflow")?;
                if fend as usize > data.len() {
                    return Err("PT_INTERP outside file");
                }
                let raw = &data[offset as usize..fend as usize];
                let n = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
                if n == 0 {
                    return Err("empty PT_INTERP");
                }
                interp = Some(raw[..n].to_vec());
            }
            PT_TLS => has_tls = true,
            PT_DYNAMIC => has_dynamic = true,
            PT_GNU_STACK if flags & PF_X != 0 => {
                return Err("executable stack requested");
            }
            _ => {}
        }
    }
    if nseg == 0 {
        return Err("no PT_LOAD segments");
    }
    // Sort segments by vaddr and verify non-overlapping pages.
    segs[..nseg].sort_by_key(|s| s.vaddr);
    for i in 1..nseg {
        if segs[i - 1].page_end() > segs[i].page_start() {
            return Err("PT_LOAD segments share a page");
        }
    }
    let lo = segs[0].page_start();
    let hi = segs[nseg - 1].page_end();
    if hi - lo > (1 << 30) {
        return Err("ELF span exceeds 1 GiB");
    }
    if !dynamic && (lo < USER_BASE || hi > USER_TOP) {
        return Err("ET_EXEC outside user address space");
    }
    let in_exec = segs[..nseg].iter().any(|s| s.flags & PF_X != 0 && entry >= s.vaddr && entry < s.vaddr + s.memsz);
    if !in_exec {
        return Err("entry point not in an executable segment");
    }
    Ok(Elf64 { dynamic, entry, phdr_vaddr, phnum: phnum as u64, lo, hi, segs, nseg, interp, has_tls, has_dynamic })
}

/// Does this ELF require D-CMPL's user-space loader (has `PT_INTERP`, `PT_TLS`, or `PT_DYNAMIC`
/// with dynamic linking)? Static ELFs like L1/L2 can be spawned directly by the kernel.
pub fn needs_userspace_loader(elf: &Elf64) -> bool {
    elf.interp.is_some() || elf.has_tls || (elf.dynamic && elf.has_dynamic)
}

/// Build a minimal valid 4 KiB static `ET_DYN` ELF64 bootstrap stub (1 `PT_LOAD` RX page with a
/// `ud2` at entry 0x100). Spawned with `SPAWN_FORWARD | SPAWN_START_EXCEPTION` so D-CMPL maps the
/// real dynamic executable and its `PT_INTERP` interpreter before any instruction runs.
pub fn build_stub_elf() -> [u8; 4096] {
    let mut b = [0u8; 4096];
    let put16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    b[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    b[4] = 2; // ELF64
    b[5] = 1; // little-endian
    b[6] = 1; // version 1
    put16(&mut b, 16, 3); // ET_DYN
    put16(&mut b, 18, 62); // EM_X86_64
    put32(&mut b, 20, 1); // EV_CURRENT
    put64(&mut b, 24, 0x100); // e_entry
    put64(&mut b, 32, 64); // e_phoff
    put16(&mut b, 52, 64); // e_ehsize
    put16(&mut b, 54, 56); // e_phentsize
    put16(&mut b, 56, 1); // e_phnum
    // Program header 0: PT_LOAD RX covering [0, 0x1000)
    put32(&mut b, 64, PT_LOAD);
    put32(&mut b, 68, PF_R | PF_X);
    put64(&mut b, 72, 0); // p_offset
    put64(&mut b, 80, 0); // p_vaddr
    put64(&mut b, 88, 0); // p_paddr
    put64(&mut b, 96, 0x1000); // p_filesz
    put64(&mut b, 104, 0x1000); // p_memsz
    put64(&mut b, 112, 0x1000); // p_align
    // Entry instruction: ud2 (never reached because EXC_START redirects RIP to the real ELF/interp)
    b[0x100] = 0x0F;
    b[0x101] = 0x0B;
    b
}

pub struct MappedElf {
    pub bias: u64,
    pub entry: u64,
    pub phdr: u64,
    pub phnum: u64,
}

/// Map all `PT_LOAD` segments of `elf` into `vmar` (with W^X + VMEX sealing for code segments)
/// and record them in `mm` for `mprotect` (RELRO) and `/proc/self/maps`.
pub fn map_into(
    vmar: Handle,
    vmex: Handle,
    data: &[u8],
    elf: &Elf64,
    mm: &mut Mm,
    label: &[u8],
) -> Result<MappedElf, &'static str> {
    let span = elf.hi - elf.lo;
    let (region, base) = if !elf.dynamic {
        sys::vmar_allocate(vmar, elf.lo - USER_BASE, span, sys::RIGHTS_SAME)
            .map_err(|_| "cannot reserve fixed ET_EXEC range")?
    } else {
        sys::vmar_allocate(vmar, sys::ANY, span, sys::RIGHTS_SAME)
            .map_err(|_| "cannot reserve ET_DYN range")?
    };
    let bias = base.wrapping_sub(elf.lo);

    for s in &elf.segs[..elf.nseg] {
        let ps = s.page_start();
        let pe = s.page_end();
        let len = pe - ps;
        let mut v = sys::vmo_create(len).map_err(|_| "no memory for ELF segment")?;
        if s.filesz > 0 {
            let dst_off = s.vaddr - ps;
            let src = &data[s.offset as usize..(s.offset + s.filesz) as usize];
            let mut done = 0usize;
            while done < src.len() {
                let n = (src.len() - done).min(64 * 1024);
                if sys::vmo_write(v, dst_off + done as u64, &src[done..done + n]) < 0 {
                    sys::handle_close(v);
                    sys::handle_close(region);
                    return Err("vmo_write failed on ELF segment");
                }
                done += n;
            }
        }
        let mut perms = sys::RIGHT_READ;
        let mut prot = PROT_READ;
        if s.flags & PF_W != 0 {
            perms |= sys::RIGHT_WRITE;
            prot |= PROT_WRITE;
        }
        if s.flags & PF_X != 0 {
            perms |= sys::RIGHT_EXECUTE;
            prot |= PROT_EXEC;
            v = match sys::vmo_make_executable(v, vmex) {
                Ok(x) => x,
                Err(_) => {
                    sys::handle_close(v);
                    sys::handle_close(region);
                    return Err("cannot seal ELF executable segment");
                }
            };
        }
        let map_off = ps - elf.lo;
        let mapped = match sys::vmar_map(region, map_off, v, 0, len, perms) {
            Ok(a) => a,
            Err(_) => {
                sys::handle_close(v);
                sys::handle_close(region);
                return Err("cannot map ELF segment");
            }
        };
        mm.record_vma(mapped, len, prot, s.offset & !(PAGE - 1), v, region, base, label);
    }
    mm.keep_region(base, span, region);
    Ok(MappedElf {
        bias,
        entry: bias.wrapping_add(elf.entry),
        phdr: if elf.phdr_vaddr != 0 { bias.wrapping_add(elf.phdr_vaddr) } else { 0 },
        phnum: elf.phnum,
    })
}
