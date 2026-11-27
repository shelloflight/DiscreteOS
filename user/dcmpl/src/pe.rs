//! PE32+ parser for D-CMPL's Windows personality (`.exe`, x86-64).
//!
//! Strict, like the kernel's ELF parser: every field the loader relies on is checked with
//! overflow-checked arithmetic and bounds-checked reads, and anything unusual is refused with a
//! reason instead of being guessed at:
//! - DOS header `MZ`, `e_lfanew` inside the file, `PE\0\0`, machine AMD64, an executable image
//!   (not a DLL), PE32+ optional header with at most 16 data directories;
//! - SectionAlignment a power of two >= 4 KiB (sections are mapped page by page), FileAlignment a
//!   power of two in 512..=SectionAlignment, ImageBase 64 KiB aligned, SizeOfImage a multiple of
//!   SectionAlignment and at most 64 MiB, headers inside the file and the image;
//! - at most 16 sections, aligned, in address order without overlap, inside the image, raw data
//!   inside the file, never writable and executable (W^X);
//! - the entry point inside an executable section;
//! - data directories inside the image; delay-load imports and .NET images are refused (not
//!   supported yet); the exception table (`.pdata`) a whole number of 12-byte entries;
//! - the TLS directory (read after relocation, `tls`): the template and the index slot inside the
//!   image, at most 1 MiB of TLS data, at most 16 callbacks, each inside an executable section;
//! - base relocations: blocks inside the directory, only DIR64 (and ABSOLUTE padding), every
//!   target 8 bytes inside the image;
//! - imports: at most 64 DLLs and 4096 functions per DLL, names NUL-terminated inside the image,
//!   by name only (an ordinal import is refused, naming the DLL), every IAT slot inside the image.
//!
//! The parser works on byte slices only, so it is fuzzed on plain buffers (`fuzz.rs`); a bug that
//! slips through the checks is an out-of-bounds slice index, i.e. a panic, never memory corruption.

use core::fmt;

pub const MAX_FILE: usize = 64 << 20;
pub const MAX_IMAGE: u32 = 64 << 20;
pub const MAX_SECTIONS: usize = 32;
const MAX_DLLS: usize = 64;
const MAX_IMPORTS: usize = 4096;
const MAX_EXPORTS: usize = 16384;
const MAX_NAME: usize = 256;
const PAGE: u32 = 4096;

const MACHINE_AMD64: u16 = 0x8664;
const FILE_RELOCS_STRIPPED: u16 = 0x0001;
const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const FILE_DLL: u16 = 0x2000;
const OPT_MAGIC_PE32PLUS: u16 = 0x20B;
const SUBSYSTEM_GUI: u16 = 2;
const SUBSYSTEM_CUI: u16 = 3;

pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_SECURITY: usize = 4; // a file offset, not an RVA
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;
const DIR_DELAY_IMPORT: usize = 13;
const DIR_CLR: usize = 14;

const REL_ABSOLUTE: u16 = 0;
const REL_DIR64: u16 = 10;

/// A name copied out of the image for error messages (truncated to 48 bytes).
#[derive(Clone, Copy)]
pub struct Name {
    b: [u8; 48],
    n: usize,
}

impl Name {
    fn new(s: &[u8]) -> Name {
        let mut b = [0u8; 48];
        let n = s.len().min(48);
        b[..n].copy_from_slice(&s[..n]);
        Name { b, n }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &c in &self.b[..self.n] {
            let c = if (0x20..0x7F).contains(&c) { c as char } else { '?' };
            fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub enum PeError {
    Truncated,
    Bad(&'static str),
    Unsupported(&'static str),
    /// An import D-CMPL does not provide: DLL and function (or ordinal).
    Import { dll: Name, func: Name, ordinal: Option<u16> },
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::Truncated => f.write_str("truncated file"),
            PeError::Bad(s) => write!(f, "malformed image: {}", s),
            PeError::Unsupported(s) => write!(f, "not supported: {}", s),
            PeError::Import { dll, ordinal: Some(o), .. } => write!(f, "unsupported import {}!#{} (by ordinal)", dll, o),
            PeError::Import { dll, func, .. } => write!(f, "unsupported import {}!{}", dll, func),
        }
    }
}

type R<T> = Result<T, PeError>;

fn rd16(b: &[u8], at: usize) -> R<u16> {
    let s = b.get(at..at.checked_add(2).ok_or(PeError::Truncated)?).ok_or(PeError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn rd32(b: &[u8], at: usize) -> R<u32> {
    let s = b.get(at..at.checked_add(4).ok_or(PeError::Truncated)?).ok_or(PeError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd64(b: &[u8], at: usize) -> R<u64> {
    let s = b.get(at..at.checked_add(8).ok_or(PeError::Truncated)?).ok_or(PeError::Truncated)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}
fn wr64(b: &mut [u8], at: usize, v: u64) -> R<()> {
    let s = b.get_mut(at..at.checked_add(8).ok_or(PeError::Truncated)?).ok_or(PeError::Truncated)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn align_up(v: u32, a: u32) -> Option<u32> {
    v.checked_add(a - 1).map(|x| x & !(a - 1))
}

#[derive(Clone, Copy, Default)]
pub struct Dir {
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Default)]
pub struct Section {
    pub name: [u8; 8],
    pub rva: u32,
    /// Size in memory (VirtualSize, or SizeOfRawData if that is 0), before page rounding.
    pub mem: u32,
    pub raw_off: u32,
    /// Bytes copied from the file: min(SizeOfRawData, mem).
    pub copy: u32,
    pub chars: u32,
}

impl Section {
    pub fn writable(&self) -> bool {
        self.chars & SCN_MEM_WRITE != 0
    }
    pub fn executable(&self) -> bool {
        self.chars & SCN_MEM_EXECUTE != 0
    }
    /// Page-rounded size in memory (checked at parse time to stay inside the image).
    pub fn pages(&self) -> u32 {
        self.mem.div_ceil(PAGE) * PAGE
    }
    pub fn name(&self) -> &str {
        let n = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }
}

#[derive(Clone, Copy)]
pub struct Image {
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry: u32,
    pub subsystem: u16,
    pub is_dll: bool,
    pub sections: [Section; MAX_SECTIONS],
    pub nsec: usize,
    pub export: Dir,
    pub import: Dir,
    pub reloc: Dir,
    pub tls: Dir,
    /// The function table (`RUNTIME_FUNCTION` entries) the SEH unwinder searches.
    pub exception: Dir,
    /// SizeOfStackReserve: the main thread's stack size and the default for new threads.
    pub stack_reserve: u64,
    /// Not linked with relocations stripped: can be loaded away from its preferred base.
    pub relocatable: bool,
}

impl Image {
    pub fn sections(&self) -> &[Section] {
        &self.sections[..self.nsec]
    }
}

/// Parse and validate the headers and section table of a PE32+ executable (`.exe`).
pub fn parse(data: &[u8]) -> R<Image> {
    parse_kind(data, false)
}

/// Parse and validate a PE32+ dynamic-link library (`.dll`).
pub fn parse_dll(data: &[u8]) -> R<Image> {
    parse_kind(data, true)
}

fn parse_kind(data: &[u8], expect_dll: bool) -> R<Image> {
    if data.len() > MAX_FILE {
        return Err(PeError::Unsupported("file larger than 64 MiB"));
    }
    if data.len() < 64 || data[0..2] != *b"MZ" {
        return Err(PeError::Bad("not an MZ executable"));
    }
    let pe = rd32(data, 0x3C)? as usize;
    if pe < 64 || !pe.is_multiple_of(4) {
        return Err(PeError::Bad("bad e_lfanew"));
    }
    if rd32(data, pe)? != 0x0000_4550 {
        return Err(PeError::Bad("no PE signature"));
    }
    let coff = pe + 4;
    if rd16(data, coff)? != MACHINE_AMD64 {
        return Err(PeError::Unsupported("not an x86-64 (AMD64) image"));
    }
    let nsec = usize::from(rd16(data, coff + 2)?);
    let opt_size = usize::from(rd16(data, coff + 16)?);
    let fchars = rd16(data, coff + 18)?;
    if fchars & FILE_EXECUTABLE_IMAGE == 0 {
        return Err(PeError::Bad("not marked executable"));
    }
    let is_dll = fchars & FILE_DLL != 0;
    if !expect_dll && is_dll {
        return Err(PeError::Unsupported("a DLL, not an EXE"));
    }
    if expect_dll && !is_dll {
        return Err(PeError::Bad("not marked as a DLL"));
    }
    if nsec == 0 || nsec > MAX_SECTIONS {
        return Err(PeError::Unsupported("no sections or more than 32"));
    }
    let opt = coff + 20;
    if opt_size < 112 {
        return Err(PeError::Bad("optional header too small"));
    }
    if rd16(data, opt)? != OPT_MAGIC_PE32PLUS {
        return Err(PeError::Unsupported("not PE32+ (64-bit)"));
    }
    let entry = rd32(data, opt + 16)?;
    let image_base = rd64(data, opt + 24)?;
    let sect_align = rd32(data, opt + 32)?;
    let file_align = rd32(data, opt + 36)?;
    let size_of_image = rd32(data, opt + 56)?;
    let size_of_headers = rd32(data, opt + 60)?;
    let subsystem = rd16(data, opt + 68)?;
    let stack_reserve = rd64(data, opt + 72)?;
    let ndirs = rd32(data, opt + 108)? as usize;
    if ndirs > 16 || 112 + 8 * ndirs > opt_size {
        return Err(PeError::Bad("bad data directory count"));
    }
    if !sect_align.is_power_of_two() || sect_align < PAGE {
        return Err(PeError::Unsupported("section alignment below 4 KiB"));
    }
    if !file_align.is_power_of_two() || !(512..=sect_align).contains(&file_align) {
        return Err(PeError::Bad("bad file alignment"));
    }
    if image_base % 0x1_0000 != 0 || image_base.checked_add(u64::from(size_of_image)).is_none() {
        return Err(PeError::Bad("bad image base"));
    }
    if size_of_image == 0 || size_of_image > MAX_IMAGE || size_of_image % sect_align != 0 {
        return Err(PeError::Unsupported("image size 0, over 64 MiB, or not section-aligned"));
    }
    if size_of_headers == 0 || size_of_headers as usize > data.len() || size_of_headers > size_of_image {
        return Err(PeError::Bad("bad header size"));
    }
    if subsystem != SUBSYSTEM_CUI && subsystem != SUBSYSTEM_GUI {
        return Err(PeError::Unsupported("subsystem other than console or GUI"));
    }
    let sec_table = opt.checked_add(opt_size).ok_or(PeError::Truncated)?;
    if sec_table + 40 * nsec > size_of_headers as usize {
        return Err(PeError::Bad("section table outside the headers"));
    }

    // Data directories.
    let mut dirs = [Dir::default(); 16];
    for (i, d) in dirs.iter_mut().enumerate().take(ndirs) {
        *d = Dir { rva: rd32(data, opt + 112 + 8 * i)?, size: rd32(data, opt + 116 + 8 * i)? };
        if i != DIR_SECURITY && d.size != 0 {
            let end = d.rva.checked_add(d.size).ok_or(PeError::Bad("data directory overflow"))?;
            if end > size_of_image {
                return Err(PeError::Bad("data directory outside the image"));
            }
        }
    }
    if dirs[DIR_TLS].size != 0 && dirs[DIR_TLS].size < 40 {
        return Err(PeError::Bad("TLS directory too small"));
    }
    if dirs[DIR_EXCEPTION].size % 12 != 0 {
        return Err(PeError::Bad("exception table not a whole number of entries"));
    }
    if dirs[DIR_DELAY_IMPORT].size != 0 {
        return Err(PeError::Unsupported("delay-load imports"));
    }
    if dirs[DIR_CLR].size != 0 {
        return Err(PeError::Unsupported(".NET (CLR) image"));
    }

    // Sections.
    let mut img = Image {
        image_base,
        size_of_image,
        size_of_headers,
        entry,
        subsystem,
        is_dll,
        sections: [Section::default(); MAX_SECTIONS],
        nsec,
        export: dirs[DIR_EXPORT],
        import: dirs[DIR_IMPORT],
        reloc: dirs[DIR_BASERELOC],
        tls: dirs[DIR_TLS],
        exception: dirs[DIR_EXCEPTION],
        stack_reserve,
        relocatable: fchars & FILE_RELOCS_STRIPPED == 0, // an empty .reloc: nothing to fix up
    };
    let mut prev_end = align_up(size_of_headers, sect_align).ok_or(PeError::Bad("bad header size"))?;
    for (i, slot) in img.sections.iter_mut().enumerate().take(nsec) {
        let at = sec_table + 40 * i;
        let mut name = [0u8; 8];
        name.copy_from_slice(data.get(at..at + 8).ok_or(PeError::Truncated)?);
        let vsize = rd32(data, at + 8)?;
        let rva = rd32(data, at + 12)?;
        let raw_size = rd32(data, at + 16)?;
        let raw_off = rd32(data, at + 20)?;
        let chars = rd32(data, at + 36)?;
        if rva % sect_align != 0 {
            return Err(PeError::Bad("section not aligned"));
        }
        if rva < prev_end {
            return Err(PeError::Bad("sections overlap or are out of order"));
        }
        let mem = if vsize == 0 { raw_size } else { vsize };
        if mem == 0 {
            return Err(PeError::Bad("empty section"));
        }
        let end = align_up(mem, sect_align)
            .and_then(|m| rva.checked_add(m))
            .ok_or(PeError::Bad("section size overflow"))?;
        if end > size_of_image {
            return Err(PeError::Bad("section outside the image"));
        }
        let copy = raw_size.min(mem);
        if copy > 0 {
            let fend = raw_off.checked_add(copy).ok_or(PeError::Truncated)?;
            if fend as usize > data.len() {
                return Err(PeError::Truncated);
            }
        }
        if chars & SCN_MEM_WRITE != 0 && chars & SCN_MEM_EXECUTE != 0 {
            return Err(PeError::Unsupported("writable and executable section (W^X)"));
        }
        *slot = Section { name, rva, mem, raw_off, copy, chars };
        prev_end = end;
    }
    if !is_dll || entry != 0 {
        let in_code = img
            .sections()
            .iter()
            .any(|s| s.executable() && entry >= s.rva && u64::from(entry) < u64::from(s.rva) + u64::from(s.mem));
        if !in_code {
            return Err(PeError::Bad("entry point not in an executable section"));
        }
    }
    Ok(img)
}

impl Image {
    /// Copy the headers and every section to their RVAs in `out` (zeroed by the caller, at least
    /// SizeOfImage bytes).
    pub fn layout(&self, data: &[u8], out: &mut [u8]) -> R<()> {
        let h = self.size_of_headers as usize;
        out.get_mut(..h).ok_or(PeError::Truncated)?.copy_from_slice(data.get(..h).ok_or(PeError::Truncated)?);
        for s in self.sections() {
            let (src, dst, n) = (s.raw_off as usize, s.rva as usize, s.copy as usize);
            if n == 0 {
                continue;
            }
            let from = data.get(src..src + n).ok_or(PeError::Truncated)?;
            out.get_mut(dst..dst + n).ok_or(PeError::Truncated)?.copy_from_slice(from);
        }
        Ok(())
    }

    /// Apply the base relocations for a load `delta` bytes away from ImageBase (laid-out image).
    /// Returns the number of relocations applied.
    pub fn relocate(&self, img: &mut [u8], delta: u64) -> R<u32> {
        if delta == 0 {
            return Ok(0);
        }
        if !self.relocatable {
            return Err(PeError::Unsupported("preferred base unavailable and the image has no relocations"));
        }
        let size = self.size_of_image as usize;
        let img = img.get_mut(..size).ok_or(PeError::Truncated)?;
        let mut at = self.reloc.rva as usize;
        let end = at + self.reloc.size as usize; // checked at parse time: inside the image
        let mut count = 0u32;
        while end - at >= 8 {
            let page = rd32(img, at)? as usize;
            let bsize = rd32(img, at + 4)? as usize;
            if bsize < 8 || !bsize.is_multiple_of(2) || bsize > end - at {
                return Err(PeError::Bad("bad relocation block"));
            }
            for e in (at + 8..at + bsize).step_by(2) {
                let v = rd16(img, e)?;
                match v >> 12 {
                    REL_ABSOLUTE => {}
                    REL_DIR64 => {
                        let t = page.checked_add(usize::from(v & 0xFFF)).ok_or(PeError::Bad("relocation overflow"))?;
                        if t.checked_add(8).is_none_or(|x| x > size) {
                            return Err(PeError::Bad("relocation outside the image"));
                        }
                        let old = rd64(img, t)?;
                        wr64(img, t, old.wrapping_add(delta))?;
                        count += 1;
                    }
                    _ => return Err(PeError::Unsupported("relocation type other than DIR64")),
                }
            }
            at += bsize;
        }
        Ok(count)
    }

    /// Bind every import of the laid-out image: `resolve(dll, function)` gives the address, or
    /// None (the image is refused, naming the import). Returns the number of IAT slots written.
    pub fn bind(&self, img: &mut [u8], resolve: impl FnMut(&[u8], &[u8]) -> Option<u64>) -> R<u32> {
        self.bind_ex(img, resolve, |_, _| None)
    }

    /// Bind imports by name or ordinal.
    pub fn bind_ex(
        &self,
        img: &mut [u8],
        mut resolve_name: impl FnMut(&[u8], &[u8]) -> Option<u64>,
        mut resolve_ord: impl FnMut(&[u8], u16) -> Option<u64>,
    ) -> R<u32> {
        if self.import.size == 0 {
            return Ok(0);
        }
        let size = self.size_of_image as usize;
        let img = img.get_mut(..size).ok_or(PeError::Truncated)?;
        let mut bound = 0u32;
        let mut d = self.import.rva as usize;
        for i in 0..=MAX_DLLS {
            if i == MAX_DLLS {
                return Err(PeError::Unsupported("more than 64 imported DLLs"));
            }
            if d.checked_add(20).is_none_or(|x| x > size) {
                return Err(PeError::Bad("import directory outside the image"));
            }
            let oft = rd32(img, d)? as usize;
            let name_rva = rd32(img, d + 12)? as usize;
            let ft = rd32(img, d + 16)? as usize;
            if oft == 0 && name_rva == 0 && ft == 0 && rd32(img, d + 4)? == 0 && rd32(img, d + 8)? == 0 {
                break;
            }
            if ft == 0 {
                return Err(PeError::Bad("import without an address table"));
            }
            let dll = Name::new(cstr(img, name_rva)?);
            let lookup = if oft != 0 { oft } else { ft };
            for j in 0..=MAX_IMPORTS {
                if j == MAX_IMPORTS {
                    return Err(PeError::Unsupported("more than 4096 imports from one DLL"));
                }
                let thunk = rd64(img, lookup + 8 * j)?;
                if thunk == 0 {
                    break;
                }
                let addr = if thunk >> 63 != 0 {
                    let ord = thunk as u16;
                    let Some(a) = resolve_ord(cstr(img, name_rva)?, ord) else {
                        return Err(PeError::Import { dll, func: Name::new(b""), ordinal: Some(ord) });
                    };
                    a
                } else {
                    if thunk >> 31 != 0 {
                        return Err(PeError::Bad("bad import thunk"));
                    }
                    let func = cstr(img, (thunk as usize).checked_add(2).ok_or(PeError::Truncated)?)?;
                    let Some(a) = resolve_name(cstr(img, name_rva)?, func) else {
                        return Err(PeError::Import { dll, func: Name::new(func), ordinal: None });
                    };
                    a
                };
                wr64(img, ft + 8 * j, addr)?;
                bound += 1;
            }
            d += 20;
        }
        Ok(bound)
    }

    /// Resolve a PE export table entry by name (supports forwarded exports).
    pub fn export_by_name<'a>(&self, img: &'a [u8], want: &[u8]) -> R<Option<ExportRef<'a>>> {
        if self.export.size < 40 {
            return Ok(None);
        }
        let img = img.get(..self.size_of_image as usize).ok_or(PeError::Truncated)?;
        let ed = self.export.rva as usize;
        let num_funcs = rd32(img, ed + 20)? as usize;
        let num_names = rd32(img, ed + 24)? as usize;
        let funcs_rva = rd32(img, ed + 28)? as usize;
        let names_rva = rd32(img, ed + 32)? as usize;
        let ords_rva = rd32(img, ed + 36)? as usize;
        if num_funcs > MAX_EXPORTS || num_names > MAX_EXPORTS {
            return Err(PeError::Unsupported("too many exports"));
        }
        // Binary search the sorted name table (falls back to linear scan if unsorted).
        let (mut lo, mut hi) = (0usize, num_names);
        let mut found_idx = None;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let nrva = rd32(img, names_rva.checked_add(4 * mid).ok_or(PeError::Bad("export name overflow"))?)? as usize;
            let name = cstr(img, nrva)?;
            match name.cmp(want) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => {
                    found_idx = Some(mid);
                    break;
                }
            }
        }
        if found_idx.is_none() {
            for i in 0..num_names {
                let nrva = rd32(img, names_rva.checked_add(4 * i).ok_or(PeError::Bad("export name overflow"))?)? as usize;
                if cstr(img, nrva)? == want {
                    found_idx = Some(i);
                    break;
                }
            }
        }
        let Some(idx) = found_idx else { return Ok(None) };
        let ord_idx = usize::from(rd16(img, ords_rva.checked_add(2 * idx).ok_or(PeError::Bad("export ord overflow"))?)?);
        if ord_idx >= num_funcs {
            return Err(PeError::Bad("export ordinal out of range"));
        }
        let rva = rd32(img, funcs_rva.checked_add(4 * ord_idx).ok_or(PeError::Bad("export func overflow"))?)?;
        self.classify_export(img, rva)
    }

    /// Resolve a PE export table entry by ordinal (1-based `ordinal` minus `Base`).
    pub fn export_by_ordinal<'a>(&self, img: &'a [u8], ordinal: u16) -> R<Option<ExportRef<'a>>> {
        if self.export.size < 40 {
            return Ok(None);
        }
        let img = img.get(..self.size_of_image as usize).ok_or(PeError::Truncated)?;
        let ed = self.export.rva as usize;
        let base = rd32(img, ed + 16)?;
        let num_funcs = rd32(img, ed + 20)? as usize;
        let funcs_rva = rd32(img, ed + 28)? as usize;
        if num_funcs > MAX_EXPORTS {
            return Err(PeError::Unsupported("too many exports"));
        }
        let Some(idx) = u32::from(ordinal).checked_sub(base) else { return Ok(None) };
        let idx = idx as usize;
        if idx >= num_funcs {
            return Ok(None);
        }
        let rva = rd32(img, funcs_rva.checked_add(4 * idx).ok_or(PeError::Bad("export func overflow"))?)?;
        self.classify_export(img, rva)
    }

    fn classify_export<'a>(&self, img: &'a [u8], rva: u32) -> R<Option<ExportRef<'a>>> {
        if rva == 0 {
            return Ok(None);
        }
        let exp_start = self.export.rva;
        let exp_end = exp_start.saturating_add(self.export.size);
        if rva >= exp_start && rva < exp_end {
            let fwd = cstr(img, rva as usize)?;
            return Ok(Some(ExportRef::Forward(fwd)));
        }
        if rva >= self.size_of_image {
            return Err(PeError::Bad("export RVA outside the image"));
        }
        Ok(Some(ExportRef::Rva(rva)))
    }
}

/// An export entry in a PE32+ module.
#[derive(Clone, Copy)]
pub enum ExportRef<'a> {
    /// Address relative to the module's load base.
    Rva(u32),
    /// Forwarder string (`"OTHERDLL.Func"` or `"OTHERDLL.#123"`).
    Forward(&'a [u8]),
}

/// The TLS directory of a laid-out, relocated image loaded at `base` (RVAs inside the image).
#[derive(Clone, Copy, Default)]
pub struct Tls {
    pub template_rva: u32,
    pub template_len: u32,
    pub zero_fill: u32,
    pub index_rva: u32,
    pub callbacks: [u32; MAX_TLS_CALLBACKS],
    pub ncallbacks: usize,
}

pub const MAX_TLS: u32 = 1 << 20;
pub const MAX_TLS_CALLBACKS: usize = 16;

impl Image {
    /// Read and check the TLS directory (after relocation: its fields are addresses).
    pub fn tls(&self, img: &[u8], base: u64) -> R<Option<Tls>> {
        if self.tls.size == 0 {
            return Ok(None);
        }
        let size = u64::from(self.size_of_image);
        let img = img.get(..size as usize).ok_or(PeError::Truncated)?;
        let d = self.tls.rva as usize;
        let rva = |va: u64| -> R<u32> {
            let r = va.checked_sub(base).ok_or(PeError::Bad("TLS address outside the image"))?;
            if r >= size { Err(PeError::Bad("TLS address outside the image")) } else { Ok(r as u32) }
        };
        let (start, end) = (rd64(img, d)?, rd64(img, d + 8)?);
        let (index, cbs) = (rd64(img, d + 16)?, rd64(img, d + 24)?);
        let zero_fill = rd32(img, d + 32)?;
        let mut t = Tls { zero_fill, ..Tls::default() };
        if end < start || end - start > u64::from(MAX_TLS) || zero_fill > MAX_TLS {
            return Err(PeError::Unsupported("TLS data over 1 MiB"));
        }
        if end > start {
            t.template_rva = rva(start)?;
            t.template_len = (end - start) as u32;
            if u64::from(t.template_rva) + u64::from(t.template_len) > size {
                return Err(PeError::Bad("TLS template outside the image"));
            }
        }
        t.index_rva = rva(index)?;
        if u64::from(t.index_rva) + 4 > size {
            return Err(PeError::Bad("TLS index outside the image"));
        }
        if cbs != 0 {
            let at = rva(cbs)? as usize;
            for i in 0..=MAX_TLS_CALLBACKS {
                let cb = rd64(img, at + 8 * i)?;
                if cb == 0 {
                    break;
                }
                if i == MAX_TLS_CALLBACKS {
                    return Err(PeError::Unsupported("more than 16 TLS callbacks"));
                }
                let r = rva(cb)?;
                if !self.sections().iter().any(|s| s.executable() && r >= s.rva && u64::from(r) < u64::from(s.rva) + u64::from(s.mem)) {
                    return Err(PeError::Bad("TLS callback not in an executable section"));
                }
                t.callbacks[i] = r;
                t.ncallbacks = i + 1;
            }
        }
        Ok(Some(t))
    }
}

/// A NUL-terminated name at `rva`, at most 256 bytes, inside `img`.
fn cstr(img: &[u8], rva: usize) -> R<&[u8]> {
    let s = img.get(rva..).ok_or(PeError::Bad("name outside the image"))?;
    let s = &s[..s.len().min(MAX_NAME + 1)];
    let n = s.iter().position(|&c| c == 0).ok_or(PeError::Bad("unterminated or overlong name"))?;
    if n == 0 {
        return Err(PeError::Bad("empty import name"));
    }
    Ok(&s[..n])
}
