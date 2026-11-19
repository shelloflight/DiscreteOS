//! ELF64 parser for `.dx` executables (x86-64, static, ET_EXEC or position-independent ET_DYN).
//!
//! Strict: everything the loader relies on is checked, with overflow-checked arithmetic, and
//! anything unusual is refused rather than guessed at:
//! - header: magic, 64-bit, little-endian, version 1, x86-64, phentsize 56, at most 64 phdrs;
//! - PT_LOAD: inside the file, filesz <= memsz, offset and address congruent modulo the page
//!   size, in address order without sharing a page, never writable and executable (W^X);
//! - no PT_INTERP (no dynamic linker), no PT_TLS, no executable PT_GNU_STACK;
//! - the entry point lies in an executable segment;
//! - ET_DYN relocations: only R_X86_64_RELATIVE (and NONE), each target 8 bytes inside a segment;
//!   no DT_NEEDED, no PLT/REL/RELR relocations, no text relocations.
//!
//! PT_GNU_PROPERTY is read for its x86 feature bits (SHSTK: the program runs with a shadow
//! stack); a malformed note only means no features.
//!
//! The parser only reads through `Source`, so it can be fuzzed on plain byte buffers.

const PAGE: u64 = 4096;
pub const MAX_IMAGE: u64 = 64 << 20;
pub const MAX_SPAN: u64 = 1 << 30;
pub const MAX_SEGMENTS: usize = 16;
const MAX_PHNUM: u16 = 64;
const MAX_DYN: u64 = 256;
const MAX_RELOCS: u64 = 1 << 20;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_SHLIB: u32 = 5;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_E551;
const PT_GNU_RELRO: u32 = 0x6474_E552;
const PT_GNU_PROPERTY: u32 = 0x6474_E553;

/// x86 feature bits of the GNU property note (GNU_PROPERTY_X86_FEATURE_1_AND): what every object
/// linked into the image supports (or what the linker was told to force, `-z shstk`).
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xC000_0002;
pub const FEATURE_1_IBT: u32 = 1;
pub const FEATURE_1_SHSTK: u32 = 2;
const MAX_PROPERTY: u64 = 4096;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_RELSZ: i64 = 18;
const DT_TEXTREL: i64 = 22;
const DT_FLAGS: i64 = 30;
const DT_RELRSZ: i64 = 35;
const DF_TEXTREL: u64 = 4;

const R_X86_64_NONE: u32 = 0;
const R_X86_64_RELATIVE: u32 = 8;

/// Where the bytes come from (a VMO for the loader, a buffer for the fuzzer).
pub trait Source {
    fn size(&self) -> u64;
    fn read(&self, off: u64, buf: &mut [u8]) -> bool;
}

impl Source for &[u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        let Ok(off) = usize::try_from(off) else { return false };
        match off.checked_add(buf.len()) {
            Some(end) if end <= self.len() => {
                buf.copy_from_slice(&self[off..end]);
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    Truncated,
    BadHeader(&'static str),
    Unsupported(&'static str),
    Malformed(&'static str),
}

impl ElfError {
    pub fn text(self) -> &'static str {
        match self {
            ElfError::Truncated => "truncated file",
            ElfError::BadHeader(s) | ElfError::Unsupported(s) | ElfError::Malformed(s) => s,
        }
    }
}

type R<T> = Result<T, ElfError>;

#[derive(Clone, Copy, Default, Debug)]
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
    /// Checked at parse time not to overflow.
    pub fn page_end(&self) -> u64 {
        (self.vaddr + self.memsz).div_ceil(PAGE) * PAGE
    }
}

#[derive(Clone, Debug)]
pub struct Image {
    pub dynamic: bool, // ET_DYN: loaded at a random base
    pub entry: u64,
    pub segs: [Segment; MAX_SEGMENTS],
    pub nseg: usize,
    pub lo: u64, // page-aligned span of all segments
    pub hi: u64,
    pub relro: Option<(u64, u64)>, // page-aligned range made read-only after relocation
    /// GNU_PROPERTY_X86_FEATURE_1_AND (FEATURE_1_*; 0 without the note or with a bad one).
    pub x86_features: u32,
    rela: Option<(u64, u64)>,      // (file offset, count)
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

fn read<S: Source + ?Sized>(src: &S, off: u64, buf: &mut [u8]) -> R<()> {
    let end = off.checked_add(buf.len() as u64).ok_or(ElfError::Truncated)?;
    if end > src.size() || !src.read(off, buf) {
        return Err(ElfError::Truncated);
    }
    Ok(())
}

/// Parse and validate. `user_lo..user_hi`: where an ET_EXEC image may live.
pub fn parse<S: Source + ?Sized>(src: &S, user_lo: u64, user_hi: u64) -> R<Image> {
    let size = src.size();
    if size > MAX_IMAGE {
        return Err(ElfError::Unsupported("image larger than 64 MiB"));
    }
    let mut h = [0u8; 64];
    read(src, 0, &mut h)?;
    if h[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(ElfError::BadHeader("not an ELF file"));
    }
    if h[4] != 2 || h[5] != 1 || h[6] != 1 {
        return Err(ElfError::BadHeader("not ELF64 little-endian version 1"));
    }
    let e_type = u16_at(&h, 16);
    let dynamic = match e_type {
        2 => false,
        3 => true,
        _ => return Err(ElfError::BadHeader("not an executable (ET_EXEC/ET_DYN)")),
    };
    if u16_at(&h, 18) != 62 || u32_at(&h, 20) != 1 {
        return Err(ElfError::BadHeader("not x86-64"));
    }
    let entry = u64_at(&h, 24);
    let phoff = u64_at(&h, 32);
    let phentsize = u16_at(&h, 54);
    let phnum = u16_at(&h, 56);
    if phentsize != 56 || phnum == 0 || phnum > MAX_PHNUM {
        return Err(ElfError::BadHeader("bad program header table"));
    }

    let mut img = Image {
        dynamic,
        entry,
        segs: [Segment::default(); MAX_SEGMENTS],
        nseg: 0,
        lo: 0,
        hi: 0,
        relro: None,
        x86_features: 0,
        rela: None,
    };
    let mut dyn_seg: Option<(u64, u64)> = None;
    for i in 0..u64::from(phnum) {
        let mut p = [0u8; 56];
        let at = phoff.checked_add(i * 56).ok_or(ElfError::Truncated)?;
        read(src, at, &mut p)?;
        let (ty, flags) = (u32_at(&p, 0), u32_at(&p, 4));
        let (offset, vaddr, filesz, memsz) = (u64_at(&p, 8), u64_at(&p, 16), u64_at(&p, 32), u64_at(&p, 40));
        match ty {
            PT_LOAD => {
                if memsz == 0 {
                    continue;
                }
                if img.nseg == MAX_SEGMENTS {
                    return Err(ElfError::Unsupported("more than 16 PT_LOAD segments"));
                }
                if filesz > memsz {
                    return Err(ElfError::Malformed("PT_LOAD filesz > memsz"));
                }
                let fend = offset.checked_add(filesz).ok_or(ElfError::Malformed("PT_LOAD offset overflow"))?;
                if fend > size {
                    return Err(ElfError::Malformed("PT_LOAD outside the file"));
                }
                if vaddr % PAGE != offset % PAGE {
                    return Err(ElfError::Malformed("PT_LOAD offset and address not page-congruent"));
                }
                let vend = vaddr.checked_add(memsz).ok_or(ElfError::Malformed("PT_LOAD address overflow"))?;
                if vend.checked_add(PAGE).is_none() {
                    return Err(ElfError::Malformed("PT_LOAD address overflow"));
                }
                if flags & PF_W != 0 && flags & PF_X != 0 {
                    return Err(ElfError::Unsupported("writable and executable segment (W^X)"));
                }
                if flags & (PF_R | PF_W | PF_X) == 0 {
                    return Err(ElfError::Malformed("PT_LOAD without permissions"));
                }
                let s = Segment { vaddr, memsz, offset, filesz, flags };
                if img.nseg > 0 && img.segs[img.nseg - 1].page_end() > s.page_start() {
                    return Err(ElfError::Malformed("PT_LOAD segments out of order or sharing a page"));
                }
                img.segs[img.nseg] = s;
                img.nseg += 1;
            }
            PT_DYNAMIC => {
                if dyn_seg.is_some() {
                    return Err(ElfError::Malformed("two PT_DYNAMIC"));
                }
                if offset.checked_add(filesz).is_none_or(|e| e > size) || filesz % 16 != 0 {
                    return Err(ElfError::Malformed("PT_DYNAMIC outside the file"));
                }
                dyn_seg = Some((offset, filesz));
            }
            PT_INTERP => return Err(ElfError::Unsupported("needs a dynamic linker (PT_INTERP)")),
            PT_SHLIB => return Err(ElfError::Unsupported("PT_SHLIB")),
            PT_TLS => return Err(ElfError::Unsupported("thread-local storage (PT_TLS)")),
            PT_GNU_STACK => {
                if flags & PF_X != 0 {
                    return Err(ElfError::Unsupported("executable stack requested"));
                }
            }
            PT_GNU_RELRO => {
                let end = vaddr.checked_add(memsz).ok_or(ElfError::Malformed("PT_GNU_RELRO overflow"))?;
                img.relro = Some((vaddr, end));
            }
            PT_GNU_PROPERTY => img.x86_features = x86_features(src, offset, filesz),
            _ => {} // PT_NULL, PT_NOTE, PT_PHDR, PT_GNU_EH_FRAME, ...
        }
    }
    if img.nseg == 0 {
        return Err(ElfError::Malformed("no PT_LOAD segment"));
    }
    img.lo = img.segs[0].page_start();
    img.hi = img.segs[img.nseg - 1].page_end();
    if img.hi - img.lo > MAX_SPAN {
        return Err(ElfError::Unsupported("image spans more than 1 GiB"));
    }
    if !dynamic && (img.lo < user_lo || img.hi > user_hi) {
        return Err(ElfError::Malformed("ET_EXEC outside the user address range"));
    }
    let in_exec = img.segs[..img.nseg]
        .iter()
        .any(|s| s.flags & PF_X != 0 && entry >= s.vaddr && entry < s.vaddr + s.memsz);
    if !in_exec {
        return Err(ElfError::Malformed("entry point not in an executable segment"));
    }
    // RELRO: shrink to whole pages inside one segment; outside that it is ignored (still safe:
    // the pages just stay as the segment says).
    img.relro = img.relro.and_then(|(s, e)| {
        let (s, e) = (s.checked_next_multiple_of(PAGE)?, e & !(PAGE - 1));
        let seg = img.segs[..img.nseg].iter().find(|g| s >= g.page_start() && e <= g.page_end())?;
        (s < e && seg.flags & PF_W != 0).then_some((s, e))
    });
    if let Some((off, len)) = dyn_seg {
        img.rela = parse_dynamic(src, &img, off, len)?;
    }
    Ok(img)
}

/// The x86 feature bits of a PT_GNU_PROPERTY segment (`.note.gnu.property`): notes of type
/// NT_GNU_PROPERTY_TYPE_0 named "GNU", each a list of (type, size, data) properties padded to
/// 8 bytes. Anything malformed counts as no features (shadow stacks stay off: fail closed).
fn x86_features<S: Source + ?Sized>(src: &S, off: u64, len: u64) -> u32 {
    if len > MAX_PROPERTY || off.checked_add(len).is_none_or(|e| e > src.size()) {
        return 0;
    }
    let mut b = [0u8; MAX_PROPERTY as usize];
    let b = &mut b[..len as usize];
    if !src.read(off, b) {
        return 0;
    }
    let mut at = 0usize;
    while at + 12 <= b.len() {
        let (namesz, descsz, ty) = (u32_at(b, at) as usize, u32_at(b, at + 4) as usize, u32_at(b, at + 8));
        let name = at + 12;
        let desc = name + namesz.next_multiple_of(4); // u32 sizes: no overflow in a usize
        let Some(end) = desc.checked_add(descsz).filter(|&e| e <= b.len()) else { return 0 };
        if ty == NT_GNU_PROPERTY_TYPE_0 && namesz == 4 && b.get(name..name + 4) == Some(b"GNU\0") {
            let mut p = desc;
            while p + 8 <= end {
                let (pt, sz) = (u32_at(b, p), u32_at(b, p + 4) as usize);
                let data = p + 8;
                if data + sz > end {
                    return 0;
                }
                if pt == GNU_PROPERTY_X86_FEATURE_1_AND {
                    return if sz == 4 { u32_at(b, data) } else { 0 };
                }
                p = data + sz.next_multiple_of(8);
            }
        }
        at = end.next_multiple_of(8);
    }
    0
}

/// File offset of [vaddr, vaddr+len) if it lies in the file part of one segment.
fn file_offset(img: &Image, vaddr: u64, len: u64) -> Option<u64> {
    let end = vaddr.checked_add(len)?;
    img.segs[..img.nseg]
        .iter()
        .find(|s| vaddr >= s.vaddr && end <= s.vaddr + s.filesz)
        .map(|s| s.offset + (vaddr - s.vaddr))
}

fn parse_dynamic<S: Source + ?Sized>(src: &S, img: &Image, off: u64, len: u64) -> R<Option<(u64, u64)>> {
    let (mut rela, mut relasz, mut relaent) = (None, 0u64, 24u64);
    let n = (len / 16).min(MAX_DYN);
    for i in 0..n {
        let mut d = [0u8; 16];
        read(src, off + i * 16, &mut d)?;
        let (tag, val) = (u64_at(&d, 0) as i64, u64_at(&d, 8));
        match tag {
            DT_NULL => break,
            DT_NEEDED => return Err(ElfError::Unsupported("needs shared libraries (DT_NEEDED)")),
            DT_PLTRELSZ | DT_RELSZ | DT_RELRSZ if val != 0 => {
                return Err(ElfError::Unsupported("PLT, REL or RELR relocations"));
            }
            DT_TEXTREL => return Err(ElfError::Unsupported("text relocations")),
            DT_FLAGS if val & DF_TEXTREL != 0 => return Err(ElfError::Unsupported("text relocations")),
            DT_RELA => rela = Some(val),
            DT_RELASZ => relasz = val,
            DT_RELAENT => relaent = val,
            _ => {}
        }
    }
    if relasz == 0 {
        return Ok(None);
    }
    if relaent != 24 || relasz % 24 != 0 || relasz / 24 > MAX_RELOCS {
        return Err(ElfError::Malformed("bad RELA table"));
    }
    let at = rela.ok_or(ElfError::Malformed("DT_RELASZ without DT_RELA"))?;
    let foff = file_offset(img, at, relasz).ok_or(ElfError::Malformed("RELA table outside the file"))?;
    Ok(Some((foff, relasz / 24)))
}

impl Image {
    /// Visit every relocation as (segment index, offset from the segment's first page, value)
    /// for an image loaded `bias` bytes above its link address. Fails on anything but
    /// R_X86_64_RELATIVE/NONE or a target that is not 8 bytes inside one segment.
    pub fn relocations<S: Source + ?Sized>(
        &self,
        src: &S,
        bias: u64,
        mut apply: impl FnMut(usize, u64, u64) -> bool,
    ) -> R<u64> {
        let Some((off, count)) = self.rela else { return Ok(0) };
        for i in 0..count {
            let mut r = [0u8; 24];
            read(src, off + i * 24, &mut r)?;
            let (at, info, addend) = (u64_at(&r, 0), u64_at(&r, 8), u64_at(&r, 16));
            match (info & 0xFFFF_FFFF) as u32 {
                R_X86_64_NONE => continue,
                R_X86_64_RELATIVE if info >> 32 == 0 => {}
                _ => return Err(ElfError::Unsupported("relocation other than R_X86_64_RELATIVE")),
            }
            let seg = self.segs[..self.nseg]
                .iter()
                .position(|s| at >= s.vaddr && at.checked_add(8).is_some_and(|e| e <= s.vaddr + s.memsz))
                .ok_or(ElfError::Malformed("relocation outside the segments"))?;
            let value = bias.wrapping_add(addend);
            if !apply(seg, at - self.segs[seg].page_start(), value) {
                return Err(ElfError::Malformed("relocation could not be applied"));
            }
        }
        Ok(count)
    }
}
