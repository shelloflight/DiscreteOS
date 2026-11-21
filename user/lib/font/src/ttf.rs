//! TrueType (`glyf`) font parsing: every read is bounds-checked, every offset and count is
//! validated against the data before use, and nothing panics on malformed input.
//!
//! Supported: the table directory, `head`, `maxp`, `hhea`, `hmtx`, `OS/2` (x-height, cap height),
//! `cmap` (formats 4 and 12), `loca` (short and long) and `glyf` (see `glyph.rs`), and pair
//! kerning from `GPOS` (lookup type 2, formats 1 and 2, also through extension lookups) or the
//! legacy `kern` table (format 0). CFF outlines (`OTTO`) are refused: D-OS ships TrueType only.
//! Hinting bytecode (`fpgm`, `prep`, glyph instructions) is never run.

/// Why a font was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FontError {
    /// Not a TrueType font (bad magic, or CFF outlines).
    NotTrueType,
    /// A required table is missing.
    MissingTable(&'static str),
    /// A table is too short or a field is out of range.
    Malformed(&'static str),
}

pub(crate) fn u8_at(d: &[u8], off: usize) -> Option<u8> {
    d.get(off).copied()
}

pub(crate) fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    let b = d.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

pub(crate) fn i16_at(d: &[u8], off: usize) -> Option<i16> {
    u16_at(d, off).map(|v| v as i16)
}

pub(crate) fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    let b = d.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// The slice `d[off..off + len]`, if it is inside `d`.
pub(crate) fn slice(d: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    d.get(off..off.checked_add(len)?)
}

/// The table `tag` from the directory: (offset, length) checked against the file.
pub(crate) fn find_table<'a>(data: &'a [u8], tag: &[u8; 4]) -> Option<&'a [u8]> {
    let n = usize::from(u16_at(data, 4)?);
    for i in 0..n.min(64) {
        let rec = 12 + i * 16;
        let t = slice(data, rec, 4)?;
        if t == tag {
            let off = u32_at(data, rec + 8)? as usize;
            let len = u32_at(data, rec + 12)? as usize;
            return slice(data, off, len);
        }
    }
    None
}

#[derive(Clone, Copy)]
enum CmapKind {
    Format4,
    Format12,
}

/// Where the pair-kerning data is.
#[derive(Clone, Copy)]
enum Kerning<'a> {
    None,
    /// `GPOS` with up to `MAX_PAIR_SUBTABLES` PairPos subtables (offsets into the table).
    Gpos { table: &'a [u8], subs: [u32; MAX_PAIR_SUBTABLES], n: usize },
    /// `kern` format 0: `nPairs` sorted (left, right, value) records.
    Kern { pairs: &'a [u8], n: usize },
}

const MAX_PAIR_SUBTABLES: usize = 32;

/// A parsed TrueType font borrowing its file data. Cheap to copy.
#[derive(Clone, Copy)]
pub struct Font<'a> {
    pub(crate) units_per_em: u16,
    pub(crate) long_loca: bool,
    pub(crate) num_glyphs: u16,
    /// `hhea` ascender / descender / line gap (font units; descender negative).
    pub ascender: i16,
    pub descender: i16,
    pub line_gap: i16,
    /// `OS/2` x-height and cap height (0 when the font does not say).
    pub x_height: i16,
    pub cap_height: i16,
    num_hmetrics: u16,
    hmtx: &'a [u8],
    pub(crate) loca: &'a [u8],
    pub(crate) glyf: &'a [u8],
    cmap: &'a [u8],
    cmap_kind: CmapKind,
    kerning: Kerning<'a>,
}

impl<'a> Font<'a> {
    /// Parse and validate a TrueType font. Every table used later is checked here once.
    pub fn parse(data: &'a [u8]) -> Result<Font<'a>, FontError> {
        let magic = u32_at(data, 0).ok_or(FontError::NotTrueType)?;
        if magic != 0x0001_0000 && magic != u32::from_be_bytes(*b"true") {
            return Err(FontError::NotTrueType);
        }
        let head = find_table(data, b"head").ok_or(FontError::MissingTable("head"))?;
        let maxp = find_table(data, b"maxp").ok_or(FontError::MissingTable("maxp"))?;
        let hhea = find_table(data, b"hhea").ok_or(FontError::MissingTable("hhea"))?;
        let hmtx = find_table(data, b"hmtx").ok_or(FontError::MissingTable("hmtx"))?;
        let loca = find_table(data, b"loca").ok_or(FontError::MissingTable("loca"))?;
        let glyf = find_table(data, b"glyf").ok_or(FontError::MissingTable("glyf"))?;
        let cmap_t = find_table(data, b"cmap").ok_or(FontError::MissingTable("cmap"))?;

        let units_per_em = u16_at(head, 18).ok_or(FontError::Malformed("head"))?;
        if !(16..=16384).contains(&units_per_em) {
            return Err(FontError::Malformed("head.unitsPerEm"));
        }
        let long_loca = match i16_at(head, 50).ok_or(FontError::Malformed("head"))? {
            0 => false,
            1 => true,
            _ => return Err(FontError::Malformed("head.indexToLocFormat")),
        };
        let num_glyphs = u16_at(maxp, 4).ok_or(FontError::Malformed("maxp"))?;
        if num_glyphs == 0 {
            return Err(FontError::Malformed("maxp.numGlyphs"));
        }
        let ascender = i16_at(hhea, 4).ok_or(FontError::Malformed("hhea"))?;
        let descender = i16_at(hhea, 6).ok_or(FontError::Malformed("hhea"))?;
        let line_gap = i16_at(hhea, 8).ok_or(FontError::Malformed("hhea"))?;
        let num_hmetrics = u16_at(hhea, 34).ok_or(FontError::Malformed("hhea"))?;
        if num_hmetrics == 0 || num_hmetrics > num_glyphs {
            return Err(FontError::Malformed("hhea.numberOfHMetrics"));
        }
        let need_hmtx = usize::from(num_hmetrics) * 4 + usize::from(num_glyphs - num_hmetrics) * 2;
        if hmtx.len() < need_hmtx {
            return Err(FontError::Malformed("hmtx"));
        }
        let loca_entry = if long_loca { 4 } else { 2 };
        if loca.len() < (usize::from(num_glyphs) + 1) * loca_entry {
            return Err(FontError::Malformed("loca"));
        }
        let (mut x_height, mut cap_height) = (0, 0);
        if let Some(os2) = find_table(data, b"OS/2")
            && u16_at(os2, 0).is_some_and(|v| v >= 2)
        {
            x_height = i16_at(os2, 86).unwrap_or(0).max(0);
            cap_height = i16_at(os2, 88).unwrap_or(0).max(0);
        }
        let (cmap, cmap_kind) = pick_cmap(cmap_t).ok_or(FontError::Malformed("cmap"))?;
        let mut font = Font {
            units_per_em,
            long_loca,
            num_glyphs,
            ascender,
            descender,
            line_gap,
            x_height,
            cap_height,
            num_hmetrics,
            hmtx,
            loca,
            glyf,
            cmap,
            cmap_kind,
            kerning: Kerning::None,
        };
        font.kerning = match find_table(data, b"GPOS").and_then(gpos_pair_subtables) {
            Some(k) => k,
            None => find_table(data, b"kern").and_then(kern_pairs).unwrap_or(Kerning::None),
        };
        Ok(font)
    }

    pub fn units_per_em(&self) -> u16 {
        self.units_per_em
    }

    pub fn num_glyphs(&self) -> u16 {
        self.num_glyphs
    }

    /// The glyph for a character (0, `.notdef`, when the font has none).
    pub fn glyph_index(&self, c: char) -> u16 {
        let cp = c as u32;
        let g = match self.cmap_kind {
            CmapKind::Format4 => cmap4_lookup(self.cmap, cp),
            CmapKind::Format12 => cmap12_lookup(self.cmap, cp),
        }
        .unwrap_or(0);
        if g < self.num_glyphs { g } else { 0 }
    }

    /// Horizontal advance of a glyph (font units).
    pub fn advance(&self, g: u16) -> u16 {
        let i = usize::from(g.min(self.num_hmetrics - 1));
        u16_at(self.hmtx, i * 4).unwrap_or(0)
    }

    /// The glyph's outline data in `glyf` (empty for blank glyphs such as the space).
    pub(crate) fn glyph_data(&self, g: u16) -> Option<&'a [u8]> {
        if g >= self.num_glyphs {
            return None;
        }
        let i = usize::from(g);
        let (start, end) = if self.long_loca {
            (u32_at(self.loca, i * 4)? as usize, u32_at(self.loca, i * 4 + 4)? as usize)
        } else {
            (usize::from(u16_at(self.loca, i * 2)?) * 2, usize::from(u16_at(self.loca, i * 2 + 2)?) * 2)
        };
        if end < start {
            return None;
        }
        self.glyf.get(start..end)
    }

    /// Pair kerning between two glyphs (font units, usually negative).
    pub fn kerning(&self, left: u16, right: u16) -> i16 {
        match self.kerning {
            Kerning::None => 0,
            Kerning::Kern { pairs, n } => kern_lookup(pairs, n, left, right).unwrap_or(0),
            Kerning::Gpos { table, subs, n } => {
                for &off in &subs[..n] {
                    if let Some(v) = pair_pos(table, off as usize, left, right) {
                        return v;
                    }
                }
                0
            }
        }
    }

    pub fn has_kerning(&self) -> bool {
        !matches!(self.kerning, Kerning::None)
    }
}

// ---- cmap -------------------------------------------------------------------------------------

/// The best Unicode subtable: format 12 (full repertoire) before format 4 (BMP).
fn pick_cmap(t: &[u8]) -> Option<(&[u8], CmapKind)> {
    let n = usize::from(u16_at(t, 2)?);
    let mut best: Option<(&[u8], CmapKind, u8)> = None;
    for i in 0..n.min(64) {
        let rec = 4 + i * 8;
        let platform = u16_at(t, rec)?;
        let encoding = u16_at(t, rec + 2)?;
        let off = u32_at(t, rec + 4)? as usize;
        let unicode = platform == 0 || (platform == 3 && (encoding == 1 || encoding == 10));
        if !unicode {
            continue;
        }
        let Some(format) = u16_at(t, off) else { continue };
        let (len, kind, rank) = match format {
            4 => (usize::from(u16_at(t, off + 2)?), CmapKind::Format4, 1),
            12 => (u32_at(t, off + 4)? as usize, CmapKind::Format12, 2),
            _ => continue,
        };
        let Some(sub) = slice(t, off, len) else { continue };
        if !cmap_valid(sub, kind) {
            continue;
        }
        if best.is_none_or(|b| rank > b.2) {
            best = Some((sub, kind, rank));
        }
    }
    best.map(|(s, k, _)| (s, k))
}

fn cmap_valid(s: &[u8], kind: CmapKind) -> bool {
    match kind {
        CmapKind::Format4 => {
            let Some(seg_x2) = u16_at(s, 6) else { return false };
            let segs = usize::from(seg_x2 / 2);
            segs > 0 && seg_x2 % 2 == 0 && s.len() >= 16 + segs * 8
        }
        CmapKind::Format12 => {
            let Some(n) = u32_at(s, 12) else { return false };
            (n as usize).checked_mul(12).and_then(|b| b.checked_add(16)).is_some_and(|need| s.len() >= need)
        }
    }
}

fn cmap4_lookup(s: &[u8], cp: u32) -> Option<u16> {
    if cp > 0xFFFF {
        return None;
    }
    let c = cp as u16;
    let segs = usize::from(u16_at(s, 6)? / 2);
    let ends = 14;
    let starts = ends + segs * 2 + 2;
    let deltas = starts + segs * 2;
    let ranges = deltas + segs * 2;
    // Binary search for the first segment whose end code is >= c.
    let (mut lo, mut hi) = (0usize, segs);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if u16_at(s, ends + mid * 2)? < c {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo >= segs {
        return None;
    }
    let start = u16_at(s, starts + lo * 2)?;
    if c < start {
        return None;
    }
    let delta = u16_at(s, deltas + lo * 2)?;
    let range = u16_at(s, ranges + lo * 2)?;
    if range == 0 {
        return Some(c.wrapping_add(delta));
    }
    let addr = ranges + lo * 2 + usize::from(range) + usize::from(c - start) * 2;
    let g = u16_at(s, addr)?;
    if g == 0 { Some(0) } else { Some(g.wrapping_add(delta)) }
}

fn cmap12_lookup(s: &[u8], cp: u32) -> Option<u16> {
    let n = u32_at(s, 12)? as usize;
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let g = 16 + mid * 12;
        let start = u32_at(s, g)?;
        let end = u32_at(s, g + 4)?;
        if cp < start {
            hi = mid;
        } else if cp > end {
            lo = mid + 1;
        } else {
            let first = u32_at(s, g + 8)?;
            let gid = first.checked_add(cp - start)?;
            return u16::try_from(gid).ok();
        }
    }
    None
}

// ---- kerning ----------------------------------------------------------------------------------

fn kern_pairs(t: &[u8]) -> Option<Kerning<'_>> {
    if u16_at(t, 0)? != 0 {
        return None; // the Apple variant is not used by fonts D-OS ships
    }
    let tables = u16_at(t, 2)?;
    let mut off = 4usize;
    for _ in 0..tables.min(8) {
        let len = usize::from(u16_at(t, off + 2)?);
        let coverage = u16_at(t, off + 4)?;
        let format = coverage >> 8;
        let horizontal = coverage & 1 != 0;
        let minimum = coverage & 2 != 0;
        if format == 0 && horizontal && !minimum {
            let n = usize::from(u16_at(t, off + 6)?);
            let pairs = slice(t, off + 14, n * 6)?;
            return Some(Kerning::Kern { pairs, n });
        }
        if len == 0 {
            break;
        }
        off = off.checked_add(len)?;
    }
    None
}

fn kern_lookup(pairs: &[u8], n: usize, left: u16, right: u16) -> Option<i16> {
    let key = u32::from(left) << 16 | u32::from(right);
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let k = u32_at(pairs, mid * 6)?;
        match k.cmp(&key) {
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
            core::cmp::Ordering::Equal => return i16_at(pairs, mid * 6 + 4),
        }
    }
    None
}

/// The PairPos subtables of the `kern` feature's lookups (offsets into the `GPOS` table).
fn gpos_pair_subtables(t: &[u8]) -> Option<Kerning<'_>> {
    if u16_at(t, 0)? != 1 {
        return None;
    }
    let features = usize::from(u16_at(t, 6)?);
    let lookups = usize::from(u16_at(t, 8)?);
    let feature_count = usize::from(u16_at(t, features)?);
    let lookup_count = usize::from(u16_at(t, lookups)?);
    let mut wanted = [false; 512];
    let mut any = false;
    for i in 0..feature_count.min(512) {
        let rec = features + 2 + i * 6;
        if slice(t, rec, 4)? != b"kern" {
            continue;
        }
        let f = features + usize::from(u16_at(t, rec + 4)?);
        let n = usize::from(u16_at(t, f + 2)?);
        for j in 0..n.min(64) {
            let li = usize::from(u16_at(t, f + 4 + j * 2)?);
            if li < wanted.len() && li < lookup_count {
                wanted[li] = true;
                any = true;
            }
        }
    }
    if !any {
        return None;
    }
    let mut subs = [0u32; MAX_PAIR_SUBTABLES];
    let mut n = 0;
    for (li, _) in wanted.iter().enumerate().filter(|(_, w)| **w) {
        let l = lookups + usize::from(u16_at(t, lookups + 2 + li * 2)?);
        let kind = u16_at(t, l)?;
        let count = usize::from(u16_at(t, l + 4)?);
        for s in 0..count.min(64) {
            let mut sub = l + usize::from(u16_at(t, l + 6 + s * 2)?);
            let mut k = kind;
            if k == 9 {
                // Extension: format 1, the real type and a 32-bit offset from this subtable.
                if u16_at(t, sub)? != 1 {
                    continue;
                }
                k = u16_at(t, sub + 2)?;
                sub = sub.checked_add(u32_at(t, sub + 4)? as usize)?;
            }
            if k == 2 && sub < t.len() && n < MAX_PAIR_SUBTABLES {
                subs[n] = sub as u32;
                n += 1;
            }
        }
    }
    (n > 0).then_some(Kerning::Gpos { table: t, subs, n })
}

/// Size of a ValueRecord with this format, and the offset of its XAdvance (if present).
fn value_record(format: u16) -> (usize, Option<usize>) {
    let size = (format & 0xFF).count_ones() as usize * 2;
    let x_adv = (format & 0x0004 != 0).then(|| (format & 0x0003).count_ones() as usize * 2);
    (size, x_adv)
}

fn coverage_index(t: &[u8], cov: usize, g: u16) -> Option<usize> {
    match u16_at(t, cov)? {
        1 => {
            let n = usize::from(u16_at(t, cov + 2)?);
            let (mut lo, mut hi) = (0usize, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let v = u16_at(t, cov + 4 + mid * 2)?;
                match v.cmp(&g) {
                    core::cmp::Ordering::Less => lo = mid + 1,
                    core::cmp::Ordering::Greater => hi = mid,
                    core::cmp::Ordering::Equal => return Some(mid),
                }
            }
            None
        }
        2 => {
            let n = usize::from(u16_at(t, cov + 2)?);
            let (mut lo, mut hi) = (0usize, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let r = cov + 4 + mid * 6;
                let (start, end) = (u16_at(t, r)?, u16_at(t, r + 2)?);
                if g < start {
                    hi = mid;
                } else if g > end {
                    lo = mid + 1;
                } else {
                    return Some(usize::from(u16_at(t, r + 4)?) + usize::from(g - start));
                }
            }
            None
        }
        _ => None,
    }
}

fn class_of(t: &[u8], cd: usize, g: u16) -> Option<u16> {
    match u16_at(t, cd)? {
        1 => {
            let start = u16_at(t, cd + 2)?;
            let n = u16_at(t, cd + 4)?;
            if g >= start && g - start < n { u16_at(t, cd + 6 + usize::from(g - start) * 2) } else { Some(0) }
        }
        2 => {
            let n = usize::from(u16_at(t, cd + 2)?);
            let (mut lo, mut hi) = (0usize, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let r = cd + 4 + mid * 6;
                let (start, end) = (u16_at(t, r)?, u16_at(t, r + 2)?);
                if g < start {
                    hi = mid;
                } else if g > end {
                    lo = mid + 1;
                } else {
                    return u16_at(t, r + 4);
                }
            }
            Some(0)
        }
        _ => None,
    }
}

/// The XAdvance adjustment of the first glyph of a pair from one PairPos subtable.
fn pair_pos(t: &[u8], sub: usize, left: u16, right: u16) -> Option<i16> {
    let format = u16_at(t, sub)?;
    let cov = sub + usize::from(u16_at(t, sub + 2)?);
    let vf1 = u16_at(t, sub + 4)?;
    let vf2 = u16_at(t, sub + 6)?;
    let (size1, xadv) = value_record(vf1);
    let (size2, _) = value_record(vf2);
    let xadv = xadv?;
    let idx = coverage_index(t, cov, left)?;
    match format {
        1 => {
            let sets = usize::from(u16_at(t, sub + 8)?);
            if idx >= sets {
                return None;
            }
            let set = sub + usize::from(u16_at(t, sub + 10 + idx * 2)?);
            let n = usize::from(u16_at(t, set)?);
            let rec = 2 + size1 + size2;
            let (mut lo, mut hi) = (0usize, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let r = set + 2 + mid * rec;
                let second = u16_at(t, r)?;
                match second.cmp(&right) {
                    core::cmp::Ordering::Less => lo = mid + 1,
                    core::cmp::Ordering::Greater => hi = mid,
                    core::cmp::Ordering::Equal => return i16_at(t, r + 2 + xadv),
                }
            }
            None
        }
        2 => {
            let cd1 = sub + usize::from(u16_at(t, sub + 8)?);
            let cd2 = sub + usize::from(u16_at(t, sub + 10)?);
            let c1n = usize::from(u16_at(t, sub + 12)?);
            let c2n = usize::from(u16_at(t, sub + 14)?);
            let c1 = usize::from(class_of(t, cd1, left)?);
            let c2 = usize::from(class_of(t, cd2, right)?);
            if c1 >= c1n || c2 >= c2n {
                return None;
            }
            let rec = size1 + size2;
            let r = sub + 16 + (c1 * c2n + c2) * rec;
            let v = i16_at(t, r + xadv)?;
            (v != 0).then_some(v)
        }
        _ => None,
    }
}
