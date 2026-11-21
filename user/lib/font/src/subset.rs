//! TrueType subsetting (`dbuild font-subset`): keep the glyphs of a set of characters (and the
//! components they use), renumbered, in a minimal valid font: `cmap` (formats 4 and 12), `glyf`,
//! `loca` (long), `hmtx`, `head`, `hhea`, `maxp`, `OS/2`, `name` and `post` (format 3, no glyph
//! names). Hinting and layout tables are dropped: D-OS never runs hinting, and the monospace face
//! needs no kerning or substitutions.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ttf::{Font, FontError, find_table, i16_at, u16_at};

const COMPOSITE_MORE: u16 = 0x0020;
const ARG_WORDS: u16 = 0x0001;
const HAVE_SCALE: u16 = 0x0008;
const XY_SCALE: u16 = 0x0040;
const TWO_BY_TWO: u16 = 0x0080;

/// Glyph ids a composite glyph's data refers to, with the byte offset of each id.
fn components(d: &[u8]) -> Vec<(usize, u16)> {
    let mut out = Vec::new();
    if i16_at(d, 0).is_none_or(|c| c >= 0) {
        return out;
    }
    let mut p = 10;
    for _ in 0..64 {
        let (Some(flags), Some(g)) = (u16_at(d, p), u16_at(d, p + 2)) else { break };
        out.push((p + 2, g));
        p += 4 + if flags & ARG_WORDS != 0 { 4 } else { 2 };
        p += if flags & HAVE_SCALE != 0 {
            2
        } else if flags & XY_SCALE != 0 {
            4
        } else if flags & TWO_BY_TWO != 0 {
            8
        } else {
            0
        };
        if flags & COMPOSITE_MORE == 0 {
            break;
        }
    }
    out
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn checksum(d: &[u8]) -> u32 {
    let mut s = 0u32;
    for c in d.chunks(4) {
        let mut b = [0u8; 4];
        b[..c.len()].copy_from_slice(c);
        s = s.wrapping_add(u32::from_be_bytes(b));
    }
    s
}

/// A subset of `data` keeping the characters for which `keep` is true. Returns the new font and
/// the number of glyphs in it.
pub fn subset(data: &[u8], keep: impl Fn(u32) -> bool) -> Result<(Vec<u8>, usize), FontError> {
    let font = Font::parse(data)?;
    let mal = FontError::Malformed;
    // Characters kept and their old glyphs.
    let mut map: BTreeMap<u32, u16> = BTreeMap::new();
    for cp in 0u32..=0x10FFFF {
        if !keep(cp) {
            continue;
        }
        let Some(c) = char::from_u32(cp) else { continue };
        let g = font.glyph_index(c);
        if g != 0 {
            map.insert(cp, g);
        }
    }
    // The glyph closure (components too), always with .notdef first.
    let mut want: Vec<bool> = alloc::vec![false; usize::from(font.num_glyphs())];
    want[0] = true;
    let mut stack: Vec<u16> = map.values().copied().collect();
    while let Some(g) = stack.pop() {
        if want[usize::from(g)] && g != 0 {
            continue;
        }
        want[usize::from(g)] = true;
        if let Some(d) = font.glyph_data(g) {
            for (_, c) in components(d) {
                if usize::from(c) < want.len() && !want[usize::from(c)] {
                    stack.push(c);
                }
            }
        }
    }
    let old: Vec<u16> = want.iter().enumerate().filter(|(_, w)| **w).map(|(i, _)| i as u16).collect();
    let mut new_of: Vec<u16> = alloc::vec![0; want.len()];
    for (n, &o) in old.iter().enumerate() {
        new_of[usize::from(o)] = n as u16;
    }
    let count = old.len();

    // glyf + loca (long).
    let mut glyf = Vec::new();
    let mut loca = Vec::new();
    for &o in &old {
        put32(&mut loca, glyf.len() as u32);
        let d = font.glyph_data(o).ok_or(mal("glyf"))?;
        let start = glyf.len();
        glyf.extend_from_slice(d);
        for (off, c) in components(d) {
            let n = new_of.get(usize::from(c)).copied().unwrap_or(0);
            glyf[start + off..start + off + 2].copy_from_slice(&n.to_be_bytes());
        }
        while glyf.len() % 4 != 0 {
            glyf.push(0);
        }
    }
    put32(&mut loca, glyf.len() as u32);

    // hmtx: full metrics for every glyph.
    let hmtx_t = find_table(data, b"hmtx").ok_or(FontError::MissingTable("hmtx"))?;
    let hhea_t = find_table(data, b"hhea").ok_or(FontError::MissingTable("hhea"))?;
    let num_h = u16_at(hhea_t, 34).ok_or(mal("hhea"))?;
    let mut hmtx = Vec::new();
    for &o in &old {
        let adv = font.advance(o);
        let lsb = if o < num_h {
            i16_at(hmtx_t, usize::from(o) * 4 + 2)
        } else {
            i16_at(hmtx_t, usize::from(num_h) * 4 + usize::from(o - num_h) * 2)
        }
        .unwrap_or(0);
        put16(&mut hmtx, adv);
        put16(&mut hmtx, lsb as u16);
    }

    // cmap: format 4 (BMP, when it fits) and format 12, both Windows Unicode.
    let pairs: Vec<(u32, u16)> = map.iter().map(|(&c, &g)| (c, new_of[usize::from(g)])).collect();
    let mut groups: Vec<(u32, u32, u16)> = Vec::new();
    for &(c, g) in &pairs {
        match groups.last_mut() {
            Some(last) if last.1 + 1 == c && u32::from(last.2) + (c - last.0) == u32::from(g) => last.1 = c,
            _ => groups.push((c, c, g)),
        }
    }
    let mut f12 = Vec::new();
    put16(&mut f12, 12);
    put16(&mut f12, 0);
    put32(&mut f12, (16 + groups.len() * 12) as u32);
    put32(&mut f12, 0);
    put32(&mut f12, groups.len() as u32);
    for &(s, e, g) in &groups {
        put32(&mut f12, s);
        put32(&mut f12, e);
        put32(&mut f12, u32::from(g));
    }
    let mut segs: Vec<(u16, u16, u16)> = groups.iter().filter(|g| g.0 <= 0xFFFF).map(|&(s, e, g)| (s as u16, e.min(0xFFFE) as u16, g)).collect();
    segs.push((0xFFFF, 0xFFFF, 0)); // terminator: idDelta 1, 0xFFFF maps to glyph 0
    let f4_len = 16 + segs.len() * 8;
    let mut f4 = Vec::new();
    if f4_len <= 0xFFFF {
        let n = segs.len() as u16;
        let mut pow = 1u16;
        let mut log = 0u16;
        while pow * 2 <= n {
            pow *= 2;
            log += 1;
        }
        put16(&mut f4, 4);
        put16(&mut f4, f4_len as u16);
        put16(&mut f4, 0);
        put16(&mut f4, n * 2);
        put16(&mut f4, pow * 2);
        put16(&mut f4, log);
        put16(&mut f4, n * 2 - pow * 2);
        segs.iter().for_each(|s| put16(&mut f4, s.1));
        put16(&mut f4, 0);
        segs.iter().for_each(|s| put16(&mut f4, s.0));
        segs.iter().for_each(|s| put16(&mut f4, s.2.wrapping_sub(s.0)));
        segs.iter().for_each(|_| put16(&mut f4, 0));
    }
    let mut cmap = Vec::new();
    let subs: u16 = if f4.is_empty() { 1 } else { 2 };
    put16(&mut cmap, 0);
    put16(&mut cmap, subs);
    let first = 4 + usize::from(subs) * 8;
    if !f4.is_empty() {
        put16(&mut cmap, 3);
        put16(&mut cmap, 1);
        put32(&mut cmap, first as u32);
    }
    put16(&mut cmap, 3);
    put16(&mut cmap, 10);
    put32(&mut cmap, (first + f4.len()) as u32);
    cmap.extend_from_slice(&f4);
    cmap.extend_from_slice(&f12);

    // head (long loca, checksum adjustment cleared), hhea, maxp: copied and patched.
    let mut head = find_table(data, b"head").ok_or(FontError::MissingTable("head"))?.to_vec();
    if head.len() < 54 {
        return Err(mal("head"));
    }
    head[8..12].copy_from_slice(&[0; 4]);
    head[50..52].copy_from_slice(&1u16.to_be_bytes());
    let mut hhea = hhea_t.to_vec();
    if hhea.len() < 36 {
        return Err(mal("hhea"));
    }
    hhea[34..36].copy_from_slice(&(count as u16).to_be_bytes());
    let mut maxp = find_table(data, b"maxp").ok_or(FontError::MissingTable("maxp"))?.to_vec();
    if maxp.len() < 6 {
        return Err(mal("maxp"));
    }
    maxp[4..6].copy_from_slice(&(count as u16).to_be_bytes());
    let mut post = find_table(data, b"post").map(|p| p.get(..32).unwrap_or(p).to_vec()).unwrap_or_else(|| alloc::vec![0; 32]);
    post.resize(32, 0);
    post[0..4].copy_from_slice(&0x0003_0000u32.to_be_bytes());

    let mut tables: Vec<([u8; 4], Vec<u8>)> = alloc::vec![
        (*b"cmap", cmap),
        (*b"glyf", glyf),
        (*b"head", head),
        (*b"hhea", hhea),
        (*b"hmtx", hmtx),
        (*b"loca", loca),
        (*b"maxp", maxp),
        (*b"post", post),
    ];
    for tag in [b"OS/2", b"name"] {
        if let Some(t) = find_table(data, tag) {
            tables.push((*tag, t.to_vec()));
        }
    }
    tables.sort_by_key(|a| a.0);

    // Assemble: directory, then each table 4-byte aligned.
    let n = tables.len() as u16;
    let mut pow = 1u16;
    let mut log = 0u16;
    while pow * 2 <= n {
        pow *= 2;
        log += 1;
    }
    let mut out = Vec::new();
    put32(&mut out, 0x0001_0000);
    put16(&mut out, n);
    put16(&mut out, pow * 16);
    put16(&mut out, log);
    put16(&mut out, n * 16 - pow * 16);
    let mut off = 12 + usize::from(n) * 16;
    let mut head_off = 0;
    for (tag, t) in &tables {
        out.extend_from_slice(tag);
        put32(&mut out, checksum(t));
        put32(&mut out, off as u32);
        put32(&mut out, t.len() as u32);
        if tag == b"head" {
            head_off = off;
        }
        off += t.len().div_ceil(4) * 4;
    }
    for (_, t) in &tables {
        out.extend_from_slice(t);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    let adj = 0xB1B0_AFBAu32.wrapping_sub(checksum(&out));
    out[head_off + 8..head_off + 12].copy_from_slice(&adj.to_be_bytes());
    // The result must parse again.
    Font::parse(&out)?;
    Ok((out, count))
}
