//! Text: faces, a glyph image cache, measuring, drawing, caret positions and line wrapping.
//!
//! Layout is per character: the face's glyph for it (or the first fallback face that has one:
//! the sans faces fall back to the monospace one, which carries the symbols and icons, and back),
//! its advance and the pair kerning with the glyph before it in the same face. Pens are in 1/64
//! pixel; glyph images are cached per quarter-pixel horizontal phase, so proportional text keeps
//! its exact spacing. Vertical metrics are snapped to whole pixels at UI sizes (the x-height lands
//! on a pixel edge): the only "hinting" there is, and no font bytecode ever runs.

use alloc::vec::Vec;

use crate::glyph::{self, Outline, SUB, Scale};
use crate::raster::{Bitmap, Raster};
use crate::ttf::Font;

/// The faces D-OS ships (`sys:/fonts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Face {
    /// Inter Regular: interface text.
    Sans = 0,
    /// Inter Medium: title bars, buttons, emphasis.
    SansMedium = 1,
    /// Inter SemiBold: headings.
    SansSemiBold = 2,
    /// Iosevka Term Nerd Font Mono: the terminal, code, symbols and icons.
    Mono = 3,
}

pub const FACE_COUNT: usize = 4;

impl Face {
    pub const ALL: [Face; FACE_COUNT] = [Face::Sans, Face::SansMedium, Face::SansSemiBold, Face::Mono];

    pub const fn from_u8(v: u8) -> Face {
        match v {
            1 => Face::SansMedium,
            2 => Face::SansSemiBold,
            3 => Face::Mono,
            _ => Face::Sans,
        }
    }

    const fn fallbacks(self) -> [Face; 3] {
        match self {
            Face::Mono => [Face::Sans, Face::Sans, Face::Sans],
            Face::Sans => [Face::Mono, Face::Mono, Face::Mono],
            _ => [Face::Sans, Face::Mono, Face::Mono],
        }
    }
}

/// A face at a size (1/64 pixel: 13 px is 832).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    pub face: Face,
    pub size64: u32,
}

impl Style {
    pub const fn px(face: Face, px: u32) -> Style {
        Style { face, size64: px * 64 }
    }
}

/// Vertical metrics in whole pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LineMetrics {
    /// Baseline to the top of the line box.
    pub ascent: i32,
    /// Baseline to the bottom of the line box (positive).
    pub descent: i32,
    /// Distance between baselines.
    pub height: i32,
}

/// A 32-bpp pixel buffer to draw into (opaque `0xFFRRGGBB` destination).
pub struct Target<'a> {
    pub px: &'a mut [u32],
    pub w: u32,
    pub h: u32,
    pub stride: u32,
}

/// A clip rectangle `[x0, x1) x [y0, y1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clip {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
}

impl Clip {
    pub const fn new(x: i32, y: i32, w: u32, h: u32) -> Clip {
        Clip { x0: x, y0: y, x1: x.saturating_add(w as i32), y1: y.saturating_add(h as i32) }
    }
}

const CACHE_SLOTS: usize = 4096;
const CACHE_BYTES: usize = 3 << 20;

#[derive(Clone, Copy, Default)]
struct Slot {
    key: u64,
    off: u32,
    left: i16,
    top: i16,
    w: u16,
    h: u16,
}

/// Rendered glyph images by (face, glyph, size, phase); emptied when it fills up.
struct Cache {
    slots: Vec<Slot>,
    used: usize,
    pixels: Vec<u8>,
    pub hits: u64,
    pub misses: u64,
}

impl Cache {
    fn new() -> Cache {
        Cache { slots: alloc::vec![Slot::default(); CACHE_SLOTS], used: 0, pixels: Vec::new(), hits: 0, misses: 0 }
    }

    fn find(&self, key: u64) -> Result<usize, usize> {
        let mut i = (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 52) as usize % CACHE_SLOTS;
        loop {
            let s = &self.slots[i];
            if s.key == key {
                return Ok(i);
            }
            if s.key == 0 {
                return Err(i);
            }
            i = (i + 1) % CACHE_SLOTS;
        }
    }

    fn clear(&mut self) {
        self.slots.iter_mut().for_each(|s| *s = Slot::default());
        self.used = 0;
        self.pixels.clear();
    }
}

/// The text engine: faces (borrowed font files), the cache and scratch buffers.
pub struct Text<'a> {
    faces: [Option<Font<'a>>; FACE_COUNT],
    cache: Cache,
    outline: Outline,
    raster: Raster,
    bitmap: Bitmap,
}

/// One laid-out character: where it starts (byte index into the text, pen x in 1/64 px).
#[derive(Clone, Copy)]
struct Placed {
    face: usize,
    glyph: u16,
    pen: i64,
}

impl<'a> Default for Text<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Text<'a> {
    pub fn new() -> Text<'a> {
        Text { faces: [None; FACE_COUNT], cache: Cache::new(), outline: Outline::default(), raster: Raster::default(), bitmap: Bitmap::default() }
    }

    pub fn set_face(&mut self, face: Face, font: Font<'a>) {
        self.faces[face as usize] = Some(font);
        self.cache.clear();
    }

    pub fn has_face(&self, face: Face) -> bool {
        self.faces[face as usize].is_some()
    }

    /// Any face loaded at all (otherwise callers draw with a bitmap font instead).
    pub fn ready(&self) -> bool {
        self.faces.iter().any(Option::is_some)
    }

    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache.hits, self.cache.misses)
    }

    fn face_or_any(&self, f: Face) -> Option<(usize, &Font<'a>)> {
        let i = f as usize;
        if let Some(font) = &self.faces[i] {
            return Some((i, font));
        }
        for c in f.fallbacks() {
            if let Some(font) = &self.faces[c as usize] {
                return Some((c as usize, font));
            }
        }
        self.faces.iter().enumerate().find_map(|(i, f)| f.as_ref().map(|f| (i, f)))
    }

    /// The face and glyph that show `c` in `face` (fallbacks included); `.notdef` of the face
    /// itself when none has it.
    fn resolve(&self, face: Face, c: char) -> Option<(usize, u16)> {
        let (fi, font) = self.face_or_any(face)?;
        let g = font.glyph_index(c);
        if g != 0 || c == '\u{0}' {
            return Some((fi, g));
        }
        for alt in face.fallbacks() {
            if let Some(f) = &self.faces[alt as usize] {
                let g = f.glyph_index(c);
                if g != 0 {
                    return Some((alt as usize, g));
                }
            }
        }
        Some((fi, 0))
    }

    /// The vertical size (1/64 px) after snapping the x-height to whole pixels (sizes below 28 px).
    fn y_size(font: &Font<'_>, size64: u32) -> i64 {
        let s = i64::from(size64);
        let xh = i64::from(font.x_height);
        let upem = i64::from(font.units_per_em());
        if xh <= 0 || s >= 28 * 64 {
            return s;
        }
        let xh64 = xh * s / upem;
        let snapped = ((xh64 + 32) / 64 * 64).max(64);
        let y = s * snapped / xh64.max(1);
        // Never more than a ninth off the requested size.
        y.clamp(s * 8 / 9, s * 10 / 9)
    }

    /// Line metrics of a style (in the primary face; whole pixels).
    pub fn metrics(&self, style: Style) -> LineMetrics {
        let Some((_, font)) = self.face_or_any(style.face) else {
            let px = (style.size64 / 64) as i32;
            return LineMetrics { ascent: px, descent: px / 4, height: px + px / 4 };
        };
        let upem = i64::from(font.units_per_em());
        let ys = Self::y_size(font, style.size64);
        let up = |v: i64| ((v * ys / upem) + 63).div_euclid(64) as i32;
        let ascent = up(i64::from(font.ascender));
        let descent = up(-i64::from(font.descender)).max(0);
        let gap = up(i64::from(font.line_gap).max(0));
        LineMetrics { ascent, descent, height: ascent + descent + gap }
    }

    /// Advance of one character in 1/64 px (for a monospace grid: the cell width).
    pub fn advance64(&self, style: Style, c: char) -> i64 {
        match self.resolve(style.face, c) {
            Some((fi, g)) => self.faces[fi].as_ref().map_or(0, |f| i64::from(f.advance(g)) * i64::from(style.size64) / i64::from(f.units_per_em())),
            None => i64::from(style.size64) / 2,
        }
    }

    fn layout(&self, style: Style, text: &str, mut f: impl FnMut(usize, Placed)) -> i64 {
        let mut pen = 0i64;
        let mut prev: Option<(usize, u16)> = None;
        for (i, c) in text.char_indices() {
            let Some((fi, g)) = self.resolve(style.face, c) else { continue };
            let Some(font) = self.faces[fi].as_ref() else { continue };
            let upem = i64::from(font.units_per_em());
            let s = i64::from(style.size64);
            if let Some((pf, pg)) = prev
                && pf == fi
            {
                pen += i64::from(font.kerning(pg, g)) * s / upem;
            }
            f(i, Placed { face: fi, glyph: g, pen });
            pen += i64::from(font.advance(g)) * s / upem;
            prev = Some((fi, g));
        }
        pen
    }

    /// Width of `text` in whole pixels (rounded up).
    pub fn measure(&self, style: Style, text: &str) -> u32 {
        let w = self.layout(style, text, |_, _| {});
        ((w + 63) / 64).max(0) as u32
    }

    /// Pen x (1/64 px) before each character boundary: `out[i]` for byte index `i` of every
    /// character start and `text.len()` (for carets and hit-testing).
    pub fn caret_positions(&self, style: Style, text: &str, out: &mut Vec<(usize, i64)>) {
        out.clear();
        let end = self.layout(style, text, |i, p| out.push((i, p.pen)));
        out.push((text.len(), end));
    }

    /// Byte index of the character boundary nearest to `x` pixels.
    pub fn index_at(&self, style: Style, text: &str, x: i32) -> usize {
        let mut pos = Vec::new();
        self.caret_positions(style, text, &mut pos);
        let x64 = i64::from(x) * 64;
        let mut best = (0usize, i64::MAX);
        for &(i, p) in &pos {
            let d = (p - x64).abs();
            if d < best.1 {
                best = (i, d);
            }
        }
        best.0
    }

    /// Break `text` into lines at most `max_w` pixels wide (at spaces, or inside a word that does
    /// not fit alone); `\n` always breaks. Byte ranges of the lines, without the breaking spaces.
    pub fn wrap(&self, style: Style, text: &str, max_w: u32, out: &mut Vec<(usize, usize)>) {
        out.clear();
        let max64 = i64::from(max_w.max(1)) * 64;
        for (para_start, para) in split_inclusive_lines(text) {
            let mut pos = Vec::new();
            self.caret_positions(style, para, &mut pos);
            let mut line_start = 0usize;
            let mut start_pen = 0i64;
            let mut last_space: Option<usize> = None;
            let mut k = 0;
            while k + 1 < pos.len() {
                let (i, _) = pos[k];
                let (_, next_pen) = pos[k + 1];
                let c = para[i..].chars().next().unwrap_or(' ');
                if c == ' ' {
                    last_space = Some(k);
                }
                if next_pen - start_pen > max64 && i > line_start {
                    let (brk, resume) = match last_space {
                        Some(s) if pos[s].0 > line_start => (pos[s].0, s + 1),
                        _ => (i, k),
                    };
                    out.push((para_start + line_start, para_start + brk));
                    line_start = pos[resume].0;
                    start_pen = pos[resume].1;
                    last_space = None;
                    k = resume;
                    continue;
                }
                k += 1;
            }
            out.push((para_start + line_start, para_start + para.len()));
        }
    }

    fn glyph(&mut self, fi: usize, g: u16, size64: u32, phase: u32) -> Option<Slot> {
        let key = 1 | (fi as u64) << 1 | u64::from(g) << 4 | u64::from(size64 & 0xFF_FFFF) << 20 | u64::from(phase & 3) << 44;
        let slot = match self.cache.find(key) {
            Ok(i) => {
                self.cache.hits += 1;
                return Some(self.cache.slots[i]);
            }
            Err(i) => i,
        };
        self.cache.misses += 1;
        let font = self.faces[fi]?;
        let upem = i64::from(font.units_per_em());
        let ys = Self::y_size(&font, size64);
        let scale = Scale { sx: i64::from(size64) * 4, sy: ys * 4, den: upem, ox: i64::from(phase) * i64::from(SUB) / 4, oy: 0 };
        glyph::outline(&font, g, &scale, &mut self.outline);
        self.raster.render(&self.outline, &mut self.bitmap);
        let b = &self.bitmap;
        let bytes = b.data.len();
        if self.cache.used * 4 >= CACHE_SLOTS * 3 || self.cache.pixels.len() + bytes > CACHE_BYTES {
            self.cache.clear();
            return self.glyph(fi, g, size64, phase);
        }
        let s = Slot { key, off: self.cache.pixels.len() as u32, left: b.left as i16, top: b.top as i16, w: b.w as u16, h: b.h as u16 };
        self.cache.pixels.extend_from_slice(&b.data);
        self.cache.slots[slot] = s;
        self.cache.used += 1;
        Some(s)
    }

    /// Draw `text` with its baseline at `baseline` and its pen starting at `x` (pixels), clipped;
    /// stops past `max_x`. The pen advance in whole pixels.
    #[allow(clippy::too_many_arguments)]
    pub fn draw(&mut self, dst: &mut Target<'_>, clip: Clip, x: i32, baseline: i32, style: Style, text: &str, color: u32, max_x: i32) -> u32 {
        let mut placed: Vec<Placed> = Vec::with_capacity(text.len());
        let end = self.layout(style, text, |_, p| placed.push(p));
        let clip = Clip { x0: clip.x0.max(0), y0: clip.y0.max(0), x1: clip.x1.min(dst.w as i32).min(max_x), y1: clip.y1.min(dst.h as i32) };
        if clip.x0 >= clip.x1 || clip.y0 >= clip.y1 {
            return ((end + 63) / 64) as u32;
        }
        for p in placed {
            let pen = i64::from(x) * 64 + p.pen;
            let px = pen.div_euclid(64) as i32;
            if px > clip.x1 {
                break;
            }
            let phase = (pen.rem_euclid(64) / 16) as u32;
            let Some(s) = self.glyph(p.face, p.glyph, style.size64, phase) else { continue };
            blit(dst, clip, px + i32::from(s.left), baseline + i32::from(s.top), &s, &self.cache.pixels, color);
        }
        ((end + 63) / 64) as u32
    }

    /// Draw one character in a monospace cell whose left edge is `x` (no kerning, whole-pixel position).
    #[allow(clippy::too_many_arguments)]
    pub fn draw_char(&mut self, dst: &mut Target<'_>, clip: Clip, x: i32, baseline: i32, style: Style, c: char, color: u32) {
        let Some((fi, g)) = self.resolve(style.face, c) else { return };
        let clip = Clip { x0: clip.x0.max(0), y0: clip.y0.max(0), x1: clip.x1.min(dst.w as i32), y1: clip.y1.min(dst.h as i32) };
        if clip.x0 >= clip.x1 || clip.y0 >= clip.y1 {
            return;
        }
        if let Some(s) = self.glyph(fi, g, style.size64, 0) {
            blit(dst, clip, x + i32::from(s.left), baseline + i32::from(s.top), &s, &self.cache.pixels, color);
        }
    }
}

/// Lines of `text` split at `\n` (byte offset of each, text without the newline).
fn split_inclusive_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut start = 0usize;
    text.split('\n').map(move |l| {
        let s = start;
        start += l.len() + 1;
        (s, l)
    })
}

/// Blend a coverage image in `color` (straight alpha `0xAARRGGBB`) onto opaque pixels.
fn blit(dst: &mut Target<'_>, clip: Clip, x: i32, y: i32, s: &Slot, pixels: &[u8], color: u32) {
    let (w, h) = (i32::from(s.w), i32::from(s.h));
    if w == 0 || h == 0 {
        return;
    }
    let x0 = x.max(clip.x0);
    let y0 = y.max(clip.y0);
    let x1 = (x + w).min(clip.x1);
    let y1 = (y + h).min(clip.y1);
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let ca = (color >> 24) & 0xFF;
    let (cr, cg, cb) = ((color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF);
    let base = s.off as usize;
    for yy in y0..y1 {
        let src_row = base + ((yy - y) * w) as usize;
        let dst_row = yy as usize * dst.stride as usize;
        for xx in x0..x1 {
            let Some(&cov) = pixels.get(src_row + (xx - x) as usize) else { continue };
            if cov == 0 {
                continue;
            }
            let a = u32::from(cov) * ca / 255;
            let Some(d) = dst.px.get_mut(dst_row + xx as usize) else { continue };
            if a >= 255 {
                *d = 0xFF00_0000 | (color & 0x00FF_FFFF);
                continue;
            }
            let inv = 255 - a;
            let (dr, dg, db) = ((*d >> 16) & 0xFF, (*d >> 8) & 0xFF, *d & 0xFF);
            let r = (cr * a + dr * inv + 127) / 255;
            let g = (cg * a + dg * inv + 127) / 255;
            let b = (cb * a + db * inv + 127) / 255;
            *d = 0xFF00_0000 | r << 16 | g << 8 | b;
        }
    }
}
