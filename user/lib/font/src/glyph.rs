//! Glyph outlines: simple and composite `glyf` glyphs decoded, transformed into pixel space
//! (1/256-pixel integer coordinates, y down) and flattened into line segments for the rasterizer.
//!
//! Bounded work on untrusted data: at most `MAX_POINTS` points per glyph (all components
//! together), `MAX_DEPTH` levels of composite nesting, and `MAX_COMPONENTS` components.

use alloc::vec::Vec;

use crate::ttf::{Font, i16_at, u8_at, u16_at};

/// Subpixel units per pixel (coordinates passed to the rasterizer).
pub const SUB: i32 = 256;

const MAX_POINTS: usize = 20_000;
const MAX_DEPTH: u32 = 6;
const MAX_COMPONENTS: usize = 64;
/// Largest flattening step count for one quadratic curve.
const MAX_STEPS: i64 = 16;

/// Font units to subpixels: `x * sx / den + ox`, `oy - y * sy / den`.
#[derive(Clone, Copy, Debug)]
pub struct Scale {
    pub sx: i64,
    pub sy: i64,
    pub den: i64,
    pub ox: i64,
    pub oy: i64,
}

/// A 2x2 matrix in 2.14 fixed point and a translation in font units.
#[derive(Clone, Copy)]
struct Affine {
    a: i64,
    b: i64,
    c: i64,
    d: i64,
    tx: i64,
    ty: i64,
}

const ONE: i64 = 1 << 14;

impl Affine {
    const IDENTITY: Affine = Affine { a: ONE, b: 0, c: 0, d: ONE, tx: 0, ty: 0 };

    fn apply(&self, x: i64, y: i64) -> (i64, i64) {
        ((self.a * x + self.c * y) / ONE + self.tx, (self.b * x + self.d * y) / ONE + self.ty)
    }

    /// `self` after `inner`: points of a component placed by `inner`, inside `self`.
    fn then(&self, inner: &Affine) -> Affine {
        let (tx, ty) = self.apply(inner.tx, inner.ty);
        Affine {
            a: (self.a * inner.a + self.c * inner.b) / ONE,
            b: (self.b * inner.a + self.d * inner.b) / ONE,
            c: (self.a * inner.c + self.c * inner.d) / ONE,
            d: (self.b * inner.c + self.d * inner.d) / ONE,
            tx,
            ty,
        }
    }
}

/// A flattened outline: line segments `(x0, y0, x1, y1)` in subpixels, and their bounds.
#[derive(Default)]
pub struct Outline {
    pub lines: Vec<[i32; 4]>,
    pub min_x: i32,
    pub min_y: i32,
    pub max_x: i32,
    pub max_y: i32,
    points: usize,
}

impl Outline {
    pub fn clear(&mut self) {
        self.lines.clear();
        self.min_x = i32::MAX;
        self.min_y = i32::MAX;
        self.max_x = i32::MIN;
        self.max_y = i32::MIN;
        self.points = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    fn line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32) {
        self.min_x = self.min_x.min(x0).min(x1);
        self.max_x = self.max_x.max(x0).max(x1);
        self.min_y = self.min_y.min(y0).min(y1);
        self.max_y = self.max_y.max(y0).max(y1);
        if y0 != y1 {
            self.lines.push([x0, y0, x1, y1]);
        }
    }

    fn quad(&mut self, p0: (i32, i32), c: (i32, i32), p1: (i32, i32)) {
        let (x0, y0) = (i64::from(p0.0), i64::from(p0.1));
        let (cx, cy) = (i64::from(c.0), i64::from(c.1));
        let (x1, y1) = (i64::from(p1.0), i64::from(p1.1));
        // The flattening error of n chords is about |p0 - 2c + p1| / (8 n^2): a quarter pixel at most.
        let dev = (x0 - 2 * cx + x1).abs() + (y0 - 2 * cy + y1).abs();
        let mut n = 1i64;
        while n < MAX_STEPS && dev > 2 * i64::from(SUB) * n * n {
            n += 1;
        }
        let mut prev = p0;
        for i in 1..=n {
            let (t, u) = (i, n - i);
            let nn = n * n;
            let x = (u * u * x0 + 2 * t * u * cx + t * t * x1) / nn;
            let y = (u * u * y0 + 2 * t * u * cy + t * t * y1) / nn;
            let p = (x as i32, y as i32);
            self.line(prev.0, prev.1, p.0, p.1);
            prev = p;
        }
    }
}

fn to_px(s: &Scale, x: i64, y: i64) -> (i32, i32) {
    let px = x * s.sx / s.den + s.ox;
    let py = s.oy - y * s.sy / s.den;
    (px.clamp(-(1 << 24), 1 << 24) as i32, py.clamp(-(1 << 24), 1 << 24) as i32)
}

/// Decode glyph `g` of `font` into `out` (cleared first). False: malformed or too complex (the
/// glyph is then drawn as nothing).
pub fn outline(font: &Font<'_>, g: u16, scale: &Scale, out: &mut Outline) -> bool {
    out.clear();
    let ok = decode(font, g, scale, &Affine::IDENTITY, 0, out);
    if !ok {
        out.clear();
    }
    ok
}

fn decode(font: &Font<'_>, g: u16, scale: &Scale, xf: &Affine, depth: u32, out: &mut Outline) -> bool {
    let Some(d) = font.glyph_data(g) else { return false };
    if d.is_empty() {
        return true; // a blank glyph (space)
    }
    let Some(contours) = i16_at(d, 0) else { return false };
    if contours >= 0 {
        simple(d, contours as usize, scale, xf, out)
    } else {
        depth < MAX_DEPTH && composite(font, d, scale, xf, depth, out)
    }
}

const ON_CURVE: u8 = 0x01;
const X_SHORT: u8 = 0x02;
const Y_SHORT: u8 = 0x04;
const REPEAT: u8 = 0x08;
const X_SAME_OR_POS: u8 = 0x10;
const Y_SAME_OR_POS: u8 = 0x20;

fn simple(d: &[u8], contours: usize, scale: &Scale, xf: &Affine, out: &mut Outline) -> bool {
    if contours == 0 {
        return true;
    }
    let mut ends: Vec<usize> = Vec::with_capacity(contours);
    let mut last: Option<usize> = None;
    for i in 0..contours {
        let Some(e) = u16_at(d, 10 + i * 2) else { return false };
        let e = usize::from(e);
        if last.is_some_and(|l| e <= l) {
            return false;
        }
        last = Some(e);
        ends.push(e);
    }
    let n = last.map_or(0, |l| l + 1);
    if out.points + n > MAX_POINTS {
        return false;
    }
    out.points += n;
    let Some(ins) = u16_at(d, 10 + contours * 2) else { return false };
    let mut p = 12 + contours * 2 + usize::from(ins);
    // Flags (with repeats).
    let mut flags: Vec<u8> = Vec::with_capacity(n);
    while flags.len() < n {
        let Some(f) = u8_at(d, p) else { return false };
        p += 1;
        flags.push(f);
        if f & REPEAT != 0 {
            let Some(r) = u8_at(d, p) else { return false };
            p += 1;
            for _ in 0..r {
                if flags.len() == n {
                    break;
                }
                flags.push(f);
            }
        }
    }
    // Coordinates (deltas).
    let mut xs: Vec<i64> = Vec::with_capacity(n);
    let mut v = 0i64;
    for &f in &flags {
        if f & X_SHORT != 0 {
            let Some(b) = u8_at(d, p) else { return false };
            p += 1;
            v += if f & X_SAME_OR_POS != 0 { i64::from(b) } else { -i64::from(b) };
        } else if f & X_SAME_OR_POS == 0 {
            let Some(w) = i16_at(d, p) else { return false };
            p += 2;
            v += i64::from(w);
        }
        xs.push(v);
    }
    let mut pts: Vec<(i32, i32, bool)> = Vec::with_capacity(n);
    let mut v = 0i64;
    for (i, &f) in flags.iter().enumerate() {
        if f & Y_SHORT != 0 {
            let Some(b) = u8_at(d, p) else { return false };
            p += 1;
            v += if f & Y_SAME_OR_POS != 0 { i64::from(b) } else { -i64::from(b) };
        } else if f & Y_SAME_OR_POS == 0 {
            let Some(w) = i16_at(d, p) else { return false };
            p += 2;
            v += i64::from(w);
        }
        let (fx, fy) = xf.apply(xs[i], v);
        let (px, py) = to_px(scale, fx, fy);
        pts.push((px, py, f & ON_CURVE != 0));
    }
    let mut start = 0;
    for &e in &ends {
        contour(&pts[start..=e], out);
        start = e + 1;
    }
    true
}

fn mid(a: (i32, i32), b: (i32, i32)) -> (i32, i32) {
    ((a.0 + b.0) / 2, (a.1 + b.1) / 2)
}

/// One closed contour of on- and off-curve points (implied on-curve midpoints between two
/// off-curve points).
fn contour(pts: &[(i32, i32, bool)], out: &mut Outline) {
    let m = pts.len();
    if m < 2 {
        return;
    }
    let xy = |i: usize| (pts[i].0, pts[i].1);
    // Start on an on-curve point (or the midpoint of the first two off-curve ones).
    let (start, first) = if pts[0].2 {
        (xy(0), 1)
    } else if pts[m - 1].2 {
        (xy(m - 1), 0)
    } else {
        (mid(xy(m - 1), xy(0)), 0)
    };
    let mut cur = start;
    let mut ctrl: Option<(i32, i32)> = None;
    let count = if pts[0].2 || pts[m - 1].2 { m - 1 } else { m };
    for k in 0..count {
        let i = (first + k) % m;
        let p = xy(i);
        if pts[i].2 {
            match ctrl.take() {
                Some(c) => out.quad(cur, c, p),
                None => out.line(cur.0, cur.1, p.0, p.1),
            }
            cur = p;
        } else {
            if let Some(c) = ctrl {
                let mp = mid(c, p);
                out.quad(cur, c, mp);
                cur = mp;
            }
            ctrl = Some(p);
        }
    }
    match ctrl {
        Some(c) => out.quad(cur, c, start),
        None => out.line(cur.0, cur.1, start.0, start.1),
    }
}

const ARG_WORDS: u16 = 0x0001;
const ARGS_XY: u16 = 0x0002;
const HAVE_SCALE: u16 = 0x0008;
const MORE: u16 = 0x0020;
const XY_SCALE: u16 = 0x0040;
const TWO_BY_TWO: u16 = 0x0080;

fn composite(font: &Font<'_>, d: &[u8], scale: &Scale, xf: &Affine, depth: u32, out: &mut Outline) -> bool {
    let mut p = 10;
    for _ in 0..MAX_COMPONENTS {
        let (Some(flags), Some(gi)) = (u16_at(d, p), u16_at(d, p + 2)) else { return false };
        p += 4;
        let (dx, dy) = if flags & ARG_WORDS != 0 {
            let (Some(a), Some(b)) = (i16_at(d, p), i16_at(d, p + 2)) else { return false };
            p += 4;
            (i64::from(a), i64::from(b))
        } else {
            let (Some(a), Some(b)) = (u8_at(d, p), u8_at(d, p + 1)) else { return false };
            p += 2;
            (i64::from(a as i8), i64::from(b as i8))
        };
        // Point-matched placement is not supported: placed at the origin instead.
        let (dx, dy) = if flags & ARGS_XY != 0 { (dx, dy) } else { (0, 0) };
        let mut m = Affine { a: ONE, b: 0, c: 0, d: ONE, tx: dx, ty: dy };
        let f2 = |o: usize| i16_at(d, o).map(i64::from);
        if flags & HAVE_SCALE != 0 {
            let Some(s) = f2(p) else { return false };
            p += 2;
            m.a = s;
            m.d = s;
        } else if flags & XY_SCALE != 0 {
            let (Some(sx), Some(sy)) = (f2(p), f2(p + 2)) else { return false };
            p += 4;
            m.a = sx;
            m.d = sy;
        } else if flags & TWO_BY_TWO != 0 {
            let (Some(a), Some(b), Some(c), Some(dd)) = (f2(p), f2(p + 2), f2(p + 4), f2(p + 6)) else { return false };
            p += 8;
            m.a = a;
            m.b = b;
            m.c = c;
            m.d = dd;
        }
        if !decode(font, gi, scale, &xf.then(&m), depth + 1, out) {
            return false;
        }
        if flags & MORE == 0 {
            return true;
        }
    }
    false
}
