//! Anti-aliasing scanline rasterizer: exact area coverage of line segments, in integers only
//! (user space has no floating point: `x86_64-unknown-none` is soft-float).
//!
//! Each segment adds, per pixel cell it crosses, its signed height (`cover`) and its height times
//! the sum of its two x positions inside the cell (`area`), in 1/256 pixel units. Sweeping a row
//! left to right, a pixel's coverage is `cover so far * 512 - area of this cell`, over 512 * 256:
//! the classic cell accumulation of FreeType's smooth rasterizer. Winding is non-zero, clamped
//! (overlapping contours of one glyph stay opaque).

use alloc::vec::Vec;

use crate::glyph::{Outline, SUB};

/// A glyph image: 8-bit coverage, `w * h` bytes, placed at (`left`, `top`) from the pen position
/// on the baseline (`top` is negative above the baseline).
#[derive(Clone, Debug, Default)]
pub struct Bitmap {
    pub left: i32,
    pub top: i32,
    pub w: u32,
    pub h: u32,
    pub data: Vec<u8>,
}

/// Reusable rasterizer buffers.
#[derive(Default)]
pub struct Raster {
    cover: Vec<i32>,
    area: Vec<i32>,
    w: usize,
    h: usize,
}

/// Largest glyph image (pixels a side): bigger outlines are clipped.
pub const MAX_GLYPH_PX: i32 = 512;

fn floor_div(a: i32, b: i32) -> i32 {
    a.div_euclid(b)
}

impl Raster {
    fn reset(&mut self, w: usize, h: usize) {
        self.w = w;
        self.h = h;
        let n = (w + 1) * h;
        self.cover.clear();
        self.cover.resize(n, 0);
        self.area.clear();
        self.area.resize(n, 0);
    }

    fn acc(&mut self, cx: i32, row: i32, ya: i32, yb: i32, fxa: i32, fxb: i32) {
        if row < 0 || row as usize >= self.h || cx >= self.w as i32 {
            return;
        }
        // Left of the image: the whole height counts for every pixel to the right.
        let (cx, fxa, fxb) = if cx < 0 { (0, 0, 0) } else { (cx, fxa, fxb) };
        let i = row as usize * (self.w + 1) + cx as usize;
        let dy = yb - ya;
        self.cover[i] += dy;
        self.area[i] += dy * (fxa + fxb);
    }

    /// One piece inside pixel row `row` (`ya`, `yb` in `0..=SUB` within the row).
    fn row_piece(&mut self, row: i32, xa: i32, ya: i32, xb: i32, yb: i32) {
        if ya == yb {
            return;
        }
        let ca = floor_div(xa, SUB);
        let cb = floor_div(xb, SUB);
        if ca == cb {
            self.acc(ca, row, ya, yb, xa - ca * SUB, xb - ca * SUB);
            return;
        }
        let step = if xb > xa { 1 } else { -1 };
        let (mut px, mut py, mut c) = (xa, ya, ca);
        let (dx, dy) = (i64::from(xb - xa), i64::from(yb - ya));
        for _ in 0..4096 {
            if c == cb {
                self.acc(c, row, py, yb, px - c * SUB, xb - c * SUB);
                return;
            }
            let bx = if step > 0 { (c + 1) * SUB } else { c * SUB };
            let ny = ya + (dy * i64::from(bx - xa) / dx) as i32;
            self.acc(c, row, py, ny, px - c * SUB, bx - c * SUB);
            px = bx;
            py = ny;
            c += step;
        }
    }

    fn line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32) {
        if y0 == y1 {
            return;
        }
        let (ylo, yhi) = (y0.min(y1), y0.max(y1));
        let r0 = floor_div(ylo, SUB).max(0);
        let r1 = floor_div(yhi - 1, SUB).min(self.h as i32 - 1);
        let (dx, dy) = (i64::from(x1 - x0), i64::from(y1 - y0));
        let x_at = |y: i32| x0 + (dx * i64::from(y - y0) / dy) as i32;
        for row in r0..=r1 {
            let top = ylo.max(row * SUB);
            let bot = yhi.min(row * SUB + SUB);
            let (ya, yb) = if y0 < y1 { (top, bot) } else { (bot, top) };
            self.row_piece(row, x_at(ya), ya - row * SUB, x_at(yb), yb - row * SUB);
        }
    }

    /// Rasterize an outline (subpixel coordinates relative to the pen on the baseline) into `out`.
    pub fn render(&mut self, o: &Outline, out: &mut Bitmap) {
        out.data.clear();
        if o.is_empty() {
            (out.left, out.top, out.w, out.h) = (0, 0, 0, 0);
            return;
        }
        let left = floor_div(o.min_x, SUB);
        let top = floor_div(o.min_y, SUB);
        let right = floor_div(o.max_x + SUB - 1, SUB);
        let bottom = floor_div(o.max_y + SUB - 1, SUB);
        let w = (right - left).clamp(1, MAX_GLYPH_PX) as usize;
        let h = (bottom - top).clamp(1, MAX_GLYPH_PX) as usize;
        self.reset(w, h);
        let (ox, oy) = (left * SUB, top * SUB);
        for l in &o.lines {
            self.line(l[0] - ox, l[1] - oy, l[2] - ox, l[3] - oy);
        }
        out.left = left;
        out.top = top;
        out.w = w as u32;
        out.h = h as u32;
        out.data.resize(w * h, 0);
        for y in 0..h {
            let mut acc = 0i32;
            let row = y * (w + 1);
            for x in 0..w {
                acc += self.cover[row + x];
                let v = (acc * 2 * SUB - self.area[row + x]).unsigned_abs();
                let c = ((v + 256) >> 9).min(255) as u8;
                out.data[y * w + x] = GAMMA[usize::from(c)];
            }
        }
    }
}

/// Coverage correction: thin antialiased stems look washed out at UI sizes (especially light
/// text on the dark themes), so mid coverage is lifted: `c + 0.3 c (1 - c)`.
static GAMMA: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let c = i as u32;
        t[i] = (c + c * (255 - c) * 30 / (255 * 100)) as u8;
        i += 1;
    }
    t
};
