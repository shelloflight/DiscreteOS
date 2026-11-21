//! Safe, clipped ARGB8888 / XRGB8888 software compositor canvas (`#![forbid(unsafe_code)]`).
//!
//! All rendering operates on an offscreen RAM backbuffer (never reading back from write-combining
//! VRAM). Supports fast opaque fills, integer Porter-Duff source-over alpha blending, crisp 1px
//! hairlines, clean rounded rectangles (no gradients), trust/status dots, text, surface blits,
//! and a minimal 64x64 ARGB8888 pointer cursor generator.

use crate::font::{self, GLYPH_H, GLYPH_W};
use crate::geom::Rect;

/// Straight-alpha source-over blend of `src` (`0xAARRGGBB`) onto opaque `dst` (`0xFFRRGGBB`).
#[inline]
pub const fn blend_over(dst: u32, src: u32) -> u32 {
    let a = (src >> 24) & 0xFF;
    if a == 0 {
        return dst;
    }
    if a == 255 {
        return src | 0xFF00_0000;
    }
    let inv = 255 - a;
    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;
    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;
    let r = (sr * a + dr * inv + 127) / 255;
    let g = (sg * a + dg * inv + 127) / 255;
    let b = (sb * a + db * inv + 127) / 255;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

/// Scale a color's alpha channel by `cov` in `0..=255`.
#[inline]
const fn scale_alpha(color: u32, cov: u32) -> u32 {
    let a = ((color >> 24) & 0xFF) * cov / 255;
    (color & 0x00FF_FFFF) | (a << 24)
}

/// Mutable 32-bpp compositor backbuffer slice with logical dimensions and pixel stride.
pub struct Canvas<'a> {
    pub pixels: &'a mut [u32],
    pub width: u32,
    pub height: u32,
    pub stride_px: u32,
}

impl<'a> Canvas<'a> {
    pub fn new(pixels: &'a mut [u32], width: u32, height: u32, stride_px: u32) -> Option<Self> {
        if width == 0 || height == 0 || stride_px < width {
            return None;
        }
        let needed = (stride_px as usize).checked_mul(height as usize)?;
        if pixels.len() < needed {
            return None;
        }
        Some(Self { pixels, width, height, stride_px })
    }

    pub const fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }

    #[inline]
    pub fn put_pixel(&mut self, clip: Rect, x: i32, y: i32, color: u32) {
        if x < clip.x
            || y < clip.y
            || i64::from(x) >= clip.right()
            || i64::from(y) >= clip.bottom()
            || x < 0
            || y < 0
            || (x as u32) >= self.width
            || (y as u32) >= self.height
        {
            return;
        }
        let idx = (y as usize) * (self.stride_px as usize) + (x as usize);
        if let Some(p) = self.pixels.get_mut(idx) {
            *p = blend_over(*p, color);
        }
    }

    pub fn get_pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.pixels.get((y as usize) * (self.stride_px as usize) + (x as usize)).copied()
    }

    /// Fill `rect` clipped to `clip` (fast opaque span fill or clean alpha-over blend).
    pub fn fill_rect(&mut self, clip: Rect, rect: Rect, color: u32) {
        let r = rect.intersect(clip).intersect(self.bounds());
        if r.is_empty() {
            return;
        }
        let a = (color >> 24) & 0xFF;
        if a == 0 {
            return;
        }
        let stride = self.stride_px as usize;
        let x0 = r.x as usize;
        let x1 = x0 + r.w as usize;
        let y0 = r.y as usize;
        let y1 = y0 + r.h as usize;
        if a == 255 {
            let solid = color | 0xFF00_0000;
            for y in y0..y1 {
                let row = y * stride;
                self.pixels[row + x0..row + x1].fill(solid);
            }
        } else {
            for y in y0..y1 {
                let row = y * stride;
                for p in &mut self.pixels[row + x0..row + x1] {
                    *p = blend_over(*p, color);
                }
            }
        }
    }

    /// Draw a crisp 1px rectangular outline inside `rect`.
    pub fn stroke_rect(&mut self, clip: Rect, rect: Rect, color: u32) {
        if rect.w == 0 || rect.h == 0 {
            return;
        }
        self.fill_rect(clip, Rect::new(rect.x, rect.y, rect.w, 1), color);
        if rect.h > 1 {
            self.fill_rect(clip, Rect::new(rect.x, rect.y.saturating_add(rect.h as i32 - 1), rect.w, 1), color);
        }
        if rect.h > 2 {
            self.fill_rect(clip, Rect::new(rect.x, rect.y.saturating_add(1), 1, rect.h - 2), color);
            if rect.w > 1 {
                self.fill_rect(
                    clip,
                    Rect::new(rect.x.saturating_add(rect.w as i32 - 1), rect.y.saturating_add(1), 1, rect.h - 2),
                    color,
                );
            }
        }
    }

    /// Draw a clean flat rounded rectangle with optional 1px hairline border (zero gradients).
    pub fn fill_rounded_rect(&mut self, clip: Rect, rect: Rect, radius: u32, fill: u32, border: u32) {
        let vis = rect.intersect(clip).intersect(self.bounds());
        if vis.is_empty() {
            return;
        }
        let rad = radius.min(rect.w / 2).min(rect.h / 2) as i32;
        if rad <= 0 {
            self.fill_rect(clip, rect, fill);
            if (border >> 24) != 0 {
                self.stroke_rect(clip, rect, border);
            }
            return;
        }
        let has_border = (border >> 24) != 0;
        let rx0 = rect.x;
        let ry0 = rect.y;
        let rx1 = rect.x + rect.w as i32 - 1;
        let ry1 = rect.y + rect.h as i32 - 1;
        let r_outer_sq = rad * rad;
        let r_inner = (rad - 1).max(0);
        let r_inner_sq = r_inner * r_inner;
        let stride = self.stride_px as usize;

        for y in vis.y..(vis.y + vis.h as i32) {
            let in_top_band = y < ry0 + rad;
            let in_bot_band = y > ry1 - rad;
            let row_off = (y as usize) * stride;
            if !in_top_band && !in_bot_band {
                // Fast interior scanline: left border, middle fill, right border.
                let mut x0 = vis.x;
                let mut x1 = vis.x + vis.w as i32;
                if has_border && x0 == rx0 {
                    let p = &mut self.pixels[row_off + x0 as usize];
                    *p = blend_over(*p, border);
                    x0 += 1;
                }
                if has_border && x1 - 1 == rx1 && x1 > x0 {
                    x1 -= 1;
                    let p = &mut self.pixels[row_off + x1 as usize];
                    *p = blend_over(*p, border);
                }
                if x1 > x0 {
                    if (fill >> 24) == 255 {
                        self.pixels[row_off + x0 as usize..row_off + x1 as usize].fill(fill | 0xFF00_0000);
                    } else {
                        for p in &mut self.pixels[row_off + x0 as usize..row_off + x1 as usize] {
                            *p = blend_over(*p, fill);
                        }
                    }
                }
                continue;
            }
            for x in vis.x..(vis.x + vis.w as i32) {
                let in_left = x < rx0 + rad;
                let in_right = x > rx1 - rad;
                if !in_left && !in_right {
                    let on_edge = y == ry0 || y == ry1;
                    let c = if has_border && on_edge { border } else { fill };
                    let p = &mut self.pixels[row_off + x as usize];
                    *p = blend_over(*p, c);
                    continue;
                }
                let cx = if in_left { rx0 + rad } else { rx1 - rad };
                let cy = if in_top_band { ry0 + rad } else { ry1 - rad };
                let dx = x - cx;
                let dy = y - cy;
                let d2 = dx * dx + dy * dy;
                if d2 <= r_inner_sq {
                    let p = &mut self.pixels[row_off + x as usize];
                    *p = blend_over(*p, fill);
                } else if d2 <= r_outer_sq {
                    let c = if has_border { border } else { fill };
                    let p = &mut self.pixels[row_off + x as usize];
                    *p = blend_over(*p, c);
                } else if d2 <= r_outer_sq + rad {
                    // Subtle 1-step corner softening without blur.
                    let c = if has_border { border } else { fill };
                    let p = &mut self.pixels[row_off + x as usize];
                    *p = blend_over(*p, scale_alpha(c, 96));
                }
            }
        }
    }

    /// Draw a clean filled circle (for trust dots and live status indicators).
    pub fn fill_circle(&mut self, clip: Rect, cx: i32, cy: i32, radius: i32, color: u32) {
        if radius <= 0 {
            return;
        }
        let bb = Rect::new(cx - radius, cy - radius, (radius * 2 + 1) as u32, (radius * 2 + 1) as u32);
        let vis = bb.intersect(clip).intersect(self.bounds());
        if vis.is_empty() {
            return;
        }
        let r2 = radius * radius;
        let stride = self.stride_px as usize;
        for y in vis.y..(vis.y + vis.h as i32) {
            let dy = y - cy;
            let row = (y as usize) * stride;
            for x in vis.x..(vis.x + vis.w as i32) {
                let dx = x - cx;
                let d2 = dx * dx + dy * dy;
                if d2 <= r2 {
                    let p = &mut self.pixels[row + x as usize];
                    *p = blend_over(*p, color);
                } else if d2 <= r2 + radius {
                    let p = &mut self.pixels[row + x as usize];
                    *p = blend_over(*p, scale_alpha(color, 110));
                }
            }
        }
    }

    /// Draw ASCII text clipped to `clip` and truncated within `max_w` pixels.
    /// Returns pixels advanced horizontally.
    pub fn draw_text(&mut self, clip: Rect, mut x: i32, y: i32, text: &[u8], color: u32, max_w: u32) -> u32 {
        let mut used = 0u32;
        for &ch in text {
            if used + GLYPH_W > max_w {
                break;
            }
            let glyph_rect = Rect::new(x, y, GLYPH_W, GLYPH_H);
            if !glyph_rect.intersect(clip).is_empty() {
                let rows = font::glyph_rows(ch);
                for (ry, &bits) in rows.iter().enumerate() {
                    if bits == 0 {
                        continue;
                    }
                    let py = y + ry as i32;
                    if py < clip.y || i64::from(py) >= clip.bottom() || py < 0 || (py as u32) >= self.height {
                        continue;
                    }
                    let row_off = (py as usize) * (self.stride_px as usize);
                    for rx in 0..8i32 {
                        if (bits & (0x80 >> rx)) != 0 {
                            let px = x + rx;
                            if px >= clip.x && i64::from(px) < clip.right() && px >= 0 && (px as u32) < self.width {
                                let p = &mut self.pixels[row_off + px as usize];
                                *p = blend_over(*p, color);
                            }
                        }
                    }
                }
            }
            x = x.saturating_add(GLYPH_W as i32);
            used += GLYPH_W;
        }
        used
    }

    /// Draw crisp minimal SSD window control icons (`min`, `max`, `close`) centered in `rect`.
    pub fn draw_win_icon(&mut self, clip: Rect, rect: Rect, kind: WinIcon, color: u32) {
        let cx = rect.x + (rect.w as i32) / 2;
        let cy = rect.y + (rect.h as i32) / 2;
        match kind {
            WinIcon::Minimize => {
                self.fill_rect(clip, Rect::new(cx - 4, cy + 2, 9, 1), color);
            }
            WinIcon::Maximize => {
                self.stroke_rect(clip, Rect::new(cx - 4, cy - 4, 9, 9), color);
            }
            WinIcon::Restore => {
                self.stroke_rect(clip, Rect::new(cx - 4, cy - 2, 7, 7), color);
                self.fill_rect(clip, Rect::new(cx - 2, cy - 4, 7, 1), color);
                self.fill_rect(clip, Rect::new(cx + 4, cy - 4, 1, 7), color);
            }
            WinIcon::Close => {
                for d in -4..=4 {
                    self.put_pixel(clip, cx + d, cy + d, color);
                    self.put_pixel(clip, cx + d, cy - d, color);
                }
            }
        }
    }

    /// Blit a client pixel buffer (`u8` little-endian XRGB8888 / ARGB8888) into the canvas,
    /// clipped to `clip` and the destination client rectangle `dst`. Never panics even on short
    /// untrusted client buffers.
    #[allow(clippy::too_many_arguments)]
    pub fn blit_client_bytes(
        &mut self,
        clip: Rect,
        dst: Rect,
        src_bytes: &[u8],
        src_w: u32,
        src_h: u32,
        src_pitch_bytes: u32,
        opaque: bool,
    ) {
        if src_w == 0 || src_h == 0 || src_pitch_bytes < src_w.saturating_mul(4) {
            return;
        }
        let src_rect = Rect::new(dst.x, dst.y, dst.w.min(src_w), dst.h.min(src_h));
        let vis = src_rect.intersect(clip).intersect(self.bounds());
        if vis.is_empty() {
            return;
        }
        let dst_stride = self.stride_px as usize;
        let src_pitch = src_pitch_bytes as usize;
        let sx_off = (vis.x - dst.x) as usize;
        let sy_off = (vis.y - dst.y) as usize;
        let cols = vis.w as usize;

        for row in 0..(vis.h as usize) {
            let src_row_start = (sy_off + row).saturating_mul(src_pitch).saturating_add(sx_off.saturating_mul(4));
            let Some(src_row_end) = src_row_start.checked_add(cols.saturating_mul(4)) else {
                break;
            };
            if src_row_end > src_bytes.len() {
                break;
            }
            let src_slice = &src_bytes[src_row_start..src_row_end];
            let dst_row_start = ((vis.y as usize) + row) * dst_stride + (vis.x as usize);
            let dst_slice = &mut self.pixels[dst_row_start..dst_row_start + cols];
            if opaque {
                for (d, &chunk) in dst_slice.iter_mut().zip(src_slice.as_chunks::<4>().0) {
                    let px = u32::from_le_bytes(chunk);
                    *d = px | 0xFF00_0000;
                }
            } else {
                for (d, &chunk) in dst_slice.iter_mut().zip(src_slice.as_chunks::<4>().0) {
                    let px = u32::from_le_bytes(chunk);
                    *d = blend_over(*d, px);
                }
            }
        }
    }

    /// Blit the software pointer cursor at `(cx, cy)` when an output lacks `CAP_HW_CURSOR`.
    pub fn draw_sw_cursor(&mut self, clip: Rect, cx: i32, cy: i32) {
        for (ry, row) in CURSOR_SHAPE.iter().enumerate() {
            for (rx, &ch) in row.iter().enumerate() {
                let col = match ch {
                    b'#' => 0xFF10_141C,
                    b'W' => 0xFFF2_F5FA,
                    _ => continue,
                };
                self.put_pixel(clip, cx + rx as i32, cy + ry as i32, col);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WinIcon {
    Minimize,
    Maximize,
    Restore,
    Close,
}

/// Clean minimal 12x18 dark-core, crisp light-outline pointer arrow.
pub const CURSOR_W: u32 = 12;
pub const CURSOR_H: u32 = 18;

const CURSOR_SHAPE: [&[u8; 12]; 18] = [
    b"W...........",
    b"WW..........",
    b"W#W.........",
    b"W##W........",
    b"W###W.......",
    b"W####W......",
    b"W#####W.....",
    b"W######W....",
    b"W#######W...",
    b"W########W..",
    b"W#########W.",
    b"W#####WWWWWW",
    b"W##W##W.....",
    b"W#W.W##W....",
    b"WW..W##W....",
    b"W....W##W...",
    b".....W##W...",
    b"......WW....",
];

/// Populate a 64x64 ARGB8888 hardware cursor image (`64 * 64 * 4 = 16384` bytes, hotspot `(0, 0)`).
pub fn write_hw_cursor_64x64(out: &mut [u8]) {
    if out.len() < 64 * 64 * 4 {
        return;
    }
    out[..64 * 64 * 4].fill(0);
    for (y, row) in CURSOR_SHAPE.iter().enumerate() {
        for (x, &ch) in row.iter().enumerate() {
            let px: u32 = match ch {
                b'#' => 0xFF10_141C,
                b'W' => 0xFFF2_F5FA,
                _ => 0,
            };
            let o = (y * 64 + x) * 4;
            out[o..o + 4].copy_from_slice(&px.to_le_bytes());
        }
    }
}
