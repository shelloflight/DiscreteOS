//! The display: a grid of cells drawn on the GOP framebuffer (8x16 glyphs, doubled on large
//! screens) or written to VGA text memory, or nothing (no display: the terminal mirrors to the
//! log). Only cells that changed are drawn again: the framebuffer is write-combining memory and is
//! never read back.

use alloc::vec;
use alloc::vec::Vec;

use libd::sys::{self, Handle};
use libd::{Mapping, println};

use crate::font;

/// A cell: the character (Unicode, bits 0-20) and the attribute (`fg | bg << 4`, bits 24-31).
/// The framebuffer and VGA text show it through code page 437 (`glyph`); the graphical terminal
/// (`view`) shows the character itself.
pub type Cell = u32;

pub fn cell(c: char, attr: u8) -> Cell {
    c as u32 | u32::from(attr) << 24
}

pub fn char_of(c: Cell) -> char {
    char::from_u32(c & 0x1F_FFFF).unwrap_or('?')
}

pub fn attr_of(c: Cell) -> u8 {
    (c >> 24) as u8
}

/// A character as a code page 437 glyph (what the font and VGA text can show).
pub fn glyph(c: char) -> u8 {
    match c {
        ' '..='~' => c as u8,
        '▸' | '►' | '▶' => 0x10,
        '◂' | '◄' => 0x11,
        '✓' | '√' => 0xFB,
        '✗' | '✘' => CROSS,
        '·' => 0xFA,
        '•' => 0x07,
        '—' | '–' | '─' => 0xC4,
        '│' => 0xB3,
        '┌' => 0xDA,
        '┐' => 0xBF,
        '└' => 0xC0,
        '┘' => 0xD9,
        '…' => b'~',
        '°' => 0xF8,
        'µ' => 0xE6,
        _ => b'?',
    }
}

/// The CGA palette (the kernel console's colours).
const RGB: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00], [0x00, 0x00, 0xAA], [0x00, 0xAA, 0x00], [0x00, 0xAA, 0xAA],
    [0xAA, 0x00, 0x00], [0xAA, 0x00, 0xAA], [0xAA, 0x55, 0x00], [0xAA, 0xAA, 0xAA],
    [0x55, 0x55, 0x55], [0x55, 0x55, 0xFF], [0x55, 0xFF, 0x55], [0x55, 0xFF, 0xFF],
    [0xFF, 0x55, 0x55], [0xFF, 0x55, 0xFF], [0xFF, 0xFF, 0x55], [0xFF, 0xFF, 0xFF],
];

/// Glyph 0x7F (a house in code page 437, never used) is drawn as a cross mark (✗) on the
/// framebuffer; VGA text shows an `x` instead.
pub const CROSS: u8 = 0x7F;
const CROSS_ROWS: [u8; 16] = [0, 0, 0, 0, 0xC6, 0xEE, 0x7C, 0x38, 0x7C, 0xEE, 0xC6, 0, 0, 0, 0, 0];

enum Backend {
    Fb { map: Mapping, pitch_px: usize, scale: usize, palette: [u32; 16] },
    Vga { map: Mapping, dev: Handle },
    None,
}

pub struct Screen {
    pub cols: usize,
    pub rows: usize,
    shown: Vec<Cell>,
    cursor: Option<(usize, usize)>,
    backend: Backend,
    pub what: &'static str,
}

impl Screen {
    /// Take the display device (mapping it takes the screen from the kernel console).
    pub fn open(dev: Handle) -> Screen {
        let none = Screen { cols: 80, rows: 25, shown: Vec::new(), cursor: None, backend: Backend::None, what: "no display" };
        if dev == 0 {
            return none;
        }
        let info = match sys::display_info(dev) {
            Ok(i) => i,
            Err(e) => return none.because("display_info", e),
        };
        let vmo = match sys::device_map_bar(dev, 0) {
            Ok(v) => v,
            Err(e) => return none.because("device_map_bar", e),
        };
        let map = match Mapping::of(vmo, info.size) {
            Ok(m) => m,
            Err(e) => return none.because("map", e),
        };
        let (cols, rows, backend, what) = match info.kind {
            sys::DISPLAY_RGB32 => {
                let (w, h) = (info.width as usize, info.height as usize);
                let scale = if w >= 2560 && h >= 1440 { 2 } else { 1 };
                let mut palette = [0u32; 16];
                for (p, c) in palette.iter_mut().zip(RGB.iter()) {
                    *p = u32::from(c[0]) << info.red_shift | u32::from(c[1]) << info.green_shift | u32::from(c[2]) << info.blue_shift;
                }
                let pitch_px = info.pitch as usize / 4;
                if pitch_px < w || (pitch_px * h * 4) as u64 > map.len {
                    return none;
                }
                (w / (font::W * scale), h / (font::H * scale), Backend::Fb { map, pitch_px, scale, palette }, "framebuffer")
            }
            sys::DISPLAY_VGA_TEXT => (info.width as usize, info.height as usize, Backend::Vga { map, dev }, "VGA text"),
            _ => return none,
        };
        if cols == 0 || rows == 0 {
            return none;
        }
        println!("terminal: display {}x{} {}, {}x{} cells", info.width, info.height, what, cols, rows);
        let mut s = Screen { cols, rows, shown: vec![u32::MAX; cols * rows], cursor: None, backend, what };
        if let Backend::Fb { map, .. } = &s.backend {
            // Whole screen black once (the area right of / below the grid included).
            for off in (0..(info.pitch as u64 * u64::from(info.height))).step_by(4) {
                map.w32(off, 0);
            }
        }
        s.clear();
        s
    }

    fn because(self, what: &str, e: i64) -> Screen {
        println!("terminal: the display cannot be used: {} failed ({})", what, sys::status(e));
        self
    }

    pub fn present(&self) -> bool {
        !matches!(self.backend, Backend::None)
    }

    /// Forget what is shown (another program drew on the screen): the next frame redraws every
    /// cell, and the framebuffer margin right of / below the grid is cleared.
    pub fn invalidate(&mut self) {
        self.shown.fill(u32::MAX);
        if let Backend::Fb { map, .. } = &self.backend {
            for off in (0..map.len).step_by(4) {
                map.w32(off, 0);
            }
        }
    }

    pub fn clear(&mut self) {
        for y in 0..self.rows {
            for x in 0..self.cols {
                self.put(x, y, cell(' ', libd::term::DEFAULT_ATTR));
            }
        }
    }

    /// Set cell (x, y); drawn only if it changed.
    pub fn put(&mut self, x: usize, y: usize, c: Cell) {
        if x >= self.cols || y >= self.rows {
            return;
        }
        let i = y * self.cols + x;
        let c = if self.cursor == Some((x, y)) { invert(c) } else { c };
        if self.shown.get(i) == Some(&c) {
            return;
        }
        if let Some(s) = self.shown.get_mut(i) {
            *s = c;
        }
        self.draw(x, y, c);
    }

    /// Move the cursor (None: hidden). Call before `put`ting the frame.
    pub fn set_cursor(&mut self, at: Option<(usize, usize)>) {
        if self.cursor == at {
            return;
        }
        let old = self.cursor.take();
        if let Some((x, y)) = old {
            // Redraw the old cell plain on the next put: forget what is shown there.
            if let Some(s) = self.shown.get_mut(y * self.cols + x) {
                *s = u32::MAX;
            }
        }
        self.cursor = at;
        if let Some((x, y)) = at
            && let Some(s) = self.shown.get_mut(y * self.cols + x)
        {
            *s = u32::MAX;
        }
        if let Backend::Vga { dev, .. } = &self.backend {
            let pos = at.map_or(self.cols * self.rows, |(x, y)| y * self.cols + x) as u64; // off-screen hides it
            let dev = *dev;
            let _ = sys::io_write(dev, 1, 0, 1, 0x0F);
            let _ = sys::io_write(dev, 1, 1, 1, pos & 0xFF);
            let _ = sys::io_write(dev, 1, 0, 1, 0x0E);
            let _ = sys::io_write(dev, 1, 1, 1, pos >> 8);
        }
    }

    fn draw(&mut self, x: usize, y: usize, c: Cell) {
        let g = glyph(char_of(c));
        let attr = attr_of(c);
        match &self.backend {
            Backend::Fb { map, pitch_px, scale, palette } => {
                let fg = palette[usize::from(attr & 0xF)];
                let bg = palette[usize::from(attr >> 4)];
                let gi = usize::from(g);
                let rows: &[u8] = if g == CROSS { &CROSS_ROWS } else { &font::FONT[gi * font::H..gi * font::H + font::H] };
                let (sc, pitch) = (*scale, *pitch_px);
                let (px, py) = (x * font::W * sc, y * font::H * sc);
                for (r, &bits) in rows.iter().enumerate() {
                    for dy in 0..sc {
                        let line = ((py + r * sc + dy) * pitch + px) as u64 * 4;
                        for b in 0..font::W {
                            let v = if bits & (0x80 >> b) != 0 { fg } else { bg };
                            for dx in 0..sc {
                                map.w32(line + ((b * sc + dx) * 4) as u64, v);
                            }
                        }
                    }
                }
            }
            Backend::Vga { map, .. } => {
                let g = if g == CROSS { b'x' } else { g };
                map.w16(((y * self.cols + x) * 2) as u64, u16::from(g) | u16::from(attr) << 8);
            }
            Backend::None => {}
        }
    }
}

/// The cursor on a framebuffer: the cell with its colours swapped. (VGA text has a hardware
/// cursor, but swapping there too keeps one look; the hardware cursor is also set.)
pub fn invert(c: Cell) -> Cell {
    let attr = attr_of(c);
    let swapped = (attr >> 4) | (attr & 0x0F) << 4;
    (c & 0x00FF_FFFF) | u32::from(swapped) << 24
}
