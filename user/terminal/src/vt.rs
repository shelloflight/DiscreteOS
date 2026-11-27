//! Lightweight VT100 / xterm ANSI screen emulator for raw-mode terminal sessions (such as SSH).
//!
//! Owns a `cols x rows` cell grid with cursor tracking, streaming UTF-8 decoding, scroll regions,
//! SGR 16/256/24-bit color mapping, line/character editing (`BS`, `CR`, `LF`, `EL`, `ED`, `DCH`,
//! `ICH`, `IL`, `DL`, `CUP`, `CUU/CUD/CUF/CUB`), and alternate screen buffer (`?1049h`/`?1049l`).

use alloc::vec;
use alloc::vec::Vec;

use libd::term;

use crate::screen::{Cell, cell};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Ground,
    Esc,
    EscCharset,
    Csi,
    Osc,
    OscEsc,
}

struct AltSaved {
    cells: Vec<Cell>,
    cx: usize,
    cy: usize,
    fg: u8,
    bg: u8,
    bold: bool,
    reverse: bool,
    scroll_top: usize,
    scroll_bottom: usize,
}

pub struct VtScreen {
    pub cols: usize,
    pub rows: usize,
    cells: Vec<Cell>,
    pub cx: usize,
    pub cy: usize,
    pub cursor_visible: bool,
    wrap_pending: bool,
    fg: u8,
    bg: u8,
    bold: bool,
    reverse: bool,
    scroll_top: usize,
    scroll_bottom: usize,
    saved_cx: usize,
    saved_cy: usize,
    alt: Option<AltSaved>,
    state: ParseState,
    csi_private: bool,
    csi_params: Vec<u16>,
    csi_cur: Option<u16>,
    utf8_buf: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
    clear_scrollback: bool,
}

impl VtScreen {
    pub fn new(cols: usize, rows: usize) -> Self {
        let cols = cols.max(1);
        let rows = rows.max(1);
        let blank = cell(' ', term::DEFAULT_ATTR);
        Self {
            cols,
            rows,
            cells: vec![blank; cols * rows],
            cx: 0,
            cy: 0,
            cursor_visible: true,
            wrap_pending: false,
            fg: term::GREY,
            bg: term::BLACK,
            bold: false,
            reverse: false,
            scroll_top: 0,
            scroll_bottom: rows - 1,
            saved_cx: 0,
            saved_cy: 0,
            alt: None,
            state: ParseState::Ground,
            csi_private: false,
            csi_params: Vec::new(),
            csi_cur: None,
            utf8_buf: [0; 4],
            utf8_len: 0,
            utf8_need: 0,
            clear_scrollback: false,
        }
    }

    pub fn reset(&mut self, cols: usize, rows: usize) {
        *self = Self::new(cols, rows);
    }

    pub fn take_clear_scrollback(&mut self) -> bool {
        core::mem::take(&mut self.clear_scrollback)
    }

    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        let new_cols = new_cols.max(1);
        let new_rows = new_rows.max(1);
        if new_cols == self.cols && new_rows == self.rows {
            return;
        }
        let blank = cell(' ', term::DEFAULT_ATTR);
        let mut next = vec![blank; new_cols * new_rows];
        let copy_r = self.rows.min(new_rows);
        let copy_c = self.cols.min(new_cols);
        for y in 0..copy_r {
            let src_off = y * self.cols;
            let dst_off = y * new_cols;
            next[dst_off..dst_off + copy_c].copy_from_slice(&self.cells[src_off..src_off + copy_c]);
        }
        self.cells = next;
        self.cols = new_cols;
        self.rows = new_rows;
        self.cx = self.cx.min(new_cols - 1);
        self.cy = self.cy.min(new_rows - 1);
        self.scroll_top = 0;
        self.scroll_bottom = new_rows - 1;
        self.wrap_pending = false;
    }

    pub fn row_slice(&self, y: usize) -> &[Cell] {
        let off = y * self.cols;
        &self.cells[off..off + self.cols]
    }

    /// Snapshot non-empty lines from the current screen (used when leaving raw mode).
    pub fn snapshot_lines(&self) -> Vec<Vec<Cell>> {
        let blank = cell(' ', term::DEFAULT_ATTR);
        let mut last = self.rows;
        while last > 0 && self.row_slice(last - 1).iter().all(|&c| c == blank) {
            last -= 1;
        }
        let mut out = Vec::with_capacity(last);
        for y in 0..last {
            let row = self.row_slice(y);
            let mut end = row.len();
            while end > 0 && row[end - 1] == blank {
                end -= 1;
            }
            out.push(row[..end].to_vec());
        }
        out
    }

    fn current_attr(&self) -> u8 {
        let mut fg = self.fg;
        let bg = self.bg;
        if self.bold && fg < 8 {
            fg += 8;
        }
        if self.reverse {
            bg | (fg << 4)
        } else {
            fg | (bg << 4)
        }
    }

    fn blank_cell(&self) -> Cell {
        cell(' ', self.fg | (self.bg << 4))
    }

    /// Feed raw bytes from the remote PTY into the VT emulator.
    /// Calls `on_scroll` with each line pushed off the top of the primary screen.
    pub fn feed<F: FnMut(Vec<Cell>)>(&mut self, bytes: &[u8], mut on_scroll: F) {
        for &b in bytes {
            match self.state {
                ParseState::Ground => self.feed_ground(b, &mut on_scroll),
                ParseState::Esc => self.feed_esc(b, &mut on_scroll),
                ParseState::EscCharset => {
                    self.state = ParseState::Ground;
                }
                ParseState::Csi => self.feed_csi(b, &mut on_scroll),
                ParseState::Osc => {
                    if b == 0x07 {
                        self.state = ParseState::Ground;
                    } else if b == 0x1B {
                        self.state = ParseState::OscEsc;
                    }
                }
                ParseState::OscEsc => {
                    self.state = ParseState::Ground;
                }
            }
        }
    }

    fn feed_ground<F: FnMut(Vec<Cell>)>(&mut self, b: u8, on_scroll: &mut F) {
        // C0 controls can interrupt even a pending UTF-8 sequence cleanly.
        if b < 0x20 || b == 0x7F {
            self.utf8_len = 0;
            self.utf8_need = 0;
            match b {
                0x1B => {
                    self.state = ParseState::Esc;
                }
                0x08 => {
                    self.wrap_pending = false;
                    self.cx = self.cx.saturating_sub(1);
                }
                b'\r' => {
                    self.wrap_pending = false;
                    self.cx = 0;
                }
                b'\n' | 0x0B | 0x0C => {
                    self.wrap_pending = false;
                    self.line_feed(on_scroll);
                }
                b'\t' => {
                    self.wrap_pending = false;
                    let next = ((self.cx / 8) + 1) * 8;
                    self.cx = next.min(self.cols - 1);
                }
                _ => {} // NUL, BEL, etc.
            }
            return;
        }

        if b < 0x80 {
            self.utf8_len = 0;
            self.utf8_need = 0;
            self.put_char(b as char, on_scroll);
            return;
        }

        // Streaming UTF-8 decoder.
        if (b & 0xC0) == 0x80 {
            if self.utf8_need > 0 && self.utf8_len < self.utf8_need {
                self.utf8_buf[self.utf8_len] = b;
                self.utf8_len += 1;
                if self.utf8_len == self.utf8_need {
                    let s = core::str::from_utf8(&self.utf8_buf[..self.utf8_len]);
                    self.utf8_len = 0;
                    self.utf8_need = 0;
                    if let Ok(s) = s
                        && let Some(ch) = s.chars().next()
                    {
                        self.put_char(ch, on_scroll);
                    }
                }
            } else {
                self.utf8_len = 0;
                self.utf8_need = 0;
            }
        } else {
            let need = if (b & 0xE0) == 0xC0 {
                2
            } else if (b & 0xF0) == 0xE0 {
                3
            } else if (b & 0xF8) == 0xF0 {
                4
            } else {
                0
            };
            if need > 0 {
                self.utf8_buf[0] = b;
                self.utf8_len = 1;
                self.utf8_need = need;
            } else {
                self.utf8_len = 0;
                self.utf8_need = 0;
            }
        }
    }

    fn put_char<F: FnMut(Vec<Cell>)>(&mut self, ch: char, on_scroll: &mut F) {
        if self.wrap_pending {
            self.wrap_pending = false;
            self.cx = 0;
            self.line_feed(on_scroll);
        }
        let attr = self.current_attr();
        let idx = self.cy * self.cols + self.cx;
        if let Some(slot) = self.cells.get_mut(idx) {
            *slot = cell(ch, attr);
        }
        if self.cx + 1 >= self.cols {
            self.wrap_pending = true;
        } else {
            self.cx += 1;
        }
    }

    fn line_feed<F: FnMut(Vec<Cell>)>(&mut self, on_scroll: &mut F) {
        if self.cy == self.scroll_bottom {
            self.scroll_up(1, on_scroll);
        } else if self.cy + 1 < self.rows {
            self.cy += 1;
        }
    }

    fn scroll_up<F: FnMut(Vec<Cell>)>(&mut self, count: usize, on_scroll: &mut F) {
        let top = self.scroll_top;
        let bot = self.scroll_bottom.min(self.rows - 1);
        if top > bot {
            return;
        }
        let blank = self.blank_cell();
        let n = count.min(bot - top + 1);
        for _ in 0..n {
            if self.alt.is_none() && top == 0 && bot == self.rows - 1 {
                let row = self.row_slice(0);
                let mut end = row.len();
                while end > 0 && row[end - 1] == cell(' ', term::DEFAULT_ATTR) {
                    end -= 1;
                }
                on_scroll(row[..end].to_vec());
            }
            for y in top..bot {
                let dst = y * self.cols;
                let src = (y + 1) * self.cols;
                self.cells.copy_within(src..src + self.cols, dst);
            }
            let last = bot * self.cols;
            self.cells[last..last + self.cols].fill(blank);
        }
    }

    fn scroll_down(&mut self, count: usize) {
        let top = self.scroll_top;
        let bot = self.scroll_bottom.min(self.rows - 1);
        if top > bot {
            return;
        }
        let blank = self.blank_cell();
        let n = count.min(bot - top + 1);
        for _ in 0..n {
            for y in (top + 1..=bot).rev() {
                let dst = y * self.cols;
                let src = (y - 1) * self.cols;
                self.cells.copy_within(src..src + self.cols, dst);
            }
            let first = top * self.cols;
            self.cells[first..first + self.cols].fill(blank);
        }
    }

    fn feed_esc<F: FnMut(Vec<Cell>)>(&mut self, b: u8, on_scroll: &mut F) {
        self.state = ParseState::Ground;
        match b {
            b'[' => {
                self.state = ParseState::Csi;
                self.csi_private = false;
                self.csi_params.clear();
                self.csi_cur = None;
            }
            b']' => {
                self.state = ParseState::Osc;
            }
            b'(' | b')' | b'*' | b'+' => {
                self.state = ParseState::EscCharset;
            }
            b'7' => {
                self.saved_cx = self.cx;
                self.saved_cy = self.cy;
            }
            b'8' => {
                self.cx = self.saved_cx.min(self.cols - 1);
                self.cy = self.saved_cy.min(self.rows - 1);
                self.wrap_pending = false;
            }
            b'D' => {
                self.wrap_pending = false;
                self.line_feed(on_scroll);
            }
            b'E' => {
                self.wrap_pending = false;
                self.cx = 0;
                self.line_feed(on_scroll);
            }
            b'M' => {
                self.wrap_pending = false;
                if self.cy == self.scroll_top {
                    self.scroll_down(1);
                } else {
                    self.cy = self.cy.saturating_sub(1);
                }
            }
            b'c' => {
                let (c, r) = (self.cols, self.rows);
                self.reset(c, r);
                self.clear_scrollback = true;
            }
            _ => {}
        }
    }

    fn feed_csi<F: FnMut(Vec<Cell>)>(&mut self, b: u8, on_scroll: &mut F) {
        match b {
            b'?' if self.csi_params.is_empty() && self.csi_cur.is_none() => {
                self.csi_private = true;
            }
            b'0'..=b'9' => {
                let cur = self.csi_cur.unwrap_or(0);
                self.csi_cur = Some(cur.saturating_mul(10).saturating_add(u16::from(b - b'0')));
            }
            b';' | b':' => {
                if self.csi_params.len() < 16 {
                    self.csi_params.push(self.csi_cur.unwrap_or(0));
                }
                self.csi_cur = None;
            }
            0x20..=0x3F => {} // intermediate / unsupported parameter byte
            0x40..=0x7E => {
                if let Some(v) = self.csi_cur.take()
                    && self.csi_params.len() < 16
                {
                    self.csi_params.push(v);
                }
                self.state = ParseState::Ground;
                self.exec_csi(b, on_scroll);
            }
            _ => {
                self.state = ParseState::Ground;
            }
        }
    }

    fn param(&self, idx: usize, default: usize) -> usize {
        match self.csi_params.get(idx).copied() {
            Some(0) | None => default,
            Some(v) => usize::from(v),
        }
    }

    fn param_raw(&self, idx: usize) -> usize {
        usize::from(self.csi_params.get(idx).copied().unwrap_or(0))
    }

    fn exec_csi<F: FnMut(Vec<Cell>)>(&mut self, cmd: u8, on_scroll: &mut F) {
        if self.csi_private {
            let set = cmd == b'h';
            let reset = cmd == b'l';
            if set || reset {
                for i in 0..self.csi_params.len() {
                    match self.csi_params[i] {
                        25 => self.cursor_visible = set,
                        47 | 1047 | 1049 => {
                            if set {
                                self.enter_alt();
                            } else {
                                self.leave_alt();
                            }
                        }
                        _ => {}
                    }
                }
            }
            return;
        }

        let blank = self.blank_cell();
        match cmd {
            b'A' => {
                self.wrap_pending = false;
                self.cy = self.cy.saturating_sub(self.param(0, 1));
            }
            b'B' => {
                self.wrap_pending = false;
                self.cy = (self.cy + self.param(0, 1)).min(self.rows - 1);
            }
            b'C' => {
                self.wrap_pending = false;
                self.cx = (self.cx + self.param(0, 1)).min(self.cols - 1);
            }
            b'D' => {
                self.wrap_pending = false;
                self.cx = self.cx.saturating_sub(self.param(0, 1));
            }
            b'E' => {
                self.wrap_pending = false;
                self.cx = 0;
                self.cy = (self.cy + self.param(0, 1)).min(self.rows - 1);
            }
            b'F' => {
                self.wrap_pending = false;
                self.cx = 0;
                self.cy = self.cy.saturating_sub(self.param(0, 1));
            }
            b'G' | b'`' => {
                self.wrap_pending = false;
                self.cx = self.param(0, 1).saturating_sub(1).min(self.cols - 1);
            }
            b'd' => {
                self.wrap_pending = false;
                self.cy = self.param(0, 1).saturating_sub(1).min(self.rows - 1);
            }
            b'H' | b'f' => {
                self.wrap_pending = false;
                self.cy = self.param(0, 1).saturating_sub(1).min(self.rows - 1);
                self.cx = self.param(1, 1).saturating_sub(1).min(self.cols - 1);
            }
            b'J' => {
                let mode = self.param_raw(0);
                let cur = self.cy * self.cols + self.cx;
                match mode {
                    0 => self.cells[cur..].fill(blank),
                    1 => {
                        let last = cur.min(self.cells.len() - 1);
                        self.cells[..=last].fill(blank);
                    }
                    2 => {
                        self.cells.fill(blank);
                        if self.alt.is_none() {
                            self.clear_scrollback = true;
                        }
                    }
                    3 => {
                        self.cells.fill(blank);
                        self.clear_scrollback = true;
                    }
                    _ => {}
                }
            }
            b'K' => {
                let mode = self.param_raw(0);
                let row_start = self.cy * self.cols;
                let row_end = row_start + self.cols;
                match mode {
                    0 => self.cells[row_start + self.cx..row_end].fill(blank),
                    1 => self.cells[row_start..=row_start + self.cx].fill(blank),
                    2 => self.cells[row_start..row_end].fill(blank),
                    _ => {}
                }
            }
            b'X' => {
                let n = self.param(0, 1);
                let start = self.cy * self.cols + self.cx;
                let end = (start + n).min((self.cy + 1) * self.cols);
                self.cells[start..end].fill(blank);
            }
            b'P' => {
                // DCH: delete n chars at cursor, shifting rest of line left.
                let n = self.param(0, 1).min(self.cols - self.cx);
                let row = self.cy * self.cols;
                if self.cx + n < self.cols {
                    self.cells.copy_within(row + self.cx + n..row + self.cols, row + self.cx);
                }
                self.cells[row + self.cols - n..row + self.cols].fill(blank);
            }
            b'@' => {
                // ICH: insert n blank chars at cursor, shifting rest of line right.
                let n = self.param(0, 1).min(self.cols - self.cx);
                let row = self.cy * self.cols;
                if self.cx + n < self.cols {
                    self.cells.copy_within(row + self.cx..row + self.cols - n, row + self.cx + n);
                }
                self.cells[row + self.cx..row + self.cx + n].fill(blank);
            }
            b'L' => {
                // IL: insert lines at cursor within scroll region.
                if self.cy >= self.scroll_top && self.cy <= self.scroll_bottom {
                    let old_top = self.scroll_top;
                    self.scroll_top = self.cy;
                    self.scroll_down(self.param(0, 1));
                    self.scroll_top = old_top;
                }
            }
            b'M' => {
                // DL: delete lines at cursor within scroll region.
                if self.cy >= self.scroll_top && self.cy <= self.scroll_bottom {
                    let old_top = self.scroll_top;
                    self.scroll_top = self.cy;
                    self.scroll_up(self.param(0, 1), &mut |_| {});
                    self.scroll_top = old_top;
                }
            }
            b'S' => self.scroll_up(self.param(0, 1), on_scroll),
            b'T' => self.scroll_down(self.param(0, 1)),
            b'r' => {
                let top = self.param(0, 1).saturating_sub(1).min(self.rows - 1);
                let bot = self.param(1, self.rows).saturating_sub(1).min(self.rows - 1);
                if top < bot {
                    self.scroll_top = top;
                    self.scroll_bottom = bot;
                } else {
                    self.scroll_top = 0;
                    self.scroll_bottom = self.rows - 1;
                }
                self.cx = 0;
                self.cy = 0;
                self.wrap_pending = false;
            }
            b's' => {
                self.saved_cx = self.cx;
                self.saved_cy = self.cy;
            }
            b'u' => {
                self.cx = self.saved_cx.min(self.cols - 1);
                self.cy = self.saved_cy.min(self.rows - 1);
                self.wrap_pending = false;
            }
            b'm' => self.apply_sgr(),
            _ => {}
        }
    }

    fn enter_alt(&mut self) {
        if self.alt.is_some() {
            return;
        }
        let blank = cell(' ', term::DEFAULT_ATTR);
        let saved = AltSaved {
            cells: core::mem::replace(&mut self.cells, vec![blank; self.cols * self.rows]),
            cx: self.cx,
            cy: self.cy,
            fg: self.fg,
            bg: self.bg,
            bold: self.bold,
            reverse: self.reverse,
            scroll_top: self.scroll_top,
            scroll_bottom: self.scroll_bottom,
        };
        self.alt = Some(saved);
        self.cx = 0;
        self.cy = 0;
        self.scroll_top = 0;
        self.scroll_bottom = self.rows - 1;
        self.wrap_pending = false;
    }

    fn leave_alt(&mut self) {
        let Some(saved) = self.alt.take() else { return };
        if saved.cells.len() == self.cols * self.rows {
            self.cells = saved.cells;
        }
        self.cx = saved.cx.min(self.cols - 1);
        self.cy = saved.cy.min(self.rows - 1);
        self.fg = saved.fg;
        self.bg = saved.bg;
        self.bold = saved.bold;
        self.reverse = saved.reverse;
        self.scroll_top = saved.scroll_top.min(self.rows - 1);
        self.scroll_bottom = saved.scroll_bottom.min(self.rows - 1);
        self.wrap_pending = false;
    }

    fn apply_sgr(&mut self) {
        if self.csi_params.is_empty() {
            self.fg = term::GREY;
            self.bg = term::BLACK;
            self.bold = false;
            self.reverse = false;
            return;
        }
        let mut i = 0;
        while i < self.csi_params.len() {
            match self.csi_params[i] {
                0 => {
                    self.fg = term::GREY;
                    self.bg = term::BLACK;
                    self.bold = false;
                    self.reverse = false;
                }
                1 => self.bold = true,
                2 => self.bold = false,
                7 => self.reverse = true,
                22 => self.bold = false,
                27 => self.reverse = false,
                30..=37 => self.fg = ansi_to_vga((self.csi_params[i] - 30) as u8, false),
                39 => self.fg = term::GREY,
                40..=47 => self.bg = ansi_to_vga((self.csi_params[i] - 40) as u8, false),
                49 => self.bg = term::BLACK,
                90..=97 => self.fg = ansi_to_vga((self.csi_params[i] - 90) as u8, true),
                100..=107 => self.bg = ansi_to_vga((self.csi_params[i] - 100) as u8, true),
                38 | 48 => {
                    let is_fg = self.csi_params[i] == 38;
                    if i + 2 < self.csi_params.len() && self.csi_params[i + 1] == 5 {
                        let c = ansi256_to_vga(self.csi_params[i + 2] as u8);
                        if is_fg {
                            self.fg = c;
                        } else {
                            self.bg = c;
                        }
                        i += 2;
                    } else if i + 4 < self.csi_params.len() && self.csi_params[i + 1] == 2 {
                        let c = rgb_to_vga(
                            self.csi_params[i + 2] as u8,
                            self.csi_params[i + 3] as u8,
                            self.csi_params[i + 4] as u8,
                        );
                        if is_fg {
                            self.fg = c;
                        } else {
                            self.bg = c;
                        }
                        i += 4;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
}

fn ansi_to_vga(n: u8, bright: bool) -> u8 {
    let base = match n & 7 {
        0 => term::BLACK,
        1 => term::RED,
        2 => term::GREEN,
        3 => term::BROWN,
        4 => term::BLUE,
        5 => term::MAGENTA,
        6 => term::CYAN,
        _ => term::GREY,
    };
    if bright { base + 8 } else { base }
}

fn ansi256_to_vga(n: u8) -> u8 {
    match n {
        0..=7 => ansi_to_vga(n, false),
        8..=15 => ansi_to_vga(n - 8, true),
        16..=231 => {
            let idx = n - 16;
            let r = (idx / 36) * 51;
            let g = ((idx / 6) % 6) * 51;
            let b = (idx % 6) * 51;
            rgb_to_vga(r, g, b)
        }
        _ => {
            let v = (n - 232) * 10 + 8;
            if v < 55 {
                term::BLACK
            } else if v < 128 {
                term::DARK_GREY
            } else if v < 200 {
                term::GREY
            } else {
                term::WHITE
            }
        }
    }
}

fn rgb_to_vga(r: u8, g: u8, b: u8) -> u8 {
    let bright = r > 170 || g > 170 || b > 170;
    let code = u8::from(r > 96) | (u8::from(g > 96) << 1) | (u8::from(b > 96) << 2);
    ansi_to_vga(code, bright)
}
