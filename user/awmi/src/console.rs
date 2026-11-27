//! `console.dsvc`: the graphical terminal. A window showing the terminal's shell session (one
//! session: the same history, scrollback and running commands as the text console), drawn with the
//! monospace face (Iosevka Term with Nerd Font symbols) in the theme's colours.
//!
//! It opens its window when a desktop session starts (a normal boot, the shell's `gui`) and from
//! its launcher entry. It reads the cells from the terminal's view grid (`terminal.view`, mapped
//! read-only; the terminal says which rows changed) and sends back the keys typed in the window.
//! The grid follows the window's size and the text size; the shell is told the new width.

use alloc::vec::Vec;

use dosawmi::{Rect, Theme, UiSettings};
use dosui::{FontText, TextStyle};
use libd::awmi::{self as wire, Event, Window};
use libd::proto::{self, HEADER, Header, key};
use libd::sys::{self, Handle};
use libd::{Mapping, Port, Startup, println, svc, term};

use crate::app::{canvas_of, settings_of, text_engine};

const KEY_WIN: u64 = 2;
const KEY_VIEW: u64 = 3;
const CALL_NS: u64 = 5_000_000_000;
/// The window's first size, in cells.
const START_COLS: u32 = 100;
const START_ROWS: u32 = 30;

/// The 16 colours of the session (`term::*`) in a theme: soft on Dark Slate, bright in High
/// Contrast. Black and grey are the theme's background and text.
fn palette(t: &Theme, contrast: bool) -> [u32; 16] {
    let soft = [0, 0xFF5F_6FA8, 0xFF6F_BF8E, 0xFF5F_B3B3, 0xFFE0_6C75, 0xFFB4_8EAD, 0xFFD1_9A66, 0, 0, 0, 0xFF8F_D9A8, 0xFF7F_D1D1, 0xFFF0_8A8A, 0xFFC9_A0DC, 0xFFE5_C07B, 0xFFFF_FFFF];
    let bright = [0, 0xFF8A_9BFF, 0xFF4A_DE80, 0xFF22_D3EE, 0xFFFF_5555, 0xFFE8_79F9, 0xFFFB_BF24, 0, 0, 0, 0xFF86_EFAC, 0xFF67_E8F9, 0xFFFF_8A8A, 0xFFF0_ABFC, 0xFFFD_E047, 0xFFFF_FFFF];
    let mut p = if contrast { bright } else { soft };
    p[0] = t.client_bg;
    p[7] = t.text_primary;
    p[8] = t.text_muted;
    p[9] = t.accent_ring;
    p
}

struct Term {
    win: Window,
    back: Vec<u32>,
    grid: Option<Mapping>,
    cols: u32,
    rows: u32,
    cell_w: u32,
    cell_h: u32,
    ascent: i32,
    pad: u32,
    in_flight: bool,
    /// Rows to draw again (start, end), and whether the whole window must be.
    dirty: Option<(u32, u32)>,
    full: bool,
    focused: bool,
}

/// One call on the view channel; the reply header and its handle (if any).
fn view_call(view: Handle, op: u32, a: u64) -> Option<(Header, Handle)> {
    let mut req = [0u8; HEADER];
    Header { txid: 0, op, status: 0, a, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let mut hs = [0 as Handle; 1];
    let (n, nh) = sys::channel_call_h(view, &req, &[], &mut rep, &mut hs, CALL_NS).ok()?;
    let h = Header::get(&rep[..n])?;
    let hd = if nh > 0 { hs[0] } else { 0 };
    if h.status != 0 {
        if hd != 0 {
            sys::handle_close(hd);
        }
        return None;
    }
    Some((h, hd))
}

impl Term {
    fn metrics(text: &FontText<'_>) -> (u32, u32, i32) {
        let st = text.style(TextStyle::Mono);
        let cw = (text.engine.advance64(st, 'M') + 32) / 64;
        let m = text.engine.metrics(st);
        (cw.max(4) as u32, m.height.max(8) as u32, m.ascent)
    }

    fn open(ep: Handle, view: Handle, text: &FontText<'_>) -> Option<Term> {
        let (cell_w, cell_h, ascent) = Self::metrics(text);
        let pad = 6;
        let (w, h) = (START_COLS * cell_w + pad * 2, START_ROWS * cell_h + pad * 2);
        let win = Window::new(ep, w, h, wire::FLAGS_DEFAULT, b"Terminal").ok()?;
        let back = alloc::vec![0u32; (win.width as usize) * (win.height as usize)];
        let mut t = Term { win, back, grid: None, cols: 0, rows: 0, cell_w, cell_h, ascent, pad, in_flight: false, dirty: None, full: true, focused: true };
        t.fit();
        let (hdr, vmo) = view_call(view, term::VIEW_ATTACH, u64::from(t.cols) | u64::from(t.rows) << 32)?;
        if vmo == 0 {
            return None;
        }
        match Mapping::of_ro(vmo, hdr.a) {
            Ok(m) => t.grid = Some(m),
            Err(e) => {
                println!("console: cannot map the terminal grid ({})", sys::status(e));
                sys::handle_close(vmo);
                return None;
            }
        }
        println!("console: terminal window {} open ({}x{} cells of {}x{} px)", t.win.id, t.cols, t.rows, cell_w, cell_h);
        Some(t)
    }

    /// The grid that fits the window.
    fn fit(&mut self) {
        self.cols = (self.win.width.saturating_sub(self.pad * 2) / self.cell_w).clamp(20, term::VIEW_MAX_COLS);
        self.rows = (self.win.height.saturating_sub(self.pad * 2) / self.cell_h).clamp(5, term::VIEW_MAX_ROWS);
    }

    fn mark(&mut self, a: u32, b: u32) {
        self.dirty = Some(match self.dirty {
            Some((x, y)) => (x.min(a), y.max(b)),
            None => (a, b),
        });
    }

    fn draw(&mut self, text: &mut FontText<'_>, theme: &Theme, contrast: bool) {
        if self.in_flight || (self.dirty.is_none() && !self.full) {
            return;
        }
        let Some(grid) = self.grid.as_ref() else { return };
        let r32 = |off: usize| grid.r32(off as u64);
        if r32(0) != term::VIEW_MAGIC {
            return;
        }
        let (gc, gr) = (r32(4).min(self.cols), r32(8).min(self.rows));
        let (cx, cy) = (r32(12), r32(16));
        let pal = palette(theme, contrast);
        let (rows_from, rows_to) = if self.full { (0, gr) } else { self.dirty.unwrap_or((0, 0)) };
        let (rows_from, rows_to) = (rows_from.min(gr), rows_to.min(gr));
        let full = self.full;
        let (cw, ch, pad, ascent) = (self.cell_w, self.cell_h, self.pad as i32, self.ascent);
        let st = text.style(TextStyle::Mono);
        let (ww, wh) = (self.win.width, self.win.height);
        let need = (ww as usize) * (wh as usize);
        if self.back.len() != need {
            self.back.resize(need, pal[0]);
        }
        let Some(mut c) = dosawmi::Canvas::new(&mut self.back, ww, wh, ww) else { return };
        let all = c.bounds();
        if full {
            c.fill_rect(all, all, pal[0]);
        }
        for y in rows_from..rows_to {
            let py = pad + (y * ch) as i32;
            let row = Rect::new(0, py, all.w, ch);
            c.fill_rect(row, row, pal[0]);
            for x in 0..gc {
                let cell = r32(term::VIEW_HEADER + ((y * gc + x) as usize) * 4);
                let ch_ = char::from_u32(cell & 0x1F_FFFF).unwrap_or('?');
                let attr = (cell >> 24) as u8;
                let (mut fg, mut bg) = (pal[usize::from(attr & 0xF)], pal[usize::from(attr >> 4)]);
                let at_cursor = x == cx && y == cy;
                if at_cursor && self.focused {
                    (fg, bg) = (pal[0], theme.accent_ring);
                }
                let px = pad + (x * cw) as i32;
                let cell_r = Rect::new(px, py, cw, ch);
                if bg != pal[0] {
                    c.fill_rect(cell_r, cell_r, bg);
                }
                if at_cursor && !self.focused {
                    c.stroke_rect(cell_r, cell_r, theme.accent_ring);
                }
                if ch_ != ' ' {
                    text.draw_cell(&mut c, cell_r, px, py + ascent, st, ch_, fg);
                }
            }
        }
        let damage: Vec<(i32, i32, u32, u32)> = if full {
            Vec::new()
        } else if rows_to > rows_from {
            alloc::vec![(0, pad + (rows_from * ch) as i32, all.w, (rows_to - rows_from) * ch)]
        } else {
            self.dirty = None;
            return;
        };
        if let Some(front) = canvas_of(&mut self.win) {
            if full {
                front.pixels[..need].copy_from_slice(&self.back[..need]);
            } else {
                let y0 = (pad + (rows_from * ch) as i32).max(0) as usize;
                let y1 = (pad + (rows_to * ch) as i32).min(wh as i32).max(0) as usize;
                let stride = ww as usize;
                if y1 > y0 {
                    front.pixels[y0 * stride..y1 * stride].copy_from_slice(&self.back[y0 * stride..y1 * stride]);
                }
            }
        }
        self.full = false;
        self.dirty = None;
        if self.win.commit(&damage).is_ok() {
            self.in_flight = true;
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "terminal") } {
        return 1;
    }
    let ep = wire::window_endpoint();
    let view = svc::endpoint(b"terminal.view");
    if ep == 0 || view == 0 {
        println!("console: needs awmi.window and terminal.view");
        return 1;
    }
    let Ok(port) = Port::new(8) else { return 1 };
    port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
    port.arm(view, sys::READABLE | sys::PEER_CLOSED, KEY_VIEW);
    let mut text = text_engine(ep, "console");
    let mut theme = Theme::DARK_SLATE;
    let mut settings = UiSettings::DEFAULT;
    // Drain any initial EVT_SETTINGS sent on connect before creating the window.
    while let Ok(Some(ev)) = wire::next_event(ep, 0) {
        if let Event::Settings { settings: s, theme: th } = ev {
            (theme, settings) = settings_of(s, &th);
            text.scale = settings.text_scale;
        }
    }
    let Some(mut tm) = Term::open(ep, view, &text) else {
        return 1;
    };
    tm.draw(&mut text, &theme, settings.theme == dosawmi::ThemeId::HighContrast);
    let detach = |view: Handle| {
        let _ = view_call(view, term::VIEW_DETACH, 0);
    };
    loop {
        let Some((k, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        match k {
            KEY_VIEW => {
                let mut buf = [0u8; HEADER + 16];
                loop {
                    match sys::channel_read(view, &mut buf, 0) {
                        Ok(n) => {
                            if let Some(h) = Header::get(&buf[..n as usize])
                                && h.op == term::VIEW_DAMAGE
                            {
                                tm.mark(h.a as u32, h.b as u32);
                            }
                        }
                        Err(sys::ERR_SHOULD_WAIT) => {
                            port.arm(view, sys::READABLE | sys::PEER_CLOSED, KEY_VIEW);
                            break;
                        }
                        Err(_) => {
                            detach(view);
                            return 0;
                        }
                    }
                }
                tm.draw(&mut text, &theme, settings.theme == dosawmi::ThemeId::HighContrast);
            }
            _ => loop {
                let ev = match wire::next_event(ep, 0) {
                    Ok(Some(e)) => e,
                    Ok(None) => {
                        port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
                        break;
                    }
                    Err(_) => {
                        detach(view);
                        return 0;
                    }
                };
                match ev {
                    Event::Settings { settings: s, theme: th } => {
                        (theme, settings) = settings_of(s, &th);
                        text.scale = settings.text_scale;
                        (tm.cell_w, tm.cell_h, tm.ascent) = Term::metrics(&text);
                        tm.fit();
                        let _ = view_call(view, term::VIEW_RESIZE, u64::from(tm.cols) | u64::from(tm.rows) << 32);
                        tm.full = true;
                    }
                    Event::Session { active: false, .. } => {
                        detach(view);
                        return 0;
                    }
                    Event::Close { window } if tm.win.id == window => {
                        detach(view);
                        return 0;
                    }
                    Event::Configure { window, width, height, state } if tm.win.id == window => {
                        tm.focused = state & wire::STATE_FOCUSED != 0;
                        if tm.win.resize(width, height).is_ok() {
                            let (oc, or) = (tm.cols, tm.rows);
                            tm.fit();
                            if (oc, or) != (tm.cols, tm.rows) {
                                let _ = view_call(view, term::VIEW_RESIZE, u64::from(tm.cols) | u64::from(tm.rows) << 32);
                            }
                        }
                        tm.full = true;
                    }
                    Event::Focus { window, focused } if tm.win.id == window => {
                        tm.focused = focused;
                        tm.full = true;
                    }
                    Event::Key { key: kv, .. } => {
                        if kv & key::RELEASE == 0 {
                            proto::send(view, term::VIEW_KEY, u64::from(kv), 0);
                        }
                    }
                    Event::Pointer { kind, wheel, .. } if kind == wire::PTR_WHEEL && wheel != 0 => {
                        let k = if wheel > 0 { key::PAGE_UP } else { key::PAGE_DOWN };
                        proto::send(view, term::VIEW_KEY, u64::from(k), 0);
                    }
                    Event::FrameDone { window, .. } if tm.win.id == window => {
                        tm.in_flight = false;
                    }
                    _ => {}
                }
                tm.draw(&mut text, &theme, settings.theme == dosawmi::ThemeId::HighContrast);
            },
        }
    }
}
