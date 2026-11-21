//! The terminal service (`terminal.dx`, docs/shell.md): the screen and the keyboard, for the shell.
//!
//! It holds two things: the display device (manifest grant `devices = ["platform:display"]`;
//! mapping it takes the screen from the kernel console) and the device manager's `input`
//! endpoint. It offers one endpoint, `session`, to the shell, and keeps no other authority: what
//! the shell can do is the shell's manifest, not the terminal's.
//!
//! - Output: text from the session with colours (`libd::term`), kept as lines in a scrollback of
//!   `MAX_LINES` lines (PgUp/PgDn, Shift too) and wrapped when drawn, so it reflows at any width.
//! - Input: a line editor for the session's `READ`: insert anywhere, Backspace/Delete, Left/Right,
//!   Home/End (Ctrl+A/Ctrl+E), history (Up/Down), Tab (the session completes the last word),
//!   Escape clears, Ctrl+C cancels the line (or interrupts the running command), Ctrl+L clears the
//!   screen. A line typed while a command runs is kept and submitted when the next prompt comes.
//! - Every line typed is logged (`terminal: line from <keyboard>: <text>`). With the argument
//!   `mirror` (or without a display) every line shown is logged too (`terminal| ...`), so a
//!   session can be followed on the serial line.
//! - `display` endpoint (the compositor): `term::DISPLAY_RELEASE` stops drawing while a graphical
//!   session owns the screen; `term::DISPLAY_RECLAIM`, or that channel closing, redraws it all.
//! - `view` endpoint (the graphical terminal): while the screen is released, the session is laid
//!   out for the viewer's grid and kept in a VMO it maps read-only (`term::VIEW_*`); the keys typed
//!   in its window come back here. When it detaches or the screen comes back, the screen's grid is
//!   used again; the shell is told each new width.

#![no_std]

extern crate alloc;

mod font;
mod screen;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use libd::proto::{self, HEADER, Header, key};
use libd::sys::{self, Handle, MsgHandle};
use libd::{Mapping, Port, Startup, println, svc, term};
use screen::{Cell, Screen, cell, char_of};

libd::entry!(_start, main);

const KEY_CTL: u64 = 1;
const KEY_INPUT: u64 = 2;
const KEY_SESSION: u64 = 3;
const KEY_INDICATOR: u64 = 4;
const KEY_DISPLAY: u64 = 5;
const KEY_VIEW: u64 = 6;

/// Lines kept for scrolling back.
const MAX_LINES: usize = 2000;
const MAX_HISTORY: usize = 100;
/// Longest line the editor takes.
const MAX_EDIT: usize = 1024;
/// Longest output line kept as one line (longer ones continue on the next).
const MAX_LINE: usize = 4096;

/// A shown character back as text (for the mirrored log lines).
fn ascii(c: char) -> char {
    match c {
        ' '..='~' => c,
        '▸' | '►' | '▶' => '>',
        '◂' | '◄' => '<',
        '✓' | '√' => 'v',
        '✗' | '✘' => 'x',
        '·' | '•' => '.',
        '—' | '–' | '─' => '-',
        '│' => '|',
        _ => '?',
    }
}

/// The session shown in a window (`terminal.view`).
struct View {
    ch: Handle,
    map: Mapping,
    vmo_ro: Handle,
    cols: usize,
    rows: usize,
    /// What the grid holds (to write and report only changes).
    shown: Vec<Cell>,
    cursor: Option<(usize, usize)>,
    attached: bool,
}

impl View {
    fn header(&self) {
        let m = &self.map;
        m.w32(0, term::VIEW_MAGIC);
        m.w32(4, self.cols as u32);
        m.w32(8, self.rows as u32);
        let (cx, cy) = self.cursor.map_or((u32::MAX, u32::MAX), |(x, y)| (x as u32, y as u32));
        m.w32(12, cx);
        m.w32(16, cy);
        m.w32(20, u32::from(term::DEFAULT_ATTR));
    }

    fn resize(&mut self, cols: usize, rows: usize) {
        self.cols = cols.clamp(20, term::VIEW_MAX_COLS as usize);
        self.rows = rows.clamp(5, term::VIEW_MAX_ROWS as usize);
        self.shown.clear();
        self.shown.resize(self.cols * self.rows, u32::MAX);
        self.header();
    }
}

struct Term {
    scr: Screen,
    /// Finished output lines (logical: wrapped only when drawn).
    lines: VecDeque<Vec<Cell>>,
    /// The output line being written (no newline yet).
    cur: Vec<Cell>,
    attr: u8,
    /// Rows scrolled back from the bottom (0: following the output).
    scroll: usize,
    // the line editor
    reading: bool,
    prompt: Vec<Cell>,
    edit: Vec<char>,
    at: usize,
    history: Vec<String>,
    hist: Option<usize>,
    saved: String,
    waiting_completion: bool,
    /// Enter was pressed while no line was being read (a command still running): the typed line
    /// is submitted as soon as the session asks for the next one (type-ahead).
    enter_ahead: bool,
    session: Handle,
    indicator: Handle,
    mic_active: bool,
    /// The compositor's `display` channel, and whether it holds the screen now.
    display: Handle,
    released: bool,
    view: Option<View>,
    /// The grid the session was last told about (columns, rows).
    told: (usize, usize),
    mirror: bool,
    /// Which keyboard the last key came from (for the log line).
    from: [u8; 24],
    from_len: usize,
}

impl Term {
    /// The grid drawn into now: the window's while a viewer shows the session, else the screen's.
    fn showing_view(&self) -> bool {
        self.released && self.view.as_ref().is_some_and(|v| v.attached)
    }

    fn grid(&self) -> (usize, usize) {
        match &self.view {
            Some(v) if self.showing_view() => (v.cols, v.rows),
            _ => (self.scr.cols, self.scr.rows),
        }
    }

    fn cols(&self) -> usize {
        self.grid().0.max(1)
    }

    /// Tell the shell when the width it formats for changes.
    fn tell_size(&mut self) {
        let g = self.grid();
        if g != self.told {
            self.told = g;
            self.send(term::SIZE, g.0 as u64, g.1 as u64, &[]);
        }
    }

    fn push_line(&mut self, l: Vec<Cell>) {
        if self.mirror {
            let s: String = l.iter().map(|&c| ascii(char_of(c))).collect();
            println!("terminal| {}", s.trim_end());
        }
        if self.lines.len() == MAX_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(l);
    }

    /// Show text with style bytes (`term::STYLE attr`, `term::PLAIN`).
    fn write(&mut self, text: &[u8]) {
        let s = String::from_utf8_lossy(text);
        let mut style = false;
        for ch in s.chars() {
            if style {
                self.attr = ch as u32 as u8;
                style = false;
                continue;
            }
            match ch {
                '\u{1}' => style = true,
                '\u{2}' => self.attr = term::DEFAULT_ATTR,
                '\n' => {
                    let l = core::mem::take(&mut self.cur);
                    self.push_line(l);
                }
                '\t' => {
                    for _ in 0..(4 - self.cur.len() % 4) {
                        self.put_char(' ');
                    }
                }
                c if (c as u32) < 0x20 => {}
                c => self.put_char(c),
            }
        }
    }

    fn put_char(&mut self, c: char) {
        if self.cur.len() >= MAX_LINE {
            let l = core::mem::take(&mut self.cur);
            self.push_line(l);
        }
        self.cur.push(cell(c, self.attr));
    }

    /// The prompt and the line being edited, wrapped: (rows, cursor (x, row)).
    fn edit_lines(&self) -> (Vec<Vec<Cell>>, (usize, usize)) {
        let cols = self.cols();
        let mut all: Vec<Cell> = self.prompt.clone();
        all.extend(self.edit.iter().map(|&c| cell(c, term::DEFAULT_ATTR)));
        let cur = self.prompt.len() + self.at;
        let n = all.len().max(cur + 1);
        let mut out = Vec::new();
        let mut i = 0;
        while i < n {
            out.push(all[i.min(all.len())..(i + cols).min(all.len())].to_vec());
            i += cols;
        }
        (out, (cur % cols, cur / cols))
    }

    /// The compositor gave the screen back (or went away): draw every cell again.
    fn reclaim(&mut self) {
        if self.released {
            self.released = false;
            self.scr.invalidate();
            println!("terminal: display reclaimed");
        }
    }

    /// The rows to show (`rows` of them, `scroll` rows up from the bottom), the cursor's place.
    fn frame(&mut self, cols: usize, rows: usize) -> (Vec<Vec<Cell>>, Option<(usize, usize)>) {
        // Rows of the live part below the scrollback: the current line, the prompt and edit.
        let mut tail: Vec<Vec<Cell>> = Vec::new();
        if !self.cur.is_empty() {
            for ch in self.cur.chunks(cols) {
                tail.push(ch.to_vec());
            }
        }
        let mut cursor_row = None;
        if self.reading {
            let (ls, (cx, cy)) = self.edit_lines();
            cursor_row = Some((cx, tail.len() + cy));
            tail.extend(ls);
        }
        // Enough wrapped rows from the end of the scrollback for the view and the scroll.
        let want = rows + self.scroll;
        let mut back: Vec<Vec<Cell>> = Vec::new();
        for l in self.lines.iter().rev() {
            if back.len() + tail.len() >= want {
                break;
            }
            let n = l.len().div_ceil(cols).max(1);
            for k in (0..n).rev() {
                back.push(l[(k * cols).min(l.len())..((k + 1) * cols).min(l.len())].to_vec());
            }
        }
        back.reverse();
        let available = back.len() + tail.len();
        self.scroll = self.scroll.min(available.saturating_sub(rows));
        let mut all = back;
        let first_tail = all.len();
        all.extend(tail);
        let end = all.len().saturating_sub(self.scroll);
        let start = end.saturating_sub(rows);
        let cursor = match cursor_row {
            Some((cx, cr)) if self.scroll == 0 => {
                let r = first_tail + cr;
                (r >= start && r < end).then(|| (cx, r - start))
            }
            _ => None,
        };
        (all[start..end].to_vec(), cursor)
    }

    /// Draw what is visible now: in the window's grid while a viewer shows the session, on the
    /// screen otherwise (nothing while a graphical session holds the screen without a viewer).
    fn render(&mut self) {
        self.tell_size();
        if self.showing_view() {
            self.render_view();
            return;
        }
        if self.released {
            return;
        }
        let (cols, rows) = (self.scr.cols, self.scr.rows);
        let (shown, cursor) = self.frame(cols, rows);
        self.scr.set_cursor(cursor);
        let blank = cell(' ', term::DEFAULT_ATTR);
        for y in 0..rows {
            let line = shown.get(y).map_or(&[][..], |l| &l[..]);
            for x in 0..cols {
                self.scr.put(x, y, line.get(x).copied().unwrap_or(blank));
            }
        }
        // Visible active microphone indicator (top-right badge on row 0, unforgeable: only audio.dsvc holds `terminal.indicator`).
        if self.mic_active && rows > 0 && cols >= 12 {
            let badge = " [MIC LIVE] ";
            let attr = term::WHITE | (term::RED << 4);
            let start = cols - badge.len();
            for (i, ch) in badge.chars().enumerate() {
                self.scr.put(start + i, 0, cell(ch, attr));
            }
        }
    }

    fn render_view(&mut self) {
        let Some((cols, rows)) = self.view.as_ref().map(|v| (v.cols, v.rows)) else { return };
        let (shown, cursor) = self.frame(cols, rows);
        let Some(v) = self.view.as_mut() else { return };
        let blank = cell(' ', term::DEFAULT_ATTR);
        let (mut lo, mut hi) = (usize::MAX, 0usize);
        for y in 0..rows {
            let line = shown.get(y).map_or(&[][..], |l| &l[..]);
            for x in 0..cols {
                let c = line.get(x).copied().unwrap_or(blank);
                let i = y * cols + x;
                if v.shown[i] != c {
                    v.shown[i] = c;
                    v.map.w32((term::VIEW_HEADER + i * 4) as u64, c);
                    lo = lo.min(y);
                    hi = hi.max(y + 1);
                }
            }
        }
        if cursor != v.cursor {
            for (_, y) in [v.cursor, cursor].into_iter().flatten() {
                lo = lo.min(y);
                hi = hi.max(y + 1);
            }
            v.cursor = cursor;
            v.header();
        }
        if lo < hi {
            proto::send(v.ch, term::VIEW_DAMAGE, lo as u64, hi as u64);
        }
    }

    fn send(&self, op: u32, a: u64, b: u64, payload: &[u8]) {
        if self.session == 0 {
            return;
        }
        let mut m = Vec::with_capacity(HEADER + payload.len());
        m.resize(HEADER, 0);
        Header { txid: 0, op, status: 0, a, b }.put(&mut m);
        m.extend_from_slice(payload);
        sys::channel_write(self.session, &m);
    }

    /// The edited line becomes output (prompt and text stay in the scrollback); then it goes to
    /// the session.
    fn submit(&mut self, cancelled: bool) {
        let text: String = self.edit.iter().collect();
        let mut line: Vec<Cell> = self.prompt.clone();
        line.extend(self.edit.iter().map(|&c| cell(c, term::DEFAULT_ATTR)));
        if cancelled {
            line.extend("^C".chars().map(|c| cell(c, term::DARK_GREY)));
        }
        self.push_line(line);
        if !cancelled {
            let from = core::str::from_utf8(&self.from[..self.from_len]).unwrap_or("?");
            println!("terminal: line from {}: {}", from, text);
            if !text.trim().is_empty() && self.history.last() != Some(&text) {
                if self.history.len() == MAX_HISTORY {
                    self.history.remove(0);
                }
                self.history.push(text.clone());
            }
        }
        self.reading = false;
        self.edit.clear();
        self.at = 0;
        self.hist = None;
        self.send(term::LINE, u64::from(cancelled), 0, if cancelled { &[] } else { text.as_bytes() });
    }

    fn set_edit(&mut self, s: &str) {
        self.edit = s.chars().take(MAX_EDIT).collect();
        self.at = self.edit.len();
    }

    fn history_step(&mut self, back: bool) {
        if self.history.is_empty() {
            return;
        }
        let next = match (self.hist, back) {
            (None, true) => {
                self.saved = self.edit.iter().collect();
                Some(self.history.len() - 1)
            }
            (None, false) => return,
            (Some(0), true) => Some(0),
            (Some(i), true) => Some(i - 1),
            (Some(i), false) if i + 1 < self.history.len() => Some(i + 1),
            (Some(_), false) => None,
        };
        self.hist = next;
        let s = match next {
            Some(i) => self.history[i].clone(),
            None => core::mem::take(&mut self.saved),
        };
        self.set_edit(&s);
    }

    /// The session's candidates for the word before the cursor.
    fn complete(&mut self, payload: &[u8]) {
        self.waiting_completion = false;
        let cands: Vec<String> = payload.split(|&c| c == 0).filter(|c| !c.is_empty()).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
        if cands.is_empty() || !self.reading {
            return;
        }
        let start = self.edit[..self.at].iter().rposition(|&c| c == ' ').map_or(0, |p| p + 1);
        let word: String = self.edit[start..self.at].iter().collect();
        let mut common: String = cands[0].clone();
        for c in &cands[1..] {
            let n = common.chars().zip(c.chars()).take_while(|(a, b)| a == b).count();
            common = common.chars().take(n).collect();
        }
        let replace = |t: &mut Term, with: &str| {
            let tail: Vec<char> = t.edit[t.at..].to_vec();
            t.edit.truncate(start);
            t.edit.extend(with.chars());
            t.at = t.edit.len();
            t.edit.extend(tail);
            t.edit.truncate(MAX_EDIT);
        };
        if cands.len() == 1 {
            let mut w = cands[0].clone();
            if !w.ends_with('/') {
                w.push(' ');
            }
            replace(self, &w);
        } else if common.chars().count() > word.chars().count() {
            replace(self, &common);
        } else {
            // Several: list them above the prompt.
            let mut line = String::new();
            for c in &cands {
                line.push_str(c);
                line.push_str("  ");
            }
            line.push('\n');
            self.write(line.as_bytes());
        }
    }

    fn key(&mut self, k: u32) {
        if k & key::RELEASE != 0 || k & key::MASK == key::META {
            return; // Super on its own is the compositor's
        }
        let base = k & key::MASK;
        if base == key::PAGE_UP || base == key::PAGE_DOWN {
            let page = self.grid().1.saturating_sub(1).max(1);
            self.scroll = if base == key::PAGE_UP { self.scroll + page } else { self.scroll.saturating_sub(page) };
            return;
        }
        self.scroll = 0;
        match base {
            0x03 => {
                self.enter_ahead = false;
                if self.reading {
                    self.submit(true);
                } else {
                    self.edit.clear();
                    self.at = 0;
                    self.send(term::INTERRUPT, 0, 0, &[]);
                }
            }
            0x0C => {
                self.lines.clear();
                self.cur.clear();
            }
            0x0A | 0x0D => {
                if self.reading {
                    self.submit(false);
                } else {
                    self.enter_ahead = true;
                }
            }
            0x08 if self.at > 0 => {
                self.at -= 1;
                self.edit.remove(self.at);
            }
            key::DELETE if self.at < self.edit.len() => {
                self.edit.remove(self.at);
            }
            key::LEFT if self.at > 0 => self.at -= 1,
            key::RIGHT if self.at < self.edit.len() => self.at += 1,
            key::HOME | 0x01 => self.at = 0,
            key::END | 0x05 => self.at = self.edit.len(),
            key::UP => self.history_step(true),
            key::DOWN => self.history_step(false),
            0x1B => {
                self.enter_ahead = false;
                self.edit.clear();
                self.at = 0;
            }
            0x09 => {
                if self.reading && !self.waiting_completion && self.session != 0 {
                    let before: String = self.edit[..self.at].iter().collect();
                    self.waiting_completion = true;
                    self.send(term::COMPLETE, 0, 0, before.as_bytes());
                }
            }
            0x20..=0x7E if self.edit.len() < MAX_EDIT => {
                self.edit.insert(self.at, char::from(base as u8));
                self.at += 1;
            }
            _ => {}
        }
    }

    /// A message from the session (the shell).
    fn session_msg(&mut self, buf: &[u8]) {
        let Some(h) = Header::get(buf) else { return };
        let payload = &buf[HEADER..];
        match h.op {
            term::WRITE => self.write(payload),
            term::READ => {
                if !self.cur.is_empty() {
                    let l = core::mem::take(&mut self.cur);
                    self.push_line(l);
                }
                let s = String::from_utf8_lossy(payload);
                let mut attr = term::DEFAULT_ATTR;
                let mut style = false;
                self.prompt.clear();
                for ch in s.chars() {
                    match ch {
                        _ if style => {
                            attr = ch as u32 as u8;
                            style = false;
                        }
                        '\u{1}' => style = true,
                        '\u{2}' => attr = term::DEFAULT_ATTR,
                        c if (c as u32) < 0x20 => {}
                        c => self.prompt.push(cell(c, attr)),
                    }
                }
                self.reading = true;
                self.scroll = 0;
                if core::mem::take(&mut self.enter_ahead) {
                    self.submit(false);
                }
            }
            term::COMPLETIONS => self.complete(payload),
            term::CLEAR => {
                self.lines.clear();
                self.cur.clear();
            }
            _ => {}
        }
    }

    fn connect(&mut self, ch: Handle) {
        if self.session != 0 {
            sys::handle_close(self.session);
        }
        self.session = ch;
        self.reading = false;
        self.waiting_completion = false;
        self.enter_ahead = false;
        let g = self.grid();
        self.told = g;
        self.send(term::SIZE, g.0 as u64, g.1 as u64, &[]);
    }

    /// A request from the viewer (`terminal.view`). The reply, if it was a call.
    fn view_msg(&mut self, h: Header) -> Option<(i64, u64, Option<Handle>)> {
        let grid = |a: u64| ((a as u32) as usize, (a >> 32) as usize);
        match h.op {
            term::VIEW_ATTACH => {
                let Some(v) = self.view.as_mut() else { return Some((sys::ERR_BAD_STATE, 0, None)) };
                let (c, r) = grid(h.a);
                v.resize(c, r);
                v.attached = true;
                v.cursor = None;
                let (cols, rows) = (v.cols, v.rows);
                let dup = sys::handle_duplicate(v.vmo_ro, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER).ok();
                println!("terminal: view attached ({}x{} cells)", cols, rows);
                Some((0, term::VIEW_BYTES as u64, dup))
            }
            term::VIEW_RESIZE => {
                if let Some(v) = self.view.as_mut() {
                    let (c, r) = grid(h.a);
                    v.resize(c, r);
                }
                Some((0, 0, None))
            }
            term::VIEW_DETACH => {
                if let Some(v) = self.view.as_mut()
                    && v.attached
                {
                    v.attached = false;
                    println!("terminal: view detached");
                }
                Some((0, 0, None))
            }
            term::VIEW_KEY => {
                let from = b"console";
                self.from[..from.len()].copy_from_slice(from);
                self.from_len = from.len();
                self.key(h.a as u32);
                None
            }
            _ => Some((sys::ERR_NOT_SUPPORTED, 0, None)),
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "terminal") } {
        return 1;
    }
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let mut input: Handle = svc::endpoint(b"devmgr.input");
    let Ok(port) = Port::new(32) else { return 1 };
    let scr = Screen::open(libd::startup_handle(sys::TAG_DEVICE));
    let mirror = libd::args().split(|&c| c == b' ' || c == 0).any(|a| a == b"mirror") || !scr.present();
    println!("terminal: ready: {} ({}x{}), keyboard input from devmgr.input{}", scr.what, scr.cols, scr.rows, if mirror { ", mirrored to the log" } else { "" });
    let told = (scr.cols, scr.rows);
    let mut t = Term {
        scr,
        lines: VecDeque::new(),
        cur: Vec::new(),
        attr: term::DEFAULT_ATTR,
        scroll: 0,
        reading: false,
        prompt: Vec::new(),
        edit: Vec::new(),
        at: 0,
        history: Vec::new(),
        hist: None,
        saved: String::new(),
        waiting_completion: false,
        enter_ahead: false,
        session: 0,
        indicator: 0,
        mic_active: false,
        display: 0,
        released: false,
        view: None,
        told,
        mirror,
        from: [0; 24],
        from_len: 0,
    };
    if ctl != 0 {
        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if input != 0 {
        port.arm(input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
    }
    t.render();
    let mut buf = alloc::vec![0u8; 64 * 1024];
    loop {
        let Some((k, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        match k {
            KEY_INPUT => loop {
                match sys::channel_read(input, &mut buf, 0) {
                    Ok(n) => {
                        let n = n as usize;
                        if let Some(h) = Header::get(&buf[..n])
                            && h.op == proto::INPUT_KEY
                        {
                            let from = (n - HEADER).min(24);
                            t.from[..from].copy_from_slice(&buf[HEADER..HEADER + from]);
                            t.from_len = from;
                            t.key(h.a as u32);
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
                        break;
                    }
                    Err(_) => break, // the device manager is gone; the service manager links us again
                }
            },
            KEY_SESSION => loop {
                match sys::channel_read(t.session, &mut buf, 0) {
                    Ok(n) => t.session_msg(&buf[..n as usize]),
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(t.session, sys::READABLE | sys::PEER_CLOSED, KEY_SESSION);
                        break;
                    }
                    Err(_) => {
                        // The shell is gone (it is restarted and connects again).
                        sys::handle_close(t.session);
                        t.session = 0;
                        t.reading = false;
                        break;
                    }
                }
            },
            KEY_INDICATOR => loop {
                match sys::channel_read(t.indicator, &mut buf, 0) {
                    Ok(n) => {
                        let n = n as usize;
                        if let Some(h) = Header::get(&buf[..n])
                            && h.op == term::INDICATOR
                        {
                            let active = (h.a & term::IND_MIC_ACTIVE) != 0;
                            if active != t.mic_active {
                                t.mic_active = active;
                                let label = core::str::from_utf8(&buf[HEADER..n]).unwrap_or("");
                                if active {
                                    println!("terminal: indicator: MIC LIVE{}", if label.is_empty() { "" } else { " (active)" });
                                } else {
                                    println!("terminal: indicator: MIC OFF");
                                }
                            }
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(t.indicator, sys::READABLE | sys::PEER_CLOSED, KEY_INDICATOR);
                        break;
                    }
                    Err(_) => {
                        sys::handle_close(t.indicator);
                        t.indicator = 0;
                        if t.mic_active {
                            t.mic_active = false;
                            println!("terminal: indicator: MIC OFF (peer closed)");
                        }
                        break;
                    }
                }
            },
            KEY_DISPLAY => loop {
                let mut hs = [0 as Handle; 1];
                match sys::channel_read_h(t.display, &mut buf, &mut hs, 0) {
                    Ok((n, nh)) => {
                        if nh > 0 {
                            sys::handle_close(hs[0]);
                        }
                        let Some(h) = Header::get(&buf[..n]) else { continue };
                        let ok = match h.op {
                            term::DISPLAY_RELEASE => {
                                if !t.released {
                                    t.released = true;
                                    println!("terminal: display released to the compositor");
                                }
                                true
                            }
                            term::DISPLAY_RECLAIM => {
                                t.reclaim();
                                true
                            }
                            _ => false,
                        };
                        if h.txid != 0 {
                            let mut rep = [0u8; HEADER];
                            let status = if ok { 0 } else { sys::ERR_NOT_SUPPORTED as i32 };
                            Header { txid: h.txid, op: h.op, status, a: 0, b: 0 }.put(&mut rep);
                            sys::channel_write(t.display, &rep);
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(t.display, sys::READABLE | sys::PEER_CLOSED, KEY_DISPLAY);
                        break;
                    }
                    Err(_) => {
                        // The compositor is gone: the screen is ours again.
                        sys::handle_close(t.display);
                        t.display = 0;
                        t.reclaim();
                        break;
                    }
                }
            },
            KEY_VIEW => while let Some(ch) = t.view.as_ref().map(|v| v.ch) {
                let mut hs = [0 as Handle; 1];
                match sys::channel_read_h(ch, &mut buf, &mut hs, 0) {
                    Ok((n, nh)) => {
                        if nh > 0 {
                            sys::handle_close(hs[0]);
                        }
                        let Some(h) = Header::get(&buf[..n]) else { continue };
                        if let Some((status, a, handle)) = t.view_msg(h)
                            && h.txid != 0
                        {
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: status as i32, a, b: 0 }.put(&mut rep);
                            match handle {
                                Some(hd) => sys::channel_write_h(ch, &rep, &[MsgHandle { handle: hd, rights: sys::RIGHTS_SAME }]),
                                None => sys::channel_write(ch, &rep),
                            };
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_VIEW);
                        break;
                    }
                    Err(_) => {
                        // The viewer is gone (the service manager links a new one if it restarts).
                        if let Some(v) = t.view.take() {
                            sys::handle_close(v.ch);
                            sys::handle_close(v.vmo_ro);
                            sys::vmar_unmap(libd::root_vmar(), v.map.addr, v.map.len);
                            sys::handle_close(v.map.vmo);
                        }
                        break;
                    }
                }
            },
            _ => loop {
                // The service manager: a session (the shell), a new input channel, or stop.
                let mut hs = [0 as Handle; 1];
                match sys::channel_read_h(ctl, &mut buf, &mut hs, 0) {
                    Ok((n, nh)) => {
                        let handle = if nh > 0 { hs[0] } else { 0 };
                        match Header::get(&buf[..n]) {
                            Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"devmgr.input" && handle != 0 => {
                                if input != 0 {
                                    sys::handle_close(input);
                                }
                                input = handle;
                                port.arm(input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
                            }
                            Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"session" && handle != 0 => {
                                t.connect(handle);
                                port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_SESSION);
                            }
                            Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"display" && handle != 0 => {
                                if t.display != 0 {
                                    sys::handle_close(t.display);
                                }
                                t.display = handle;
                                t.reclaim();
                                port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_DISPLAY);
                            }
                            Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"view" && handle != 0 => {
                                // One viewer: a new one replaces the old.
                                if let Some(v) = t.view.take() {
                                    sys::handle_close(v.ch);
                                    sys::handle_close(v.vmo_ro);
                                    sys::vmar_unmap(libd::root_vmar(), v.map.addr, v.map.len);
                                    sys::handle_close(v.map.vmo);
                                }
                                match Mapping::new(term::VIEW_BYTES as u64).and_then(|m| sys::handle_duplicate(m.vmo, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER | sys::RIGHT_DUPLICATE).map(|ro| (m, ro))) {
                                    Ok((map, vmo_ro)) => {
                                        let mut v = View { ch: handle, map, vmo_ro, cols: 80, rows: 25, shown: Vec::new(), cursor: None, attached: false };
                                        v.resize(80, 25);
                                        t.view = Some(v);
                                        port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_VIEW);
                                    }
                                    Err(e) => {
                                        println!("terminal: no memory for a view grid ({})", sys::status(e));
                                        sys::handle_close(handle);
                                    }
                                }
                            }
                            Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"indicator" && handle != 0 => {
                                if t.indicator != 0 {
                                    sys::handle_close(t.indicator);
                                }
                                t.indicator = handle;
                                port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_INDICATOR);
                            }
                            Some(h) if h.op == svc::SHUTDOWN => return 0,
                            _ => {
                                if handle != 0 {
                                    sys::handle_close(handle);
                                }
                            }
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                        break;
                    }
                    Err(_) => break,
                }
            },
        }
        t.render();
    }
}
