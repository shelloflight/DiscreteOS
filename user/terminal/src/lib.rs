//! The terminal service (`terminal.dx`, docs/shell.md): the screen and the keyboard, for the shell.
//!
//! It holds two things: the display device (manifest grant `devices = ["platform:display"]`;
//! mapping it takes the screen from the kernel console) and the device manager's `input`
//! endpoint. It offers one endpoint, `session`, to the shell, and keeps no other authority: what
//! the shell can do is the shell's manifest, not the terminal's.
//!
//! - Output: text from the session with colours (`libd::term`), wrapped at the screen's width,
//!   kept in a scrollback of `MAX_LINES` lines (PgUp/PgDn, Shift too).
//! - Input: a line editor for the session's `READ`: insert anywhere, Backspace/Delete, Left/Right,
//!   Home/End (Ctrl+A/Ctrl+E), history (Up/Down), Tab (the session completes the last word),
//!   Escape clears, Ctrl+C cancels the line (or interrupts the running command), Ctrl+L clears the
//!   screen. A line typed while a command runs is kept and submitted when the next prompt comes.
//! - Every line typed is logged (`terminal: line from <keyboard>: <text>`). With the argument
//!   `mirror` (or without a display) every line shown is logged too (`terminal| ...`), so a
//!   session can be followed on the serial line.
//! - `display` endpoint (the compositor): `term::DISPLAY_RELEASE` stops drawing while a graphical
//!   session owns the screen; `term::DISPLAY_RECLAIM`, or that channel closing, redraws it all.

#![no_std]

extern crate alloc;

mod font;
mod screen;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use libd::proto::{self, HEADER, Header, key};
use libd::sys::{self, Handle};
use libd::{Port, Startup, println, svc, term};
use screen::{CROSS, Cell, Screen, cell};

libd::entry!(_start, main);

const KEY_CTL: u64 = 1;
const KEY_INPUT: u64 = 2;
const KEY_SESSION: u64 = 3;
const KEY_INDICATOR: u64 = 4;
const KEY_DISPLAY: u64 = 5;

/// Lines kept for scrolling back.
const MAX_LINES: usize = 2000;
const MAX_HISTORY: usize = 100;
/// Longest line the editor takes.
const MAX_EDIT: usize = 1024;

/// A character as a code page 437 glyph (what the font and VGA text can show).
fn glyph(c: char) -> u8 {
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

/// A shown glyph back as text (for the mirrored log lines).
fn ascii(g: u8) -> char {
    match g {
        0x20..=0x7E => g as char,
        0x10 => '>',
        0x11 => '<',
        0xFB => 'v',
        CROSS => 'x',
        0xFA | 0x07 => '.',
        0xC4 => '-',
        0xB3 => '|',
        _ => '?',
    }
}

struct Term {
    scr: Screen,
    /// Finished output lines (each at most `cols` cells).
    lines: VecDeque<Vec<Cell>>,
    /// The output line being written (no newline yet).
    cur: Vec<Cell>,
    attr: u8,
    /// Lines scrolled back from the bottom (0: following the output).
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
    mirror: bool,
    /// Which keyboard the last key came from (for the log line).
    from: [u8; 24],
    from_len: usize,
}

impl Term {
    fn cols(&self) -> usize {
        self.scr.cols
    }

    fn push_line(&mut self, l: Vec<Cell>) {
        if self.mirror {
            let s: String = l.iter().map(|&c| ascii((c & 0xFF) as u8)).collect();
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
        if self.cur.len() >= self.cols() {
            let l = core::mem::take(&mut self.cur);
            self.push_line(l);
        }
        self.cur.push(cell(glyph(c), self.attr));
    }

    /// The prompt and the line being edited, wrapped: (lines, cursor (x, line)).
    fn edit_lines(&self) -> (Vec<Vec<Cell>>, (usize, usize)) {
        let cols = self.cols();
        let mut all: Vec<Cell> = self.prompt.clone();
        all.extend(self.edit.iter().map(|&c| cell(glyph(c), term::DEFAULT_ATTR)));
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

    /// Draw what is visible now (nothing while a graphical session holds the screen).
    fn render(&mut self) {
        if self.released {
            return;
        }
        let mut extra: Vec<Vec<Cell>> = Vec::new();
        if !self.cur.is_empty() {
            extra.push(self.cur.clone());
        }
        let mut cursor_line = None;
        if self.reading {
            let (ls, (cx, cy)) = self.edit_lines();
            cursor_line = Some((cx, extra.len() + cy));
            extra.extend(ls);
        }
        let total = self.lines.len() + extra.len();
        let rows = self.scr.rows;
        self.scroll = self.scroll.min(total.saturating_sub(rows));
        let first = total.saturating_sub(rows + self.scroll);
        let cursor = match cursor_line {
            Some((cx, cl)) if self.scroll == 0 => {
                let line = self.lines.len() + cl;
                (line >= first && line < first + rows).then(|| (cx, line - first))
            }
            _ => None,
        };
        self.scr.set_cursor(cursor);
        let blank = cell(b' ', term::DEFAULT_ATTR);
        for y in 0..rows {
            let idx = first + y;
            let line: &[Cell] = if idx < self.lines.len() {
                &self.lines[idx]
            } else if idx - self.lines.len() < extra.len() {
                &extra[idx - self.lines.len()]
            } else {
                &[]
            };
            for x in 0..self.scr.cols {
                let c = line.get(x).copied().unwrap_or(blank);
                self.scr.put(x, y, c);
            }
        }
        // Visible active microphone indicator (top-right badge on row 0, unforgeable: only audio.dsvc holds `terminal.indicator`).
        if self.mic_active && self.scr.rows > 0 && self.scr.cols >= 12 {
            let badge = b" [MIC LIVE] ";
            let attr = term::WHITE | (term::RED << 4);
            let start = self.scr.cols - badge.len();
            for (i, &ch) in badge.iter().enumerate() {
                self.scr.put(start + i, 0, cell(ch, attr));
            }
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
        let (mut ls, _) = self.edit_lines();
        if cancelled
            && let Some(l) = ls.last_mut()
        {
            l.extend("^C".chars().map(|c| cell(glyph(c), term::DARK_GREY)));
        }
        for l in ls {
            self.push_line(l);
        }
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
        let base = k & key::MASK;
        if base == key::PAGE_UP || base == key::PAGE_DOWN {
            let page = self.scr.rows.saturating_sub(1).max(1);
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
                        c => self.prompt.push(cell(glyph(c), attr)),
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
        self.send(term::SIZE, self.scr.cols as u64, self.scr.rows as u64, &[]);
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
