//! `awmi-demo.dsvc`: the built-in demo windows of a session started with them (the shell's `gui`).
//!
//! An ordinary client of `awmi.window`, with no other authority: it waits for a session, then
//! opens two windows it draws itself through the same isolated path as any program:
//! - **About**: what D-AWMI is and the keyboard shortcuts;
//! - **Canvas**: draw with the pointer (left button), the last key typed, focus state; it follows
//!   resizes and snaps (`EVT_CONFIGURE`) with a buffer of the new size.
//!
//! Closing a window (its button, `Super+Q`) closes it; both close when the session ends.

use dosawmi::{Canvas, Rect, Theme};
use libd::awmi::{self as wire, Event, Window};
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Port, Startup, println, svc};

const KEY_CTL: u64 = 1;
const KEY_WIN: u64 = 2;

/// Messages from the service manager: a new window channel (the compositor was restarted), or
/// stop. False: stop.
fn on_ctl(ctl: Handle, ep: &mut Handle, port: &Port) -> bool {
    let mut buf = [0u8; HEADER + 64];
    loop {
        let mut hs = [0 as Handle; 1];
        match sys::channel_read_h(ctl, &mut buf, &mut hs, 0) {
            Ok((n, nh)) => {
                let hnd = if nh > 0 { hs[0] } else { 0 };
                match Header::get(&buf[..n]) {
                    Some(h) if h.op == svc::CONNECT && hnd != 0 && &buf[HEADER..n] == b"awmi.window" => {
                        sys::handle_close(*ep);
                        *ep = hnd;
                        port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
                    }
                    Some(h) if h.op == svc::SHUTDOWN => return false,
                    _ => {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                    }
                }
            }
            Err(sys::ERR_SHOULD_WAIT) => {
                port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                return true;
            }
            Err(_) => return true,
        }
    }
}

const SHORTCUTS: &[&[u8]] = &[
    b"Super+Left/Right    snap to a half",
    b"Super+Up / Down     maximize / restore",
    b"Super+Shift+Arrows  snap to a quarter",
    b"Super+1..4          switch workspace",
    b"Super+Shift+1..4    move window there",
    b"Alt+Tab             next window",
    b"Super+Q             close the window",
    b"Super+Esc           back to the shell",
    b"Ctrl+Alt+Esc        (same, inside a VM)",
];

fn canvas_of(win: &mut Window) -> Option<Canvas<'_>> {
    let (w, h) = (win.width, win.height);
    let bytes = win.pixels();
    let px = (w as usize) * (h as usize);
    if bytes.len() < px * 4 || !(bytes.as_ptr() as usize).is_multiple_of(4) {
        return None;
    }
    // SAFETY: the window's pixels are a page-aligned private mapping of at least `px * 4` bytes
    // (checked above), borrowed mutably for the canvas's lifetime.
    let px_slice = unsafe { core::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<u32>(), px) };
    Canvas::new(px_slice, w, h, w)
}

fn draw_about(win: &mut Window, desktop: (u32, u32)) {
    let t = Theme::DARK_SLATE;
    let Some(mut c) = canvas_of(win) else { return };
    let all = c.bounds();
    c.fill_rect(all, all, t.client_bg);
    c.draw_text(all, 16, 14, b"D-AWMI", t.text_primary, all.w);
    c.draw_text(all, 16 + 7 * 8, 14, b"compositor & window manager", t.text_muted, all.w);
    c.fill_rect(all, Rect::new(16, 38, all.w.saturating_sub(32), 1), t.border_inactive);
    let mut line = [0u8; 48];
    let n = fmt_size(&mut line, b"desktop ", desktop.0, desktop.1);
    c.draw_text(all, 16, 48, &line[..n], t.text_muted, all.w);
    for (i, s) in SHORTCUTS.iter().enumerate() {
        c.draw_text(all, 16, 76 + i as i32 * 18, s, t.text_primary, all.w.saturating_sub(24));
    }
}

/// `<prefix><w>x<h>` into `out`; the length.
fn fmt_size(out: &mut [u8], prefix: &[u8], w: u32, h: u32) -> usize {
    let mut n = 0;
    let mut put = |b: u8| {
        if n < out.len() {
            out[n] = b;
            n += 1;
        }
    };
    prefix.iter().for_each(|&b| put(b));
    for (i, v) in [w, h].into_iter().enumerate() {
        if i == 1 {
            put(b'x');
        }
        let mut digits = [0u8; 10];
        let mut k = 0;
        let mut x = v;
        loop {
            digits[k] = b'0' + (x % 10) as u8;
            k += 1;
            x /= 10;
            if x == 0 {
                break;
            }
        }
        digits[..k].iter().rev().for_each(|&d| put(d));
    }
    n
}

struct Paint {
    win: Window,
    last_key: u32,
    focused: bool,
    down: bool,
    last: Option<(i32, i32)>,
}

impl Paint {
    fn redraw(&mut self) {
        let t = Theme::DARK_SLATE;
        let (focused, last_key) = (self.focused, self.last_key);
        let Some(mut c) = canvas_of(&mut self.win) else { return };
        let all = c.bounds();
        c.fill_rect(all, all, t.desktop_subtle);
        c.fill_rect(all, Rect::new(0, 0, all.w, 26), t.client_bg);
        let label: &[u8] = if focused { b"focused: draw with the left button" } else { b"click to focus" };
        c.draw_text(all, 10, 5, label, if focused { t.text_primary } else { t.text_muted }, all.w.saturating_sub(120));
        let mut k = *b"key: -  ";
        if (0x21..0x7F).contains(&(last_key & 0xFFFF)) {
            k[5] = (last_key & 0xFF) as u8;
        }
        c.draw_text(all, all.w as i32 - 72, 5, &k, t.text_muted, 64);
    }

    /// A stroke segment from the last point to `(x, y)`: small dots along the line.
    fn stroke(&mut self, x: i32, y: i32) -> Option<(i32, i32, u32, u32)> {
        let t = Theme::DARK_SLATE;
        let from = self.last.unwrap_or((x, y));
        self.last = Some((x, y));
        let mut c = canvas_of(&mut self.win)?;
        let all = c.bounds();
        let clip = Rect::new(0, 27, all.w, all.h.saturating_sub(27));
        let steps = (x - from.0).abs().max((y - from.1).abs()).max(1);
        for i in 0..=steps {
            let px = from.0 + (x - from.0) * i / steps;
            let py = from.1 + (y - from.1) * i / steps;
            c.fill_circle(clip, px, py, 2, t.accent_focus);
        }
        let (x0, y0) = (from.0.min(x) - 3, from.1.min(y) - 3);
        Some((x0, y0, ((from.0 - x).unsigned_abs() + 7), ((from.1 - y).unsigned_abs() + 7)))
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "awmi-demo") } {
        return 1;
    }
    if libd::args().split(|&c| c == b' ' || c == 0).any(|a| a == b"off") {
        return 0;
    }
    let mut ep: Handle = wire::window_endpoint();
    if ep == 0 {
        println!("awmi-demo: no awmi.window grant");
        return 1;
    }
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(port) = Port::new(8) else { return 1 };
    if ctl != 0 {
        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
    let mut about: Option<Window> = None;
    let mut paint: Option<Paint> = None;
    let mut desktop = (0u32, 0u32);
    loop {
        let Some((k, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        if k == KEY_CTL {
            if !on_ctl(ctl, &mut ep, &port) {
                return 0;
            }
            continue;
        }
        let ev = match wire::next_event(ep, 0) {
            Ok(Some(e)) => e,
            Ok(None) => {
                port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
                continue;
            }
            Err(_) => {
                // The compositor is gone (restarted: the service manager links us again).
                about = None;
                paint = None;
                continue;
            }
        };
        // More may be queued: come back for them.
        port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
        match ev {
            Event::Session { active: true, demo, width, height } => {
                desktop = (width, height);
                // Only a session started with the demo (`gui`, not a test) gets the windows.
                if !demo {
                    continue;
                }
                if let Ok(mut w) = Window::new(ep, 380, 260, wire::FLAGS_DEFAULT, b"About D-AWMI") {
                    draw_about(&mut w, desktop);
                    let _ = w.commit(&[]);
                    about = Some(w);
                }
                if let Ok(w) = Window::new(ep, 420, 280, wire::FLAGS_DEFAULT, b"Canvas") {
                    let mut p = Paint { win: w, last_key: 0, focused: true, down: false, last: None };
                    p.redraw();
                    let _ = p.win.commit(&[]);
                    paint = Some(p);
                }
            }
            Event::Session { active: false, .. } => {
                // The compositor closed every window already: release our buffers.
                about = None;
                paint = None;
            }
            Event::Close { window } => {
                if about.as_ref().is_some_and(|w| w.id == window) {
                    about = None;
                }
                if paint.as_ref().is_some_and(|p| p.win.id == window) {
                    paint = None;
                }
            }
            Event::Configure { window, width, height, state } => {
                if let Some(w) = about.as_mut().filter(|w| w.id == window)
                    && w.resize(width, height).is_ok()
                {
                    draw_about(w, desktop);
                    let _ = w.commit(&[]);
                }
                if let Some(p) = paint.as_mut().filter(|p| p.win.id == window) {
                    p.focused = state & wire::STATE_FOCUSED != 0;
                    if p.win.resize(width, height).is_ok() {
                        p.redraw();
                        let _ = p.win.commit(&[]);
                    }
                }
            }
            Event::Focus { window, focused } => {
                if let Some(p) = paint.as_mut().filter(|p| p.win.id == window) {
                    p.focused = focused;
                    p.redraw();
                    let _ = p.win.commit(&[(0, 0, p.win.width, 26)]);
                }
            }
            Event::Key { window, key } => {
                if let Some(p) = paint.as_mut().filter(|p| p.win.id == window) {
                    p.last_key = key;
                    p.redraw();
                    let _ = p.win.commit(&[(0, 0, p.win.width, 26)]);
                }
            }
            Event::Pointer { window, x, y, buttons, .. } => {
                if let Some(p) = paint.as_mut().filter(|p| p.win.id == window) {
                    let down = buttons & 1 != 0;
                    if down && y > 26 {
                        if !p.down {
                            p.last = None;
                        }
                        if let Some(r) = p.stroke(x, y) {
                            let _ = p.win.commit(&[r]);
                        }
                    }
                    p.down = down;
                }
            }
            Event::FrameDone { .. } => {}
        }
    }
}
