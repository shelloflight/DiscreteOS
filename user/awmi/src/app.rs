//! Running `dosui` apps in D-AWMI windows: the fonts from the compositor, a window per app, and
//! the event plumbing (configure, focus, keys, pointer, frames, settings) between the compositor
//! and the toolkit runtime.

use alloc::boxed::Box;
use alloc::vec::Vec;

use dosawmi::{Canvas, Theme, UiSettings};
use dosui::{FontText, Node, Ui, fonts};
use libd::awmi::{self as wire, Event, Window};
use libd::sys::{self, Handle};
use libd::{Mapping, println};

/// A declarative app (docs/ui.md).
pub trait App {
    type Msg: Clone + 'static;
    fn title(&self) -> &str;
    /// The initial client size.
    fn size(&self) -> (u32, u32);
    fn view(&self) -> Node<Self::Msg>;
    fn update(&mut self, msg: Self::Msg);
    /// The theme this window draws with: the desktop's unless the app previews another.
    fn theme(&self, desktop: Theme) -> Theme {
        desktop
    }
}

/// The text engine over the compositor's fonts (empty without them: nothing is drawn as text).
pub fn text_engine(ep: Handle, who: &str) -> FontText<'static> {
    match wire::fonts(ep) {
        Ok(map) => {
            let map: &'static Mapping = Box::leak(Box::new(map));
            FontText::new(fonts::engine(map.bytes()), 100)
        }
        Err(e) => {
            println!("{}: no fonts from the compositor ({})", who, sys::status(e));
            FontText::new(dosfont::Text::new(), 100)
        }
    }
}

/// The current theme and settings from an `Event::Settings`.
pub fn settings_of(settings: u64, theme: &[u8]) -> (Theme, UiSettings) {
    let s = UiSettings::unpack(settings);
    (Theme::decode(theme).unwrap_or(s.theme.builtin()), s)
}

/// A window's pixels as a canvas.
pub fn canvas_of(win: &mut Window) -> Option<Canvas<'_>> {
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

/// An app in a window.
pub struct UiWindow<A: App> {
    pub app: A,
    pub win: Window,
    back: Vec<u32>,
    ui: Ui<A::Msg>,
    /// The desktop's theme and settings (the app may draw with another theme, `App::theme`).
    desktop: (Theme, UiSettings),
    shown: Theme,
    /// A frame is on its way to the screen (the next one waits for `FrameDone`).
    in_flight: bool,
    dirty: bool,
}

impl<A: App> UiWindow<A> {
    pub fn open(ep: Handle, app: A, theme: Theme, settings: UiSettings, text: &FontText<'_>) -> Result<Self, i64> {
        let (w, h) = app.size();
        let scale = u32::from(settings.text_scale);
        let win = Window::new(ep, w * scale / 100, h * scale / 100, wire::FLAGS_DEFAULT, app.title().as_bytes())?;
        let back = alloc::vec![theme.client_bg; (win.width as usize) * (win.height as usize)];
        let shown = app.theme(theme);
        let mut ui = Ui::new(shown, settings);
        ui.resize(win.width, win.height, text);
        ui.set_view(app.view(), text);
        ui.damage_all();
        Ok(UiWindow { app, win, back, ui, desktop: (theme, settings), shown, in_flight: false, dirty: true })
    }

    pub fn id(&self) -> u32 {
        self.win.id
    }

    pub fn set_settings(&mut self, theme: Theme, settings: UiSettings, text: &FontText<'_>) {
        self.desktop = (theme, settings);
        self.shown = self.app.theme(theme);
        self.ui.set_theme(self.shown, settings, text);
        self.ui.set_view(self.app.view(), text);
        self.dirty = true;
    }

    fn deliver(&mut self, msgs: Vec<A::Msg>, text: &FontText<'_>) {
        if msgs.is_empty() {
            self.dirty = true;
            return;
        }
        for m in msgs {
            self.app.update(m);
        }
        let want = self.app.theme(self.desktop.0);
        if want != self.shown {
            self.shown = want;
            self.ui.set_theme(want, self.desktop.1, text);
        }
        self.ui.set_view(self.app.view(), text);
        self.dirty = true;
    }

    /// An event for this window. False: the user asked to close it.
    pub fn event(&mut self, ev: &Event, text: &mut FontText<'_>) -> bool {
        self.ui.set_time(sys::clock_ns());
        match *ev {
            Event::Configure { width, height, state, .. } => {
                if self.win.resize(width, height).is_ok() {
                    self.ui.resize(width, height, text);
                    self.ui.damage_all();
                }
                self.ui.set_window_focus(state & wire::STATE_FOCUSED != 0);
                self.dirty = true;
            }
            Event::Focus { focused, .. } => {
                self.ui.set_window_focus(focused);
                self.dirty = true;
            }
            Event::Key { key, .. } => {
                let m = self.ui.key(key, text);
                self.deliver(m, text);
            }
            Event::Pointer { x, y, buttons, wheel, .. } => {
                let m = self.ui.pointer(x, y, buttons, wheel, text);
                self.deliver(m, text);
            }
            Event::FrameDone { .. } => {
                self.in_flight = false;
                if self.ui.animating() || self.ui.has_damage() {
                    self.dirty = true;
                }
            }
            Event::Close { .. } => return false,
            _ => {}
        }
        self.draw(text);
        true
    }

    /// Paint what changed into a private backbuffer and blit finished regions before committing.
    pub fn draw(&mut self, text: &mut FontText<'_>) {
        if !self.dirty || self.in_flight {
            return;
        }
        self.dirty = false;
        let (ww, wh) = (self.win.width, self.win.height);
        let need = (ww as usize) * (wh as usize);
        if need == 0 {
            return;
        }
        if self.back.len() != need {
            self.back.resize(need, self.shown.client_bg);
            self.ui.damage_all();
        }
        let damage = {
            let Some(mut c) = Canvas::new(&mut self.back, ww, wh, ww) else { return };
            self.ui.paint(&mut c, text)
        };
        if damage.is_empty() {
            return; // nothing changed (an empty commit would redraw the whole window)
        }
        if let Some(front) = canvas_of(&mut self.win) {
            let stride = ww as usize;
            let iw = ww as i32;
            let ih = wh as i32;
            for r in damage.as_slice() {
                let x0 = r.x.clamp(0, iw) as usize;
                let y0 = r.y.clamp(0, ih) as usize;
                let x1 = (r.x.saturating_add(r.w as i32)).clamp(0, iw) as usize;
                let y1 = (r.y.saturating_add(r.h as i32)).clamp(0, ih) as usize;
                if x1 <= x0 || y1 <= y0 {
                    continue;
                }
                for row in y0..y1 {
                    let off = row * stride;
                    front.pixels[off + x0..off + x1].copy_from_slice(&self.back[off + x0..off + x1]);
                }
            }
        }
        let rects: Vec<(i32, i32, u32, u32)> = damage.as_slice().iter().map(|r| (r.x, r.y, r.w, r.h)).collect();
        if self.win.commit(&rects).is_ok() {
            self.in_flight = true;
        }
    }
}
