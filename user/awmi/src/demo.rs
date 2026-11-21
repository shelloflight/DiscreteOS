//! `awmi-demo.dsvc`: the built-in example apps, written with the native toolkit (`dosui`).
//!
//! An ordinary client of `awmi.window`, with no other authority. It registers two launcher
//! entries and opens their windows when the user picks them (or when a session is started with
//! the demo windows, the shell's `gui demo`):
//! - **Widgets**: a tour of the toolkit. Every control works but changes only this window:
//!   checkboxes, a toggle, a slider driving a progress bar, a text field with a greeting, and a
//!   theme preview list that re-themes this window (the desktop's theme is changed from the
//!   launcher or `gui theme`).
//! - **About D-OS**: what the desktop is and its keyboard shortcuts.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosawmi::{Theme, ThemeId, UiSettings};
use dosui::{Length, Node, Tone, button, caption, checkbox, column, divider, heading, input, item, label, panel, progress, row, scroll, slider, spacer, text, toggle};
use libd::awmi::{self as wire, Event};
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Port, Startup, println, svc};

use crate::app::{App, UiWindow, settings_of, text_engine};

const KEY_CTL: u64 = 1;
const KEY_WIN: u64 = 2;
const ENTRY_WIDGETS: u8 = 0;
const ENTRY_ABOUT: u8 = 1;

#[derive(Clone)]
enum WMsg {
    Notify,
    Remember,
    Animations,
    Level(i32),
    Name(String),
    Greet,
    Preview(Option<ThemeId>),
    Reset,
}

struct Widgets {
    notify: bool,
    remember: bool,
    animations: bool,
    level: i32,
    name: String,
    greeting: String,
    /// The theme previewed in this window (None: the desktop's).
    preview: Option<ThemeId>,
    theme: &'static str,
    scale: u16,
}

const PREVIEWS: [(&str, Option<ThemeId>); 3] = [("Follow the desktop", None), ("Dark Slate", Some(ThemeId::DarkSlate)), ("High Contrast", Some(ThemeId::HighContrast))];

impl App for Widgets {
    type Msg = WMsg;

    fn title(&self) -> &str {
        "Widgets"
    }

    fn size(&self) -> (u32, u32) {
        (560, 560)
    }

    fn view(&self) -> Node<WMsg> {
        let left = column([
            label("Controls"),
            checkbox("Notifications", self.notify).on_toggle(WMsg::Notify),
            checkbox("Remember this choice", self.remember).on_toggle(WMsg::Remember),
            toggle("Animations", self.animations).on_toggle(WMsg::Animations),
            caption(format!("Level {}%", self.level)),
            slider(self.level, 0, 100).step(5).on_slide(WMsg::Level).width(Length::Fill),
            progress((self.level as u16) * 10).width(Length::Fill),
            divider(),
            label("Text"),
            input(self.name.clone()).placeholder("Type your name").on_change(WMsg::Name).on_submit(WMsg::Greet).width(Length::Fill),
            text(self.greeting.clone()).tone(Tone::Accent),
        ])
        .gap(10)
        .width(Length::Fill);
        let list = column(PREVIEWS.iter().enumerate().map(|(i, (name, id))| {
            let detail = if id.is_none() { String::from(self.theme) } else { String::new() };
            item(*name, self.preview == *id).detail(detail).on_select(WMsg::Preview(*id)).key(100 + i as u64)
        }))
        .gap(2);
        let right = column([
            label("Theme preview"),
            caption("Re-themes this window only. To change the whole desktop, tap Super and type theme, or run gui theme contrast in the terminal.").wrap(),
            scroll(list).height(Length::Fill),
        ])
        .gap(10)
        .width(Length::Fill)
        .height(Length::Fill);
        column([
            heading("Widgets"),
            caption(format!("A tour of the native toolkit: every control works, but changes only this window. Text {}%. Tab moves the focus, Enter or Space activates.", self.scale)).wrap(),
            row([panel([left]).fill(), panel([right]).fill()]).gap(12).height(Length::Fill).align(dosui::Align::Stretch),
            row([
                button("Reset").danger().on_press(WMsg::Reset),
                spacer(),
                button("Say hello").primary().on_press(WMsg::Greet),
            ])
            .gap(8),
        ])
        .padding(16)
        .gap(12)
    }

    fn theme(&self, desktop: Theme) -> Theme {
        self.preview.map_or(desktop, ThemeId::builtin)
    }

    fn update(&mut self, m: WMsg) {
        match m {
            WMsg::Notify => self.notify = !self.notify,
            WMsg::Remember => self.remember = !self.remember,
            WMsg::Animations => self.animations = !self.animations,
            WMsg::Level(v) => self.level = v,
            WMsg::Name(s) => self.name = s,
            WMsg::Greet => {
                let who = self.name.trim();
                self.greeting = if who.is_empty() { String::from("Hello!") } else { format!("Hello, {}!", who) };
                println!("awmi-demo: widgets: {}", self.greeting);
            }
            WMsg::Preview(id) => self.preview = id,
            WMsg::Reset => {
                *self = Widgets { theme: self.theme, scale: self.scale, ..Widgets::new() };
            }
        }
    }
}

impl Widgets {
    fn new() -> Widgets {
        Widgets { notify: true, remember: false, animations: true, level: 40, name: String::new(), greeting: String::new(), preview: None, theme: "Dark Slate", scale: 100 }
    }
}

#[derive(Clone)]
enum AMsg {}

struct About;

const SHORTCUTS: &[(&str, &str)] = &[
    ("Super", "open the launcher (Alt+F1 in a VM)"),
    ("Super+Left / Right", "snap to a half"),
    ("Super+Up / Down", "maximize / restore"),
    ("Super+Shift+Arrows", "snap to a quarter"),
    ("Super+1..4", "switch workspace"),
    ("Super+Shift+1..4", "move the window there"),
    ("Alt+Tab", "next window"),
    ("Super+Q", "close the window"),
    ("Super+Esc", "leave the desktop (Ctrl+Alt+Esc in a VM)"),
];

impl App for About {
    type Msg = AMsg;

    fn title(&self) -> &str {
        "About D-OS"
    }

    fn size(&self) -> (u32, u32) {
        (460, 420)
    }

    fn view(&self) -> Node<AMsg> {
        let mut rows: Vec<Node<AMsg>> = Vec::new();
        for (k, what) in SHORTCUTS {
            rows.push(row([label(*k).width(Length::Px(170)), text(*what).tone(Tone::Muted)]).gap(8));
        }
        column([
            heading("D-OS"),
            text("Discrete Operating System: fast, secure, practical. Every window shows the name and trust of the program that drew it, as the service manager verified it.").wrap(),
            divider(),
            label("Keyboard"),
            column(rows).gap(6),
        ])
        .padding(18)
        .gap(12)
    }

    fn update(&mut self, m: AMsg) {
        match m {}
    }
}

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
                        let _ = wire::register_app(hnd, ENTRY_WIDGETS, b"Widgets");
                        let _ = wire::register_app(hnd, ENTRY_ABOUT, b"About D-OS");
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

fn window_of(ev: &Event) -> Option<u32> {
    match *ev {
        Event::Configure { window, .. } | Event::Key { window, .. } | Event::Pointer { window, .. } | Event::Focus { window, .. } | Event::Close { window } | Event::FrameDone { window, .. } => Some(window),
        _ => None,
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
    let _ = wire::register_app(ep, ENTRY_WIDGETS, b"Widgets");
    let _ = wire::register_app(ep, ENTRY_ABOUT, b"About D-OS");
    let mut text = text_engine(ep, "awmi-demo");
    let mut theme = Theme::DARK_SLATE;
    let mut settings = UiSettings::DEFAULT;
    let mut widgets: Option<UiWindow<Widgets>> = None;
    let mut about: Option<UiWindow<About>> = None;
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
                widgets = None;
                about = None;
                continue;
            }
        };
        port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
        let open_widgets = |w: &mut Option<UiWindow<Widgets>>, theme: Theme, settings: UiSettings, text: &mut dosui::FontText<'static>| {
            if w.is_none() {
                let mut app = Widgets::new();
                app.theme = settings.theme.name();
                app.scale = settings.text_scale;
                if let Ok(mut win) = UiWindow::open(ep, app, theme, settings, text) {
                    win.draw(text);
                    *w = Some(win);
                    println!("awmi-demo: widgets window open");
                }
            }
        };
        let open_about = |w: &mut Option<UiWindow<About>>, theme: Theme, settings: UiSettings, text: &mut dosui::FontText<'static>| {
            if w.is_none()
                && let Ok(mut win) = UiWindow::open(ep, About, theme, settings, text)
            {
                win.draw(text);
                *w = Some(win);
            }
        };
        match ev {
            Event::Settings { settings: s, theme: t } => {
                (theme, settings) = settings_of(s, &t);
                text.scale = settings.text_scale;
                if let Some(w) = widgets.as_mut() {
                    w.app.theme = settings.theme.name();
                    w.app.scale = settings.text_scale;
                    w.set_settings(theme, settings, &text);
                    w.draw(&mut text);
                }
                if let Some(w) = about.as_mut() {
                    w.set_settings(theme, settings, &text);
                    w.draw(&mut text);
                }
            }
            Event::Session { active: true, demo, .. } => {
                // Only a session started with the demo windows (`gui demo`) opens them.
                if demo {
                    open_about(&mut about, theme, settings, &mut text);
                    open_widgets(&mut widgets, theme, settings, &mut text);
                }
            }
            Event::Session { active: false, .. } => {
                // The compositor closed every window already: release our buffers.
                widgets = None;
                about = None;
            }
            Event::Launch { app } => match app {
                ENTRY_WIDGETS => open_widgets(&mut widgets, theme, settings, &mut text),
                ENTRY_ABOUT => open_about(&mut about, theme, settings, &mut text),
                _ => {}
            },
            ref e => {
                let Some(win) = window_of(e) else { continue };
                if widgets.as_ref().is_some_and(|w| w.id() == win) && !widgets.as_mut().is_some_and(|w| w.event(e, &mut text)) {
                    widgets = None;
                }
                if about.as_ref().is_some_and(|w| w.id() == win) && !about.as_mut().is_some_and(|w| w.event(e, &mut text)) {
                    about = None;
                }
            }
        }
    }
}
