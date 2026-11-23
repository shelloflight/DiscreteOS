//! Shared `dosui` + `awmi` application runner and `DRES` resource pack helper for native `.dapp` apps.

use alloc::boxed::Box;
use alloc::vec::Vec;

use dosapp::ResourcePack;
use dosawmi::{Canvas, Theme, UiSettings};
use dosui::{FontText, Node, Ui, fonts};
use libd::appmgr::TAG_APP_RESOURCES;
use libd::awmi::{self as wire, Event, Window};
use libd::sys::{self, Handle};
use libd::{Mapping, Port, Timer, println};

const KEY_WIN: u64 = 1;
const KEY_TICK: u64 = 2;

pub trait App {
    type Msg: Clone + 'static;
    fn title(&self) -> &str;
    fn size(&self) -> (u32, u32);
    fn view(&self) -> Node<Self::Msg>;
    fn update(&mut self, msg: Self::Msg);
    fn tick(&mut self) -> bool {
        false
    }
}

/// Read an embedded resource file from the app's read-only `DRES` VMO (`TAG_APP_RESOURCES`).
#[allow(dead_code)]
pub fn read_resource(name: &str) -> Option<Vec<u8>> {
    let h = libd::startup_handle(TAG_APP_RESOURCES);
    if h == 0 {
        return None;
    }
    let size = sys::vmo_size(h).ok()? as usize;
    if size == 0 || size > 4 << 20 {
        return None;
    }
    let mut buf = alloc::vec![0u8; size];
    if sys::vmo_read(h, 0, &mut buf) != 0 {
        return None;
    }
    ResourcePack::get(&buf, name).map(<[u8]>::to_vec)
}

fn text_engine(ep: Handle, who: &str) -> FontText<'static> {
    match wire::fonts(ep) {
        Ok(map) => {
            let map: &'static Mapping = Box::leak(Box::new(map));
            FontText::new(fonts::engine(map.bytes()), 100)
        }
        Err(e) => {
            println!("{}: no fonts from compositor ({})", who, sys::status(e));
            FontText::new(dosfont::Text::new(), 100)
        }
    }
}

fn canvas_of(win: &mut Window) -> Option<Canvas<'_>> {
    let (w, h) = (win.width, win.height);
    let bytes = win.pixels();
    let px = (w as usize) * (h as usize);
    if bytes.len() < px * 4 || !(bytes.as_ptr() as usize).is_multiple_of(4) {
        return None;
    }
    // SAFETY: the window pixel mapping is page-aligned and at least `px * 4` bytes long.
    let px_slice = unsafe { core::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<u32>(), px) };
    Canvas::new(px_slice, w, h, w)
}

pub fn run_app<A: App>(name: &str, mut app: A, tick_ms: u64) -> i32 {
    let ep = wire::window_endpoint();
    if ep == 0 {
        println!("{}: window permission not granted", name);
        return 1;
    }
    let Ok(port) = Port::new(16) else { return 1 };
    let mut text = text_engine(ep, name);
    let mut theme = Theme::DARK_SLATE;
    let mut settings = UiSettings::DEFAULT;
    // Drain initial EVT_SETTINGS sent on connect before creating the window.
    while let Ok(Some(ev)) = wire::next_event(ep, 0) {
        if let Event::Settings { settings: s, theme: th } = ev {
            settings = UiSettings::unpack(s);
            theme = Theme::decode(&th).unwrap_or(settings.theme.builtin());
            text.scale = settings.text_scale;
        }
    }
    let (bw, bh) = app.size();
    let sc = u32::from(settings.text_scale);
    let mut win = match Window::new(ep, bw * sc / 100, bh * sc / 100, wire::FLAGS_DEFAULT, app.title().as_bytes()) {
        Ok(w) => w,
        Err(e) => {
            println!("{}: cannot open window ({})", name, sys::status(e));
            return 1;
        }
    };
    let mut ui = Ui::new(theme, settings);
    ui.resize(win.width, win.height, &text);
    ui.set_view(app.view(), &text);
    ui.damage_all();
    let mut in_flight = false;
    let mut dirty = true;

    let paint = |win: &mut Window, ui: &mut Ui<A::Msg>, text: &mut FontText<'_>, in_flight: &mut bool, dirty: &mut bool| {
        if !*dirty || *in_flight {
            return;
        }
        *dirty = false;
        let Some(mut c) = canvas_of(win) else { return };
        let damage = ui.paint(&mut c, text);
        if damage.is_empty() {
            return;
        }
        let rects: Vec<(i32, i32, u32, u32)> = damage.as_slice().iter().map(|r| (r.x, r.y, r.w, r.h)).collect();
        if win.commit(&rects).is_ok() {
            *in_flight = true;
        }
    };

    paint(&mut win, &mut ui, &mut text, &mut in_flight, &mut dirty);
    println!("{}: window {} open", name, win.id);

    port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
    let timer = if tick_ms > 0 {
        Timer::new().ok().inspect(|t| {
            t.set(tick_ms * 1_000_000);
            port.arm(t.0.raw(), sys::SIGNALED, KEY_TICK);
        })
    } else {
        None
    };

    loop {
        let Some((k, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        if k == KEY_TICK {
            if app.tick() {
                ui.set_view(app.view(), &text);
                dirty = true;
                paint(&mut win, &mut ui, &mut text, &mut in_flight, &mut dirty);
            }
            if let Some(t) = timer.as_ref() {
                t.set(tick_ms * 1_000_000);
                port.arm(t.0.raw(), sys::SIGNALED, KEY_TICK);
            }
            continue;
        }
        loop {
            let ev = match wire::next_event(ep, 0) {
                Ok(Some(e)) => e,
                Ok(None) => {
                    port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
                    break;
                }
                Err(_) => return 0,
            };
            ui.set_time(sys::clock_ns());
            match ev {
                Event::Settings { settings: s, theme: th } => {
                    settings = UiSettings::unpack(s);
                    theme = Theme::decode(&th).unwrap_or(settings.theme.builtin());
                    text.scale = settings.text_scale;
                    ui.set_theme(theme, settings, &text);
                    ui.set_view(app.view(), &text);
                    dirty = true;
                }
                Event::Session { active: false, .. } => return 0,
                Event::Close { window } if window == win.id => return 0,
                Event::Configure { window, width, height, state } if window == win.id => {
                    if win.resize(width, height).is_ok() {
                        ui.resize(width, height, &text);
                        ui.damage_all();
                    }
                    ui.set_window_focus(state & wire::STATE_FOCUSED != 0);
                    dirty = true;
                }
                Event::Focus { window, focused } if window == win.id => {
                    ui.set_window_focus(focused);
                    dirty = true;
                }
                Event::Key { window, key } if window == win.id => {
                    let msgs = ui.key(key, &text);
                    for m in msgs {
                        app.update(m);
                    }
                    ui.set_view(app.view(), &text);
                    dirty = true;
                }
                Event::Pointer { window, x, y, buttons, wheel, .. } if window == win.id => {
                    let msgs = ui.pointer(x, y, buttons, wheel, &text);
                    for m in msgs {
                        app.update(m);
                    }
                    ui.set_view(app.view(), &text);
                    dirty = true;
                }
                Event::FrameDone { window, .. } if window == win.id => {
                    in_flight = false;
                    if ui.animating() {
                        dirty = true;
                    }
                }
                _ => {}
            }
            paint(&mut win, &mut ui, &mut text, &mut in_flight, &mut dirty);
        }
    }
}
