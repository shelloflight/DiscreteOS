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
    fn should_exit(&self) -> bool {
        false
    }
    fn on_key(&mut self, _key: u32) -> bool {
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
    // Private shadow backbuffer: paint complete frames offscreen before copying finished
    // damaged rows into the shared compositor VMO, eliminating mid-paint flicker at 240+ Hz.
    let mut back: Vec<u32> = alloc::vec![theme.client_bg; (win.width as usize) * (win.height as usize)];
    let mut in_flight = false;
    let mut dirty = true;

    let paint = |win: &mut Window, back: &mut Vec<u32>, ui: &mut Ui<A::Msg>, text: &mut FontText<'_>, in_flight: &mut bool, dirty: &mut bool| {
        if !*dirty || *in_flight {
            return;
        }
        *dirty = false;
        let (w, h) = (win.width, win.height);
        let need = (w as usize) * (h as usize);
        if back.len() != need {
            back.resize(need, ui.theme.client_bg);
            ui.damage_all();
        }
        let Some(mut c) = Canvas::new(back, w, h, w) else { return };
        let damage = ui.paint(&mut c, text);
        if damage.is_empty() {
            return;
        }
        // Copy only finished damaged rectangle rows into the shared VMO.
        if let Some(front) = canvas_of(win) {
            let stride = w as usize;
            for r in damage.as_slice() {
                let x0 = r.x.max(0) as usize;
                let y0 = r.y.max(0) as usize;
                let x1 = (r.x + r.w as i32).min(w as i32).max(0) as usize;
                let y1 = (r.y + r.h as i32).min(h as i32).max(0) as usize;
                if x1 <= x0 || y1 <= y0 {
                    continue;
                }
                for y in y0..y1 {
                    let off = y * stride;
                    front.pixels[off + x0..off + x1].copy_from_slice(&back[off + x0..off + x1]);
                }
            }
        }
        let rects: Vec<(i32, i32, u32, u32)> = damage.as_slice().iter().map(|r| (r.x, r.y, r.w, r.h)).collect();
        if win.commit(&rects).is_ok() {
            *in_flight = true;
        }
    };

    paint(&mut win, &mut back, &mut ui, &mut text, &mut in_flight, &mut dirty);
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
                paint(&mut win, &mut back, &mut ui, &mut text, &mut in_flight, &mut dirty);
            }
            if let Some(t) = timer.as_ref() {
                t.set(tick_ms * 1_000_000);
                port.arm(t.0.raw(), sys::SIGNALED, KEY_TICK);
            }
            continue;
        }
        let mut pending_move: Option<(i32, i32, u8)> = None;
        let mut view_dirty = false;
        let flush_move = |app: &mut A, ui: &mut Ui<A::Msg>, text: &FontText<'_>, mv: &mut Option<(i32, i32, u8)>, view_dirty: &mut bool, dirty: &mut bool| -> bool {
            if let Some((x, y, buttons)) = mv.take() {
                let msgs = ui.pointer(x, y, buttons, 0, text);
                for m in msgs {
                    app.update(m);
                    if app.should_exit() {
                        return true;
                    }
                    *view_dirty = true;
                }
                *dirty = true;
            }
            false
        };
        loop {
            let ev = match wire::next_event(ep, 0) {
                Ok(Some(e)) => e,
                Ok(None) => {
                    if flush_move(&mut app, &mut ui, &text, &mut pending_move, &mut view_dirty, &mut dirty) {
                        return 0;
                    }
                    if view_dirty {
                        ui.set_view(app.view(), &text);
                    }
                    paint(&mut win, &mut back, &mut ui, &mut text, &mut in_flight, &mut dirty);
                    port.arm(ep, sys::READABLE | sys::PEER_CLOSED, KEY_WIN);
                    break;
                }
                Err(_) => return 0,
            };
            ui.set_time(sys::clock_ns());
            match ev {
                Event::Settings { settings: s, theme: th } => {
                    if flush_move(&mut app, &mut ui, &text, &mut pending_move, &mut view_dirty, &mut dirty) {
                        return 0;
                    }
                    settings = UiSettings::unpack(s);
                    theme = Theme::decode(&th).unwrap_or(settings.theme.builtin());
                    text.scale = settings.text_scale;
                    ui.set_theme(theme, settings, &text);
                    view_dirty = true;
                    dirty = true;
                }
                Event::Session { active: false, .. } => return 0,
                Event::Close { window } if window == win.id => return 0,
                Event::Configure { window, width, height, state } if window == win.id => {
                    if flush_move(&mut app, &mut ui, &text, &mut pending_move, &mut view_dirty, &mut dirty) {
                        return 0;
                    }
                    if win.resize(width, height).is_ok() {
                        back.resize((win.width as usize) * (win.height as usize), ui.theme.client_bg);
                        ui.resize(width, height, &text);
                        ui.damage_all();
                    }
                    ui.set_window_focus(state & wire::STATE_FOCUSED != 0);
                    dirty = true;
                }
                Event::Focus { window, focused } if window == win.id => {
                    if flush_move(&mut app, &mut ui, &text, &mut pending_move, &mut view_dirty, &mut dirty) {
                        return 0;
                    }
                    ui.set_window_focus(focused);
                    dirty = true;
                }
                Event::Key { window, key } if window == win.id => {
                    if flush_move(&mut app, &mut ui, &text, &mut pending_move, &mut view_dirty, &mut dirty) {
                        return 0;
                    }
                    if app.on_key(key) {
                        if app.should_exit() {
                            return 0;
                        }
                        view_dirty = true;
                        dirty = true;
                        continue;
                    }
                    let msgs = ui.key(key, &text);
                    for m in msgs {
                        app.update(m);
                        if app.should_exit() {
                            return 0;
                        }
                    }
                    view_dirty = true;
                    dirty = true;
                }
                Event::Pointer { window, kind, x, y, buttons, wheel } if window == win.id => {
                    if kind == wire::PTR_MOVE && wheel == 0 {
                        // Coalesce bursty hover/drag move events in one drain cycle.
                        pending_move = Some((x, y, buttons));
                    } else {
                        if flush_move(&mut app, &mut ui, &text, &mut pending_move, &mut view_dirty, &mut dirty) {
                            return 0;
                        }
                        let msgs = ui.pointer(x, y, buttons, wheel, &text);
                        for m in msgs {
                            app.update(m);
                            if app.should_exit() {
                                return 0;
                            }
                        }
                        view_dirty = true;
                        dirty = true;
                    }
                }
                Event::FrameDone { window, .. } if window == win.id => {
                    in_flight = false;
                    if ui.animating() || ui.has_damage() {
                        dirty = true;
                    }
                }
                _ => {}
            }
        }
    }
}
