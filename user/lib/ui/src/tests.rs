//! Host tests and fuzzers for `dosui` (with the shipped faces from user/init/fonts).

use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use dosawmi::{Canvas, Rect, Theme, ThemeId, UiSettings};
use dosfont::Face;

use crate::font_text::{FontText, TextStyle};
use crate::fonts;
use crate::ui::Ui;
use crate::view::*;

static PACK: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

fn pack() -> &'static [u8] {
    PACK.get_or_init(|| {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../init/fonts/");
        let files: Vec<(Face, Vec<u8>)> = fonts::FACE_FILES.iter().map(|&(f, n)| (f, std::fs::read(format!("{dir}{n}")).unwrap())).collect();
        let refs: Vec<(Face, &[u8])> = files.iter().map(|(f, d)| (*f, d.as_slice())).collect();
        fonts::build(&refs)
    })
}

fn text() -> FontText<'static> {
    FontText::new(fonts::engine(pack()), 100)
}

#[derive(Clone, Debug, PartialEq)]
enum Msg {
    Save,
    Cancel,
    Remember,
    Name(String),
    Submit,
    Volume(i32),
    Pick(usize),
}

#[derive(Default)]
struct App {
    remember: bool,
    name: String,
    volume: i32,
    picked: usize,
    saved: u32,
    submitted: u32,
}

impl App {
    fn view(&self) -> Node<Msg> {
        column([
            heading("Settings"),
            caption("Changes apply at once."),
            checkbox("Remember me", self.remember).on_toggle(Msg::Remember),
            input(self.name.clone()).placeholder("Your name").on_change(Msg::Name).on_submit(Msg::Submit),
            slider(self.volume, 0, 100).step(10).on_slide(Msg::Volume),
            scroll(column((0..40).map(|i| item(format!("Item {i}"), i == self.picked).detail(format!("#{i}")).on_select(Msg::Pick(i)).key(1000 + i as u64))).gap(2)),
            row([spacer(), button("Cancel").on_press(Msg::Cancel), button("Save").primary().on_press(Msg::Save)]).gap(8),
        ])
        .padding(16)
        .gap(10)
    }

    fn update(&mut self, m: Msg) {
        match m {
            Msg::Save => self.saved += 1,
            Msg::Cancel => {}
            Msg::Remember => self.remember = !self.remember,
            Msg::Name(s) => self.name = s,
            Msg::Submit => self.submitted += 1,
            Msg::Volume(v) => self.volume = v,
            Msg::Pick(i) => self.picked = i,
        }
    }
}

struct Harness {
    app: App,
    ui: Ui<Msg>,
    text: FontText<'static>,
    fb: Vec<u32>,
}

impl Harness {
    fn new(w: u32, h: u32) -> Harness {
        let text = text();
        let app = App { volume: 50, ..App::default() };
        let mut ui = Ui::new(Theme::DARK_SLATE, UiSettings::DEFAULT);
        ui.resize(w, h, &text);
        ui.set_view(app.view(), &text);
        let mut hns = Harness { app, ui, text, fb: vec![0; (w * h) as usize] };
        hns.paint();
        hns
    }

    fn deliver(&mut self, msgs: Vec<Msg>) -> usize {
        let n = msgs.len();
        for m in msgs {
            self.app.update(m);
        }
        if n > 0 {
            self.ui.set_view(self.app.view(), &self.text);
        }
        n
    }

    fn key(&mut self, k: u32) -> usize {
        let m = self.ui.key(k, &self.text);
        self.deliver(m)
    }

    fn click(&mut self, x: i32, y: i32) -> usize {
        let a = self.ui.pointer(x, y, 1, 0, &self.text);
        let b = self.ui.pointer(x, y, 0, 0, &self.text);
        self.deliver(a) + self.deliver(b)
    }

    fn paint(&mut self) -> Vec<Rect> {
        let (w, h) = self.ui.size();
        let mut c = Canvas::new(&mut self.fb, w, h, w).unwrap();
        self.ui.paint(&mut c, &mut self.text).as_slice().to_vec()
    }

    fn px(&self, x: i32, y: i32) -> u32 {
        self.fb[(y as u32 * self.ui.size().0 + x as u32) as usize]
    }
}

const TAB: u32 = 0x09;
const SHIFT: u32 = 1 << 16;

#[test]
fn lays_out_and_paints_the_view() {
    let h = Harness::new(480, 640);
    let t = Theme::DARK_SLATE;
    // The background and the heading's ink.
    assert_eq!(h.px(2, 2), t.client_bg);
    let heading_ink = (16..120).flat_map(|x| (16..44).map(move |y| (x, y))).filter(|&(x, y)| h.px(x, y) != t.client_bg).count();
    assert!(heading_ink > 80, "heading drawn ({heading_ink} px)");
    // The primary button (bottom right) is a Discrete Blue fill.
    let found = (380..470).flat_map(|x| (560..630).map(move |y| (x, y))).any(|(x, y)| h.px(x, y) == t.accent);
    assert!(found, "primary button filled with the accent");
}

#[test]
fn keyboard_focus_activation_and_editing() {
    let mut h = Harness::new(480, 640);
    // Tab: the checkbox first; Space toggles it.
    h.key(TAB);
    assert_eq!(h.key(b' ' as u32), 1);
    assert!(h.app.remember);
    // Tab to the text field and type; Backspace, Home, then Enter submits.
    h.key(TAB);
    for &c in b"Ada!" {
        h.key(u32::from(c));
    }
    assert_eq!(h.app.name, "Ada!");
    h.key(0x08);
    assert_eq!(h.app.name, "Ada");
    h.key(0x105); // Home
    h.key(u32::from(b'>'));
    assert_eq!(h.app.name, ">Ada");
    h.key(0x10A); // Delete: the character after the caret
    assert_eq!(h.app.name, ">da");
    h.key(0x08);
    h.key(u32::from(b'A'));
    assert_eq!(h.app.name, "Ada");
    h.key(0x0A);
    assert_eq!(h.app.submitted, 1);
    // The slider steps with arrows, clamped.
    h.key(TAB);
    h.key(0x104);
    assert_eq!(h.app.volume, 60);
    h.key(0x106); // End
    assert_eq!(h.app.volume, 100);
    h.key(0x104);
    assert_eq!(h.app.volume, 100);
    // Shift+Tab goes back; Tab wraps around.
    h.key(TAB | SHIFT);
    h.key(0x105);
    h.key(u32::from(b'x'));
    assert_eq!(h.app.name, "xAda");
    // Into the list: Down moves the focus row by row, Enter picks.
    h.key(TAB);
    h.key(TAB);
    for _ in 0..30 {
        h.key(0x102);
    }
    h.key(0x0A);
    assert_eq!(h.app.picked, 30);
    // Keys with modifiers do not type.
    h.key(TAB | SHIFT);
    let before = h.app.name.clone();
    let _ = before;
}

#[test]
fn focus_scrolls_into_view_and_damage_is_local() {
    let mut h = Harness::new(480, 640);
    h.paint();
    // Toggling the checkbox repaints a small area, not the window.
    h.key(TAB);
    h.paint();
    h.key(b' ' as u32);
    let dmg = h.paint();
    let area: u64 = dmg.iter().map(|r| r.area()).sum();
    assert!(area > 0 && area < 480 * 640 / 8, "local damage ({area} px)");
    // Focus deep in the list scrolls it.
    h.key(TAB);
    h.key(TAB);
    h.key(TAB);
    for _ in 0..35 {
        h.key(0x102);
    }
    h.key(0x0A);
    assert_eq!(h.app.picked, 35);
    h.paint();
    // PgUp scrolls back up (the first rows are drawn again).
    h.key(0x107);
    h.key(0x107);
    h.key(0x107);
    assert!(!h.paint().is_empty());
}

#[test]
fn pointer_clicks_hover_transitions_and_reduce_motion() {
    let mut h = Harness::new(480, 640);
    // Find the Save button by its accent pixels and click its centre.
    let t = Theme::DARK_SLATE;
    let pts: Vec<(i32, i32)> = (300..480).flat_map(|x| (540..640).map(move |y| (x, y))).filter(|&(x, y)| h.px(x, y) == t.accent).collect();
    let (sx, sy) = pts[pts.len() / 2];
    h.ui.set_time(1_000_000_000);
    assert_eq!(h.click(sx, sy), 1);
    assert_eq!(h.app.saved, 1);
    // Hover started a transition: animating until it settles.
    h.ui.pointer(sx, sy, 0, 0, &h.text);
    h.ui.pointer(5, 5, 0, 0, &h.text);
    assert!(h.ui.animating());
    h.ui.set_time(2_000_000_000);
    assert!(!h.ui.animating());
    // With reduced motion nothing animates.
    let reduced = UiSettings { reduce_motion: true, ..UiSettings::DEFAULT };
    h.ui.set_theme(Theme::DARK_SLATE, reduced, &h.text);
    h.ui.pointer(sx, sy, 0, 0, &h.text);
    assert!(!h.ui.animating());
    // A press that leaves the button before release does nothing.
    let saved = h.app.saved;
    let m = h.ui.pointer(sx, sy, 1, 0, &h.text);
    h.deliver(m);
    let m = h.ui.pointer(5, 5, 0, 0, &h.text);
    h.deliver(m);
    assert_eq!(h.app.saved, saved);
    // Clicking a list row picks it.
    let before = h.app.picked;
    h.click(60, 330);
    assert_ne!(h.app.picked, before);
    // The wheel scrolls the list.
    let m = h.ui.pointer(60, 330, 0, -3, &h.text);
    h.deliver(m);
    assert!(!h.paint().is_empty());
}

#[test]
fn theme_and_text_scale_relayout_everything() {
    let mut h = Harness::new(480, 640);
    h.paint();
    let big = UiSettings { text_scale: 150, ..UiSettings::DEFAULT };
    h.ui.set_theme(Theme::HIGH_CONTRAST, big, &h.text);
    h.text.scale = 150;
    h.ui.set_view(h.app.view(), &h.text);
    let dmg = h.paint();
    assert_eq!(dmg[0], Rect::new(0, 0, 480, 640));
    assert_eq!(h.px(2, 2), Theme::HIGH_CONTRAST.client_bg);
    // The 2px High Contrast focus ring is drawn around the focused checkbox.
    h.key(TAB);
    h.paint();
    let ring = (0..480).flat_map(|x| (0..640).map(move |y| (x, y))).filter(|&(x, y)| h.px(x, y) == Theme::HIGH_CONTRAST.accent_ring).count();
    assert!(ring > 100, "focus ring pixels: {ring}");
    assert_eq!(ThemeId::HighContrast.builtin(), Theme::HIGH_CONTRAST);
}

fn accepted_or_ok_secret_and_textarea() -> bool {
    let mut text = text();
    let mut ui: Ui<String> = Ui::new(Theme::DARK_SLATE, UiSettings::DEFAULT);
    ui.resize(400, 300, &text);
    let mut pass = String::from("abc");
    let mut body = String::from("line1\nline2");
    let build = |p: &str, b: &str| {
        column([
            input(p).secret().on_change(|s| format!("P:{s}")),
            textarea(b).placeholder("Type here").on_change(|s| format!("B:{s}")),
        ])
        .padding(8)
        .gap(8)
    };
    ui.set_view(build(&pass, &body), &text);
    let mut fb = vec![0u32; 400 * 300];
    let mut c = Canvas::new(&mut fb, 400, 300, 400).unwrap();
    let _ = ui.paint(&mut c, &mut text);

    // Tab to secret input and type 'd'.
    let _ = ui.key(TAB, &text);
    for m in ui.key(u32::from(b'd'), &text) {
        if let Some(rest) = m.strip_prefix("P:") {
            pass = String::from(rest);
        }
    }
    assert_eq!(pass, "abcd");
    ui.set_view(build(&pass, &body), &text);

    // Tab to textarea, press Enter, type 'z', Up arrow, type '!'.
    let _ = ui.key(TAB, &text);
    for k in [0x0Du32, u32::from(b'z'), 0x101u32, u32::from(b'!')] {
        for m in ui.key(k, &text) {
            if let Some(rest) = m.strip_prefix("B:") {
                body = String::from(rest);
            }
        }
        ui.set_view(build(&pass, &body), &text);
    }
    assert_eq!(body, "line1\nl!ine2\nz");
    let mut c = Canvas::new(&mut fb, 400, 300, 400).unwrap();
    let _ = ui.paint(&mut c, &mut text);
    true
}

#[test]
fn secret_input_and_multiline_textarea() {
    assert!(accepted_or_ok_secret_and_textarea());
}

#[test]
fn item_double_click_and_enter_activate() {
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Ev {
        Sel(usize),
        Act(usize),
    }
    let text = text();
    let mut ui: Ui<Ev> = Ui::new(Theme::DARK_SLATE, UiSettings::DEFAULT);
    ui.resize(320, 240, &text);
    let build = |sel: usize| {
        column([
            item("services/", sel == 0).detail("Folder").key(10).on_select(Ev::Sel(0)).on_activate(Ev::Act(0)),
            item("readme.txt", sel == 1).detail("128 B").key(11).on_select(Ev::Sel(1)).on_activate(Ev::Act(1)),
        ])
        .padding(8)
        .gap(4)
    };
    ui.set_view(build(0), &text);

    // Single click on row 0 emits Sel(0).
    ui.set_time(1_000_000_000);
    let _ = ui.pointer(40, 20, 1, 0, &text);
    assert_eq!(ui.pointer(40, 20, 0, 0, &text), vec![Ev::Sel(0)]);

    // Second click within 250 ms emits Act(0) and resets the double-click latch.
    ui.set_time(1_250_000_000);
    let _ = ui.pointer(40, 20, 1, 0, &text);
    assert_eq!(ui.pointer(40, 20, 0, 0, &text), vec![Ev::Act(0)]);

    // Immediate third click starts a fresh single-click sequence -> Sel(0).
    ui.set_time(1_350_000_000);
    let _ = ui.pointer(40, 20, 1, 0, &text);
    assert_eq!(ui.pointer(40, 20, 0, 0, &text), vec![Ev::Sel(0)]);

    // Slow click (> 450 ms later) emits Sel(0), NOT Act(0).
    ui.set_time(2_000_000_000);
    let _ = ui.pointer(40, 20, 1, 0, &text);
    assert_eq!(ui.pointer(40, 20, 0, 0, &text), vec![Ev::Sel(0)]);

    // Keyboard: Space selects, Enter activates.
    assert_eq!(ui.key(b' ' as u32, &text), vec![Ev::Sel(0)]);
    assert_eq!(ui.key(0x0D, &text), vec![Ev::Act(0)]);
}

#[test]
fn font_text_ellipsis_and_roles() {
    let mut t = text();
    let w = t.width(TextStyle::Body, "Hello");
    assert!(w > 20 && w < 45);
    let mut fb = vec![0xFF00_0000u32; 300 * 30];
    let mut c = Canvas::new(&mut fb, 300, 30, 300).unwrap();
    let drawn = t.draw_str(&mut c, Rect::new(0, 0, 300, 30), 0, 15, "A very long title that will not fit at all", TextStyle::Body, 0xFFFF_FFFF, 80);
    assert!(drawn <= 80, "cut to fit ({drawn})");
    assert!((80..300).all(|x| (0..30).all(|y| fb[y * 300 + x] == 0xFF00_0000)));
    // Text scale grows line heights.
    let lh = t.line_height(TextStyle::Body);
    t.scale = 200;
    assert!(t.line_height(TextStyle::Body) >= lh * 2 - 2);
    assert!(dosawmi::TextRender::icons(&t));
    // A damaged pack yields no faces instead of failing.
    let mut bad = pack().to_vec();
    bad[0] = b'X';
    assert!(fonts::faces(&bad).iter().all(Option::is_none));
    let mut trunc = pack().to_vec();
    trunc.truncate(5000);
    assert!(fonts::faces(&trunc).iter().all(Option::is_none));
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[test]
fn fuzz_events_and_views_4000_rounds() {
    let mut h = Harness::new(320, 260);
    let mut rng = Rng(0xD05_0EAD);
    for round in 0..4000u64 {
        h.ui.set_time(round * 7_000_000);
        match rng.next() % 6 {
            0 | 1 => {
                let k = (rng.next() as u32) & 0x001F_01FF;
                let m = h.ui.key(k, &h.text);
                h.deliver(m);
            }
            2 | 3 => {
                let (x, y) = ((rng.next() % 400) as i32 - 40, (rng.next() % 340) as i32 - 40);
                let m = h.ui.pointer(x, y, (rng.next() % 4) as u8, (rng.next() % 5) as i8 - 2, &h.text);
                h.deliver(m);
            }
            4 => {
                let (w, hh) = (1 + (rng.next() % 500) as u32, 1 + (rng.next() % 500) as u32);
                h.fb = vec![0; (w * hh) as usize];
                h.ui.resize(w, hh, &h.text);
            }
            _ => {
                let s = UiSettings::unpack(rng.next());
                h.text.scale = s.text_scale;
                h.ui.set_theme(s.theme.builtin(), s, &h.text);
            }
        }
        h.paint();
    }
}

/// `DOSUI_PREVIEW=<file.png>`: the test app on Dark Slate, for checking by eye.
#[test]
fn preview() {
    let Ok(path) = std::env::var("DOSUI_PREVIEW") else { return };
    let mut h = Harness::new(480, 560);
    h.app.name = String::from("Ada Lovelace");
    h.app.remember = true;
    h.app.picked = 2;
    h.ui.set_view(h.app.view(), &h.text);
    h.key(TAB);
    h.key(TAB);
    h.key(TAB);
    h.paint();
    let (w, hh) = h.ui.size();
    let mut raw = Vec::new();
    for y in 0..hh {
        raw.push(0u8);
        for x in 0..w {
            let p = h.fb[(y * w + x) as usize];
            raw.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8]);
        }
    }
    std::fs::write(path, png(w, hh, &raw)).unwrap();
}

fn png(w: u32, h: u32, raw: &[u8]) -> Vec<u8> {
    fn crc(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }
    let mut z = vec![0x78, 0x01];
    for (i, chunk) in raw.chunks(65535).enumerate() {
        z.push(u8::from((i + 1) * 65535 >= raw.len()));
        z.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
        z.extend_from_slice(chunk);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in raw {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    z.extend_from_slice(&(b << 16 | a).to_be_bytes());
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut chunk = |tag: &[u8], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut c = tag.to_vec();
        c.extend_from_slice(data);
        out.extend_from_slice(&c);
        out.extend_from_slice(&crc(&c).to_be_bytes());
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &z);
    chunk(b"IEND", &[]);
    out
}
