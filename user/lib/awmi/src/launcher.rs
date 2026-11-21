//! The launcher: a centred, type-to-search panel the compositor draws itself (tap `Super`, or
//! `Alt+F1` where the host takes `Super`). It lists the programs that registered a launcher entry
//! (each shown with the identity and trust tier the service manager verified, like a title bar:
//! a program can name its entry but not pose as another) and the built-in actions: theme, text
//! size, motion, leaving the desktop. Keyboard first: type to filter, Up/Down/Tab to choose,
//! Enter to open, Escape to close; the pointer works too.

use crate::geom::{Point, Rect};
use crate::pixel::Canvas;
use crate::proto::{MAX_IDENTITY_BYTES, TrustTier, sanitize_label};
use crate::text::{TextRender, TextRole};
use crate::theme::{Theme, ThemeId};

pub const MAX_LAUNCH_APPS: usize = 24;
pub const LAUNCH_LABEL_BYTES: usize = 32;
/// Entries per program.
pub const MAX_APPS_PER_CLIENT: usize = 4;
const MAX_QUERY: usize = 32;
/// Rows shown at once.
pub const MAX_ROWS: usize = 8;
/// The open animation (fade and slide), unless motion is reduced.
pub const OPEN_NS: u64 = 120_000_000;

/// A built-in launcher action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// Dark Slate <-> High Contrast.
    ThemeToggle,
    TextLarger,
    TextSmaller,
    /// Reduce motion on/off.
    MotionToggle,
    /// End the session (back to the text console).
    LeaveDesktop,
}

const SETTINGS: [Setting; 5] = [Setting::ThemeToggle, Setting::TextLarger, Setting::TextSmaller, Setting::MotionToggle, Setting::LeaveDesktop];

/// What a launcher row opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchTarget {
    /// A program's entry: the compositor sends it `EVT_LAUNCH` with `app`.
    App { owner: u32, app: u8 },
    Setting(Setting),
}

/// The user-facing settings the compositor applies (and sends to every program).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiSettings {
    pub theme: ThemeId,
    /// Text size in percent (100, 125, 150, 175, 200).
    pub text_scale: u16,
    pub reduce_motion: bool,
}

impl UiSettings {
    pub const DEFAULT: UiSettings = UiSettings { theme: ThemeId::DarkSlate, text_scale: 100, reduce_motion: false };
    pub const SCALES: [u16; 5] = [100, 125, 150, 175, 200];

    /// `a` of `EVT_SETTINGS` / `OP_SETTINGS`: theme | text scale << 8 | reduce motion << 24.
    pub const fn pack(self) -> u64 {
        self.theme as u64 | (self.text_scale as u64) << 8 | (self.reduce_motion as u64) << 24
    }

    pub fn unpack(v: u64) -> UiSettings {
        let scale = ((v >> 8) & 0xFFFF) as u16;
        UiSettings {
            theme: ThemeId::from_u8(v as u8),
            text_scale: if Self::SCALES.contains(&scale) { scale } else { 100 },
            reduce_motion: (v >> 24) & 1 != 0,
        }
    }

    pub fn larger(self) -> UiSettings {
        let i = Self::SCALES.iter().position(|&s| s == self.text_scale).unwrap_or(0);
        UiSettings { text_scale: Self::SCALES[(i + 1).min(Self::SCALES.len() - 1)], ..self }
    }

    pub fn smaller(self) -> UiSettings {
        let i = Self::SCALES.iter().position(|&s| s == self.text_scale).unwrap_or(0);
        UiSettings { text_scale: Self::SCALES[i.saturating_sub(1)], ..self }
    }

    /// The settings after a launcher action (`LeaveDesktop` changes nothing here).
    pub fn apply(self, s: Setting) -> UiSettings {
        match s {
            Setting::ThemeToggle => UiSettings {
                theme: if self.theme == ThemeId::DarkSlate { ThemeId::HighContrast } else { ThemeId::DarkSlate },
                ..self
            },
            Setting::TextLarger => self.larger(),
            Setting::TextSmaller => self.smaller(),
            Setting::MotionToggle => UiSettings { reduce_motion: !self.reduce_motion, ..self },
            Setting::LeaveDesktop => self,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct App {
    owner: u32,
    app: u8,
    label: [u8; LAUNCH_LABEL_BYTES],
    label_len: u8,
    identity: [u8; MAX_IDENTITY_BYTES],
    id_len: u8,
    trust: TrustTier,
}

const EMPTY_APP: App = App { owner: 0, app: 0, label: [0; LAUNCH_LABEL_BYTES], label_len: 0, identity: [0; MAX_IDENTITY_BYTES], id_len: 0, trust: TrustTier::Native };

impl App {
    fn label(&self) -> &[u8] {
        &self.label[..usize::from(self.label_len)]
    }
    fn identity(&self) -> &[u8] {
        &self.identity[..usize::from(self.id_len)]
    }
}

/// What a key did to the launcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Consumed (the query or the selection changed, or nothing).
    Changed,
    Close,
    Activate(LaunchTarget),
}

/// Geometry of the open launcher (output-local).
#[derive(Clone, Copy, Debug, Default)]
pub struct LauncherRects {
    pub panel: Rect,
    pub field: Rect,
    pub rows: [Rect; MAX_ROWS],
    pub n: usize,
}

pub struct Launcher {
    pub open: bool,
    apps: [App; MAX_LAUNCH_APPS],
    napps: usize,
    query: [u8; MAX_QUERY],
    qlen: usize,
    /// Selected row among the results.
    pub sel: usize,
    /// When it opened (`WmState::now_ns`), for the animation.
    pub opened_at: u64,
}

impl Default for Launcher {
    fn default() -> Self {
        Self::new()
    }
}

fn lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// `needle` occurs in `hay`, ignoring ASCII case.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w.iter().zip(needle).all(|(&a, &b)| lower(a) == lower(b)))
}

fn setting_words(s: Setting) -> &'static [u8] {
    match s {
        Setting::ThemeToggle => b"theme high contrast dark slate colours colors accessibility",
        Setting::TextLarger => b"larger text size bigger zoom font accessibility",
        Setting::TextSmaller => b"smaller text size zoom font accessibility",
        Setting::MotionToggle => b"reduce motion animation accessibility",
        Setting::LeaveDesktop => b"leave desktop exit text console shell quit",
    }
}

/// A row's label for an action, which depends on the current settings.
pub fn setting_label(s: Setting, cur: UiSettings, out: &mut [u8; 48]) -> usize {
    let mut n = 0;
    let mut put = |t: &[u8]| {
        for &b in t {
            if n < out.len() {
                out[n] = b;
                n += 1;
            }
        }
    };
    match s {
        Setting::ThemeToggle => put(if cur.theme == ThemeId::DarkSlate { b"Theme: switch to High Contrast" } else { b"Theme: switch to Dark Slate" }),
        Setting::TextLarger | Setting::TextSmaller => {
            put(if s == Setting::TextLarger { b"Larger text (" } else { b"Smaller text (" });
            let next = if s == Setting::TextLarger { cur.larger() } else { cur.smaller() }.text_scale;
            let mut d = [0u8; 3];
            let mut k = 0;
            let mut v = next;
            loop {
                d[k] = b'0' + (v % 10) as u8;
                k += 1;
                v /= 10;
                if v == 0 || k == 3 {
                    break;
                }
            }
            for i in (0..k).rev() {
                put(&d[i..=i]);
            }
            put(b"%)");
        }
        Setting::MotionToggle => put(if cur.reduce_motion { b"Motion: turn animations back on" } else { b"Motion: reduce motion" }),
        Setting::LeaveDesktop => put(b"Leave the desktop (text console)"),
    }
    n
}

impl Launcher {
    pub const fn new() -> Launcher {
        Launcher { open: false, apps: [EMPTY_APP; MAX_LAUNCH_APPS], napps: 0, query: [0; MAX_QUERY], qlen: 0, sel: 0, opened_at: 0 }
    }

    pub fn query(&self) -> &[u8] {
        &self.query[..self.qlen]
    }

    pub fn app_count(&self) -> usize {
        self.napps
    }

    /// Add or replace program `owner`'s entry `app` (at most `MAX_APPS_PER_CLIENT` per program).
    pub fn register(&mut self, owner: u32, app: u8, label: &[u8], identity: &[u8], trust: TrustTier) -> bool {
        if usize::from(app) >= MAX_APPS_PER_CLIENT {
            return false;
        }
        let mut e = App { owner, app, trust, ..EMPTY_APP };
        e.label_len = sanitize_label(label, &mut e.label) as u8;
        e.id_len = sanitize_label(identity, &mut e.identity) as u8;
        if e.label_len == 0 {
            return false;
        }
        if let Some(x) = self.apps[..self.napps].iter_mut().find(|x| x.owner == owner && x.app == app) {
            *x = e;
            return true;
        }
        if self.napps == MAX_LAUNCH_APPS {
            return false;
        }
        self.apps[self.napps] = e;
        self.napps += 1;
        true
    }

    /// Drop every entry of a program that went away.
    pub fn remove_owner(&mut self, owner: u32) {
        let mut k = 0;
        for i in 0..self.napps {
            if self.apps[i].owner != owner {
                self.apps[k] = self.apps[i];
                k += 1;
            }
        }
        self.napps = k;
        self.sel = 0;
    }

    pub fn show(&mut self, now: u64) {
        self.open = true;
        self.qlen = 0;
        self.sel = 0;
        self.opened_at = now;
    }

    pub fn hide(&mut self) {
        self.open = false;
        self.qlen = 0;
    }

    /// The matching rows, apps first: (target, index among apps or settings).
    pub fn results(&self, out: &mut [LaunchTarget; MAX_LAUNCH_APPS + 5]) -> usize {
        let q = self.query();
        let mut n = 0;
        for a in &self.apps[..self.napps] {
            if contains(a.label(), q) || contains(a.identity(), q) {
                out[n] = LaunchTarget::App { owner: a.owner, app: a.app };
                n += 1;
            }
        }
        for s in SETTINGS {
            if contains(setting_words(s), q) {
                out[n] = LaunchTarget::Setting(s);
                n += 1;
            }
        }
        n
    }

    fn selected(&self) -> Option<LaunchTarget> {
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_LAUNCH_APPS + 5];
        let n = self.results(&mut r);
        (n > 0).then(|| r[self.sel.min(n - 1)])
    }

    /// A key while open (`base`: the key without modifiers; only presses arrive here).
    pub fn key(&mut self, base: u32) -> Outcome {
        const UP: u32 = 0x101;
        const DOWN: u32 = 0x102;
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_LAUNCH_APPS + 5];
        let n = self.results(&mut r);
        match base {
            0x1B => Outcome::Close,
            0x0A | 0x0D => match self.selected() {
                Some(t) => Outcome::Activate(t),
                None => Outcome::Changed,
            },
            UP => {
                self.sel = self.sel.saturating_sub(1);
                Outcome::Changed
            }
            DOWN | 0x09 => {
                if n > 0 {
                    self.sel = (self.sel + 1).min(n - 1);
                }
                Outcome::Changed
            }
            0x08 => {
                self.qlen = self.qlen.saturating_sub(1);
                self.sel = 0;
                Outcome::Changed
            }
            0x20..=0x7E if self.qlen < MAX_QUERY => {
                self.query[self.qlen] = base as u8;
                self.qlen += 1;
                self.sel = 0;
                Outcome::Changed
            }
            _ => Outcome::Changed,
        }
    }

    /// Where the launcher is on an output of `out_w` x `out_h`, for a body line height.
    pub fn rects(&self, out_w: u32, out_h: u32, line_h: u32) -> LauncherRects {
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_LAUNCH_APPS + 5];
        let n = self.results(&mut r).min(MAX_ROWS);
        let row_h = (line_h + 18).max(34);
        let field_h = (line_h + 24).max(42);
        let w = 560u32.min(out_w.saturating_sub(48)).max(200.min(out_w));
        let pad = 10u32;
        let h = pad * 2 + field_h + 8 + row_h * n.max(1) as u32;
        let x = (out_w.saturating_sub(w) / 2) as i32;
        let y = (out_h / 5).min(out_h.saturating_sub(h) / 2) as i32;
        let panel = Rect::new(x, y, w, h);
        let field = Rect::new(x + pad as i32, y + pad as i32, w - pad * 2, field_h);
        let mut rows = [Rect::EMPTY; MAX_ROWS];
        for (i, row) in rows.iter_mut().enumerate().take(n) {
            *row = Rect::new(x + pad as i32, field.y + (field_h + 8 + row_h * i as u32) as i32, w - pad * 2, row_h);
        }
        LauncherRects { panel, field, rows, n }
    }

    /// The first row shown (the list scrolls to keep the selection visible).
    fn first_row(&self) -> usize {
        self.sel.saturating_sub(MAX_ROWS - 1)
    }

    /// The target under output-local point `p`, if any; `None` with `inside` false: outside the panel.
    pub fn hit(&self, rects: &LauncherRects, p: Point) -> (bool, Option<(usize, LaunchTarget)>) {
        if !rects.panel.contains_point(p) {
            return (false, None);
        }
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_LAUNCH_APPS + 5];
        let n = self.results(&mut r);
        for (i, row) in rects.rows.iter().enumerate().take(rects.n) {
            let idx = self.first_row() + i;
            if row.contains_point(p) && idx < n {
                return (true, Some((idx, r[idx])));
            }
        }
        (true, None)
    }

    /// Draw the launcher on an output (`progress` 0-255 of the open animation).
    #[allow(clippy::too_many_arguments)]
    pub fn render(&self, canvas: &mut Canvas<'_>, clip: Rect, theme: &Theme, text: &mut dyn TextRender, rects: &LauncherRects, settings: UiSettings, progress: u32) {
        let out = canvas.bounds();
        // Dim the desktop behind, at once: only the panel animates, so an opening redraws the
        // whole screen once instead of every frame (a full-screen copy can tear without vsync).
        canvas.fill_rect(clip, out, theme.overlay_dim);
        let slide = (12 * (255 - progress.min(255)) / 255) as i32;
        let panel = rects.panel.translate(0, slide);
        if panel.intersect(clip).is_empty() {
            return;
        }
        canvas.fill_rounded_rect(clip, panel, theme.radius + 4, theme.surface_raised, theme.dock_border);
        // The search field (always focused: ring in the accent tint).
        let field = rects.field.translate(0, slide);
        canvas.fill_rounded_rect(clip, field, theme.radius, theme.input_bg, theme.accent_ring);
        if theme.focus_ring > 1 {
            canvas.fill_rounded_rect(clip, field.inset(1), theme.radius.saturating_sub(1), 0, theme.accent_ring);
        }
        let fy = field.y + field.h as i32 / 2;
        let mut tx = field.x + 14;
        if text.icons() {
            tx += text.draw(canvas, clip, tx, fy, "\u{F002}".as_bytes(), TextRole::Icon, theme.text_muted, 40) as i32 + 10;
        }
        let q = self.query();
        let caret_x = if q.is_empty() {
            text.draw(canvas, clip, tx, fy, b"Search apps and settings", TextRole::Large, theme.text_muted, field.w.saturating_sub(40));
            tx
        } else {
            tx + text.draw(canvas, clip, tx, fy, q, TextRole::Large, theme.text_primary, field.w.saturating_sub(40)) as i32
        };
        let lh = text.line_height(TextRole::Large) as i32;
        canvas.fill_rect(clip, Rect::new(caret_x + 1, fy - lh / 2 + 2, 2, (lh - 4).max(4) as u32), theme.accent_ring);

        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_LAUNCH_APPS + 5];
        let n = self.results(&mut r);
        if n == 0 {
            if let Some(&row) = rects.rows.first() {
                let row = Rect::new(row.x, field.y + field.h as i32 + 8, row.w, row.h.max(34));
                text.draw(canvas, clip, row.x + 14, row.y + row.h as i32 / 2, b"No matches", TextRole::Body, theme.text_muted, row.w);
            }
            return;
        }
        let first = self.first_row();
        for (i, row) in rects.rows.iter().enumerate().take(rects.n) {
            let idx = first + i;
            if idx >= n {
                break;
            }
            let row = row.translate(0, slide);
            let selected = idx == self.sel;
            if selected {
                canvas.fill_rounded_rect(clip, row, theme.radius, theme.accent, 0);
            }
            let (fg, muted) = if selected { (theme.text_on_accent, theme.text_on_accent) } else { (theme.text_primary, theme.text_muted) };
            let my = row.y + row.h as i32 / 2;
            match r[idx] {
                LaunchTarget::App { owner, app } => {
                    let Some(a) = self.apps[..self.napps].iter().find(|a| a.owner == owner && a.app == app) else { continue };
                    let dot = match a.trust {
                        TrustTier::System => theme.trust_system,
                        TrustTier::Native => theme.trust_native,
                        TrustTier::Sandbox => theme.trust_sandbox,
                    };
                    canvas.fill_circle(clip, row.x + 16, my, 4, if selected { theme.text_on_accent } else { dot });
                    let idw = text.measure(a.identity(), TextRole::Small).min(row.w / 3);
                    text.draw(canvas, clip, row.x + 30, my, a.label(), TextRole::Body, fg, row.w.saturating_sub(48 + idw));
                    text.draw(canvas, clip, row.x + row.w as i32 - 12 - idw as i32, my, a.identity(), TextRole::Small, muted, idw);
                }
                LaunchTarget::Setting(s) => {
                    let mut lbl = [0u8; 48];
                    let k = setting_label(s, settings, &mut lbl);
                    // The icon centred where an entry's trust dot is; the label aligned with entries'.
                    if text.icons() {
                        let icon = match s {
                            Setting::ThemeToggle => "\u{F042}",
                            Setting::TextLarger => "\u{F00E}",
                            Setting::TextSmaller => "\u{F010}",
                            Setting::MotionToggle => "\u{F04C}",
                            Setting::LeaveDesktop => "\u{F120}",
                        };
                        let iw = text.measure(icon.as_bytes(), TextRole::Icon).min(22);
                        text.draw(canvas, clip, row.x + 16 - (iw / 2) as i32, my, icon.as_bytes(), TextRole::Icon, muted, 22);
                    }
                    text.draw(canvas, clip, row.x + 30, my, &lbl[..k], TextRole::Body, fg, row.w.saturating_sub(40));
                }
            }
        }
    }
}
