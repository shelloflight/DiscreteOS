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
/// Entries per program (appmgr registers up to 16 native .dapp apps).
pub const MAX_APPS_PER_CLIENT: usize = 16;
pub const SETTING_COUNT: usize = 6;
/// Maximum indexed files & directories held in RAM for instant launcher lookup.
pub const MAX_FS_ENTRIES: usize = 256;
/// Maximum UTF-8 bytes of an indexed filesystem path.
pub const FS_PATH_BYTES: usize = 96;
/// Maximum matching file/directory rows returned per query.
pub const MAX_FS_RESULTS: usize = 6;
/// Number of power control actions in the launcher power menu.
pub const POWER_COUNT: usize = 4;
/// Upper bound on results returned by `Launcher::results`.
pub const MAX_RESULTS: usize = MAX_LAUNCH_APPS + MAX_FS_RESULTS + SETTING_COUNT + POWER_COUNT;
const MAX_QUERY: usize = 32;
/// Rows shown at once.
pub const MAX_ROWS: usize = 8;
/// The open animation (fade and slide), unless motion is reduced.
pub const OPEN_NS: u64 = 120_000_000;

/// Power control actions exposed in the launcher's power menu and search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerAction {
    Off,
    Reboot,
    Lock,
    Sleep,
}

pub const POWER_ACTIONS: [PowerAction; POWER_COUNT] = [
    PowerAction::Off,
    PowerAction::Reboot,
    PowerAction::Lock,
    PowerAction::Sleep,
];

impl PowerAction {
    /// Short button label for the launcher footer power menu.
    pub const fn short_label(self) -> &'static [u8] {
        match self {
            PowerAction::Off => b"Off",
            PowerAction::Reboot => b"Reboot",
            PowerAction::Lock => b"Lock",
            PowerAction::Sleep => b"Rest",
        }
    }

    /// Descriptive row label when matched by search query.
    pub const fn row_label(self) -> &'static [u8] {
        match self {
            PowerAction::Off => b"Power Off",
            PowerAction::Reboot => b"Reboot",
            PowerAction::Lock => b"Lock Screen",
            PowerAction::Sleep => b"Rest (Sleep)",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            PowerAction::Off => "\u{F011}",
            PowerAction::Reboot => "\u{F021}",
            PowerAction::Lock => "\u{F023}",
            PowerAction::Sleep => "\u{F186}",
        }
    }
}

/// Interactive hit target inside the launcher footer power control bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerHit {
    Toggle,
    Action(PowerAction),
}

/// One indexed file or directory entry stored in RAM for instant lookup.
#[derive(Clone, Copy, Debug)]
pub struct FsEntry {
    pub path: [u8; FS_PATH_BYTES],
    pub path_len: u8,
    pub name_off: u8,
    pub is_dir: bool,
}

const EMPTY_FS: FsEntry = FsEntry {
    path: [0; FS_PATH_BYTES],
    path_len: 0,
    name_off: 0,
    is_dir: false,
};

impl FsEntry {
    pub fn path(&self) -> &[u8] {
        &self.path[..usize::from(self.path_len).min(FS_PATH_BYTES)]
    }

    pub fn name(&self) -> &[u8] {
        let p = self.path();
        let off = usize::from(self.name_off).min(p.len());
        &p[off..]
    }

    pub fn parent(&self) -> &[u8] {
        let p = self.path();
        let off = usize::from(self.name_off).min(p.len());
        if off <= 1 {
            &p[..off]
        } else {
            &p[..off - 1]
        }
    }
}

/// A built-in launcher action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// Dark Slate <-> High Contrast.
    ThemeToggle,
    TextLarger,
    TextSmaller,
    /// Reduce motion on/off.
    MotionToggle,
    /// Engage the compositor lock screen.
    LockScreen,
    /// End the session (back to the text console).
    LeaveDesktop,
}

const SETTINGS: [Setting; SETTING_COUNT] = [
    Setting::ThemeToggle,
    Setting::TextLarger,
    Setting::TextSmaller,
    Setting::MotionToggle,
    Setting::LockScreen,
    Setting::LeaveDesktop,
];

/// What a launcher row opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchTarget {
    /// A program's entry: the compositor sends it `EVT_LAUNCH` with `app`.
    App { owner: u32, app: u8 },
    /// An indexed file or directory (`Launcher::fs_entry(index)`).
    File { index: u16 },
    Setting(Setting),
    /// A system power action.
    Power(PowerAction),
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
            Setting::LockScreen | Setting::LeaveDesktop => self,
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
    pinned: bool,
}

const EMPTY_APP: App = App {
    owner: 0,
    app: 0,
    label: [0; LAUNCH_LABEL_BYTES],
    label_len: 0,
    identity: [0; MAX_IDENTITY_BYTES],
    id_len: 0,
    trust: TrustTier::Native,
    pinned: false,
};

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
    pub footer: Rect,
    pub power_btn: Rect,
    pub power_opts: [Rect; POWER_COUNT],
    pub power_open: bool,
}

pub struct Launcher {
    pub open: bool,
    apps: [App; MAX_LAUNCH_APPS],
    napps: usize,
    files: [FsEntry; MAX_FS_ENTRIES],
    nfiles: usize,
    query: [u8; MAX_QUERY],
    qlen: usize,
    /// Selected row among the results.
    pub sel: usize,
    /// When it opened (`WmState::now_ns`), for the animation.
    pub opened_at: u64,
    /// Whether the inline power control menu in the footer is expanded.
    pub power_open: bool,
    /// Currently hovered power button or option in the footer.
    pub power_hover: Option<PowerHit>,
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

/// `hay` starts with `needle`, ignoring ASCII case.
fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay[..needle.len()].iter().zip(needle).all(|(&a, &b)| lower(a) == lower(b))
}

fn setting_words(s: Setting) -> &'static [u8] {
    match s {
        Setting::ThemeToggle => b"theme high contrast dark slate colours colors accessibility",
        Setting::TextLarger => b"larger text size bigger zoom font accessibility",
        Setting::TextSmaller => b"smaller text size zoom font accessibility",
        Setting::MotionToggle => b"reduce motion animation accessibility",
        Setting::LockScreen => b"lock screen security sign out",
        Setting::LeaveDesktop => b"leave desktop exit text console shell quit",
    }
}

fn power_words(p: PowerAction) -> &'static [u8] {
    match p {
        PowerAction::Off => b"power off shutdown shut down halt turn off",
        PowerAction::Reboot => b"reboot restart power",
        PowerAction::Lock => b"lock power",
        PowerAction::Sleep => b"rest sleep suspend power",
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
        Setting::LockScreen => put(b"Lock screen (Super+L)"),
        Setting::LeaveDesktop => put(b"Leave the desktop (text console)"),
    }
    n
}

impl Launcher {
    pub const fn new() -> Launcher {
        Launcher {
            open: false,
            apps: [EMPTY_APP; MAX_LAUNCH_APPS],
            napps: 0,
            files: [EMPTY_FS; MAX_FS_ENTRIES],
            nfiles: 0,
            query: [0; MAX_QUERY],
            qlen: 0,
            sel: 0,
            opened_at: 0,
            power_open: false,
            power_hover: None,
        }
    }

    pub fn query(&self) -> &[u8] {
        &self.query[..self.qlen]
    }

    pub fn app_count(&self) -> usize {
        self.napps
    }

    pub fn file_count(&self) -> usize {
        self.nfiles
    }

    /// Clear all indexed files/directories before refreshing the lightweight in-RAM lookup index.
    pub fn clear_files(&mut self) {
        self.nfiles = 0;
    }

    /// Add one file or directory path (e.g. `b"/home/notes.txt"`) to the instant lookup index.
    pub fn push_file(&mut self, path: &[u8], is_dir: bool) -> bool {
        if self.nfiles >= MAX_FS_ENTRIES || path.is_empty() || path.len() > FS_PATH_BYTES {
            return false;
        }
        let mut e = EMPTY_FS;
        let len = sanitize_label(path, &mut e.path);
        if len == 0 {
            return false;
        }
        e.path_len = len as u8;
        let name_off = match e.path[..len].iter().rposition(|&b| b == b'/') {
            Some(pos) if pos + 1 < len => pos + 1,
            _ => 0,
        };
        e.name_off = name_off as u8;
        e.is_dir = is_dir;
        self.files[self.nfiles] = e;
        self.nfiles += 1;
        true
    }

    /// Look up an indexed filesystem entry by its index from `LaunchTarget::File`.
    pub fn fs_entry(&self, index: u16) -> Option<&FsEntry> {
        let i = usize::from(index);
        (i < self.nfiles).then(|| &self.files[i])
    }

    /// Add or replace program `owner`'s entry `app` (at most `MAX_APPS_PER_CLIENT` per program).
    pub fn register(&mut self, owner: u32, app: u8, label: &[u8], identity: &[u8], trust: TrustTier) -> bool {
        self.register_ex(owner, app, label, identity, trust, false)
    }

    /// Add or replace program `owner`'s entry `app`, optionally pinned as a dock quick-launch pill.
    pub fn register_ex(&mut self, owner: u32, app: u8, label: &[u8], identity: &[u8], trust: TrustTier, pinned: bool) -> bool {
        if usize::from(app) >= MAX_APPS_PER_CLIENT {
            return false;
        }
        let mut e = App { owner, app, trust, pinned, ..EMPTY_APP };
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

    /// Update the pinned-to-dock state of `(owner, app)`. Returns true if the state changed.
    pub fn set_pinned(&mut self, owner: u32, app: u8, pinned: bool) -> bool {
        if let Some(x) = self.apps[..self.napps].iter_mut().find(|x| x.owner == owner && x.app == app)
            && x.pinned != pinned
        {
            x.pinned = pinned;
            return true;
        }
        false
    }

    /// Toggle the pinned-to-dock state of `(owner, app)`. Returns `Some(new_pinned)` if found.
    pub fn toggle_pinned(&mut self, owner: u32, app: u8) -> Option<bool> {
        let x = self.apps[..self.napps].iter_mut().find(|x| x.owner == owner && x.app == app)?;
        x.pinned = !x.pinned;
        Some(x.pinned)
    }

    /// Collect up to `MAX_DOCK_PINNED` pinned entries for the floating dock.
    pub fn pinned_entries(&self, out: &mut [crate::dock::DockPinnedEntry; crate::dock::MAX_DOCK_PINNED]) -> usize {
        let mut n = 0usize;
        for a in &self.apps[..self.napps] {
            if !a.pinned {
                continue;
            }
            if n >= out.len() {
                break;
            }
            let mut e = crate::dock::DockPinnedEntry {
                owner: a.owner,
                app: a.app,
                running: false,
                label: [0; 16],
                label_len: 0,
            };
            let len = a.label().len().min(e.label.len());
            e.label[..len].copy_from_slice(&a.label()[..len]);
            e.label_len = len as u8;
            out[n] = e;
            n += 1;
        }
        n
    }

    /// Drop every entry of a program that went away; returns true if a pinned entry was removed.
    pub fn remove_owner(&mut self, owner: u32) -> bool {
        let mut removed_pinned = false;
        let mut k = 0;
        for i in 0..self.napps {
            if self.apps[i].owner != owner {
                self.apps[k] = self.apps[i];
                k += 1;
            } else if self.apps[i].pinned {
                removed_pinned = true;
            }
        }
        self.napps = k;
        self.sel = 0;
        removed_pinned
    }

    pub fn show(&mut self, now: u64) {
        self.open = true;
        self.qlen = 0;
        self.sel = 0;
        self.opened_at = now;
        self.power_open = false;
        self.power_hover = None;
    }

    pub fn hide(&mut self) {
        self.open = false;
        self.qlen = 0;
        self.power_open = false;
        self.power_hover = None;
    }

    /// The matching rows: apps first, then matching files/directories (when typing),
    /// then settings, then power actions (when typing).
    pub fn results(&self, out: &mut [LaunchTarget]) -> usize {
        let q = self.query();
        let cap = out.len();
        let mut n = 0;
        for a in &self.apps[..self.napps] {
            if n >= cap {
                return n;
            }
            if contains(a.label(), q) || contains(a.identity(), q) {
                out[n] = LaunchTarget::App { owner: a.owner, app: a.app };
                n += 1;
            }
        }
        if !q.is_empty() && self.nfiles > 0 {
            // Bounded top-K scoring: basename prefix > basename substring > full-path substring,
            // preferring shorter paths and directories on ties (zero heap allocation).
            let mut best: [(u16, u8, u8, bool); MAX_FS_RESULTS] = [(0, 0, 255, false); MAX_FS_RESULTS];
            let mut k = 0usize;
            for (idx, f) in self.files[..self.nfiles].iter().enumerate() {
                let name = f.name();
                let score = if starts_with(name, q) {
                    3u8
                } else if contains(name, q) {
                    2u8
                } else if contains(f.path(), q) {
                    1u8
                } else {
                    0u8
                };
                if score == 0 {
                    continue;
                }
                let cand = (idx as u16, score, f.path_len, f.is_dir);
                let mut pos = k;
                while pos > 0 {
                    let prev = best[pos - 1];
                    let better = cand.1 > prev.1
                        || (cand.1 == prev.1 && (cand.2 < prev.2 || (cand.2 == prev.2 && cand.3 && !prev.3)));
                    if !better {
                        break;
                    }
                    if pos < MAX_FS_RESULTS {
                        best[pos] = prev;
                    }
                    pos -= 1;
                }
                if pos < MAX_FS_RESULTS {
                    best[pos] = cand;
                    if k < MAX_FS_RESULTS {
                        k += 1;
                    }
                }
            }
            for &(idx, _, _, _) in &best[..k] {
                if n >= cap {
                    return n;
                }
                out[n] = LaunchTarget::File { index: idx };
                n += 1;
            }
        }
        for s in SETTINGS {
            if n >= cap {
                return n;
            }
            if contains(setting_words(s), q) {
                out[n] = LaunchTarget::Setting(s);
                n += 1;
            }
        }
        if !q.is_empty() {
            // Prefix matches on short_label first (e.g. "rest" ranks Rest before Reboot's "restart").
            for prefix_pass in [true, false] {
                for p in POWER_ACTIONS {
                    if p == PowerAction::Lock {
                        continue; // LockScreen setting already handles "lock" search queries
                    }
                    let is_prefix = starts_with(p.short_label(), q);
                    if prefix_pass != is_prefix || (!is_prefix && !contains(power_words(p), q)) {
                        continue;
                    }
                    if n >= cap {
                        return n;
                    }
                    out[n] = LaunchTarget::Power(p);
                    n += 1;
                }
            }
        }
        n
    }

    fn selected(&self) -> Option<LaunchTarget> {
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_RESULTS];
        let n = self.results(&mut r);
        (n > 0).then(|| r[self.sel.min(n - 1)])
    }

    /// A key while open (`base`: the key without modifiers; only presses arrive here).
    pub fn key(&mut self, base: u32) -> Outcome {
        const UP: u32 = 0x101;
        const DOWN: u32 = 0x102;
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_RESULTS];
        let n = self.results(&mut r);
        match base {
            0x1B => {
                if self.power_open {
                    self.power_open = false;
                    self.power_hover = None;
                    Outcome::Changed
                } else {
                    Outcome::Close
                }
            }
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
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_RESULTS];
        let n = self.results(&mut r).min(MAX_ROWS);
        let row_h = (line_h + 18).max(34);
        let field_h = (line_h + 24).max(42);
        let footer_h = (line_h + 20).max(36);
        let w = 560u32.min(out_w.saturating_sub(48)).max(200.min(out_w));
        let pad = 10u32;
        let h = pad * 2 + field_h + 8 + row_h * n.max(1) as u32 + 10 + footer_h;
        let x = (out_w.saturating_sub(w) / 2) as i32;
        let y = (out_h / 5).min(out_h.saturating_sub(h) / 2) as i32;
        let panel = Rect::new(x, y, w, h);
        let field = Rect::new(x + pad as i32, y + pad as i32, w - pad * 2, field_h);
        let mut rows = [Rect::EMPTY; MAX_ROWS];
        for (i, row) in rows.iter_mut().enumerate().take(n) {
            *row = Rect::new(x + pad as i32, field.y + (field_h + 8 + row_h * i as u32) as i32, w - pad * 2, row_h);
        }
        let footer = Rect::new(x + pad as i32, y + (h - pad - footer_h) as i32, w - pad * 2, footer_h);
        let btn_h = footer_h.saturating_sub(6).max(24);
        let btn_y = footer.y + ((footer.h.saturating_sub(btn_h)) / 2) as i32;
        let power_w = 88u32.min(footer.w / 3).max(52.min(footer.w));
        let power_btn = Rect::new(footer.x + (footer.w.saturating_sub(power_w)) as i32, btn_y, power_w, btn_h);
        let mut power_opts = [Rect::EMPTY; POWER_COUNT];
        if self.power_open {
            let gap = 6u32;
            let avail = footer.w.saturating_sub(power_w + 10);
            let opt_w = (avail.saturating_sub(gap * (POWER_COUNT as u32 - 1)) / POWER_COUNT as u32).clamp(36, 94);
            let total_w = opt_w * POWER_COUNT as u32 + gap * (POWER_COUNT as u32 - 1);
            let start_x = power_btn.x - 10 - total_w as i32;
            let base_x = start_x.max(footer.x);
            for (i, opt) in power_opts.iter_mut().enumerate() {
                *opt = Rect::new(base_x + ((opt_w + gap) * i as u32) as i32, btn_y, opt_w, btn_h);
            }
        }
        LauncherRects {
            panel,
            field,
            rows,
            n,
            footer,
            power_btn,
            power_opts,
            power_open: self.power_open,
        }
    }

    /// The first row shown (the list scrolls to keep the selection visible).
    fn first_row(&self) -> usize {
        self.sel.saturating_sub(MAX_ROWS - 1)
    }

    /// Hit-test the footer's Power toggle button and expanded power option pills.
    pub fn hit_power(&self, rects: &LauncherRects, p: Point) -> Option<PowerHit> {
        if rects.power_btn.contains_point(p) {
            return Some(PowerHit::Toggle);
        }
        if rects.power_open {
            for (i, opt) in rects.power_opts.iter().enumerate() {
                if opt.contains_point(p) {
                    return Some(PowerHit::Action(POWER_ACTIONS[i]));
                }
            }
        }
        None
    }

    /// The target under output-local point `p`, if any; `None` with `inside` false: outside the panel.
    pub fn hit(&self, rects: &LauncherRects, p: Point) -> (bool, Option<(usize, LaunchTarget)>) {
        if !rects.panel.contains_point(p) {
            return (false, None);
        }
        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_RESULTS];
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
            text.draw(canvas, clip, tx, fy, b"Search apps, files and settings", TextRole::Large, theme.text_muted, field.w.saturating_sub(40));
            tx
        } else {
            tx + text.draw(canvas, clip, tx, fy, q, TextRole::Large, theme.text_primary, field.w.saturating_sub(40)) as i32
        };
        let lh = text.line_height(TextRole::Large) as i32;
        canvas.fill_rect(clip, Rect::new(caret_x + 1, fy - lh / 2 + 2, 2, (lh - 4).max(4) as u32), theme.accent_ring);

        let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_RESULTS];
        let n = self.results(&mut r);
        if n == 0 {
            let empty_row = Rect::new(field.x, field.y + field.h as i32 + 8, field.w, (text.line_height(TextRole::Body) + 18).max(34));
            text.draw(canvas, clip, empty_row.x + 14, empty_row.y + empty_row.h as i32 / 2, b"No matches", TextRole::Body, theme.text_muted, empty_row.w);
        } else {
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
                    LaunchTarget::File { index } => {
                        let Some(f) = self.fs_entry(index) else { continue };
                        let icon_col = if selected {
                            theme.text_on_accent
                        } else if f.is_dir {
                            theme.accent_ring
                        } else {
                            theme.text_muted
                        };
                        if text.icons() {
                            let icon = if f.is_dir { "\u{F07B}" } else { "\u{F15B}" };
                            let iw = text.measure(icon.as_bytes(), TextRole::Icon).min(22);
                            text.draw(canvas, clip, row.x + 16 - (iw / 2) as i32, my, icon.as_bytes(), TextRole::Icon, icon_col, 22);
                        } else if f.is_dir {
                            canvas.fill_rect(clip, Rect::new(row.x + 11, my - 4, 5, 2), icon_col);
                            canvas.fill_rect(clip, Rect::new(row.x + 11, my - 2, 11, 7), icon_col);
                        } else {
                            canvas.stroke_rect(clip, Rect::new(row.x + 12, my - 5, 8, 10), icon_col);
                        }
                        let parent = f.parent();
                        let pw = text.measure(parent, TextRole::Small).min(row.w * 2 / 5);
                        text.draw(canvas, clip, row.x + 30, my, f.name(), TextRole::Body, fg, row.w.saturating_sub(48 + pw));
                        if !parent.is_empty() {
                            text.draw(canvas, clip, row.x + row.w as i32 - 12 - pw as i32, my, parent, TextRole::Small, muted, pw);
                        }
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
                                Setting::LockScreen => "\u{F023}",
                                Setting::LeaveDesktop => "\u{F120}",
                            };
                            let iw = text.measure(icon.as_bytes(), TextRole::Icon).min(22);
                            text.draw(canvas, clip, row.x + 16 - (iw / 2) as i32, my, icon.as_bytes(), TextRole::Icon, muted, 22);
                        }
                        text.draw(canvas, clip, row.x + 30, my, &lbl[..k], TextRole::Body, fg, row.w.saturating_sub(40));
                    }
                    LaunchTarget::Power(p) => {
                        let ic = if selected {
                            theme.text_on_accent
                        } else if p == PowerAction::Off {
                            theme.ind_alert_red
                        } else {
                            muted
                        };
                        if text.icons() {
                            let icon = p.icon();
                            let iw = text.measure(icon.as_bytes(), TextRole::Icon).min(22);
                            text.draw(canvas, clip, row.x + 16 - (iw / 2) as i32, my, icon.as_bytes(), TextRole::Icon, ic, 22);
                        }
                        text.draw(canvas, clip, row.x + 30, my, p.row_label(), TextRole::Body, fg, row.w.saturating_sub(40));
                    }
                }
            }
        }

        // Clean footer bar with subtle hairline divider and inline Power menu controls.
        let footer = rects.footer.translate(0, slide);
        canvas.fill_rect(clip, Rect::new(footer.x, footer.y - 5, footer.w, 1), theme.border_inactive);
        let pbtn = rects.power_btn.translate(0, slide);
        let pbtn_hov = self.power_hover == Some(PowerHit::Toggle);
        let (pbtn_bg, pbtn_border, pbtn_fg) = if self.power_open {
            (theme.accent, theme.accent_ring, theme.text_on_accent)
        } else if pbtn_hov {
            (theme.btn_hover, theme.border_active, theme.text_primary)
        } else {
            (theme.input_bg, theme.border_inactive, theme.text_primary)
        };
        canvas.fill_rounded_rect(clip, pbtn, theme.radius, pbtn_bg, pbtn_border);
        let pcy = pbtn.y + pbtn.h as i32 / 2;
        let lbl = b"Power";
        let lbl_w = text.measure(lbl, TextRole::Small);
        if text.icons() {
            let ic = "\u{F011}".as_bytes();
            let ic_w = text.measure(ic, TextRole::Icon).min(18);
            let total = ic_w + 6 + lbl_w;
            let sx = pbtn.x + (pbtn.w.saturating_sub(total) / 2) as i32;
            let ic_col = if self.power_open { theme.text_on_accent } else { theme.accent_ring };
            text.draw(canvas, clip, sx, pcy, ic, TextRole::Icon, ic_col, ic_w + 2);
            text.draw(canvas, clip, sx + ic_w as i32 + 6, pcy, lbl, TextRole::Small, pbtn_fg, pbtn.w.saturating_sub(ic_w + 10));
        } else {
            let sx = pbtn.x + (pbtn.w.saturating_sub(lbl_w) / 2) as i32;
            text.draw(canvas, clip, sx, pcy, lbl, TextRole::Small, pbtn_fg, pbtn.w.saturating_sub(8));
        }

        if rects.power_open {
            for (i, &act) in POWER_ACTIONS.iter().enumerate() {
                let r_opt = rects.power_opts[i].translate(0, slide);
                if r_opt.is_empty() {
                    continue;
                }
                let hov = self.power_hover == Some(PowerHit::Action(act));
                let (bg, border, fg, ic_col) = if act == PowerAction::Off {
                    if hov {
                        (theme.btn_close_hover, theme.ind_alert_red, theme.text_on_accent, theme.text_on_accent)
                    } else {
                        (theme.input_bg, theme.border_inactive, theme.text_primary, theme.ind_alert_red)
                    }
                } else if hov {
                    (theme.accent, theme.accent_ring, theme.text_on_accent, theme.text_on_accent)
                } else {
                    (theme.input_bg, theme.border_inactive, theme.text_primary, theme.text_muted)
                };
                canvas.fill_rounded_rect(clip, r_opt, theme.radius, bg, border);
                let cy = r_opt.y + r_opt.h as i32 / 2;
                let olbl = act.short_label();
                let olw = text.measure(olbl, TextRole::Small);
                if text.icons() && r_opt.w >= olw + 24 {
                    let ic = act.icon().as_bytes();
                    let ic_w = text.measure(ic, TextRole::Icon).min(16);
                    let total = ic_w + 5 + olw;
                    let sx = r_opt.x + (r_opt.w.saturating_sub(total) / 2) as i32;
                    text.draw(canvas, clip, sx, cy, ic, TextRole::Icon, ic_col, ic_w + 2);
                    text.draw(canvas, clip, sx + ic_w as i32 + 5, cy, olbl, TextRole::Small, fg, r_opt.w.saturating_sub(ic_w + 8));
                } else {
                    let sx = r_opt.x + (r_opt.w.saturating_sub(olw) / 2) as i32;
                    text.draw(canvas, clip, sx, cy, olbl, TextRole::Small, fg, r_opt.w.saturating_sub(6));
                }
            }
        } else {
            let hint = b"Files, folders, apps & settings";
            let avail = footer.w.saturating_sub(pbtn.w + 16);
            text.draw(canvas, clip, footer.x + 6, pcy, hint, TextRole::Small, theme.text_muted, avail);
        }
    }
}
