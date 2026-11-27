//! Multi-monitor output layout, hybrid floating/snapping window manager, SSD hit-testing,
//! strict surface/input isolation, and damage-tracked compositing.

use crate::dock::{DockHit, DockLayout, DockPinnedEntry, DockTrayState, DockWindowEntry, MAX_DOCK_PINNED, MAX_DOCK_WINDOWS};
use crate::geom::{DamageSet, Point, Rect};
use crate::launcher::{FS_PATH_BYTES, LaunchTarget, Launcher, OPEN_NS, Outcome, PowerAction, PowerHit, Setting, UiSettings};
use crate::lock::{LockMode, LockOutcome, LockReason, LockScreen};
use crate::perm::{PermOutcome, PermPrompt};
use crate::pixel::{Canvas, CursorKind, WinIcon};
use crate::proto::{MAX_IDENTITY_BYTES, MAX_TITLE_BYTES, TrustTier, sanitize_label, win_flags, win_state};
use crate::text::{TextRender, TextRole};
use crate::theme::{ChromeMetrics, DockConfig, Theme};

/// The Super key on its own (`proto::key::META`): pressed and released (`RELEASE`) events.
pub const KEY_META: u32 = 0x11C;
const KEY_F1: u32 = 0x110;

pub const MAX_OUTPUTS: usize = 8;
pub const MAX_WINDOWS: usize = 64;
pub const WORKSPACE_COUNT: u8 = 4;

/// A logical display output (one physical or virtual monitor from `gpu.dsvc`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub adapter_id: u32,
    pub bounds: Rect,
    pub refresh_mhz: u32,
    pub scale: u16,
    pub hw_cursor: bool,
    pub primary: bool,
    pub online: bool,
}

impl Output {
    /// Recommended text/UI scale percentage for an output of pixel width `width`.
    pub const fn recommended_scale(width: u32) -> u16 {
        if width >= 3840 {
            150
        } else if width >= 2560 {
            125
        } else {
            100
        }
    }
}

/// Multi-monitor virtual desktop layout.
#[derive(Clone, Debug)]
pub struct OutputLayout {
    pub outputs: [Output; MAX_OUTPUTS],
    pub count: usize,
}

impl Default for OutputLayout {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputLayout {
    pub const fn new() -> Self {
        Self { outputs: [Output { adapter_id: 0, bounds: Rect::EMPTY, refresh_mhz: 60_000, scale: 100, hw_cursor: false, primary: false, online: false }; MAX_OUTPUTS], count: 0 }
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Add an output arranged cleanly left-to-right in virtual desktop coordinates, using the
    /// recommended per-output scale derived from its width.
    pub fn add_output(&mut self, adapter_id: u32, width: u32, height: u32, refresh_mhz: u32, hw_cursor: bool) -> Option<usize> {
        self.add_output_scaled(adapter_id, width, height, refresh_mhz, hw_cursor, Output::recommended_scale(width))
    }

    /// Add an output with an explicit UI/text scale percentage (`UiSettings::SCALES`; 0 = auto).
    pub fn add_output_scaled(
        &mut self,
        adapter_id: u32,
        width: u32,
        height: u32,
        refresh_mhz: u32,
        hw_cursor: bool,
        scale: u16,
    ) -> Option<usize> {
        if self.count >= MAX_OUTPUTS || width == 0 || height == 0 {
            return None;
        }
        let x = if self.count == 0 {
            0
        } else {
            let prev = self.outputs[self.count - 1].bounds;
            prev.x.saturating_add(prev.w as i32)
        };
        let eff_scale = if UiSettings::SCALES.contains(&scale) {
            scale
        } else {
            Output::recommended_scale(width)
        };
        let idx = self.count;
        self.outputs[idx] = Output {
            adapter_id,
            bounds: Rect::new(x, 0, width, height),
            refresh_mhz: if refresh_mhz == 0 { 60_000 } else { refresh_mhz },
            scale: eff_scale,
            hw_cursor,
            primary: idx == 0,
            online: true,
        };
        self.count += 1;
        Some(idx)
    }

    /// Update the scale percentage (`UiSettings::SCALES`, or 0 for recommended auto) on `adapter_id`
    /// (0 targets the primary output). Returns true if a matching output was updated.
    pub fn set_output_scale(&mut self, adapter_id: u32, scale: u16) -> bool {
        if scale != 0 && !UiSettings::SCALES.contains(&scale) {
            return false;
        }
        let target = if adapter_id == 0 {
            self.outputs[..self.count].iter_mut().find(|o| o.primary && o.online)
        } else {
            self.outputs[..self.count].iter_mut().find(|o| o.adapter_id == adapter_id && o.online)
        };
        let Some(out) = target else {
            return false;
        };
        out.scale = if scale == 0 { Output::recommended_scale(out.bounds.w) } else { scale };
        true
    }

    pub fn as_slice(&self) -> &[Output] {
        &self.outputs[..self.count]
    }

    pub fn primary(&self) -> Option<Output> {
        self.as_slice().iter().copied().find(|o| o.primary && o.online).or_else(|| self.as_slice().first().copied())
    }

    /// Virtual bounding box covering all online outputs.
    pub fn desktop_bounds(&self) -> Rect {
        let mut bb = Rect::EMPTY;
        for o in self.as_slice().iter().filter(|o| o.online) {
            bb = bb.union(o.bounds);
        }
        bb
    }

    /// Find the output containing point `p` (or primary fallback).
    pub fn output_at(&self, p: Point) -> Option<Output> {
        self.as_slice()
            .iter()
            .copied()
            .find(|o| o.online && o.bounds.contains_point(p))
            .or_else(|| self.primary())
    }

    /// Clamp a pointer position onto the nearest online output.
    pub fn clamp_point(&self, p: Point) -> Point {
        if let Some(o) = self.as_slice().iter().find(|o| o.online && o.bounds.contains_point(p)) {
            let _ = o;
            return p;
        }
        let mut best = p;
        let mut best_dist = i64::MAX;
        for o in self.as_slice().iter().filter(|o| o.online) {
            let cx = p.x.clamp(o.bounds.x, o.bounds.x + o.bounds.w as i32 - 1);
            let cy = p.y.clamp(o.bounds.y, o.bounds.y + o.bounds.h as i32 - 1);
            let dx = i64::from(p.x - cx);
            let dy = i64::from(p.y - cy);
            let d = dx * dx + dy * dy;
            if d < best_dist {
                best_dist = d;
                best = Point::new(cx, cy);
            }
        }
        best
    }

    /// Usable window work area on `output` (reserves space for the floating bottom dock on primary).
    pub fn work_area(&self, output: Output, dock_cfg: DockConfig) -> Rect {
        if output.primary {
            let res = dock_cfg.reserved_bottom().min(output.bounds.h / 2);
            Rect::new(output.bounds.x, output.bounds.y, output.bounds.w, output.bounds.h.saturating_sub(res))
        } else {
            output.bounds
        }
    }

    /// Fastest active refresh rate (in mHz) across online outputs for vsync frame pacing.
    pub fn max_refresh_mhz(&self) -> u32 {
        self.as_slice()
            .iter()
            .filter(|o| o.online)
            .map(|o| o.refresh_mhz)
            .max()
            .unwrap_or(60_000)
            .clamp(30_000, 1_000_000)
    }
}

/// Hybrid floating/snapping state of a window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SnapState {
    #[default]
    Floating,
    LeftHalf,
    RightHalf,
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
    Maximized,
}

impl SnapState {
    /// Compute the snapped outer frame rectangle inside `work_area`.
    pub fn target_rect(self, work: Rect) -> Rect {
        let half_w = work.w / 2;
        let rem_w = work.w.saturating_sub(half_w);
        let half_h = work.h / 2;
        let rem_h = work.h.saturating_sub(half_h);
        match self {
            Self::Floating | Self::Maximized => work,
            Self::LeftHalf => Rect::new(work.x, work.y, half_w, work.h),
            Self::RightHalf => Rect::new(work.x + half_w as i32, work.y, rem_w, work.h),
            Self::TopLeft => Rect::new(work.x, work.y, half_w, half_h),
            Self::TopRight => Rect::new(work.x + half_w as i32, work.y, rem_w, half_h),
            Self::BottomLeft => Rect::new(work.x, work.y + half_h as i32, half_w, rem_h),
            Self::BottomRight => Rect::new(work.x + half_w as i32, work.y + half_h as i32, rem_w, rem_h),
        }
    }
}

/// Window decoration hit-test target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WinHit {
    None,
    Client,
    TitleBar,
    BtnMinimize,
    BtnMaximize,
    BtnClose,
    Resize(ResizeEdge),
}

/// 8-way window resize edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResizeEdge {
    pub left: bool,
    pub right: bool,
    pub top: bool,
    pub bottom: bool,
}

impl ResizeEdge {
    pub const fn any(self) -> bool {
        self.left || self.right || self.top || self.bottom
    }

    pub const fn cursor_kind(self) -> CursorKind {
        if (self.left && self.top) || (self.right && self.bottom) {
            CursorKind::ResizeNWSE
        } else if (self.right && self.top) || (self.left && self.bottom) {
            CursorKind::ResizeNESW
        } else if self.left || self.right {
            CursorKind::ResizeEW
        } else if self.top || self.bottom {
            CursorKind::ResizeNS
        } else {
            CursorKind::Default
        }
    }
}

/// Metadata for one isolated client window.
#[derive(Clone, Debug)]
pub struct Window {
    pub id: u32,
    /// Owning client connection id (strict isolation: only `owner` may mutate or receive events).
    pub owner: u32,
    /// Unforgeable manifest identity supplied by `init`.
    pub identity: [u8; MAX_IDENTITY_BYTES],
    pub identity_len: u8,
    pub trust: TrustTier,
    /// App-supplied window title (never alters `identity` or `trust`).
    pub title: [u8; MAX_TITLE_BYTES],
    pub title_len: u8,
    pub workspace: u8,
    pub flags: u32,
    pub frame: Rect,
    /// Saved floating rectangle before snapping or maximizing.
    pub saved_floating: Rect,
    pub snap: SnapState,
    pub minimized: bool,
    /// Whether the client has attached and committed pixels.
    pub mapped: bool,
    pub z_order: u32,
}

impl Window {
    pub fn identity_bytes(&self) -> &[u8] {
        let n = (self.identity_len as usize).min(self.identity.len());
        &self.identity[..n]
    }

    pub fn title_bytes(&self) -> &[u8] {
        let n = (self.title_len as usize).min(self.title.len());
        &self.title[..n]
    }

    pub fn is_decorated(&self) -> bool {
        (self.flags & win_flags::DECORATED) != 0
    }

    pub fn is_resizable(&self) -> bool {
        (self.flags & win_flags::RESIZABLE) != 0
    }

    pub fn is_opaque(&self) -> bool {
        (self.flags & win_flags::OPAQUE) != 0
    }

    /// Client drawable pixel rectangle inside `self.frame`.
    pub fn client_rect(&self, chrome: ChromeMetrics) -> Rect {
        if !self.is_decorated() {
            return self.frame;
        }
        let b = chrome.border_w;
        let top = chrome.title_h;
        let cw = self.frame.w.saturating_sub(b.saturating_mul(2));
        let ch = self.frame.h.saturating_sub(top.saturating_add(b));
        Rect::new(self.frame.x.saturating_add(b as i32), self.frame.y.saturating_add(top as i32), cw, ch)
    }

    /// Outer frame size for a requested client size `(cw, ch)`.
    pub fn frame_size_for_client(cw: u32, ch: u32, flags: u32, chrome: ChromeMetrics) -> (u32, u32) {
        let cw = cw.max(chrome.min_client_w);
        let ch = ch.max(chrome.min_client_h);
        if (flags & win_flags::DECORATED) != 0 {
            (cw.saturating_add(chrome.border_w * 2), ch.saturating_add(chrome.title_h + chrome.border_w))
        } else {
            (cw, ch)
        }
    }

    /// Encode current state flags for `EVT_CONFIGURE`.
    pub fn state_bits(&self, focused_id: Option<u32>) -> u32 {
        let mut s = 0u32;
        if focused_id == Some(self.id) {
            s |= win_state::FOCUSED;
        }
        if self.snap == SnapState::Maximized {
            s |= win_state::MAXIMIZED;
        } else if self.snap != SnapState::Floating {
            s |= win_state::SNAPPED;
        }
        if self.minimized {
            s |= win_state::MINIMIZED;
        }
        s
    }

    /// Hit-test a desktop point against this window's SSD frame and client area.
    pub fn hit_test(&self, p: Point, chrome: ChromeMetrics) -> WinHit {
        if !self.frame.contains_point(p) {
            return WinHit::None;
        }
        if !self.is_decorated() {
            return WinHit::Client;
        }
        let m = chrome.resize_margin as i32;
        if self.is_resizable() && self.snap != SnapState::Maximized {
            let edge = ResizeEdge {
                left: p.x < self.frame.x + m,
                right: i64::from(p.x) >= self.frame.right() - i64::from(m),
                top: p.y < self.frame.y + m,
                bottom: i64::from(p.y) >= self.frame.bottom() - i64::from(m),
            };
            // Don't steal titlebar button clicks for top-right resize unless on the very 2px outer rim.
            let near_buttons = p.y < self.frame.y + chrome.title_h as i32
                && i64::from(p.x) >= self.frame.right() - i64::from(chrome.btn_w * 3);
            let outer_rim = p.y < self.frame.y + 2 || i64::from(p.x) >= self.frame.right() - 2;
            if edge.any() && (!near_buttons || outer_rim) {
                return WinHit::Resize(edge);
            }
        }
        let title_r = Rect::new(self.frame.x, self.frame.y, self.frame.w, chrome.title_h);
        if title_r.contains_point(p) {
            let right = self.frame.x + self.frame.w as i32;
            let bw = chrome.btn_w as i32;
            if p.x >= right - bw {
                return WinHit::BtnClose;
            }
            if p.x >= right - bw * 2 {
                return WinHit::BtnMaximize;
            }
            if p.x >= right - bw * 3 {
                return WinHit::BtnMinimize;
            }
            return WinHit::TitleBar;
        }
        WinHit::Client
    }
}

/// Active pointer drag interaction inside the window manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DragOp {
    None,
    Move {
        window_id: u32,
        grab_dx: i32,
        grab_dy: i32,
        snap_preview: Option<SnapState>,
    },
    Resize {
        window_id: u32,
        edge: ResizeEdge,
        start_ptr: Point,
        start_frame: Rect,
    },
}

/// High-level action produced by a WM input event (consumed by `awmi.dsvc` to emit IPC).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WmAction {
    None,
    /// Route key event exclusively to this `(owner, window_id)`.
    DeliverKey { owner: u32, window_id: u32 },
    /// Route pointer event (window-local coordinates) exclusively to `(owner, window_id)`.
    DeliverPointer { owner: u32, window_id: u32, local_x: i32, local_y: i32 },
    /// Ask `(owner, window_id)` to close cleanly (`EVT_CLOSE_REQUESTED`).
    RequestClose { owner: u32, window_id: u32 },
    /// Window geometry/focus changed; send `EVT_CONFIGURE`.
    Configure { owner: u32, window_id: u32 },
    /// User pressed `Super+Esc` or `Ctrl+Alt+Esc`: exit GUI session back to shell.
    ExitSession,
    /// The user opened a program's launcher entry: send it `EVT_LAUNCH`.
    Launch { owner: u32, app: u8 },
    /// The user opened a file or directory from the launcher lookup.
    OpenPath { path: [u8; FS_PATH_BYTES], len: u8, is_dir: bool },
    /// The user activated a power control action (Off, Reboot, Lock, Sleep) in the launcher.
    Power(PowerAction),
    /// The user picked a built-in action in the launcher.
    Setting(Setting),
    /// User pressed `Super+L` or `Ctrl+Alt+L` (or picked Lock screen in launcher).
    LockSession,
    /// User submitted a passphrase on the compositor lock/login screen for `identity_id`.
    UnlockAttempt { identity_id: u32 },
    /// User answered the compositor modal permission prompt.
    PermPromptResult { request_id: u32, choice: u8 },
    /// User pinned or unpinned a launcher app on the taskbar (e.g. right-click on dock or launcher).
    SetAppPinned { owner: u32, app: u8, pinned: bool },
}

/// Client surface pixel provider callback for compositing.
pub struct SurfaceView<'a> {
    pub bytes: &'a [u8],
    pub width: u32,
    pub height: u32,
    pub pitch_bytes: u32,
}

/// Core D-AWMI compositor and hybrid window manager state (zero heap allocation, zero unsafe).
pub struct WmState {
    pub theme: Theme,
    pub chrome: ChromeMetrics,
    pub dock_cfg: DockConfig,
    pub layout: OutputLayout,
    pub tray: DockTrayState,
    windows: [Option<Window>; MAX_WINDOWS],
    next_win_id: u32,
    next_z: u32,
    pub active_workspace: u8,
    pub focused: Option<u32>,
    pub hovered: Option<u32>,
    pub pointer: Point,
    pub cursor_kind: CursorKind,
    pub buttons: u8,
    pub drag: DragOp,
    pub damage: DamageSet,
    cascade_step: i32,
    /// The launcher (tap `Super`, `Alt+F1`).
    pub launcher: Launcher,
    /// Compositor-drawn unforgeable lock / login screen.
    pub lock: LockScreen,
    /// Compositor-drawn unforgeable permission prompt modal.
    pub perm_prompt: PermPrompt,
    /// Theme, text size, motion (applied by `apply_settings`).
    pub settings: UiSettings,
    /// Monotonic time (ns), set by the compositor before input and compositing (animations).
    pub now_ns: u64,
    /// Line height and average character width of body text (layout of the dock and launcher).
    pub line_h: u32,
    pub char_w: u32,
    /// `Super` went down with no other key since: its release opens the launcher.
    super_tap: bool,
    /// When the current snap preview appeared (its fade-in).
    snap_since: u64,
}

impl Default for WmState {
    fn default() -> Self {
        Self::new()
    }
}

impl WmState {
    pub const fn new() -> Self {
        Self {
            theme: Theme::DARK_SLATE,
            chrome: ChromeMetrics::DEFAULT,
            dock_cfg: DockConfig::DEFAULT,
            layout: OutputLayout::new(),
            tray: DockTrayState {
                active_workspace: 0,
                workspace_count: WORKSPACE_COUNT,
                net_online: false,
                audio_muted: false,
                audio_volume: 100,
                indicators: 0,
                hour: 0,
                minute: 0,
                clock_valid: false,
            },
            windows: [const { None }; MAX_WINDOWS],
            next_win_id: 1,
            next_z: 1,
            active_workspace: 0,
            focused: None,
            hovered: None,
            pointer: Point::ZERO,
            cursor_kind: CursorKind::Default,
            buttons: 0,
            drag: DragOp::None,
            damage: DamageSet::new(),
            cascade_step: 0,
            launcher: Launcher::new(),
            lock: LockScreen::new(),
            perm_prompt: PermPrompt::new(),
            settings: UiSettings::DEFAULT,
            now_ns: 0,
            line_h: 16,
            char_w: 8,
            super_tap: false,
            snap_since: 0,
        }
    }

    /// Apply new settings: the theme, and chrome sized for the text (line height `line_h`,
    /// average character width `char_w`, both from the compositor's text engine).
    pub fn apply_settings(&mut self, settings: UiSettings, theme: Theme, line_h: u32, char_w: u32) {
        self.settings = settings;
        self.theme = theme;
        self.line_h = line_h.clamp(8, 96);
        self.char_w = char_w.clamp(4, 48);
        self.chrome = ChromeMetrics::for_line_height(self.line_h);
        self.dock_cfg = DockConfig::for_line_height(self.line_h);
        // Snapped and maximized windows follow the new work area.
        let snapped: [Option<(u32, SnapState)>; MAX_WINDOWS] =
            core::array::from_fn(|i| self.windows[i].as_ref().filter(|w| w.snap != SnapState::Floating).map(|w| (w.id, w.snap)));
        for (id, snap) in snapped.into_iter().flatten() {
            let center = self.window(id).map(|w| Point::new(w.frame.x + w.frame.w as i32 / 2, w.frame.y + w.frame.h as i32 / 2));
            let Some(out) = center.and_then(|c| self.layout.output_at(c)) else { continue };
            let work = self.layout.work_area(out, self.dock_cfg);
            if let Some(w) = self.window_mut(id) {
                w.frame = snap.target_rect(work);
            }
        }
        self.damage_all();
    }

    /// Re-fit pointer and all windows after outputs are added, removed, or change resolution.
    pub fn fit_windows_to_layout(&mut self) {
        let desk = self.layout.desktop_bounds();
        if desk.w > 0 && desk.h > 0 {
            let inside = |layout: &OutputLayout, p: Point| {
                layout.as_slice().iter().any(|o| o.online && o.bounds.contains_point(p))
            };
            if !inside(&self.layout, self.pointer) {
                self.pointer = Point::new(
                    self.pointer.x.clamp(desk.x, desk.x + desk.w as i32 - 1),
                    self.pointer.y.clamp(desk.y, desk.y + desk.h as i32 - 1),
                );
            }
            if !inside(&self.layout, self.pointer)
                && let Some(p) = self.layout.primary()
            {
                self.pointer = Point::new(p.bounds.x + p.bounds.w as i32 / 2, p.bounds.y + p.bounds.h as i32 / 2);
            }
        }
        let ids: [Option<u32>; MAX_WINDOWS] = core::array::from_fn(|i| self.windows[i].as_ref().map(|w| w.id));
        let chrome = self.chrome;
        let min_w = chrome.min_client_w + chrome.border_w * 2;
        let min_h = chrome.min_client_h + chrome.title_h + chrome.border_w;
        for id in ids.into_iter().flatten() {
            let center = self.window(id).map(|w| Point::new(w.frame.x + w.frame.w as i32 / 2, w.frame.y + w.frame.h as i32 / 2));
            let Some(out) = center.and_then(|c| self.layout.output_at(c)).or_else(|| self.layout.primary()) else { continue };
            let work = self.layout.work_area(out, self.dock_cfg);
            if work.w == 0 || work.h == 0 {
                continue;
            }
            if let Some(w) = self.window_mut(id) {
                if w.snap != SnapState::Floating {
                    w.frame = w.snap.target_rect(work);
                } else {
                    let nw = w.frame.w.min(work.w).max(min_w.min(work.w));
                    let nh = w.frame.h.min(work.h).max(min_h.min(work.h));
                    let max_x = work.x + work.w.saturating_sub(nw) as i32;
                    let max_y = work.y + work.h.saturating_sub(nh) as i32;
                    w.frame = Rect::new(w.frame.x.clamp(work.x, max_x), w.frame.y.clamp(work.y, max_y), nw, nh);
                    w.saved_floating = w.frame;
                }
            }
        }
        self.sync_cursor_kind();
        self.damage_all();
    }

    pub fn engage_lock(&mut self, mode: LockMode, reason: LockReason) {
        self.launcher.hide();
        self.perm_prompt.close();
        self.drag = DragOp::None;
        self.super_tap = false;
        self.lock.engage(mode, reason);
        self.cursor_kind = self.compute_cursor_kind();
        self.damage_all();
    }

    pub fn disengage_lock(&mut self) {
        self.lock.unlock();
        self.cursor_kind = self.compute_cursor_kind();
        self.damage_all();
    }

    pub fn open_perm_prompt(&mut self, request_id: u32, app_name: &[u8], app_title: &[u8], perm_mask: u32) {
        self.launcher.hide();
        self.drag = DragOp::None;
        self.perm_prompt.open(request_id, app_name, app_title, perm_mask);
        self.sync_cursor_kind();
        self.damage_launcher_output();
    }

    fn activate_launch_target(&self, target: LaunchTarget) -> WmAction {
        match target {
            LaunchTarget::App { owner, app } => WmAction::Launch { owner, app },
            LaunchTarget::File { index } => match self.launcher.fs_entry(index) {
                Some(e) => WmAction::OpenPath { path: e.path, len: e.path_len, is_dir: e.is_dir },
                None => WmAction::None,
            },
            LaunchTarget::Setting(s) => WmAction::Setting(s),
            LaunchTarget::Power(p) => WmAction::Power(p),
        }
    }

    pub fn toggle_launcher(&mut self) {
        if self.lock.active || self.perm_prompt.active {
            return;
        }
        if self.launcher.open {
            self.launcher.hide();
        } else {
            self.launcher.show(self.now_ns);
            self.drag = DragOp::None;
        }
        self.sync_cursor_kind();
        self.damage_launcher_output();
    }

    /// Determine the context-aware minimal cursor shape for the current pointer position and state.
    pub fn compute_cursor_kind(&self) -> CursorKind {
        let p = self.pointer;
        if self.lock.active {
            if let Some(prim) = self.layout.primary()
                && prim.bounds.contains_point(p)
            {
                let local = Point::new(p.x - prim.bounds.x, p.y - prim.bounds.y);
                return self.lock.cursor_at(local, prim.bounds.w, prim.bounds.h, self.line_h);
            }
            return CursorKind::Default;
        }
        if self.perm_prompt.active {
            if let Some(prim) = self.layout.primary()
                && prim.bounds.contains_point(p)
            {
                let local = Point::new(p.x - prim.bounds.x, p.y - prim.bounds.y);
                return self.perm_prompt.cursor_at(local, prim.bounds.w, prim.bounds.h, self.line_h);
            }
            return CursorKind::Default;
        }
        if self.launcher.open {
            if let Some(prim) = self.layout.primary()
                && prim.bounds.contains_point(p)
            {
                let local = Point::new(p.x - prim.bounds.x, p.y - prim.bounds.y);
                let rects = self.launcher.rects(prim.bounds.w, prim.bounds.h, self.line_h);
                if rects.field.contains_point(local) {
                    return CursorKind::Text;
                }
                if rects.rows[..rects.n].iter().any(|r| r.contains_point(local))
                    || self.launcher.hit_power(&rects, local).is_some()
                {
                    return CursorKind::Pointer;
                }
            }
            return CursorKind::Default;
        }
        match self.drag {
            DragOp::Move { .. } => return CursorKind::Move,
            DragOp::Resize { edge, .. } => return edge.cursor_kind(),
            DragOp::None => {}
        }
        if let Some(prim) = self.layout.primary()
            && prim.bounds.contains_point(p)
        {
            let local = Point::new(p.x - prim.bounds.x, p.y - prim.bounds.y);
            let dl = self.dock_layout_for(prim);
            if matches!(dl.hit_test(local), DockHit::Pinned(..) | DockHit::Window(_) | DockHit::Workspace(_)) {
                return CursorKind::Pointer;
            }
        }
        if let Some(wid) = self.window_at(p)
            && let Some(w) = self.window(wid)
        {
            return match w.hit_test(p, self.chrome) {
                WinHit::Resize(edge) => edge.cursor_kind(),
                WinHit::BtnClose | WinHit::BtnMinimize | WinHit::BtnMaximize => CursorKind::Pointer,
                WinHit::TitleBar | WinHit::Client | WinHit::None => CursorKind::Default,
            };
        }
        CursorKind::Default
    }

    /// Recompute `self.cursor_kind`, damaging both old and new software cursor rects if it changed.
    pub fn sync_cursor_kind(&mut self) {
        let next = self.compute_cursor_kind();
        if next != self.cursor_kind {
            if self.layout.output_at(self.pointer).is_some_and(|o| !o.hw_cursor) {
                self.damage.add(self.cursor_kind.bounds_at(self.pointer));
                self.damage.add(next.bounds_at(self.pointer));
            }
            self.cursor_kind = next;
        }
    }

    fn damage_launcher_output(&mut self) {
        if let Some(p) = self.layout.primary() {
            self.damage.add(p.bounds);
        }
    }

    /// An animation is running (the compositor keeps drawing frames).
    pub fn animating(&self) -> bool {
        if self.settings.reduce_motion {
            return false;
        }
        let since = |t: u64| self.now_ns.saturating_sub(t) < OPEN_NS;
        (self.launcher.open && since(self.launcher.opened_at))
            || (matches!(self.drag, DragOp::Move { snap_preview: Some(_), .. }) && since(self.snap_since))
    }

    /// Damage what animates this frame.
    pub fn tick(&mut self) {
        if !self.animating() {
            return;
        }
        if self.launcher.open {
            // Only the sliding panel changes while it opens (the dim is drawn once).
            if let Some(p) = self.layout.primary() {
                let r = self.launcher.rects(p.bounds.w, p.bounds.h, self.line_h).panel;
                self.damage.add(Rect::new(p.bounds.x + r.x, p.bounds.y + r.y, r.w, r.h + 16));
            }
        } else if let DragOp::Move { snap_preview: Some(s), .. } = self.drag
            && let Some(out) = self.layout.output_at(self.pointer)
        {
            let work = self.layout.work_area(out, self.dock_cfg);
            self.damage.add(s.target_rect(work));
        }
    }

    /// 0-255 progress of an animation that started at `since`.
    fn progress(&self, since: u64) -> u32 {
        if self.settings.reduce_motion {
            return 255;
        }
        (self.now_ns.saturating_sub(since).min(OPEN_NS) * 255 / OPEN_NS) as u32
    }

    /// Register program `owner`'s launcher entry.
    pub fn register_app(&mut self, owner: u32, app: u8, label: &[u8], identity: &[u8], trust: TrustTier) -> bool {
        self.register_app_ex(owner, app, label, identity, trust, false)
    }

    /// Register program `owner`'s launcher entry, optionally pinned to the floating dock.
    pub fn register_app_ex(
        &mut self,
        owner: u32,
        app: u8,
        label: &[u8],
        identity: &[u8],
        trust: TrustTier,
        pinned: bool,
    ) -> bool {
        let ok = self.launcher.register_ex(owner, app, label, identity, trust, pinned);
        if ok {
            if self.launcher.open {
                self.damage_launcher_output();
            }
            self.damage_dock();
        }
        ok
    }

    /// Pin or unpin an existing registered app on the floating dock.
    pub fn set_app_pinned(&mut self, owner: u32, app: u8, pinned: bool) -> bool {
        let changed = self.launcher.set_pinned(owner, app, pinned);
        if changed {
            self.damage_dock();
            if self.launcher.open {
                self.damage_launcher_output();
            }
        }
        changed
    }

    pub fn damage_all(&mut self) {
        let bb = self.layout.desktop_bounds();
        self.damage.add(bb);
    }

    pub fn damage_dock(&mut self) {
        if let Some(p) = self.layout.primary() {
            let dl = self.dock_layout_for(p);
            self.damage.add(dl.bar.translate(p.bounds.x, p.bounds.y));
        }
    }

    pub fn window_count(&self) -> usize {
        self.windows.iter().filter(|w| w.is_some()).count()
    }

    /// Every window (any workspace, minimized or not), in slot order.
    pub fn windows(&self) -> impl Iterator<Item = &Window> {
        self.windows.iter().flatten()
    }

    /// Windows owned by client `owner`.
    pub fn owner_window_count(&self, owner: u32) -> usize {
        self.windows().filter(|w| w.owner == owner).count()
    }

    pub fn window(&self, id: u32) -> Option<&Window> {
        self.windows.iter().flatten().find(|w| w.id == id)
    }

    pub(crate) fn window_mut(&mut self, id: u32) -> Option<&mut Window> {
        self.windows.iter_mut().flatten().find(|w| w.id == id)
    }

    /// Strict ownership check: only the owning client may modify or destroy `window_id`.
    pub fn is_owner(&self, owner: u32, window_id: u32) -> bool {
        self.window(window_id).is_some_and(|w| w.owner == owner)
    }

    /// Create a new floating window owned exclusively by `owner` with `init`-verified `identity`/`trust`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_window(
        &mut self,
        owner: u32,
        identity: &[u8],
        trust: TrustTier,
        client_w: u32,
        client_h: u32,
        flags: u32,
        title: &[u8],
    ) -> Option<u32> {
        let slot = self.windows.iter().position(Option::is_none)?;
        let id = self.next_win_id;
        self.next_win_id = self.next_win_id.wrapping_add(1).max(1);
        let z = self.next_z;
        self.next_z = self.next_z.wrapping_add(1);

        let prim = self.layout.primary().unwrap_or(Output {
            adapter_id: 0,
            bounds: Rect::new(0, 0, 1024, 768),
            refresh_mhz: 60_000,
            scale: 100,
            hw_cursor: false,
            primary: true,
            online: true,
        });
        let work = self.layout.work_area(prim, self.dock_cfg);
        let (fw, fh) = Window::frame_size_for_client(client_w, client_h, flags, self.chrome);
        let fw = fw.min(work.w.max(self.chrome.min_client_w));
        let fh = fh.min(work.h.max(self.chrome.min_client_h));

        let step = (self.cascade_step % 6) * 28;
        self.cascade_step = self.cascade_step.wrapping_add(1);
        let max_x = work.x + work.w.saturating_sub(fw) as i32;
        let max_y = work.y + work.h.saturating_sub(fh) as i32;
        let fx = (work.x + 48 + step).clamp(work.x, max_x.max(work.x));
        let fy = (work.y + 36 + step).clamp(work.y, max_y.max(work.y));
        let frame = Rect::new(fx, fy, fw, fh);

        let mut id_buf = [0u8; MAX_IDENTITY_BYTES];
        let id_len = sanitize_label(identity, &mut id_buf) as u8;
        let mut title_buf = [0u8; MAX_TITLE_BYTES];
        let title_len = sanitize_label(title, &mut title_buf) as u8;

        self.windows[slot] = Some(Window {
            id,
            owner,
            identity: id_buf,
            identity_len: id_len,
            trust,
            title: title_buf,
            title_len,
            workspace: self.active_workspace,
            flags,
            frame,
            saved_floating: frame,
            snap: SnapState::Floating,
            minimized: false,
            mapped: true,
            z_order: z,
        });
        self.focused = Some(id);
        self.damage.add(frame);
        self.damage_dock();
        Some(id)
    }

    /// Update only the app-supplied title (never alters verified `identity` or `trust`).
    pub fn set_title(&mut self, owner: u32, window_id: u32, title: &[u8]) -> bool {
        let chrome = self.chrome;
        let Some(w) = self.window_mut(window_id) else {
            return false;
        };
        if w.owner != owner {
            return false;
        }
        w.title.fill(0);
        w.title_len = sanitize_label(title, &mut w.title) as u8;
        let title_bar = Rect::new(w.frame.x, w.frame.y, w.frame.w, chrome.title_h);
        self.damage.add(title_bar);
        self.damage_dock();
        true
    }

    /// Record client surface damage (clipped strictly to the window's own client rect!).
    pub fn commit_damage(&mut self, owner: u32, window_id: u32, local_rects: &[Rect]) -> bool {
        let chrome = self.chrome;
        let active_ws = self.active_workspace;
        let Some(w) = self.window(window_id) else {
            return false;
        };
        if w.owner != owner {
            return false;
        }
        if self.lock.active || w.minimized || w.workspace != active_ws {
            return true;
        }
        let client = w.client_rect(chrome);
        if local_rects.is_empty() {
            self.damage.add(client);
        } else {
            for &r in local_rects {
                let global = r.translate(client.x, client.y);
                self.damage.add_clipped(global, client);
            }
        }
        true
    }

    /// Destroy a window owned by `owner`.
    pub fn destroy_window(&mut self, owner: u32, window_id: u32) -> bool {
        let Some(pos) = self.windows.iter().position(|slot| slot.as_ref().is_some_and(|w| w.id == window_id && w.owner == owner)) else {
            return false;
        };
        if let Some(w) = self.windows[pos].take() {
            self.damage.add(w.frame);
        }
        if self.focused == Some(window_id) {
            self.focused = self.top_visible_window();
        }
        if self.hovered == Some(window_id) {
            self.hovered = None;
        }
        if matches!(self.drag, DragOp::Move { window_id: wid, .. } | DragOp::Resize { window_id: wid, .. } if wid == window_id) {
            self.drag = DragOp::None;
        }
        self.damage_dock();
        true
    }

    /// Destroy all windows belonging to a disconnected client.
    pub fn remove_client(&mut self, owner: u32) {
        let removed_pinned = self.launcher.remove_owner(owner);
        let mut removed = false;
        for slot in &mut self.windows {
            if slot.as_ref().is_some_and(|w| w.owner == owner)
                && let Some(w) = slot.take()
            {
                self.damage.add(w.frame);
                if self.focused == Some(w.id) {
                    self.focused = None;
                }
                if self.hovered == Some(w.id) {
                    self.hovered = None;
                }
                if matches!(self.drag, DragOp::Move { window_id: wid, .. } | DragOp::Resize { window_id: wid, .. } if wid == w.id) {
                    self.drag = DragOp::None;
                }
                removed = true;
            }
        }
        if removed {
            if self.focused.is_none() {
                self.focused = self.top_visible_window();
            }
            self.damage_dock();
        } else if removed_pinned {
            self.damage_dock();
        }
    }

    /// Raise and focus a window (restoring it if minimized, switching to its workspace).
    pub fn focus_window(&mut self, window_id: u32) -> Option<(u32, u32)> {
        let old_focused = self.focused;
        let z = self.next_z;
        self.next_z = self.next_z.wrapping_add(1);
        let (owner, frame, ws) = {
            let w = self.window_mut(window_id)?;
            w.minimized = false;
            w.z_order = z;
            (w.owner, w.frame, w.workspace)
        };
        if ws != self.active_workspace {
            self.switch_workspace(ws);
        }
        if let Some(old_id) = old_focused
            && old_id != window_id
            && let Some(ow) = self.window(old_id)
        {
            self.damage.add(ow.frame);
        }
        self.focused = Some(window_id);
        self.damage.add(frame);
        self.damage_dock();
        Some((owner, window_id))
    }

    pub fn minimize_window(&mut self, window_id: u32) -> Option<(u32, u32)> {
        let (owner, frame) = {
            let w = self.window_mut(window_id)?;
            w.minimized = true;
            (w.owner, w.frame)
        };
        self.damage.add(frame);
        if self.focused == Some(window_id) {
            self.focused = self.top_visible_window();
        }
        self.damage_dock();
        Some((owner, window_id))
    }

    /// Apply a snap/tiling state (or toggle back to floating if already in that state).
    pub fn snap_window(&mut self, window_id: u32, snap: SnapState) -> Option<(u32, u32)> {
        let output = {
            let w = self.window(window_id)?;
            let center = Point::new(w.frame.x + (w.frame.w as i32) / 2, w.frame.y + (w.frame.h as i32) / 2);
            self.layout.output_at(center)?
        };
        let work = self.layout.work_area(output, self.dock_cfg);
        let w = self.window_mut(window_id)?;
        let old_frame = w.frame;
        if snap == SnapState::Floating || w.snap == snap {
            w.snap = SnapState::Floating;
            w.frame = w.saved_floating;
        } else {
            if w.snap == SnapState::Floating {
                w.saved_floating = w.frame;
            }
            w.snap = snap;
            w.frame = snap.target_rect(work);
        }
        let owner = w.owner;
        let new_frame = w.frame;
        self.damage.add(old_frame);
        self.damage.add(new_frame);
        Some((owner, window_id))
    }

    pub fn switch_workspace(&mut self, ws: u8) {
        if ws >= WORKSPACE_COUNT || ws == self.active_workspace {
            return;
        }
        self.active_workspace = ws;
        self.tray.active_workspace = ws;
        self.drag = DragOp::None;
        self.focused = self.top_visible_window();
        self.damage_all();
    }

    pub fn move_window_to_workspace(&mut self, window_id: u32, ws: u8) -> bool {
        if ws >= WORKSPACE_COUNT {
            return false;
        }
        let Some(w) = self.window_mut(window_id) else {
            return false;
        };
        let old = w.frame;
        w.workspace = ws;
        self.damage.add(old);
        if ws != self.active_workspace && self.focused == Some(window_id) {
            self.focused = self.top_visible_window();
        }
        self.damage_dock();
        true
    }

    /// Cycle focus through visible windows on the active workspace (`Alt+Tab`).
    pub fn cycle_focus(&mut self) -> Option<(u32, u32)> {
        let mut ids = [0u32; MAX_WINDOWS];
        let mut n = 0usize;
        for w in self.windows.iter().flatten() {
            if w.workspace == self.active_workspace && !w.minimized {
                ids[n] = w.id;
                n += 1;
            }
        }
        if n == 0 {
            return None;
        }
        // Sort by z_order descending.
        for i in 0..n {
            for j in (i + 1)..n {
                let zi = self.window(ids[i]).map_or(0, |w| w.z_order);
                let zj = self.window(ids[j]).map_or(0, |w| w.z_order);
                if zj > zi {
                    ids.swap(i, j);
                }
            }
        }
        let next = if n >= 2 && self.focused == Some(ids[0]) { ids[1] } else { ids[0] };
        self.focus_window(next)
    }

    pub fn top_visible_window(&self) -> Option<u32> {
        self.windows
            .iter()
            .flatten()
            .filter(|w| w.workspace == self.active_workspace && !w.minimized)
            .max_by_key(|w| w.z_order)
            .map(|w| w.id)
    }

    /// Find topmost visible window containing desktop point `p`.
    pub fn window_at(&self, p: Point) -> Option<u32> {
        self.windows
            .iter()
            .flatten()
            .filter(|w| w.workspace == self.active_workspace && !w.minimized && w.frame.contains_point(p))
            .max_by_key(|w| w.z_order)
            .map(|w| w.id)
    }

    /// Handle a keyboard event (`key_val` from `libd::proto::key`, `pressed`).
    /// Intercepts WM shortcuts (`Super+*`, `Alt+Tab`, `Ctrl+Alt+Esc`) and routes all other keys
    /// strictly to the currently focused window (or drops them if no window is focused).
    pub fn handle_key(&mut self, key_val: u32, pressed: bool) -> WmAction {
        const SHIFT: u32 = 1 << 16;
        const CTRL: u32 = 1 << 17;
        const ALT: u32 = 1 << 18;
        const SUPER: u32 = 1 << 19;
        const UP: u32 = 0x101;
        const DOWN: u32 = 0x102;
        const LEFT: u32 = 0x103;
        const RIGHT: u32 = 0x104;

        let base = key_val & 0xFFFF;
        let has_super = (key_val & SUPER) != 0;
        let has_alt = (key_val & ALT) != 0;
        let has_ctrl = (key_val & CTRL) != 0;
        let has_shift = (key_val & SHIFT) != 0;

        // 1. Lock / login screen has absolute priority: blocks Super, launcher, clients, and ExitSession!
        if self.lock.active {
            self.super_tap = false;
            return match self.lock.key(key_val, pressed) {
                LockOutcome::None => WmAction::None,
                LockOutcome::Changed => {
                    self.damage_launcher_output();
                    WmAction::None
                }
                LockOutcome::Submit { identity_id } => {
                    self.damage_launcher_output();
                    WmAction::UnlockAttempt { identity_id }
                }
            };
        }

        // 2. Unforgeable compositor permission prompt modal: blocks client key delivery.
        if self.perm_prompt.active {
            self.super_tap = false;
            if pressed && base == 0x1B && (has_super || (has_ctrl && has_alt)) {
                self.perm_prompt.close();
                self.damage_launcher_output();
                return WmAction::ExitSession;
            }
            return match self.perm_prompt.key(base, pressed) {
                PermOutcome::None => WmAction::None,
                PermOutcome::Changed => {
                    self.damage_launcher_output();
                    WmAction::None
                }
                PermOutcome::Decided { request_id, choice } => {
                    self.damage_launcher_output();
                    WmAction::PermPromptResult { request_id, choice }
                }
            };
        }

        // Super alone: a tap (down and up with nothing between) opens or closes the launcher.
        // It is the window manager's key: programs never see it.
        if base == KEY_META {
            if pressed {
                self.super_tap = true;
            } else if core::mem::take(&mut self.super_tap) {
                self.toggle_launcher();
            }
            return WmAction::None;
        }
        if pressed {
            self.super_tap = false;
        }
        if pressed && base == KEY_F1 && has_alt && !has_ctrl {
            self.toggle_launcher();
            return WmAction::None;
        }
        if self.launcher.open {
            if !pressed {
                return WmAction::None;
            }
            if base == 0x1B && (has_super || (has_ctrl && has_alt)) {
                self.launcher.hide();
                return WmAction::ExitSession;
            }
            let outcome = self.launcher.key(base);
            self.damage_launcher_output();
            return match outcome {
                Outcome::Changed => WmAction::None,
                Outcome::Close => {
                    self.launcher.hide();
                    WmAction::None
                }
                Outcome::Activate(t) => {
                    let act = self.activate_launch_target(t);
                    self.launcher.hide();
                    act
                }
            };
        }

        if pressed {
            // Exit GUI session back to shell: Super+Esc or Ctrl+Alt+Esc.
            if base == 0x1B && (has_super || (has_ctrl && has_alt)) {
                return WmAction::ExitSession;
            }
            // Lock session: Super+L or Ctrl+Alt+L.
            if (base == u32::from(b'l') || base == u32::from(b'L')) && (has_super || (has_ctrl && has_alt)) {
                return WmAction::LockSession;
            }
            // Alt+Tab window switcher.
            if has_alt && !has_ctrl && !has_super && base == u32::from(b'\t') {
                if let Some((owner, wid)) = self.cycle_focus() {
                    return WmAction::Configure { owner, window_id: wid };
                }
                return WmAction::None;
            }
            if has_super {
                // Workspaces: Super+1..4 switch, Super+Shift+1..4 move focused window.
                if (u32::from(b'1')..=u32::from(b'4')).contains(&base) {
                    let ws = (base - u32::from(b'1')) as u8;
                    if has_shift {
                        if let Some(wid) = self.focused {
                            self.move_window_to_workspace(wid, ws);
                        }
                    } else {
                        self.switch_workspace(ws);
                    }
                    return WmAction::None;
                }
                // Close focused window: Super+Q.
                if base == u32::from(b'q') || base == u32::from(b'Q') {
                    if let Some(wid) = self.focused
                        && let Some(w) = self.window(wid)
                    {
                        return WmAction::RequestClose { owner: w.owner, window_id: wid };
                    }
                    return WmAction::None;
                }
                // Hybrid snapping / tiling shortcuts: Super+Arrows (halves/max/restore) & Super+Shift+Arrows (quarters).
                if let Some(wid) = self.focused {
                    let snap = match (base, has_shift) {
                        (LEFT, false) => Some(SnapState::LeftHalf),
                        (RIGHT, false) => Some(SnapState::RightHalf),
                        (UP, false) => Some(SnapState::Maximized),
                        (DOWN, false) => Some(SnapState::Floating),
                        (LEFT, true) => Some(SnapState::TopLeft),
                        (RIGHT, true) => Some(SnapState::TopRight),
                        (UP, true) => Some(SnapState::BottomLeft),
                        (DOWN, true) => Some(SnapState::BottomRight),
                        _ => None,
                    };
                    if let Some(s) = snap {
                        if let Some((owner, wid)) = self.snap_window(wid, s) {
                            return WmAction::Configure { owner, window_id: wid };
                        }
                        return WmAction::None;
                    }
                }
                return WmAction::None;
            }
        }

        // Strict focus isolation: deliver key ONLY to the focused window on the active workspace.
        if let Some(wid) = self.focused
            && let Some(w) = self.window(wid)
            && w.workspace == self.active_workspace
            && !w.minimized
        {
            return WmAction::DeliverKey { owner: w.owner, window_id: wid };
        }
        WmAction::None
    }

    /// Handle pointer movement/buttons/wheel (either relative `(dx, dy)` or absolute `abs`).
    pub fn handle_pointer(&mut self, dx: i32, dy: i32, abs: Option<Point>, buttons: u8) -> WmAction {
        let old_ptr = self.pointer;
        let old_kind = self.cursor_kind;
        let next = match abs {
            Some(p) => self.layout.clamp_point(p),
            None => self.layout.clamp_point(Point::new(old_ptr.x.saturating_add(dx), old_ptr.y.saturating_add(dy))),
        };
        let moved = next != old_ptr;
        if moved {
            // Damage old software-cursor rect on outputs lacking hardware cursor.
            if self.layout.output_at(old_ptr).is_some_and(|o| !o.hw_cursor) {
                self.damage.add(old_kind.bounds_at(old_ptr));
            }
            self.pointer = next;
        }
        let action = self.handle_pointer_inner(next, buttons);
        self.sync_cursor_kind();
        if moved && self.layout.output_at(next).is_some_and(|o| !o.hw_cursor) {
            self.damage.add(self.cursor_kind.bounds_at(next));
        }
        action
    }

    fn handle_pointer_inner(&mut self, next: Point, buttons: u8) -> WmAction {
        let prev_buttons = self.buttons;
        self.buttons = buttons;
        let left_pressed = (buttons & 1) != 0 && (prev_buttons & 1) == 0;
        let left_released = (buttons & 1) == 0 && (prev_buttons & 1) != 0;
        let right_pressed = (buttons & 2) != 0 && (prev_buttons & 2) == 0;

        // 1. Lock screen: traps all pointer input; zero delivery to dock or clients.
        if self.lock.active {
            if let Some(prim) = self.layout.primary()
                && prim.bounds.contains_point(next)
            {
                let local = Point::new(next.x - prim.bounds.x, next.y - prim.bounds.y);
                match self.lock.pointer(local, left_pressed, prim.bounds.w, prim.bounds.h, self.line_h) {
                    LockOutcome::None => {}
                    LockOutcome::Changed => self.damage_launcher_output(),
                    LockOutcome::Submit { identity_id } => {
                        self.damage_launcher_output();
                        return WmAction::UnlockAttempt { identity_id };
                    }
                }
            }
            return WmAction::None;
        }

        // 2. Permission prompt modal: traps pointer input until answered.
        if self.perm_prompt.active {
            if let Some(prim) = self.layout.primary()
                && prim.bounds.contains_point(next)
            {
                let local = Point::new(next.x - prim.bounds.x, next.y - prim.bounds.y);
                match self.perm_prompt.pointer(local, left_pressed, prim.bounds.w, prim.bounds.h, self.line_h) {
                    PermOutcome::None => {}
                    PermOutcome::Changed => self.damage_launcher_output(),
                    PermOutcome::Decided { request_id, choice } => {
                        self.damage_launcher_output();
                        return WmAction::PermPromptResult { request_id, choice };
                    }
                }
            }
            return WmAction::None;
        }

        // The open launcher is modal: the pointer selects and opens its rows, a click elsewhere
        // closes it, and nothing reaches the windows meanwhile.
        if self.launcher.open {
            let Some(prim) = self.layout.primary() else { return WmAction::None };
            let local = Point::new(next.x - prim.bounds.x, next.y - prim.bounds.y);
            let rects = self.launcher.rects(prim.bounds.w, prim.bounds.h, self.line_h);
            let phit = self.launcher.hit_power(&rects, local);
            if self.launcher.power_hover != phit {
                self.launcher.power_hover = phit;
                self.damage.add(rects.panel.translate(prim.bounds.x, prim.bounds.y));
            }
            if let Some(ph) = phit {
                if left_pressed {
                    match ph {
                        PowerHit::Toggle => {
                            self.launcher.power_open = !self.launcher.power_open;
                            self.damage.add(rects.panel.translate(prim.bounds.x, prim.bounds.y));
                        }
                        PowerHit::Action(act) => {
                            self.launcher.hide();
                            self.damage.add(prim.bounds);
                            return WmAction::Power(act);
                        }
                    }
                }
                return WmAction::None;
            }
            let (inside, hit) = self.launcher.hit(&rects, local);
            if let Some((idx, target)) = hit {
                if self.launcher.sel != idx {
                    self.launcher.sel = idx;
                    self.damage.add(rects.panel.translate(prim.bounds.x, prim.bounds.y));
                }
                if left_pressed {
                    let act = self.activate_launch_target(target);
                    self.launcher.hide();
                    self.damage.add(prim.bounds);
                    return act;
                } else if right_pressed
                    && let LaunchTarget::App { owner, app } = target
                    && let Some(pinned) = self.launcher.toggle_pinned(owner, app)
                {
                    self.damage_dock();
                    self.damage_launcher_output();
                    return WmAction::SetAppPinned { owner, app, pinned };
                }
            } else if left_pressed && !inside {
                self.launcher.hide();
                self.damage.add(prim.bounds);
            }
            return WmAction::None;
        }

        // Active drag completion on button release.
        if left_released {
            match self.drag {
                DragOp::Move { window_id, snap_preview, .. } => {
                    self.drag = DragOp::None;
                    self.damage_all();
                    if let Some(s) = snap_preview
                        && let Some((owner, wid)) = self.snap_window(window_id, s)
                    {
                        return WmAction::Configure { owner, window_id: wid };
                    }
                    return WmAction::None;
                }
                DragOp::Resize { window_id, .. } => {
                    self.drag = DragOp::None;
                    if let Some(w) = self.window(window_id) {
                        return WmAction::Configure { owner: w.owner, window_id };
                    }
                    return WmAction::None;
                }
                DragOp::None => {}
            }
        }

        // Active drag motion.
        if (buttons & 1) != 0 {
            match self.drag {
                DragOp::Move { window_id, grab_dx, grab_dy, snap_preview: old_snap } => {
                    let preview = self.detect_edge_snap(next);
                    if let Some(w) = self.window_mut(window_id) {
                        let old = w.frame;
                        if w.snap != SnapState::Floating {
                            w.snap = SnapState::Floating;
                            w.frame.w = w.saved_floating.w;
                            w.frame.h = w.saved_floating.h;
                        }
                        w.frame.x = next.x.saturating_sub(grab_dx);
                        w.frame.y = next.y.saturating_sub(grab_dy);
                        w.saved_floating = w.frame;
                        let new = w.frame;
                        self.damage.add(old);
                        self.damage.add(new);
                    }
                    if preview != old_snap {
                        self.damage_all();
                        self.snap_since = self.now_ns;
                        self.drag = DragOp::Move { window_id, grab_dx, grab_dy, snap_preview: preview };
                    }
                    return WmAction::None;
                }
                DragOp::Resize { window_id, edge, start_ptr, start_frame } => {
                    let chrome = self.chrome;
                    if let Some(w) = self.window_mut(window_id) {
                        let old = w.frame;
                        let ddx = next.x - start_ptr.x;
                        let ddy = next.y - start_ptr.y;
                        let min_w = chrome.min_client_w + chrome.border_w * 2;
                        let min_h = chrome.min_client_h + chrome.title_h + chrome.border_w;
                        let mut nf = start_frame;
                        if edge.right {
                            nf.w = (i64::from(start_frame.w) + i64::from(ddx)).max(i64::from(min_w)) as u32;
                        }
                        if edge.bottom {
                            nf.h = (i64::from(start_frame.h) + i64::from(ddy)).max(i64::from(min_h)) as u32;
                        }
                        if edge.left {
                            let new_w = (i64::from(start_frame.w) - i64::from(ddx)).max(i64::from(min_w)) as u32;
                            nf.x = start_frame.x + (start_frame.w as i32 - new_w as i32);
                            nf.w = new_w;
                        }
                        if edge.top {
                            let new_h = (i64::from(start_frame.h) - i64::from(ddy)).max(i64::from(min_h)) as u32;
                            nf.y = start_frame.y + (start_frame.h as i32 - new_h as i32);
                            nf.h = new_h;
                        }
                        w.snap = SnapState::Floating;
                        w.frame = nf;
                        w.saved_floating = nf;
                        self.damage.add(old);
                        self.damage.add(nf);
                    }
                    return WmAction::None;
                }
                DragOp::None => {}
            }
        }

        // Check dock hit on primary output first.
        if let Some(prim) = self.layout.primary()
            && prim.bounds.contains_point(next)
        {
            let local = Point::new(next.x - prim.bounds.x, next.y - prim.bounds.y);
            let dl = self.dock_layout_for(prim);
            let dhit = dl.hit_test(local);
            if dhit != DockHit::None {
                self.hovered = None;
                if right_pressed
                    && let DockHit::Pinned(owner, app) = dhit
                    && self.set_app_pinned(owner, app, false)
                {
                    return WmAction::SetAppPinned { owner, app, pinned: false };
                }
                if left_pressed {
                    match dhit {
                        DockHit::Pinned(owner, app) => {
                            // Focus/restore an existing window of this pinned app if open; otherwise launch it.
                            let existing = self
                                .windows
                                .iter()
                                .flatten()
                                .filter(|w| w.owner == owner && w.workspace == self.active_workspace)
                                .max_by_key(|w| w.z_order)
                                .or_else(|| {
                                    self.windows
                                        .iter()
                                        .flatten()
                                        .filter(|w| w.owner == owner)
                                        .max_by_key(|w| w.z_order)
                                })
                                .map(|w| w.id);
                            if let Some(wid) = existing {
                                if let Some((ow, id)) = self.focus_window(wid) {
                                    return WmAction::Configure { owner: ow, window_id: id };
                                }
                            } else {
                                return WmAction::Launch { owner, app };
                            }
                        }
                        DockHit::Window(wid) => {
                            let is_focused_vis = self.focused == Some(wid)
                                && self.window(wid).is_some_and(|w| !w.minimized && w.workspace == self.active_workspace);
                            if is_focused_vis {
                                if let Some((owner, id)) = self.minimize_window(wid) {
                                    return WmAction::Configure { owner, window_id: id };
                                }
                            } else if let Some((owner, id)) = self.focus_window(wid) {
                                return WmAction::Configure { owner, window_id: id };
                            }
                        }
                        DockHit::Workspace(ws) => {
                            self.switch_workspace(ws);
                        }
                        _ => {}
                    }
                }
                return WmAction::None;
            }
        }

        // Window hit-testing (topmost Z-order).
        let Some(wid) = self.window_at(next) else {
            self.hovered = None;
            return WmAction::None;
        };
        self.hovered = Some(wid);
        let chrome = self.chrome;
        let (owner, hit, frame, client) = {
            let Some(w) = self.window(wid) else {
                return WmAction::None;
            };
            (w.owner, w.hit_test(next, chrome), w.frame, w.client_rect(chrome))
        };

        if left_pressed {
            self.focus_window(wid);
            match hit {
                WinHit::TitleBar => {
                    self.drag = DragOp::Move {
                        window_id: wid,
                        grab_dx: next.x - frame.x,
                        grab_dy: next.y - frame.y,
                        snap_preview: None,
                    };
                    return WmAction::Configure { owner, window_id: wid };
                }
                WinHit::Resize(edge) => {
                    self.drag = DragOp::Resize {
                        window_id: wid,
                        edge,
                        start_ptr: next,
                        start_frame: frame,
                    };
                    return WmAction::Configure { owner, window_id: wid };
                }
                WinHit::BtnClose => return WmAction::RequestClose { owner, window_id: wid },
                WinHit::BtnMinimize => {
                    self.minimize_window(wid);
                    return WmAction::Configure { owner, window_id: wid };
                }
                WinHit::BtnMaximize => {
                    self.snap_window(wid, SnapState::Maximized);
                    return WmAction::Configure { owner, window_id: wid };
                }
                WinHit::Client | WinHit::None => {
                    return WmAction::DeliverPointer {
                        owner,
                        window_id: wid,
                        local_x: next.x - client.x,
                        local_y: next.y - client.y,
                    };
                }
            }
        }

        if hit == WinHit::Client {
            return WmAction::DeliverPointer {
                owner,
                window_id: wid,
                local_x: next.x - client.x,
                local_y: next.y - client.y,
            };
        }
        WmAction::None
    }

    fn detect_edge_snap(&self, p: Point) -> Option<SnapState> {
        let out = self.layout.output_at(p)?;
        let work = self.layout.work_area(out, self.dock_cfg);
        let margin = 12i32;
        let corner = 48i32;
        let near_l = p.x <= work.x + margin;
        let near_r = i64::from(p.x) >= work.right() - i64::from(margin);
        let near_t = p.y <= work.y + margin;
        let near_b = i64::from(p.y) >= work.bottom() - i64::from(margin);
        if near_l && p.y <= work.y + corner {
            Some(SnapState::TopLeft)
        } else if near_l && i64::from(p.y) >= work.bottom() - i64::from(corner) {
            Some(SnapState::BottomLeft)
        } else if near_r && p.y <= work.y + corner {
            Some(SnapState::TopRight)
        } else if near_r && i64::from(p.y) >= work.bottom() - i64::from(corner) {
            Some(SnapState::BottomRight)
        } else if near_l {
            Some(SnapState::LeftHalf)
        } else if near_r {
            Some(SnapState::RightHalf)
        } else if near_t && !near_b {
            Some(SnapState::Maximized)
        } else {
            None
        }
    }

    /// The dock lists the windows of the active workspace only (each workspace has its own dock).
    fn dock_windows(&self) -> ([DockWindowEntry; MAX_DOCK_WINDOWS], usize) {
        let mut entries = [DockWindowEntry::default(); MAX_DOCK_WINDOWS];
        let mut n = 0usize;
        for w in self.windows.iter().flatten().filter(|w| w.workspace == self.active_workspace) {
            if n >= MAX_DOCK_WINDOWS {
                break;
            }
            let mut e = DockWindowEntry {
                window_id: w.id,
                workspace: w.workspace,
                focused: self.focused == Some(w.id),
                minimized: w.minimized,
                label: [0; 20],
                label_len: 0,
            };
            let src = if !w.title_bytes().is_empty() { w.title_bytes() } else { w.identity_bytes() };
            let len = src.len().min(e.label.len());
            e.label[..len].copy_from_slice(&src[..len]);
            e.label_len = len as u8;
            entries[n] = e;
            n += 1;
        }
        (entries, n)
    }

    fn dock_pinned(&self) -> ([DockPinnedEntry; MAX_DOCK_PINNED], usize) {
        let mut entries = [DockPinnedEntry::default(); MAX_DOCK_PINNED];
        let n = self.launcher.pinned_entries(&mut entries);
        for e in entries.iter_mut().take(n) {
            e.running = self.windows.iter().flatten().any(|w| w.owner == e.owner);
        }
        (entries, n)
    }

    pub(crate) fn dock_layout_for(&self, out: Output) -> DockLayout {
        let (pinned, pn) = self.dock_pinned();
        let (entries, n) = self.dock_windows();
        DockLayout::compute_with_pinned(out.bounds.w, out.bounds.h, self.dock_cfg, &pinned[..pn], &entries[..n], &self.tray, self.char_w)
    }

    /// Composite all dirty rectangles for `output` into `canvas`.
    /// `fetch_surface` supplies the read-only client buffer bytes for each `window_id`.
    /// Returns the output-local `DamageSet` that was rendered (ready for `gpu::present`).
    pub fn composite_output<'s, F>(&self, output: Output, canvas: &mut Canvas<'_>, text: &mut dyn TextRender, mut fetch_surface: F) -> DamageSet
    where
        F: FnMut(u32) -> Option<SurfaceView<'s>>,
    {
        let local_damage = self.damage.for_output(output.bounds);
        if local_damage.is_empty() {
            return local_damage;
        }

        // When locked, render ONLY the opaque compositor lock/login screen (zero client window pixels!).
        if self.lock.active {
            for &clip in local_damage.as_slice() {
                self.lock.render(canvas, clip, &self.theme, text, &self.tray, output.primary, self.line_h);
                if !output.hw_cursor && output.bounds.contains_point(self.pointer) {
                    canvas.draw_sw_cursor_kind(clip, self.pointer.x - output.bounds.x, self.pointer.y - output.bounds.y, self.cursor_kind);
                }
            }
            return local_damage;
        }

        // Collect visible windows on the active workspace, sorted bottom-to-top by z_order.
        let mut order = [0usize; MAX_WINDOWS];
        let mut count = 0usize;
        for (i, slot) in self.windows.iter().enumerate() {
            if let Some(w) = slot
                && w.workspace == self.active_workspace
                && !w.minimized
                && w.mapped
                && !w.frame.intersect(output.bounds).is_empty()
            {
                order[count] = i;
                count += 1;
            }
        }
        for i in 0..count {
            for j in (i + 1)..count {
                let zi = self.windows[order[i]].as_ref().map_or(0, |w| w.z_order);
                let zj = self.windows[order[j]].as_ref().map_or(0, |w| w.z_order);
                if zj < zi {
                    order.swap(i, j);
                }
            }
        }

        let (dock_pinned, dock_pn) = if output.primary {
            self.dock_pinned()
        } else {
            ([DockPinnedEntry::default(); MAX_DOCK_PINNED], 0)
        };
        let (dock_entries, dock_n) = if output.primary {
            self.dock_windows()
        } else {
            ([DockWindowEntry::default(); MAX_DOCK_WINDOWS], 0)
        };
        let dock_layout = output.primary.then(|| {
            DockLayout::compute_with_pinned(
                output.bounds.w,
                output.bounds.h,
                self.dock_cfg,
                &dock_pinned[..dock_pn],
                &dock_entries[..dock_n],
                &self.tray,
                self.char_w,
            )
        });
        let launcher = (output.primary && self.launcher.open).then(|| self.launcher.rects(output.bounds.w, output.bounds.h, self.line_h));

        let snap_preview_local = match self.drag {
            DragOp::Move { snap_preview: Some(s), .. } => {
                if output.bounds.contains_point(self.pointer) {
                    let work = self.layout.work_area(output, self.dock_cfg);
                    Some(s.target_rect(work).translate(-output.bounds.x, -output.bounds.y).inset(4))
                } else {
                    None
                }
            }
            _ => None,
        };

        for &clip in local_damage.as_slice() {
            // 1. Clean flat dark slate desktop backdrop (zero gradients).
            canvas.fill_rect(clip, clip, self.theme.desktop_bg);

            // 2. Visible windows in Z-order with crisp SSD chrome and unforgeable trust framing.
            for &slot_idx in &order[..count] {
                let Some(w) = &self.windows[slot_idx] else {
                    continue;
                };
                let frame_local = w.frame.translate(-output.bounds.x, -output.bounds.y);
                if frame_local.intersect(clip).is_empty() {
                    continue;
                }
                let focused = self.focused == Some(w.id);
                let client_local = w.client_rect(self.chrome).translate(-output.bounds.x, -output.bounds.y);

                if w.is_decorated() {
                    let title_bg = if focused { self.theme.title_active } else { self.theme.title_inactive };
                    let title_rect = Rect::new(frame_local.x, frame_local.y, frame_local.w, self.chrome.title_h);
                    canvas.fill_rect(clip, title_rect, title_bg);

                    // Subtle bottom hairline separating titlebar from client area.
                    canvas.fill_rect(
                        clip,
                        Rect::new(frame_local.x + 1, frame_local.y + self.chrome.title_h as i32 - 1, frame_local.w.saturating_sub(2), 1),
                        self.theme.border_inactive,
                    );

                    // Unforgeable trust dot (left of titlebar).
                    let trust_col = match w.trust {
                        TrustTier::System => self.theme.trust_system,
                        TrustTier::Native => self.theme.trust_native,
                        TrustTier::Sandbox => self.theme.trust_sandbox,
                    };
                    let dot_cy = title_rect.y + (title_rect.h as i32) / 2;
                    canvas.fill_circle(clip, title_rect.x + 12, dot_cy, 4, trust_col);

                    // Verified manifest identity (muted) + separator + app title.
                    let text_mid = title_rect.y + (title_rect.h / 2) as i32;
                    let btns_w = self.chrome.btn_w * 3 + 6;
                    let max_label_w = title_rect.w.saturating_sub(24 + btns_w);
                    let mut tx = title_rect.x + 22;
                    let mut rem = max_label_w;
                    let id_b = w.identity_bytes();
                    if !id_b.is_empty() && rem >= self.char_w {
                        let used = text.draw(canvas, clip, tx, text_mid, id_b, TextRole::Title, self.theme.text_muted, rem);
                        tx += used as i32;
                        rem = rem.saturating_sub(used);
                        if !w.title_bytes().is_empty() && rem >= self.char_w * 3 {
                            let sep = text.draw(canvas, clip, tx, text_mid, b" - ", TextRole::Title, self.theme.text_muted, rem);
                            tx += sep as i32;
                            rem = rem.saturating_sub(sep);
                        }
                    }
                    if !w.title_bytes().is_empty() && rem >= self.char_w {
                        let title_col = if focused { self.theme.text_primary } else { self.theme.text_muted };
                        text.draw(canvas, clip, tx, text_mid, w.title_bytes(), TextRole::Title, title_col, rem);
                    }

                    // Minimal window buttons: minimize, maximize/restore, close.
                    let right = title_rect.x + title_rect.w as i32;
                    let bw = self.chrome.btn_w;
                    let r_close = Rect::new(right - bw as i32, title_rect.y + 1, bw, title_rect.h.saturating_sub(2));
                    let r_max = Rect::new(right - (bw * 2) as i32, title_rect.y + 1, bw, title_rect.h.saturating_sub(2));
                    let r_min = Rect::new(right - (bw * 3) as i32, title_rect.y + 1, bw, title_rect.h.saturating_sub(2));
                    let icon_col = if focused { self.theme.text_primary } else { self.theme.text_muted };
                    canvas.draw_win_icon(clip, r_min, WinIcon::Minimize, icon_col);
                    canvas.draw_win_icon(
                        clip,
                        r_max,
                        if w.snap == SnapState::Maximized { WinIcon::Restore } else { WinIcon::Maximize },
                        icon_col,
                    );
                    canvas.draw_win_icon(clip, r_close, WinIcon::Close, icon_col);
                }

                // Client pixel area (fallback dark client bg + zero-panic clipped surface blit).
                canvas.fill_rect(clip, client_local, self.theme.client_bg);
                if let Some(surf) = fetch_surface(w.id) {
                    canvas.blit_client_bytes(
                        clip,
                        client_local,
                        surf.bytes,
                        surf.width,
                        surf.height,
                        surf.pitch_bytes,
                        w.is_opaque(),
                    );
                }

                // Crisp 1px window border (amber hairline tint for sandboxed/foreign apps).
                if w.is_decorated() {
                    let border_col = if w.trust == TrustTier::Sandbox {
                        self.theme.border_sandbox
                    } else if focused {
                        self.theme.border_active
                    } else {
                        self.theme.border_inactive
                    };
                    canvas.stroke_rect(clip, frame_local, border_col);
                }
            }

            // 3. Snap-zone preview overlay while edge-dragging (fading in).
            if let Some(sr) = snap_preview_local {
                let p = self.progress(self.snap_since);
                let fade = |c: u32| (c & 0x00FF_FFFF) | (((c >> 24) * p / 255) << 24);
                canvas.fill_rounded_rect(clip, sr, 6, fade(self.theme.snap_preview_fill), fade(self.theme.snap_preview_border));
            }

            // 4. Unified floating bottom dock (primary output).
            if let Some(ref dl) = dock_layout {
                dl.render_with_pinned(canvas, clip, &self.theme, self.dock_cfg, &dock_pinned[..dock_pn], &dock_entries[..dock_n], &self.tray, text);
            }

            // 5. The launcher or permission prompt modal over everything but the pointer.
            if let Some(ref lr) = launcher {
                self.launcher.render(canvas, clip, &self.theme, text, lr, self.settings, self.progress(self.launcher.opened_at));
            } else if output.primary && self.perm_prompt.active {
                self.perm_prompt.render(canvas, clip, &self.theme, text, self.line_h);
            }

            // 6. Software pointer cursor fallback if adapter lacks hardware cursor.
            if !output.hw_cursor && output.bounds.contains_point(self.pointer) {
                canvas.draw_sw_cursor_kind(clip, self.pointer.x - output.bounds.x, self.pointer.y - output.bounds.y, self.cursor_kind);
            }
        }

        local_damage
    }
}
