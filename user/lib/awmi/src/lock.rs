//! Compositor-drawn lock and login screen (`dosawmi`).
//!
//! Because D-AWMI renders this screen directly across every output and suppresses all client
//! window pixels, the floating dock, the launcher, and all client input delivery while active,
//! no application can imitate, obscure, or intercept passphrases typed here.

use crate::dock::DockTrayState;
use crate::geom::{Point, Rect};
use crate::pixel::Canvas;
use crate::proto::sanitize_label;
use crate::text::{TextRender, TextRole};
use crate::theme::Theme;

pub const MAX_LOCK_IDENTITIES: usize = 8;
pub const MAX_PASS_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum LockMode {
    /// Initial sign-in screen before the desktop session starts.
    Login = 1,
    /// Active session locked on manual action, idle timeout, or suspend.
    #[default]
    Locked = 2,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum LockReason {
    Boot = 1,
    #[default]
    Manual = 2,
    Idle = 3,
    Sleep = 4,
}

impl LockReason {
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Boot => b"Sign in to start your session",
            Self::Manual => b"Session locked",
            Self::Idle => b"Locked after inactivity",
            Self::Sleep => b"Locked before sleep",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockIdentity {
    pub id: u32,
    pub name: [u8; 24],
    pub name_len: u8,
    pub display: [u8; 32],
    pub display_len: u8,
    pub seal_tpm: bool,
    pub enrolled: bool,
}

impl LockIdentity {
    pub const EMPTY: Self = Self {
        id: 0,
        name: [0; 24],
        name_len: 0,
        display: [0; 32],
        display_len: 0,
        seal_tpm: false,
        enrolled: false,
    };

    pub fn new(id: u32, name: &[u8], display: &[u8], seal_tpm: bool, enrolled: bool) -> Self {
        let mut out = Self { id, seal_tpm, enrolled, ..Self::EMPTY };
        out.name_len = sanitize_label(name, &mut out.name) as u8;
        out.display_len = sanitize_label(display, &mut out.display) as u8;
        out
    }

    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len).min(24)]
    }

    pub fn display_bytes(&self) -> &[u8] {
        let d = &self.display[..usize::from(self.display_len).min(32)];
        if d.is_empty() { self.name_bytes() } else { d }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockOutcome {
    None,
    Changed,
    /// User pressed Enter or clicked Unlock for `identity_id`.
    Submit { identity_id: u32 },
}

#[derive(Clone, Copy, Debug, Default)]
struct LockRects {
    card: Rect,
    field: Rect,
    unlock_btn: Rect,
    id_pills: [Rect; MAX_LOCK_IDENTITIES],
    id_count: usize,
}

/// Compositor lock/login screen state (zero heap allocation, zero unsafe).
pub struct LockScreen {
    pub active: bool,
    pub mode: LockMode,
    pub reason: LockReason,
    identities: [LockIdentity; MAX_LOCK_IDENTITIES],
    count: usize,
    pub selected: usize,
    pass: [u8; MAX_PASS_BYTES],
    pass_len: usize,
    error: [u8; 64],
    error_len: usize,
    pub tpm_present: bool,
}

impl Default for LockScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl LockScreen {
    pub const fn new() -> Self {
        Self {
            active: false,
            mode: LockMode::Locked,
            reason: LockReason::Manual,
            identities: [LockIdentity::EMPTY; MAX_LOCK_IDENTITIES],
            count: 0,
            selected: 0,
            pass: [0; MAX_PASS_BYTES],
            pass_len: 0,
            error: [0; 64],
            error_len: 0,
            tpm_present: false,
        }
    }

    /// Replace the identity list shown on the lock/login screen and select `active_id`.
    pub fn set_identities(&mut self, list: &[LockIdentity], active_id: u32, tpm_present: bool) {
        self.count = list.len().min(MAX_LOCK_IDENTITIES);
        for (i, item) in list.iter().take(self.count).enumerate() {
            self.identities[i] = *item;
        }
        self.tpm_present = tpm_present;
        self.selected = self.identities[..self.count].iter().position(|i| i.id == active_id).unwrap_or(0);
    }

    pub fn selected_identity(&self) -> Option<&LockIdentity> {
        (self.count > 0).then(|| &self.identities[self.selected.min(self.count - 1)])
    }

    /// Engage the unforgeable lock/login screen and wipe any leftover passphrase bytes.
    pub fn engage(&mut self, mode: LockMode, reason: LockReason) {
        self.active = true;
        self.mode = mode;
        self.reason = reason;
        self.clear_passphrase();
        self.error_len = 0;
    }

    /// Disengage the lock screen and wipe passphrase bytes immediately.
    pub fn unlock(&mut self) {
        self.clear_passphrase();
        self.error_len = 0;
        self.active = false;
    }

    /// Show an error message (e.g. wrong passphrase or throttle wait) and wipe the typed passphrase.
    pub fn set_error(&mut self, msg: &[u8]) {
        self.clear_passphrase();
        self.error.fill(0);
        self.error_len = sanitize_label(msg, &mut self.error);
    }

    pub fn passphrase(&self) -> &[u8] {
        &self.pass[..self.pass_len]
    }

    pub fn pass_len(&self) -> usize {
        self.pass_len
    }

    /// Explicitly wipe the passphrase buffer with an optimization barrier.
    pub fn clear_passphrase(&mut self) {
        self.pass.fill(0);
        core::hint::black_box(&self.pass);
        self.pass_len = 0;
    }

    pub fn error_bytes(&self) -> &[u8] {
        &self.error[..self.error_len]
    }

    fn current_id(&self) -> u32 {
        self.selected_identity().map_or(1, |i| i.id)
    }

    /// Process a key press while locked. Blocks every window/session escape shortcut.
    pub fn key(&mut self, key_val: u32, pressed: bool) -> LockOutcome {
        const CTRL: u32 = 1 << 17;
        const ALT: u32 = 1 << 18;
        const SUPER: u32 = 1 << 19;
        const UP: u32 = 0x101;
        const DOWN: u32 = 0x102;
        if !pressed {
            return LockOutcome::None;
        }
        let base = key_val & 0xFFFF;
        let mods = key_val & (CTRL | ALT | SUPER);
        // Ctrl+U clears the passphrase field.
        if (key_val & CTRL) != 0 && (base == u32::from(b'u') || base == u32::from(b'U') || base == 0x15) {
            self.clear_passphrase();
            return LockOutcome::Changed;
        }
        if mods != 0 {
            // Never leak modified shortcuts (Super+Esc, Ctrl+Alt+Esc, Alt+Tab, Super+L, etc.).
            return LockOutcome::None;
        }
        match base {
            0x0A | 0x0D => LockOutcome::Submit { identity_id: self.current_id() },
            0x08 => {
                if self.pass_len > 0 {
                    self.pass_len -= 1;
                    self.pass[self.pass_len] = 0;
                    core::hint::black_box(&self.pass);
                    return LockOutcome::Changed;
                }
                LockOutcome::None
            }
            0x09 | DOWN if self.mode == LockMode::Login && self.count > 1 => {
                self.selected = (self.selected + 1) % self.count;
                self.clear_passphrase();
                self.error_len = 0;
                LockOutcome::Changed
            }
            UP if self.mode == LockMode::Login && self.count > 1 => {
                self.selected = (self.selected + self.count - 1) % self.count;
                self.clear_passphrase();
                self.error_len = 0;
                LockOutcome::Changed
            }
            0x20..=0x7E if self.pass_len < MAX_PASS_BYTES => {
                self.pass[self.pass_len] = base as u8;
                self.pass_len += 1;
                self.error_len = 0;
                LockOutcome::Changed
            }
            _ => LockOutcome::None,
        }
    }

    fn layout(&self, out_w: u32, out_h: u32, line_h: u32) -> LockRects {
        let card_w = 440u32.min(out_w.saturating_sub(32)).max(240.min(out_w));
        let show_switcher = self.mode == LockMode::Login && self.count > 1;
        let switcher_h = if show_switcher { line_h + 18 } else { 0 };
        let field_h = (line_h + 22).max(38);
        let btn_h = (line_h + 18).max(36);
        let foot_h = if self.error_len > 0 { 30 } else { 0 };
        let card_h = (122 + switcher_h + field_h + btn_h + foot_h).min(out_h.saturating_sub(64).max(160));
        let cx = (out_w.saturating_sub(card_w) / 2) as i32;
        let cy = (out_h.saturating_sub(card_h) / 2) as i32;
        let card = Rect::new(cx, cy, card_w, card_h);

        let mut id_pills = [Rect::EMPTY; MAX_LOCK_IDENTITIES];
        let mut id_count = 0usize;
        if show_switcher {
            let n = self.count.min(4);
            let gap = 8u32;
            let total_w = card_w.saturating_sub(48);
            let pw = (total_w.saturating_sub(gap * (n as u32).saturating_sub(1))) / n.max(1) as u32;
            for (i, slot) in id_pills.iter_mut().enumerate().take(n) {
                *slot = Rect::new(cx + 24 + (i as u32 * (pw + gap)) as i32, cy + 72, pw, line_h + 12);
            }
            id_count = n;
        }
        let fy = cy + 80 + switcher_h as i32;
        let field = Rect::new(cx + 24, fy, card_w.saturating_sub(48), field_h);
        let unlock_btn = Rect::new(cx + 24, fy + field_h as i32 + 16, card_w.saturating_sub(48), btn_h);
        LockRects { card, field, unlock_btn, id_pills, id_count }
    }

    /// Process a left click in primary-output coordinates while locked.
    pub fn pointer(&mut self, local: Point, left_pressed: bool, out_w: u32, out_h: u32, line_h: u32) -> LockOutcome {
        if !left_pressed {
            return LockOutcome::None;
        }
        let r = self.layout(out_w, out_h, line_h);
        for (i, pill) in r.id_pills.iter().enumerate().take(r.id_count) {
            if pill.contains_point(local) {
                if self.selected != i {
                    self.selected = i;
                    self.clear_passphrase();
                    self.error_len = 0;
                    return LockOutcome::Changed;
                }
                return LockOutcome::None;
            }
        }
        if r.unlock_btn.contains_point(local) {
            return LockOutcome::Submit { identity_id: self.current_id() };
        }
        LockOutcome::None
    }

    /// Context-aware cursor shape for primary-output local position `local` while locked.
    pub fn cursor_at(&self, local: Point, out_w: u32, out_h: u32, line_h: u32) -> crate::pixel::CursorKind {
        let r = self.layout(out_w, out_h, line_h);
        if r.field.contains_point(local) {
            return crate::pixel::CursorKind::Text;
        }
        if r.unlock_btn.contains_point(local)
            || r.id_pills[..r.id_count].iter().any(|p| p.contains_point(local))
        {
            return crate::pixel::CursorKind::Pointer;
        }
        crate::pixel::CursorKind::Default
    }

    /// Colour of the top-right `TPM 2.0` status indicator based on hardware presence and sealing state:
    /// - Green (`status_ok`): hardware TPM 2.0 present and active credential sealed by TPM 2.0.
    /// - Amber (`trust_sandbox`): hardware TPM 2.0 present, active credential not TPM-sealed.
    /// - Red (`ind_alert_red`): hardware TPM 2.0 unavailable.
    pub fn tpm_badge_color(&self, theme: &Theme) -> u32 {
        if self.tpm_present && self.selected_identity().is_some_and(|i| i.seal_tpm) {
            theme.status_ok
        } else if self.tpm_present {
            theme.trust_sandbox
        } else {
            theme.ind_alert_red
        }
    }

    /// Render the unforgeable lock/login screen covering 100% of `output`.
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &self,
        canvas: &mut Canvas<'_>,
        clip: Rect,
        theme: &Theme,
        text: &mut dyn TextRender,
        tray: &DockTrayState,
        is_primary: bool,
        line_h: u32,
    ) {
        let out = canvas.bounds();
        // Opaque desktop background across 100% of the output: zero window pixels can ever show through.
        canvas.fill_rect(clip, out, theme.desktop_bg);

        // Top unforgeable compositor security banner.
        let bar_h = (line_h + 18).max(36);
        let bar = Rect::new(0, 0, out.w, bar_h);
        canvas.fill_rect(clip, bar, theme.title_active);
        canvas.fill_rect(clip, Rect::new(0, bar_h as i32 - 1, out.w, 1), theme.accent_ring);
        let mid_y = (bar_h / 2) as i32;
        canvas.fill_circle(clip, 18, mid_y, 5, theme.trust_system);
        text.draw(canvas, clip, 32, mid_y, b"D-OS", TextRole::Title, theme.text_primary, out.w / 2);

        // TPM 2.0 status badge (colour-coded by hardware & sealing state) + UTC clock on the right.
        let tpm_label = b"TPM 2.0";
        let tpm_color = self.tpm_badge_color(theme);
        let badge_w = text.measure(tpm_label, TextRole::Small);
        let mut right_x = out.w as i32 - 16;
        if tray.clock_valid {
            let clk = [
                b'0' + (tray.hour / 10),
                b'0' + (tray.hour % 10),
                b':',
                b'0' + (tray.minute / 10),
                b'0' + (tray.minute % 10),
            ];
            let cw = text.measure(&clk, TextRole::Title);
            right_x -= cw as i32;
            text.draw(canvas, clip, right_x, mid_y, &clk, TextRole::Title, theme.text_primary, cw + 4);
            right_x -= 16;
        }
        right_x -= badge_w as i32;
        if right_x > 120 {
            text.draw(canvas, clip, right_x, mid_y, tpm_label, TextRole::Small, tpm_color, badge_w + 4);
        }

        if !is_primary {
            let msg = b"Secondary display locked";
            let mw = text.measure(msg, TextRole::Body);
            text.draw(canvas, clip, (out.w.saturating_sub(mw) / 2) as i32, (out.h / 2) as i32, msg, TextRole::Body, theme.text_muted, out.w);
            return;
        }

        // Centered authentication card on the primary output.
        let r = self.layout(out.w, out.h, line_h);
        canvas.fill_rounded_rect(clip, r.card, theme.radius + 6, theme.surface_raised, theme.accent_ring);
        if theme.focus_ring > 1 {
            canvas.fill_rounded_rect(clip, r.card.inset(1), theme.radius + 5, 0, theme.accent_ring);
        }

        let id = self.selected_identity();
        let name_label = id.map_or(b"Local User".as_slice(), |i| i.display_bytes());
        text.draw(canvas, clip, r.card.x + 24, r.card.y + 30, name_label, TextRole::Large, theme.text_primary, r.card.w.saturating_sub(48));
        text.draw(canvas, clip, r.card.x + 24, r.card.y + 54, self.reason.label(), TextRole::Small, theme.text_muted, r.card.w.saturating_sub(48));

        // Optional identity selector pills in Login mode.
        for (i, pill) in r.id_pills.iter().enumerate().take(r.id_count) {
            let sel = i == self.selected;
            let fill = if sel { theme.accent } else { theme.input_bg };
            let fg = if sel { theme.text_on_accent } else { theme.text_primary };
            canvas.fill_rounded_rect(clip, *pill, theme.radius, fill, theme.border_active);
            let lbl = self.identities[i].name_bytes();
            let lw = text.measure(lbl, TextRole::Small).min(pill.w.saturating_sub(12));
            text.draw(canvas, clip, pill.x + (pill.w.saturating_sub(lw) / 2) as i32, pill.y + (pill.h / 2) as i32, lbl, TextRole::Small, fg, lw + 2);
        }

        // Masked passphrase field.
        canvas.fill_rounded_rect(clip, r.field, theme.radius, theme.input_bg, theme.accent_ring);
        let fy = r.field.y + (r.field.h / 2) as i32;
        if self.pass_len == 0 {
            let ph = if id.is_some_and(|i| !i.enrolled) {
                b"Press Enter to unlock (no passphrase set)".as_slice()
            } else {
                b"Enter passphrase".as_slice()
            };
            text.draw(canvas, clip, r.field.x + 12, fy, ph, TextRole::Body, theme.text_muted, r.field.w.saturating_sub(24));
        } else {
            let dots = [b'*'; 48];
            let shown = self.pass_len.min(dots.len());
            let used = text.draw(canvas, clip, r.field.x + 12, fy, &dots[..shown], TextRole::Large, theme.text_primary, r.field.w.saturating_sub(28));
            let cx = r.field.x + 14 + used as i32;
            canvas.fill_rect(clip, Rect::new(cx, fy - (line_h as i32 / 2) + 2, 2, line_h.saturating_sub(4).max(6)), theme.accent_ring);
        }

        // Primary Unlock / Sign In button.
        canvas.fill_rounded_rect(clip, r.unlock_btn, theme.radius, theme.accent, 0);
        let btn_lbl = if self.mode == LockMode::Login { b"Sign In".as_slice() } else { b"Unlock".as_slice() };
        let bw = text.measure(btn_lbl, TextRole::Body);
        text.draw(
            canvas,
            clip,
            r.unlock_btn.x + (r.unlock_btn.w.saturating_sub(bw) / 2) as i32,
            r.unlock_btn.y + (r.unlock_btn.h / 2) as i32,
            btn_lbl,
            TextRole::Body,
            theme.text_on_accent,
            r.unlock_btn.w,
        );

        // Error message below button when authentication fails.
        if self.error_len > 0 {
            let foot_y = r.unlock_btn.y + r.unlock_btn.h as i32 + 22;
            text.draw(canvas, clip, r.card.x + 24, foot_y, self.error_bytes(), TextRole::Small, theme.ind_alert_red, r.card.w.saturating_sub(48));
        }
    }
}
