//! Unified minimal floating bottom dock:
//! - Wide rounded island inset ~24px from the left & right edges, sitting slightly above the bottom.
//! - Left/center: running windows & pinned quick-launch slots (active focus highlight).
//! - Right: workspace switcher (1..4), network status, audio status, unforgeable privacy/security
//!   indicators (MIC LIVE = green, critical security alert = red), and UTC clock.

use crate::geom::{Point, Rect};
use crate::pixel::Canvas;
use crate::proto::indicator_bits;
use crate::text::{TextRender, TextRole};
use crate::theme::{DockConfig, Theme};

pub const MAX_DOCK_WINDOWS: usize = 12;

/// Summary of a window entry shown in the dock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DockWindowEntry {
    pub window_id: u32,
    pub workspace: u8,
    pub focused: bool,
    pub minimized: bool,
    pub label: [u8; 20],
    pub label_len: u8,
}

impl DockWindowEntry {
    pub fn label_bytes(&self) -> &[u8] {
        let n = (self.label_len as usize).min(self.label.len());
        &self.label[..n]
    }
}

/// Live system tray data rendered on the right side of the unified bottom dock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DockTrayState {
    pub active_workspace: u8,
    pub workspace_count: u8,
    pub net_online: bool,
    pub audio_muted: bool,
    pub audio_volume: u8,
    pub indicators: u64,
    pub hour: u8,
    pub minute: u8,
    pub clock_valid: bool,
}

/// Hit-test result when clicking inside the floating bottom dock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockHit {
    None,
    Background,
    Window(u32),
    Workspace(u8),
    NetStatus,
    AudioStatus,
    Indicator,
    Clock,
}

/// Computed rectangles for the dock and its interactive items (in output-local coordinates).
#[derive(Clone, Debug)]
pub struct DockLayout {
    pub bar: Rect,
    pub win_rects: [(u32, Rect); MAX_DOCK_WINDOWS],
    pub win_count: usize,
    pub ws_rects: [Rect; 4],
    pub ws_count: usize,
    pub net_rect: Rect,
    pub audio_rect: Rect,
    pub mic_rect: Rect,
    pub alert_rect: Rect,
    pub clock_rect: Rect,
}

impl DockLayout {
    /// Compute the floating dock layout for an output of size `(out_w, out_h)`.
    pub fn compute(
        out_w: u32,
        out_h: u32,
        cfg: DockConfig,
        windows: &[DockWindowEntry],
        tray: &DockTrayState,
        char_w: u32,
    ) -> Self {
        let inset_x = cfg.inset_x.min(out_w / 8);
        let bar_w = out_w.saturating_sub(inset_x.saturating_mul(2)).max(120.min(out_w));
        let bar_h = cfg.height.min(out_h / 4).max(24);
        let bar_x = ((out_w.saturating_sub(bar_w)) / 2) as i32;
        let bar_y = out_h.saturating_sub(bar_h + cfg.margin_bottom) as i32;
        let bar = Rect::new(bar_x, bar_y, bar_w, bar_h);

        let pill_h = bar_h.saturating_sub(12).max(18);
        let pill_y = bar.y + ((bar_h - pill_h) / 2) as i32;

        // Lay out right-side system tray from right to left so it never collides with windows.
        let mut rx = bar.x + bar.w as i32 - 12;

        // Clock ("HH:MM").
        let cw = char_w.max(4);
        let clock_w = (cw * 5 + 14).max(50);
        rx -= clock_w as i32;
        let clock_rect = Rect::new(rx, pill_y, clock_w, pill_h);
        rx -= 8;

        // Critical security alert pill (only occupies width when active).
        let alert_rect = if (tray.indicators & indicator_bits::SECURITY_ALERT) != 0 {
            let w = (cw * 5 + 30).max(68);
            rx -= w as i32;
            let r = Rect::new(rx, pill_y, w, pill_h);
            rx -= 6;
            r
        } else {
            Rect::EMPTY
        };

        // Unforgeable MIC LIVE green indicator (only occupies width when active).
        let mic_rect = if (tray.indicators & indicator_bits::MIC_LIVE) != 0 {
            let w = (cw * 8 + 26).max(84);
            rx -= w as i32;
            let r = Rect::new(rx, pill_y, w, pill_h);
            rx -= 6;
            r
        } else {
            Rect::EMPTY
        };

        // Audio status ("VOL").
        let audio_w = (cw * 3 + 18).max(42);
        rx -= audio_w as i32;
        let audio_rect = Rect::new(rx, pill_y, audio_w, pill_h);
        rx -= 6;

        // Network status ("NET").
        let net_w = (cw * 3 + 18).max(42);
        rx -= net_w as i32;
        let net_rect = Rect::new(rx, pill_y, net_w, pill_h);
        rx -= 10;

        // Workspace switcher pills ("1" "2" "3" "4").
        let ws_count = (tray.workspace_count as usize).clamp(1, 4);
        let ws_w = (cw + 16).max(24);
        let ws_gap = 4i32;
        let mut ws_rects = [Rect::EMPTY; 4];
        for i in (0..ws_count).rev() {
            rx -= ws_w as i32;
            ws_rects[i] = Rect::new(rx, pill_y, ws_w, pill_h);
            rx -= ws_gap;
        }
        let right_boundary = rx - 10;

        // Left/center: running windows.
        let mut win_rects = [(0u32, Rect::EMPTY); MAX_DOCK_WINDOWS];
        let mut win_count = 0usize;
        let mut lx = bar.x + 12;
        let max_pill_w = 136u32;
        for w in windows.iter().take(MAX_DOCK_WINDOWS) {
            let avail = right_boundary - lx;
            if avail < 56 {
                break;
            }
            // `cw` is an average; proportional text runs wider on capitals and wide letters.
            let text_w = (w.label_bytes().len() as u32) * (cw + cw.div_ceil(3));
            let pw = (text_w + 28).clamp(64, max_pill_w).min(avail as u32);
            win_rects[win_count] = (w.window_id, Rect::new(lx, pill_y, pw, pill_h));
            win_count += 1;
            lx += pw as i32 + 6;
        }

        Self {
            bar,
            win_rects,
            win_count,
            ws_rects,
            ws_count,
            net_rect,
            audio_rect,
            mic_rect,
            alert_rect,
            clock_rect,
        }
    }

    pub fn hit_test(&self, p: Point) -> DockHit {
        if !self.bar.contains_point(p) {
            return DockHit::None;
        }
        for &(wid, r) in self.win_rects.iter().take(self.win_count) {
            if r.contains_point(p) {
                return DockHit::Window(wid);
            }
        }
        for (i, r) in self.ws_rects.iter().enumerate().take(self.ws_count) {
            if r.contains_point(p) {
                return DockHit::Workspace(i as u8);
            }
        }
        if self.net_rect.contains_point(p) {
            return DockHit::NetStatus;
        }
        if self.audio_rect.contains_point(p) {
            return DockHit::AudioStatus;
        }
        if self.mic_rect.contains_point(p) || self.alert_rect.contains_point(p) {
            return DockHit::Indicator;
        }
        if self.clock_rect.contains_point(p) {
            return DockHit::Clock;
        }
        DockHit::Background
    }

    /// Render the unified minimal floating bottom dock clipped to `clip`.
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &self,
        canvas: &mut Canvas<'_>,
        clip: Rect,
        theme: &Theme,
        cfg: DockConfig,
        windows: &[DockWindowEntry],
        tray: &DockTrayState,
        text: &mut dyn TextRender,
    ) {
        if self.bar.intersect(clip).is_empty() {
            return;
        }
        // Dock floating surface + crisp 1px hairline border.
        canvas.fill_rounded_rect(clip, self.bar, cfg.corner_r, theme.dock_bg, theme.dock_border);

        // Left/center: running window pills (or subtle brand mark when desktop is empty).
        let mid = |r: Rect| r.y + (r.h / 2) as i32;
        if self.win_count == 0 {
            text.draw(canvas, clip, self.bar.x + 16, mid(self.bar), b"D-OS", TextRole::Title, theme.text_muted, 80);
        } else {
            for &(wid, rect) in self.win_rects.iter().take(self.win_count) {
                let Some(entry) = windows.iter().find(|e| e.window_id == wid) else {
                    continue;
                };
                let fill = if entry.focused { theme.dock_pill_active } else { theme.dock_pill_idle };
                let border = if entry.focused { theme.border_active } else { 0 };
                canvas.fill_rounded_rect(clip, rect, 6, fill, border);
                if entry.focused {
                    // Subtle 2px focus underline inside the active window pill.
                    let bar_r = Rect::new(rect.x + 10, rect.y + rect.h as i32 - 3, rect.w.saturating_sub(20), 2);
                    canvas.fill_rect(clip, bar_r, theme.accent_ring);
                }
                let text_col = if entry.focused {
                    theme.text_primary
                } else {
                    theme.text_muted
                };
                // Centred in the pill (and over the focus underline); cut with an ellipsis if long.
                let avail = rect.w.saturating_sub(16);
                let tw = text.measure(entry.label_bytes(), TextRole::Body).min(avail);
                let tx = rect.x + (rect.w.saturating_sub(tw) / 2) as i32;
                text.draw(canvas, clip, tx, mid(rect), entry.label_bytes(), TextRole::Body, text_col, avail);
            }
        }

        // Right: workspace switcher pills.
        for (i, &r) in self.ws_rects.iter().enumerate().take(self.ws_count) {
            let active = (i as u8) == tray.active_workspace;
            let fill = if active { theme.accent } else { 0 };
            let border = if active { theme.accent_ring } else { theme.border_inactive };
            canvas.fill_rounded_rect(clip, r, 5, fill, border);
            let digit = [b'1' + (i as u8)];
            let col = if active { theme.text_on_accent } else { theme.text_muted };
            let dw = text.measure(&digit, TextRole::Body);
            text.draw(canvas, clip, r.x + (r.w.saturating_sub(dw) / 2) as i32, mid(r), &digit, TextRole::Body, col, r.w);
        }

        // Right: subtle vertical separator before tray statuses.
        let sep_x = self.net_rect.x - 5;
        canvas.fill_rect(clip, Rect::new(sep_x, self.bar.y + 10, 1, self.bar.h.saturating_sub(20)), theme.dock_border);

        // Network indicator (clean dot + "NET").
        {
            let r = self.net_rect;
            let cy = r.y + (r.h as i32) / 2;
            let dot_col = if tray.net_online { theme.status_ok } else { theme.status_off };
            canvas.fill_circle(clip, r.x + 6, cy, 3, dot_col);
            let lbl: &[u8] = if text.icons() { "\u{F0318}".as_bytes() } else { b"NET" };
            text.draw(canvas, clip, r.x + 14, cy, lbl, if text.icons() { TextRole::Icon } else { TextRole::Body }, theme.text_muted, r.w.saturating_sub(14));
        }

        // Audio indicator (clean dot + "VOL" / "MUT").
        {
            let r = self.audio_rect;
            let cy = r.y + (r.h as i32) / 2;
            let dot_col = if tray.audio_muted { theme.status_off } else { theme.status_ok };
            canvas.fill_circle(clip, r.x + 6, cy, 3, dot_col);
            let lbl: &[u8] = match (text.icons(), tray.audio_muted) {
                (true, true) => "\u{F026}".as_bytes(),
                (true, false) => "\u{F028}".as_bytes(),
                (false, true) => b"MUT",
                (false, false) => b"VOL",
            };
            text.draw(canvas, clip, r.x + 14, cy, lbl, if text.icons() { TextRole::Icon } else { TextRole::Body }, theme.text_muted, r.w.saturating_sub(14));
        }

        // Unforgeable MIC LIVE green indicator (semantic green, clean dark pill).
        if !self.mic_rect.is_empty() {
            let r = self.mic_rect;
            canvas.fill_rounded_rect(clip, r, 6, theme.dock_pill_active, theme.ind_mic_live);
            let cy = r.y + (r.h as i32) / 2;
            canvas.fill_circle(clip, r.x + 9, cy, 3, theme.ind_mic_live);
            text.draw(canvas, clip, r.x + 17, cy, b"MIC LIVE", TextRole::Title, theme.ind_mic_live, r.w.saturating_sub(19));
        }

        // Unforgeable critical security alert indicator (semantic red).
        if !self.alert_rect.is_empty() {
            let r = self.alert_rect;
            canvas.fill_rounded_rect(clip, r, 6, theme.dock_pill_active, theme.ind_alert_red);
            let cy = r.y + (r.h as i32) / 2;
            canvas.fill_circle(clip, r.x + 9, cy, 3, theme.ind_alert_red);
            text.draw(canvas, clip, r.x + 17, cy, b"ALERT", TextRole::Title, theme.ind_alert_red, r.w.saturating_sub(19));
        }

        // UTC clock ("HH:MM").
        {
            let r = self.clock_rect;
            let clock = if tray.clock_valid {
                [
                    b'0' + (tray.hour / 10) % 10,
                    b'0' + (tray.hour % 10),
                    b':',
                    b'0' + (tray.minute / 10) % 10,
                    b'0' + (tray.minute % 10),
                ]
            } else {
                *b"--:--"
            };
            text.draw(canvas, clip, r.x + 5, mid(r), &clock, TextRole::Body, theme.text_primary, r.w.saturating_sub(4));
        }
    }
}
