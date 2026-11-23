//! Compositor-drawn unforgeable application permission prompt (`dosawmi`).
//!
//! Shown when `appmgr.dsvc` launches a `.dapp` whose manifest declares permissions in `prompt`
//! that the active user has not yet decided. Because D-AWMI renders the modal directly and
//! traps all input until answered, apps cannot fake or auto-approve the prompt.

use crate::geom::{Point, Rect};
use crate::pixel::Canvas;
use crate::proto::sanitize_label;
use crate::text::{TextRender, TextRole};
use crate::theme::Theme;

pub const PERM_ALLOW: u8 = 1;
pub const PERM_DENY: u8 = 2;
pub const PERM_CANCEL: u8 = 3;

const PERM_LABELS: [&[u8]; 15] = [
    b"Display windows",
    b"Read files in your namespace",
    b"Create, edit, and delete files",
    b"Attach to terminal session",
    b"Read display modes & refresh rates",
    b"Change display modes & desktop theme",
    b"Adjust audio devices & volume",
    b"Play audio output",
    b"View network link & DNS status",
    b"Change DNS & network settings",
    b"Inspect running services & logs",
    b"Read user identity & lock status",
    b"Manage identities & lock policy",
    b"List installed applications",
    b"Grant or revoke app permissions",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermOutcome {
    None,
    Changed,
    Decided { request_id: u32, choice: u8 },
}

#[derive(Clone, Copy, Debug, Default)]
struct PermRects {
    card: Rect,
    btns: [Rect; 3],
}

pub struct PermPrompt {
    pub active: bool,
    pub request_id: u32,
    app_name: [u8; 24],
    app_name_len: usize,
    app_title: [u8; 32],
    app_title_len: usize,
    pub perm_mask: u32,
    pub selected: usize,
}

impl Default for PermPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl PermPrompt {
    pub const fn new() -> Self {
        Self {
            active: false,
            request_id: 0,
            app_name: [0; 24],
            app_name_len: 0,
            app_title: [0; 32],
            app_title_len: 0,
            perm_mask: 0,
            selected: 0,
        }
    }

    pub fn open(&mut self, request_id: u32, app_name: &[u8], app_title: &[u8], perm_mask: u32) {
        self.active = true;
        self.request_id = request_id;
        self.app_name.fill(0);
        self.app_name_len = sanitize_label(app_name, &mut self.app_name);
        self.app_title.fill(0);
        self.app_title_len = sanitize_label(app_title, &mut self.app_title);
        self.perm_mask = perm_mask;
        self.selected = 0;
    }

    pub fn close(&mut self) {
        self.active = false;
        self.perm_mask = 0;
    }

    pub fn key(&mut self, base: u32, pressed: bool) -> PermOutcome {
        const LEFT: u32 = 0x103;
        const RIGHT: u32 = 0x104;
        if !pressed {
            return PermOutcome::None;
        }
        match base {
            0x1B => {
                let id = self.request_id;
                self.close();
                PermOutcome::Decided { request_id: id, choice: PERM_CANCEL }
            }
            LEFT => {
                self.selected = (self.selected + 2) % 3;
                PermOutcome::Changed
            }
            RIGHT | 0x09 => {
                self.selected = (self.selected + 1) % 3;
                PermOutcome::Changed
            }
            0x0A | 0x0D | 0x20 => {
                let id = self.request_id;
                let choice = match self.selected {
                    0 => PERM_ALLOW,
                    1 => PERM_DENY,
                    _ => PERM_CANCEL,
                };
                self.close();
                PermOutcome::Decided { request_id: id, choice }
            }
            _ => PermOutcome::None,
        }
    }

    fn layout(&self, out_w: u32, out_h: u32, line_h: u32) -> PermRects {
        let count = (self.perm_mask & 0x7FFF).count_ones().clamp(1, 6);
        let card_w = 480u32.min(out_w.saturating_sub(32)).max(260.min(out_w));
        let row_h = (line_h + 8).max(22);
        let btn_h = (line_h + 16).max(34);
        let card_h = (132 + count * row_h + btn_h).min(out_h.saturating_sub(48).max(180));
        let cx = (out_w.saturating_sub(card_w) / 2) as i32;
        let cy = (out_h.saturating_sub(card_h) / 2) as i32;
        let card = Rect::new(cx, cy, card_w, card_h);
        let gap = 10u32;
        let inner_w = card_w.saturating_sub(48);
        let bw = inner_w.saturating_sub(gap * 2) / 3;
        let by = cy + card_h as i32 - btn_h as i32 - 20;
        let btns = [
            Rect::new(cx + 24, by, bw, btn_h),
            Rect::new(cx + 24 + (bw + gap) as i32, by, bw, btn_h),
            Rect::new(cx + 24 + ((bw + gap) * 2) as i32, by, bw, btn_h),
        ];
        PermRects { card, btns }
    }

    pub fn pointer(&mut self, local: Point, left_pressed: bool, out_w: u32, out_h: u32, line_h: u32) -> PermOutcome {
        let r = self.layout(out_w, out_h, line_h);
        for (i, b) in r.btns.iter().enumerate() {
            if b.contains_point(local) {
                if left_pressed {
                    let id = self.request_id;
                    let choice = match i {
                        0 => PERM_ALLOW,
                        1 => PERM_DENY,
                        _ => PERM_CANCEL,
                    };
                    self.close();
                    return PermOutcome::Decided { request_id: id, choice };
                } else if self.selected != i {
                    self.selected = i;
                    return PermOutcome::Changed;
                }
            }
        }
        PermOutcome::None
    }

    pub fn cursor_at(&self, local: Point, out_w: u32, out_h: u32, line_h: u32) -> crate::pixel::CursorKind {
        let r = self.layout(out_w, out_h, line_h);
        if r.btns.iter().any(|b| b.contains_point(local)) {
            crate::pixel::CursorKind::Pointer
        } else {
            crate::pixel::CursorKind::Default
        }
    }

    pub fn render(&self, canvas: &mut Canvas<'_>, clip: Rect, theme: &Theme, text: &mut dyn TextRender, line_h: u32) {
        let out = canvas.bounds();
        canvas.fill_rect(clip, out, theme.overlay_dim);
        let r = self.layout(out.w, out.h, line_h);
        if r.card.intersect(clip).is_empty() {
            return;
        }
        canvas.fill_rounded_rect(clip, r.card, theme.radius + 4, theme.surface_raised, theme.accent_ring);
        let hdr_h = (line_h + 16).max(32);
        canvas.fill_rect(clip, Rect::new(r.card.x + 1, r.card.y + 1, r.card.w.saturating_sub(2), hdr_h), theme.title_active);
        canvas.fill_circle(clip, r.card.x + 18, r.card.y + (hdr_h / 2) as i32, 4, theme.trust_native);
        text.draw(
            canvas,
            clip,
            r.card.x + 30,
            r.card.y + (hdr_h / 2) as i32,
            b"D-OS PERMISSION REQUEST",
            TextRole::Title,
            theme.text_primary,
            r.card.w.saturating_sub(40),
        );

        let title = if self.app_title_len > 0 { &self.app_title[..self.app_title_len] } else { &self.app_name[..self.app_name_len] };
        let mut y = r.card.y + hdr_h as i32 + 22;
        text.draw(canvas, clip, r.card.x + 24, y, title, TextRole::Large, theme.text_primary, r.card.w.saturating_sub(48));
        y += (line_h + 8) as i32;
        text.draw(
            canvas,
            clip,
            r.card.x + 24,
            y,
            b"This signed app requests permission to:",
            TextRole::Small,
            theme.text_muted,
            r.card.w.saturating_sub(48),
        );
        y += (line_h + 10) as i32;

        let row_h = (line_h + 8) as i32;
        let mut drawn = 0usize;
        for (bit, label) in PERM_LABELS.iter().enumerate() {
            if self.perm_mask & (1u32 << bit) != 0 && drawn < 6 {
                canvas.fill_circle(clip, r.card.x + 32, y, 3, theme.accent_ring);
                text.draw(canvas, clip, r.card.x + 44, y, label, TextRole::Body, theme.text_primary, r.card.w.saturating_sub(68));
                y += row_h;
                drawn += 1;
            }
        }

        let labels: [&[u8]; 3] = [b"Allow", b"Deny & Launch", b"Cancel"];
        for (i, (btn, lbl)) in r.btns.iter().zip(labels.iter()).enumerate() {
            let sel = i == self.selected;
            let fill = if i == 0 {
                theme.accent
            } else if sel {
                theme.btn_hover
            } else {
                theme.input_bg
            };
            let border = if sel { theme.accent_ring } else { theme.border_active };
            let fg = if i == 0 { theme.text_on_accent } else { theme.text_primary };
            canvas.fill_rounded_rect(clip, *btn, theme.radius, fill, border);
            let lw = text.measure(lbl, TextRole::Small).min(btn.w.saturating_sub(8));
            text.draw(canvas, clip, btn.x + (btn.w.saturating_sub(lw) / 2) as i32, btn.y + (btn.h / 2) as i32, lbl, TextRole::Small, fg, lw + 2);
        }
    }
}
