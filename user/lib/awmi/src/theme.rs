//! Visual theme, chrome metrics, and customizable dock configuration.
//!
//! Aesthetic: clean, minimal dark neutral/slate palette with crisp 1px hairlines, subtle cool
//! focus accent, zero gradients, and semantic-only status colors (green = active mic, amber =
//! sandboxed/foreign trust framing, red = critical security alert / close hover).

/// Pack `0xAARRGGBB` color.
pub const fn argb(a: u8, r: u8, g: u8, b: u8) -> u32 {
    ((a as u32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// Pack opaque `0xFFRRGGBB` color.
pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    argb(0xFF, r, g, b)
}

/// Baseline dark neutral/slate theme palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    /// Clean solid dark slate desktop backdrop (no gradients).
    pub desktop_bg: u32,
    /// Subtle structural grid/accent line on desktop backdrop if desired (0 = solid flat).
    pub desktop_subtle: u32,
    /// Active window titlebar fill.
    pub title_active: u32,
    /// Inactive window titlebar fill.
    pub title_inactive: u32,
    /// Default window client backdrop before first commit.
    pub client_bg: u32,
    /// Active window 1px border.
    pub border_active: u32,
    /// Inactive window 1px border.
    pub border_inactive: u32,
    /// Sandboxed/foreign window subtle 1px border tint.
    pub border_sandbox: u32,
    /// Cool focus accent (active pill underline, snap preview border, focused indicator).
    pub accent_focus: u32,
    /// Translucent snap-zone preview fill.
    pub snap_preview_fill: u32,
    /// Translucent snap-zone preview 1px border.
    pub snap_preview_border: u32,
    /// Floating unified bottom dock translucent surface.
    pub dock_bg: u32,
    /// Floating dock 1px hairline border.
    pub dock_border: u32,
    /// Dock active window / workspace pill fill.
    pub dock_pill_active: u32,
    /// Dock inactive window / workspace pill fill.
    pub dock_pill_idle: u32,
    /// Primary crisp light text.
    pub text_primary: u32,
    /// Secondary muted text (manifest prefix, inactive titles, metadata).
    pub text_muted: u32,
    /// Unforgeable trust dot for verified core system services.
    pub trust_system: u32,
    /// Unforgeable trust dot for verified native D-OS apps.
    pub trust_native: u32,
    /// Unforgeable trust dot for sandboxed / foreign apps.
    pub trust_sandbox: u32,
    /// Semantic green for unforgeable `[MIC LIVE]` indicator.
    pub ind_mic_live: u32,
    /// Semantic red for critical security alerts & destructive hover.
    pub ind_alert_red: u32,
    /// Subtle neutral button hover fill on window titlebar.
    pub btn_hover: u32,
    /// Close button glyph / hover accent.
    pub btn_close_hover: u32,
    /// Active online status dot (network/audio normal).
    pub status_ok: u32,
    /// Muted / offline indicator dot.
    pub status_off: u32,
}

impl Theme {
    pub const DARK_SLATE: Self = Self {
        desktop_bg: rgb(0x0E, 0x11, 0x16),
        desktop_subtle: rgb(0x14, 0x18, 0x20),
        title_active: rgb(0x18, 0x1C, 0x24),
        title_inactive: rgb(0x13, 0x16, 0x1D),
        client_bg: rgb(0x11, 0x14, 0x1A),
        border_active: rgb(0x3B, 0x47, 0x5C),
        border_inactive: rgb(0x23, 0x29, 0x36),
        border_sandbox: rgb(0xB8, 0x7E, 0x24),
        accent_focus: rgb(0x52, 0x94, 0xE2),
        snap_preview_fill: argb(0x38, 0x52, 0x94, 0xE2),
        snap_preview_border: argb(0xCC, 0x52, 0x94, 0xE2),
        dock_bg: argb(0xDC, 0x15, 0x19, 0x22),
        dock_border: argb(0xE0, 0x2B, 0x33, 0x43),
        dock_pill_active: argb(0xE8, 0x25, 0x2D, 0x3D),
        dock_pill_idle: argb(0x90, 0x1B, 0x20, 0x2C),
        text_primary: rgb(0xE5, 0xE9, 0xF0),
        text_muted: rgb(0x88, 0x92, 0xA4),
        trust_system: rgb(0x6E, 0xB5, 0xFF),
        trust_native: rgb(0x93, 0xA8, 0xC6),
        trust_sandbox: rgb(0xE5, 0xA9, 0x3B),
        ind_mic_live: rgb(0x34, 0xD3, 0x99),
        ind_alert_red: rgb(0xEF, 0x44, 0x44),
        btn_hover: argb(0xCC, 0x28, 0x30, 0x40),
        btn_close_hover: argb(0xD8, 0xC0, 0x39, 0x39),
        status_ok: rgb(0x7C, 0xC6, 0x9D),
        status_off: rgb(0x5C, 0x65, 0x76),
    };
}

/// Server-side decoration (SSD) dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChromeMetrics {
    pub title_h: u32,
    pub border_w: u32,
    pub resize_margin: u32,
    pub btn_w: u32,
    pub min_client_w: u32,
    pub min_client_h: u32,
}

impl ChromeMetrics {
    pub const DEFAULT: Self = Self {
        title_h: 28,
        border_w: 1,
        resize_margin: 6,
        btn_w: 28,
        min_client_w: 160,
        min_client_h: 96,
    };
}

/// Unified floating bottom dock layout configuration (designed to be customizable later).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DockConfig {
    /// Horizontal inset from the left and right edges of the primary output (20-30px range).
    pub inset_x: u32,
    /// Vertical gap from the bottom edge of the primary output.
    pub margin_bottom: u32,
    /// Height of the floating dock island in pixels.
    pub height: u32,
    /// Corner radius in pixels.
    pub corner_r: u32,
    /// Gap between work area bottom and the dock top.
    pub work_gap: u32,
}

impl DockConfig {
    pub const DEFAULT: Self = Self {
        inset_x: 24,
        margin_bottom: 10,
        height: 40,
        corner_r: 10,
        work_gap: 6,
    };

    /// Total vertical space reserved at the bottom of the primary output.
    pub const fn reserved_bottom(self) -> u32 {
        self.height + self.margin_bottom + self.work_gap
    }
}
