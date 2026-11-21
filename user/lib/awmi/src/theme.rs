//! Themes (colour and shape tokens), chrome metrics and the dock's configuration.
//!
//! Two themes ship (`sys:/themes/*.toml`, also built in here): **Dark Slate**, the default (deep
//! neutral slate surfaces, 1px hairlines, the Discrete Blue accent `#566087`), and **High
//! Contrast** (black and white, thicker focus rings, opaque surfaces). Discrete Blue is used as a
//! fill (buttons, selection, active pills, white text on it: 6.1:1); its lighter tints carry the
//! thin things on dark surfaces that need contrast: focus rings, links and accent text
//! (`accent_ring`, 5.4:1 on a title bar). Green, amber and red are semantic only: microphone live,
//! sandboxed program, security alert. No gradients anywhere.

/// Pack `0xAARRGGBB` color.
pub const fn argb(a: u8, r: u8, g: u8, b: u8) -> u32 {
    ((a as u32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// Pack opaque `0xFFRRGGBB` color.
pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    argb(0xFF, r, g, b)
}

const fn hex(v: u32) -> u32 {
    0xFF00_0000 | v
}

macro_rules! theme_colors {
    ($( $(#[$doc:meta])* $name:ident ),* $(,)?) => {
        /// A theme: every colour (`0xAARRGGBB`) and shape token the compositor and the toolkit use.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Theme {
            $( $(#[$doc])* pub $name: u32, )*
            /// Focus ring width in pixels.
            pub focus_ring: u32,
            /// Corner radius of controls and panels.
            pub radius: u32,
        }

        /// The colour token names, in wire and file order.
        pub const COLOR_NAMES: &[&str] = &[$( stringify!($name) ),*];

        impl Theme {
            fn colors(&self) -> [u32; COLOR_NAMES.len()] {
                [$( self.$name ),*]
            }

            fn colors_mut(&mut self) -> [&mut u32; COLOR_NAMES.len()] {
                [$( &mut self.$name ),*]
            }
        }
    };
}

theme_colors! {
    /// Desktop backdrop (flat).
    desktop_bg,
    /// Secondary backdrop (canvases, wells).
    desktop_subtle,
    /// Title bar of the focused window.
    title_active,
    /// Title bar of other windows.
    title_inactive,
    /// A window's client area before its first frame; app backgrounds.
    client_bg,
    /// Raised surfaces: the launcher, menus, cards.
    surface_raised,
    /// Text fields and other inset controls.
    input_bg,
    /// Focused window border.
    border_active,
    /// Other borders and hairlines.
    border_inactive,
    /// Sandboxed (foreign code) window border: amber.
    border_sandbox,
    /// Discrete Blue: fills (buttons, selection, active pills).
    accent,
    /// Discrete Blue, hovered.
    accent_hover,
    /// Discrete Blue, pressed.
    accent_pressed,
    /// Discrete Blue tint for thin things on dark surfaces: focus rings, links, accent text.
    accent_ring,
    /// Discrete Blue, lightest tint (headings, the high-contrast ring).
    accent_strong,
    /// Snap preview fill (translucent).
    snap_preview_fill,
    /// Snap preview border.
    snap_preview_border,
    /// Dock surface (translucent on Dark Slate).
    dock_bg,
    /// Dock hairline.
    dock_border,
    /// Dock pill: focused window, active workspace.
    dock_pill_active,
    /// Dock pill: other windows.
    dock_pill_idle,
    /// Primary text.
    text_primary,
    /// Secondary text: identities, metadata, inactive titles.
    text_muted,
    /// Text on an `accent` fill.
    text_on_accent,
    /// Trust dot: system services.
    trust_system,
    /// Trust dot: native programs.
    trust_native,
    /// Trust dot: sandboxed programs (amber).
    trust_sandbox,
    /// Microphone live (green).
    ind_mic_live,
    /// Security alert, destructive actions (red).
    ind_alert_red,
    /// Title bar button hover.
    btn_hover,
    /// Close button hover.
    btn_close_hover,
    /// Status dot: on.
    status_ok,
    /// Status dot: off.
    status_off,
    /// Backdrop dimming behind the launcher.
    overlay_dim,
}

/// Which theme (`EVT_SETTINGS`, `OP_SETTINGS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ThemeId {
    #[default]
    DarkSlate = 0,
    HighContrast = 1,
}

impl ThemeId {
    pub const fn from_u8(v: u8) -> ThemeId {
        if v == 1 { ThemeId::HighContrast } else { ThemeId::DarkSlate }
    }

    pub const fn builtin(self) -> Theme {
        match self {
            ThemeId::DarkSlate => Theme::DARK_SLATE,
            ThemeId::HighContrast => Theme::HIGH_CONTRAST,
        }
    }

    /// The theme file on the system volume (`sys:/themes/<file>`).
    pub const fn file(self) -> &'static str {
        match self {
            ThemeId::DarkSlate => "dark-slate.toml",
            ThemeId::HighContrast => "high-contrast.toml",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            ThemeId::DarkSlate => "Dark Slate",
            ThemeId::HighContrast => "High Contrast",
        }
    }
}

/// Bytes of an encoded theme (`EVT_SETTINGS` payload).
pub const THEME_BYTES: usize = COLOR_NAMES.len() * 4 + 8;

/// Why a theme file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeError {
    /// Line number (1-based) of a line that is not `key = value`, `[section]` or a comment.
    Syntax(u32),
    /// Line of an unknown key or section.
    Unknown(u32),
    /// Line of a value that is not `"#RRGGBB"` / `"#AARRGGBB"` (colours) or a small number.
    Value(u32),
    /// A colour the file does not set (its index in `COLOR_NAMES`).
    Missing(usize),
}

impl Theme {
    pub const DARK_SLATE: Self = Self {
        desktop_bg: hex(0x0E1016),
        desktop_subtle: hex(0x141620),
        title_active: hex(0x181A24),
        title_inactive: hex(0x13151D),
        client_bg: hex(0x11131A),
        surface_raised: hex(0x1B1E2A),
        input_bg: hex(0x0F1118),
        border_active: hex(0x3B425C),
        border_inactive: hex(0x232736),
        border_sandbox: hex(0xB87E24),
        accent: hex(0x566087),
        accent_hover: hex(0x616C98),
        accent_pressed: hex(0x485070),
        accent_ring: hex(0x838EB9),
        accent_strong: hex(0xA7B0D2),
        snap_preview_fill: argb(0x38, 0x56, 0x60, 0x87),
        snap_preview_border: argb(0xCC, 0x83, 0x8E, 0xB9),
        dock_bg: argb(0xDC, 0x15, 0x18, 0x22),
        dock_border: argb(0xE0, 0x2B, 0x30, 0x43),
        dock_pill_active: argb(0xE8, 0x25, 0x2A, 0x3D),
        dock_pill_idle: argb(0x90, 0x1B, 0x1E, 0x2C),
        text_primary: hex(0xE5E7F0),
        text_muted: hex(0x888EA4),
        text_on_accent: hex(0xFFFFFF),
        trust_system: hex(0x838EB9),
        trust_native: hex(0xA3A8B4),
        trust_sandbox: hex(0xE5A93B),
        ind_mic_live: hex(0x34D399),
        ind_alert_red: hex(0xEF4444),
        btn_hover: argb(0xCC, 0x28, 0x2D, 0x40),
        btn_close_hover: argb(0xD8, 0xC0, 0x39, 0x39),
        status_ok: hex(0x7CC69D),
        status_off: hex(0x5C6176),
        overlay_dim: argb(0x66, 0x06, 0x07, 0x0B),
        focus_ring: 1,
        radius: 6,
    };

    pub const HIGH_CONTRAST: Self = Self {
        desktop_bg: hex(0x000000),
        desktop_subtle: hex(0x0A0A0A),
        title_active: hex(0x000000),
        title_inactive: hex(0x000000),
        client_bg: hex(0x000000),
        surface_raised: hex(0x000000),
        input_bg: hex(0x000000),
        border_active: hex(0xFFFFFF),
        border_inactive: hex(0xA0A0A0),
        border_sandbox: hex(0xFFB000),
        accent: hex(0x485070),
        accent_hover: hex(0x566087),
        accent_pressed: hex(0x3A4160),
        accent_ring: hex(0xC9D0EA),
        accent_strong: hex(0xDDE2F5),
        snap_preview_fill: argb(0x40, 0xA7, 0xB0, 0xD2),
        snap_preview_border: hex(0xFFFFFF),
        dock_bg: hex(0x000000),
        dock_border: hex(0xFFFFFF),
        dock_pill_active: hex(0x1A1D28),
        dock_pill_idle: hex(0x000000),
        text_primary: hex(0xFFFFFF),
        text_muted: hex(0xD0D4E0),
        text_on_accent: hex(0xFFFFFF),
        trust_system: hex(0xC9D0EA),
        trust_native: hex(0xFFFFFF),
        trust_sandbox: hex(0xFFB000),
        ind_mic_live: hex(0x4ADE80),
        ind_alert_red: hex(0xFF5555),
        btn_hover: hex(0x2A2F40),
        btn_close_hover: hex(0xD02020),
        status_ok: hex(0x4ADE80),
        status_off: hex(0xA0A0A0),
        overlay_dim: argb(0xB0, 0x00, 0x00, 0x00),
        focus_ring: 2,
        radius: 6,
    };

    /// The wire form (`THEME_BYTES`): every colour (little-endian), then focus ring and radius.
    pub fn encode(&self, out: &mut [u8; THEME_BYTES]) {
        for (i, c) in self.colors().iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&c.to_le_bytes());
        }
        let m = COLOR_NAMES.len() * 4;
        out[m..m + 4].copy_from_slice(&self.focus_ring.to_le_bytes());
        out[m + 4..m + 8].copy_from_slice(&self.radius.to_le_bytes());
    }

    /// Decode the wire form; shape tokens are clamped to sane ranges.
    pub fn decode(b: &[u8]) -> Option<Theme> {
        if b.len() < THEME_BYTES {
            return None;
        }
        let mut t = Theme::DARK_SLATE;
        for (i, c) in t.colors_mut().into_iter().enumerate() {
            *c = u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        }
        let m = COLOR_NAMES.len() * 4;
        t.focus_ring = u32::from_le_bytes([b[m], b[m + 1], b[m + 2], b[m + 3]]).clamp(1, 4);
        t.radius = u32::from_le_bytes([b[m + 4], b[m + 5], b[m + 6], b[m + 7]]).min(16);
        Some(t)
    }

    /// Parse a theme file: `name = "..."`, `[colors]` with every token as `"#RRGGBB"` or
    /// `"#AARRGGBB"`, `[metrics]` with `focus_ring` (1-4) and `radius` (0-16). Strict: unknown keys
    /// and missing colours are errors, so a file always describes a whole theme.
    pub fn from_toml(text: &str) -> Result<Theme, ThemeError> {
        let mut t = Theme::DARK_SLATE;
        let mut seen = [false; COLOR_NAMES.len()];
        let mut section = 0u8; // 0 top, 1 colors, 2 metrics
        for (n, raw) in text.lines().enumerate() {
            let ln = n as u32 + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(s) = line.strip_prefix('[') {
                section = match s.strip_suffix(']').map(str::trim) {
                    Some("colors") => 1,
                    Some("metrics") => 2,
                    Some(_) => return Err(ThemeError::Unknown(ln)),
                    None => return Err(ThemeError::Syntax(ln)),
                };
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { return Err(ThemeError::Syntax(ln)) };
            let (k, v) = (k.trim(), v.trim());
            match section {
                0 if k == "name" => {
                    if !(v.len() >= 2 && v.starts_with('"') && v.ends_with('"') && v.len() <= 66) {
                        return Err(ThemeError::Value(ln));
                    }
                }
                1 => {
                    let i = COLOR_NAMES.iter().position(|&c| c == k).ok_or(ThemeError::Unknown(ln))?;
                    *t.colors_mut()[i] = parse_color(v).ok_or(ThemeError::Value(ln))?;
                    seen[i] = true;
                }
                2 => {
                    let x: u32 = v.parse().map_err(|_| ThemeError::Value(ln))?;
                    match k {
                        "focus_ring" if (1..=4).contains(&x) => t.focus_ring = x,
                        "radius" if x <= 16 => t.radius = x,
                        "focus_ring" | "radius" => return Err(ThemeError::Value(ln)),
                        _ => return Err(ThemeError::Unknown(ln)),
                    }
                }
                _ => return Err(ThemeError::Unknown(ln)),
            }
        }
        if let Some(i) = seen.iter().position(|s| !s) {
            return Err(ThemeError::Missing(i));
        }
        Ok(t)
    }
}

fn strip_comment(s: &str) -> &str {
    let mut in_str = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &s[..i],
            _ => {}
        }
    }
    s
}

fn parse_color(v: &str) -> Option<u32> {
    let s = v.strip_prefix('"')?.strip_suffix('"')?.strip_prefix('#')?;
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let x = u32::from_str_radix(s, 16).ok()?;
    match s.len() {
        6 => Some(0xFF00_0000 | x),
        8 => Some(x),
        _ => None,
    }
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

    /// Metrics for a text line height (larger text: taller title bars and wider buttons).
    pub fn for_line_height(line_h: u32) -> Self {
        let mut m = Self::DEFAULT;
        m.title_h = (line_h + 12).max(28);
        m.btn_w = m.title_h;
        m
    }
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

    /// The dock for a text line height.
    pub fn for_line_height(line_h: u32) -> Self {
        let mut d = Self::DEFAULT;
        d.height = (line_h + 24).max(40);
        d
    }

    /// Total vertical space reserved at the bottom of the primary output.
    pub const fn reserved_bottom(self) -> u32 {
        self.height + self.margin_bottom + self.work_gap
    }
}
