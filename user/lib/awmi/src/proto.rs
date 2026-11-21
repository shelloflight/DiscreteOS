//! Strict wire-format codecs for D-AWMI IPC messages (zero panics on untrusted bytes).

use crate::geom::Rect;

/// Maximum title bytes accepted from a client.
pub const MAX_TITLE_BYTES: usize = 48;
/// Maximum verified manifest identity bytes attached by `init`.
pub const MAX_IDENTITY_BYTES: usize = 24;

/// Unforgeable trust tier assigned by `init` when connecting a client to `awmi.window`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustTier {
    /// Core verified D-OS system service.
    System = 1,
    /// Verified native D-OS application.
    #[default]
    Native = 2,
    /// Sandboxed / foreign application (e.g. D-CMPL).
    Sandbox = 3,
}

impl TrustTier {
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::System,
            3 => Self::Sandbox,
            _ => Self::Native,
        }
    }
}

/// Window creation/configuration flags.
pub mod win_flags {
    pub const DECORATED: u32 = 1 << 0;
    pub const RESIZABLE: u32 = 1 << 1;
    pub const OPAQUE: u32 = 1 << 2;
    pub const DEFAULT: u32 = DECORATED | RESIZABLE | OPAQUE;
}

/// Window state bits reported in `EVT_CONFIGURE`.
pub mod win_state {
    pub const FOCUSED: u32 = 1 << 0;
    pub const MAXIMIZED: u32 = 1 << 1;
    pub const SNAPPED: u32 = 1 << 2;
    pub const MINIMIZED: u32 = 1 << 3;
}

/// Pointer event sub-kinds.
pub mod ptr_kind {
    pub const MOVE: u32 = 1;
    pub const BUTTON: u32 = 2;
    pub const WHEEL: u32 = 3;
    pub const ENTER: u32 = 4;
    pub const LEAVE: u32 = 5;
}

/// Indicator flag bits for `awmi.indicator`.
pub mod indicator_bits {
    pub const MIC_LIVE: u64 = 1 << 0;
    pub const SECURITY_ALERT: u64 = 1 << 1;
    pub const SCREEN_SHARE: u64 = 1 << 2;
}

/// Decoded damage rectangle list from an untrusted `OP_COMMIT` payload.
pub fn decode_damage_rects(payload: &[u8], out: &mut [Rect]) -> usize {
    let count = (payload.len() / 16).min(out.len());
    for (i, slot) in out.iter_mut().take(count).enumerate() {
        let o = i * 16;
        let x = i32::from_le_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]]);
        let y = i32::from_le_bytes([payload[o + 4], payload[o + 5], payload[o + 6], payload[o + 7]]);
        let w = u32::from_le_bytes([payload[o + 8], payload[o + 9], payload[o + 10], payload[o + 11]]);
        let h = u32::from_le_bytes([payload[o + 12], payload[o + 13], payload[o + 14], payload[o + 15]]);
        *slot = Rect::new(x, y, w, h);
    }
    count
}

/// Encode damage rects into `out`; returns bytes written.
pub fn encode_damage_rects(rects: &[Rect], out: &mut [u8]) -> usize {
    let count = (out.len() / 16).min(rects.len());
    for (i, r) in rects.iter().take(count).enumerate() {
        let o = i * 16;
        out[o..o + 4].copy_from_slice(&r.x.to_le_bytes());
        out[o + 4..o + 8].copy_from_slice(&r.y.to_le_bytes());
        out[o + 8..o + 12].copy_from_slice(&r.w.to_le_bytes());
        out[o + 12..o + 16].copy_from_slice(&r.h.to_le_bytes());
    }
    count * 16
}

/// Sanitize an untrusted UTF-8 title slice into a clean single-line ASCII/UTF-8 buffer (strips
/// control bytes and bounds length to `MAX_TITLE_BYTES`).
pub fn sanitize_label(src: &[u8], dst: &mut [u8]) -> usize {
    let mut n = 0;
    for &b in src {
        if n >= dst.len() {
            break;
        }
        if b == 0 {
            break;
        }
        if (0x20..=0x7E).contains(&b) {
            dst[n] = b;
            n += 1;
        } else if b == b'\t' {
            dst[n] = b' ';
            n += 1;
        }
    }
    n
}

/// Compositor status summary returned by `OP_QUERY_STATUS` (64 bytes).
pub const STATUS_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AwmiStatus {
    pub active: bool,
    pub outputs: u8,
    pub workspaces: u8,
    pub active_workspace: u8,
    pub windows: u16,
    pub focused_window: u32,
    pub width: u32,
    pub height: u32,
    pub refresh_mhz: u32,
    pub indicators: u64,
    pub frames: u64,
    pub damage_flushes: u64,
    /// Keys from real keyboards (not test injections) received during sessions.
    pub input_keys: u32,
    /// Pointer events from real mice/tablets received during sessions.
    pub input_pointer: u32,
    /// `UiSettings::pack()`: theme, text scale, reduce motion.
    pub settings: u32,
    /// The launcher is open.
    pub launcher_open: bool,
    /// The vector fonts are loaded (otherwise the bitmap font draws).
    pub fonts: bool,
    /// Launcher entries registered by programs.
    pub apps: u8,
}

impl AwmiStatus {
    pub fn encode(&self, out: &mut [u8; STATUS_BYTES]) {
        out.fill(0);
        out[0] = u8::from(self.active);
        out[1] = self.outputs;
        out[2] = self.workspaces;
        out[3] = self.active_workspace;
        out[4..6].copy_from_slice(&self.windows.to_le_bytes());
        out[8..12].copy_from_slice(&self.focused_window.to_le_bytes());
        out[12..16].copy_from_slice(&self.width.to_le_bytes());
        out[16..20].copy_from_slice(&self.height.to_le_bytes());
        out[20..24].copy_from_slice(&self.refresh_mhz.to_le_bytes());
        out[24..32].copy_from_slice(&self.indicators.to_le_bytes());
        out[32..40].copy_from_slice(&self.frames.to_le_bytes());
        out[40..48].copy_from_slice(&self.damage_flushes.to_le_bytes());
        out[48..52].copy_from_slice(&self.input_keys.to_le_bytes());
        out[52..56].copy_from_slice(&self.input_pointer.to_le_bytes());
        out[56..60].copy_from_slice(&self.settings.to_le_bytes());
        out[60] = u8::from(self.launcher_open);
        out[61] = u8::from(self.fonts);
        out[62] = self.apps;
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < STATUS_BYTES {
            return None;
        }
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]])
        };
        Some(Self {
            active: b[0] != 0,
            outputs: b[1],
            workspaces: b[2],
            active_workspace: b[3],
            windows: u16_at(4),
            focused_window: u32_at(8),
            width: u32_at(12),
            height: u32_at(16),
            refresh_mhz: u32_at(20),
            indicators: u64_at(24),
            frames: u64_at(32),
            damage_flushes: u64_at(40),
            input_keys: u32_at(48),
            input_pointer: u32_at(52),
            settings: u32_at(56),
            launcher_open: b[60] != 0,
            fonts: b[61] != 0,
            apps: b[62],
        })
    }
}

/// Test-hook window record size (`OP_TEST_WINDOWS`).
pub const WINDOW_INFO_BYTES: usize = 128;

/// Encode one window for the test hook: id, frame, client rect, trust, workspace, minimized,
/// focused, identity, title (the layout `libd::awmi::WindowInfo` decodes).
#[allow(clippy::too_many_arguments)]
pub fn encode_window_info(
    out: &mut [u8; WINDOW_INFO_BYTES],
    id: u32,
    frame: Rect,
    client: Rect,
    trust: TrustTier,
    workspace: u8,
    minimized: bool,
    focused: bool,
    identity: &[u8],
    title: &[u8],
) {
    out.fill(0);
    let put_rect = |o: &mut [u8], r: Rect| {
        o[0..4].copy_from_slice(&r.x.to_le_bytes());
        o[4..8].copy_from_slice(&r.y.to_le_bytes());
        o[8..12].copy_from_slice(&r.w.to_le_bytes());
        o[12..16].copy_from_slice(&r.h.to_le_bytes());
    };
    out[0..4].copy_from_slice(&id.to_le_bytes());
    put_rect(&mut out[4..20], frame);
    put_rect(&mut out[20..36], client);
    out[36] = trust as u8;
    out[37] = workspace;
    out[38] = u8::from(minimized);
    out[39] = u8::from(focused);
    let il = identity.len().min(MAX_IDENTITY_BYTES);
    let tl = title.len().min(MAX_TITLE_BYTES);
    out[40] = il as u8;
    out[41] = tl as u8;
    out[44..44 + il].copy_from_slice(&identity[..il]);
    out[68..68 + tl].copy_from_slice(&title[..tl]);
}

/// Split a `svc::CONNECT` payload from the service manager: `<endpoint>` or
/// `<endpoint>\0<verified client service name>` (providers with `provides.identify`).
pub fn split_connect(payload: &[u8]) -> (&[u8], &[u8]) {
    match payload.iter().position(|&c| c == 0) {
        Some(i) => (&payload[..i], &payload[i + 1..]),
        None => (payload, &[]),
    }
}
