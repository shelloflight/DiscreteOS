//! Atomic Kernel Mode Setting (KMS) object model, validation, and mode-revert state machine.
//!
//! Models connectors, CRTCs (pipes), planes (primary, cursor, overlay), framebuffers, and atomic
//! state commits (`ATOMIC_TEST_ONLY` + `ATOMIC_ALLOW_MODESET` + `ATOMIC_NONBLOCK`) uniformly across
//! VirtIO-GPU, UEFI GOP, and upstream AMD `dc`, NVIDIA `nvkms`, and Intel `xe` backends.

use crate::edid::DetailedTiming;
use crate::{DamageRect, MAX_DIM, MAX_FB_BYTES, PixelFormat};

pub const MAX_CONNECTORS: usize = 4;
pub const MAX_CRTCS: usize = 4;
pub const MAX_PLANES: usize = 8;
pub const MAX_KMS_MODES: usize = 16;
pub const MAX_KMS_FBS: usize = 16;
pub const MAX_COMMIT_DAMAGE: usize = 16;

/// Default automatic revert timeout (12 seconds) for unconfirmed interactive mode switches.
pub const DEFAULT_REVERT_TIMEOUT_NS: u64 = 12_000_000_000;

// Mode flags.
pub const MODE_FLAG_PREFERRED: u32 = 1 << 0;
pub const MODE_FLAG_CURRENT: u32 = 1 << 1;

// Atomic commit flags (`AtomicCommit::flags`).
pub const ATOMIC_TEST_ONLY: u32 = 1 << 0;
pub const ATOMIC_ALLOW_MODESET: u32 = 1 << 1;
pub const ATOMIC_NONBLOCK: u32 = 1 << 2;
pub const ATOMIC_PAGE_FLIP_EVENT: u32 = 1 << 3;
pub const ATOMIC_CURSOR_ONLY: u32 = 1 << 4;
pub const ATOMIC_REQUIRE_CONFIRM: u32 = 1 << 5;
pub const ATOMIC_RESET_BOOT: u32 = 1 << 6;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectorKind {
    #[default]
    Unknown = 0,
    FirmwareGop = 1,
    Virtual = 2,
    DisplayPort = 3,
    HdmiA = 4,
    Edp = 5,
}

impl ConnectorKind {
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::FirmwareGop,
            2 => Self::Virtual,
            3 => Self::DisplayPort,
            4 => Self::HdmiA,
            5 => Self::Edp,
            _ => Self::Unknown,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::FirmwareGop => "GOP",
            Self::Virtual => "Virtual",
            Self::DisplayPort => "DP",
            Self::HdmiA => "HDMI-A",
            Self::Edp => "eDP",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum PlaneKind {
    #[default]
    Primary = 1,
    Cursor = 2,
    Overlay = 3,
}

impl PlaneKind {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Primary),
            2 => Some(Self::Cursor),
            3 => Some(Self::Overlay),
            _ => None,
        }
    }
}

/// Full KMS mode timing descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KmsMode {
    pub width: u32,
    pub height: u32,
    pub refresh_mhz: u32,
    pub pixel_clock_khz: u32,
    pub htotal: u16,
    pub vtotal: u16,
    pub flags: u32,
}

impl KmsMode {
    pub fn from_timing(t: &DetailedTiming, current: bool) -> Self {
        let mut flags = if t.preferred { MODE_FLAG_PREFERRED } else { 0 };
        if current {
            flags |= MODE_FLAG_CURRENT;
        }
        Self {
            width: t.h_active,
            height: t.v_active,
            refresh_mhz: t.refresh_mhz,
            pixel_clock_khz: t.pixel_clock_khz,
            htotal: t.h_total().min(u16::MAX as u32) as u16,
            vtotal: t.v_total().min(u16::MAX as u32) as u16,
            flags,
        }
    }

    pub fn simple(width: u32, height: u32, refresh_mhz: u32, flags: u32) -> Self {
        if let Some(t) = DetailedTiming::cvt_rb(width, height, refresh_mhz) {
            Self {
                width,
                height,
                refresh_mhz,
                pixel_clock_khz: t.pixel_clock_khz,
                htotal: t.h_total().min(u16::MAX as u32) as u16,
                vtotal: t.v_total().min(u16::MAX as u32) as u16,
                flags,
            }
        } else {
            Self {
                width,
                height,
                refresh_mhz,
                pixel_clock_khz: 0,
                htotal: width.min(u16::MAX as u32) as u16,
                vtotal: height.min(u16::MAX as u32) as u16,
                flags,
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KmsConnector {
    pub id: u32,
    pub kind: ConnectorKind,
    pub connected: bool,
    pub crtc_id: u32,
    pub dp_lanes: u8,
    pub dp_rate_mbps: u32,
    pub edid_blocks: u8,
    pub vrr_min_hz: u16,
    pub vrr_max_hz: u16,
    pub vrr_capable: bool,
    pub hdr_capable: bool,
    pub dsc_capable: bool,
    pub monitor_name: [u8; 24],
    pub monitor_len: u8,
}

impl Default for KmsConnector {
    fn default() -> Self {
        Self {
            id: 0,
            kind: ConnectorKind::Unknown,
            connected: false,
            crtc_id: 0,
            dp_lanes: 0,
            dp_rate_mbps: 0,
            edid_blocks: 0,
            vrr_min_hz: 0,
            vrr_max_hz: 0,
            vrr_capable: false,
            hdr_capable: false,
            dsc_capable: false,
            monitor_name: [0; 24],
            monitor_len: 0,
        }
    }
}

impl KmsConnector {
    pub fn set_monitor_name(&mut self, name: &[u8]) {
        let n = name.len().min(self.monitor_name.len());
        self.monitor_name.fill(0);
        self.monitor_name[..n].copy_from_slice(&name[..n]);
        self.monitor_len = n as u8;
    }

    pub fn monitor_str(&self) -> &str {
        let n = (self.monitor_len as usize).min(self.monitor_name.len());
        core::str::from_utf8(&self.monitor_name[..n]).unwrap_or("")
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KmsCrtc {
    pub id: u32,
    pub pipe: u8,
    pub active: bool,
    pub mode: KmsMode,
    pub vrr_enabled: bool,
    pub hdr_enabled: bool,
    pub dsc_enabled: bool,
    pub vblank_seq: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KmsPlane {
    pub id: u32,
    pub kind: PlaneKind,
    pub possible_crtcs: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    pub hot_x: u16,
    pub hot_y: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KmsFb {
    pub fb_id: u32,
    pub gem_handle: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub format: u32,
    pub modifier: u64,
}

impl KmsFb {
    pub fn validate(gem_handle: u32, width: u32, height: u32, pitch: u32, format: u32, bo_size: u64) -> Result<(), KmsError> {
        if gem_handle == 0 || width == 0 || height == 0 || width > MAX_DIM || height > MAX_DIM {
            return Err(KmsError::InvalidArgs);
        }
        let Some(fmt) = PixelFormat::from_u32(format) else {
            return Err(KmsError::UnsupportedFormat);
        };
        let min_pitch = width.checked_mul(fmt.bpp()).ok_or(KmsError::InvalidArgs)?;
        if pitch < min_pitch || !pitch.is_multiple_of(4) {
            return Err(KmsError::InvalidArgs);
        }
        let need = u64::from(pitch).checked_mul(u64::from(height)).ok_or(KmsError::InvalidArgs)?;
        if need == 0 || need > MAX_FB_BYTES || bo_size < need {
            return Err(KmsError::BufferTooSmall);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KmsError {
    InvalidArgs,
    UnknownObject,
    UnsupportedFormat,
    UnsupportedMode,
    ModesetRequired,
    CapabilityUnsupported,
    BufferTooSmall,
    NoResources,
}

/// Atomic state transition request (`OP_KMS_ATOMIC_COMMIT` / `DRV_KMS_ATOMIC_COMMIT`).
#[derive(Clone, Copy, Debug)]
pub struct AtomicCommit {
    pub flags: u32,
    pub crtc_id: u32,
    pub connector_id: u32,
    pub mode_changed: bool,
    pub mode_width: u32,
    pub mode_height: u32,
    pub mode_refresh_mhz: u32,
    pub vrr_changed: bool,
    pub vrr_enable: bool,
    pub hdr_changed: bool,
    pub hdr_enable: bool,
    pub primary_changed: bool,
    pub primary_fb_id: u32,
    pub damage: [DamageRect; MAX_COMMIT_DAMAGE],
    pub damage_count: u8,
    pub cursor_changed: bool,
    pub cursor_fb_id: u32,
    pub cursor_x: i32,
    pub cursor_y: i32,
    pub cursor_hot_x: u16,
    pub cursor_hot_y: u16,
    pub in_syncobj: u32,
    pub in_point: u64,
    pub out_syncobj: u32,
    pub out_point: u64,
}

impl Default for AtomicCommit {
    fn default() -> Self {
        Self {
            flags: 0,
            crtc_id: 1,
            connector_id: 1,
            mode_changed: false,
            mode_width: 0,
            mode_height: 0,
            mode_refresh_mhz: 0,
            vrr_changed: false,
            vrr_enable: false,
            hdr_changed: false,
            hdr_enable: false,
            primary_changed: false,
            primary_fb_id: 0,
            damage: [DamageRect::EMPTY; MAX_COMMIT_DAMAGE],
            damage_count: 0,
            cursor_changed: false,
            cursor_fb_id: 0,
            cursor_x: 0,
            cursor_y: 0,
            cursor_hot_x: 0,
            cursor_hot_y: 0,
            in_syncobj: 0,
            in_point: 0,
            out_syncobj: 0,
            out_point: 0,
        }
    }
}

/// Per-adapter KMS topology, framebuffer table, and atomic validation state.
pub struct KmsState {
    pub connectors: [Option<KmsConnector>; MAX_CONNECTORS],
    pub crtcs: [Option<KmsCrtc>; MAX_CRTCS],
    pub planes: [Option<KmsPlane>; MAX_PLANES],
    pub modes: [KmsMode; MAX_KMS_MODES],
    pub mode_count: usize,
    pub fbs: [Option<KmsFb>; MAX_KMS_FBS],
    next_fb_id: u32,
    pub allow_arbitrary_modeset: bool,
}

impl Default for KmsState {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsState {
    pub const fn new() -> Self {
        Self {
            connectors: [None; MAX_CONNECTORS],
            crtcs: [None; MAX_CRTCS],
            planes: [None; MAX_PLANES],
            modes: [KmsMode {
                width: 0,
                height: 0,
                refresh_mhz: 0,
                pixel_clock_khz: 0,
                htotal: 0,
                vtotal: 0,
                flags: 0,
            }; MAX_KMS_MODES],
            mode_count: 0,
            fbs: [None; MAX_KMS_FBS],
            next_fb_id: 1,
            allow_arbitrary_modeset: false,
        }
    }

    /// Initialize a standard single-pipe KMS graph (Connector #1 -> CRTC #1, Primary #1, optional Cursor #2).
    pub fn init_single_pipe(
        &mut self,
        conn_kind: ConnectorKind,
        monitor_name: &[u8],
        width: u32,
        height: u32,
        refresh_mhz: u32,
        has_cursor: bool,
    ) {
        let mode = KmsMode::simple(width, height, refresh_mhz, MODE_FLAG_PREFERRED | MODE_FLAG_CURRENT);
        let mut conn = KmsConnector {
            id: 1,
            kind: conn_kind,
            connected: width > 0 && height > 0,
            crtc_id: 1,
            ..KmsConnector::default()
        };
        conn.set_monitor_name(monitor_name);
        self.connectors[0] = Some(conn);
        self.crtcs[0] = Some(KmsCrtc {
            id: 1,
            pipe: 0,
            active: width > 0 && height > 0,
            mode,
            vrr_enabled: false,
            hdr_enabled: false,
            dsc_enabled: false,
            vblank_seq: 0,
        });
        self.planes[0] = Some(KmsPlane {
            id: 1,
            kind: PlaneKind::Primary,
            possible_crtcs: 1,
            crtc_id: 1,
            fb_id: 0,
            crtc_x: 0,
            crtc_y: 0,
            crtc_w: width,
            crtc_h: height,
            hot_x: 0,
            hot_y: 0,
        });
        if has_cursor {
            self.planes[1] = Some(KmsPlane {
                id: 2,
                kind: PlaneKind::Cursor,
                possible_crtcs: 1,
                crtc_id: 1,
                fb_id: 0,
                crtc_x: 0,
                crtc_y: 0,
                crtc_w: 64,
                crtc_h: 64,
                hot_x: 0,
                hot_y: 0,
            });
        }
        self.modes[0] = mode;
        self.mode_count = if width > 0 && height > 0 { 1 } else { 0 };
    }

    pub fn push_mode(&mut self, mut mode: KmsMode) {
        if mode.width == 0 || mode.height == 0 || self.mode_count >= MAX_KMS_MODES {
            return;
        }
        if let Some(crtc) = self.crtcs[0]
            && crtc.mode.width == mode.width
            && crtc.mode.height == mode.height
            && crtc.mode.refresh_mhz.abs_diff(mode.refresh_mhz) <= 500
        {
            mode.flags |= MODE_FLAG_CURRENT;
        }
        for existing in &mut self.modes[..self.mode_count] {
            if existing.width == mode.width
                && existing.height == mode.height
                && existing.refresh_mhz.abs_diff(mode.refresh_mhz) <= 500
            {
                existing.flags |= mode.flags;
                return;
            }
        }
        self.modes[self.mode_count] = mode;
        self.mode_count += 1;
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_fb(
        &mut self,
        gem_handle: u32,
        width: u32,
        height: u32,
        pitch: u32,
        format: u32,
        modifier: u64,
        bo_size: u64,
    ) -> Result<u32, KmsError> {
        KmsFb::validate(gem_handle, width, height, pitch, format, bo_size)?;
        let active_primary = self.planes[0].map_or(0, |p| p.fb_id);
        let active_cursor = self.planes[1].map_or(0, |p| p.fb_id);
        let slot = self
            .fbs
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.fbs.iter().position(|s| {
                    s.is_some_and(|f| f.fb_id != active_primary && f.fb_id != active_cursor)
                })
            })
            .ok_or(KmsError::NoResources)?;
        let fb_id = self.next_fb_id;
        self.next_fb_id = self.next_fb_id.wrapping_add(1).max(1);
        self.fbs[slot] = Some(KmsFb {
            fb_id,
            gem_handle,
            width,
            height,
            pitch,
            format,
            modifier,
        });
        Ok(fb_id)
    }

    pub fn remove_fb(&mut self, fb_id: u32) -> Option<KmsFb> {
        for slot in &mut self.fbs {
            if slot.is_some_and(|f| f.fb_id == fb_id) {
                return slot.take();
            }
        }
        None
    }

    pub fn get_fb(&self, fb_id: u32) -> Option<KmsFb> {
        self.fbs.iter().flatten().copied().find(|f| f.fb_id == fb_id)
    }

    /// Validate an `AtomicCommit` without mutating state (`ATOMIC_TEST_ONLY` safe).
    pub fn validate_commit(&self, req: &AtomicCommit) -> Result<Option<KmsMode>, KmsError> {
        let crtc_id = if req.crtc_id == 0 { 1 } else { req.crtc_id };
        let Some(crtc) = self.crtcs.iter().flatten().find(|c| c.id == crtc_id) else {
            return Err(KmsError::UnknownObject);
        };
        let conn_id = if req.connector_id == 0 { 1 } else { req.connector_id };
        let Some(conn) = self.connectors.iter().flatten().find(|c| c.id == conn_id) else {
            return Err(KmsError::UnknownObject);
        };

        let mut resolved_mode: Option<KmsMode> = None;
        if req.mode_changed {
            if (req.flags & ATOMIC_ALLOW_MODESET) == 0 {
                return Err(KmsError::ModesetRequired);
            }
            if !(320..=MAX_DIM).contains(&req.mode_width) || !(200..=MAX_DIM).contains(&req.mode_height) {
                return Err(KmsError::UnsupportedMode);
            }
            let target_hz = if req.mode_refresh_mhz == 0 { 60_000 } else { req.mode_refresh_mhz };
            if let Some(m) = self.modes[..self.mode_count].iter().copied().find(|m| {
                m.width == req.mode_width
                    && m.height == req.mode_height
                    && (req.mode_refresh_mhz == 0 || m.refresh_mhz.abs_diff(target_hz) <= 1_500)
            }) {
                resolved_mode = Some(m);
            } else if self.allow_arbitrary_modeset {
                resolved_mode = Some(KmsMode::simple(req.mode_width, req.mode_height, target_hz, 0));
            } else {
                return Err(KmsError::UnsupportedMode);
            }
        }

        if req.vrr_changed && req.vrr_enable && !conn.vrr_capable {
            return Err(KmsError::CapabilityUnsupported);
        }
        if req.hdr_changed && req.hdr_enable && !conn.hdr_capable {
            return Err(KmsError::CapabilityUnsupported);
        }

        if req.primary_changed && req.primary_fb_id != 0 {
            let Some(fb) = self.get_fb(req.primary_fb_id) else {
                return Err(KmsError::UnknownObject);
            };
            let _ = (crtc, fb);
        }

        if req.cursor_changed {
            let has_cursor_plane = self
                .planes
                .iter()
                .flatten()
                .any(|p| p.kind == PlaneKind::Cursor);
            if !has_cursor_plane {
                return Err(KmsError::CapabilityUnsupported);
            }
            if req.cursor_fb_id != 0 {
                let Some(cfb) = self.get_fb(req.cursor_fb_id) else {
                    return Err(KmsError::UnknownObject);
                };
                if !matches!((cfb.width, cfb.height), (64, 64) | (128, 128) | (256, 256)) {
                    return Err(KmsError::InvalidArgs);
                }
            }
        }

        Ok(resolved_mode)
    }

    /// Apply a previously validated `AtomicCommit` to the in-memory KMS state.
    pub fn apply_commit(&mut self, req: &AtomicCommit, resolved_mode: Option<KmsMode>) {
        let crtc_id = if req.crtc_id == 0 { 1 } else { req.crtc_id };
        if let Some(m) = resolved_mode {
            for em in &mut self.modes[..self.mode_count] {
                if em.width == m.width
                    && em.height == m.height
                    && em.refresh_mhz.abs_diff(m.refresh_mhz) <= 1_500
                {
                    em.flags |= MODE_FLAG_CURRENT;
                } else {
                    em.flags &= !MODE_FLAG_CURRENT;
                }
            }
            if let Some(crtc) = self.crtcs.iter_mut().flatten().find(|c| c.id == crtc_id) {
                let mut active_m = m;
                active_m.flags |= MODE_FLAG_CURRENT;
                crtc.mode = active_m;
                crtc.active = true;
            }
        }
        if let Some(crtc) = self.crtcs.iter_mut().flatten().find(|c| c.id == crtc_id) {
            if req.vrr_changed {
                crtc.vrr_enabled = req.vrr_enable;
            }
            if req.hdr_changed {
                crtc.hdr_enabled = req.hdr_enable;
            }
            if req.primary_changed {
                crtc.vblank_seq = crtc.vblank_seq.saturating_add(1);
            }
        }
        if req.primary_changed {
            let fb_opt = self.get_fb(req.primary_fb_id);
            if let Some(p) = self.planes.iter_mut().flatten().find(|p| p.kind == PlaneKind::Primary) {
                p.fb_id = req.primary_fb_id;
                if let Some(fb) = fb_opt {
                    p.crtc_w = fb.width;
                    p.crtc_h = fb.height;
                }
            }
        }
        if req.cursor_changed
            && let Some(p) = self.planes.iter_mut().flatten().find(|p| p.kind == PlaneKind::Cursor)
        {
            if req.cursor_fb_id != 0 {
                p.fb_id = req.cursor_fb_id;
                p.hot_x = req.cursor_hot_x;
                p.hot_y = req.cursor_hot_y;
            }
            p.crtc_x = req.cursor_x;
            p.crtc_y = req.cursor_y;
        }
    }
}

/// Guards interactive mode switches with a 12-second confirmation deadline so an out-of-range
/// monitor mode automatically reverts to the last confirmed working `KmsMode`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ModeRevertGuard {
    pending: Option<(u32, KmsMode, u64)>,
}

impl ModeRevertGuard {
    pub const fn new() -> Self {
        Self { pending: None }
    }

    pub fn arm(&mut self, adapter_id: u32, prev_mode: KmsMode, now_ns: u64, timeout_ns: u64) {
        // Keep the original known-good mode if the user tries a second mode before confirming.
        let base_mode = match self.pending {
            Some((id, orig, _)) if id == adapter_id => orig,
            _ => prev_mode,
        };
        self.pending = Some((adapter_id, base_mode, now_ns.saturating_add(timeout_ns)));
    }

    pub fn confirm(&mut self, adapter_id: u32) -> bool {
        if self.pending.is_some_and(|(id, _, _)| adapter_id == 0 || id == adapter_id) {
            self.pending = None;
            true
        } else {
            false
        }
    }

    /// Immediately consume and return a pending unconfirmed modeset for explicit revert.
    pub fn take_pending(&mut self, adapter_id: u32) -> Option<(u32, KmsMode)> {
        if let Some((id, mode, _)) = self.pending
            && (adapter_id == 0 || id == adapter_id)
        {
            self.pending = None;
            return Some((id, mode));
        }
        None
    }

    pub const fn secs_left(&self, adapter_id: u32, now_ns: u64) -> u8 {
        match self.pending {
            Some((id, _, dl)) if (adapter_id == 0 || id == adapter_id) && dl > now_ns => {
                let rem = dl - now_ns;
                let secs = rem.div_ceil(1_000_000_000);
                if secs > 255 { 255 } else { secs as u8 }
            }
            _ => 0,
        }
    }

    pub const fn deadline_ns(&self) -> Option<u64> {
        match self.pending {
            Some((_, _, dl)) => Some(dl),
            None => None,
        }
    }

    pub fn poll_expired(&mut self, now_ns: u64) -> Option<(u32, KmsMode)> {
        if let Some((id, mode, dl)) = self.pending
            && now_ns >= dl
        {
            self.pending = None;
            return Some((id, mode));
        }
        None
    }
}
