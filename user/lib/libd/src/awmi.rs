//! D-AWMI compositor & window manager client protocol (`libd::awmi`, docs/awmi.md).
//!
//! Capability separation (`grants.awmi` in a manifest):
//! - `awmi.window`: create and draw this program's own windows; receive input for them only
//!   while focused (keys) or under the pointer (pointer events).
//! - `awmi.query`: read the compositor's status (`OP_STATUS`).
//! - `awmi.admin`: start and stop the graphical session (`OP_SESSION_START`, `OP_SESSION_STOP`),
//!   plus status; with the compositor started in test mode, the test hooks (`OP_TEST_*`).
//! - `awmi.indicator`: set system indicators on the dock (`OP_INDICATOR`: security alert).
//!
//! Window programs also get the shipped fonts as one read-only VMO (`OP_FONTS`), can name a
//! launcher entry (`OP_APP_REGISTER`; the launcher shows it with the verified identity, and
//! `EVT_LAUNCH` arrives when the user opens it), and are told the theme, text size and motion
//! setting (`EVT_SETTINGS`, with the theme's colours as payload) when a session starts and whenever
//! they change (`OP_SETTINGS` on `awmi.admin`: the shell's `gui theme|text|motion`).
//!
//! Every window's pixels live in a VMO its program created; the compositor gets a read-only
//! duplicate (`RIGHT_READ | RIGHT_MAP | RIGHT_TRANSFER`) and never writes it. A program cannot
//! name, read or change another program's window: window ids are checked against the channel
//! that created them. The title bar shows the program's verified manifest name and trust tier
//! (attached by the service manager when it connected the channel), which no program can change.

use crate::proto::{HEADER, Header};
use crate::svc;
use crate::sys::{self, Handle, MsgHandle};
use crate::Mapping;

// ---- `awmi.window` (calls) ----------------------------------------------------------------------

/// Create a window. `a` = client width | height << 32, `b` = flags (`FLAG_*`); payload = title.
/// Reply: `a` = window id, `b` = the client area's width | height << 32.
pub const OP_CREATE: u32 = 900;
/// Attach a pixel buffer. `a` = window id, `b` = width | height << 32; payload = pitch (u32),
/// format (u32, `gpu::FMT_*`); one handle: the VMO.
pub const OP_ATTACH: u32 = 901;
/// Show the attached buffer. `a` = window id, `b` = sequence number; payload = damage rects
/// (x i32, y i32, w u32, h u32 each, window-local; none = everything). `EVT_FRAME_DONE` follows.
pub const OP_COMMIT: u32 = 902;
/// Change the title (payload). `a` = window id. The verified identity is never part of it.
pub const OP_SET_TITLE: u32 = 903;
/// Destroy a window. `a` = window id.
pub const OP_DESTROY: u32 = 904;
/// The shipped fonts: reply with one read-only VMO handle (a font pack, `dosui::fonts`) and
/// `a` = its size. `ERR_NOT_FOUND` when the compositor has no fonts.
pub const OP_FONTS: u32 = 905;
/// Name a launcher entry: `a` = entry number (0-3), `b` = flags (`APP_FLAG_PINNED`),
/// payload = label. Shown with the program's verified identity and trust tier.
pub const OP_APP_REGISTER: u32 = 906;
pub const APP_FLAG_PINNED: u64 = 1;

// ---- compositor -> window client (events, txid 0) -----------------------------------------------

/// `a` = window id | state (`STATE_*`) << 32, `b` = client width | height << 32.
pub const EVT_CONFIGURE: u32 = 920;
/// `a` = window id, `b` = key value (`proto::key`, with modifier bits; `proto::key::RELEASE` set
/// when released).
pub const EVT_KEY: u32 = 921;
/// `a` = window id | kind (`PTR_*`) << 32 | buttons << 40 | wheel (i8) << 48,
/// `b` = window-local x (i32) | y (i32) << 32.
pub const EVT_POINTER: u32 = 922;
/// `a` = window id, `b` = 1 focused / 0 not.
pub const EVT_FOCUS: u32 = 923;
/// The user asked to close the window. `a` = window id.
pub const EVT_CLOSE: u32 = 924;
/// The committed frame is on screen. `a` = window id, `b` = its sequence number.
pub const EVT_FRAME_DONE: u32 = 925;
/// A graphical session started (`a` bit 0 = 1; bit 1 = the session asked for the built-in demo
/// windows; bit 2 = a desktop session, which opens the terminal window; `b` = primary output
/// width | height << 32) or ended (`a` = 0: every window is gone).
pub const EVT_SESSION: u32 = 926;
/// The user opened this program's launcher entry `a`.
pub const EVT_LAUNCH: u32 = 927;
/// Settings: `a` = theme | text scale (percent) << 8 | reduce motion << 24; payload = the
/// theme (`dosawmi::THEME_BYTES`).
pub const EVT_SETTINGS: u32 = 928;
/// `awmi.launcher`: user answered the compositor permission prompt (`a` = request_id, `b` = choice:
/// 1 = Allow, 2 = Deny & Launch, 3 = Cancel).
pub const EVT_PERM_RESULT: u32 = 929;

// ---- `awmi.admin`, `awmi.query`, `awmi.indicator` (calls) ---------------------------------------

/// `awmi.admin`: take the screens and the input (the shell's `gui`); `a` = `SESSION_*` flags.
/// Reply `a` = outputs.
pub const OP_SESSION_START: u32 = 930;
/// Open the built-in demo windows.
pub const SESSION_DEMO: u64 = 1;
/// A desktop session: the terminal window opens (a normal boot, the shell's `gui`).
pub const SESSION_DESKTOP: u64 = 2;
/// `awmi.admin`: give the screens and the input back.
pub const OP_SESSION_STOP: u32 = 931;
/// `awmi.query` or `awmi.admin`: payload of the reply = `Status` (`STATUS_BYTES`).
pub const OP_STATUS: u32 = 932;
/// `awmi.indicator`: `a` = indicator bits (`IND_SECURITY_ALERT`).
pub const OP_INDICATOR: u32 = 933;
/// `awmi.admin`: change settings. `a` as in `EVT_SETTINGS`, `b` = which to change (`SET_*`).
/// Reply `a` = the settings now.
pub const OP_SETTINGS: u32 = 934;
pub const SET_THEME: u64 = 1;
pub const SET_TEXT_SCALE: u64 = 2;
pub const SET_MOTION: u64 = 4;
/// `awmi.admin`: configure display mode, VRR, HDR, confirmation, or per-output scale on an output:
/// `a` = adapter_id | (subop `DISPLAY_SET_*` << 32).
pub const OP_SET_DISPLAY: u32 = 936;
pub const DISPLAY_SET_MODE: u8 = 0;
pub const DISPLAY_SET_VRR: u8 = 1;
pub const DISPLAY_SET_HDR: u8 = 2;
pub const DISPLAY_SET_SCALE: u8 = 3;
pub const DISPLAY_CONFIRM_MODE: u8 = 4;
/// `awmi.admin`: engage the unforgeable compositor lock/login screen (`a` = reason 1..4, `b` = mode 1..2).
pub const OP_LOCK: u32 = 937;
pub const LOCK_REASON_BOOT: u64 = 1;
pub const LOCK_REASON_MANUAL: u64 = 2;
pub const LOCK_REASON_IDLE: u64 = 3;
pub const LOCK_REASON_SLEEP: u64 = 4;
pub const LOCK_MODE_LOGIN: u64 = 1;
pub const LOCK_MODE_LOCKED: u64 = 2;
/// `awmi.admin`: push updated idle timeout & sleep-lock policy to the compositor
/// (`a` = idle_timeout_secs | (lock_on_sleep << 32)).
pub const OP_SET_LOCK_POLICY: u32 = 938;
/// `awmi.launcher`: open the unforgeable compositor permission prompt (`a` = request_id,
/// `b` = perm_mask, payload = `<app_name>\0<app_title>`).
pub const OP_PERM_PROMPT: u32 = 939;

// ---- `awmi.admin`, compositor in test mode only ---------------------------------------------------

/// `a` = key value, `b` = 1 pressed / 0 released.
pub const OP_TEST_KEY: u32 = 940;
/// `a` = desktop x | y << 32 (absolute), `b` = buttons.
pub const OP_TEST_POINTER: u32 = 941;
/// Composite what is pending, then reply `a` = the backbuffer pixel at desktop x | y << 32 (`a`).
pub const OP_TEST_PIXEL: u32 = 942;
/// Composite what is pending, then reply with every window (`WindowInfo`, `WINDOW_INFO_BYTES`).
pub const OP_TEST_WINDOWS: u32 = 943;
/// Add a virtual output (memory only) right of the others: `a` = width | height << 32.
pub const OP_TEST_ADD_OUTPUT: u32 = 944;
/// Composite, then reply with a hash of the primary output's backbuffer (`a`) and the number of
/// pixels differing from the desktop background (`b`): what tests check about rendering.
pub const OP_TEST_FRAME: u32 = 945;
/// Test mode: advance idle tracking past `idle_timeout_secs` to trigger idle auto-lock immediately.
pub const OP_TEST_IDLE_EXPIRE: u32 = 946;

// ---- flags & bits -------------------------------------------------------------------------------

/// Window flags (`OP_CREATE`).
pub const FLAG_DECORATED: u32 = 1 << 0;
pub const FLAG_RESIZABLE: u32 = 1 << 1;
pub const FLAG_OPAQUE: u32 = 1 << 2;
pub const FLAGS_DEFAULT: u32 = FLAG_DECORATED | FLAG_RESIZABLE | FLAG_OPAQUE;

/// Window state bits (`EVT_CONFIGURE`).
pub const STATE_FOCUSED: u32 = 1 << 0;
pub const STATE_MAXIMIZED: u32 = 1 << 1;
pub const STATE_SNAPPED: u32 = 1 << 2;
pub const STATE_MINIMIZED: u32 = 1 << 3;

/// Pointer event kinds (`EVT_POINTER`).
pub const PTR_MOVE: u32 = 1;
pub const PTR_BUTTON: u32 = 2;
pub const PTR_WHEEL: u32 = 3;

/// Dock indicators (`Status::indicators`, `OP_INDICATOR`).
pub const IND_MIC_LIVE: u64 = 1 << 0;
pub const IND_SECURITY_ALERT: u64 = 1 << 1;

/// Trust tiers (`WindowInfo::trust`; attached by the service manager).
pub const TRUST_SYSTEM: u8 = 1;
pub const TRUST_NATIVE: u8 = 2;
pub const TRUST_SANDBOX: u8 = 3;

pub const MAX_TITLE: usize = 48;
pub const MAX_DAMAGE: usize = 16;

const CALL_TIMEOUT_NS: u64 = 10_000_000_000;

pub fn window_endpoint() -> Handle {
    svc::endpoint(b"awmi.window")
}
pub fn admin_endpoint() -> Handle {
    svc::endpoint(b"awmi.admin")
}
pub fn query_endpoint() -> Handle {
    svc::endpoint(b"awmi.query")
}
pub fn indicator_endpoint() -> Handle {
    svc::endpoint(b"awmi.indicator")
}
pub fn launcher_endpoint() -> Handle {
    svc::endpoint(b"awmi.launcher")
}

/// A call with an optional handle; the reply header.
fn call(ep: Handle, op: u32, a: u64, b: u64, payload: &[u8], handle: Option<Handle>, reply: &mut [u8]) -> Result<(Header, usize), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    if payload.len() > 512 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let mut req = [0u8; HEADER + 512];
    Header { txid: 0, op, status: 0, a, b }.put(&mut req);
    req[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    let req = &req[..HEADER + payload.len()];
    let n = match handle {
        Some(h) => {
            let mut rh = [0 as Handle; 1];
            sys::channel_call_h(ep, req, &[MsgHandle { handle: h, rights: sys::RIGHTS_SAME }], reply, &mut rh, CALL_TIMEOUT_NS)?.0
        }
        None => sys::channel_call(ep, req, reply, CALL_TIMEOUT_NS)? as usize,
    };
    let h = Header::get(&reply[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok((h, n))
}

fn simple(ep: Handle, op: u32, a: u64, b: u64, payload: &[u8]) -> Result<Header, i64> {
    let mut rep = [0u8; HEADER];
    call(ep, op, a, b, payload, None, &mut rep).map(|(h, _)| h)
}

/// Create a window with a `w` x `h` client area: (window id, configured client width, height).
pub fn create(ep: Handle, w: u32, h: u32, flags: u32, title: &[u8]) -> Result<(u32, u32, u32), i64> {
    let t = &title[..title.len().min(MAX_TITLE)];
    let r = simple(ep, OP_CREATE, u64::from(w) | u64::from(h) << 32, u64::from(flags), t)?;
    Ok((r.a as u32, r.b as u32, (r.b >> 32) as u32))
}

/// Attach `vmo` (duplicated read-only for the compositor) as window `id`'s pixels.
pub fn attach(ep: Handle, id: u32, vmo: Handle, w: u32, h: u32, pitch: u32, format: u32) -> Result<(), i64> {
    let dup = sys::handle_duplicate(vmo, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER)?;
    let mut p = [0u8; 8];
    p[..4].copy_from_slice(&pitch.to_le_bytes());
    p[4..].copy_from_slice(&format.to_le_bytes());
    let mut rep = [0u8; HEADER];
    call(ep, OP_ATTACH, u64::from(id), u64::from(w) | u64::from(h) << 32, &p, Some(dup), &mut rep).map(|_| ())
}

/// Show window `id`'s buffer; `damage` (window-local `(x, y, w, h)`) limits what is redrawn.
pub fn commit(ep: Handle, id: u32, seq: u64, damage: &[(i32, i32, u32, u32)]) -> Result<(), i64> {
    let mut p = [0u8; MAX_DAMAGE * 16];
    let n = damage.len().min(MAX_DAMAGE);
    for (i, &(x, y, w, h)) in damage.iter().take(n).enumerate() {
        let o = i * 16;
        p[o..o + 4].copy_from_slice(&x.to_le_bytes());
        p[o + 4..o + 8].copy_from_slice(&y.to_le_bytes());
        p[o + 8..o + 12].copy_from_slice(&w.to_le_bytes());
        p[o + 12..o + 16].copy_from_slice(&h.to_le_bytes());
    }
    simple(ep, OP_COMMIT, u64::from(id), seq, &p[..n * 16]).map(|_| ())
}

pub fn set_title(ep: Handle, id: u32, title: &[u8]) -> Result<(), i64> {
    simple(ep, OP_SET_TITLE, u64::from(id), 0, &title[..title.len().min(MAX_TITLE)]).map(|_| ())
}

pub fn destroy(ep: Handle, id: u32) -> Result<(), i64> {
    simple(ep, OP_DESTROY, u64::from(id), 0, &[]).map(|_| ())
}

/// The shipped fonts: a read-only mapping of the font pack (programs keep it for their life).
pub fn fonts(ep: Handle) -> Result<Mapping, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_FONTS, status: 0, a: 0, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let mut hs = [0 as Handle; 1];
    let (n, nh) = sys::channel_call_h(ep, &req, &[], &mut rep, &mut hs, CALL_TIMEOUT_NS)?;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        if nh > 0 {
            sys::handle_close(hs[0]);
        }
        return Err(i64::from(h.status));
    }
    if nh == 0 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    Mapping::of_ro(hs[0], h.a).inspect_err(|_| {
        sys::handle_close(hs[0]);
    })
}

/// Register launcher entry `app` (0-3) with `label`.
pub fn register_app(ep: Handle, app: u8, label: &[u8]) -> Result<(), i64> {
    register_app_pinned(ep, app, label, false)
}

/// Register launcher entry `app` (0-15) with `label`, optionally pinned in the floating dock.
pub fn register_app_pinned(ep: Handle, app: u8, label: &[u8], pinned: bool) -> Result<(), i64> {
    let flags = if pinned { APP_FLAG_PINNED } else { 0 };
    simple(ep, OP_APP_REGISTER, u64::from(app), flags, &label[..label.len().min(32)]).map(|_| ())
}

/// Register launcher entry on `awmi.launcher` with explicit `<label>\0<verified_app_id>`.
pub fn register_launcher_app(ep: Handle, app: u8, label: &[u8], app_id: &[u8], pinned: bool) -> Result<(), i64> {
    let mut p = [0u8; 64];
    let ll = label.len().min(32);
    let il = app_id.len().min(24);
    p[..ll].copy_from_slice(&label[..ll]);
    p[ll] = 0;
    p[ll + 1..ll + 1 + il].copy_from_slice(&app_id[..il]);
    let flags = if pinned { APP_FLAG_PINNED } else { 0 };
    simple(ep, OP_APP_REGISTER, u64::from(app), flags, &p[..ll + 1 + il]).map(|_| ())
}

/// Engage the compositor lock/login screen (`awmi.admin`).
pub fn lock_session(ep: Handle, reason: u64, mode: u64) -> Result<(), i64> {
    simple(ep, OP_LOCK, reason, mode, &[]).map(|_| ())
}

/// Push updated idle auto-lock & sleep-lock policy to `awmi` (`awmi.admin`).
pub fn set_lock_policy(ep: Handle, idle_timeout_secs: u32, lock_on_sleep: bool) -> Result<(), i64> {
    let a = u64::from(idle_timeout_secs) | (u64::from(lock_on_sleep) << 32);
    simple(ep, OP_SET_LOCK_POLICY, a, 0, &[]).map(|_| ())
}

/// Open the compositor permission prompt modal (`awmi.launcher`).
pub fn open_perm_prompt(ep: Handle, request_id: u32, perm_mask: u32, app_name: &[u8], app_title: &[u8]) -> Result<(), i64> {
    let mut p = [0u8; 64];
    let nl = app_name.len().min(24);
    let tl = app_title.len().min(32);
    p[..nl].copy_from_slice(&app_name[..nl]);
    p[nl] = 0;
    p[nl + 1..nl + 1 + tl].copy_from_slice(&app_title[..tl]);
    simple(ep, OP_PERM_PROMPT, u64::from(request_id), u64::from(perm_mask), &p[..nl + 1 + tl]).map(|_| ())
}

/// Test mode (`awmi.admin`): force idle timer expiry to trigger idle auto-lock.
pub fn test_idle_expire(ep: Handle) -> Result<(), i64> {
    simple(ep, OP_TEST_IDLE_EXPIRE, 0, 0, &[]).map(|_| ())
}

/// Change settings (`which`: `SET_*` bits); the settings now.
pub fn set_settings(ep: Handle, packed: u64, which: u64) -> Result<u64, i64> {
    simple(ep, OP_SETTINGS, packed, which, &[]).map(|h| h.a)
}

/// Switch display mode/refresh rate on `adapter_id` (0 = active primary PCI output) via `awmi.admin`.
/// `flags`: bit 0 = allow DSC, bit 1 = allow DP link retrain. Guarded by verify-and-revert in the driver.
pub fn set_display_mode(
    ep: Handle,
    adapter_id: u32,
    width: u32,
    height: u32,
    refresh_mhz: u32,
    flags: u32,
) -> Result<(), i64> {
    let mut p = [0u8; 16];
    p[0..4].copy_from_slice(&width.to_le_bytes());
    p[4..8].copy_from_slice(&height.to_le_bytes());
    p[8..12].copy_from_slice(&refresh_mhz.to_le_bytes());
    p[12..16].copy_from_slice(&flags.to_le_bytes());
    let a = u64::from(adapter_id) | (u64::from(DISPLAY_SET_MODE) << 32);
    simple(ep, OP_SET_DISPLAY, a, 0, &p).map(|_| ())
}

/// Enable or disable Variable Refresh Rate (FreeSync / Adaptive-Sync) via `awmi.admin`.
pub fn set_display_vrr(ep: Handle, adapter_id: u32, enable: bool, min_hz: u16, max_hz: u16) -> Result<(), i64> {
    let a = u64::from(adapter_id) | (u64::from(DISPLAY_SET_VRR) << 32);
    let b = u64::from(enable) | (u64::from(min_hz) << 16) | (u64::from(max_hz) << 32);
    simple(ep, OP_SET_DISPLAY, a, b, &[]).map(|_| ())
}

/// Enable or disable 10-bit HDR10 scanout via `awmi.admin`.
pub fn set_display_hdr(ep: Handle, adapter_id: u32, enable: bool) -> Result<(), i64> {
    let a = u64::from(adapter_id) | (u64::from(DISPLAY_SET_HDR) << 32);
    simple(ep, OP_SET_DISPLAY, a, u64::from(enable), &[]).map(|_| ())
}

/// Set per-output UI/text scale percentage (`100..=200` in 25% steps, or `0` for auto) via `awmi.admin`.
pub fn set_output_scale(ep: Handle, adapter_id: u32, scale_pct: u16) -> Result<(), i64> {
    let a = u64::from(adapter_id) | (u64::from(DISPLAY_SET_SCALE) << 32);
    simple(ep, OP_SET_DISPLAY, a, u64::from(scale_pct), &[]).map(|_| ())
}

/// Confirm (`confirm = true`) or immediately revert (`confirm = false`) a pending 12-second
/// modeset on `adapter_id` via `awmi.admin`.
pub fn confirm_display_mode(ep: Handle, adapter_id: u32, confirm: bool) -> Result<(), i64> {
    let a = u64::from(adapter_id) | (u64::from(DISPLAY_CONFIRM_MODE) << 32);
    simple(ep, OP_SET_DISPLAY, a, u64::from(confirm), &[]).map(|_| ())
}

/// Test hook: (hash of the primary output's pixels, pixels that are not the desktop background).
pub fn test_frame(ep: Handle) -> Result<(u64, u64), i64> {
    simple(ep, OP_TEST_FRAME, 0, 0, &[]).map(|h| (h.a, h.b))
}

/// Start the session (`demo`: with the built-in demo windows); the number of outputs.
pub fn session_start(ep: Handle, demo: bool) -> Result<u32, i64> {
    session_start_with(ep, if demo { SESSION_DEMO } else { 0 })
}

/// Start the session with `SESSION_*` flags; the number of outputs.
pub fn session_start_with(ep: Handle, flags: u64) -> Result<u32, i64> {
    simple(ep, OP_SESSION_START, flags, 0, &[]).map(|h| h.a as u32)
}

pub fn session_stop(ep: Handle) -> Result<(), i64> {
    simple(ep, OP_SESSION_STOP, 0, 0, &[]).map(|_| ())
}

pub fn set_indicators(ep: Handle, bits: u64) -> Result<(), i64> {
    simple(ep, OP_INDICATOR, bits, 0, &[]).map(|_| ())
}

/// The compositor's status (64 bytes on the wire; the layout is `dosawmi::AwmiStatus`'s).
pub const STATUS_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
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
    /// Keys from the keyboard (not test injections) the compositor received during sessions.
    pub input_keys: u32,
    /// Pointer events from a mouse or tablet the compositor received during sessions.
    pub input_pointer: u32,
    /// Theme | text scale << 8 | reduce motion << 24 (as `EVT_SETTINGS`).
    pub settings: u32,
    pub launcher_open: bool,
    /// The vector fonts are loaded.
    pub fonts: bool,
    /// Launcher entries registered by programs.
    pub apps: u8,
    /// Compositor lock / login screen is engaged.
    pub locked: bool,
}

impl Status {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < STATUS_BYTES {
            return None;
        }
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| u64::from(u32_at(o)) | u64::from(u32_at(o + 4)) << 32;
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
            locked: b[63] != 0,
        })
    }
}

pub fn status(ep: Handle) -> Result<Status, i64> {
    let mut rep = [0u8; HEADER + STATUS_BYTES];
    let (_, n) = call(ep, OP_STATUS, 0, 0, &[], None, &mut rep)?;
    Status::decode(&rep[HEADER..n]).ok_or(sys::ERR_INVALID_ARGS)
}

/// One window as the test hook reports it (`OP_TEST_WINDOWS`; 128 bytes on the wire).
pub const WINDOW_INFO_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowInfo {
    pub id: u32,
    pub frame: (i32, i32, u32, u32),
    pub client: (i32, i32, u32, u32),
    pub trust: u8,
    pub workspace: u8,
    pub minimized: bool,
    pub focused: bool,
    pub identity: [u8; 24],
    pub identity_len: u8,
    pub title: [u8; MAX_TITLE],
    pub title_len: u8,
}

impl Default for WindowInfo {
    fn default() -> Self {
        Self {
            id: 0,
            frame: (0, 0, 0, 0),
            client: (0, 0, 0, 0),
            trust: 0,
            workspace: 0,
            minimized: false,
            focused: false,
            identity: [0; 24],
            identity_len: 0,
            title: [0; MAX_TITLE],
            title_len: 0,
        }
    }
}

impl WindowInfo {
    pub fn identity(&self) -> &[u8] {
        &self.identity[..usize::from(self.identity_len).min(24)]
    }
    pub fn title(&self) -> &[u8] {
        &self.title[..usize::from(self.title_len).min(MAX_TITLE)]
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < WINDOW_INFO_BYTES {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let rect = |o: usize| (u32_at(o) as i32, u32_at(o + 4) as i32, u32_at(o + 8), u32_at(o + 12));
        let mut w = Self { id: u32_at(0), frame: rect(4), client: rect(20), trust: b[36], workspace: b[37], minimized: b[38] != 0, focused: b[39] != 0, ..Self::default() };
        w.identity_len = b[40].min(24);
        w.title_len = b[41].min(MAX_TITLE as u8);
        w.identity.copy_from_slice(&b[44..68]);
        w.title.copy_from_slice(&b[68..68 + MAX_TITLE]);
        Some(w)
    }
}

pub fn test_key(ep: Handle, key: u32, pressed: bool) -> Result<(), i64> {
    simple(ep, OP_TEST_KEY, u64::from(key), u64::from(pressed), &[]).map(|_| ())
}

pub fn test_pointer(ep: Handle, x: i32, y: i32, buttons: u8) -> Result<(), i64> {
    simple(ep, OP_TEST_POINTER, u64::from(x as u32) | u64::from(y as u32) << 32, u64::from(buttons), &[]).map(|_| ())
}

pub fn test_pixel(ep: Handle, x: i32, y: i32) -> Result<u32, i64> {
    simple(ep, OP_TEST_PIXEL, u64::from(x as u32) | u64::from(y as u32) << 32, 0, &[]).map(|h| h.a as u32)
}

pub fn test_add_output(ep: Handle, w: u32, h: u32) -> Result<(), i64> {
    simple(ep, OP_TEST_ADD_OUTPUT, u64::from(w) | u64::from(h) << 32, 0, &[]).map(|_| ())
}

/// Every window (at most `out.len()`); the count.
pub fn test_windows(ep: Handle, out: &mut [WindowInfo]) -> Result<usize, i64> {
    let mut rep = [0u8; HEADER + 16 * WINDOW_INFO_BYTES];
    let (_, n) = call(ep, OP_TEST_WINDOWS, 0, 0, &[], None, &mut rep)?;
    let body = &rep[HEADER..n];
    let count = (body.len() / WINDOW_INFO_BYTES).min(out.len());
    for (i, slot) in out.iter_mut().take(count).enumerate() {
        *slot = WindowInfo::decode(&body[i * WINDOW_INFO_BYTES..]).unwrap_or_default();
    }
    Ok(count)
}

/// An event for a window client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Configure { window: u32, state: u32, width: u32, height: u32 },
    Key { window: u32, key: u32 },
    Pointer { window: u32, kind: u32, x: i32, y: i32, buttons: u8, wheel: i8 },
    Focus { window: u32, focused: bool },
    Close { window: u32 },
    FrameDone { window: u32, seq: u64 },
    Session { active: bool, demo: bool, desktop: bool, width: u32, height: u32 },
    Launch { app: u8 },
    /// `settings` as in `EVT_SETTINGS`; `theme` the encoded colours (`THEME_LEN` bytes used).
    Settings { settings: u64, theme: [u8; THEME_MAX] },
    /// `awmi.launcher`: compositor modal permission prompt answer.
    PermResult { request_id: u32, choice: u8 },
}

/// Room for an encoded theme in `Event::Settings`.
pub const THEME_MAX: usize = 192;

impl Event {
    pub fn decode(msg: &[u8]) -> Option<Self> {
        let h = Header::get(msg)?;
        let window = h.a as u32;
        Some(match h.op {
            EVT_CONFIGURE => Self::Configure { window, state: (h.a >> 32) as u32, width: h.b as u32, height: (h.b >> 32) as u32 },
            EVT_KEY => Self::Key { window, key: h.b as u32 },
            EVT_POINTER => Self::Pointer {
                window,
                kind: ((h.a >> 32) & 0xFF) as u32,
                x: h.b as u32 as i32,
                y: (h.b >> 32) as u32 as i32,
                buttons: (h.a >> 40) as u8,
                wheel: (h.a >> 48) as u8 as i8,
            },
            EVT_FOCUS => Self::Focus { window, focused: h.b != 0 },
            EVT_CLOSE => Self::Close { window },
            EVT_FRAME_DONE => Self::FrameDone { window, seq: h.b },
            EVT_SESSION => Self::Session { active: h.a & 1 != 0, demo: h.a & 2 != 0, desktop: h.a & 4 != 0, width: h.b as u32, height: (h.b >> 32) as u32 },
            EVT_LAUNCH => Self::Launch { app: h.a as u8 },
            EVT_SETTINGS => {
                let mut theme = [0u8; THEME_MAX];
                let body = &msg[HEADER.min(msg.len())..];
                let n = body.len().min(THEME_MAX);
                theme[..n].copy_from_slice(&body[..n]);
                Self::Settings { settings: h.a, theme }
            }
            EVT_PERM_RESULT => Self::PermResult { request_id: h.a as u32, choice: h.b as u8 },
            _ => return None,
        })
    }
}

/// The next event on a window channel, waiting up to `timeout` ns.
pub fn next_event(ep: Handle, timeout: u64) -> Result<Option<Event>, i64> {
    let mut buf = [0u8; HEADER + THEME_MAX];
    loop {
        let mut hs = [0 as Handle; 1];
        let (n, nh) = match sys::channel_read_h(ep, &mut buf, &mut hs, timeout) {
            Ok(r) => r,
            Err(sys::ERR_SHOULD_WAIT | sys::ERR_TIMED_OUT) => return Ok(None),
            Err(e) => return Err(e),
        };
        if nh > 0 {
            sys::handle_close(hs[0]);
        }
        if let Some(e) = Event::decode(&buf[..n]) {
            return Ok(Some(e));
        }
    }
}

/// A window with its own XRGB8888 pixel buffer (the program draws into `pixels()`).
pub struct Window {
    pub ep: Handle,
    pub id: u32,
    pub width: u32,
    pub height: u32,
    map: Option<Mapping>,
    seq: u64,
}

impl Window {
    /// Create a window and a buffer of its configured size.
    pub fn new(ep: Handle, w: u32, h: u32, flags: u32, title: &[u8]) -> Result<Window, i64> {
        let (id, cw, ch) = create(ep, w, h, flags, title)?;
        let mut win = Window { ep, id, width: 0, height: 0, map: None, seq: 0 };
        win.resize(cw, ch)?;
        Ok(win)
    }

    /// A new buffer of `w` x `h` (after `Event::Configure`); the old one is released.
    pub fn resize(&mut self, w: u32, h: u32) -> Result<(), i64> {
        if w == 0 || h == 0 || w > 8192 || h > 8192 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        if self.width == w && self.height == h && self.map.is_some() {
            return Ok(());
        }
        let map = Mapping::new(u64::from(w) * u64::from(h) * 4)?;
        attach(self.ep, self.id, map.vmo, w, h, w * 4, crate::gpu::FMT_XRGB8888)?;
        if let Some(old) = self.map.replace(map) {
            sys::vmar_unmap(crate::root_vmar(), old.addr, old.len);
            sys::handle_close(old.vmo);
        }
        self.width = w;
        self.height = h;
        Ok(())
    }

    /// The pixels (XRGB8888, `width * 4` bytes per row).
    pub fn pixels(&mut self) -> &mut [u8] {
        match self.map.as_mut() {
            Some(m) => {
                let n = (self.width as usize) * (self.height as usize) * 4;
                &mut m.bytes_mut()[..n]
            }
            None => &mut [],
        }
    }

    /// Show what was drawn (`damage` empty: the whole window).
    pub fn commit(&mut self, damage: &[(i32, i32, u32, u32)]) -> Result<u64, i64> {
        self.seq += 1;
        commit(self.ep, self.id, self.seq, damage)?;
        Ok(self.seq)
    }

    pub fn set_title(&self, title: &[u8]) -> Result<(), i64> {
        set_title(self.ep, self.id, title)
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = destroy(self.ep, self.id);
        if let Some(m) = self.map.take() {
            sys::vmar_unmap(crate::root_vmar(), m.addr, m.len);
            sys::handle_close(m.vmo);
        }
    }
}
