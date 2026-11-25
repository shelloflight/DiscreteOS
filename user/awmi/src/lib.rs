//! D-AWMI (`awmi.dsvc`, docs/awmi.md): D-OS's compositor and window manager.
//!
//! Idle at boot: no screen, no input, a few pages of memory. `OP_SESSION_START` (the shell's
//! `gui`) takes the session:
//! 1. outputs from `gpu.display` (the firmware framebuffer the terminal uses when there is one,
//!    otherwise every online PCI GPU), one offscreen backbuffer VMO each, attached once (zero-copy
//!    IOMMU scanout on PCI GPUs, write-combining blits on the firmware framebuffer);
//! 2. the screen from the terminal (`terminal.display`) and the keyboard and pointer from the
//!    device manager (`devmgr.input` exclusive grab: nothing typed reaches the shell meanwhile);
//! 3. an event loop: client requests, input, and a refresh-paced frame timer that composites only
//!    the damaged rectangles (`dosawmi::WmState`) and presents just those.
//!
//! `Super+Esc` / `Ctrl+Alt+Esc` or `OP_SESSION_STOP` end it: every window is closed, the grab
//! released, the terminal redraws. If this service exits or crashes, the device manager and the
//! terminal see their channels close and take input and screen back on their own.
//!
//! Isolation: a client draws only into its own VMO (mapped here read-only), names only the windows
//! it created on its channel, and gets keys only while its window is focused and pointer events
//! only over its window. The title bar's identity and trust dot come from the service manager
//! (`provides.identify`), never from the client.
//!
//! The UI foundation (docs/ui.md): the shipped faces (`sys:/fonts`) are read once at start and
//! drawn with `dosfont` (the chrome, the dock, the launcher) and shared read-only with window
//! programs (`OP_FONTS`); the themes come from `sys:/themes` (built-in copies if missing); the
//! launcher (tap Super, Alt+F1) opens programs' entries and the accessibility actions; settings
//! (theme, text size, reduce motion) are sent to every window program. With the argument
//! `autostart` (a normal boot) a desktop session starts as soon as there is a display.

#![no_std]

extern crate alloc;

mod app;
mod console;
mod demo;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosawmi::{
    AwmiStatus, BitmapText, Canvas, CursorKind, DamageSet, LockIdentity, LockMode, LockReason, MAX_IDENTITY_BYTES, Point, Rect, STATUS_BYTES, Setting, SurfaceView, THEME_BYTES, Theme, ThemeId, TrustTier, UiSettings,
    WINDOW_INFO_BYTES, WmAction, WmState, encode_window_info, split_connect,
};
use dosui::{FontText, fonts};
use libd::fs as fp;
use libd::awmi as wire;
use libd::gpu::{self, AdapterInfo, ModeEntry};
use libd::identity as idwire;
use libd::proto::{self, HEADER, Header, key};
use libd::sys::{self, Handle};
use libd::{Mapping, Port, Startup, println, svc, term, time};

libd::entry!(dsvc_awmi, main);
libd::entry!(dsvc_awmi_demo, demo::main);
libd::entry!(dx_console, console::main);

const KEY_CTL: u64 = 1;
const KEY_INPUT: u64 = 2;
const KEY_GPU: u64 = 3;
const KEY_CLIENT_BASE: u64 = 0x1000;

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;
/// How often the dock's clock, network, audio and microphone state is refreshed in a session.
const TRAY_POLL_NS: u64 = 500 * MS;
const MAX_WINDOWS_PER_CLIENT: usize = 16;
/// Largest client buffer accepted (8192 x 8192 would be 256 MiB: refused).
const MAX_SURFACE_BYTES: u64 = 64 << 20;
const MAX_CLIENTS: usize = 64;
/// How long a boot waits for a display before staying in the text console.
const AUTOSTART_WAIT_NS: u64 = 20 * SEC;
/// Largest font or theme file read from the system volume.
const MAX_FONT_FILE: usize = 8 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Window,
    Admin,
    Query,
    Indicator,
    Launcher,
}

struct Client {
    id: u32,
    ch: Handle,
    role: Role,
    identity: [u8; MAX_IDENTITY_BYTES],
    identity_len: usize,
    trust: TrustTier,
}

/// A client's pixels: its VMO, mapped read-only here.
struct Surface {
    window: u32,
    owner: u32,
    map: Mapping,
    width: u32,
    height: u32,
    pitch: u32,
    /// Sequence number of a commit waiting for `EVT_FRAME_DONE`.
    pending: Option<u64>,
    /// What the client was last told (`EVT_CONFIGURE`, `EVT_FOCUS`): client size and state bits.
    told: (u32, u32, u32),
    /// A new buffer attached (a resize) but not committed yet: the current one stays on screen,
    /// and its pending frame is still answered, until the client commits into the new one.
    staged: Option<Box<Surface>>,
}

impl Drop for Surface {
    fn drop(&mut self) {
        if self.map.len != 0 {
            sys::vmar_unmap(libd::root_vmar(), self.map.addr, self.map.len);
        }
        if self.map.vmo != 0 {
            sys::handle_close(self.map.vmo);
        }
    }
}

/// One output's backbuffer (kept across sessions: the GPU keeps its GEM BO & KMS FB attached).
struct OutBuf {
    /// `gpu.dsvc` adapter id (0: a virtual output, memory only, test mode).
    adapter: u32,
    restarts: u32,
    gem_handle: u32,
    fb_id: u32,
    map: Mapping,
    width: u32,
    height: u32,
    refresh_mhz: u32,
    hw_cursor: bool,
    async_flip: bool,
    native_kms: bool,
}

/// The backbuffer's pixels as `u32`s.
fn pixels_of(map: &mut Mapping, len_px: usize) -> &mut [u32] {
    let bytes = map.bytes_mut();
    assert!(bytes.len() >= len_px * 4 && (bytes.as_ptr() as usize).is_multiple_of(4));
    // SAFETY: the mapping is page-aligned (so 4-byte aligned), at least `len_px * 4` bytes long
    // (checked), private to this process and borrowed mutably for the slice's lifetime.
    unsafe { core::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<u32>(), len_px) }
}

struct RegisteredApp {
    owner: u32,
    app: u8,
    label: Vec<u8>,
    identity: Vec<u8>,
    trust: TrustTier,
    pinned: bool,
}

struct Awmi {
    port: Port,
    ctl: Handle,
    input: Handle,
    term: Handle,
    gpu: Handle,
    clock: Handle,
    audio: Handle,
    net: Handle,
    identity: Handle,
    test_mode: bool,
    firmware_display: bool,
    lock_at_boot_cfg: bool,
    idle_timeout_ns: u64,
    lock_on_sleep: bool,
    last_input_ns: u64,
    session_notified: bool,
    pending_perm_owner: u32,
    clients: Vec<Client>,
    next_client: u32,
    wm: Box<WmState>,
    surfaces: Vec<Surface>,
    outs: Vec<OutBuf>,
    active: bool,
    demo: bool,
    frames: u64,
    flushes: u64,
    input_keys: u32,
    input_pointer: u32,
    next_frame: u64,
    next_tray: u64,
    /// True while an asynchronous vsync flip is in flight waiting for `gpu::EVT_FLIP_DONE`.
    flip_pending: bool,
    /// Safety timeout for an in-flight async flip (recovers if a driver restarts mid-flip).
    flip_deadline: u64,
    /// Timestamp of the last completed vsync flip.
    last_flip_ns: u64,
    /// When a frame missed its refresh deadline, hold the next composite until this time so we
    /// drop cleanly to every other refresh rather than tearing.
    pace_skip_until: u64,
    /// The pointer moved since the last frame (hardware cursor position to update if software/deferred).
    cursor_moved: bool,
    cursor_map: Option<Mapping>,
    cursor_adapter: u32,
    cursor_restarts: u32,
    cursor_gem: u32,
    cursor_fb: u32,
    hw_cursor_kind: CursorKind,
    /// Indicators set over `awmi.indicator`, and the microphone state polled from the audio service.
    ext_indicators: u64,
    mic_live: bool,
    clock_base: Option<time::Base>,
    /// Output list or mode changed: outputs are reconciled at the next frame.
    reattach: bool,
    /// A present failed: force re-attaching client backbuffer VMOs even if dimensions match.
    force_reattach_fb: bool,
    /// Post-modeset redraw timer: DisplayPort monitors take ~1-2.5s to re-lock on refresh changes;
    /// schedule a handful of full-frame repaints so the desktop is always live once the panel wakes.
    modeset_redraw_at: u64,
    modeset_redraw_left: u8,
    /// The vector text engine over the font pack (None: the bitmap font draws).
    text: Option<FontText<'static>>,
    /// The font pack VMO and its size (shared read-only with window programs).
    pack_vmo: Handle,
    pack_len: u64,
    /// Dark Slate and High Contrast as read from the system volume.
    themes: [Theme; 2],
    settings: UiSettings,
    /// The text size was chosen (`OP_SETTINGS`, the launcher): not sized for the display any more.
    scale_set: bool,
    /// Per-output explicit scale overrides (`(adapter_id, scale_pct)`).
    output_scales: Vec<(u32, u16)>,
    /// Launcher entries programs/appmgr registered; replayed into each session.
    apps: Vec<RegisteredApp>,
    /// What the session was started with (`SESSION_DEMO`, `SESSION_DESKTOP`).
    session_flags: u64,
    /// Boot: start a desktop session once a display is there (until this time).
    autostart_until: u64,
}

/// Read a whole file from the system volume (`/sys` in this service's namespace).
fn read_sys(path: &[u8], max: usize) -> Option<Vec<u8>> {
    let ns = fp::Namespace::get();
    let (dir, rest) = ns.resolve(path)?;
    let d = fp::Node::from(dir);
    let out = (|| {
        let (f, _, size) = d.open(rest, 0, fp::R_READ).ok()?;
        let size = usize::try_from(size).ok()?;
        if size == 0 || size > max {
            return None;
        }
        let mut buf = alloc::vec![0u8; size];
        let n = f.read(0, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    })();
    let _ = d.into_handle(); // the namespace keeps its directory
    out
}

/// The shipped faces as one font pack in a VMO; `None` without fonts (the bitmap font is used).
fn load_fonts() -> Option<(Mapping, u64)> {
    let mut files: Vec<(dosfont::Face, Vec<u8>)> = Vec::new();
    for (face, name) in fonts::FACE_FILES {
        let mut path = Vec::from(&b"/sys/fonts/"[..]);
        path.extend_from_slice(name.as_bytes());
        match read_sys(&path, MAX_FONT_FILE) {
            Some(d) if dosfont::Font::parse(&d).is_ok() => files.push((face, d)),
            _ => println!("awmi: font {} missing or invalid", name),
        }
    }
    if files.is_empty() {
        return None;
    }
    let refs: Vec<(dosfont::Face, &[u8])> = files.iter().map(|(f, d)| (*f, d.as_slice())).collect();
    let pack = fonts::build(&refs);
    let mut map = Mapping::new(pack.len() as u64).ok()?;
    map.bytes_mut()[..pack.len()].copy_from_slice(&pack);
    println!("awmi: fonts: {} face(s), {} KiB (shared read-only with window programs)", files.len(), pack.len() / 1024);
    Some((map, pack.len() as u64))
}

/// A theme from `sys:/themes`, or the built-in copy.
fn load_theme(id: ThemeId) -> Theme {
    let mut path = Vec::from(&b"/sys/themes/"[..]);
    path.extend_from_slice(id.file().as_bytes());
    match read_sys(&path, 64 * 1024).map(|d| Theme::from_toml(&String::from_utf8_lossy(&d))) {
        Some(Ok(t)) => t,
        Some(Err(e)) => {
            println!("awmi: theme {} refused ({:?}): the built-in one is used", id.file(), e);
            id.builtin()
        }
        None => id.builtin(),
    }
}

impl Awmi {
    // ---- channels from the service manager --------------------------------------------------------

    fn on_ctl(&mut self) -> bool {
        let mut buf = [0u8; HEADER + 128];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        svc::CONNECT if hnd != 0 => self.connect(&buf[HEADER..n], h.b, hnd),
                        svc::SUSPEND => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            if self.active && self.lock_on_sleep && !self.wm.lock.active {
                                self.engage_lock_screen(LockMode::Locked, LockReason::Sleep);
                                self.flush();
                            }
                            if h.txid != 0 {
                                let mut rep = [0u8; HEADER];
                                Header { txid: h.txid, op: svc::SUSPEND, status: 0, a: 0, b: 0 }.put(&mut rep);
                                sys::channel_write(self.ctl, &rep);
                            }
                        }
                        svc::SHUTDOWN => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            if self.active {
                                self.session_stop("the system is shutting down");
                            }
                            return false;
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    return true;
                }
                Err(_) => return true,
            }
        }
    }

    fn replace(slot: &mut Handle, h: Handle) {
        if *slot != 0 {
            sys::handle_close(*slot);
        }
        *slot = h;
    }

    fn connect(&mut self, payload: &[u8], tier: u64, hnd: Handle) {
        let (ep, who) = split_connect(payload);
        match ep {
            // Providers restarted: fresh channels.
            b"devmgr.input" => {
                Self::replace(&mut self.input, hnd);
                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
                if self.active {
                    self.grab(true);
                }
            }
            b"terminal.display" => {
                Self::replace(&mut self.term, hnd);
                if self.active {
                    self.term_call(term::DISPLAY_RELEASE);
                }
            }
            b"gpu.display" => {
                Self::replace(&mut self.gpu, hnd);
                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_GPU);
                self.flip_pending = false;
                self.flip_deadline = 0;
                self.reattach = true;
            }
            b"clock.time" => Self::replace(&mut self.clock, hnd),
            b"audio.control" => Self::replace(&mut self.audio, hnd),
            b"net.status" => Self::replace(&mut self.net, hnd),
            b"identity.session" => Self::replace(&mut self.identity, hnd),
            // Our own endpoints: a client, with the identity the service manager verified.
            b"window" | b"admin" | b"query" | b"indicator" | b"launcher" => {
                let role = match ep {
                    b"window" => Role::Window,
                    b"admin" => Role::Admin,
                    b"query" => Role::Query,
                    b"launcher" => Role::Launcher,
                    _ => Role::Indicator,
                };
                self.clients.retain(|c| c.ch != 0);
                if self.clients.len() >= MAX_CLIENTS {
                    println!("awmi: more than {} clients: one refused", MAX_CLIENTS);
                    sys::handle_close(hnd);
                    return;
                }
                let id = self.next_client;
                self.next_client = self.next_client.wrapping_add(1).max(1);
                let mut identity = [0u8; MAX_IDENTITY_BYTES];
                let n = dosawmi::proto::sanitize_label(who, &mut identity);
                let trust = TrustTier::from_u8(tier as u8);
                self.clients.push(Client { id, ch: hnd, role, identity, identity_len: n, trust });
                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + u64::from(id));
                if role == Role::Window && self.active {
                    self.send_settings(hnd);
                    if self.session_notified {
                        self.send_session(hnd, true);
                    }
                } else if role == Role::Launcher && self.active && self.session_notified {
                    self.send_session(hnd, true);
                }
            }
            _ => {
                sys::handle_close(hnd);
            }
        }
    }

    // ---- input ------------------------------------------------------------------------------------

    fn grab(&mut self, on: bool) {
        if self.input == 0 {
            return;
        }
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: proto::INPUT_GRAB, status: 0, a: u64::from(on), b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER];
        match sys::channel_call(self.input, &req, &mut rep, 5 * SEC) {
            Ok(n) if Header::get(&rep[..n as usize]).is_some_and(|h| h.status == 0) => {}
            Ok(n) => println!("awmi: input grab {} refused ({})", if on { "take" } else { "release" }, Header::get(&rep[..n as usize]).map_or(0, |h| h.status)),
            Err(e) => println!("awmi: input grab failed: {}", sys::status(e)),
        }
    }

    fn term_call(&mut self, op: u32) {
        if self.term == 0 {
            return;
        }
        let mut req = [0u8; HEADER];
        Header { txid: 0, op, status: 0, a: 0, b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER];
        let _ = sys::channel_call(self.term, &req, &mut rep, 5 * SEC);
    }

    fn on_input(&mut self) {
        let mut buf = [0u8; HEADER + 32];
        loop {
            match sys::channel_read(self.input, &mut buf, 0) {
                Ok(n) => {
                    let Some(h) = Header::get(&buf[..n as usize]) else { continue };
                    if !self.active {
                        continue; // idle: input is the terminal's (no grab); ours is dropped
                    }
                    match h.op {
                        proto::INPUT_KEY => {
                            self.input_keys = self.input_keys.saturating_add(1);
                            if self.input_keys == 1 {
                                println!("awmi: keys routed to the compositor (input grab held)");
                            }
                            self.key(h.a as u32);
                        }
                        proto::INPUT_POINTER => {
                            self.input_pointer = self.input_pointer.saturating_add(1);
                            if self.input_pointer == 1 {
                                println!("awmi: pointer input routed to the compositor (grab held)");
                            }
                            self.pointer_raw(h.a, h.b);
                        }
                        _ => {}
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
                    return;
                }
                Err(_) => return, // the device manager is gone; the service manager links us again
            }
        }
    }

    fn key(&mut self, k: u32) {
        let now = sys::clock_ns();
        self.wm.now_ns = now;
        self.last_input_ns = now;
        let pressed = k & key::RELEASE == 0;
        let action = self.wm.handle_key(k & !key::RELEASE, pressed);
        match action {
            WmAction::DeliverKey { owner, window_id } => self.send_to(owner, wire::EVT_KEY, u64::from(window_id), u64::from(k)),
            other => self.act(other),
        }
        self.sync_windows();
    }

    /// A pointer event from the device manager: relative motion, or absolute `[0, 32767]` from a
    /// tablet (QEMU) mapped onto the whole desktop.
    fn pointer_raw(&mut self, a: u64, b: u64) {
        let buttons = (b & 0xFF) as u8;
        let wheel = ((b >> 8) & 0xFF) as u8 as i8;
        if b & proto::POINTER_ABS != 0 {
            let d = self.wm.layout.desktop_bounds();
            let ax = i64::from((a as u32).min(32767));
            let ay = i64::from(((a >> 32) as u32).min(32767));
            let x = i64::from(d.x) + ax * i64::from(d.w) / 32768;
            let y = i64::from(d.y) + ay * i64::from(d.h) / 32768;
            self.pointer(0, 0, Some(Point::new(x as i32, y as i32)), buttons, wheel);
        } else {
            self.pointer(a as u32 as i32, (a >> 32) as u32 as i32, None, buttons, wheel);
        }
    }

    fn pointer(&mut self, dx: i32, dy: i32, abs: Option<Point>, buttons: u8, wheel: i8) {
        self.last_input_ns = sys::clock_ns();
        let before = (self.wm.pointer, self.wm.buttons);
        let action = self.wm.handle_pointer(dx, dy, abs, buttons);
        if self.outs.iter().any(|o| o.hw_cursor) && self.wm.cursor_kind != self.hw_cursor_kind {
            self.upload_cursor();
        }
        if self.wm.pointer != before.0 {
            if let Some(o) = self.outs.iter().find(|o| o.hw_cursor) {
                // Hardware cursor plane moves atomically without triggering a full frame composite.
                let p = self.wm.pointer;
                let _ = gpu::kms_set_cursor_atomic(self.gpu, o.adapter, 0, p.x, p.y, 0, 0);
            } else {
                self.cursor_moved = true;
            }
        }
        if let WmAction::DeliverPointer { owner, window_id, local_x, local_y } = action {
            let kind = if wheel != 0 {
                wire::PTR_WHEEL
            } else if buttons != before.1 {
                wire::PTR_BUTTON
            } else {
                wire::PTR_MOVE
            };
            let a = u64::from(window_id) | u64::from(kind) << 32 | u64::from(buttons) << 40 | u64::from(wheel as u8) << 48;
            let b = u64::from(local_x as u32) | u64::from(local_y as u32) << 32;
            self.send_to(owner, wire::EVT_POINTER, a, b);
        } else {
            self.act(action);
        }
        self.sync_windows();
    }

    fn sync_lock_identities(&mut self) -> (bool, bool) {
        if self.identity == 0 {
            let mut list = [LockIdentity::EMPTY; 1];
            list[0] = LockIdentity::new(1, b"user", b"Local User", false, false);
            self.wm.lock.set_identities(&list, 1, false);
            return (false, false);
        }
        let mut lock_at_boot = false;
        let mut tpm = false;
        if let Ok(pol) = idwire::policy(self.identity) {
            self.idle_timeout_ns = u64::from(pol.idle_timeout_secs) * SEC;
            self.lock_on_sleep = pol.lock_on_sleep;
            lock_at_boot = pol.lock_at_boot;
            tpm = pol.tpm_available;
        }
        let mut infos = [idwire::IdentityInfo::default(); dosawmi::MAX_LOCK_IDENTITIES];
        let cnt = idwire::list(self.identity, &mut infos).unwrap_or(0);
        let mut active_id = 1u32;
        let mut active_enrolled = false;
        let mut lock_ids = [LockIdentity::EMPTY; dosawmi::MAX_LOCK_IDENTITIES];
        for (i, info) in infos[..cnt].iter().enumerate() {
            lock_ids[i] = LockIdentity::new(
                info.id,
                info.name_str().as_bytes(),
                info.display_str().as_bytes(),
                info.seal == idwire::SEAL_TPM2,
                info.enrolled,
            );
            if info.active {
                active_id = info.id;
                active_enrolled = info.enrolled;
            }
        }
        if cnt > 0 {
            self.wm.lock.set_identities(&lock_ids[..cnt], active_id, tpm);
        }
        (active_enrolled, lock_at_boot)
    }

    fn engage_lock_screen(&mut self, mode: LockMode, reason: LockReason) {
        let _ = self.sync_lock_identities();
        self.wm.engage_lock(mode, reason);
        let why = match reason {
            LockReason::Boot => "boot sign-in",
            LockReason::Manual => "manual",
            LockReason::Idle => "idle timeout",
            LockReason::Sleep => "before sleep",
        };
        println!("awmi: session locked ({})", why);
    }

    fn broadcast_session(&self, active: bool) {
        let chans: Vec<Handle> = self
            .clients
            .iter()
            .filter(|c| matches!(c.role, Role::Window | Role::Launcher) && c.ch != 0)
            .map(|c| c.ch)
            .collect();
        for ch in chans {
            self.send_session(ch, active);
        }
    }

    fn act(&mut self, action: WmAction) {
        match action {
            WmAction::RequestClose { owner, window_id } => self.send_to(owner, wire::EVT_CLOSE, u64::from(window_id), 0),
            WmAction::ExitSession | WmAction::Setting(Setting::LeaveDesktop) => self.session_stop("the user left the session"),
            WmAction::LockSession | WmAction::Setting(Setting::LockScreen) => {
                self.engage_lock_screen(LockMode::Locked, LockReason::Manual);
            }
            WmAction::UnlockAttempt { identity_id } => {
                let mut pass = [0u8; dosawmi::lock::MAX_PASS_BYTES];
                let plen = self.wm.lock.pass_len().min(pass.len());
                pass[..plen].copy_from_slice(&self.wm.lock.passphrase()[..plen]);
                self.wm.lock.clear_passphrase();
                let res = if self.identity != 0 {
                    idwire::authenticate(self.identity, identity_id, &pass[..plen])
                } else {
                    Ok(identity_id)
                };
                pass.fill(0);
                core::hint::black_box(&pass);
                match res {
                    Ok(uid) => {
                        self.wm.disengage_lock();
                        self.last_input_ns = sys::clock_ns();
                        println!("awmi: session unlocked (identity #{})", uid);
                        if !self.session_notified {
                            self.session_notified = true;
                            self.broadcast_session(true);
                        }
                    }
                    Err((_, retry_secs)) => {
                        if retry_secs > 0 {
                            let msg = format!("Too many attempts; retry in {}s", retry_secs);
                            self.wm.lock.set_error(msg.as_bytes());
                        } else {
                            self.wm.lock.set_error(b"Invalid passphrase");
                        }
                        self.wm.damage_all();
                    }
                }
            }
            WmAction::PermPromptResult { request_id, choice } => {
                let owner = self.pending_perm_owner;
                self.pending_perm_owner = 0;
                if owner != 0 {
                    self.send_to(owner, wire::EVT_PERM_RESULT, u64::from(request_id), u64::from(choice));
                }
            }
            WmAction::Launch { owner, app } => {
                println!("awmi: launcher: opening entry {} of client {}", app, owner);
                self.send_to(owner, wire::EVT_LAUNCH, u64::from(app), 0);
            }
            WmAction::Setting(s) => {
                if matches!(s, Setting::TextLarger | Setting::TextSmaller) {
                    self.scale_set = true;
                }
                self.settings = self.settings.apply(s);
                self.apply_settings();
            }
            _ => {}
        }
    }

    // ---- settings ---------------------------------------------------------------------------------

    /// Apply the settings: text engine scale, the window manager's theme and chrome metrics, and
    /// every window program is told.
    fn apply_settings(&mut self) {
        let theme = self.themes[self.settings.theme as usize];
        let (line_h, char_w) = match self.text.as_mut() {
            Some(t) => {
                t.scale = self.settings.text_scale;
                let sample = "The quick brown fox jumps 0123";
                (t.line_height(dosui::TextStyle::Body), t.width(dosui::TextStyle::Body, sample) / sample.len() as u32)
            }
            None => (16, 8),
        };
        self.wm.apply_settings(self.settings, theme, line_h, char_w.max(4));
        let chans: Vec<Handle> = self.clients.iter().filter(|c| c.role == Role::Window && c.ch != 0).map(|c| c.ch).collect();
        for ch in chans {
            self.send_settings(ch);
        }
        println!(
            "awmi: settings: theme {}, text {}%, motion {}",
            self.settings.theme.name(),
            self.settings.text_scale,
            if self.settings.reduce_motion { "reduced" } else { "on" }
        );
    }

    fn send_settings(&self, ch: Handle) {
        let mut m = [0u8; HEADER + THEME_BYTES];
        Header { txid: 0, op: wire::EVT_SETTINGS, status: 0, a: self.settings.pack(), b: 0 }.put(&mut m);
        let mut t = [0u8; THEME_BYTES];
        self.themes[self.settings.theme as usize].encode(&mut t);
        m[HEADER..].copy_from_slice(&t);
        sys::channel_write(ch, &m);
    }

    /// Tell each window's owner about size, state and focus changes (snaps, resizes, workspace
    /// switches, minimizing): one `EVT_CONFIGURE` per change, `EVT_FOCUS` when focus moves.
    fn sync_windows(&mut self) {
        let chrome = self.wm.chrome;
        let focused = self.wm.focused;
        let mut msgs: Vec<(u32, u32, u64, u64)> = Vec::new();
        for s in &mut self.surfaces {
            let Some(w) = self.wm.window(s.window) else { continue };
            let c = w.client_rect(chrome);
            let state = w.state_bits(focused);
            let now = (c.w, c.h, state);
            if now != s.told {
                let was_focused = s.told.2 & wire::STATE_FOCUSED != 0;
                let is_focused = state & wire::STATE_FOCUSED != 0;
                msgs.push((s.owner, wire::EVT_CONFIGURE, u64::from(s.window) | u64::from(state) << 32, u64::from(c.w) | u64::from(c.h) << 32));
                if was_focused != is_focused {
                    msgs.push((s.owner, wire::EVT_FOCUS, u64::from(s.window), u64::from(is_focused)));
                }
                s.told = now;
            }
        }
        for (owner, op, a, b) in msgs {
            self.send_to(owner, op, a, b);
        }
    }

    fn send_to(&self, owner: u32, op: u32, a: u64, b: u64) {
        if let Some(c) = self.clients.iter().find(|c| c.id == owner && c.ch != 0) {
            proto::send(c.ch, op, a, b); // a full or closed client loses the event, never us
        }
    }

    fn send_session(&self, ch: Handle, active: bool) {
        let p = self.wm.layout.primary().map_or(Rect::EMPTY, |o| o.bounds);
        let desktop = active && self.session_flags & wire::SESSION_DESKTOP != 0;
        let a = u64::from(active) | u64::from(active && self.demo) << 1 | u64::from(desktop) << 2;
        proto::send(ch, wire::EVT_SESSION, a, u64::from(p.w) | u64::from(p.h) << 32);
    }

    // ---- outputs & the session --------------------------------------------------------------------

    /// The outputs to use:
    /// - Unless `firmware_display` (`BOOT.CFG display = firmware`), prefer a native KMS PCI output
    ///   (`CAP_NATIVE_KMS`, plus any additional active page-flipping outputs on the same PCI GPU)
    ///   over GOP;
    /// - Otherwise prefer the firmware GOP framebuffer when present, else every online PCI GPU.
    fn choose_adapters(&self) -> Vec<(AdapterInfo, u32)> {
        let mut ads = [AdapterInfo::empty(); 8];
        let n = gpu::list_adapters(self.gpu, &mut ads).unwrap_or(0);
        let online: Vec<AdapterInfo> = ads[..n].iter().copied().filter(|a| a.online && a.width > 0 && a.height > 0).collect();
        let pick: Vec<AdapterInfo> = if !self.firmware_display
            && let Some(nat) = online
                .iter()
                .find(|a| a.kind != gpu::KIND_GOP && (a.caps & gpu::CAP_NATIVE_KMS) != 0)
        {
            let (vendor, device) = (nat.vendor, nat.device);
            online
                .into_iter()
                .filter(|a| {
                    a.vendor == vendor
                        && a.device == device
                        && (a.caps & (gpu::CAP_NATIVE_KMS | gpu::CAP_PAGE_FLIP)) != 0
                })
                .collect()
        } else {
            match online.iter().find(|a| a.kind == gpu::KIND_GOP) {
                Some(g) => alloc::vec![*g],
                None => online,
            }
        };
        pick.into_iter()
            .map(|a| {
                let mut modes = [ModeEntry::default(); 16];
                let m = gpu::get_modes(self.gpu, a.id, &mut modes).unwrap_or(0);
                let hz = modes[..m].iter().find(|e| e.flags & gpu::MODE_FLAG_CURRENT != 0).map_or(60_000, |e| e.refresh_mhz);
                (a, hz)
            })
            .collect()
    }

    /// Attach (or reuse) one GEM-backed KMS framebuffer per chosen adapter; the layout follows.
    fn attach_outputs(&mut self) -> usize {
        let chosen = self.choose_adapters();
        let (virtuals, mut old): (Vec<OutBuf>, Vec<OutBuf>) = self.outs.drain(..).partition(|o| o.adapter == 0);
        let mut kept: Vec<OutBuf> = Vec::new();
        let mut to_alloc: Vec<(gpu::AdapterInfo, u32, bool, bool, bool)> = Vec::new();
        for &(a, hz) in &chosen {
            let (w, h) = (a.width, a.height);
            let hw = chosen.len() == 1 && a.caps & gpu::CAP_HW_CURSOR != 0;
            let async_flip = a.caps & gpu::CAP_ASYNC_FLIP != 0;
            let native_kms = a.caps & gpu::CAP_NATIVE_KMS != 0;
            if let Some(i) = old.iter().position(|o| {
                o.adapter == a.id
                    && o.width == w
                    && o.height == h
                    && o.restarts == a.restarts
                    && !self.force_reattach_fb
            }) {
                let mut reused = old.remove(i);
                if reused.refresh_mhz != hz
                    || reused.hw_cursor != hw
                    || reused.async_flip != async_flip
                    || reused.native_kms != native_kms
                {
                    println!(
                        "awmi: output: adapter #{} '{}' {}x{} @ {}.{:02} Hz (reused backbuffer){}{}",
                        a.id,
                        a.name_str(),
                        w,
                        h,
                        hz / 1000,
                        hz % 1000 / 10,
                        if native_kms { ", native kms" } else { "" },
                        if async_flip { ", async flip" } else { "" }
                    );
                }
                reused.refresh_mhz = hz;
                reused.hw_cursor = hw;
                reused.async_flip = async_flip;
                reused.native_kms = native_kms;
                kept.push(reused);
                continue;
            }
            to_alloc.push((a, hz, hw, async_flip, native_kms));
        }
        // Release incompatible KMS FBs, GEM BOs, and VMOs before allocating new ones so peak memory stays bounded.
        for o in old {
            if o.adapter != 0 && self.gpu != 0 {
                if o.fb_id != 0 {
                    let _ = gpu::kms_destroy_fb(self.gpu, o.adapter, o.fb_id);
                }
                if o.gem_handle != 0 {
                    let _ = gpu::gem_close(self.gpu, o.adapter, o.gem_handle);
                }
            }
            sys::vmar_unmap(libd::root_vmar(), o.map.addr, o.map.len);
            sys::handle_close(o.map.vmo);
        }
        for (a, hz, hw, async_flip, native_kms) in to_alloc {
            let (w, h) = (a.width, a.height);
            let len = u64::from(w) * u64::from(h) * 4;
            let Ok(map) = Mapping::new(len) else {
                println!("awmi: no memory for a {}x{} backbuffer", w, h);
                continue;
            };
            match gpu::kms_attach_scanout_vmo(self.gpu, a.id, map.vmo, w, h, w * 4, gpu::FMT_XRGB8888) {
                Ok((gem_handle, fb_id)) => {
                    println!(
                        "awmi: output: adapter #{} '{}' {}x{} @ {}.{:02} Hz, {} cursor{}{}",
                        a.id,
                        a.name_str(),
                        w,
                        h,
                        hz / 1000,
                        hz % 1000 / 10,
                        if hw { "hardware" } else { "software" },
                        if native_kms { ", native kms" } else { "" },
                        if async_flip { ", async flip" } else { "" }
                    );
                    kept.push(OutBuf {
                        adapter: a.id,
                        restarts: a.restarts,
                        gem_handle,
                        fb_id,
                        map,
                        width: w,
                        height: h,
                        refresh_mhz: hz,
                        hw_cursor: hw,
                        async_flip,
                        native_kms,
                    });
                }
                Err(e) => {
                    println!("awmi: adapter #{} refused the backbuffer: {}", a.id, sys::status(e));
                    sys::vmar_unmap(libd::root_vmar(), map.addr, map.len);
                    sys::handle_close(map.vmo);
                }
            }
        }
        if !chosen.is_empty() && kept.is_empty() {
            // Transient attach failure: keep retrying instead of stranding the desktop with 0 outputs.
            self.reattach = true;
            self.force_reattach_fb = true;
            self.next_frame = sys::clock_ns() + 100 * MS;
        } else {
            self.reattach = false;
            self.force_reattach_fb = false;
        }
        kept.extend(virtuals);
        self.outs = kept;
        self.relayout();
        self.outs.iter().filter(|o| o.adapter != 0).count()
    }

    fn relayout(&mut self) {
        self.wm.layout.clear();
        for o in &self.outs {
            let scale = self
                .output_scales
                .iter()
                .find(|&&(id, _)| id == o.adapter)
                .map_or_else(|| dosawmi::Output::recommended_scale(o.width), |&(_, sc)| sc);
            self.wm.layout.add_output_scaled(o.adapter, o.width, o.height, o.refresh_mhz, o.hw_cursor, scale);
        }
        self.wm.fit_windows_to_layout();
        self.sync_windows();
    }

    fn upload_cursor(&mut self) {
        let Some(o) = self.outs.iter().find(|o| o.hw_cursor) else { return };
        let adapter = o.adapter;
        let restarts = o.restarts;
        let kind = self.wm.cursor_kind;
        if self.cursor_map.is_none() {
            let Ok(m) = Mapping::new(64 * 64 * 4) else { return };
            self.cursor_map = Some(m);
        }
        let Some(m) = self.cursor_map.as_mut() else { return };
        let (hx, hy) = dosawmi::write_hw_cursor_64x64_kind(kind, m.bytes_mut());
        let vmo = m.vmo;

        if self.cursor_adapter != adapter || self.cursor_restarts != restarts || self.cursor_fb == 0 {
            if self.cursor_adapter != 0 && self.cursor_adapter == adapter && self.cursor_restarts == restarts {
                if self.cursor_fb != 0 {
                    let _ = gpu::kms_destroy_fb(self.gpu, self.cursor_adapter, self.cursor_fb);
                }
                if self.cursor_gem != 0 {
                    let _ = gpu::gem_close(self.gpu, self.cursor_adapter, self.cursor_gem);
                }
            }
            self.cursor_adapter = 0;
            self.cursor_gem = 0;
            self.cursor_fb = 0;
            let size = 64 * 64 * 4;
            match gpu::gem_import(self.gpu, adapter, vmo, size, gpu::BO_CURSOR)
                .and_then(|(gh, _)| {
                    gpu::kms_create_fb(self.gpu, adapter, gh, 64, 64, 64 * 4, gpu::FMT_ARGB8888, 0)
                        .map(|fid| (gh, fid))
                        .inspect_err(|_| {
                            let _ = gpu::gem_close(self.gpu, adapter, gh);
                        })
                }) {
                Ok((gh, fid)) => {
                    self.cursor_adapter = adapter;
                    self.cursor_restarts = restarts;
                    self.cursor_gem = gh;
                    self.cursor_fb = fid;
                }
                Err(e) => {
                    println!("awmi: hardware cursor FB refused ({}): software cursor", sys::status(e));
                    for o in &mut self.outs {
                        o.hw_cursor = false;
                    }
                    self.relayout();
                    return;
                }
            }
        }

        let p = self.wm.pointer;
        if let Err(e) = gpu::kms_set_cursor_atomic(
            self.gpu,
            adapter,
            self.cursor_fb,
            p.x,
            p.y,
            hx as u16,
            hy as u16,
        ) {
            println!("awmi: hardware cursor refused ({}): software cursor", sys::status(e));
            for o in &mut self.outs {
                o.hw_cursor = false;
            }
            self.relayout();
        } else {
            self.hw_cursor_kind = kind;
        }
    }

    fn session_start(&mut self, flags: u64) -> Result<u32, i64> {
        if self.active {
            return Ok(self.wm.layout.count as u32);
        }
        *self.wm = WmState::new();
        let mut n = self.attach_outputs();
        if n == 0 && self.gpu != 0 && self.autostart_until == 0 {
            // PCI GPU drivers on `sys:/bin/` spawn concurrently with `awmi`; wait briefly if an
            // explicit `OP_SESSION_START` arrives before `devmgr` finishes binding the GPU.
            let wait_dl = sys::clock_ns() + 4 * SEC;
            while n == 0 && sys::clock_ns() < wait_dl {
                libd::handle::sleep(50 * MS);
                self.on_gpu_event();
                n = self.attach_outputs();
            }
        }
        if n == 0 {
            println!("awmi: no display output: the session cannot start");
            return Err(sys::ERR_NOT_SUPPORTED);
        }
        self.demo = flags & wire::SESSION_DEMO != 0;
        self.session_flags = flags;
        self.autostart_until = 0;
        // Large displays start with larger text (until the user picks a size).
        if !self.scale_set
            && let Some(p) = self.wm.layout.primary()
        {
            self.settings.text_scale = p.scale;
        }
        self.wm.now_ns = sys::clock_ns();
        self.apply_settings();
        for a in &self.apps {
            if self.clients.iter().any(|c| c.id == a.owner && c.ch != 0) {
                self.wm.register_app_ex(a.owner, a.app, &a.label, &a.identity, a.trust, a.pinned);
            }
        }
        self.term_call(term::DISPLAY_RELEASE);
        self.grab(true);
        self.upload_cursor();
        if let Some(p) = self.wm.layout.primary() {
            self.wm.pointer = Point::new(p.bounds.x + p.bounds.w as i32 / 2, p.bounds.y + p.bounds.h as i32 / 2);
        }
        self.cursor_moved = true;
        self.active = true;
        self.last_input_ns = sys::clock_ns();
        self.next_tray = 0;
        self.poll_tray();
        let (enrolled, lock_at_boot) = self.sync_lock_identities();
        let require_login = (enrolled || lock_at_boot || self.lock_at_boot_cfg) && !self.test_mode;
        if require_login {
            self.wm.engage_lock(LockMode::Login, LockReason::Boot);
            self.session_notified = false;
            println!("awmi: session locked at boot (awaiting user sign-in)");
        } else {
            self.session_notified = true;
        }
        self.wm.damage_all();
        self.next_frame = 0;
        let d = self.wm.layout.desktop_bounds();
        println!("awmi: session started: {} output(s), desktop {}x{}{}", n, d.w, d.h, if self.test_mode { " (test hooks on)" } else { "" });
        if self.session_notified {
            self.broadcast_session(true);
        }
        Ok(n as u32)
    }

    fn session_stop(&mut self, why: &str) {
        if !self.active {
            return;
        }
        self.active = false;
        self.session_notified = false;
        self.pending_perm_owner = 0;
        self.broadcast_session(false);
        self.surfaces.clear();
        *self.wm = WmState::new();
        // Virtual outputs (test mode) end with the session.
        let (virt, real): (Vec<OutBuf>, Vec<OutBuf>) = self.outs.drain(..).partition(|o| o.adapter == 0);
        for o in virt {
            sys::vmar_unmap(libd::root_vmar(), o.map.addr, o.map.len);
            sys::handle_close(o.map.vmo);
        }
        self.outs = real;
        self.flip_pending = false;
        self.flip_deadline = 0;
        self.pace_skip_until = 0;
        self.modeset_redraw_at = 0;
        self.modeset_redraw_left = 0;
        // Reset native KMS outputs back to their boot mode before the terminal reclaims the screen.
        let mut released_any = false;
        for o in &self.outs {
            if o.adapter != 0 && o.native_kms {
                let _ = gpu::kms_reset_boot_atomic(self.gpu, o.adapter);
                released_any = true;
            }
        }
        if !released_any && self.gpu != 0 {
            let _ = gpu::kms_reset_boot_atomic(self.gpu, 0);
        }
        self.grab(false);
        self.term_call(term::DISPLAY_RECLAIM);
        println!("awmi: session ended ({}): display and input returned to the terminal", why);
    }

    fn deliver_frame_done(&mut self) {
        let done: Vec<(u32, u32, u64)> = self.surfaces.iter_mut().filter_map(|s| s.pending.take().map(|q| (s.owner, s.window, q))).collect();
        for (owner, window, seq) in done {
            self.send_to(owner, wire::EVT_FRAME_DONE, u64::from(window), seq);
        }
    }

    /// Receive unsolicited `gpu::EVT_VBLANK` and `gpu::EVT_ADAPTERS_CHANGED` events from `gpu.dsvc`.
    fn on_gpu_event(&mut self) {
        let mut buf = [0u8; HEADER + 32];
        let mut check_adapters = false;
        loop {
            if self.gpu == 0 {
                return;
            }
            match sys::channel_read(self.gpu, &mut buf, 0) {
                Ok(n) => {
                    let Some(h) = Header::get(&buf[..n as usize]) else { continue };
                    match h.op {
                        gpu::EVT_VBLANK => {
                            let now = sys::clock_ns();
                            let late_flag = (h.a >> 32) != 0;
                            let interval = self.frame_interval();
                            let missed_deadline = late_flag
                                || (self.last_flip_ns > 0 && now.saturating_sub(self.last_flip_ns) > (interval * 3) / 2);
                            self.flip_pending = false;
                            self.flip_deadline = 0;
                            self.last_flip_ns = now;
                            if missed_deadline {
                                // Drop cleanly to every other refresh rather than tearing when a frame is late.
                                self.pace_skip_until = now + interval;
                            }
                            self.deliver_frame_done();
                        }
                        gpu::EVT_ADAPTERS_CHANGED => {
                            check_adapters = true;
                        }
                        _ => {}
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.gpu, sys::READABLE | sys::PEER_CLOSED, KEY_GPU);
                    break;
                }
                Err(_) => {
                    self.flip_pending = false;
                    self.flip_deadline = 0;
                    return;
                }
            }
        }
        if check_adapters && self.active {
            self.check_output_upgrade();
        }
    }

    /// Re-evaluate available GPU outputs when `gpu.dsvc` reports an adapter change (e.g. a native
    /// KMS PCI GPU driver coming online, an automatic 12s mode revert, or an explicit mode switch).
    fn check_output_upgrade(&mut self) {
        let next = self.choose_adapters();
        let cur: Vec<&OutBuf> = self.outs.iter().filter(|o| o.adapter != 0).collect();
        let changed = next.len() != cur.len()
            || next.iter().zip(cur.iter()).any(|((a, hz), o)| {
                let nat = (a.caps & gpu::CAP_NATIVE_KMS) != 0;
                o.adapter != a.id
                    || o.width != a.width
                    || o.height != a.height
                    || o.refresh_mhz != *hz
                    || o.native_kms != nat
                    || o.restarts != a.restarts
            });
        if changed && !next.is_empty() {
            println!("awmi: display outputs changed: switching cleanly to updated GPU output(s)");
            self.reattach = true;
            self.flip_pending = false;
            self.flip_deadline = 0;
            self.pace_skip_until = 0;
            self.wm.damage_all();
        }
    }

    // ---- the dock's live state --------------------------------------------------------------------

    fn poll_tray(&mut self) {
        let now = sys::clock_ns();
        if now < self.next_tray {
            return;
        }
        self.next_tray = now + TRAY_POLL_NS;
        let before = self.wm.tray;
        if self.clock_base.is_none() && self.clock != 0 {
            self.clock_base = time::query(self.clock);
        }
        if let Some(b) = self.clock_base {
            let c = b.now().to_civil();
            self.wm.tray.hour = c.hour;
            self.wm.tray.minute = c.minute;
            self.wm.tray.clock_valid = true;
        }
        if self.net != 0 {
            self.wm.tray.net_online = libd::net::status(self.net).is_ok_and(|s| s.link_up && s.dhcp_bound);
        }
        if self.audio != 0 {
            // Capture streams open (b bits 0-7): the microphone is live. Only the audio service
            // can say so: no client of ours can light this indicator.
            if let Ok(h) = libd::audio::control_call(self.audio, libd::audio::OP_STATUS, 0, 0) {
                let live = h.b & 0xFF != 0;
                if live != self.mic_live {
                    self.mic_live = live;
                    println!("awmi: indicator: MIC LIVE {}", if live { "on" } else { "off" });
                }
            }
            let mut devs = [libd::audio::DeviceEntry::empty(); 8];
            if let Ok(n) = libd::audio::list_devices(self.audio, &mut devs) {
                self.wm.tray.audio_muted = devs[..n].iter().find(|d| d.active_out).is_some_and(|d| d.muted || d.volume == 0);
            }
        }
        self.wm.tray.indicators = self.ext_indicators | if self.mic_live { wire::IND_MIC_LIVE } else { 0 };
        if self.wm.tray != before {
            self.wm.damage_dock();
        }
    }

    // ---- compositing ------------------------------------------------------------------------------

    /// Composite the damage into each output's backbuffer and present just those rectangles.
    fn frame(&mut self) {
        if self.reattach {
            self.attach_outputs();
            self.upload_cursor();
        }
        self.wm.now_ns = sys::clock_ns();
        self.wm.tick();
        let Self { wm, outs, surfaces, gpu: gpu_ep, text, output_scales, scale_set, settings, .. } = self;
        let mut bitmap = BitmapText;
        let mut presented = 0u64;
        let mut failed = false;
        let mut any_async = false;
        if !wm.damage.is_empty() {
            for (i, ob) in outs.iter_mut().enumerate() {
                let Some(&out) = wm.layout.as_slice().get(i) else { continue };
                let px = (ob.width as usize) * (ob.height as usize);
                let (w, h) = (ob.width, ob.height);
                let Some(mut canvas) = Canvas::new(pixels_of(&mut ob.map, px), w, h, w) else { continue };
                let eff_scale = if output_scales.iter().any(|&(id, _)| id == out.adapter_id) {
                    out.scale
                } else if *scale_set {
                    settings.text_scale
                } else {
                    out.scale
                };
                let local: DamageSet = match text.as_mut() {
                    Some(t) => {
                        let prev = t.scale;
                        t.scale = eff_scale;
                        let d = wm.composite_output(out, &mut canvas, t, |wid| {
                            surfaces.iter().find(|s| s.window == wid).map(|s| SurfaceView { bytes: s.map.bytes(), width: s.width, height: s.height, pitch_bytes: s.pitch })
                        });
                        t.scale = prev;
                        d
                    }
                    None => wm.composite_output(out, &mut canvas, &mut bitmap, |wid| {
                        surfaces.iter().find(|s| s.window == wid).map(|s| SurfaceView { bytes: s.map.bytes(), width: s.width, height: s.height, pitch_bytes: s.pitch })
                    }),
                };
                if ob.adapter == 0 {
                    continue;
                }
                let slice = local.as_slice();
                if slice.is_empty() {
                    continue;
                }
                let mut rects = [(0u32, 0u32, 0u32, 0u32); gpu::MAX_PRESENT_RECTS];
                let cnt = slice.len().min(gpu::MAX_PRESENT_RECTS);
                for (slot, r) in rects.iter_mut().take(cnt).zip(slice.iter()) {
                    *slot = (r.x as u32, r.y as u32, r.w, r.h);
                }
                match gpu::kms_present_atomic(*gpu_ep, ob.adapter, ob.fb_id, &rects[..cnt]) {
                    Ok((_, is_async)) => {
                        presented += cnt as u64;
                        if is_async {
                            any_async = true;
                        }
                    }
                    Err(e) => {
                        if !failed {
                            println!("awmi: present on adapter #{} failed ({}): attaching again", ob.adapter, sys::status(e));
                        }
                        failed = true;
                    }
                }
            }
            wm.damage.clear();
            self.frames += 1;
            self.flushes += presented;
        }
        if failed {
            self.reattach = true;
            self.force_reattach_fb = true;
            self.flip_pending = false;
            self.flip_deadline = 0;
            self.wm.damage_all();
        }
        if self.outs.iter().any(|o| o.hw_cursor) && self.wm.cursor_kind != self.hw_cursor_kind {
            self.upload_cursor();
        }
        if self.cursor_moved {
            self.cursor_moved = false;
            if let Some(o) = self.outs.iter().find(|o| o.hw_cursor) {
                let p = self.wm.pointer;
                let _ = gpu::kms_set_cursor_atomic(self.gpu, o.adapter, 0, p.x, p.y, 0, 0);
            }
        }
        if any_async && !failed {
            let now = sys::clock_ns();
            self.flip_pending = true;
            self.flip_deadline = now + (self.frame_interval() * 4).max(50 * MS);
        } else {
            self.deliver_frame_done();
        }
    }

    fn frame_interval(&self) -> u64 {
        1_000_000_000_000 / u64::from(self.wm.layout.max_refresh_mhz())
    }

    /// Composite now if anything is due (test hooks read back a settled frame).
    fn flush(&mut self) {
        if !self.wm.damage.is_empty() || self.surfaces.iter().any(|s| s.pending.is_some()) {
            self.frame();
        }
    }

    /// True if any attached real output uses asynchronous `EVT_FLIP_DONE` pacing.
    fn has_async_output(&self) -> bool {
        self.outs.iter().any(|o| o.adapter != 0 && o.async_flip)
    }

    /// A frame is due: damage, owed frames, the cursor, an animation.
    fn due(&self) -> bool {
        !self.wm.damage.is_empty()
            || self.cursor_moved
            || (self.outs.iter().any(|o| o.hw_cursor) && self.wm.cursor_kind != self.hw_cursor_kind)
            || self.reattach
            || self.wm.animating()
            || self.surfaces.iter().any(|s| s.pending.is_some())
    }

    /// The font pack for a window program: a read-only duplicate of the pack VMO.
    fn fonts_reply(&self, ch: Handle, txid: u32) {
        let mut rep = [0u8; HEADER];
        let dup = if self.pack_vmo != 0 { sys::handle_duplicate(self.pack_vmo, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER).ok() } else { None };
        match dup {
            Some(h) => {
                Header { txid, op: wire::OP_FONTS, status: 0, a: self.pack_len, b: 0 }.put(&mut rep);
                sys::channel_write_h(ch, &rep, &[sys::MsgHandle { handle: h, rights: sys::RIGHTS_SAME }]);
            }
            None => {
                Header { txid, op: wire::OP_FONTS, status: sys::ERR_NOT_SUPPORTED as i32, a: 0, b: 0 }.put(&mut rep);
                sys::channel_write(ch, &rep);
            }
        }
    }

    // ---- client requests --------------------------------------------------------------------------

    fn on_client(&mut self, id: u32) {
        let mut buf = alloc::vec![0u8; HEADER + 1024];
        loop {
            let Some(c) = self.clients.iter().find(|c| c.id == id && c.ch != 0) else { return };
            let ch = c.ch;
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(ch, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    let is_window = self.clients.iter().any(|c| c.id == id && c.role == Role::Window);
                    if h.op == wire::OP_FONTS && is_window && h.txid != 0 {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        self.fonts_reply(ch, h.txid);
                        continue;
                    }
                    let (status, a, b, body) = self.request(id, h, &buf[HEADER..n], hnd);
                    if h.txid != 0 {
                        let mut rep = alloc::vec![0u8; HEADER + body.len()];
                        Header { txid: h.txid, op: h.op, status: status as i32, a, b }.put(&mut rep);
                        rep[HEADER..].copy_from_slice(&body);
                        sys::channel_write(ch, &rep);
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + u64::from(id));
                    return;
                }
                Err(_) => {
                    // Gone (exited or crashed): its windows go with it.
                    sys::handle_close(ch);
                    if let Some(c) = self.clients.iter_mut().find(|c| c.id == id) {
                        c.ch = 0;
                    }
                    self.apps.retain(|a| a.owner != id);
                    self.surfaces.retain(|s| s.owner != id);
                    self.wm.remove_client(id);
                    self.sync_windows();
                    return;
                }
            }
        }
    }

    /// One request from client `id`: (status, a, b, reply payload). Every handle is consumed.
    fn request(&mut self, id: u32, h: Header, payload: &[u8], hnd: Handle) -> (i64, u64, u64, Vec<u8>) {
        let Some(c) = self.clients.iter().find(|c| c.id == id) else {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            return (sys::ERR_BAD_STATE, 0, 0, Vec::new());
        };
        let (role, trust) = (c.role, c.trust);
        let identity = c.identity;
        let identity_len = c.identity_len;
        if h.op != wire::OP_ATTACH && hnd != 0 {
            sys::handle_close(hnd);
        }
        let ok = |a: u64, b: u64| (0, a, b, Vec::new());
        let err = |e: i64| (e, 0, 0, Vec::new());
        let admin = role == Role::Admin;
        let test = admin && self.test_mode;
        match h.op {
            wire::OP_STATUS if admin || role == Role::Query => {
                let mut b = [0u8; STATUS_BYTES];
                self.status().encode(&mut b);
                (0, 0, 0, b.to_vec())
            }
            wire::OP_SESSION_START if admin => match self.session_start(h.a & (wire::SESSION_DEMO | wire::SESSION_DESKTOP)) {
                Ok(n) => ok(u64::from(n), 0),
                Err(e) => err(e),
            },
            wire::OP_SESSION_STOP if admin => {
                self.session_stop("asked to");
                ok(0, 0)
            }
            wire::OP_SETTINGS if admin => {
                let want = UiSettings::unpack(h.a);
                let mut s = self.settings;
                if h.b & wire::SET_THEME != 0 {
                    s.theme = want.theme;
                }
                if h.b & wire::SET_TEXT_SCALE != 0 {
                    s.text_scale = want.text_scale;
                    self.scale_set = true;
                }
                if h.b & wire::SET_MOTION != 0 {
                    s.reduce_motion = want.reduce_motion;
                }
                if s != self.settings {
                    self.settings = s;
                    self.apply_settings();
                }
                ok(self.settings.pack(), 0)
            }
            wire::OP_SET_DISPLAY if admin => {
                if self.gpu == 0 {
                    return err(sys::ERR_BAD_STATE);
                }
                let adapter_id = h.a as u32;
                let subop = (h.a >> 32) as u8;
                match subop {
                    wire::DISPLAY_SET_MODE => {
                        if payload.len() < 16 {
                            return err(sys::ERR_INVALID_ARGS);
                        }
                        let w = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        let hh = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        let refresh_mhz = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
                        let flags = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
                        let require_confirm = (flags & 4) != 0;
                        // Always validate via `ATOMIC_TEST_ONLY` before committing the real modeset.
                        if let Err(e) = gpu::kms_modeset_atomic(self.gpu, adapter_id, w, hh, refresh_mhz, true, false) {
                            return err(e);
                        }
                        match gpu::kms_modeset_atomic(self.gpu, adapter_id, w, hh, refresh_mhz, false, require_confirm) {
                            Ok(()) => {
                                self.reattach = true;
                                self.flip_pending = false;
                                self.flip_deadline = 0;
                                self.pace_skip_until = 0;
                                self.next_frame = 0;
                                if self.active {
                                    self.wm.damage_all();
                                    self.modeset_redraw_left = 4;
                                    self.modeset_redraw_at = sys::clock_ns() + 400 * MS;
                                } else {
                                    self.term_call(term::DISPLAY_RECLAIM);
                                }
                                ok(0, 0)
                            }
                            Err(e) => err(e),
                        }
                    }
                    wire::DISPLAY_SET_VRR => {
                        let enable = (h.b & 1) != 0;
                        match gpu::kms_set_vrr_atomic(self.gpu, adapter_id, enable) {
                            Ok(()) => ok(0, 0),
                            Err(e) => err(e),
                        }
                    }
                    wire::DISPLAY_SET_HDR => {
                        let enable = (h.b & 1) != 0;
                        match gpu::kms_set_hdr_atomic(self.gpu, adapter_id, enable) {
                            Ok(()) => {
                                self.wm.damage_all();
                                ok(0, 0)
                            }
                            Err(e) => err(e),
                        }
                    }
                    wire::DISPLAY_CONFIRM_MODE => {
                        let confirm = (h.b & 1) != 0;
                        match gpu::kms_confirm_mode(self.gpu, adapter_id, confirm) {
                            Ok(()) => {
                                if !confirm {
                                    self.reattach = true;
                                    self.flip_pending = false;
                                    self.flip_deadline = 0;
                                    if self.active {
                                        self.wm.damage_all();
                                    }
                                }
                                ok(0, 0)
                            }
                            Err(e) => err(e),
                        }
                    }
                    wire::DISPLAY_SET_SCALE => {
                        let scale = h.b as u16;
                        if scale != 0 && !UiSettings::SCALES.contains(&scale) {
                            return err(sys::ERR_INVALID_ARGS);
                        }
                        let resolved = if adapter_id == 0 {
                            self.wm.layout.primary().map_or(0, |o| o.adapter_id)
                        } else {
                            adapter_id
                        };
                        if !self.wm.layout.set_output_scale(adapter_id, scale) {
                            return err(sys::ERR_OUT_OF_RANGE);
                        }
                        self.output_scales.retain(|&(id, _)| id != resolved);
                        if scale != 0 {
                            self.output_scales.push((resolved, scale));
                        }
                        let is_primary = self.wm.layout.primary().is_some_and(|o| o.adapter_id == resolved);
                        if is_primary && !self.scale_set {
                            if let Some(p) = self.wm.layout.primary() {
                                self.settings.text_scale = p.scale;
                            }
                            self.apply_settings();
                        } else {
                            self.wm.damage_all();
                        }
                        ok(0, 0)
                    }
                    _ => err(sys::ERR_INVALID_ARGS),
                }
            }
            wire::OP_LOCK if admin => {
                if !self.active {
                    return err(sys::ERR_BAD_STATE);
                }
                let reason = match h.a {
                    wire::LOCK_REASON_BOOT => LockReason::Boot,
                    wire::LOCK_REASON_IDLE => LockReason::Idle,
                    wire::LOCK_REASON_SLEEP => LockReason::Sleep,
                    _ => LockReason::Manual,
                };
                let mode = if h.b == wire::LOCK_MODE_LOGIN { LockMode::Login } else { LockMode::Locked };
                self.engage_lock_screen(mode, reason);
                ok(0, 0)
            }
            wire::OP_SET_LOCK_POLICY if admin => {
                let secs = (h.a as u32).min(86_400);
                self.idle_timeout_ns = u64::from(secs) * SEC;
                self.lock_on_sleep = ((h.a >> 32) & 1) != 0;
                ok(0, 0)
            }
            wire::OP_PERM_PROMPT if role == Role::Launcher => {
                if !self.active || self.wm.lock.active {
                    return err(sys::ERR_BAD_STATE);
                }
                let (app_name, app_title) = match payload.iter().position(|&b| b == 0) {
                    Some(nul) => (&payload[..nul], &payload[nul + 1..]),
                    None => (payload, payload),
                };
                self.pending_perm_owner = id;
                self.wm.open_perm_prompt(h.a as u32, app_name, app_title, h.b as u32);
                ok(0, 0)
            }
            wire::OP_APP_REGISTER if role == Role::Window || role == Role::Launcher => {
                let app = h.a as u8;
                let pinned = (h.b & wire::APP_FLAG_PINNED) != 0;
                let max_per = if role == Role::Launcher { dosawmi::launcher::MAX_APPS_PER_CLIENT } else { 4 };
                let (raw_label, raw_ident, eff_trust) = if role == Role::Launcher {
                    let (lbl, aid) = match payload.iter().position(|&b| b == 0) {
                        Some(nul) => (&payload[..nul], &payload[nul + 1..]),
                        None => (payload, &identity[..identity_len]),
                    };
                    (lbl, aid, TrustTier::Native)
                } else {
                    (payload, &identity[..identity_len], trust)
                };
                let label: Vec<u8> = raw_label[..raw_label.len().min(dosawmi::launcher::LAUNCH_LABEL_BYTES)].to_vec();
                let ident: Vec<u8> = raw_ident[..raw_ident.len().min(MAX_IDENTITY_BYTES)].to_vec();
                if usize::from(app) >= max_per || label.is_empty() || h.a > 0xFF {
                    return err(sys::ERR_INVALID_ARGS);
                }
                if self.apps.len() >= dosawmi::launcher::MAX_LAUNCH_APPS && !self.apps.iter().any(|a| a.owner == id && a.app == app) {
                    return err(sys::ERR_NO_RESOURCES);
                }
                self.apps.retain(|a| !(a.owner == id && a.app == app));
                self.apps.push(RegisteredApp {
                    owner: id,
                    app,
                    label: label.clone(),
                    identity: ident.clone(),
                    trust: eff_trust,
                    pinned,
                });
                if self.active {
                    self.wm.register_app_ex(id, app, &label, &ident, eff_trust, pinned);
                }
                ok(0, 0)
            }
            wire::OP_INDICATOR if role == Role::Indicator => {
                self.ext_indicators = h.a & wire::IND_SECURITY_ALERT;
                self.next_tray = 0;
                self.poll_tray();
                ok(0, 0)
            }
            wire::OP_CREATE if role == Role::Window => {
                if !self.active {
                    return err(sys::ERR_BAD_STATE);
                }
                if self.wm.owner_window_count(id) >= MAX_WINDOWS_PER_CLIENT {
                    return err(sys::ERR_NO_RESOURCES);
                }
                let (w, hh) = ((h.a as u32).clamp(1, 8192), ((h.a >> 32) as u32).clamp(1, 8192));
                // Server-side decorations are mandatory so no client can imitate the lock screen.
                let flags = ((h.b as u32) & wire::FLAGS_DEFAULT) | wire::FLAG_DECORATED;
                let title = &payload[..payload.len().min(wire::MAX_TITLE)];
                let Some(win) = self.wm.create_window(id, &identity[..identity_len], trust, w, hh, flags, title) else {
                    return err(sys::ERR_NO_RESOURCES);
                };
                let Some(cr) = self.wm.window(win).map(|x| x.client_rect(self.wm.chrome)) else {
                    return err(sys::ERR_BAD_STATE);
                };
                // The new window is focused: the one that had focus is told.
                self.sync_windows();
                ok(u64::from(win), u64::from(cr.w) | u64::from(cr.h) << 32)
            }
            wire::OP_ATTACH if role == Role::Window => self.attach(id, h, payload, hnd),
            wire::OP_COMMIT if role == Role::Window => {
                let win = h.a as u32;
                if !self.wm.is_owner(id, win) {
                    return err(sys::ERR_ACCESS_DENIED);
                }
                let Some(s) = self.surfaces.iter_mut().find(|s| s.window == win) else {
                    return err(sys::ERR_BAD_STATE);
                };
                s.pending = Some(h.b);
                let mut rects = [Rect::EMPTY; wire::MAX_DAMAGE];
                let mut n = dosawmi::proto::decode_damage_rects(payload, &mut rects);
                // The first commit into a newly attached buffer swaps it in (the old one is
                // unmapped when `new`, now holding it, drops) and shows all of it.
                if let Some(mut new) = s.staged.take() {
                    core::mem::swap(&mut s.map, &mut new.map);
                    s.width = new.width;
                    s.height = new.height;
                    s.pitch = new.pitch;
                    n = 0;
                }
                self.wm.commit_damage(id, win, &rects[..n]);
                ok(0, 0)
            }
            wire::OP_SET_TITLE if role == Role::Window => {
                if self.wm.set_title(id, h.a as u32, &payload[..payload.len().min(wire::MAX_TITLE)]) {
                    ok(0, 0)
                } else {
                    err(sys::ERR_ACCESS_DENIED)
                }
            }
            wire::OP_DESTROY if role == Role::Window => {
                let win = h.a as u32;
                if !self.wm.destroy_window(id, win) {
                    return err(sys::ERR_ACCESS_DENIED);
                }
                self.surfaces.retain(|s| s.window != win);
                self.sync_windows();
                ok(0, 0)
            }
            wire::OP_TEST_KEY if test && self.active => {
                self.key(h.a as u32 | if h.b == 0 { key::RELEASE } else { 0 });
                ok(0, 0)
            }
            wire::OP_TEST_POINTER if test && self.active => {
                self.pointer(0, 0, Some(Point::new(h.a as u32 as i32, (h.a >> 32) as u32 as i32)), h.b as u8, 0);
                ok(0, 0)
            }
            wire::OP_TEST_PIXEL if test && self.active => {
                self.flush();
                let p = Point::new(h.a as u32 as i32, (h.a >> 32) as u32 as i32);
                let i = self.wm.layout.as_slice().iter().position(|o| o.bounds.contains_point(p));
                match i.and_then(|i| Some((self.wm.layout.as_slice()[i].bounds, self.outs.get_mut(i)?))) {
                    Some((bounds, ob)) => {
                        let (x, y) = ((p.x - bounds.x) as u64, (p.y - bounds.y) as u64);
                        let off = (y * u64::from(ob.width) + x) * 4;
                        ok(u64::from(ob.map.r32(off)), 0)
                    }
                    None => err(sys::ERR_OUT_OF_RANGE),
                }
            }
            wire::OP_TEST_WINDOWS if test => {
                self.flush();
                let chrome = self.wm.chrome;
                let mut body = Vec::new();
                for w in self.wm.windows().take(16) {
                    let mut rec = [0u8; WINDOW_INFO_BYTES];
                    let focused = self.wm.focused == Some(w.id);
                    encode_window_info(&mut rec, w.id, w.frame, w.client_rect(chrome), w.trust, w.workspace, w.minimized, focused, w.identity_bytes(), w.title_bytes());
                    body.extend_from_slice(&rec);
                }
                (0, 0, 0, body)
            }
            wire::OP_TEST_FRAME if test && self.active => {
                self.flush();
                let bg = self.wm.theme.desktop_bg & 0x00FF_FFFF;
                let Some(ob) = self.outs.first() else { return err(sys::ERR_BAD_STATE) };
                let px = (ob.width as usize) * (ob.height as usize);
                let bytes = ob.map.bytes();
                let mut hash = 0xcbf2_9ce4_8422_2325u64;
                let mut other = 0u64;
                for c in bytes[..px * 4].as_chunks::<4>().0 {
                    let v = u32::from_le_bytes(*c) & 0x00FF_FFFF;
                    hash = (hash ^ u64::from(v)).wrapping_mul(0x0100_0000_01b3);
                    other += u64::from(v != bg);
                }
                ok(hash, other)
            }
            wire::OP_TEST_ADD_OUTPUT if test && self.active => {
                let (w, hh) = ((h.a as u32).clamp(320, 4096), ((h.a >> 32) as u32).clamp(200, 4096));
                let Ok(map) = Mapping::new(u64::from(w) * u64::from(hh) * 4) else {
                    return err(sys::ERR_NO_MEMORY);
                };
                for o in &mut self.outs {
                    o.hw_cursor = false; // one cursor for every output: drawn in software
                }
                self.outs.push(OutBuf {
                    adapter: 0,
                    restarts: 0,
                    gem_handle: 0,
                    fb_id: 0,
                    map,
                    width: w,
                    height: hh,
                    refresh_mhz: 60_000,
                    hw_cursor: false,
                    async_flip: false,
                    native_kms: false,
                });
                self.relayout();
                println!("awmi: test: virtual output {}x{} added right of the others", w, hh);
                ok(self.wm.layout.count as u64, 0)
            }
            wire::OP_TEST_IDLE_EXPIRE if test && self.active => {
                if self.idle_timeout_ns == 0 {
                    return err(sys::ERR_BAD_STATE);
                }
                self.last_input_ns = sys::clock_ns().saturating_sub(self.idle_timeout_ns.saturating_add(SEC));
                if !self.wm.lock.active {
                    self.engage_lock_screen(LockMode::Locked, LockReason::Idle);
                }
                ok(0, 0)
            }
            _ => err(sys::ERR_ACCESS_DENIED),
        }
    }

    fn attach(&mut self, id: u32, h: Header, payload: &[u8], hnd: Handle) -> (i64, u64, u64, Vec<u8>) {
        let fail = |e: i64| {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            (e, 0, 0, Vec::new())
        };
        let win = h.a as u32;
        if !self.wm.is_owner(id, win) {
            return fail(sys::ERR_ACCESS_DENIED);
        }
        if hnd == 0 || payload.len() < 8 {
            return fail(sys::ERR_INVALID_ARGS);
        }
        let (w, hh) = (h.b as u32, (h.b >> 32) as u32);
        let pitch = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let format = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if w == 0 || hh == 0 || w > 8192 || hh > 8192 || pitch < w.saturating_mul(4) || !matches!(format, gpu::FMT_XRGB8888 | gpu::FMT_ARGB8888) {
            return fail(sys::ERR_INVALID_ARGS);
        }
        let need = u64::from(pitch) * u64::from(hh);
        if need > MAX_SURFACE_BYTES || !sys::vmo_size(hnd).is_ok_and(|s| s >= need) {
            return fail(sys::ERR_OUT_OF_RANGE);
        }
        let Ok(map) = Mapping::of_ro(hnd, need) else {
            return fail(sys::ERR_ACCESS_DENIED); // not readable or mappable
        };
        let new = Surface { window: win, owner: id, map, width: w, height: hh, pitch, pending: None, told: (0, 0, 0), staged: None };
        match self.surfaces.iter_mut().find(|s| s.window == win) {
            // A resize: shown at the next commit (see `OP_COMMIT`); until then the old pixels.
            Some(s) => s.staged = Some(Box::new(new)),
            None => self.surfaces.push(new),
        }
        self.sync_windows();
        (0, 0, 0, Vec::new())
    }

    fn status(&self) -> AwmiStatus {
        let d = self.wm.layout.primary().map_or(Rect::EMPTY, |o| o.bounds);
        AwmiStatus {
            active: self.active,
            outputs: self.wm.layout.count as u8,
            workspaces: dosawmi::WORKSPACE_COUNT,
            active_workspace: self.wm.active_workspace,
            windows: self.wm.window_count() as u16,
            focused_window: self.wm.focused.unwrap_or(0),
            width: d.w,
            height: d.h,
            refresh_mhz: if self.active { self.wm.layout.max_refresh_mhz() } else { 0 },
            indicators: self.wm.tray.indicators,
            frames: self.frames,
            damage_flushes: self.flushes,
            input_keys: self.input_keys,
            input_pointer: self.input_pointer,
            settings: self.settings.pack() as u32,
            launcher_open: self.active && self.wm.launcher.open,
            fonts: self.text.is_some(),
            apps: self.apps.len() as u8,
            locked: self.active && self.wm.lock.active,
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "awmi") } {
        return 1;
    }
    let has_arg = |w: &[u8]| libd::args().split(|&c| c == b' ' || c == 0).any(|a| a == w);
    let test_mode = has_arg(b"test");
    let autostart = has_arg(b"autostart");
    let firmware_display = has_arg(b"firmware-display");
    let lock_at_boot_cfg = has_arg(b"lock-at-boot");
    let Ok(port) = Port::new(256) else { return 1 };
    let (text, pack_vmo, pack_len) = match load_fonts() {
        Some((map, len)) => {
            let vmo = map.vmo;
            // The pack lives as long as this service: the engine borrows it for ever.
            let map: &'static Mapping = Box::leak(Box::new(map));
            (Some(FontText::new(fonts::engine(&map.bytes()[..len as usize]), 100)), vmo, len)
        }
        None => {
            println!("awmi: no fonts on the system volume: the built-in bitmap font draws");
            (None, 0, 0)
        }
    };
    let themes = [load_theme(ThemeId::DarkSlate), load_theme(ThemeId::HighContrast)];
    let mut a = Awmi {
        port,
        ctl: libd::startup_handle(proto::TAG_CONTROL),
        input: svc::endpoint(b"devmgr.input"),
        term: svc::endpoint(b"terminal.display"),
        gpu: gpu::display_endpoint(),
        clock: svc::endpoint(b"clock.time"),
        audio: libd::audio::control_endpoint(),
        net: libd::net::status_endpoint(),
        identity: idwire::session_endpoint(),
        test_mode,
        firmware_display,
        lock_at_boot_cfg,
        idle_timeout_ns: 300 * SEC,
        lock_on_sleep: true,
        last_input_ns: sys::clock_ns(),
        session_notified: false,
        pending_perm_owner: 0,
        clients: Vec::new(),
        next_client: 1,
        wm: Box::new(WmState::new()),
        surfaces: Vec::new(),
        outs: Vec::new(),
        active: false,
        demo: false,
        frames: 0,
        flushes: 0,
        input_keys: 0,
        input_pointer: 0,
        next_frame: 0,
        next_tray: 0,
        flip_pending: false,
        flip_deadline: 0,
        last_flip_ns: 0,
        pace_skip_until: 0,
        cursor_moved: false,
        cursor_map: None,
        cursor_adapter: 0,
        cursor_restarts: 0,
        cursor_gem: 0,
        cursor_fb: 0,
        hw_cursor_kind: CursorKind::Default,
        ext_indicators: 0,
        mic_live: false,
        clock_base: None,
        reattach: false,
        force_reattach_fb: false,
        modeset_redraw_at: 0,
        modeset_redraw_left: 0,
        text,
        pack_vmo,
        pack_len,
        themes,
        settings: UiSettings::DEFAULT,
        scale_set: false,
        output_scales: Vec::new(),
        apps: Vec::new(),
        session_flags: 0,
        autostart_until: if autostart { sys::clock_ns() + AUTOSTART_WAIT_NS } else { 0 },
    };
    if a.ctl != 0 {
        a.port.arm(a.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if a.input != 0 {
        a.port.arm(a.input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
    }
    if a.gpu != 0 {
        a.port.arm(a.gpu, sys::READABLE | sys::PEER_CLOSED, KEY_GPU);
    }
    println!(
        "awmi: ready, idle until a session starts (endpoints: window, admin, query, indicator, launcher{}{})",
        if test_mode { "; test hooks on" } else { "" },
        if firmware_display { "; firmware display forced" } else { "" }
    );
    let mut next_try = 0u64;
    loop {
        // Boot: a desktop session as soon as a display is there (the GPU drivers come up after
        // this service); without one by the deadline, the text console stays.
        let now = sys::clock_ns();
        if a.autostart_until != 0 && !a.active && now >= next_try {
            if now >= a.autostart_until {
                println!("awmi: no display for a desktop: staying in the text console");
                a.autostart_until = 0;
            } else if a.gpu != 0 && a.session_start(wire::SESSION_DESKTOP).is_ok() {
                println!("awmi: desktop session started at boot");
            } else {
                next_try = now + 500 * MS;
            }
        }
        // Idle: wait for a request. In a session:
        // - If an async flip is pending, wait for `EVT_FLIP_DONE` (or safety deadline) & tray.
        // - If async output is idle with no damage, sleep until next tray poll (zero CPU).
        // - Otherwise wait until next refresh-paced frame or late-frame skip window.
        let timeout = if !a.active {
            if a.autostart_until != 0 { next_try.saturating_sub(now).max(MS) } else { sys::WAIT_FOREVER }
        } else {
            let mut until = a.next_tray;
            if !a.wm.lock.active && a.idle_timeout_ns > 0 {
                until = until.min(a.last_input_ns.saturating_add(a.idle_timeout_ns));
            }
            if a.modeset_redraw_left > 0 && a.modeset_redraw_at != 0 {
                until = until.min(a.modeset_redraw_at);
            }
            if a.flip_pending {
                if a.flip_deadline != 0 {
                    until = until.min(a.flip_deadline);
                }
            } else if a.due() {
                let target = if a.has_async_output() {
                    a.pace_skip_until
                } else {
                    a.next_frame.max(a.pace_skip_until)
                };
                until = until.min(target);
            }
            until.saturating_sub(now)
        };
        if let Some((k, _)) = a.port.wait(timeout) {
            match k {
                KEY_CTL => {
                    if !a.on_ctl() {
                        return 0;
                    }
                }
                KEY_INPUT => a.on_input(),
                KEY_GPU => a.on_gpu_event(),
                k if k >= KEY_CLIENT_BASE => a.on_client((k - KEY_CLIENT_BASE) as u32),
                _ => {}
            }
        }
        if a.active {
            let now = sys::clock_ns();
            a.wm.now_ns = now;
            if !a.wm.lock.active && a.idle_timeout_ns > 0 && now >= a.last_input_ns.saturating_add(a.idle_timeout_ns) {
                a.engage_lock_screen(LockMode::Locked, LockReason::Idle);
            }
            if a.modeset_redraw_left > 0 && now >= a.modeset_redraw_at {
                a.modeset_redraw_left -= 1;
                a.modeset_redraw_at = if a.modeset_redraw_left > 0 {
                    now + if a.modeset_redraw_left == 3 { 600 * MS } else { 700 * MS }
                } else {
                    0
                };
                a.wm.damage_all();
            }
            a.poll_tray();
            // Recover cleanly if a driver restarted mid-flip and missed `EVT_FLIP_DONE`.
            if a.flip_pending && a.flip_deadline != 0 && now >= a.flip_deadline {
                a.flip_pending = false;
                a.flip_deadline = 0;
                a.deliver_frame_done();
            }
            let ready_to_draw = if a.has_async_output() {
                !a.flip_pending && now >= a.pace_skip_until
            } else {
                now >= a.next_frame && now >= a.pace_skip_until
            };
            if a.due() && ready_to_draw {
                a.frame();
                // Refresh-paced for synchronous outputs; async outputs pace off real `EVT_FLIP_DONE`.
                a.next_frame = now + a.frame_interval();
            }
        }
    }
}
