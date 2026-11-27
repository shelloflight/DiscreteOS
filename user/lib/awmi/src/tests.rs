//! Host unit tests and 12,000-round fuzzers for `dosawmi`.

use std::vec;

use crate::dock::{DockHit, DockLayout};
use crate::geom::{DamageSet, Point, Rect};
use crate::pixel::{Canvas, blend_over, write_hw_cursor_64x64};
use crate::proto::{AwmiStatus, STATUS_BYTES, TrustTier, decode_damage_rects, encode_damage_rects, indicator_bits, sanitize_label, win_flags};
use crate::theme::{ChromeMetrics, DockConfig, Theme, argb, rgb};
use crate::launcher::{LaunchTarget, Setting, UiSettings};
use crate::text::BitmapText;
use crate::theme::{COLOR_NAMES, THEME_BYTES, ThemeError, ThemeId};
use crate::wm::{KEY_META, SnapState, SurfaceView, WmAction, WmState};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn u32(&mut self) -> u32 {
        self.next() as u32
    }
    fn i32(&mut self) -> i32 {
        self.next() as i32
    }
    fn u8(&mut self) -> u8 {
        self.next() as u8
    }
}

#[test]
fn damage_coalescing_and_output_clipping() {
    let mut dmg = DamageSet::new();
    dmg.add(Rect::new(10, 10, 40, 40));
    dmg.add(Rect::new(20, 20, 10, 10)); // contained -> ignored
    assert_eq!(dmg.len(), 1);
    assert_eq!(dmg.as_slice()[0], Rect::new(10, 10, 40, 40));

    // Adjacent rect merges cleanly.
    dmg.add(Rect::new(50, 10, 30, 40));
    assert_eq!(dmg.len(), 1);
    assert_eq!(dmg.as_slice()[0], Rect::new(10, 10, 70, 40));

    // Overflow (> MAX_DAMAGE_RECTS disjoint rects) coalesces to single bounding rect.
    dmg.clear();
    for i in 0..24 {
        dmg.add(Rect::new(i * 100, i * 100, 10, 10));
    }
    assert!(dmg.len() <= 16);
    assert_eq!(dmg.bounds(), Rect::new(0, 0, 2310, 2310));

    // Multi-monitor clipping translates into output-local coordinates.
    let out1 = Rect::new(1024, 0, 1024, 768);
    let mut multi = DamageSet::new();
    multi.add(Rect::new(900, 100, 300, 200));
    let local = multi.for_output(out1);
    assert_eq!(local.len(), 1);
    assert_eq!(local.as_slice()[0], Rect::new(0, 100, 176, 200));
}

#[test]
fn hybrid_wm_snapping_workspaces_and_isolation() {
    let mut wm = WmState::new();
    wm.layout.add_output(0, 1280, 800, 60_000, true).unwrap();
    wm.layout.add_output(1, 1024, 768, 75_000, false).unwrap();
    assert_eq!(wm.layout.max_refresh_mhz(), 75_000);

    // Client 1 creates a Native window; Client 2 creates a Sandbox window.
    let w1 = wm.create_window(1, b"demo-a", TrustTier::Native, 400, 300, win_flags::DEFAULT, b"Alpha").unwrap();
    let w2 = wm.create_window(2, b"foreign-b", TrustTier::Sandbox, 400, 300, win_flags::DEFAULT, b"Beta").unwrap();

    // Strict ownership isolation: client 1 cannot touch or destroy client 2's window.
    assert!(!wm.is_owner(1, w2));
    assert!(!wm.set_title(1, w2, b"hijacked"));
    assert!(!wm.commit_damage(1, w2, &[Rect::new(0, 0, 10, 10)]));
    assert!(!wm.destroy_window(1, w2));

    // Unforgeable identity: set_title changes title only, never verified manifest identity or trust tier.
    assert!(wm.set_title(2, w2, b"system: fake"));
    let win2 = wm.window(w2).unwrap();
    assert_eq!(win2.identity_bytes(), b"foreign-b");
    assert_eq!(win2.trust, TrustTier::Sandbox);
    assert_eq!(win2.title_bytes(), b"system: fake");

    // Focus & input isolation: w2 is focused, so keys go exclusively to (owner=2, w2).
    assert_eq!(wm.handle_key(u32::from(b'a'), true), WmAction::DeliverKey { owner: 2, window_id: w2 });

    // Super+Left snaps w2 to left half of work area; Super+Right snaps to right half.
    const SUPER: u32 = 1 << 19;
    const LEFT: u32 = 0x103;
    const RIGHT: u32 = 0x104;
    assert_eq!(wm.handle_key(SUPER | LEFT, true), WmAction::Configure { owner: 2, window_id: w2 });
    let work = wm.layout.work_area(wm.layout.primary().unwrap(), wm.dock_cfg);
    assert_eq!(wm.window(w2).unwrap().frame, SnapState::LeftHalf.target_rect(work));
    assert_eq!(wm.handle_key(SUPER | RIGHT, true), WmAction::Configure { owner: 2, window_id: w2 });
    assert_eq!(wm.window(w2).unwrap().frame, SnapState::RightHalf.target_rect(work));

    // Workspace switch: Super+2 hides workspace 1 windows from input & focus.
    assert_eq!(wm.handle_key(SUPER | u32::from(b'2'), true), WmAction::None);
    assert_eq!(wm.active_workspace, 1);
    assert_eq!(wm.focused, None);
    assert_eq!(wm.handle_key(u32::from(b'x'), true), WmAction::None);

    // Super+1 switches back and restores focus to topmost window on workspace 1.
    wm.handle_key(SUPER | u32::from(b'1'), true);
    assert_eq!(wm.active_workspace, 0);
    assert_eq!(wm.focused, Some(w2));

    // Alt+Tab switches focus to w1.
    const ALT: u32 = 1 << 18;
    assert_eq!(wm.handle_key(ALT | u32::from(b'\t'), true), WmAction::Configure { owner: 1, window_id: w1 });
    assert_eq!(wm.handle_key(u32::from(b'z'), true), WmAction::DeliverKey { owner: 1, window_id: w1 });

    // Super+Esc and Ctrl+Alt+Esc exit session.
    assert_eq!(wm.handle_key(SUPER | 0x1B, true), WmAction::ExitSession);
    assert_eq!(wm.handle_key((1 << 17) | ALT | 0x1B, true), WmAction::ExitSession);
}

#[test]
fn dock_geometry_indicators_and_compositor_render() {
    let mut wm = WmState::new();
    wm.layout.add_output(0, 1024, 768, 60_000, false).unwrap();
    wm.tray.net_online = true;
    wm.tray.indicators = indicator_bits::MIC_LIVE;
    wm.tray.hour = 14;
    wm.tray.minute = 35;
    wm.tray.clock_valid = true;

    let w1 = wm.create_window(10, b"sys-info", TrustTier::System, 320, 200, win_flags::DEFAULT, b"Inspector").unwrap();
    let client_r = wm.window(w1).unwrap().client_rect(ChromeMetrics::DEFAULT);

    // Prepare a solid blue client surface for w1.
    let surf_w = client_r.w;
    let surf_h = client_r.h;
    let mut surf = vec![0u8; (surf_w * surf_h * 4) as usize];
    for chunk in surf.as_chunks_mut::<4>().0 {
        *chunk = rgb(0x20, 0x60, 0xCC).to_le_bytes();
    }

    let mut fb = vec![0u32; 1024 * 768];
    let mut canvas = Canvas::new(&mut fb, 1024, 768, 1024).unwrap();
    wm.damage_all();
    let flushed = wm.composite_output(wm.layout.primary().unwrap(), &mut canvas, &mut BitmapText, |wid| {
        if wid == w1 {
            Some(SurfaceView { bytes: &surf, width: surf_w, height: surf_h, pitch_bytes: surf_w * 4 })
        } else {
            None
        }
    });
    assert!(!flushed.is_empty());

    // Verify client area pixel matches our solid blue surface.
    let sample = canvas.get_pixel((client_r.x + 10) as u32, (client_r.y + 10) as u32).unwrap();
    assert_eq!(sample, rgb(0x20, 0x60, 0xCC));

    // Verify dock sits inset 24px from left/right edges and detects workspace & mic indicator hits.
    let dl = DockLayout::compute(1024, 768, DockConfig::DEFAULT, &[], &wm.tray, 8);
    assert_eq!(dl.bar.x, 24);
    assert_eq!(dl.bar.w, 1024 - 48);
    assert_eq!(dl.hit_test(Point::new(dl.ws_rects[2].x + 4, dl.ws_rects[2].y + 4)), DockHit::Workspace(2));
    assert_eq!(dl.hit_test(Point::new(dl.mic_rect.x + 8, dl.mic_rect.y + 8)), DockHit::Indicator);
    // Verify green MIC LIVE dot pixel was rendered inside the dock.
    let mic_dot = canvas.get_pixel((dl.mic_rect.x + 9) as u32, (dl.mic_rect.y + dl.mic_rect.h as i32 / 2) as u32).unwrap();
    assert_eq!(mic_dot, Theme::DARK_SLATE.ind_mic_live);

    // Each workspace has its own dock: a window moved to workspace 2 leaves this dock.
    let w2 = wm.create_window(11, b"other", TrustTier::Native, 200, 150, win_flags::DEFAULT, b"Other").unwrap();
    let out = wm.layout.primary().unwrap();
    assert_eq!(wm.dock_layout_for(out).win_count, 2);
    assert!(wm.move_window_to_workspace(w2, 1));
    let dl = wm.dock_layout_for(out);
    assert_eq!((dl.win_count, dl.win_rects[0].0), (1, w1));
    wm.switch_workspace(1);
    let dl = wm.dock_layout_for(out);
    assert_eq!((dl.win_count, dl.win_rects[0].0), (1, w2));

    // Hardware cursor bitmap generation sanity check.
    let mut cur = vec![0u8; 64 * 64 * 4];
    write_hw_cursor_64x64(&mut cur);
    assert_ne!(u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]]), 0);
}

#[test]
fn alpha_blend_and_status_codec() {
    assert_eq!(blend_over(rgb(0x10, 0x20, 0x30), argb(0, 0xFF, 0xFF, 0xFF)), rgb(0x10, 0x20, 0x30));
    assert_eq!(blend_over(rgb(0x10, 0x20, 0x30), argb(255, 0xAA, 0xBB, 0xCC)), rgb(0xAA, 0xBB, 0xCC));

    let st = AwmiStatus {
        active: true,
        outputs: 2,
        workspaces: 4,
        active_workspace: 1,
        windows: 3,
        focused_window: 7,
        width: 2560,
        height: 1440,
        refresh_mhz: 144_000,
        indicators: indicator_bits::MIC_LIVE,
        frames: 420,
        damage_flushes: 512,
        input_keys: 9,
        input_pointer: 77,
        settings: 0x0100_7D01,
        launcher_open: true,
        fonts: true,
        apps: 3,
        locked: true,
    };
    let mut buf = [0u8; STATUS_BYTES];
    st.encode(&mut buf);
    assert_eq!(AwmiStatus::decode(&buf), Some(st));
    assert_eq!(AwmiStatus::decode(&buf[..10]), None);
}

#[test]
fn fuzz_untrusted_protocol_geometry_and_wm_12000_rounds() {
    let mut rng = Rng(0xD05A_7711_5EED_CAFE);

    // 4,000 rounds: untrusted wire decoders & label sanitizer.
    for _ in 0..4000 {
        let len = (rng.u32() % 260) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = rng.u8();
        }
        let mut rects = [Rect::EMPTY; 16];
        let n = decode_damage_rects(&buf, &mut rects);
        assert!(n <= 16);
        let mut enc = [0u8; 256];
        let _ = encode_damage_rects(&rects[..n], &mut enc);
        let _ = AwmiStatus::decode(&buf);
        let mut lbl = [0u8; 48];
        let ln = sanitize_label(&buf, &mut lbl);
        assert!(ln <= 48);
        assert!(lbl[..ln].iter().all(|&c| (0x20..=0x7E).contains(&c)));
    }

    // 4,000 rounds: DamageSet stress with extreme signed/unsigned coordinates.
    let mut dmg = DamageSet::new();
    for _ in 0..4000 {
        if rng.u8().is_multiple_of(32) {
            dmg.clear();
        }
        let r = Rect::new(rng.i32(), rng.i32(), rng.u32(), rng.u32());
        dmg.add(r);
        assert!(dmg.len() <= 16);
        let _ = dmg.for_output(Rect::new(0, 0, 1920, 1080));
    }

    // 4,000 rounds: adversarial WM state machine & clipped compositor fuzzing.
    let mut wm = WmState::new();
    wm.layout.add_output(0, 320, 240, 60_000, false).unwrap();
    let mut fb = vec![0u32; 320 * 240];
    let dummy_surf = vec![0x55u8; 64 * 64 * 4];
    for step in 0..4000u32 {
        let owner = (rng.u32() % 4) + 1;
        match rng.u8() % 8 {
            0 => {
                let _ = wm.create_window(owner, b"fuzz", TrustTier::from_u8(rng.u8() % 4), rng.u32() % 800, rng.u32() % 600, rng.u32() & 7, b"W");
            }
            1 => {
                let _ = wm.destroy_window(owner, (rng.u32() % 16) + 1);
            }
            2 => {
                let _ = wm.set_title(owner, (rng.u32() % 16) + 1, b"title\x00\x07!");
            }
            3 => {
                let r = Rect::new(rng.i32() % 400, rng.i32() % 300, rng.u32() % 400, rng.u32() % 300);
                let _ = wm.commit_damage(owner, (rng.u32() % 16) + 1, &[r]);
            }
            4 => {
                let _ = wm.handle_pointer(rng.i32() % 50, rng.i32() % 50, None, rng.u8() & 7);
            }
            5 => {
                let _ = wm.handle_key(rng.u32() & 0x001F_FFFF, rng.u8() & 1 != 0);
            }
            6 => {
                wm.switch_workspace(rng.u8() % 4);
            }
            _ => {
                if step % 64 == 0 {
                    wm.remove_client(owner);
                }
            }
        }
        if step % 200 == 0 && !wm.damage.is_empty() {
            let mut canvas = Canvas::new(&mut fb, 320, 240, 320).unwrap();
            let _ = wm.composite_output(wm.layout.primary().unwrap(), &mut canvas, &mut BitmapText, |_| {
                Some(SurfaceView { bytes: &dummy_surf, width: 64, height: 64, pitch_bytes: 64 * 4 })
            });
            wm.damage.clear();
        }
    }
}

#[test]
fn connect_identity_and_window_info_codec() {
    use crate::proto::{WINDOW_INFO_BYTES, encode_window_info, split_connect};
    // The service manager's `<endpoint>\0<verified service name>`; plain endpoints still parse.
    assert_eq!(split_connect(b"window\0svc-awmi-a"), (&b"window"[..], &b"svc-awmi-a"[..]));
    assert_eq!(split_connect(b"devmgr.input"), (&b"devmgr.input"[..], &b""[..]));
    assert_eq!(split_connect(b"window\0"), (&b"window"[..], &b""[..]));

    let mut rec = [0u8; WINDOW_INFO_BYTES];
    let frame = Rect::new(-5, 40, 322, 229);
    let client = Rect::new(-4, 68, 320, 200);
    encode_window_info(&mut rec, 7, frame, client, TrustTier::Sandbox, 2, true, false, b"svc-awmi-b", b"system: fake");
    let u32_at = |o: usize| u32::from_le_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]]);
    assert_eq!(u32_at(0), 7);
    assert_eq!(u32_at(4) as i32, -5);
    assert_eq!((u32_at(8), u32_at(12), u32_at(16)), (40, 322, 229));
    assert_eq!((u32_at(20) as i32, u32_at(24), u32_at(28), u32_at(32)), (-4, 68, 320, 200));
    assert_eq!((rec[36], rec[37], rec[38], rec[39]), (3, 2, 1, 0));
    assert_eq!((rec[40], rec[41]), (10, 12));
    assert_eq!(&rec[44..54], b"svc-awmi-b");
    assert_eq!(&rec[68..80], b"system: fake");

    // Per-client window accounting (the service caps windows per client).
    let mut wm = WmState::new();
    wm.layout.add_output(0, 800, 600, 60_000, false).unwrap();
    for _ in 0..3 {
        wm.create_window(4, b"x", TrustTier::Native, 100, 100, win_flags::DEFAULT, b"").unwrap();
    }
    wm.create_window(5, b"y", TrustTier::Native, 100, 100, win_flags::DEFAULT, b"").unwrap();
    assert_eq!((wm.owner_window_count(4), wm.owner_window_count(5), wm.windows().count()), (3, 1, 4));
    wm.remove_client(4);
    assert_eq!((wm.owner_window_count(4), wm.window_count()), (0, 1));
}

#[test]
fn themes_parse_encode_and_meet_contrast() {
    // The shipped theme files are exactly the built-in themes.
    for (file, id) in [
        (include_str!("../../../init/themes/dark-slate.toml"), ThemeId::DarkSlate),
        (include_str!("../../../init/themes/high-contrast.toml"), ThemeId::HighContrast),
    ] {
        assert_eq!(Theme::from_toml(file), Ok(id.builtin()), "{}", id.file());
    }
    // Discrete Blue is the accent fill.
    assert_eq!(Theme::DARK_SLATE.accent, rgb(0x56, 0x60, 0x87));
    // Wire round trip, and clamping of shape tokens from untrusted bytes.
    let mut b = [0u8; THEME_BYTES];
    Theme::HIGH_CONTRAST.encode(&mut b);
    assert_eq!(Theme::decode(&b), Some(Theme::HIGH_CONTRAST));
    assert_eq!(Theme::decode(&b[..10]), None);
    let m = COLOR_NAMES.len() * 4;
    b[m..m + 4].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(Theme::decode(&b).unwrap().focus_ring, 4);
    // Strictness: unknown keys, bad values and missing colours are refused.
    assert_eq!(Theme::from_toml("[colors]\nnope = \"#000000\""), Err(ThemeError::Unknown(2)));
    assert_eq!(Theme::from_toml("[colors]\ndesktop_bg = \"#00000\""), Err(ThemeError::Value(2)));
    assert_eq!(Theme::from_toml("[colors]\ndesktop_bg = #000000"), Err(ThemeError::Value(2)));
    assert!(matches!(Theme::from_toml("[colors]\ndesktop_bg = \"#000000\""), Err(ThemeError::Missing(_))));
    assert_eq!(Theme::from_toml("[metrics]\nfocus_ring = 9"), Err(ThemeError::Value(2)));
    assert_eq!(Theme::from_toml("garbage"), Err(ThemeError::Syntax(1)));
    // WCAG contrast of the pairs that matter (text 4.5:1, rings and outlines 3:1).
    fn lin(c: u32) -> f64 {
        let v = f64::from(c & 0xFF) / 255.0;
        if v <= 0.04045 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
    }
    fn lum(c: u32) -> f64 {
        0.2126 * lin(c >> 16) + 0.7152 * lin(c >> 8) + 0.0722 * lin(c)
    }
    fn ratio(a: u32, b: u32) -> f64 {
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }
    for t in [Theme::DARK_SLATE, Theme::HIGH_CONTRAST] {
        assert!(ratio(t.text_primary, t.title_active) >= 7.0);
        assert!(ratio(t.text_muted, t.title_active) >= 4.5, "muted text {:.2}", ratio(t.text_muted, t.title_active));
        assert!(ratio(t.text_on_accent, t.accent) >= 4.5, "text on accent {:.2}", ratio(t.text_on_accent, t.accent));
        assert!(ratio(t.accent_ring, t.title_active) >= 3.0, "ring {:.2}", ratio(t.accent_ring, t.title_active));
        assert!(ratio(t.accent_ring, t.surface_raised) >= 3.0);
        assert!(ratio(t.accent_ring, t.desktop_bg) >= 4.5, "accent text on desktop {:.2}", ratio(t.accent_ring, t.desktop_bg));
    }
    assert!(ratio(Theme::HIGH_CONTRAST.text_primary, Theme::HIGH_CONTRAST.client_bg) >= 15.0);
}

fn launcher_wm() -> WmState {
    let mut wm = WmState::new();
    wm.layout.add_output(1, 1280, 800, 60_000, false).unwrap();
    wm.register_app(7, 0, b"Terminal", b"console", TrustTier::System);
    wm.register_app(8, 0, b"Widgets", b"awmi-demo", TrustTier::System);
    wm.register_app(9, 1, b"Notes", b"foreign-notes", TrustTier::Sandbox);
    wm
}

#[test]
fn launcher_opens_on_super_tap_and_searches() {
    let mut wm = launcher_wm();
    let w = wm.create_window(7, b"console", TrustTier::System, 400, 300, win_flags::DEFAULT, b"Terminal").unwrap();
    // A Super tap opens; Super used as a modifier does not.
    assert_eq!(wm.handle_key(KEY_META, true), WmAction::None);
    let _ = wm.handle_key(0x103 | 1 << 19, true); // Super+Left
    assert_eq!(wm.handle_key(KEY_META, false), WmAction::None);
    assert!(!wm.launcher.open);
    wm.handle_key(KEY_META, true);
    wm.handle_key(KEY_META, false);
    assert!(wm.launcher.open);
    // While open, typing goes to the search, never to the focused window.
    for &c in b"term" {
        assert_eq!(wm.handle_key(u32::from(c), true), WmAction::None);
    }
    assert_eq!(wm.launcher.query(), b"term");
    assert_eq!(wm.handle_key(0x0A, true), WmAction::Launch { owner: 7, app: 0 });
    assert!(!wm.launcher.open);
    // Keys reach the window again.
    assert_eq!(wm.handle_key(u32::from(b'x'), true), WmAction::DeliverKey { owner: 7, window_id: w });
    // Alt+F1 opens too; the identity matches ("foreign"), Escape closes.
    wm.handle_key(0x110 | 1 << 18, true);
    assert!(wm.launcher.open);
    for &c in b"foreign" {
        wm.handle_key(u32::from(c), true);
    }
    let mut r = [LaunchTarget::Setting(Setting::ThemeToggle); 24 + crate::launcher::SETTING_COUNT];
    assert_eq!(wm.launcher.results(&mut r), 1);
    assert_eq!(r[0], LaunchTarget::App { owner: 9, app: 1 });
    wm.handle_key(0x1B, true);
    assert!(!wm.launcher.open);
    // Settings: "text" finds the two text sizes and the text console; Down moves the selection.
    wm.toggle_launcher();
    for &c in b"text" {
        wm.handle_key(u32::from(c), true);
    }
    assert_eq!(wm.launcher.results(&mut r), 3, "larger, smaller, leave (text console)");
    wm.handle_key(0x102, true);
    assert_eq!(wm.handle_key(0x0D, true), WmAction::Setting(Setting::TextSmaller));
    // Super+Esc still leaves the session from the launcher.
    wm.toggle_launcher();
    assert_eq!(wm.handle_key(0x1B | 1 << 19, true), WmAction::ExitSession);
    // A program that goes away loses its entries.
    wm.remove_client(9);
    wm.toggle_launcher();
    assert_eq!(wm.launcher.results(&mut r), 2 + crate::launcher::SETTING_COUNT);
}

#[test]
fn launcher_is_modal_for_the_pointer() {
    let mut wm = launcher_wm();
    let w = wm.create_window(7, b"console", TrustTier::System, 400, 300, win_flags::DEFAULT, b"Terminal").unwrap();
    let c = wm.window(w).unwrap().client_rect(wm.chrome);
    wm.toggle_launcher();
    let rects = wm.launcher.rects(1280, 800, wm.line_h);
    assert!(rects.n >= 3);
    // Moving over the second row selects it; a click opens it.
    let r1 = rects.rows[1];
    assert_eq!(wm.handle_pointer(0, 0, Some(Point::new(r1.x + 20, r1.y + 5)), 0), WmAction::None);
    assert_eq!(wm.launcher.sel, 1);
    assert_eq!(wm.handle_pointer(0, 0, Some(Point::new(r1.x + 20, r1.y + 5)), 1), WmAction::Launch { owner: 8, app: 0 });
    wm.handle_pointer(0, 0, Some(Point::new(r1.x + 20, r1.y + 5)), 0);
    // A click outside closes it and is not delivered to the window under it.
    wm.toggle_launcher();
    assert_eq!(wm.handle_pointer(0, 0, Some(Point::new(c.x + 5, c.y + c.h as i32 - 5)), 1), WmAction::None);
    assert!(!wm.launcher.open);
    // Rendering the open launcher (with the bitmap font) draws the panel.
    wm.handle_pointer(0, 0, Some(Point::new(0, 0)), 0);
    wm.toggle_launcher();
    wm.now_ns = 1_000_000_000;
    let mut fb = vec![0u32; 1280 * 800];
    let mut canvas = Canvas::new(&mut fb, 1280, 800, 1280).unwrap();
    wm.composite_output(wm.layout.primary().unwrap(), &mut canvas, &mut BitmapText, |_| None);
    let p = rects.panel;
    assert_eq!(canvas.get_pixel((p.x + 30) as u32, (p.y + p.h as i32 - 4) as u32), Some(Theme::DARK_SLATE.surface_raised));
}

#[test]
fn settings_resize_chrome_and_animations_respect_reduce_motion() {
    let mut wm = launcher_wm();
    let w = wm.create_window(7, b"console", TrustTier::System, 400, 300, win_flags::DEFAULT, b"").unwrap();
    wm.snap_window(w, SnapState::Maximized);
    let before = wm.window(w).unwrap().frame;
    let s = UiSettings::DEFAULT.apply(Setting::TextLarger).apply(Setting::TextLarger);
    assert_eq!(s.text_scale, 150);
    assert_eq!(UiSettings::unpack(s.pack()), s);
    assert_eq!(UiSettings::unpack(0xFFFF_FFFF).text_scale, 100, "unknown scales fall back");
    wm.apply_settings(s, Theme::HIGH_CONTRAST, 24, 11);
    assert_eq!(wm.chrome.title_h, 36);
    assert!(wm.dock_cfg.height > 40);
    let after = wm.window(w).unwrap().frame;
    assert!(after.h < before.h, "maximized windows follow the taller dock");
    assert_eq!(wm.theme, Theme::HIGH_CONTRAST);
    // The open animation runs for OPEN_NS unless motion is reduced.
    wm.now_ns = 5_000_000_000;
    wm.toggle_launcher();
    assert!(wm.animating());
    wm.now_ns += 200_000_000;
    assert!(!wm.animating());
    wm.toggle_launcher();
    wm.apply_settings(s.apply(Setting::MotionToggle), Theme::DARK_SLATE, 16, 8);
    wm.toggle_launcher();
    assert!(!wm.animating());
    assert_eq!(UiSettings::DEFAULT.apply(Setting::ThemeToggle).theme, ThemeId::HighContrast);
    assert_eq!(UiSettings::DEFAULT.smaller().text_scale, 100);
}

#[test]
fn rounded_shapes_are_antialiased_with_crisp_edges() {
    // Integer square root: exact floor for small values, squares and their neighbours.
    for n in 0u64..5000 {
        let r = crate::pixel::isqrt(n);
        assert!(r * r <= n && (r + 1) * (r + 1) > n, "isqrt({n}) = {r}");
    }
    for k in [255u64, 4096, 65_535, 1 << 20, 3_000_000_000] {
        assert_eq!(crate::pixel::isqrt(k * k), k);
        assert_eq!(crate::pixel::isqrt(k * k - 1), k - 1);
    }

    const BG: u32 = 0xFF00_0000;
    const FILL: u32 = 0xFFFF_FFFF;
    const BORDER: u32 = 0xFFFF_0000;
    let mut fb = vec![BG; 64 * 64];
    let mut c = Canvas::new(&mut fb, 64, 64, 64).unwrap();
    let all = c.bounds();
    let r = Rect::new(10, 10, 40, 30);
    c.fill_rounded_rect(all, r, 8, FILL, 0);
    let px = |c: &Canvas<'_>, x: u32, y: u32| c.get_pixel(x, y).unwrap() & 0xFF; // blue channel
    // The very corner is outside the curve, the interior and straight edges fully covered.
    assert_eq!(px(&c, 10, 10), 0);
    assert_eq!(px(&c, 30, 10), 255, "top edge");
    assert_eq!(px(&c, 10, 25), 255, "left edge");
    assert_eq!(px(&c, 30, 25), 255, "interior");
    assert_eq!(px(&c, 9, 25), 0, "nothing outside the rectangle");
    // Along the curve there are partial pixels (anti-aliasing), and coverage grows inward.
    let partial = (10..18).flat_map(|y| (10..18).map(move |x| (x, y))).filter(|&(x, y)| (1..255).contains(&px(&c, x, y))).count();
    assert!(partial >= 6, "only {partial} anti-aliased corner pixels");
    assert!(px(&c, 11, 13) <= px(&c, 12, 13) && px(&c, 12, 13) <= px(&c, 13, 13));
    // The corner is symmetric.
    for d in 0..8 {
        assert_eq!(px(&c, 10 + d, 12), px(&c, 49 - d, 12), "left/right mirror at {d}");
        assert_eq!(px(&c, 10 + d, 12), px(&c, 10 + d, 37), "top/bottom mirror at {d}");
    }

    // With a border: the 1px band is the border colour on straight edges, fill inside.
    let mut fb = vec![BG; 64 * 64];
    let mut c = Canvas::new(&mut fb, 64, 64, 64).unwrap();
    c.fill_rounded_rect(all, r, 8, FILL, BORDER);
    assert_eq!(c.get_pixel(30, 10), Some(BORDER));
    assert_eq!(c.get_pixel(49, 25), Some(BORDER));
    assert_eq!(c.get_pixel(30, 11), Some(FILL));

    // Circles: the centre covered, a smooth rim, nothing past it.
    let mut fb = vec![BG; 64 * 64];
    let mut c = Canvas::new(&mut fb, 64, 64, 64).unwrap();
    c.fill_circle(all, 20, 20, 6, FILL);
    assert_eq!(px(&c, 20, 20), 255);
    assert_eq!(px(&c, 20, 13), 0);
    assert!((1..255).contains(&px(&c, 24, 25)), "rim pixel {}", px(&c, 24, 25));
}

#[test]
fn dock_pinned_apps_and_per_output_scale() {
    let mut wm = WmState::new();
    // Mixed-DPI multi-monitor layout: 2560x1440 (auto 125%) + 3840x2160 (auto 150%) + 1920x1080 (auto 100%).
    wm.layout.add_output(1, 2560, 1440, 240_000, true).unwrap();
    wm.layout.add_output(2, 3840, 2160, 60_000, false).unwrap();
    wm.layout.add_output(3, 1920, 1080, 144_000, false).unwrap();
    assert_eq!(wm.layout.as_slice()[0].scale, 125);
    assert_eq!(wm.layout.as_slice()[1].scale, 150);
    assert_eq!(wm.layout.as_slice()[2].scale, 100);
    assert!(wm.layout.set_output_scale(2, 175));
    assert_eq!(wm.layout.as_slice()[1].scale, 175);
    assert!(!wm.layout.set_output_scale(2, 133)); // invalid scale rejected
    assert!(wm.layout.set_output_scale(2, 0)); // 0 resets to recommended auto
    assert_eq!(wm.layout.as_slice()[1].scale, 150);

    // Pin Terminal (owner 7, app 0) to the floating dock.
    assert!(wm.register_app_ex(7, 0, b"Terminal", b"console", TrustTier::System, true));
    let prim = wm.layout.primary().unwrap();
    let dl = wm.dock_layout_for(prim);
    assert_eq!(dl.pinned_count, 1);
    let (_, _, pr) = dl.pinned_rects[0];
    let click_pt = Point::new(pr.x + 12, pr.y + (pr.h as i32) / 2);
    assert_eq!(dl.hit_test(click_pt), DockHit::Pinned(7, 0));

    // Clicking pinned pill while closed emits WmAction::Launch.
    let act = wm.handle_pointer(0, 0, Some(click_pt), 1);
    assert_eq!(act, WmAction::Launch { owner: 7, app: 0 });
    wm.handle_pointer(0, 0, Some(click_pt), 0);

    // Once owner 7 opens a window (and even if minimized), clicking the pinned pill focuses/restores it.
    let wid = wm.create_window(7, b"console", TrustTier::System, 640, 400, win_flags::DEFAULT, b"Terminal").unwrap();
    wm.minimize_window(wid);
    assert!(wm.window(wid).unwrap().minimized);
    let act2 = wm.handle_pointer(0, 0, Some(click_pt), 1);
    assert_eq!(act2, WmAction::Configure { owner: 7, window_id: wid });
    assert!(!wm.window(wid).unwrap().minimized);
    assert_eq!(wm.focused, Some(wid));

    // Render pinned pill + running dot cleanly without panic.
    let mut fb = vec![0u32; 2560 * 1440];
    let mut canvas = Canvas::new(&mut fb, 2560, 1440, 2560).unwrap();
    wm.damage_all();
    let flushed = wm.composite_output(prim, &mut canvas, &mut BitmapText, |_| None);
    assert!(!flushed.is_empty());

    // Disconnecting owner 7 removes the pinned pill from the dock.
    wm.remove_client(7);
    assert_eq!(wm.dock_layout_for(prim).pinned_count, 0);
}

#[test]
fn lock_screen_hides_windows_blocks_escape_and_wipes_passphrase() {
    use crate::lock::{LockIdentity, LockMode, LockReason};
    use crate::perm::{PERM_ALLOW, PERM_CANCEL};

    let mut wm = WmState::new();
    wm.layout.add_output(0, 800, 600, 60_000, false).unwrap();
    let w1 = wm.create_window(1, b"secret-app", TrustTier::Native, 300, 200, win_flags::DEFAULT, b"Secret").unwrap();
    let client_r = wm.window(w1).unwrap().client_rect(wm.chrome);

    // Super+L triggers LockSession when unlocked.
    const SUPER: u32 = 1 << 19;
    const CTRL: u32 = 1 << 17;
    const ALT: u32 = 1 << 18;
    assert_eq!(wm.handle_key(SUPER | u32::from(b'l'), true), WmAction::LockSession);
    assert_eq!(wm.handle_key(CTRL | ALT | u32::from(b'l'), true), WmAction::LockSession);

    // Engage lock screen with bright-magenta secret window underneath.
    let ids = [LockIdentity::new(1, b"user", b"Local User", true, true)];
    wm.lock.set_identities(&ids, 1, true);
    wm.engage_lock(LockMode::Locked, LockReason::Manual);
    assert!(wm.lock.active);

    // Super+Esc, Ctrl+Alt+Esc, Super tap, and client input are ALL blocked while locked!
    assert_eq!(wm.handle_key(SUPER | 0x1B, true), WmAction::None);
    assert_eq!(wm.handle_key(CTRL | ALT | 0x1B, true), WmAction::None);
    assert_eq!(wm.handle_key(KEY_META, true), WmAction::None);
    assert_eq!(wm.handle_key(KEY_META, false), WmAction::None);
    assert!(!wm.launcher.open);
    assert_eq!(wm.handle_pointer(0, 0, Some(Point::new(client_r.x + 10, client_r.y + 10)), 1), WmAction::None);

    // Composite output: ZERO bright-magenta client pixels may appear anywhere on screen!
    let magenta = rgb(0xFF, 0x00, 0xFF);
    let mut surf = vec![0u8; (client_r.w * client_r.h * 4) as usize];
    for c in surf.as_chunks_mut::<4>().0 {
        *c = magenta.to_le_bytes();
    }
    let mut fb = vec![0u32; 800 * 600];
    let mut canvas = Canvas::new(&mut fb, 800, 600, 800).unwrap();
    let prim = wm.layout.primary().unwrap();
    wm.composite_output(prim, &mut canvas, &mut BitmapText, |_| {
        Some(SurfaceView { bytes: &surf, width: client_r.w, height: client_r.h, pitch_bytes: client_r.w * 4 })
    });
    assert!(!fb.contains(&magenta), "lock screen leaked client window pixels!");

    // Typing passphrase goes ONLY to lock screen and submits UnlockAttempt on Enter.
    for &c in b"s3cret" {
        assert_eq!(wm.handle_key(u32::from(c), true), WmAction::None);
    }
    assert_eq!(wm.lock.passphrase(), b"s3cret");
    assert_eq!(wm.handle_key(0x0D, true), WmAction::UnlockAttempt { identity_id: 1 });
    wm.lock.set_error(b"Invalid passphrase");
    assert_eq!(wm.lock.pass_len(), 0);
    wm.disengage_lock();
    assert!(!wm.lock.active);

    // Compositor modal permission prompt traps input until answered.
    wm.open_perm_prompt(42, b"files", b"Files", 0b110);
    assert!(wm.perm_prompt.active);
    assert_eq!(wm.handle_key(u32::from(b'a'), true), WmAction::None);
    assert_eq!(wm.handle_key(0x0D, true), WmAction::PermPromptResult { request_id: 42, choice: PERM_ALLOW });
    assert!(!wm.perm_prompt.active);
    wm.open_perm_prompt(43, b"files", b"Files", 0b10);
    assert_eq!(wm.handle_key(0x1B, true), WmAction::PermPromptResult { request_id: 43, choice: PERM_CANCEL });
}

#[test]
fn custom_cursors_and_lock_screen_tpm_badge_colors() {
    use crate::lock::{LockIdentity, LockMode, LockReason};
    use crate::pixel::{CursorKind, write_hw_cursor_64x64_kind};

    // 1. Every custom cursor has non-empty silhouette, valid hotspot inside sprite, and crisp HW 64x64 blit.
    let all = [
        CursorKind::Default,
        CursorKind::Pointer,
        CursorKind::Text,
        CursorKind::Move,
        CursorKind::ResizeEW,
        CursorKind::ResizeNS,
        CursorKind::ResizeNWSE,
        CursorKind::ResizeNESW,
    ];
    let mut hw = vec![0u8; 64 * 64 * 4];
    for kind in all {
        let (w, h) = kind.size();
        let (hx, hy) = kind.hotspot();
        assert!(w >= 9 && h >= 9 && (hx as u32) < w && (hy as u32) < h, "{kind:?}");
        let (rhx, rhy) = write_hw_cursor_64x64_kind(kind, &mut hw);
        assert_eq!((rhx, rhy), (hx as u32, hy as u32));
        assert!(hw.as_chunks::<4>().0.iter().any(|c| c[3] == 0xFF), "empty hw cursor for {kind:?}");
    }

    // 2. Context-aware cursor transitions on window edges/corners, buttons, drag, dock, and lock screen.
    let mut wm = WmState::new();
    wm.layout.add_output(0, 1280, 720, 60_000, false).unwrap();
    let wid = wm.create_window(1, b"demo", TrustTier::Native, 400, 300, win_flags::DEFAULT, b"Demo").unwrap();
    let f = wm.window(wid).unwrap().frame;

    // Right edge -> ResizeEW, bottom edge -> ResizeNS, top-left -> ResizeNWSE, top-right -> ResizeNESW.
    wm.handle_pointer(0, 0, Some(Point::new(f.x + f.w as i32 - 1, f.y + f.h as i32 / 2)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::ResizeEW);
    wm.handle_pointer(0, 0, Some(Point::new(f.x + f.w as i32 / 2, f.y + f.h as i32 - 1)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::ResizeNS);
    wm.handle_pointer(0, 0, Some(Point::new(f.x + 1, f.y + 1)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::ResizeNWSE);
    wm.handle_pointer(0, 0, Some(Point::new(f.x + f.w as i32 - 1, f.y + 1)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::ResizeNESW);

    // Close button -> Pointer; Titlebar drag -> Move; release -> Default.
    wm.handle_pointer(0, 0, Some(Point::new(f.x + f.w as i32 - 12, f.y + 14)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::Pointer);
    let tb = Point::new(f.x + 80, f.y + 14);
    wm.handle_pointer(0, 0, Some(tb), 0);
    assert_eq!(wm.cursor_kind, CursorKind::Default);
    wm.handle_pointer(0, 0, Some(tb), 1);
    assert_eq!(wm.cursor_kind, CursorKind::Move);
    wm.handle_pointer(0, 0, Some(Point::new(tb.x + 20, tb.y + 10)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::Default);

    // 3. Lock screen TPM 2.0 badge colour reflects hardware presence and sealing state.
    let theme = Theme::DARK_SLATE;
    let sealed_id = [LockIdentity::new(1, b"user", b"Local User", true, true)];
    let soft_id = [LockIdentity::new(1, b"user", b"Local User", false, true)];
    wm.lock.set_identities(&sealed_id, 1, true);
    assert_eq!(wm.lock.tpm_badge_color(&theme), theme.status_ok);
    wm.lock.set_identities(&soft_id, 1, true);
    assert_eq!(wm.lock.tpm_badge_color(&theme), theme.trust_sandbox);
    wm.lock.set_identities(&soft_id, 1, false);
    assert_eq!(wm.lock.tpm_badge_color(&theme), theme.ind_alert_red);

    // Lock screen passphrase field shows Text cursor and desktop background shows Default.
    wm.engage_lock(LockMode::Locked, LockReason::Manual);
    wm.handle_pointer(0, 0, Some(Point::new(10, 10)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::Default);
    wm.handle_pointer(0, 0, Some(Point::new(640, 360)), 0);
    assert_eq!(wm.cursor_kind, CursorKind::Text);
}

#[test]
fn mode_switch_refits_pointer_snapped_and_floating_windows() {
    let mut wm = WmState::new();
    wm.layout.add_output(1, 2560, 1440, 60_000, false).unwrap();
    let max_id = wm.create_window(1, b"settings", TrustTier::Native, 800, 600, win_flags::DEFAULT, b"Settings").unwrap();
    let flt_id = wm.create_window(2, b"term", TrustTier::Native, 600, 400, win_flags::DEFAULT, b"Terminal").unwrap();
    wm.snap_window(max_id, SnapState::Maximized);
    if let Some(w) = wm.window_mut(flt_id) {
        w.frame = Rect::new(2000, 1050, 600, 400);
        w.saved_floating = w.frame;
    }
    wm.pointer = Point::new(2400, 1300);

    // Switch output to a smaller 240 Hz mode and verify full damage + clamped geometry.
    wm.damage.clear();
    wm.layout.clear();
    wm.layout.add_output(1, 1920, 1080, 240_000, false).unwrap();
    wm.fit_windows_to_layout();

    assert!(!wm.damage.is_empty());
    assert!(wm.pointer.x < 1920 && wm.pointer.y < 1080);
    let out = wm.layout.primary().unwrap();
    let work = wm.layout.work_area(out, wm.dock_cfg);
    assert_eq!(wm.window(max_id).unwrap().frame, work);
    let ff = wm.window(flt_id).unwrap().frame;
    assert!(ff.x >= work.x && ff.y >= work.y);
    assert!(ff.x + ff.w as i32 <= work.x + work.w as i32);
    assert!(ff.y + ff.h as i32 <= work.y + work.h as i32);
}

#[test]
fn right_click_unpins_dock_app_and_toggles_launcher_pin() {
    let mut wm = WmState::new();
    wm.layout.add_output(0, 1280, 800, 60_000, false).unwrap();
    assert!(wm.register_app_ex(7, 0, b"Terminal", b"terminal", TrustTier::Native, true));
    assert!(wm.register_app_ex(7, 1, b"Install D-OS", b"installer", TrustTier::Native, true));

    let out = wm.layout.primary().unwrap();
    let dl = wm.dock_layout_for(out);
    assert_eq!(dl.pinned_count, 2);
    let (_, _, pill) = dl.pinned_rects[1];
    let pt = Point::new(pill.x + 8, pill.y + 8);
    // Right-click (button bit 1 = value 2) on the second pinned pill unpins it.
    let act = wm.handle_pointer(0, 0, Some(pt), 2);
    assert_eq!(act, WmAction::SetAppPinned { owner: 7, app: 1, pinned: false });
    wm.handle_pointer(0, 0, Some(pt), 0);
    let dl2 = wm.dock_layout_for(wm.layout.primary().unwrap());
    assert_eq!(dl2.pinned_count, 1);

    // Re-pinning via open launcher right-click restores it to the dock.
    wm.toggle_launcher();
    let prim = wm.layout.primary().unwrap();
    let rects = wm.launcher.rects(prim.bounds.w, prim.bounds.h, wm.line_h);
    let row1 = rects.rows[1];
    let rpt = Point::new(prim.bounds.x + row1.x + 12, prim.bounds.y + row1.y + 8);
    let act2 = wm.handle_pointer(0, 0, Some(rpt), 2);
    assert_eq!(act2, WmAction::SetAppPinned { owner: 7, app: 1, pinned: true });
    let dl3 = wm.dock_layout_for(wm.layout.primary().unwrap());
    assert_eq!(dl3.pinned_count, 2);
}

#[test]
fn launcher_file_lookup_ranks_and_opens_paths() {
    use crate::launcher::{MAX_RESULTS, PowerAction};
    let mut wm = launcher_wm();
    wm.launcher.push_file(b"/home/docs", true);
    wm.launcher.push_file(b"/home/docs/report.txt", false);
    wm.launcher.push_file(b"/home/readme.md", false);
    wm.launcher.push_file(b"/sys/themes/dark-slate.toml", false);
    assert_eq!(wm.launcher.file_count(), 4);

    // Empty query keeps the clean default Apps + Settings view (no file clutter).
    wm.toggle_launcher();
    let mut res = [LaunchTarget::Setting(Setting::ThemeToggle); MAX_RESULTS];
    let n_empty = wm.launcher.results(&mut res);
    assert!(res[..n_empty].iter().all(|t| !matches!(t, LaunchTarget::File { .. } | LaunchTarget::Power(_))));

    // Typing "rep" ranks "/home/docs/report.txt" at top and Enter emits WmAction::OpenPath.
    for &c in b"rep" {
        assert_eq!(wm.handle_key(u32::from(c), true), WmAction::None);
    }
    let n = wm.launcher.results(&mut res);
    assert!(n >= 1);
    assert!(matches!(res[0], LaunchTarget::File { .. }));
    let act = wm.handle_key(0x0A, true);
    match act {
        WmAction::OpenPath { path, len, is_dir } => {
            assert_eq!(&path[..usize::from(len)], b"/home/docs/report.txt");
            assert!(!is_dir);
        }
        other => panic!("expected OpenPath for report.txt, got {:?}", other),
    }
    assert!(!wm.launcher.open);

    // Directory lookup: typing "docs" selects directory "/home/docs" before nested file.
    wm.toggle_launcher();
    for &c in b"docs" {
        assert_eq!(wm.handle_key(u32::from(c), true), WmAction::None);
    }
    match wm.handle_key(0x0D, true) {
        WmAction::OpenPath { path, len, is_dir } => {
            assert_eq!(&path[..usize::from(len)], b"/home/docs");
            assert!(is_dir);
        }
        other => panic!("expected OpenPath for /home/docs, got {:?}", other),
    }

    // Typing "reboot" or "rest" matches Power actions directly from keyboard.
    wm.toggle_launcher();
    for &c in b"reboot" {
        let _ = wm.handle_key(u32::from(c), true);
    }
    assert_eq!(wm.handle_key(0x0A, true), WmAction::Power(PowerAction::Reboot));
    wm.toggle_launcher();
    for &c in b"rest" {
        let _ = wm.handle_key(u32::from(c), true);
    }
    assert_eq!(wm.handle_key(0x0A, true), WmAction::Power(PowerAction::Sleep));
}

#[test]
fn launcher_power_menu_toggle_and_all_four_controls() {
    use crate::CursorKind;
    use crate::launcher::PowerAction;
    let mut wm = launcher_wm();
    let expected = [PowerAction::Off, PowerAction::Reboot, PowerAction::Lock, PowerAction::Sleep];

    for (idx, &want) in expected.iter().enumerate() {
        wm.toggle_launcher();
        assert!(wm.launcher.open);
        assert!(!wm.launcher.power_open);
        let prim = wm.layout.primary().unwrap();
        let rects = wm.launcher.rects(prim.bounds.w, prim.bounds.h, wm.line_h);

        // Hovering Power button shows Pointer cursor; clicking toggles the 4 power controls open.
        let pbtn = Point::new(prim.bounds.x + rects.power_btn.x + 8, prim.bounds.y + rects.power_btn.y + 8);
        assert_eq!(wm.handle_pointer(0, 0, Some(pbtn), 0), WmAction::None);
        assert_eq!(wm.cursor_kind, CursorKind::Pointer);
        assert_eq!(wm.handle_pointer(0, 0, Some(pbtn), 1), WmAction::None);
        assert_eq!(wm.handle_pointer(0, 0, Some(pbtn), 0), WmAction::None);
        assert!(wm.launcher.power_open);

        // Click option `idx` (Off / Reboot / Lock / Rest).
        let open_rects = wm.launcher.rects(prim.bounds.w, prim.bounds.h, wm.line_h);
        let opt = open_rects.power_opts[idx];
        assert!(!opt.is_empty());
        let opt_pt = Point::new(prim.bounds.x + opt.x + 8, prim.bounds.y + opt.y + 8);
        assert_eq!(wm.handle_pointer(0, 0, Some(opt_pt), 0), WmAction::None);
        assert_eq!(wm.cursor_kind, CursorKind::Pointer);
        assert_eq!(wm.handle_pointer(0, 0, Some(opt_pt), 1), WmAction::Power(want));
        assert_eq!(wm.handle_pointer(0, 0, Some(opt_pt), 0), WmAction::None);
        assert!(!wm.launcher.open);
    }

    // Escape closes the expanded power menu first without dismissing the launcher.
    wm.toggle_launcher();
    let prim = wm.layout.primary().unwrap();
    let rects = wm.launcher.rects(prim.bounds.w, prim.bounds.h, wm.line_h);
    let pbtn = Point::new(prim.bounds.x + rects.power_btn.x + 8, prim.bounds.y + rects.power_btn.y + 8);
    wm.handle_pointer(0, 0, Some(pbtn), 1);
    wm.handle_pointer(0, 0, Some(pbtn), 0);
    assert!(wm.launcher.power_open);
    assert_eq!(wm.handle_key(0x1B, true), WmAction::None);
    assert!(wm.launcher.open && !wm.launcher.power_open);
    assert_eq!(wm.handle_key(0x1B, true), WmAction::None);
    assert!(!wm.launcher.open);
}
