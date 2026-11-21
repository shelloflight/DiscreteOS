//! Host unit tests and 12,000-round fuzzers for `dosawmi`.

use std::vec;

use crate::dock::{DockHit, DockLayout};
use crate::geom::{DamageSet, Point, Rect};
use crate::pixel::{Canvas, blend_over, write_hw_cursor_64x64};
use crate::proto::{AwmiStatus, STATUS_BYTES, TrustTier, decode_damage_rects, encode_damage_rects, indicator_bits, sanitize_label, win_flags};
use crate::theme::{ChromeMetrics, DockConfig, Theme, argb, rgb};
use crate::wm::{SnapState, SurfaceView, WmAction, WmState};

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
    let flushed = wm.composite_output(wm.layout.primary().unwrap(), &mut canvas, |wid| {
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
    let dl = DockLayout::compute(1024, 768, DockConfig::DEFAULT, &[], &wm.tray);
    assert_eq!(dl.bar.x, 24);
    assert_eq!(dl.bar.w, 1024 - 48);
    assert_eq!(dl.hit_test(Point::new(dl.ws_rects[2].x + 4, dl.ws_rects[2].y + 4)), DockHit::Workspace(2));
    assert_eq!(dl.hit_test(Point::new(dl.mic_rect.x + 8, dl.mic_rect.y + 8)), DockHit::Indicator);
    // Verify green MIC LIVE dot pixel was rendered inside the dock.
    let mic_dot = canvas.get_pixel((dl.mic_rect.x + 9) as u32, (dl.mic_rect.y + dl.mic_rect.h as i32 / 2) as u32).unwrap();
    assert_eq!(mic_dot, Theme::DARK_SLATE.ind_mic_live);

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
            let _ = wm.composite_output(wm.layout.primary().unwrap(), &mut canvas, |_| {
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
