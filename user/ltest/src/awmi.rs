//! D-AWMI compositor tests (`awmi-virtio`, `awmi-gop`; manifests in user/init/services/awmi):
//! - `svc-awmi-ungranted`: no grant, no compositor endpoint;
//! - `svc-awmi-a`, `svc-awmi-b`: window-only clients: refused every admin, status, indicator and
//!   test operation and every other client's window; each draws its window in its own colour and
//!   must receive exactly the one key typed while it was focused, then close on request;
//! - `svc-awmi-full`: starts the session and checks, through the compositor's test hooks: surface
//!   isolation by readback, click-to-focus and key routing, verified identity and trust tier,
//!   keyboard snapping, workspaces, a second (virtual) output, indicators (the microphone through
//!   a real capture stream), close requests, and the exclusive input grab with real keys and
//!   pointer events typed by the host; then ends the session. Before the client windows: the
//!   shared fonts (read-only), launcher registration and the Super-tap launcher, the settings
//!   (theme, text size, motion; admin only) and the frame readback.

use libd::awmi::{self, Event, Window, WindowInfo};
use libd::proto::key;
use libd::{println, sys};

macro_rules! check {
    ($c:expr, $($t:tt)*) => {
        if !$c {
            println!("ltest: svc FAIL: {} (line {})", format_args!($($t)*), line!());
            return 1;
        }
    };
}

const SEC: u64 = 1_000_000_000;
const RED: u32 = 0x00D0_3030;
const GREEN: u32 = 0x0030_C050;
const DENIED: Result<(), i64> = Err(sys::ERR_ACCESS_DENIED);

fn fill(w: &mut Window, color: u32) {
    let px = color.to_le_bytes();
    for c in w.pixels().as_chunks_mut::<4>().0 {
        *c = px;
    }
}

pub fn ungranted() -> i32 {
    check!(
        awmi::window_endpoint() == 0 && awmi::admin_endpoint() == 0 && awmi::query_endpoint() == 0 && awmi::indicator_endpoint() == 0,
        "an ungranted process received a compositor endpoint"
    );
    println!("svc-awmi-ungranted: PASSED (no compositor endpoint)");
    0
}

/// A window-only client: `name`, its colour, the one key it must get, an optional later title.
pub fn client(name: &str, color: u32, title: &[u8], retitle: Option<&[u8]>, want: u8) -> i32 {
    let ep = awmi::window_endpoint();
    check!(ep != 0, "no awmi.window endpoint");
    check!(awmi::admin_endpoint() == 0 && awmi::query_endpoint() == 0 && awmi::indicator_endpoint() == 0, "a window client got more than awmi.window");
    // The window endpoint is refused everything but windows.
    check!(awmi::session_start(ep, false).map(|_| ()) == DENIED, "session start over awmi.window not refused");
    check!(awmi::session_stop(ep) == DENIED, "session stop over awmi.window not refused");
    check!(awmi::status(ep).map(|_| ()) == DENIED, "status over awmi.window not refused");
    check!(awmi::set_indicators(ep, awmi::IND_MIC_LIVE | awmi::IND_SECURITY_ALERT) == DENIED, "a window client could set the indicators");
    check!(awmi::test_key(ep, u32::from(b'x'), true) == DENIED, "test key injection over awmi.window not refused");
    check!(awmi::test_pixel(ep, 0, 0).map(|_| ()) == DENIED, "pixel readback over awmi.window not refused");
    let mut list = [WindowInfo::default(); 4];
    check!(awmi::test_windows(ep, &mut list).map(|_| ()) == DENIED, "window list over awmi.window not refused");

    // A session first.
    let deadline = sys::clock_ns() + 90 * SEC;
    loop {
        check!(sys::clock_ns() < deadline, "no session started");
        if let Ok(Some(Event::Session { active: true, .. })) = awmi::next_event(ep, SEC) {
            break;
        }
    }
    let mut w = match Window::new(ep, 320, 200, awmi::FLAGS_DEFAULT, title) {
        Ok(w) => w,
        Err(e) => {
            println!("ltest: svc FAIL: create window: {}", sys::status(e));
            return 1;
        }
    };
    fill(&mut w, color);
    check!(w.commit(&[]).is_ok(), "commit failed");
    if let Some(t) = retitle {
        check!(w.set_title(t).is_ok(), "set_title failed");
    }
    // Every other id: not ours, refused (whether it exists or not).
    for id in (1..=8u32).filter(|&i| i != w.id) {
        check!(awmi::destroy(ep, id) == DENIED, "destroyed window {} of another client", id);
        check!(awmi::set_title(ep, id, b"pwned") == DENIED, "retitled window {} of another client", id);
        check!(awmi::commit(ep, id, 1, &[]) == DENIED, "committed to window {} of another client", id);
    }
    println!("{}: window {} up, other clients' windows refused", name, w.id);

    let mut keys: [u32; 8] = [0; 8];
    let mut nkeys = 0usize;
    loop {
        check!(sys::clock_ns() < deadline, "no close request (keys: {:?})", &keys[..nkeys]);
        let ev = match awmi::next_event(ep, SEC) {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(e) => {
                println!("ltest: svc FAIL: event channel: {}", sys::status(e));
                return 1;
            }
        };
        let win = match ev {
            Event::Configure { window, .. } | Event::Key { window, .. } | Event::Pointer { window, .. } | Event::Focus { window, .. } | Event::Close { window } | Event::FrameDone { window, .. } => window,
            Event::Session { active, .. } => {
                check!(active, "the session ended before the close request");
                continue;
            }
            Event::Launch { .. } | Event::Settings { .. } | Event::PermResult { .. } => continue,
        };
        check!(win == w.id, "received an event for window {} (ours is {})", win, w.id);
        match ev {
            Event::Key { key: k, .. } => {
                if nkeys < keys.len() {
                    keys[nkeys] = k;
                }
                nkeys += 1;
            }
            Event::Configure { width, height, .. } => {
                if w.resize(width, height).is_ok() {
                    fill(&mut w, color);
                    let _ = w.commit(&[]);
                }
            }
            Event::Close { .. } => break,
            _ => {}
        }
    }
    check!(nkeys == 1 && keys[0] == u32::from(want), "keys received {:?}, expected exactly '{}'", &keys[..nkeys.min(8)], want as char);
    println!("{}: PASSED (only its own key '{}', closed on request)", name, want as char);
    0
}

fn windows(admin: sys::Handle) -> ([WindowInfo; 16], usize) {
    let mut list = [WindowInfo::default(); 16];
    let n = awmi::test_windows(admin, &mut list).unwrap_or(0);
    (list, n)
}

fn find<'a>(list: &'a [WindowInfo], identity: &[u8]) -> Option<&'a WindowInfo> {
    list.iter().find(|w| w.identity() == identity)
}

fn inside(f: (i32, i32, u32, u32), x: i32, y: i32) -> bool {
    x >= f.0 && y >= f.1 && i64::from(x) < i64::from(f.0) + i64::from(f.2) && i64::from(y) < i64::from(f.1) + i64::from(f.3)
}

/// A point of `w`'s client area that no other window's frame covers.
fn free_point(w: &WindowInfo, list: &[WindowInfo]) -> Option<(i32, i32)> {
    let (x, y, cw, ch) = w.client;
    let (r, b) = (x + cw as i32 - 7, y + ch as i32 - 7);
    [(x + 6, y + 6), (r, y + 6), (x + 6, b), (r, b), (x + cw as i32 / 2, y + ch as i32 / 2)]
        .into_iter()
        .find(|&(px, py)| list.iter().filter(|o| o.id != w.id).all(|o| !inside(o.frame, px, py)))
}

fn pixel_is(admin: sys::Handle, x: i32, y: i32, color: u32, timeout: u64) -> bool {
    let deadline = sys::clock_ns() + timeout;
    loop {
        if awmi::test_pixel(admin, x, y).is_ok_and(|p| p & 0x00FF_FFFF == color) {
            return true;
        }
        if sys::clock_ns() >= deadline {
            return false;
        }
        libd::handle::sleep(50_000_000);
    }
}

/// Click at `(x, y)`, then park the pointer in the desktop's corner: a software cursor (the
/// firmware framebuffer has no hardware one) must not sit on the pixels read back.
fn click(admin: sys::Handle, x: i32, y: i32) {
    let _ = awmi::test_pointer(admin, x, y, 1);
    let _ = awmi::test_pointer(admin, x, y, 0);
    let _ = awmi::test_pointer(admin, 0, 0, 0);
}

pub fn full() -> i32 {
    let admin = awmi::admin_endpoint();
    let query = awmi::query_endpoint();
    let ind = awmi::indicator_endpoint();
    let win = awmi::window_endpoint();
    check!(admin != 0 && query != 0 && ind != 0 && win != 0, "missing compositor endpoints");

    // 1. Idle, and each endpoint only does its own job.
    let st = awmi::status(query);
    check!(st.is_ok_and(|s| !s.active), "compositor not idle at start: {:?}", st);
    check!(awmi::session_start(query, false).map(|_| ()) == DENIED, "session start over awmi.query not refused");
    check!(awmi::test_key(query, u32::from(b'a'), true) == DENIED, "test hook over awmi.query not refused");
    check!(awmi::set_indicators(query, awmi::IND_SECURITY_ALERT) == DENIED, "indicator over awmi.query not refused");
    check!(awmi::session_start(ind, false).map(|_| ()) == DENIED, "session start over awmi.indicator not refused");
    check!(awmi::create(win, 64, 64, awmi::FLAGS_DEFAULT, b"early").map(|_| ()) == Err(sys::ERR_BAD_STATE), "a window was created without a session");

    // 2. The session.
    let outputs = match awmi::session_start(admin, false) {
        Ok(n) => n,
        Err(e) => {
            println!("ltest: svc FAIL: session start: {}", sys::status(e));
            return 1;
        }
    };
    let Ok(st) = awmi::status(admin) else {
        println!("ltest: svc FAIL: status");
        return 1;
    };
    check!(outputs >= 1 && st.active && st.width >= 640 && st.height >= 480, "session not active: {:?}", st);
    let (sw, sh) = (st.width as i32, st.height as i32);
    println!("svc-awmi-full: session OK ({} output(s), {}x{}, {}.{:03} Hz)", outputs, sw, sh, st.refresh_mhz / 1000, st.refresh_mhz % 1000);

    // 2b. The UI foundation: vector fonts shared read-only, the launcher, the settings.
    check!(st.fonts, "the compositor has no vector fonts (sys:/fonts)");
    match awmi::fonts(win) {
        Ok(map) => {
            let b = map.bytes();
            check!(b.len() >= 16 && &b[..4] == b"DFNT", "the font pack has no DFNT header");
            // The pack is read-only for window programs.
            check!(sys::vmo_write(map.vmo, 0, b"X") < 0 && sys::vmar_map(libd::root_vmar(), sys::ANY, map.vmo, 0, sys::PAGE, sys::RIGHT_READ | sys::RIGHT_WRITE).is_err(), "the shared font pack is writable");
            println!("svc-awmi-full: fonts OK ({} KiB pack, read-only)", map.len / 1024);
        }
        Err(e) => {
            println!("ltest: svc FAIL: fonts: {}", sys::status(e));
            return 1;
        }
    }
    check!(awmi::fonts(query).is_err(), "fonts over awmi.query not refused");
    check!(awmi::register_app(win, 0, b"Probe").is_ok(), "launcher registration refused");
    check!(awmi::register_app(win, 9, b"Too many").is_err(), "an out-of-range launcher entry was accepted");
    check!(awmi::register_app(query, 0, b"Probe").is_err(), "launcher registration over awmi.query not refused");
    let apps = awmi::status(admin).map(|s| s.apps).unwrap_or(0);
    check!(apps >= 1, "no launcher entries registered");
    let (h0, painted) = awmi::test_frame(admin).unwrap_or((0, 0));
    check!(painted > 0, "the desktop frame is empty (dock not drawn)");
    let _ = awmi::test_key(admin, key::META, true);
    let _ = awmi::test_key(admin, key::META, false);
    check!(awmi::status(admin).is_ok_and(|s| s.launcher_open), "a Super tap did not open the launcher");
    let (h1, _) = awmi::test_frame(admin).unwrap_or((0, 0));
    check!(h1 != h0, "the launcher was not drawn");
    let _ = awmi::test_key(admin, 0x1B, true);
    check!(awmi::status(admin).is_ok_and(|s| !s.launcher_open), "Escape did not close the launcher");
    check!(awmi::set_settings(query, 1, awmi::SET_THEME).is_err(), "settings over awmi.query not refused");
    check!(awmi::set_settings(win, 1, awmi::SET_THEME).is_err(), "settings over awmi.window not refused");
    check!(awmi::set_output_scale(query, 0, 125) == DENIED, "display config over awmi.query not refused");
    check!(awmi::set_output_scale(win, 0, 125) == DENIED, "display config over awmi.window not refused");
    check!(awmi::set_output_scale(admin, 0, 125).is_ok(), "per-output scale on admin failed");
    check!(awmi::set_output_scale(admin, 0, 0).is_ok(), "per-output scale reset on admin failed");
    let now = awmi::set_settings(admin, 1 | 150 << 8 | 1 << 24, awmi::SET_THEME | awmi::SET_TEXT_SCALE | awmi::SET_MOTION);
    check!(now == Ok(1 | 150 << 8 | 1 << 24), "settings not applied: {:?}", now);
    let mut told = false;
    let dl = sys::clock_ns() + 5 * SEC;
    while !told && sys::clock_ns() < dl {
        if let Ok(Some(Event::Settings { settings, theme })) = awmi::next_event(win, SEC / 4) {
            told = settings == 1 | 150 << 8 | 1 << 24 && theme[..4] != [0; 4];
        }
    }
    check!(told, "window programs were not told the settings");
    let (h2, _) = awmi::test_frame(admin).unwrap_or((0, 0));
    check!(h2 != h0, "the high-contrast theme did not change the frame");
    let back = awmi::set_settings(admin, 100 << 8, awmi::SET_THEME | awmi::SET_TEXT_SCALE | awmi::SET_MOTION);
    check!(back == Ok(100 << 8), "settings not restored: {:?}", back);
    println!("svc-awmi-full: launcher & settings OK ({} entries; theme, text size and motion sent to window programs)", apps);

    // 3. Both clients' windows, each in its own colour at its own place.
    let deadline = sys::clock_ns() + 30 * SEC;
    let (mut list, mut n);
    loop {
        (list, n) = windows(admin);
        // B renames itself right after its first frame: wait for that too.
        if find(&list[..n], b"svc-awmi-a").is_some() && find(&list[..n], b"svc-awmi-b").is_some_and(|w| w.title() == b"system: fake") {
            break;
        }
        check!(sys::clock_ns() < deadline, "the client windows did not appear ({} windows)", n);
        libd::handle::sleep(100_000_000);
    }
    let (Some(&wa), Some(&wb)) = (find(&list[..n], b"svc-awmi-a"), find(&list[..n], b"svc-awmi-b")) else { return 1 };
    let (Some(pa), Some(pb)) = (free_point(&wa, &list[..n]), free_point(&wb, &list[..n])) else {
        println!("ltest: svc FAIL: the windows cover each other entirely");
        return 1;
    };
    check!(pixel_is(admin, pa.0, pa.1, RED, 5 * SEC), "window A is not red at {:?}: {:?}", pa, awmi::test_pixel(admin, pa.0, pa.1));
    check!(pixel_is(admin, pb.0, pb.1, GREEN, 5 * SEC), "window B is not green at {:?}: {:?}", pb, awmi::test_pixel(admin, pb.0, pb.1));
    println!("svc-awmi-full: surface isolation OK (A red at {:?}, B green at {:?})", pa, pb);

    // 4. Identity: the service manager's, never the client's title.
    check!(wa.trust == awmi::TRUST_NATIVE && wa.title() == b"Alpha", "window A identity/trust/title wrong: {} {:?}", wa.trust, wa.title());
    check!(wb.trust == awmi::TRUST_SANDBOX && wb.title() == b"system: fake", "window B trust/title wrong: {} {:?}", wb.trust, wb.title());
    println!("svc-awmi-full: verified identity OK (svc-awmi-a native, svc-awmi-b sandbox despite title 'system: fake')");

    // 5. Click to focus; keys go to the focused window only.
    click(admin, pa.0, pa.1);
    let (list, n) = windows(admin);
    check!(find(&list[..n], b"svc-awmi-a").is_some_and(|w| w.focused), "a click did not focus window A");
    check!(awmi::test_key(admin, u32::from(b'a'), true).is_ok(), "key injection failed");
    click(admin, pb.0, pb.1);
    let (list, n) = windows(admin);
    check!(find(&list[..n], b"svc-awmi-b").is_some_and(|w| w.focused), "a click did not focus window B");
    check!(awmi::test_key(admin, u32::from(b'b'), true).is_ok(), "key injection failed");
    println!("svc-awmi-full: focus & input routing OK");

    // 6. Keyboard snapping (B focused): left half, maximized, restored.
    let before = find(&list[..n], b"svc-awmi-b").map(|w| w.frame);
    let _ = awmi::test_key(admin, key::SUPER | key::LEFT, true);
    let (list, n) = windows(admin);
    let f = find(&list[..n], b"svc-awmi-b").map(|w| w.frame);
    check!(f.is_some_and(|f| f.0 == 0 && f.1 == 0 && f.2 == sw as u32 / 2), "Super+Left: frame {:?}", f);
    let _ = awmi::test_key(admin, key::SUPER | key::UP, true);
    let (list, n) = windows(admin);
    let f = find(&list[..n], b"svc-awmi-b").map(|w| w.frame);
    check!(f.is_some_and(|f| f.0 == 0 && f.2 == sw as u32), "Super+Up: frame {:?}", f);
    let _ = awmi::test_key(admin, key::SUPER | key::DOWN, true);
    let (list, n) = windows(admin);
    let f = find(&list[..n], b"svc-awmi-b").map(|w| w.frame);
    check!(f == before, "Super+Down did not restore {:?}: {:?}", before, f);
    check!(pixel_is(admin, pb.0, pb.1, GREEN, 5 * SEC), "window B not redrawn after the snaps");
    println!("svc-awmi-full: snapping OK (left half, maximize, restore)");

    // 7. Workspaces: on workspace 2 nothing of workspace 1 shows or has focus.
    let _ = awmi::test_key(admin, key::SUPER | u32::from(b'2'), true);
    let st = awmi::status(admin);
    check!(st.is_ok_and(|s| s.active_workspace == 1 && s.focused_window == 0), "Super+2: {:?}", st);
    check!(!pixel_is(admin, pb.0, pb.1, GREEN, 0), "window B still visible on workspace 2");
    let _ = awmi::test_key(admin, key::SUPER | u32::from(b'1'), true);
    check!(awmi::status(admin).is_ok_and(|s| s.active_workspace == 0), "Super+1 did not switch back");
    check!(pixel_is(admin, pb.0, pb.1, GREEN, 5 * SEC), "window B not back on workspace 1");
    println!("svc-awmi-full: workspaces OK");

    // 8. A second output: drag B by its title bar onto it.
    check!(awmi::test_add_output(admin, 640, 480).is_ok(), "virtual output refused");
    check!(awmi::status(admin).is_ok_and(|s| u32::from(s.outputs) == outputs + 1), "the second output is missing");
    let (list, n) = windows(admin);
    let Some(&wb) = find(&list[..n], b"svc-awmi-b") else { return 1 };
    let grab = (wb.frame.0 + 40, wb.frame.1 + 14);
    let _ = awmi::test_pointer(admin, grab.0, grab.1, 1);
    let _ = awmi::test_pointer(admin, sw + 100, 120, 1);
    let _ = awmi::test_pointer(admin, sw + 100, 120, 0);
    let _ = awmi::test_pointer(admin, 0, 0, 0);
    let (list, n) = windows(admin);
    let Some(&wb2) = find(&list[..n], b"svc-awmi-b") else { return 1 };
    check!(wb2.frame.0 >= sw && wb2.frame.0 < sw + 640, "window B not on the second output: {:?}", wb2.frame);
    let Some(pb2) = free_point(&wb2, &list[..n]) else { return 1 };
    check!(pixel_is(admin, pb2.0, pb2.1, GREEN, 5 * SEC), "window B not drawn on the second output at {:?}", pb2);
    check!(!pixel_is(admin, pb.0, pb.1, GREEN, 0), "window B still drawn at its old place on the first output");
    check!(awmi::test_pixel(admin, sw + 640, 10) == Err(sys::ERR_OUT_OF_RANGE), "readback outside every output not refused");
    println!("svc-awmi-full: multi-monitor OK (window B dragged to output 2 at x={})", wb2.frame.0);

    // 9. Indicators: the indicator endpoint's alert, and the microphone from the audio service.
    check!(awmi::set_indicators(ind, awmi::IND_SECURITY_ALERT).is_ok(), "indicator refused");
    check!(awmi::status(query).is_ok_and(|s| s.indicators & awmi::IND_SECURITY_ALERT != 0), "the alert indicator did not light");
    check!(awmi::set_indicators(ind, awmi::IND_MIC_LIVE).is_ok(), "indicator refused");
    check!(awmi::status(query).is_ok_and(|s| s.indicators == 0), "the indicator endpoint could light MIC LIVE");
    match libd::audio::CaptureStream::open(libd::audio::capture_endpoint(), 48_000, 2, libd::audio::FMT_S16_LE, 0, b"svc-awmi-full") {
        Ok(mic) => {
            let dl = sys::clock_ns() + 5 * SEC;
            while !awmi::status(query).is_ok_and(|s| s.indicators & awmi::IND_MIC_LIVE != 0) {
                check!(sys::clock_ns() < dl, "MIC LIVE did not light during capture");
                libd::handle::sleep(100_000_000);
            }
            mic.close();
            let dl = sys::clock_ns() + 5 * SEC;
            while awmi::status(query).is_ok_and(|s| s.indicators & awmi::IND_MIC_LIVE != 0) {
                check!(sys::clock_ns() < dl, "MIC LIVE stayed on after capture");
                libd::handle::sleep(100_000_000);
            }
            println!("svc-awmi-full: indicators OK (alert; MIC LIVE from the audio service only)");
        }
        Err(e) => println!("svc-awmi-full: indicators OK (alert; no capture device for MIC LIVE: {})", sys::status(e)),
    }

    // 10. Close requests (Super+Q on the focused window): both clients exit, their windows go.
    for (who, p) in [(&b"svc-awmi-a"[..], pa), (&b"svc-awmi-b"[..], pb2)] {
        click(admin, p.0, p.1);
        let (list, n) = windows(admin);
        check!(find(&list[..n], who).is_some_and(|w| w.focused), "could not focus {:?}", core::str::from_utf8(who));
        let _ = awmi::test_key(admin, key::SUPER | u32::from(b'q'), true);
    }
    let deadline = sys::clock_ns() + 15 * SEC;
    while windows(admin).1 != 0 {
        check!(sys::clock_ns() < deadline, "the clients' windows did not close");
        libd::handle::sleep(100_000_000);
    }
    println!("svc-awmi-full: close requests OK");

    // 11. The exclusive input grab: what the host types now reaches the compositor, not the shell.
    let base = awmi::status(admin).map(|s| (s.input_keys, s.input_pointer)).unwrap_or((0, 0));
    println!("svc-awmi-full: input grab active, type now");
    let deadline = sys::clock_ns() + 45 * SEC;
    loop {
        let st = awmi::status(admin).unwrap_or_default();
        if st.input_keys >= base.0 + 5 && st.input_pointer > base.1 {
            println!("svc-awmi-full: input grab OK ({} keys, {} pointer events to the compositor)", st.input_keys - base.0, st.input_pointer - base.1);
            break;
        }
        check!(sys::clock_ns() < deadline, "real input did not reach the compositor ({} keys, {} pointer)", st.input_keys, st.input_pointer);
        libd::handle::sleep(100_000_000);
    }

    // 12. The end: display and input back to the terminal.
    check!(awmi::session_stop(admin).is_ok(), "session stop failed");
    check!(awmi::status(query).is_ok_and(|s| !s.active && s.windows == 0), "the session did not end");
    check!(awmi::create(win, 64, 64, awmi::FLAGS_DEFAULT, b"late").map(|_| ()) == Err(sys::ERR_BAD_STATE), "a window was created after the session");
    println!("svc-awmi-full: session ended, display and input returned");
    println!("svc-awmi-full: PASSED");
    0
}
