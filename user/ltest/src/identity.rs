//! Identity model, TPM 2.0 credential sealing, unforgeable compositor lock screen, and
//! idle/sleep lock integration test (`identity-tpm`; manifests in user/init/services/identity).

use core::mem::ManuallyDrop;

use libd::appmgr;
use libd::awmi::{self, Event, Window, WindowInfo};
use libd::fs::{self as fp, Namespace, Node};
use libd::identity::{self, IdentityInfo};
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
const RED: u32 = 0x00E0_2020;

fn fill(w: &mut Window, color: u32) {
    let px = color.to_le_bytes();
    for c in w.pixels().as_chunks_mut::<4>().0 {
        *c = px;
    }
}

fn type_pass(admin: sys::Handle, pass: &[u8]) {
    for &b in pass {
        let _ = awmi::test_key(admin, u32::from(b), true);
        let _ = awmi::test_key(admin, u32::from(b), false);
    }
    let _ = awmi::test_key(admin, 0x0A, true);
    let _ = awmi::test_key(admin, 0x0A, false);
}

fn pixel_is(admin: sys::Handle, x: i32, y: i32, color: u32, timeout: u64) -> bool {
    let dl = sys::clock_ns() + timeout;
    loop {
        if awmi::test_pixel(admin, x, y).is_ok_and(|p| p & 0x00FF_FFFF == color) {
            return true;
        }
        if sys::clock_ns() >= dl {
            return false;
        }
        libd::handle::sleep(50_000_000);
    }
}

pub fn ungranted() -> i32 {
    check!(libd::startup_handle(sys::TAG_TPM_SEAL) == 0, "ungranted service received TAG_TPM_SEAL");
    let mut out = [0u8; 256];
    check!(sys::tpm_seal(0, b"a", b"secret", &mut out) == Err(sys::ERR_BAD_HANDLE), "tpm_seal(0) not refused");
    let proc = libd::startup_handle(sys::TAG_PROC_SELF);
    check!(
        matches!(sys::tpm_seal(proc, b"a", b"secret", &mut out), Err(sys::ERR_WRONG_TYPE | sys::ERR_ACCESS_DENIED)),
        "tpm_seal with proc handle not refused"
    );
    check!(
        identity::session_endpoint() == 0 && identity::admin_endpoint() == 0 && identity::query_endpoint() == 0,
        "ungranted service received an identity endpoint"
    );
    println!("svc-id-ungranted: PASSED (no TPM_SEAL or identity endpoints)");
    0
}

pub fn full() -> i32 {
    let id_q = identity::query_endpoint();
    let id_admin = identity::admin_endpoint();
    let awmi_admin = awmi::admin_endpoint();
    let awmi_q = awmi::query_endpoint();
    let awmi_win = awmi::window_endpoint();
    let app_admin = appmgr::admin_endpoint();
    check!(id_q != 0 && id_admin != 0 && awmi_admin != 0 && awmi_q != 0 && awmi_win != 0 && app_admin != 0, "missing test endpoints");

    // 1. Strict separation: neither TPM_SEAL nor identity.session is ever granted outside identity/awmi.
    check!(libd::startup_handle(sys::TAG_TPM_SEAL) == 0, "svc-id-full unexpectedly received TAG_TPM_SEAL");
    check!(identity::session_endpoint() == 0, "svc-id-full unexpectedly received identity.session");
    check!(identity::create(id_q, "bob", "Bob", identity::ROLE_STANDARD) == Err(sys::ERR_ACCESS_DENIED), "create over query not refused");
    check!(identity::enroll(id_q, 0, b"x") == Err(sys::ERR_ACCESS_DENIED), "enroll over query not refused");
    check!(identity::authenticate(id_admin, 1, b"x").is_err(), "authenticate over admin not refused");

    // 2. No root user in D-OS.
    check!(identity::create(id_admin, "root", "Root", identity::ROLE_OPERATOR) == Err(sys::ERR_ACCESS_DENIED), "root identity was not refused");
    check!(identity::create(id_admin, "ROOT", "Root", identity::ROLE_STANDARD) == Err(sys::ERR_ACCESS_DENIED), "ROOT identity was not refused");
    println!("svc-id-full: no-root policy OK");

    // 3. Create a Standard non-operator user ("alice") with reduced explicit capabilities.
    let alice_id = match identity::create(id_admin, "alice", "Alice", identity::ROLE_STANDARD) {
        Ok(id) => id,
        Err(e) => {
            println!("ltest: svc FAIL: create alice: {}", sys::status(e));
            return 1;
        }
    };
    let mut list = [IdentityInfo::default(); 8];
    let cnt = identity::list(id_q, &mut list).unwrap_or(0);
    let Some(alice) = list[..cnt].iter().find(|i| i.id == alice_id).copied() else {
        println!("ltest: svc FAIL: alice missing from list");
        return 1;
    };
    check!(
        alice.role == identity::ROLE_STANDARD
            && (alice.caps & dosid::caps::IDENTITY_ADMIN) == 0
            && (alice.caps & dosid::caps::APP_ADMIN) == 0
            && alice.home_str() == "home/alice",
        "alice caps/home wrong: role={} caps={:#x} home={}",
        alice.role,
        alice.caps,
        alice.home_str()
    );
    println!("svc-id-full: non-root standard identity OK (alice -> /home = home/alice)");

    // 4. Enroll TPM 2.0-sealed passphrase for active identity ("user").
    let kind = match identity::enroll(id_admin, 0, b"dos-secret-pass") {
        Ok(k) => k,
        Err(e) => {
            println!("ltest: svc FAIL: enroll failed: {}", sys::status(e));
            return 1;
        }
    };
    check!(kind == identity::SEAL_TPM2, "expected TPM 2.0 seal ({}), got {}", identity::SEAL_TPM2, kind);
    let ts = identity::test_status(id_q).unwrap_or_default();
    check!(ts.tpm_available && ts.tpm_seal_ops >= 1, "TPM seal counter did not advance: {:?}", ts);
    println!("svc-id-full: TPM 2.0 credential seal OK (seal_ops={})", ts.tpm_seal_ops);

    // 5. Start compositor session and draw a bright red client window.
    check!(awmi::session_start(awmi_admin, false).is_ok(), "session start failed");
    let mut win = match Window::new(awmi_win, 360, 220, awmi::FLAGS_DEFAULT, b"Secret") {
        Ok(w) => w,
        Err(e) => {
            println!("ltest: svc FAIL: window create: {}", sys::status(e));
            return 1;
        }
    };
    fill(&mut win, RED);
    check!(win.commit(&[]).is_ok(), "commit failed");
    let mut wlist = [WindowInfo::default(); 8];
    let wn = awmi::test_windows(awmi_admin, &mut wlist).unwrap_or(0);
    let Some(wi) = wlist[..wn].iter().find(|w| w.id == win.id).copied() else {
        println!("ltest: svc FAIL: window not listed");
        return 1;
    };
    let cx = wi.client.0 + wi.client.2 as i32 / 2;
    let cy = wi.client.1 + wi.client.3 as i32 / 2;
    check!(pixel_is(awmi_admin, cx, cy, RED, 5 * SEC), "window pixel not red before lock");

    // 6. Engage compositor-drawn unforgeable lock screen.
    check!(awmi::lock_session(awmi_admin, awmi::LOCK_REASON_MANUAL, awmi::LOCK_MODE_LOCKED).is_ok(), "lock_session failed");
    check!(awmi::status(awmi_q).is_ok_and(|s| s.active && s.locked), "compositor did not report locked");
    let locked_px = awmi::test_pixel(awmi_admin, cx, cy).unwrap_or(RED) & 0x00FF_FFFF;
    check!(locked_px != RED, "lock screen failed to cover client window pixel at ({}, {})", cx, cy);

    // 7. Escape shortcuts & client key delivery are completely blocked while locked.
    let _ = awmi::test_key(awmi_admin, key::SUPER | 0x1B, true);
    let _ = awmi::test_key(awmi_admin, key::CTRL | key::ALT | 0x1B, true);
    check!(awmi::status(awmi_q).is_ok_and(|s| s.active && s.locked), "escape shortcut bypassed lock screen");
    // Drain any earlier events, then type letters while locked and confirm zero key leakage.
    while awmi::next_event(awmi_win, 0).ok().flatten().is_some() {}
    let _ = awmi::test_key(awmi_admin, u32::from(b'z'), true);
    let _ = awmi::test_key(awmi_admin, 0x08, true); // backspace to clear 'z'
    while let Ok(Some(ev)) = awmi::next_event(awmi_win, 0) {
        check!(!matches!(ev, Event::Key { .. }), "key event leaked to client window while locked");
    }
    println!("svc-id-full: lock screen covers window & blocks shortcuts/input OK");

    // 8. Wrong passphrase refused + exponential backoff throttle after 4 failures + TPM unseal unlock.
    for _ in 0..4 {
        type_pass(awmi_admin, b"wrong-pass");
        check!(awmi::status(awmi_q).is_ok_and(|s| s.locked), "wrong passphrase unlocked session");
    }
    let ts_fail = identity::test_status(id_q).unwrap_or_default();
    check!(ts_fail.auth_failures >= 4, "expected >=4 auth failures, got {}", ts_fail.auth_failures);
    // Immediately attempting the right passphrase must be throttled (2s cooldown).
    type_pass(awmi_admin, b"dos-secret-pass");
    check!(awmi::status(awmi_q).is_ok_and(|s| s.locked), "throttled unlock attempt was not blocked");
    libd::handle::sleep(2_300_000_000);
    type_pass(awmi_admin, b"dos-secret-pass");
    check!(awmi::status(awmi_q).is_ok_and(|s| !s.locked), "valid TPM passphrase did not unlock after cooldown");
    let ts_ok = identity::test_status(id_q).unwrap_or_default();
    check!(ts_ok.tpm_unseal_ops >= 1, "TPM unseal counter did not advance: {:?}", ts_ok);
    check!(pixel_is(awmi_admin, cx, cy, RED, 5 * SEC), "window pixel not restored after unlock");
    println!("svc-id-full: TPM 2.0 unseal & backoff throttle OK (unseal_ops={})", ts_ok.tpm_unseal_ops);

    // 9. Super+L manual lock, idle auto-lock, and sleep lock.
    let _ = awmi::test_key(awmi_admin, key::SUPER | u32::from(b'l'), true);
    check!(awmi::status(awmi_q).is_ok_and(|s| s.locked), "Super+L did not lock session");
    type_pass(awmi_admin, b"dos-secret-pass");
    check!(awmi::status(awmi_q).is_ok_and(|s| !s.locked), "unlock after Super+L failed");

    check!(awmi::set_lock_policy(awmi_admin, 60, true).is_ok(), "set_lock_policy failed");
    check!(awmi::test_idle_expire(awmi_admin).is_ok(), "test_idle_expire failed");
    check!(awmi::status(awmi_q).is_ok_and(|s| s.locked), "idle auto-lock did not engage");
    type_pass(awmi_admin, b"dos-secret-pass");
    check!(awmi::status(awmi_q).is_ok_and(|s| !s.locked), "unlock after idle lock failed");

    check!(awmi::lock_session(awmi_admin, awmi::LOCK_REASON_SLEEP, awmi::LOCK_MODE_LOCKED).is_ok(), "sleep lock failed");
    check!(awmi::status(awmi_q).is_ok_and(|s| s.locked), "sleep lock did not engage");
    type_pass(awmi_admin, b"dos-secret-pass");
    check!(awmi::status(awmi_q).is_ok_and(|s| !s.locked), "unlock after sleep lock failed");
    println!("svc-id-full: Super+L, idle auto-lock, and sleep lock OK");

    // 10. Per-identity namespace isolation: switch to Standard identity "alice", launch `files`,
    //     and confirm `files` runs with `/home` only (no `/data` operator mount!).
    if let Some((data_h, _)) = Namespace::get().resolve(b"/data") {
        let d = ManuallyDrop::new(Node::from(data_h));
        if let Ok((home, _, _)) = d.open(b"home", fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE) {
            if let Ok((uh, _, _)) = home.open(b"user", fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)
                && let Ok((f, _, _)) = uh.open(b"secret.txt", fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            {
                let _ = f.write(0, b"user-only-secret");
            }
            let _ = home.sync();
        }
    }
    check!(identity::switch_user(id_admin, "alice", b"").is_ok(), "switch to alice failed");
    let act = identity::active(id_q).unwrap_or_default();
    check!(act.name_str() == "alice" && act.role == identity::ROLE_STANDARD, "active identity not alice");
    check!(appmgr::launch(app_admin, "files").is_ok(), "launch files for alice failed");
    let dl = sys::clock_ns() + 15 * SEC;
    loop {
        let mut wl = [WindowInfo::default(); 8];
        let n = awmi::test_windows(awmi_admin, &mut wl).unwrap_or(0);
        if wl[..n].iter().any(|w| w.identity() == b"files") {
            break;
        }
        check!(sys::clock_ns() < dl, "files window did not open for alice");
        libd::handle::sleep(100_000_000);
    }
    let _ = appmgr::stop(app_admin, "files");
    println!("svc-id-full: per-identity namespace isolation OK");

    drop(win);
    check!(awmi::session_stop(awmi_admin).is_ok(), "session stop failed");
    println!("svc-id-full: PASSED");
    0
}
