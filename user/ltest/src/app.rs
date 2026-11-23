//! Application bundles (`.dapp`), signature verification, compositor permission prompt,
//! live permission revocation, and core native GUI apps test (`apps-virtio`).

use dosapp::Permission;
use libd::appmgr::{self, AppInfo, DECISION_DENIED, DECISION_GRANTED, MAX_APPS};
use libd::awmi::{self, WindowInfo};
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

fn wait_window(admin: sys::Handle, identity: &[u8], timeout: u64) -> Option<WindowInfo> {
    let dl = sys::clock_ns() + timeout;
    loop {
        let mut list = [WindowInfo::default(); 16];
        let n = awmi::test_windows(admin, &mut list).unwrap_or(0);
        if let Some(&w) = list[..n].iter().find(|w| w.identity() == identity) {
            return Some(w);
        }
        if sys::clock_ns() >= dl {
            return None;
        }
        libd::handle::sleep(100_000_000);
    }
}

pub fn ungranted() -> i32 {
    check!(
        appmgr::query_endpoint() == 0 && appmgr::admin_endpoint() == 0 && awmi::launcher_endpoint() == 0,
        "ungranted service received appmgr or awmi.launcher endpoint"
    );
    println!("svc-app-ungranted: PASSED (no appmgr or awmi.launcher endpoints)");
    0
}

pub fn full() -> i32 {
    let app_q = appmgr::query_endpoint();
    let app_admin = appmgr::admin_endpoint();
    let awmi_admin = awmi::admin_endpoint();
    let awmi_q = awmi::query_endpoint();
    check!(app_q != 0 && app_admin != 0 && awmi_admin != 0 && awmi_q != 0, "missing app test endpoints");

    // 1. Capability separation: query cannot launch, stop, revoke, or verify.
    check!(appmgr::launch(app_q, "files") == Err(sys::ERR_ACCESS_DENIED), "launch over query not refused");
    check!(appmgr::stop(app_q, "files") == Err(sys::ERR_ACCESS_DENIED), "stop over query not refused");
    check!(appmgr::set_perm(app_q, "files", Permission::FilesRead as u8, DECISION_DENIED) == Err(sys::ERR_ACCESS_DENIED), "set_perm over query not refused");
    check!(appmgr::install_check(app_q, "/sys/apps/files.dapp") == Err(sys::ERR_ACCESS_DENIED), "install_check over query not refused");

    // 2. All 5 core native `.dapp` bundles verified from `sys:/apps/`.
    let mut apps = [AppInfo::default(); MAX_APPS];
    let n = appmgr::list(app_q, &mut apps).unwrap_or(0);
    for req in ["terminal", "files", "editor", "settings", "sysmon"] {
        check!(
            apps[..n].iter().any(|a| a.name_str() == req && a.verified),
            "core app '{}' missing or unverified (got {} apps)",
            req,
            n
        );
    }
    println!("svc-app-full: 5 core .dapp bundles verified (terminal, files, editor, settings, sysmon)");

    // 3. Valid, tampered, and unsigned `.dapp` verification checks.
    check!(appmgr::install_check(app_admin, "/sys/apps/files.dapp").is_ok(), "valid files.dapp rejected");
    check!(appmgr::install_check(app_admin, "/esp/DOS/APPS/BAD.DAPP") == Err(sys::ERR_BAD_SIGNATURE), "tampered .dapp was not refused");
    check!(appmgr::install_check(app_admin, "/esp/DOS/APPS/UNSIGNED.DAPP") == Err(sys::ERR_BAD_SIGNATURE), "unsigned .dapp was not refused");
    println!("svc-app-full: .dapp signature enforcement OK (valid accepted, tampered & unsigned refused)");

    // 4. Start compositor session and launch core native apps (`files`, `settings`, `sysmon`).
    check!(awmi::session_start(awmi_admin, false).is_ok(), "session start failed");
    for name in ["files", "settings", "sysmon"] {
        check!(appmgr::launch(app_admin, name) == Ok(1), "launch {} failed", name);
        let Some(w) = wait_window(awmi_admin, name.as_bytes(), 20 * SEC) else {
            println!("ltest: svc FAIL: {} window did not appear", name);
            return 1;
        };
        check!(w.trust == awmi::TRUST_NATIVE, "{} wrong trust tier {}", name, w.trust);
    }
    println!("svc-app-full: core native apps open with verified identities (files, settings, sysmon)");

    // 5. Compositor-drawn unforgeable permission prompt (`editor` has `prompt = ["files:write"]`).
    check!(appmgr::launch(app_admin, "editor") == Ok(2), "editor did not trigger compositor permission prompt");
    check!(appmgr::running_count(app_q, "editor") == Ok(0), "editor launched before permission prompt was answered");
    // Answer Allow (default selected button 0) with Enter via compositor test input.
    let _ = awmi::test_key(awmi_admin, 0x0A, true);
    let _ = awmi::test_key(awmi_admin, 0x0A, false);
    let Some(ew) = wait_window(awmi_admin, b"editor", 20 * SEC) else {
        println!("ltest: svc FAIL: editor did not launch after approving permission prompt");
        return 1;
    };
    check!(ew.trust == awmi::TRUST_NATIVE, "editor wrong trust tier {}", ew.trust);
    let (eff, _) = appmgr::perms(app_q, "editor").unwrap_or((0, 0));
    check!((eff & Permission::FilesWrite.bit()) != 0, "editor missing files:write after Allow");
    println!("svc-app-full: compositor permission prompt OK (editor approved & launched)");

    // 6. Live permission revocation: revoking `files:read` from running `files` immediately stops it.
    check!(appmgr::running_count(app_q, "files").unwrap_or(0) >= 1, "files not running before revocation");
    check!(
        appmgr::set_perm(app_admin, "files", Permission::FilesRead as u8, DECISION_DENIED).is_ok(),
        "revoke files:read failed"
    );
    let dl = sys::clock_ns() + 10 * SEC;
    while appmgr::running_count(app_q, "files").unwrap_or(1) != 0 {
        check!(sys::clock_ns() < dl, "running files instance was not terminated on live permission revocation");
        libd::handle::sleep(50_000_000);
    }
    let (eff, denied) = appmgr::perms(app_q, "files").unwrap_or((u32::MAX, 0));
    check!(
        (eff & Permission::FilesRead.bit()) == 0 && (denied & Permission::FilesRead.bit()) != 0,
        "revoked files:read still active: eff={:#x} denied={:#x}",
        eff,
        denied
    );
    // Re-grant restores permission cleanly.
    check!(
        appmgr::set_perm(app_admin, "files", Permission::FilesRead as u8, DECISION_GRANTED).is_ok(),
        "re-grant files:read failed"
    );
    let (eff2, _) = appmgr::perms(app_q, "files").unwrap_or((0, 0));
    check!((eff2 & Permission::FilesRead.bit()) != 0, "re-granted files:read missing");
    println!("svc-app-full: live permission revocation & re-grant OK");

    // 7. Stop remaining apps and end session cleanly.
    for name in ["editor", "settings", "sysmon"] {
        let _ = appmgr::stop(app_admin, name);
    }
    check!(awmi::session_stop(awmi_admin).is_ok(), "session stop failed");
    println!("svc-app-full: PASSED");
    0
}
