//! init: the first user process and the service manager (src/mgr.rs, docs/services.md).
//!
//! Started by the kernel with exactly: its process, thread and root VMAR; the log; one read-only
//! VMO per embedded program (PROGRAM) and per embedded service manifest (MANIFEST); one handle per
//! device; the VMEX, POWER and MEASURE resources. Nothing else exists for it.
//!
//! Arguments:
//!   (none)              the system: the embedded manifests of group `system` (storaged,
//!                       devmgr), then signed ones from the boot volume (`esp:/DOS/SERVICES`);
//!                       supervised for ever. Disks are read-only (docs/hardware.md)
//!   time test           writable storage and svc-time (the wall-clock time across a reboot),
//!                       then a clean shutdown and power-off
//!   services test       the service manager's test run: system and test services, signed and
//!                       refused disk manifests, exact grants, quotas, restart with backoff and
//!                       giving up, storaged and devmgr killed and restarted with I/O working
//!                       again, then a clean shutdown in reverse order and power-off
//!   devmgr [args]       the device manager alone with [args] (no storage), exit with its code
//!   run <prog> [args]   spawn <prog>.dx with [args], the log, the VMEX resource and copies of the
//!                       program VMOs (the test programs and loaders); exit with its exit code
//!   storage test        storaged (test hooks) and devmgr with writable disks, then fstest with
//!                       every volume in its namespace (/<volume>)
//!   storage readonly    the default setup with storaged checking that every driver refuses a
//!                       raw write; then `fstest readonly`
//!   power off|reboot    switch the machine off or reset it with the POWER resource
//!   bench               the hardware benchmark image (docs/benchmarks.md): storage read-only,
//!                       then `utest bench` and `fstest bench`; 0 only if both passed

#![no_std]

extern crate alloc;

mod mgr;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dman::Group;
use doscrypt::sha2::sha256;
use libd::fs::{self as fp, NsBuilder};
use libd::sys::{self, Handle, SpawnHandle};
use libd::{Startup, println};
use mgr::{Mgr, State};

libd::entry!(_start, main);

const SEC: u64 = 1_000_000_000;

fn startup(tag: u32) -> Handle {
    libd::startup_handle(tag)
}

fn exit_text(code: i64) -> &'static str {
    match code as i32 {
        sys::EXIT_KILLED => " (KILLED)",
        sys::EXIT_FAULT => " (FAULT)",
        _ => "",
    }
}

fn wait_exit(p: Handle, what: &str) -> i32 {
    let _ = sys::object_wait(p, sys::TERMINATED, sys::WAIT_FOREVER);
    let code = sys::process_exit_code(p);
    println!("init: {} exited with code {}{}", what, code, exit_text(code));
    sys::handle_close(p);
    code as i32
}

/// `run`: the log, VMEX and copies of every program VMO (test programs spawn copies of
/// themselves; loaders need VMEX), plus every volume (moved) when `vols` is given.
fn run(cmd: &str, vols: Option<&mut Vec<mgr::Volume>>) -> i32 {
    let (prog, args) = cmd.split_once(' ').unwrap_or((cmd, ""));
    let file = format!("{}.dx", prog);
    let Some(image) = libd::find_program(file.as_bytes()) else {
        println!("init: no program '{}'", prog);
        return 1;
    };
    let mut hs: Vec<SpawnHandle> = Vec::new();
    let mut give = |h: Result<Handle, i64>, tag: u32| {
        if let Ok(h) = h {
            hs.push(SpawnHandle { handle: h, rights: sys::RIGHTS_SAME, tag, reserved: 0 });
        }
    };
    give(sys::handle_duplicate(startup(sys::TAG_LOG), sys::RIGHTS_SAME), sys::TAG_LOG);
    give(sys::handle_duplicate(startup(sys::TAG_VMEX), sys::RIGHTS_SAME), sys::TAG_VMEX);
    for (h, t) in libd::startup_handles() {
        if t == sys::TAG_PROGRAM {
            give(sys::handle_duplicate(h, sys::RIGHTS_SAME), sys::TAG_PROGRAM);
        }
    }
    if let Some(vols) = vols {
        let mut ns = NsBuilder::new();
        for v in vols.drain(..) {
            let path = format!("/{}", v.name);
            ns.add(path.as_bytes(), v.root);
        }
        let mut out = [SpawnHandle::default(); fp::MAX_NS + 1];
        if let Ok(n) = ns.finish(&mut out) {
            hs.extend_from_slice(&out[..n]);
        }
    }
    let limits = sys::Limits { memory: 96 << 20, handles: 2048, threads: 48 };
    match sys::spawn(startup(sys::TAG_PROC_SELF), image, prog.as_bytes(), args.as_bytes(), &hs, &limits) {
        Ok(p) => wait_exit(p, cmd),
        Err(e) => {
            println!("init: spawn {} failed: {}", prog, sys::status(e));
            1
        }
    }
}

/// The system services, with argument overrides (test modes), until the volumes present at boot
/// are announced (or 30 s).
fn start_system(overrides: &[(&str, &str)], groups: &[Group]) -> Option<Mgr> {
    let mut m = match Mgr::new() {
        Ok(m) => m,
        Err(e) => {
            println!("init: {}", e);
            return None;
        }
    };
    m.load_embedded(groups);
    m.check_set();
    for (name, args) in overrides {
        if let Some(i) = m.find(name) {
            m.svcs[i].args = Some(String::from(*args));
        }
    }
    let providers = m.svcs.iter().any(|s| s.m.volumes);
    if providers && !m.run_until(30 * SEC, |m| m.volumes_done) {
        println!("init: storaged did not report its volumes in time");
    }
    Some(m)
}

fn power(action: u64) -> i32 {
    let pw = startup(sys::TAG_POWER);
    // A program without the resource is refused first.
    let denied = sys::system_power(startup(sys::TAG_VMEX), action);
    println!("init: power: the VMEX resource is refused ({}); asking with POWER", denied);
    if denied != sys::ERR_ACCESS_DENIED {
        return 1;
    }
    let r = sys::system_power(pw, action);
    println!("init: power: system_power returned {}", r);
    1
}

fn list_programs() {
    let mut progs = String::new();
    let mut mans = String::new();
    for (h, t) in libd::startup_handles() {
        match t {
            sys::TAG_PROGRAM => {
                progs.push(' ');
                progs.push_str(&mgr::object_name(h));
            }
            sys::TAG_MANIFEST => {
                mans.push(' ');
                mans.push_str(&mgr::object_name(h));
            }
            _ => {}
        }
    }
    println!("init: programs:{}", progs);
    println!("init: service manifests:{}", if mans.is_empty() { " none" } else { &mans });
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "init") } {
        return 1;
    }
    let v = sys::abi_version();
    let me = sys::object_info(startup(sys::TAG_PROC_SELF));
    if v < i64::from(sys::ABI_VERSION) || !me.is_ok_and(|i| i.obj_type == sys::OBJ_PROCESS) {
        println!("init: ABI mismatch (kernel ABI {}, init built for {})", v, sys::ABI_VERSION);
        return 1;
    }
    let n = libd::startup_handles().count();
    println!("init: running in ring 3, ABI v{}, process koid {}, {} startup handles", v, me.map_or(0, |i| i.koid), n);

    let args = String::from_utf8_lossy(libd::args()).into_owned();
    let a = args.trim_end_matches('\0');
    if let Some(cmd) = a.strip_prefix("run ") {
        return run(cmd, None);
    }
    if a == "devmgr" || a.starts_with("devmgr ") {
        // The device manager alone (driver tests): no storage service to connect to.
        let Ok(mut m) = Mgr::new() else { return 1 };
        m.standalone = true;
        m.load_embedded(&[Group::System]);
        m.svcs.retain(|s| s.m.name == "devmgr");
        for s in m.svcs.iter_mut() {
            s.m.after.clear(); // alone: nothing to wait for (and its storage connection is skipped)
        }
        m.check_set();
        let Some(i) = m.find("devmgr") else {
            println!("init: no devmgr manifest");
            return 1;
        };
        m.svcs[i].m.restart.policy = dman::Policy::Never;
        m.svcs[i].args = Some(String::from(a.strip_prefix("devmgr").unwrap_or("").trim_start()));
        m.run_until(u64::MAX, |m| matches!(m.svcs[0].state, State::Done(_) | State::Failed));
        return match m.svcs[0].state {
            State::Done(c) => c as i32,
            _ => 1,
        };
    }
    match a {
        "storage test" | "storage readonly" | "bench" => {
            let (sargs, dargs) = match a {
                "storage test" => ("test", "rw"),
                "storage readonly" => ("rocheck", ""),
                _ => ("", ""),
            };
            let Some(mut m) = start_system(&[("storaged", sargs), ("devmgr", dargs)], &[Group::System]) else { return 1 };
            return match a {
                "storage test" => run("fstest", Some(&mut m.volumes)),
                "storage readonly" => run("fstest readonly", Some(&mut m.volumes)),
                _ => {
                    let u = run("utest bench", None);
                    let f = run("fstest bench", Some(&mut m.volumes));
                    i32::from(u != 0 || f != 0)
                }
            };
        }
        "power off" => return power(sys::POWER_OFF),
        "power reboot" => return power(sys::POWER_REBOOT),
        "services test" => return services_test(),
        "time test" => return time_test(),
        _ => {}
    }

    list_programs();
    let Some(mut m) = start_system(&[], &[Group::System]) else { return 1 };
    if m.load_from_volume("esp", &[Group::System]) > 0 {
        m.check_set();
    }
    loop {
        m.pump(sys::WAIT_FOREVER);
    }
}

// ---- the service manager's test run ---------------------------------------------------------

macro_rules! check {
    ($c:expr, $($t:tt)*) => {
        if !$c {
            println!("init: test FAIL: {}", format_args!($($t)*));
            return 1;
        }
    };
}

/// The first 64 KiB of the kernel on the boot volume, hashed: proves the whole I/O path
/// (storaged, the block driver, devmgr's link between them).
fn read_check(m: &Mgr) -> Option<[u8; 32]> {
    let v = m.volumes.iter().find(|v| v.name == "esp")?;
    let (f, _, _) = v.root.open(b"DOS/KERNEL.BIN", 0, fp::R_READ).ok()?;
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let n = f.read(0, &mut buf).ok()?;
    (n == buf.len()).then(|| sha256(&buf))
}

/// Read again until it works (the storage path is coming back) or 15 s pass.
fn read_again(m: &mut Mgr) -> Option<[u8; 32]> {
    let deadline = sys::clock_ns() + 15 * SEC;
    loop {
        if m.volumes_done
            && let Some(h) = read_check(m)
        {
            return Some(h);
        }
        if sys::clock_ns() >= deadline {
            return None;
        }
        m.pump(100_000_000);
    }
}

fn state(m: &Mgr, name: &str) -> Option<State> {
    m.find(name).map(|i| m.svcs[i].state)
}

/// The `time` test: writable storage and the svc-time service, which records the time (first
/// boot: exit 10) or checks it against the record (second boot: exit 0). Then a clean shutdown and
/// power-off; the host boots the same disks again for the second part.
fn time_test() -> i32 {
    let groups = [Group::System, Group::Test];
    let Some(mut m) = start_system(&[("storaged", "test"), ("devmgr", "rw")], &groups) else { return 1 };
    let ok = m.run_until(60 * SEC, |m| matches!(state(m, "svc-time"), Some(State::Done(_) | State::Failed)));
    check!(ok, "svc-time did not finish");
    let code = match state(&m, "svc-time") {
        Some(State::Done(c)) => c,
        _ => -1,
    };
    println!("init: time test: {}", match code {
        10 => "first boot done (time recorded)",
        0 => "second boot PASSED",
        _ => "FAILED",
    });
    m.shutdown();
    let r = sys::system_power(startup(sys::TAG_POWER), sys::POWER_OFF);
    println!("init: power: system_power returned {}", r);
    1
}

fn services_test() -> i32 {
    let groups = [Group::System, Group::Test];
    let Some(mut m) = start_system(&[], &groups) else { return 1 };
    check!(m.volumes_done, "no volumes");
    // Two embedded manifests are bad on purpose: an unknown key, an endpoint nobody provides.
    check!(m.refused == 2, "{} embedded manifest(s) refused, expected 2", m.refused);
    check!(m.find("svc-badkey").is_none() && m.find("svc-badcap").is_none(), "a bad manifest was accepted");
    println!("init: test: manifests: unknown key and ungranted endpoint refused");

    // Manifests from the boot volume: one signed, one unsigned, one tampered.
    let before = m.refused;
    let got = m.load_from_volume("esp", &groups);
    m.check_set();
    check!(got == 1 && m.find("hello").is_some(), "the signed manifest from disk was not accepted ({})", got);
    check!(m.refused == before + 2, "{} disk manifest(s) refused, expected 2 (unsigned, tampered)", m.refused - before);
    println!("init: test: disk manifests: signed one accepted, unsigned and tampered ones refused");

    // The test services run to their end: grants and quota checked inside, the crash given up.
    let ok = m.run_until(60 * SEC, |m| {
        matches!(state(m, "svc-grants"), Some(State::Done(_)))
            && matches!(state(m, "svc-quota"), Some(State::Done(_)))
            && matches!(state(m, "hello"), Some(State::Done(_)))
            && matches!(state(m, "svc-log"), Some(State::Done(_)))
            && state(m, "svc-crash") == Some(State::GaveUp)
    });
    check!(ok, "the test services did not finish");
    for s in ["svc-grants", "svc-quota", "svc-log"] {
        check!(state(&m, s) == Some(State::Done(0)), "{} ended with {:?}", s, state(&m, s));
    }
    // hello.dx says it ran by exiting with 42.
    check!(state(&m, "hello") == Some(State::Done(42)), "hello ended with {:?}", state(&m, "hello"));
    let c = m.find("svc-crash").map_or(0, |i| m.svcs[i].starts);
    check!(c == 3, "svc-crash started {} times, expected 3 (1 + 2 restarts)", c);
    println!("init: test: grants, quota, restart with backoff and giving up: as the manifests say; the log read back");

    // Crash + restart of the storage service: devmgr is linked to the new one, I/O works.
    let first = read_check(&m);
    check!(first.is_some(), "cannot read the boot volume");
    check!(m.kill("storaged"), "cannot kill storaged");
    let ok = m.run_until(15 * SEC, |m| state(m, "storaged") == Some(State::Running) && m.svcs[m.find("storaged").unwrap_or(0)].starts == 2);
    check!(ok, "storaged was not restarted");
    let again = read_again(&mut m);
    check!(again == first, "after the storaged restart the boot volume reads {:?}", again.map(|h| h[0]));
    println!("init: test: storaged killed and restarted, devmgr linked again, I/O works again");

    // Crash + restart of the device manager: storaged gets the disks again, I/O works.
    check!(m.kill("devmgr"), "cannot kill devmgr");
    let ok = m.run_until(15 * SEC, |m| state(m, "devmgr") == Some(State::Running) && m.svcs[m.find("devmgr").unwrap_or(0)].starts == 2);
    check!(ok, "devmgr was not restarted");
    let again = read_again(&mut m);
    check!(again == first, "after the devmgr restart the boot volume reads {:?}", again.map(|h| h[0]));
    println!("init: test: devmgr killed and restarted, disks handed to storaged again, I/O works again");

    // Clean shutdown, then power-off.
    m.shutdown();
    check!(m.svcs.iter().all(|s| !matches!(s.state, State::Running)), "a service is still running");
    println!("init: test: PASSED");
    let r = sys::system_power(startup(sys::TAG_POWER), sys::POWER_OFF);
    println!("init: power: system_power returned {}", r);
    1
}
