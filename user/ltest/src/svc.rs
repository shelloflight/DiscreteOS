//! Services the service manager's test run starts (manifests in user/init/services/test):
//! - `svc-grants`: the process holds exactly what its manifest grants (the log, its control
//!   channel, `/system` read-only, PCI class 01 devices) and nothing else;
//! - `svc-quota`: the manifest's quota is the process's quota, and the kernel enforces it;
//! - `svc-crash`: fails on purpose (restart with backoff, then given up).

use libd::fs::{self, Namespace, Node};
use libd::proto;
use libd::sys;
use libd::println;

macro_rules! check {
    ($c:expr, $($t:tt)*) => {
        if !$c {
            println!("ltest: svc FAIL: {} (line {})", format_args!($($t)*), line!());
            return 1;
        }
    };
}

pub fn grants() -> i32 {
    let mut devices = 0;
    let mut other = 0;
    for (h, tag) in libd::startup_handles() {
        match tag {
            sys::TAG_PROC_SELF | sys::TAG_THREAD_SELF | sys::TAG_VMAR_ROOT | sys::TAG_LOG | proto::TAG_CONTROL | fs::TAG_NS_NAMES => {}
            t if t == fs::TAG_NS => {}
            sys::TAG_DEVICE => {
                let info = sys::device_info(h);
                check!(info.is_ok_and(|i| i.kind == sys::DEV_KIND_PCI && i.class == 1), "a device outside PCI class 01: {:?}", info.map(|i| (i.class, i.subclass)));
                devices += 1;
            }
            t => {
                println!("ltest: svc FAIL: a handle the manifest does not grant (tag {:#x})", t);
                other += 1;
            }
        }
    }
    check!(other == 0, "{} handle(s) not granted", other);
    check!(devices > 0, "no device of PCI class 01");
    let ns = Namespace::get();
    check!(ns.entries().count() == 1, "the namespace has {} entries, not 1", ns.entries().count());
    let Some(dir) = ns.dir(b"/system") else {
        println!("ltest: svc FAIL: /system not granted");
        return 1;
    };
    let root = Node::from(dir);
    let st = root.stat();
    check!(st.is_ok_and(|s| s.rights == fs::R_READ), "/system rights {:?}, not read-only", st.map(|s| s.rights));
    let mut entries = 0;
    check!(root.list(|_, _| entries += 1).is_ok(), "cannot list /system");
    let w = root.open(b"svc-grants-was-here", fs::O_CREATE, fs::R_READ | fs::R_WRITE);
    check!(w.is_err(), "created a file on a read-only grant");
    let _ = root.into_handle(); // the startup handle stays owned by the startup block
    println!(
        "ltest: svc-grants: exactly the granted handles: log, control channel, {} PCI class 01 device(s), /system read-only ({} entries; create refused: {})",
        devices,
        entries,
        fs::status(w.err().unwrap_or(0))
    );
    0
}

pub fn quota() -> i32 {
    let q = sys::process_quota(libd::startup_handle(sys::TAG_PROC_SELF));
    check!(q.is_ok(), "no quota");
    let q = q.unwrap_or_default();
    check!(q.limits.memory == 4 << 20 && q.limits.handles == 32 && q.limits.threads == 2, "limits {} / {} / {}", q.limits.memory, q.limits.handles, q.limits.threads);
    let big = sys::vmo_create(8 << 20);
    check!(big.is_err(), "an 8 MiB VMO was granted under a 4 MiB quota");
    let small = sys::vmo_create(1 << 20);
    check!(small.is_ok(), "a 1 MiB VMO was refused: {:?}", small.err().map(sys::status));
    sys::handle_close(small.unwrap_or(0));
    println!(
        "ltest: svc-quota: limits from the manifest (4 MiB, 32 handles, 2 threads); 8 MiB refused ({}), 1 MiB granted",
        sys::status(big.err().unwrap_or(0))
    );
    0
}

pub fn crash() -> i32 {
    println!("ltest: svc-crash: failing on purpose");
    3
}
