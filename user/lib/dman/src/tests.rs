//! Host tests: the schema, every kind of malformed manifest, and a mutation fuzzer over the real
//! manifests (nothing may panic; whatever is accepted must satisfy the schema's invariants).

use super::*;
use std::string::ToString;
use std::vec;

const STORAGED: &[u8] = include_bytes!("../../../init/services/storaged.dman");
const DEVMGR: &[u8] = include_bytes!("../../../init/services/devmgr.dman");
const SEEDS: &[&[u8]] = &[
    STORAGED,
    DEVMGR,
    include_bytes!("../../../init/services/log.dman"),
    include_bytes!("../../../init/services/clock.dman"),
    include_bytes!("../../../init/services/terminal.dman"),
    include_bytes!("../../../init/services/shell.dman"),
    include_bytes!("../../../init/services/test/svc-grants.dman"),
    include_bytes!("../../../init/services/test/svc-quota.dman"),
    include_bytes!("../../../init/services/test/svc-crash.dman"),
    include_bytes!("../../../init/services/test/svc-badcap.dman"),
    include_bytes!("../../../init/services/disk/hello.dman"),
];

fn refused(src: &str) -> String {
    match parse(src.as_bytes()) {
        Ok(m) => panic!("accepted: {:?}\n{}", m.name, src),
        Err(e) => e.to_string(),
    }
}

#[test]
fn the_system_manifests_parse() {
    let s = parse(STORAGED).unwrap();
    assert_eq!((s.name.as_str(), s.image.as_str(), s.group), ("storaged", "storaged.dx", Group::System));
    assert_eq!(s.endpoints, vec!["disks".to_string()]);
    assert!(s.volumes && s.log && !s.vmex && !s.power && s.devices.is_empty() && !s.kernel_log && !s.boot_time);
    assert_eq!(s.connect, vec![Connect { service: "clock".into(), endpoint: "time".into() }]);
    assert_eq!(s.log_level, LEVEL_INFO);
    assert_eq!(s.quota, Quota { memory: 96 << 20, handles: 2048, threads: 8 });
    assert_eq!(s.restart, Restart { policy: Policy::Always, limit: 5, backoff_ms: 100 });
    let d = parse(DEVMGR).unwrap();
    assert_eq!(d.after, vec!["storaged".to_string()]);
    assert_eq!(d.devices, vec![DeviceSel::AllPci, DeviceSel::Platform("ps2".into())]);
    assert!(d.devices[0].matches(true, 1, 6, 1, "") && !d.devices[0].matches(false, 0, 0, 0, "rtc") && !d.devices[1].matches(false, 0, 0, 0, "rtc"));
    assert_eq!(d.endpoints, vec!["input".to_string()]);
    assert_eq!(d.programs, vec!["*.ddrv".to_string()]);
    assert_eq!(d.connect, vec![Connect { service: "storaged".into(), endpoint: "disks".into() }]);
    assert_eq!(summary(&d), "log, 2 device selector(s), programs *.ddrv, storaged.disks");
    let l = parse(include_bytes!("../../../init/services/log.dman")).unwrap();
    assert!(l.kernel_log && !l.boot_time && l.endpoints == vec!["read".to_string()]);
    assert_eq!(summary(&l), "log, kernel log");
    let c = parse(include_bytes!("../../../init/services/clock.dman")).unwrap();
    assert!(c.boot_time && !c.kernel_log && c.devices == vec![DeviceSel::Platform("rtc".into())]);
    let x = parse(b"name = \"x\"\nimage = \"x.dx\"\ngroup = \"test\"\nlog-level = \"debug\"\n").unwrap();
    assert_eq!(x.log_level, LEVEL_DEBUG);
}

#[test]
fn grants_and_selectors() {
    let m = parse(
        br#"
name = "x"   # comment
image = "x.dx"
group = "test"
[grants]
devices = ["pci:01", "pci:0c03", "pci:0c0330", "platform:ps2"]
namespace = ["/system=system:r", "/data=data:rw", "/admin=data:rwa"]
programs = ["*.ddrv", "hello.dx"]
connect = [
    "storaged.disks",   # multi-line, trailing comma
]
[quota]
memory = 1_048_576
"#,
    )
    .unwrap();
    assert!(m.devices[0].matches(true, 1, 6, 1, ""));
    assert!(!m.devices[0].matches(true, 2, 0, 0, ""));
    assert!(m.devices[1].matches(true, 0x0C, 3, 0x30, "") && !m.devices[1].matches(true, 0x0C, 5, 0, ""));
    assert!(m.devices[2].matches(true, 0x0C, 3, 0x30, "") && !m.devices[2].matches(true, 0x0C, 3, 0x20, ""));
    assert!(m.devices[3].matches(false, 0, 0, 0, "ps2") && !m.devices[3].matches(true, 0, 0, 0, "ps2"));
    assert_eq!(m.namespace[1], NsGrant { path: "/data".into(), volume: "data".into(), rights: NS_READ | NS_WRITE });
    assert_eq!(m.namespace[2].rights, NS_READ | NS_WRITE | NS_ADMIN);
    assert!(program_matches("*.ddrv", "ahci.ddrv") && !program_matches("*.ddrv", "init.dx") && !program_matches("*.ddrv", ".ddrv"));
    assert!(program_matches("hello.dx", "hello.dx") && !program_matches("hello.dx", "hello.dxx"));
    assert_eq!(m.quota.memory, 1 << 20);
    assert_eq!(m.restart.delay_ms(1), 100);
    assert_eq!(m.restart.delay_ms(3), 400);
    assert_eq!(m.restart.delay_ms(30), 10_000);
}

#[test]
fn unknown_keys_and_tables_are_refused_by_name() {
    let base = "name = \"x\"\nimage = \"x.dx\"\ngroup = \"test\"\n";
    assert_eq!(refused(&(base.to_string() + "[grants]\nkernel-memory = true\n")), "line 5: unknown key 'grants.kernel-memory'");
    assert_eq!(refused(&(base.to_string() + "colour = \"red\"\n")), "line 4: unknown key 'colour'");
    assert_eq!(refused(&(base.to_string() + "[secrets]\n")), "line 4: unknown table [secrets]");
    assert_eq!(refused(&(base.to_string() + "[secrets]\nx = 1\n")), "line 4: unknown table [secrets]");
}

#[test]
fn every_kind_of_bad_manifest_is_refused() {
    let base = "name = \"x\"\nimage = \"x.dx\"\ngroup = \"test\"\n";
    let bad = [
        // syntax
        "name = \"x\nimage = \"x.dx\"\ngroup = \"test\"\n",
        "name = 'x'\n",
        "name = \"x\" junk\n",
        "name \"x\"\n",
        "a.b = 1\n",
        "[[grants]]\n",
        "[grants.sub]\n",
        "[grants]\n[grants]\n",
        "name = \"x\"\nname = \"y\"\n",
        "x = {a = 1}\n",
        "x = [[1]]\n",
        "x = 1.5\n",
        "x = -1\n",
        "x = 1_\n",
        "x = 99999999999999999999999\n",
        "x = \"\\q\"\n",
        "x = \"a\u{1}b\"\n",
        "x = [1, 2\n",
        "x = tru\n",
        "x = truex\n",
        "\r",
    ];
    for b in bad {
        assert!(toml::parse(b.as_bytes()).is_err(), "syntax accepted: {:?}", b);
    }
    // schema
    for extra in [
        "args = 1\n",
        "after = \"storaged\"\n",
        "after = [\"Storaged\"]\n",
        "after = [\"x\"]\n",
        "after = [\"a\", \"a\"]\n",
        "[grants]\nlog = \"yes\"\n",
        "[grants]\ndevices = [\"pci:1\"]\n",
        "[grants]\ndevices = [\"usb:01\"]\n",
        "[grants]\ndevices = [\"pci:zz\"]\n",
        "[grants]\nnamespace = [\"system=system:r\"]\n",
        "[grants]\nnamespace = [\"/system=system:x\"]\n",
        "[grants]\nnamespace = [\"/a/b=system:r\"]\n",
        "[grants]\nnamespace = [\"/s=system:r\", \"/s=data:r\"]\n",
        "[grants]\nconnect = [\"storaged\"]\n",
        "[grants]\nconnect = [\"x.disks\"]\n",
        "[grants]\nprograms = [\"*\"]\n",
        "[grants]\nprograms = [\"../init.dx\"]\n",
        "[grants]\nprograms = [\"*.exe\"]\n",
        "[quota]\nmemory = \"1T\"\n",
        "[quota]\nmemory = \"4K\"\n",
        "[quota]\nmemory = \"2G\"\n",
        "[quota]\nmemory = true\n",
        "[quota]\nhandles = 5000\n",
        "[quota]\nthreads = 0\n",
        "[restart]\npolicy = \"sometimes\"\n",
        "[restart]\nbackoff = 1\n",
        "[restart]\nlimit = 1000\n",
        "log-level = \"loud\"\n",
        "log-level = 3\n",
        "[grants]\nkernel-log = \"yes\"\n",
        "[grants]\ndevices = [\"pcie\"]\n",
    ] {
        let src = base.to_string() + extra;
        assert!(parse(src.as_bytes()).is_err(), "accepted: {:?}", extra);
    }
    for missing in ["image = \"x.dx\"\ngroup = \"test\"\n", "name = \"x\"\ngroup = \"test\"\n", "name = \"x\"\nimage = \"x.dx\"\n"] {
        assert!(parse(missing.as_bytes()).is_err());
    }
    for bad_value in ["name = \"X\"", "name = \"1x\"", "name = \"a-very-long-name-of-25-chr\"", "image = \"x.exe\"", "image = \"x\"", "group = \"boot\""] {
        let src = base.to_string() + bad_value + "\n";
        // A second `name` / `image` / `group` is a duplicate key, also refused; check the value alone too.
        assert!(parse(src.as_bytes()).is_err());
        let alone = bad_value.to_string() + "\n" + &base.lines().filter(|l| !l.starts_with(bad_value.split(' ').next().unwrap())).collect::<Vec<_>>().join("\n") + "\n";
        assert!(parse(alone.as_bytes()).is_err(), "accepted: {}", alone);
    }
    assert!(parse(&vec![b'#'; toml::MAX_SIZE + 1]).is_err());
}

/// xorshift64*: deterministic, so a failure is reproducible from the round number.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TOKENS: &[&[u8]] = &[
    b"[", b"]", b"[[", b"\"", b"=", b",", b"#", b"\n", b"\r\n", b"\\", b"true", b"false", b"0", b"_", b"99999999999999999999",
    b"[grants]", b"[quota]", b"[restart]", b"[provides]", b"devices = [\"all\"]", b"connect = [\"a.b\"]", b"memory = \"1G\"",
    b"namespace = [\"/a=b:rw\"]", b"\xff", b"\x00", b"{", b"'",
];

/// Whatever the parser accepts must satisfy the schema.
fn invariants(m: &Manifest) {
    assert!(valid_name(&m.name) && valid_program(&m.image));
    assert!(m.after.iter().all(|s| valid_name(s)) && m.endpoints.iter().all(|s| valid_name(s)));
    assert!(m.connect.iter().all(|c| valid_name(&c.service) && valid_name(&c.endpoint) && c.service != m.name));
    assert!(m.namespace.iter().all(|n| ((n.path.starts_with('/') && valid_name(&n.path[1..]) && valid_name(&n.volume)) || (n.path == "*" && n.volume == "*" && m.namespace.len() == 1)) && n.rights & NS_READ != 0));
    assert!((64 << 10..=1 << 30).contains(&m.quota.memory) && (16..=4096).contains(&m.quota.handles) && (1..=256).contains(&m.quota.threads));
    assert!(m.restart.limit <= 100 && (10..=60_000).contains(&m.restart.backoff_ms));
}

#[test]
fn fuzz_manifests() {
    const ROUNDS: usize = 100_000;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut accepted, mut refused) = (0usize, 0usize);
    for _ in 0..ROUNDS {
        let mut b = SEEDS[rng.below(SEEDS.len())].to_vec();
        for _ in 0..1 + rng.below(8) {
            let at = if b.is_empty() { 0 } else { rng.below(b.len() + 1) };
            match rng.below(6) {
                0 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    b[i] ^= 1 << rng.below(8);
                }
                1 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    let n = rng.below(16).min(b.len() - i);
                    b.drain(i..i + n);
                }
                2 => {
                    let t = TOKENS[rng.below(TOKENS.len())];
                    b.splice(at..at, t.iter().copied());
                }
                3 if !b.is_empty() => {
                    // duplicate a slice of itself somewhere else
                    let i = rng.below(b.len());
                    let n = rng.below(64).min(b.len() - i);
                    let s: Vec<u8> = b[i..i + n].to_vec();
                    b.splice(at..at, s);
                }
                4 => b.truncate(at),
                _ => b.insert(at, rng.next() as u8),
            }
        }
        match parse(&b) {
            Ok(m) => {
                invariants(&m);
                accepted += 1;
            }
            Err(e) => {
                assert!(!e.msg.is_empty());
                refused += 1;
            }
        }
    }
    // Every truncation of every seed: refused or valid, never a panic.
    for s in SEEDS {
        for n in 0..s.len() {
            if let Ok(m) = parse(&s[..n]) {
                invariants(&m);
            }
        }
    }
    std::println!("dman fuzz: {} mutated manifests ({} accepted, {} refused), every truncation of {} seeds", ROUNDS, accepted, refused, SEEDS.len());
    assert!(accepted > 0 && refused > 0);
}

// ---- tool manifests and the shell's grants ------------------------------------------------------

const TOOLS: &[&[u8]] = &[
    include_bytes!("../../../tools/manifests/list.dman"),
    include_bytes!("../../../tools/manifests/show.dman"),
    include_bytes!("../../../tools/manifests/copy.dman"),
    include_bytes!("../../../tools/manifests/move.dman"),
    include_bytes!("../../../tools/manifests/delete.dman"),
    include_bytes!("../../../tools/manifests/make.dman"),
];

#[test]
fn the_shell_manifest_grants_its_session() {
    let s = parse(include_bytes!("../../../init/services/shell.dman")).unwrap();
    assert!(s.tools && s.manage_services && s.manage_power && s.log);
    assert_eq!(s.namespace, vec![NsGrant { path: "*".into(), volume: "*".into(), rights: NS_READ | NS_WRITE }]);
    assert_eq!(summary(&s), "log, terminal.session, log.read, clock.time, every volume, manager (services, power), tools");
    let t = parse(include_bytes!("../../../init/services/terminal.dman")).unwrap();
    assert_eq!(t.devices, vec![DeviceSel::Platform("display".into())]);
    assert!(!t.tools && !t.manage_services && t.namespace.is_empty());
    let r = parse(b"name = \"x\"
image = \"x.dx\"
group = \"test\"
[grants]
namespace = [\"*:r\"]
manager = [\"services\"]
").unwrap();
    assert_eq!(r.namespace[0].rights, NS_READ);
    assert!(r.manage_services && !r.manage_power);
    assert!(refused("name = \"x\"
image = \"x.dx\"
group = \"test\"
[grants]
namespace = [\"*\", \"/a=b:r\"]
").contains("must be the only entry"));
    assert!(refused("name = \"x\"
image = \"x.dx\"
group = \"test\"
[grants]
manager = [\"kernel\"]
").contains("unknown manager right"));
    assert!(refused("name = \"x\"
image = \"x.dx\"
group = \"test\"
[grants]
namespace = [\"*:rwa\"]
").contains("not a namespace entry"));
    // A tool manifest is not a service manifest.
    assert!(parse(TOOLS[0]).is_err());
}

#[test]
fn the_tool_manifests_parse() {
    for t in TOOLS {
        assert!(tool::is_tool(t));
        let m = tool::parse(t).unwrap();
        assert!(m.image == format!("{}.dx", m.name) && !m.aliases.is_empty() && !m.description.is_empty());
        assert!(m.params.iter().all(|p| !p.about.is_empty()));
    }
    let c = tool::parse(TOOLS[2]).unwrap();
    assert_eq!(c.usage(), "copy <from> <to>");
    assert!(c.params[0].read && !c.params[0].write && c.params[1].write && c.params[1].create);
    assert_eq!(tool::parse(TOOLS[0]).unwrap().usage(), "list [place]");
    assert_eq!(tool::parse(TOOLS[4]).unwrap().usage(), "delete <path>...");
    assert!(!tool::is_tool(STORAGED));
}

fn tool_refused(src: &str) -> String {
    match tool::parse(src.as_bytes()) {
        Ok(t) => panic!("accepted: {:?}
{}", t.name, src),
        Err(e) => e.to_string(),
    }
}

#[test]
fn bad_tool_manifests_are_refused() {
    let head = "kind = \"tool\"
name = \"t\"
image = \"t.dx\"
";
    let with = |rest: &str| format!("{}{}", head, rest);
    assert!(tool_refused("name = \"t\"
image = \"t.dx\"
").contains("missing 'kind'"));
    assert!(tool_refused("kind = \"service\"
name = \"t\"
image = \"t.dx\"
").contains("'kind' must be"));
    assert!(tool_refused(&with("image2 = \"x\"
")).contains("unknown key 'image2'"));
    assert!(tool_refused(&with("[grants]
log = true
")).contains("unknown table [grants]"));
    assert!(tool_refused("kind = \"tool\"
name = \"t\"
image = \"t.ddrv\"
").contains("'image'"));
    assert!(tool_refused(&with("[parameters]
a = \"path\"
")).contains("needs read or write"));
    assert!(tool_refused(&with("[parameters]
a = \"path:read,create\"
")).contains("create needs write"));
    assert!(tool_refused(&with("[parameters]
a = \"text:read\"
")).contains("paths only"));
    assert!(tool_refused(&with("[parameters]
a = \"file:read\"
")).contains("unknown kind"));
    assert!(tool_refused(&with("[parameters]
a = \"path:read,fly\"
")).contains("unknown flag"));
    assert!(tool_refused(&with("[parameters]
a = \"path:read,read\"
")).contains("given twice"));
    assert!(tool_refused(&with("[parameters]
a = \"path:read,many\"
b = \"text\"
")).contains("only the last"));
    assert!(tool_refused(&with("[parameters]
a = \"text,optional\"
")).contains("unknown kind"));
    assert!(tool_refused(&with("[parameters]
a = \"text:optional\"
b = \"text\"
")).contains("cannot follow an optional"));
    assert!(tool_refused(&with("[about]
z = \"x\"
")).contains("no such parameter"));
    assert!(tool_refused(&with("aliases = [\"a\", \"a\"]
")).contains("listed twice"));
    let w = tool::parse(with("[parameters]
a = \"path:write\"
").as_bytes()).unwrap();
    assert!(w.params[0].read && w.params[0].write, "write includes read");
}

#[test]
fn fuzz_tool_manifests() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let mut accepted = 0usize;
    for _ in 0..50_000 {
        let mut b = TOOLS[rng.below(TOOLS.len())].to_vec();
        for _ in 0..1 + rng.below(6) {
            let at = rng.below(b.len() + 1);
            match rng.below(4) {
                0 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    b[i] ^= 1 << rng.below(8);
                }
                1 => {
                    let t = TOKENS[rng.below(TOKENS.len())];
                    b.splice(at..at, t.iter().copied());
                }
                2 => b.truncate(at),
                _ => b.insert(at, rng.next() as u8),
            }
        }
        if let Ok(t) = tool::parse(&b) {
            accepted += 1;
            assert!(valid_name(&t.name) && t.image.ends_with(".dx") && t.params.len() <= 8);
            assert!(t.params.iter().all(|p| p.kind != tool::ParamKind::Path || p.read));
            assert!(t.params.iter().all(|p| !p.create || p.write));
            assert!(t.params.iter().rev().skip(1).all(|p| !p.many && !p.optional));
        }
    }
    assert!(accepted > 0);
}
