//! Built-in commands: the ones that use the session's own grants (places, the log, the clock, the
//! service manager) or the shell's state (the current place, jobs). Each returns records.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use libd::fs::{self as fp};
use libd::proto::{HEADER, Header};
use libd::rec::{self, Record, Value};
use libd::sys::{self, Handle};
use libd::{svc, time};

use crate::{Shell, filter, normalize, rights_word, show};

pub struct Builtin {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub usage: &'static str,
    pub description: &'static str,
}

pub const BUILTINS: &[Builtin] = &[
    Builtin { name: "help", aliases: &["?"], usage: "help [command]", description: "the commands, or how to use one" },
    Builtin { name: "go", aliases: &["cd"], usage: "go [place]", description: "change the current place (no place: /home, or /)" },
    Builtin { name: "places", aliases: &[], usage: "places", description: "what this session may reach, and with which rights" },
    Builtin { name: "tasks", aliases: &["ps"], usage: "tasks", description: "the services and this session's jobs" },
    Builtin { name: "objects", aliases: &["objs"], usage: "objects [job | service]", description: "the handles held (by the shell if none named)" },
    Builtin { name: "end", aliases: &["kill"], usage: "end <job | service>", description: "end a job, or stop a service" },
    Builtin { name: "restart", aliases: &[], usage: "restart <service>", description: "restart a service" },
    Builtin { name: "jobs", aliases: &[], usage: "jobs", description: "the commands started with 'start'" },
    Builtin { name: "wait", aliases: &[], usage: "wait <job>", description: "wait for a job and show its output" },
    Builtin { name: "log", aliases: &[], usage: "log [source]", description: "the system log (every record, or one source's)" },
    Builtin { name: "time", aliases: &["date"], usage: "time", description: "the date and time (UTC) and the time since boot" },
    Builtin { name: "audio", aliases: &["sound"], usage: "audio [vol <0-100%> | mute [on|off] | unmute | out <id|auto> | tone [hz] [ms] | mic <on|off>]", description: "audio devices, volume, mute/unmute, output switching and test tone" },
    Builtin { name: "net", aliases: &["ip"], usage: "net [check | dhcp | dns <ip|auto> [dns2] | static <ip> <mask> <gw> [dns1] [dns2]]", description: "network status, diagnostics, DHCP renewal, DNS and static IPv4 configuration" },
    Builtin { name: "ping", aliases: &[], usage: "ping <host> [count]", description: "send ICMP echo requests to a host" },
    Builtin { name: "tls", aliases: &[], usage: "tls <host> [port]", description: "verify a TLS 1.3 connection using the system root CAs" },
    Builtin { name: "ssh", aliases: &[], usage: "ssh [user@]host [-p port] [-i key] [-y] [command...] | ssh probe <host> [port] | ssh keygen [path]", description: "connect to an SSH-2 server, run remote commands, probe host keys, or generate Ed25519 keys" },
    Builtin { name: "gpu", aliases: &["display"], usage: "gpu [modes [id] | display [id] | mode <w> <h> <hz> [id] | confirm [id] | revert [id] | vrr on|off [id] | hdr on|off [id] | scale <pct|auto> [id]]", description: "GPU adapters, Atomic KMS topology, refresh/mode, confirm/revert, VRR, HDR, and UI scale" },
    Builtin { name: "gui", aliases: &["awmi"], usage: "gui [demo | status | lock | theme dark|contrast | text 100-200 | motion on|off]", description: "start the desktop (D-AWMI), show its status, lock the screen, or change theme, text size and motion" },
    Builtin { name: "identity", aliases: &["id", "whoami"], usage: "identity [list | enroll <pass> | create <name> <display> [standard|operator] | switch <name> [pass] | policy [idle <sec>|sleep on|off|boot on|off]]", description: "user identities, TPM 2.0 credential sealing, and session lock policy" },
    Builtin { name: "apps", aliases: &["app"], usage: "apps [list | launch <name> | stop <name> | perms <name> | grant <name> <perm> | revoke <name> <perm> | verify <path>]", description: "signed .dapp bundles, launching, and live revocable permissions" },
    Builtin { name: "install", aliases: &[], usage: "install [disks | parts <disk> | plan <disk> [dual|whole|wipe [--confirm]] | delete-part <disk> <index> --confirm | run <disk> [dual|whole|wipe [--confirm]]]", description: "dual-boot safe disk installer, whole-disk install, and partition management" },
    Builtin { name: "setup", aliases: &["oobe"], usage: "setup [status | skip | complete [lang] [keyboard] [timezone] [skip|dhcp]]", description: "first-boot setup status, skip, or complete configuration on an installed disk" },
    Builtin { name: "power", aliases: &[], usage: "power off | restart | sleep", description: "switch off, restart, or sleep after every service stopped cleanly" },
    Builtin { name: "clear", aliases: &["cls"], usage: "clear", description: "clear the screen" },
];

fn find(name: &str) -> Option<&'static Builtin> {
    BUILTINS.iter().find(|b| b.name == name || b.aliases.contains(&name))
}

type Res = Result<Vec<Record>, String>;

fn text(s: &str) -> Value {
    Value::Text(String::from(s))
}

/// Run built-in `name`; None if there is no such built-in.
pub fn run(sh: &mut Shell, name: &str, args: &[String]) -> Option<Res> {
    let b = find(name)?;
    let max_args = match b.name {
        "help" | "go" | "objects" | "log" => 1,
        "end" | "restart" | "wait" | "power" => 1,
        "ping" | "tls" | "gui" => 2,
        "audio" | "apps" => 3,
        "gpu" | "identity" | "install" | "setup" => 5,
        "net" => 6,
        "ssh" => 32,
        _ => 0,
    };
    if args.len() > max_args {
        return Some(Err(format!("{}: too many arguments; usage: {}", b.name, b.usage)));
    }
    let arg = args.first().map(String::as_str);
    Some(match b.name {
        "help" => help(sh, arg),
        "go" => {
            let home_avail = sh.places.iter().any(|p| p.path == "/home");
            let target = match arg {
                None | Some("~") => if home_avail { "/home" } else { "/" },
                Some(p) => p,
            };
            go(sh, target)
        }
        "places" => places(sh),
        "tasks" => tasks(sh),
        "objects" => objects(sh, arg),
        "end" => end(sh, arg),
        "restart" => manager_name(sh, svc::MGR_RESTART, "restart", arg).map(|_| Vec::new()),
        "jobs" => Ok(jobs(sh)),
        "wait" => wait(sh, arg),
        "log" => log(sh, arg),
        "time" => clock(sh),
        "audio" => audio_cmd(sh, args),
        "net" => match arg {
            None => net_cmd(sh),
            Some("check") => net_check(sh),
            Some("dhcp") => net_dhcp(sh),
            Some("dns") => net_dns(sh, &args[1..]),
            Some("static") => net_static(sh, &args[1..]),
            Some(other) => Err(format!(
                "net: unknown argument '{}'; usage: net [check | dhcp | dns <ip|auto> [dns2] | static <ip> <mask> <gw> [dns1] [dns2]]",
                other
            )),
        },
        "ping" => ping_cmd(sh, args),
        "tls" => tls_cmd(sh, args),
        "ssh" => crate::ssh_cmd::ssh_cmd(sh, args),
        "gpu" => gpu_cmd(sh, args),
        "gui" => gui_cmd(sh, args),
        "identity" => identity_cmd(sh, args),
        "apps" => apps_cmd(sh, args),
        "install" => install_cmd(sh, args),
        "setup" => setup_cmd(sh, args),
        "power" => power(sh, arg),
        _ => {
            sh.clear();
            Ok(Vec::new())
        }
    })
}

fn help(sh: &Shell, what: Option<&str>) -> Res {
    let Some(w) = what else {
        let mut rs = Vec::new();
        for b in BUILTINS {
            rs.push(Record::new().with("command", text(b.name)).with("also", text(&b.aliases.join(" "))).with("what it does", text(b.description)));
        }
        for t in &sh.tools {
            rs.push(Record::new().with("command", text(&t.name)).with("also", text(&t.aliases.join(" "))).with("what it does", text(&t.description)));
        }
        rs.push(Record::new().with("command", text("run")).with("also", text("")).with("what it does", text("run a tool, or a Windows or Linux program under D-CMPL: run <tool or file> [arguments]")));
        rs.push(Record::new().with("command", text("start")).with("also", text("")).with("what it does", text("run a command as a job: start <command>")));
        for f in filter::NAMES {
            rs.push(Record::new().with("command", text(f)).with("also", text("")).with("what it does", text(&format!("filter: ... | {}", filter::usage(f)))));
        }
        rs.sort_by_key(|r| r.get("command").map(show::value).unwrap_or_default());
        return Ok(rs);
    };
    if let Some(t) = sh.find_tool(w) {
        let mut s = format!("{}  {}\n  usage: {}\n", t.name, show::coloured(libd::term::DARK_GREY, &t.description), t.usage());
        if !t.aliases.is_empty() {
            s.push_str(&format!("  also: {}\n", t.aliases.join(", ")));
        }
        for p in &t.params {
            let rights = match (p.kind, p.write, p.create) {
                (dman::tool::ParamKind::Path, false, _) => "a path; the tool may read it",
                (dman::tool::ParamKind::Path, true, false) => "a path; the tool may change it",
                (dman::tool::ParamKind::Path, true, true) => "a path; the tool may create it",
                (dman::tool::ParamKind::Text, _, _) => "text",
                (dman::tool::ParamKind::Number, _, _) => "a number",
            };
            s.push_str(&format!("  {:<8} {}{}\n", p.name, p.about, show::coloured(libd::term::DARK_GREY, &format!(" ({})", rights))));
        }
        s.push_str(&show::coloured(libd::term::DARK_GREY, "  The tool gets only these paths, with these rights.\n"));
        sh.write(&s);
        return Ok(Vec::new());
    }
    if let Some(b) = find(w) {
        let also = if b.aliases.is_empty() { String::new() } else { format!("\n  also: {}", b.aliases.join(", ")) };
        sh.write(&format!("{}  {}\n  usage: {}{}\n", b.name, show::coloured(libd::term::DARK_GREY, b.description), b.usage, also));
        return Ok(Vec::new());
    }
    if filter::is_filter(w) {
        sh.write(&format!("{}  filter\n  usage: ... | {}\n", w, filter::usage(w)));
        return Ok(Vec::new());
    }
    Err(format!("help: no command '{}'", w))
}

fn go(sh: &mut Shell, to: &str) -> Res {
    let abs = normalize(&sh.place, to);
    if abs != "/" {
        let (_, kind) = sh.open("go", &abs, 0, fp::R_READ)?;
        if kind != fp::KIND_DIR {
            return Err(format!("go: {}: {}", abs, fp::message(fp::ERR_NOT_DIR)));
        }
    }
    sh.place = abs;
    Ok(Vec::new())
}

fn places(sh: &Shell) -> Res {
    let mut rs = Vec::new();
    for p in &sh.places {
        let n = crate::borrow(p.h);
        let v = n.volinfo().ok();
        rs.push(
            Record::new()
                .with("place", Value::Path(p.path.clone()))
                .with("rights", text(rights_word(p.rights)))
                .with("size", v.map_or(text(""), |v| Value::Size(v.total.saturating_mul(v.block))))
                .with("free", v.map_or(text(""), |v| Value::Size(v.free.saturating_mul(v.block)))),
        );
    }
    Ok(rs)
}

/// One call on the manager channel: (status, payload).
fn manager(sh: &Shell, op: u32, a: u64, payload: &[u8]) -> Result<Vec<u8>, String> {
    if sh.mgr == 0 {
        return Err(String::from("this session may not manage services (no manager grant)"));
    }
    let mut req = alloc::vec![0u8; HEADER];
    Header { txid: 0, op, status: 0, a, b: 0 }.put(&mut req);
    req.extend_from_slice(payload);
    let mut rep = alloc::vec![0u8; HEADER + rec::MAX_PAYLOAD];
    let n = sys::channel_call(sh.mgr, &req, &mut rep, 10_000_000_000).map_err(|e| format!("the service manager did not answer ({})", sys::status(e)))? as usize;
    let h = Header::get(&rep[..n]).ok_or_else(|| String::from("a malformed answer"))?;
    let body = rep[HEADER..n].to_vec();
    if h.status != 0 {
        let why = String::from_utf8_lossy(&body).into_owned();
        return Err(if why.is_empty() { String::from(sys::status(i64::from(h.status))) } else { why });
    }
    Ok(body)
}

fn manager_name(sh: &Shell, op: u32, what: &str, name: Option<&str>) -> Result<Vec<u8>, String> {
    let Some(n) = name else { return Err(format!("{}: which service? (tasks lists them)", what)) };
    let r = manager(sh, op, 0, n.as_bytes()).map_err(|e| format!("{}: {}: {}", what, n, e))?;
    if op == svc::MGR_RESTART || op == svc::MGR_STOP {
        sh.write(&show::ok_line(&format!("{} {}", if op == svc::MGR_STOP { "stopping" } else { "restarting" }, n)));
    }
    Ok(r)
}

fn job_record(j: &crate::Job) -> Record {
    let q = if j.code.is_none() { sys::process_quota(j.proc.raw()).ok() } else { None };
    let state = match j.code {
        None => String::from("running"),
        Some(0) => String::from("done"),
        Some(c) => format!("ended ({})", c),
    };
    Record::new()
        .with("name", text(&format!("job {}: {}", j.id, j.line)))
        .with("kind", text("job"))
        .with("state", Value::Text(state))
        .with("memory", q.map_or(text(""), |q| Value::Size(q.used.memory)))
        .with("handles", q.map_or(text(""), |q| Value::Int(q.used.handles as i64)))
}

fn tasks(sh: &Shell) -> Res {
    let mut rs: Vec<Record> = Vec::new();
    if sh.mgr != 0 {
        for r in rec::decode_all(&manager(sh, svc::MGR_LIST, 0, &[])?) {
            let get = |n: &str| r.get(n).cloned().unwrap_or(text(""));
            rs.push(
                Record::new()
                    .with("name", get("name"))
                    .with("kind", text("service"))
                    .with("state", get("state"))
                    .with("memory", get("memory"))
                    .with("handles", get("handles"))
                    .with("restarts", get("restarts")),
            );
        }
    }
    rs.extend(sh.jobs.iter().map(job_record));
    Ok(rs)
}

fn jobs(sh: &Shell) -> Vec<Record> {
    sh.jobs.iter().map(job_record).collect()
}

fn job_id(arg: &str) -> Option<u32> {
    arg.trim_start_matches('#').parse().ok()
}

fn objects(sh: &Shell, target: Option<&str>) -> Res {
    let bytes = match target {
        None => crate_objects(Shell::self_process()),
        Some(t) => match job_id(t) {
            Some(id) => {
                let j = sh.jobs.iter().find(|j| j.id == id).ok_or_else(|| format!("objects: no job {}", id))?;
                crate_objects(j.proc.raw())
            }
            None => manager(sh, svc::MGR_OBJECTS, 0, t.as_bytes()).map_err(|e| format!("objects: {}: {}", t, e))?,
        },
    };
    Ok(rec::decode_all(&bytes))
}

/// The handles of a process this shell holds (itself or a job), as records.
fn crate_objects(p: Handle) -> Vec<u8> {
    const TYPES: [&str; 15] = ["?", "process", "thread", "vmo", "vmar", "event", "timer", "log", "channel", "port", "exception", "resource", "device", "interrupt", "pin"];
    let mut buf = alloc::vec![sys::HandleEntry::default(); 256];
    let n = sys::process_handles(p, &mut buf).map_or(0, |n| (n as usize).min(buf.len()));
    let mut out = Vec::new();
    let letters = [
        (sys::RIGHT_READ, 'r'),
        (sys::RIGHT_WRITE, 'w'),
        (sys::RIGHT_EXECUTE, 'x'),
        (sys::RIGHT_MAP, 'm'),
        (sys::RIGHT_TRANSFER, 't'),
        (sys::RIGHT_DUPLICATE, 'd'),
        (sys::RIGHT_WAIT, 'W'),
        (sys::RIGHT_SIGNAL, 's'),
        (sys::RIGHT_INSPECT, 'i'),
        (sys::RIGHT_MANAGE, 'M'),
    ];
    for e in &buf[..n] {
        let rights: String = letters.iter().map(|&(b, c)| if e.rights & b != 0 { c } else { '-' }).collect();
        Record::new()
            .with("type", text(TYPES.get(e.ty as usize).copied().unwrap_or("?")))
            .with("name", text(e.name()))
            .with("rights", Value::Text(rights))
            .with("koid", Value::Int(e.koid as i64))
            .encode(&mut out);
    }
    out
}

fn end(sh: &mut Shell, target: Option<&str>) -> Res {
    let Some(t) = target else { return Err(String::from("end: what? (a job number from 'jobs', or a service from 'tasks')")) };
    if let Some(id) = job_id(t) {
        let j = sh.jobs.iter().find(|j| j.id == id).ok_or_else(|| format!("end: no job {}", id))?;
        sys::process_kill(j.proc.raw());
        sh.write(&show::ok_line(&format!("job {} ended", id)));
        return Ok(Vec::new());
    }
    manager_name(sh, svc::MGR_STOP, "end", Some(t)).map(|_| Vec::new())
}

fn wait(sh: &mut Shell, arg: Option<&str>) -> Res {
    let id = arg.and_then(job_id).ok_or_else(|| String::from("wait: which job? (jobs lists them)"))?;
    let j = sh.jobs.iter_mut().find(|j| j.id == id).ok_or_else(|| format!("wait: no job {}", id))?;
    if j.code.is_none() {
        // Still running: wait for it like a command typed now.
        let _ = sys::object_wait(j.proc.raw(), sys::TERMINATED, sys::WAIT_FOREVER);
        j.code = Some(sys::process_exit_code(j.proc.raw()));
    }
    j.background = false;
    sh.finish(id);
    Ok(Vec::new())
}

fn level_name(l: u8) -> &'static str {
    match u32::from(l) {
        sys::LOG_ERROR => "error",
        sys::LOG_WARN => "warn",
        sys::LOG_INFO => "info",
        _ => "debug",
    }
}

fn log(sh: &Shell, source: Option<&str>) -> Res {
    if sh.log == 0 {
        return Err(String::from("log: this session cannot read the log (no log.read grant)"));
    }
    let base = if sh.clock != 0 { time::query(sh.clock) } else { None };
    let mut rs = Vec::new();
    let mut from = 0;
    loop {
        let b = libd::log::read(sh.log, from, libd::log::MAX_PER_READ, false, 2_000_000_000).map_err(|e| format!("log: {}", sys::status(e)))?;
        for r in &b.records[..b.count] {
            let src = String::from_utf8_lossy(r.source()).into_owned();
            if source.is_some_and(|s| s != src) {
                continue;
            }
            let when = base.map_or(0, |b| b.wall.add_ns((r.time_us * 1000) as i64 - b.mono as i64).0);
            rs.push(
                Record::new()
                    .with("time", Value::Time(when))
                    .with("level", text(level_name(r.level)))
                    .with("source", Value::Text(src))
                    .with("text", Value::Text(String::from_utf8_lossy(r.text()).trim_end().into())),
            );
        }
        if b.count == 0 || b.next <= from {
            break;
        }
        from = b.next;
    }
    Ok(rs)
}

fn clock(sh: &Shell) -> Res {
    let up = sys::clock_ns() / 1_000_000_000;
    let uptime = if up >= 3600 { format!("{} h {:02} min", up / 3600, up % 3600 / 60) } else { format!("{} min {:02} s", up / 60, up % 60) };
    let (now, src) = match sh.clock {
        0 => (0, "no clock granted"),
        c => match time::query(c) {
            Some(b) => (
                b.now().0,
                match b.source {
                    time::SOURCE_UEFI => "UEFI clock at boot",
                    time::SOURCE_RTC => "CMOS clock",
                    _ => "unknown",
                },
            ),
            None => (0, "the clock service did not answer"),
        },
    };
    sh.write(&format!("{}\n", show::time_seconds(now)));
    Ok(alloc::vec![Record::new().with("since boot", Value::Text(uptime)).with("source", text(src))])
}

fn power(sh: &Shell, what: Option<&str>) -> Res {
    let action = match what {
        Some("off") => sys::POWER_OFF,
        Some("restart" | "reboot") => sys::POWER_REBOOT,
        Some("sleep" | "suspend") => sys::POWER_SUSPEND,
        _ => return Err(String::from("power: usage: power off | restart | sleep")),
    };
    manager(sh, svc::MGR_POWER, action, &[]).map_err(|e| format!("power: {}", e))?;
    let msg = match action {
        sys::POWER_OFF => "switching off: every service stops first",
        sys::POWER_REBOOT => "restarting: every service stops first",
        _ => "entering sleep: syncing volumes and quiescing drivers",
    };
    sh.write(&show::ok_line(msg));
    Ok(Vec::new())
}

/// Parse a non-negative integer or single-decimal number scaled by `scale` (e.g. `"1.5"` * 1000 = 1500).
fn parse_scaled_u32(num: &str, scale: u64) -> Option<u32> {
    if num.is_empty() {
        return None;
    }
    let (whole_s, frac_s) = match num.split_once('.') {
        Some((w, f)) => (w, f),
        None => (num, ""),
    };
    if whole_s.is_empty() && frac_s.is_empty() {
        return None;
    }
    let whole: u64 = if whole_s.is_empty() { 0 } else { whole_s.parse().ok()? };
    let mut frac_val = 0u64;
    let mut frac_div = 1u64;
    for b in frac_s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        if frac_div < 10_000 {
            frac_val = frac_val * 10 + u64::from(b - b'0');
            frac_div *= 10;
        }
    }
    let total = whole.checked_mul(scale)?.checked_add((frac_val * scale) / frac_div)?;
    u32::try_from(total).ok()
}

/// Parse a frequency like `"440"`, `"500Hz"`, `"1.5kHz"` -> Hz (clamped to `80..=8000`).
fn parse_hz(raw: &str) -> Result<u32, String> {
    let lower = raw.to_ascii_lowercase();
    let (num, scale) = if let Some(n) = lower.strip_suffix("khz") {
        (n, 1000u64)
    } else if let Some(n) = lower.strip_suffix("hz") {
        (n, 1u64)
    } else {
        (lower.as_str(), 1u64)
    };
    let hz = parse_scaled_u32(num, scale)
        .filter(|&v| v > 0)
        .ok_or_else(|| format!("audio: invalid frequency '{}' (e.g. 440, 500Hz, 1.5kHz)", raw))?;
    Ok(hz.clamp(80, 8000))
}

/// Parse a duration like `"500"`, `"1000ms"`, `"1.5s"` -> ms (clamped to `50..=5000`).
fn parse_ms(raw: &str) -> Result<u32, String> {
    let lower = raw.to_ascii_lowercase();
    let (num, scale) = if let Some(n) = lower.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = lower.strip_suffix('s') {
        (n, 1000u64)
    } else {
        (lower.as_str(), 1u64)
    };
    let ms = parse_scaled_u32(num, scale)
        .filter(|&v| v > 0)
        .ok_or_else(|| format!("audio: invalid duration '{}' (e.g. 500, 1000ms, 1.5s)", raw))?;
    Ok(ms.clamp(50, 5000))
}

fn audio_cmd(sh: &Shell, args: &[String]) -> Res {
    use dosaudio::pcm::{SampleFormat, StreamParams, ToneGen};
    use dosaudio::route::DeviceKind;
    use libd::audio::{self, DeviceEntry, FMT_S16_LE, PlaybackStream};

    let sub = args.first().map(String::as_str);
    match sub {
        None | Some("list") => {
            let ch = if sh.audio_ctl != 0 { sh.audio_ctl } else { sh.audio_play };
            if ch == 0 {
                return Err(String::from("audio: no audio capability granted to this session"));
            }
            let mut devs = [DeviceEntry::empty(); 16];
            let n = audio::list_devices(ch, &mut devs).map_err(|e| format!("audio: {}", sys::status(e)))?;
            let mut rs = Vec::new();
            for d in &devs[..n] {
                let state = if d.active_out {
                    "active out"
                } else if d.active_in {
                    "active in"
                } else if !d.online {
                    "offline"
                } else if (d.flags & audio::FLAG_PLUGGED) != 0 {
                    "plugged"
                } else {
                    "unplugged"
                };
                let vol = if d.muted {
                    format!("{}% (muted)", d.volume)
                } else {
                    format!("{}%", d.volume)
                };
                rs.push(
                    Record::new()
                        .with("id", Value::Int(i64::from(d.id)))
                        .with("name", Value::Text(String::from(d.name_str())))
                        .with("kind", text(DeviceKind::from_u8(d.kind).label()))
                        .with("state", text(state))
                        .with("volume", Value::Text(vol)),
                );
            }
            Ok(rs)
        }
        Some("vol") => {
            let Some(vs) = args.get(1) else {
                return Err(String::from("audio: usage: audio vol <0-100%> [device-id]"));
            };
            let vs = vs.strip_suffix('%').unwrap_or(vs.as_str());
            let vol: u8 = vs.parse().map_err(|_| String::from("audio: volume must be 0..=100"))?;
            if vol > 100 {
                return Err(String::from("audio: volume must be 0..=100"));
            }
            let dev_id: u64 = match args.get(2) {
                Some(s) => s.parse().map_err(|_| format!("audio: invalid device id '{}'", s))?,
                None => 0,
            };
            audio::control_call(sh.audio_ctl, audio::OP_SET_VOL, dev_id, u64::from(vol))
                .map_err(|e| format!("audio: {}", sys::status(e)))?;
            sh.write(&show::ok_line(&format!("volume set to {}%", vol)));
            Ok(Vec::new())
        }
        Some("mute") => {
            let mut devs = [DeviceEntry::empty(); 16];
            let n = audio::list_devices(sh.audio_ctl, &mut devs).unwrap_or(0);
            let active = devs[..n].iter().find(|d| d.active_out);
            let cur_muted = active.is_some_and(|d| d.muted);
            let muted = match args.get(1).map(|s| s.to_ascii_lowercase()).as_deref() {
                None => !cur_muted,
                Some("on" | "1" | "true") => true,
                Some("off" | "0" | "false") => false,
                Some(_) => return Err(String::from("audio: usage: audio mute [on|off]")),
            };
            let b = audio::VOL_FLAG_MUTE_ONLY | (u64::from(muted) << 8);
            let rep = audio::control_call(sh.audio_ctl, audio::OP_SET_VOL, 0, b)
                .map_err(|e| format!("audio: {}", sys::status(e)))?;
            if muted {
                sh.write(&show::ok_line("output muted"));
            } else {
                sh.write(&show::ok_line(&format!("output unmuted ({}%)", rep.b)));
            }
            Ok(Vec::new())
        }
        Some("unmute") => {
            let rep = audio::control_call(sh.audio_ctl, audio::OP_SET_VOL, 0, audio::VOL_FLAG_MUTE_ONLY)
                .map_err(|e| format!("audio: {}", sys::status(e)))?;
            sh.write(&show::ok_line(&format!("output unmuted ({}%)", rep.b)));
            Ok(Vec::new())
        }
        Some("out") => {
            let Some(sel) = args.get(1).map(String::as_str) else {
                return Err(String::from("audio: usage: audio out <id|auto>"));
            };
            let id: u64 = if sel == "auto" {
                0
            } else {
                sel.parse().map_err(|_| String::from("audio: device id must be a number or 'auto'"))?
            };
            audio::control_call(sh.audio_ctl, audio::OP_SET_DEFAULT, id, 0)
                .map_err(|e| format!("audio: {}", sys::status(e)))?;
            sh.write(&show::ok_line(if id == 0 { "automatic output switching enabled" } else { "output switched" }));
            Ok(Vec::new())
        }
        Some("mic") => {
            let allow = match args.get(1).map(String::as_str) {
                Some("on" | "allow" | "1") => true,
                Some("off" | "revoke" | "0") => false,
                _ => return Err(String::from("audio: usage: audio mic <on|off>")),
            };
            audio::control_call(sh.audio_ctl, audio::OP_SET_MIC_GRANT, u64::from(allow), 0)
                .map_err(|e| format!("audio: {}", sys::status(e)))?;
            sh.write(&show::ok_line(if allow { "microphone capture allowed" } else { "microphone capture revoked" }));
            Ok(Vec::new())
        }
        Some("tone") => {
            let hz: u32 = match args.get(1) {
                Some(s) => parse_hz(s)?,
                None => 440,
            };
            let ms: u32 = match args.get(2) {
                Some(s) => parse_ms(s)?,
                None => 500,
            };
            let mut stream = PlaybackStream::open(sh.audio_play, 48_000, 2, FMT_S16_LE, 0)
                .map_err(|e| format!("audio: cannot open playback: {}", sys::status(e)))?;
            let params = StreamParams { rate: 48_000, channels: 2, format: SampleFormat::S16Le };
            let mut tone = ToneGen::new(hz, 48_000, 16_000);
            let total_frames = (48_000u64 * u64::from(ms) / 1000) as usize;
            let mut buf = alloc::vec![0u8; 480 * 4]; // 10 ms chunks
            let mut sent = 0usize;
            while sent < total_frames {
                let chunk_frames = (total_frames - sent).min(480);
                let bytes = chunk_frames * 4;
                tone.fill(params, &mut buf[..bytes]);
                stream.write(&buf[..bytes]).map_err(|e| format!("audio: write failed: {}", sys::status(e)))?;
                sent += chunk_frames;
            }
            // Flush 120 ms of trailing silence so hardware DMA and host audio buffers finish
            // playing the tone cleanly and retain no stale PCM after stream close.
            buf.fill(0);
            for _ in 0..12 {
                let _ = stream.write(&buf);
            }
            stream.drain(2_000_000_000);
            stream.close();
            sh.write(&show::ok_line(&format!("played {} Hz tone for {} ms", hz, ms)));
            Ok(Vec::new())
        }
        _ => Err(String::from("audio: usage: audio [vol <0-100%> | mute [on|off] | unmute | out <id|auto> | tone [hz] [ms] | mic <on|off>]")),
    }
}

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn net_cmd(sh: &Shell) -> Res {
    let ch = if sh.net_ctl != 0 {
        sh.net_ctl
    } else if sh.net_client != 0 {
        sh.net_client
    } else {
        sh.net_icmp
    };
    if ch == 0 {
        return Err(String::from("net: no network capability granted to this session"));
    }
    let st = libd::net::status(ch).map_err(|e| format!("net: {}", sys::status(e)))?;
    if st.name_len == 0 {
        sh.write("no network interface attached\n");
        return Ok(Vec::new());
    }
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        st.mac[0], st.mac[1], st.mac[2], st.mac[3], st.mac[4], st.mac[5]
    );
    let state = if st.static_mode {
        if st.link_up { "up (static)" } else { "down (static)" }
    } else if st.dhcp_bound {
        "up (dhcp)"
    } else if st.link_up {
        "link up (acquiring dhcp)"
    } else {
        "down"
    };
    let dns_str = if st.dns2 != [0; 4] {
        format!("{}, {}", fmt_ip(st.dns), fmt_ip(st.dns2))
    } else {
        fmt_ip(st.dns)
    };
    Ok(alloc::vec![
        Record::new()
            .with("interface", Value::Text(String::from(st.name_str())))
            .with("state", text(state))
            .with("ip", Value::Text(fmt_ip(st.ip)))
            .with("gateway", Value::Text(fmt_ip(st.gateway)))
            .with("dns", Value::Text(dns_str))
            .with("mac", Value::Text(mac))
            .with("rx", Value::Int(st.rx_packets as i64))
            .with("tx", Value::Int(st.tx_packets as i64)),
    ])
}

fn net_dhcp(sh: &Shell) -> Res {
    if sh.net_ctl == 0 {
        return Err(String::from("net: no net.control capability granted to this session"));
    }
    let cfg = libd::net::NetConfig {
        dhcp: true,
        ip: [0; 4],
        netmask: [0; 4],
        gateway: [0; 4],
        dns1: [0; 4],
        dns2: [0; 4],
        dns_port: 53,
        dns_fallback: true,
    };
    libd::net::set_config(sh.net_ctl, &cfg).map_err(|e| format!("net dhcp: {}", sys::status(e)))?;
    sh.write(&show::ok_line("switched to automatic DHCPv4 (acquiring lease)"));
    Ok(Vec::new())
}

fn net_dns(sh: &Shell, args: &[String]) -> Res {
    if sh.net_ctl == 0 {
        return Err(String::from("net: no net.control capability granted to this session"));
    }
    let Some(first) = args.first().map(String::as_str) else {
        return Err(String::from("net: usage: net dns <ip|auto> [dns2]"));
    };
    let st = libd::net::status(sh.net_ctl).map_err(|e| format!("net dns: {}", sys::status(e)))?;
    let (dns1, dns2) = if first == "auto" {
        ([0; 4], [0; 4])
    } else {
        let d1 = dosnet::parse_ipv4(first)
            .ok_or_else(|| format!("net dns: invalid IPv4 address '{}'", first))?;
        let d2 = match args.get(1).map(String::as_str) {
            Some(s) => dosnet::parse_ipv4(s)
                .ok_or_else(|| format!("net dns: invalid secondary IPv4 address '{}'", s))?,
            None => [0; 4],
        };
        (d1, d2)
    };
    let cfg = libd::net::NetConfig {
        dhcp: !st.static_mode,
        ip: st.ip,
        netmask: st.netmask,
        gateway: st.gateway,
        dns1,
        dns2,
        dns_port: if st.dns_port == 0 { 53 } else { st.dns_port },
        dns_fallback: st.dns_fallback,
    };
    libd::net::set_config(sh.net_ctl, &cfg).map_err(|e| format!("net dns: {}", sys::status(e)))?;
    if dns1 == [0; 4] {
        sh.write(&show::ok_line("DNS reset to automatic (DHCP)"));
    } else if dns2 != [0; 4] {
        sh.write(&show::ok_line(&format!("DNS set to {}, {}", fmt_ip(dns1), fmt_ip(dns2))));
    } else {
        sh.write(&show::ok_line(&format!("DNS set to {}", fmt_ip(dns1))));
    }
    Ok(Vec::new())
}

fn net_static(sh: &Shell, args: &[String]) -> Res {
    if sh.net_ctl == 0 {
        return Err(String::from("net: no net.control capability granted to this session"));
    }
    let (Some(ip_s), Some(mask_s), Some(gw_s)) = (args.first(), args.get(1), args.get(2)) else {
        return Err(String::from("net: usage: net static <ip> <mask> <gw> [dns1] [dns2]"));
    };
    let ip = dosnet::parse_ipv4(ip_s)
        .filter(|&a| a != [0; 4])
        .ok_or_else(|| format!("net static: invalid IPv4 address '{}'", ip_s))?;
    let netmask = dosnet::parse_ipv4(mask_s)
        .filter(|&a| a != [0; 4])
        .ok_or_else(|| format!("net static: invalid subnet mask '{}'", mask_s))?;
    let gateway = dosnet::parse_ipv4(gw_s)
        .ok_or_else(|| format!("net static: invalid gateway '{}'", gw_s))?;
    let st = libd::net::status(sh.net_ctl).unwrap_or_else(|_| libd::net::NetStatus::empty());
    let (dns1, dns2) = match args.get(3) {
        Some(d1s) => {
            let d1 = dosnet::parse_ipv4(d1s)
                .ok_or_else(|| format!("net static: invalid DNS address '{}'", d1s))?;
            let d2 = match args.get(4) {
                Some(d2s) => dosnet::parse_ipv4(d2s)
                    .ok_or_else(|| format!("net static: invalid secondary DNS '{}'", d2s))?,
                None => [0; 4],
            };
            (d1, d2)
        }
        None => (
            if st.dns != [0; 4] { st.dns } else { [1, 1, 1, 1] },
            if st.dns2 != [0; 4] { st.dns2 } else { [8, 8, 8, 8] },
        ),
    };
    let cfg = libd::net::NetConfig {
        dhcp: false,
        ip,
        netmask,
        gateway,
        dns1,
        dns2,
        dns_port: 53,
        dns_fallback: st.dns_fallback,
    };
    libd::net::set_config(sh.net_ctl, &cfg).map_err(|e| format!("net static: {}", sys::status(e)))?;
    sh.write(&show::ok_line(&format!(
        "static IPv4 set: {} mask {} gw {} dns {}",
        fmt_ip(ip),
        fmt_ip(netmask),
        fmt_ip(gateway),
        fmt_ip(dns1)
    )));
    Ok(Vec::new())
}

/// `net check`: try each step to the internet in turn (lease, router, internet by ICMP and by
/// TCP, name lookup) and say in one line what does not work.
fn net_check(sh: &Shell) -> Res {
    use libd::net;
    let ch = [sh.net_ctl, sh.net_client, sh.net_icmp].into_iter().find(|&h| h != 0).ok_or_else(|| String::from("net: no network capability granted to this session"))?;
    let st = net::status(ch).map_err(|e| format!("net: {}", sys::status(e)))?;
    let mut rs = Vec::new();
    let mut row = |step: &str, ok: Option<bool>, detail: String| {
        let result = match ok {
            Some(true) => "ok",
            Some(false) => "FAILED",
            None => "skipped",
        };
        rs.push(Record::new().with("step", text(step)).with("result", text(result)).with("detail", Value::Text(detail)));
    };
    let leased = st.name_len != 0 && (st.dhcp_bound || (st.static_mode && st.ip != [0; 4]));
    row(
        "address",
        Some(leased),
        if st.name_len == 0 {
            String::from("no network adapter")
        } else if !st.link_up {
            String::from("no link: check the cable")
        } else if !leased {
            String::from("link up, but no DHCP lease from the router yet")
        } else {
            let mode = if st.static_mode { "static" } else { "dhcp" };
            format!("{} ({}) via {} (gateway {}, DNS {})", fmt_ip(st.ip), mode, st.name_str(), fmt_ip(st.gateway), fmt_ip(st.dns))
        },
    );
    if !leased {
        drop(row);
        sh.write(&show::err_line("net check: no address yet; nothing further can work"));
        return Ok(rs);
    }
    let ping = |ip: [u8; 4]| -> Option<u32> {
        (sh.net_icmp != 0).then_some(())?;
        (1..=2u16).find_map(|seq| net::ping(sh.net_icmp, ip, seq, 1_500).ok()).map(|(rtt, _)| rtt)
    };
    let icmp = sh.net_icmp != 0;
    let gw = ping(st.gateway);
    row("router", icmp.then_some(gw.is_some()), match gw {
        Some(ms) => format!("{} answers ping ({} ms)", fmt_ip(st.gateway), ms),
        None if icmp => format!("{} does not answer ping", fmt_ip(st.gateway)),
        None => String::from("no ICMP right in this session"),
    });
    const PROBE: [u8; 4] = [1, 1, 1, 1];
    let inet_icmp = ping(PROBE);
    row("internet (ping)", icmp.then_some(inet_icmp.is_some()), match inet_icmp {
        Some(ms) => format!("1.1.1.1 answers ping ({} ms)", ms),
        None => String::from("1.1.1.1 does not answer ping"),
    });
    let tcp_start = sys::clock_ns();
    let inet_tcp = (sh.net_client != 0).then(|| net::TcpStream::connect(sh.net_client, PROBE, 443, 3_000).map(|s| s.close()).is_ok());
    let tcp_ms = (sys::clock_ns() - tcp_start) / 1_000_000;
    row("internet (tcp)", inet_tcp, match inet_tcp {
        Some(true) => format!("connected to 1.1.1.1 port 443 ({} ms)", tcp_ms),
        Some(false) => String::from("no connection to 1.1.1.1 port 443"),
        None => String::from("no TCP right in this session"),
    });
    // Lookups are served on the ICMP and client endpoints (not on control).
    let dns_ch = if sh.net_icmp != 0 { sh.net_icmp } else { sh.net_client };
    let dns = if dns_ch != 0 { net::resolve(dns_ch, "example.com") } else { Err(sys::ERR_ACCESS_DENIED) };
    row("name lookup", Some(dns.is_ok()), match dns {
        Ok(ip) => format!("example.com is {}", fmt_ip(ip)),
        Err(e) => format!("example.com: {} (DNS {} and the public resolvers)", sys::status(e), fmt_ip(st.dns)),
    });
    drop(row);
    let internet = inet_icmp.is_some() || inet_tcp == Some(true);
    let verdict = match (gw.is_some(), internet, inet_icmp.is_some(), dns.is_ok()) {
        (_, true, true, true) => Ok("everything works"),
        (_, true, false, true) => Ok("the internet works; ping replies are blocked on the way (by the router or the network), so ping cannot reach outside hosts"),
        (_, true, _, false) => Err("the internet works but no DNS server answers: names cannot be looked up"),
        (true, false, _, _) => Err("the router answers but nothing beyond it: the router has no internet connection, or does not forward for this machine"),
        (false, false, _, _) => Err("neither the router nor the internet answers: check the router, or the gateway the DHCP lease named"),
    };
    match verdict {
        Ok(v) => sh.write(&show::ok_line(&format!("net check: {}", v))),
        Err(v) => sh.write(&show::err_line(&format!("net check: {}", v))),
    }
    Ok(rs)
}

fn ping_cmd(sh: &Shell, args: &[String]) -> Res {
    let Some(host) = args.first().map(String::as_str) else {
        return Err(String::from("ping: usage: ping <host> [count]"));
    };
    if sh.net_icmp == 0 {
        return Err(String::from("ping: no network ICMP capability granted to this session"));
    }
    let count: u16 = match args.get(1) {
        Some(s) => s
            .parse::<u16>()
            .ok()
            .filter(|&n| (1..=16).contains(&n))
            .ok_or_else(|| String::from("ping: count must be between 1 and 16"))?,
        None => 4,
    };
    let ip = libd::net::resolve(sh.net_icmp, host)
        .map_err(|e| format!("ping: cannot resolve '{}': {}", host, sys::status(e)))?;
    let ip_s = fmt_ip(ip);
    sh.write(&format!("PING {} ({}): {} request(s)\n", host, ip_s, count));

    let mut rs = Vec::new();
    let mut recv = 0u16;
    let mut min_ms = u32::MAX;
    let mut max_ms = 0u32;
    let mut sum_ms = 0u64;

    for seq in 1..=count {
        match libd::net::ping(sh.net_icmp, ip, seq, 2_000) {
            Ok((rtt, ttl)) => {
                recv += 1;
                min_ms = min_ms.min(rtt);
                max_ms = max_ms.max(rtt);
                sum_ms += u64::from(rtt);
                rs.push(
                    Record::new()
                        .with("host", Value::Text(ip_s.clone()))
                        .with("seq", Value::Int(i64::from(seq)))
                        .with("ttl", Value::Int(i64::from(ttl)))
                        .with("rtt", Value::Text(format!("{} ms", rtt)))
                        .with("status", text("reply")),
                );
            }
            Err(e) => {
                rs.push(
                    Record::new()
                        .with("host", Value::Text(ip_s.clone()))
                        .with("seq", Value::Int(i64::from(seq)))
                        .with("ttl", text("-"))
                        .with("rtt", text("-"))
                        .with("status", Value::Text(String::from(sys::status(e)))),
                );
            }
        }
        if seq < count {
            libd::handle::sleep(200_000_000);
        }
    }
    let loss = (u32::from(count - recv) * 100) / u32::from(count);
    if recv > 0 {
        let avg = sum_ms / u64::from(recv);
        sh.write(&show::ok_line(&format!(
            "ping {}: {}/{} received ({}% loss), rtt min/avg/max = {}/{}/{} ms",
            ip_s, recv, count, loss, min_ms, avg, max_ms
        )));
    } else {
        sh.write(&show::err_line(&format!(
            "ping {}: 0/{} received (100% loss)",
            ip_s, count
        )));
        // Many networks drop ping but carry everything else: say whether the host is reachable.
        let start = sys::clock_ns();
        let tcp = (sh.net_client != 0)
            .then(|| [443u16, 80].into_iter().find(|&port| libd::net::TcpStream::connect(sh.net_client, ip, port, 2_000).map(|s| s.close()).is_ok()))
            .flatten();
        match tcp {
            Some(port) => sh.write(&show::ok_line(&format!(
                "{} is reachable over TCP port {} ({} ms): ping replies are blocked on the way",
                ip_s,
                port,
                (sys::clock_ns() - start) / 1_000_000
            ))),
            None => sh.write("  `net check` shows which step to the internet does not work
"),
        }
    }
    Ok(rs)
}

fn load_system_roots(sh: &Shell) -> Result<Vec<Vec<u8>>, String> {
    let (node, _) = sh.open("tls", "/sys/certs/roots.der", 0, fp::R_READ)?;
    let st = node.stat().map_err(|e| format!("tls: stat /sys/certs/roots.der: {}", sys::status(e)))?;
    let size = st.size as usize;
    if size == 0 || size > 512 * 1024 {
        return Err(String::from("tls: /sys/certs/roots.der has invalid size"));
    }
    let mut raw = alloc::vec![0u8; size];
    let mut off = 0usize;
    while off < size {
        let n = node
            .read(off as u64, &mut raw[off..])
            .map_err(|e| format!("tls: read /sys/certs/roots.der: {}", sys::status(e)))?;
        if n == 0 {
            break;
        }
        off += n;
    }
    dosnet::roots::parse_der_bundle(&raw[..off])
        .ok_or_else(|| String::from("tls: malformed root CA bundle /sys/certs/roots.der"))
}

fn tls_cmd(sh: &Shell, args: &[String]) -> Res {
    let Some(host) = args.first().map(String::as_str) else {
        return Err(String::from("tls: usage: tls <host> [port]"));
    };
    if sh.net_client == 0 {
        return Err(String::from("tls: no network client capability granted to this session"));
    }
    let port: u16 = match args.get(1) {
        Some(s) => s
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| String::from("tls: port must be between 1 and 65535"))?,
        None => 443,
    };
    let roots = load_system_roots(sh)?;
    let root_count = roots.len();
    let now_unix = if sh.clock != 0
        && let Some(b) = time::query(sh.clock)
        && b.now().0 > 0
    {
        b.now().to_unix_secs()
    } else {
        return Err(String::from("tls: UTC clock unavailable (cannot verify certificate expiry)"));
    };
    let ip = libd::net::resolve(sh.net_client, host)
        .map_err(|e| format!("tls: cannot resolve '{}': {}", host, sys::status(e)))?;
    let ip_s = fmt_ip(ip);
    let mut stream = libd::net::TcpStream::connect(sh.net_client, ip, port, 10_000)
        .map_err(|e| format!("tls: connect {}:{} failed: {}", ip_s, port, sys::status(e)))?;

    let mut rand160 = [0u8; 160];
    libd::net::random_bytes(&mut rand160)
        .map_err(|e| format!("tls: kernel CSPRNG refused: {}", sys::status(e)))?;

    let mut client = dosnet::tls::TlsClient::new_with_options(
        host,
        roots,
        Vec::new(),
        Some(b"http/1.1"),
        now_unix,
        &rand160,
    );
    let mut buf = [0u8; 4096];
    let dl = sys::clock_ns() + 15_000_000_000;
    while !client.is_connected() {
        let out = client.take_tx();
        if !out.is_empty() {
            stream
                .write_all(&out)
                .map_err(|e| format!("tls: write failed: {}", sys::status(e)))?;
        }
        if sys::clock_ns() >= dl {
            stream.close();
            return Err(String::from("tls: handshake timed out"));
        }
        let n = stream
            .read(&mut buf, 5_000)
            .map_err(|e| format!("tls: read failed: {}", sys::status(e)))?;
        if n == 0 {
            stream.close();
            return Err(String::from("tls: peer closed connection during handshake"));
        }
        if let Err(e) = client.feed_rx(&buf[..n]) {
            stream.close();
            return Err(format!("tls: handshake rejected: {:?}", e));
        }
    }
    let out = client.take_tx();
    if !out.is_empty() {
        let _ = stream.write_all(&out);
    }
    let cipher = client.negotiated_cipher().map_or("?", |c| c.name());
    let group = client.negotiated_group().map_or("?", |g| g.name());
    client.close();
    let fin = client.take_tx();
    if !fin.is_empty() {
        let _ = stream.write_all(&fin);
    }
    stream.close();

    sh.write(&show::ok_line(&format!(
        "TLS 1.3 verified {} ({}:{}): {} / {} ({} system roots)",
        host, ip_s, port, cipher, group, root_count
    )));
    Ok(alloc::vec![
        Record::new()
            .with("host", Value::Text(String::from(host)))
            .with("ip", Value::Text(ip_s))
            .with("port", Value::Int(i64::from(port)))
            .with("protocol", text("TLS 1.3"))
            .with("cipher", text(cipher))
            .with("group", text(group))
            .with("roots", Value::Int(root_count as i64)),
    ])
}

/// `gui`: start the desktop (the keyboard and screen go to the compositor, this session shows in
/// the terminal window, until Super+Esc, or Ctrl+Alt+Esc in a VM); `gui demo` also opens the
/// example apps; `gui status`: the compositor's state; `gui theme|text|motion`: its settings.
fn gui_cmd(sh: &Shell, args: &[String]) -> Res {
    use libd::awmi;
    let arg = args.first().map(String::as_str);
    let admin = || if sh.awmi_admin == 0 { Err(String::from("gui: no awmi.admin grant in this session")) } else { Ok(sh.awmi_admin) };
    let set = |packed: u64, which: u64| -> Res {
        let now = awmi::set_settings(admin()?, packed, which).map_err(|e| format!("gui: the setting was refused ({})", sys::status(e)))?;
        let theme = if now & 0xFF == 1 { "high contrast" } else { "dark slate" };
        sh.write(&show::ok_line(&format!("theme {}, text {}%, motion {}", theme, (now >> 8) & 0xFFFF, if now >> 24 & 1 != 0 { "reduced" } else { "on" })));
        Ok(Vec::new())
    };
    let value = || args.get(1).map(String::as_str);
    match arg {
        None | Some("demo") => {
            let flags = awmi::SESSION_DESKTOP | if arg == Some("demo") { awmi::SESSION_DEMO } else { 0 };
            let n = awmi::session_start_with(admin()?, flags).map_err(|e| format!("gui: the session did not start ({})", sys::status(e)))?;
            sh.write(&show::ok_line(&format!("desktop on {} output(s); Super+Esc (Ctrl+Alt+Esc in a VM) comes back here", n)));
            Ok(Vec::new())
        }
        Some("lock") => {
            awmi::lock_session(admin()?, awmi::LOCK_REASON_MANUAL, awmi::LOCK_MODE_LOCKED)
                .map_err(|e| format!("gui: lock refused ({})", sys::status(e)))?;
            sh.write(&show::ok_line("desktop session locked"));
            Ok(Vec::new())
        }
        Some("theme") => match value() {
            Some("dark") => set(0, awmi::SET_THEME),
            Some("contrast") => set(1, awmi::SET_THEME),
            _ => Err(String::from("gui: usage: gui theme dark|contrast")),
        },
        Some("text") => match value().and_then(|v| v.trim_end_matches('%').parse::<u64>().ok()) {
            Some(p) if [100, 125, 150, 175, 200].contains(&p) => set(p << 8, awmi::SET_TEXT_SCALE),
            _ => Err(String::from("gui: usage: gui text 100|125|150|175|200")),
        },
        Some("motion") => match value() {
            Some("on") => set(0, awmi::SET_MOTION),
            Some("off") => set(1 << 24, awmi::SET_MOTION),
            _ => Err(String::from("gui: usage: gui motion on|off")),
        },
        Some("status") => {
            let ep = if sh.awmi_query != 0 { sh.awmi_query } else { sh.awmi_admin };
            if ep == 0 {
                return Err(String::from("gui: no awmi.query grant in this session"));
            }
            let st = awmi::status(ep).map_err(|e| format!("gui: status failed ({})", sys::status(e)))?;
            let mut ind = Vec::new();
            if st.indicators & awmi::IND_MIC_LIVE != 0 {
                ind.push("mic live");
            }
            if st.indicators & awmi::IND_SECURITY_ALERT != 0 {
                ind.push("security alert");
            }
            let mode = if st.active { format!("{}x{} @ {} Hz", st.width, st.height, st.refresh_mhz / 1000) } else { String::from("-") };
            let theme = if st.settings & 0xFF == 1 { "high contrast" } else { "dark slate" };
            Ok(alloc::vec![
                Record::new()
                    .with("session", text(if st.active { "active" } else { "idle" }))
                    .with("outputs", Value::Int(i64::from(st.outputs)))
                    .with("mode", Value::Text(mode))
                    .with("windows", Value::Int(i64::from(st.windows)))
                    .with("workspace", Value::Text(format!("{} of {}", st.active_workspace + 1, st.workspaces)))
                    .with("frames", Value::Int(st.frames as i64))
                    .with("indicators", Value::Text(if ind.is_empty() { String::from("none") } else { ind.join(", ") }))
                    .with("theme", text(theme))
                    .with("text", Value::Text(format!("{}%", (st.settings >> 8) & 0xFFFF)))
                    .with("motion", text(if st.settings >> 24 & 1 != 0 { "reduced" } else { "on" }))
                    .with("fonts", text(if st.fonts { "vector" } else { "bitmap" }))
                    .with("apps", Value::Int(i64::from(st.apps))),
            ])
        }
        Some(other) => Err(format!("gui: unknown argument '{}'; usage: gui [demo | status | theme dark|contrast | text 100-200 | motion on|off]", other)),
    }
}

fn gpu_cmd(sh: &Shell, args: &[String]) -> Res {
    use libd::gpu::{self, AdapterInfo, ModeEntry};
    if sh.gpu_query == 0 {
        return Err(String::from("gpu: no gpu.query grant in this session"));
    }
    if let Some(sub) = args.first().map(String::as_str) {
        let parse_id = |arg: Option<&String>| -> Result<u32, String> {
            match arg {
                Some(s) => s.parse::<u32>().map_err(|_| format!("gpu: invalid adapter id '{}'", s)),
                None => Ok(0),
            }
        };
        match sub {
            "modes" => {
                let id = parse_id(args.get(1))?;
                let mut modes = [ModeEntry::default(); 16];
                let n = gpu::get_modes(sh.gpu_query, id, &mut modes)
                    .map_err(|e| format!("gpu: get_modes failed ({})", sys::status(e)))?;
                let mut rs = Vec::new();
                for m in &modes[..n] {
                    let mut flags = String::new();
                    if (m.flags & gpu::MODE_FLAG_CURRENT) != 0 {
                        flags.push_str("current");
                    }
                    if (m.flags & gpu::MODE_FLAG_PREFERRED) != 0 {
                        if !flags.is_empty() {
                            flags.push(' ');
                        }
                        flags.push_str("preferred");
                    }
                    let timing = if m.pixel_clock_khz > 0 {
                        format!("{}.{:02} MHz ({}x{})", m.pixel_clock_khz / 1000, (m.pixel_clock_khz % 1000) / 10, m.htotal, m.vtotal)
                    } else {
                        String::from("-")
                    };
                    rs.push(
                        Record::new()
                            .with("mode", Value::Text(format!("{}x{}", m.width, m.height)))
                            .with(
                                "refresh",
                                Value::Text(format!("{}.{:02} Hz", m.refresh_mhz / 1000, (m.refresh_mhz % 1000) / 10)),
                            )
                            .with("timing", Value::Text(timing))
                            .with("flags", Value::Text(flags)),
                    );
                }
                return Ok(rs);
            }
            "display" => {
                let id = parse_id(args.get(1))?;
                let mut modes = [ModeEntry::default(); 16];
                let (k, mn) = gpu::kms_get_resources(sh.gpu_query, id, &mut modes)
                    .map_err(|e| format!("gpu: kms_get_resources failed ({})", sys::status(e)))?;
                let link_str = if k.dp_lanes > 0 {
                    format!(
                        "{}x ({} Mbps{})",
                        k.dp_lanes,
                        k.dp_rate_mbps,
                        if (k.status_flags & gpu::KMS_STATUS_DSC_ENABLED) != 0 {
                            ", DSC on"
                        } else if (k.status_flags & gpu::KMS_STATUS_DSC_CAPABLE) != 0 {
                            ", DSC cap"
                        } else {
                            ""
                        }
                    )
                } else {
                    String::from("none")
                };
                let mode_str = format!(
                    "{}x{} (total {}x{}, pitch {})",
                    k.width, k.height, k.htotal, k.vtotal, k.pitch_bytes
                );
                let hz_str = if k.refresh_mhz > 0 {
                    format!("{}.{:02} Hz", k.refresh_mhz / 1000, (k.refresh_mhz % 1000) / 10)
                } else {
                    String::from("inactive")
                };
                let mut state_parts = Vec::new();
                state_parts.push("atomic-kms");
                if (k.status_flags & gpu::KMS_STATUS_CRTC_ACTIVE) != 0 {
                    state_parts.push("crtc-active");
                }
                if (k.status_flags & gpu::KMS_STATUS_CURSOR_PLANE) != 0 {
                    state_parts.push("cursor-plane");
                }
                if (k.status_flags & gpu::KMS_STATUS_FIRMWARE_LOADED) != 0 {
                    state_parts.push("fw-ok");
                }
                if (k.status_flags & gpu::KMS_STATUS_VENDOR_SHIM_OK) != 0 {
                    state_parts.push("shim-ok");
                }
                if (k.status_flags & gpu::KMS_STATUS_VRR_CAPABLE) != 0 {
                    state_parts.push(if (k.status_flags & gpu::KMS_STATUS_VRR_ENABLED) != 0 { "vrr-on" } else { "vrr-cap" });
                }
                if (k.status_flags & gpu::KMS_STATUS_HDR_CAPABLE) != 0 {
                    state_parts.push(if (k.status_flags & gpu::KMS_STATUS_HDR_ENABLED) != 0 { "hdr-on" } else { "hdr-cap" });
                }
                if (k.status_flags & gpu::KMS_STATUS_REVERT_PENDING) != 0 {
                    state_parts.push("revert-pending");
                }

                let mut edid_modes = String::new();
                for (idx, m) in modes[..mn].iter().enumerate() {
                    if idx > 0 {
                        edid_modes.push_str(", ");
                    }
                    edid_modes.push_str(&format!("{}x{}@{}", m.width, m.height, m.refresh_mhz / 1000));
                }
                if !k.note_str().is_empty() {
                    sh.write(&format!("  note: {}\n", k.note_str()));
                }
                return Ok(alloc::vec![
                    Record::new()
                        .with("adapter", Value::Int(i64::from(k.adapter_id)))
                        .with("connector", Value::Text(format!("{}-{}", k.connector_kind_str(), k.connector_id)))
                        .with("crtc", Value::Text(format!("#{} (pipe {}, {} planes)", k.crtc_id, k.pipe, k.plane_count)))
                        .with("monitor", Value::Text(String::from(k.monitor_str())))
                        .with("mode", Value::Text(mode_str))
                        .with("refresh", Value::Text(hz_str))
                        .with("link", Value::Text(link_str))
                        .with("vblanks", Value::Int(k.vblank_seq as i64))
                        .with("state", Value::Text(state_parts.join(",")))
                        .with("modes", Value::Text(edid_modes)),
                ]);
            }
            "mode" => {
                if sh.awmi_admin == 0 {
                    return Err(String::from("gpu: mode switching requires awmi.admin grant"));
                }
                let (Some(ws), Some(hs), Some(hzs)) = (args.get(1), args.get(2), args.get(3)) else {
                    return Err(String::from("gpu: usage: gpu mode <width> <height> <hz> [adapter_id]"));
                };
                let w = ws.parse::<u32>().map_err(|_| format!("gpu: invalid width '{}'", ws))?;
                let h = hs.parse::<u32>().map_err(|_| format!("gpu: invalid height '{}'", hs))?;
                let raw_hz = hzs.parse::<u32>().map_err(|_| format!("gpu: invalid refresh '{}'", hzs))?;
                let refresh_mhz = if raw_hz >= 10_000 { raw_hz } else { raw_hz.saturating_mul(1000) };
                let id = parse_id(args.get(4))?;
                // Pass bit 2 (`require_confirm`) so an unconfirmed mode automatically reverts in 12s.
                libd::awmi::set_display_mode(sh.awmi_admin, id, w, h, refresh_mhz, 7)
                    .map_err(|e| format!("gpu: mode {}x{} @ {} Hz failed ({})", w, h, refresh_mhz / 1000, sys::status(e)))?;
                sh.write(&show::ok_line(&format!(
                    "display mode set to {}x{} @ {}.{:02} Hz (run 'gpu confirm' within 12s to keep, or 'gpu revert')",
                    w,
                    h,
                    refresh_mhz / 1000,
                    (refresh_mhz % 1000) / 10
                )));
                return Ok(Vec::new());
            }
            "confirm" | "revert" => {
                if sh.awmi_admin == 0 {
                    return Err(String::from("gpu: confirm/revert requires awmi.admin grant"));
                }
                let confirm = sub == "confirm";
                let id = parse_id(args.get(1))?;
                libd::awmi::confirm_display_mode(sh.awmi_admin, id, confirm)
                    .map_err(|e| format!("gpu: {} failed ({})", sub, sys::status(e)))?;
                sh.write(&show::ok_line(if confirm {
                    "display mode confirmed"
                } else {
                    "display mode reverted to previous mode"
                }));
                return Ok(Vec::new());
            }
            "vrr" => {
                if sh.awmi_admin == 0 {
                    return Err(String::from("gpu: VRR control requires awmi.admin grant"));
                }
                let enable = match args.get(1).map(String::as_str) {
                    Some("on") => true,
                    Some("off") => false,
                    _ => return Err(String::from("gpu: usage: gpu vrr on|off [adapter_id]")),
                };
                let id = parse_id(args.get(2))?;
                libd::awmi::set_display_vrr(sh.awmi_admin, id, enable, 0, 0)
                    .map_err(|e| format!("gpu: VRR {} failed ({})", if enable { "on" } else { "off" }, sys::status(e)))?;
                sh.write(&show::ok_line(&format!("VRR (Adaptive-Sync) {}", if enable { "enabled" } else { "disabled" })));
                return Ok(Vec::new());
            }
            "hdr" => {
                if sh.awmi_admin == 0 {
                    return Err(String::from("gpu: HDR control requires awmi.admin grant"));
                }
                let enable = match args.get(1).map(String::as_str) {
                    Some("on") => true,
                    Some("off") => false,
                    _ => return Err(String::from("gpu: usage: gpu hdr on|off [adapter_id]")),
                };
                let id = parse_id(args.get(2))?;
                libd::awmi::set_display_hdr(sh.awmi_admin, id, enable)
                    .map_err(|e| format!("gpu: HDR {} failed ({})", if enable { "on" } else { "off" }, sys::status(e)))?;
                sh.write(&show::ok_line(&format!("HDR10 (10-bit scanout) {}", if enable { "enabled" } else { "disabled" })));
                return Ok(Vec::new());
            }
            "scale" => {
                if sh.awmi_admin == 0 {
                    return Err(String::from("gpu: output scale requires awmi.admin grant"));
                }
                let scale: u16 = match args.get(1).map(String::as_str) {
                    Some("auto") => 0,
                    Some(v) => v
                        .trim_end_matches('%')
                        .parse::<u16>()
                        .ok()
                        .filter(|p| [100, 125, 150, 175, 200].contains(p))
                        .ok_or_else(|| String::from("gpu: usage: gpu scale 100|125|150|175|200|auto [adapter_id]"))?,
                    None => return Err(String::from("gpu: usage: gpu scale 100|125|150|175|200|auto [adapter_id]")),
                };
                let id = parse_id(args.get(2))?;
                libd::awmi::set_output_scale(sh.awmi_admin, id, scale)
                    .map_err(|e| format!("gpu: scale failed ({})", sys::status(e)))?;
                if scale == 0 {
                    sh.write(&show::ok_line("output scale reset to automatic"));
                } else {
                    sh.write(&show::ok_line(&format!("output scale set to {}%", scale)));
                }
                return Ok(Vec::new());
            }
            _ => return Err(String::from("gpu: usage: gpu [modes [id] | display [id] | mode <w> <h> <hz> [id] | confirm [id] | revert [id] | vrr on|off [id] | hdr on|off [id] | scale <pct|auto> [id]]")),
        }
    }
    let mut adapters = [AdapterInfo::empty(); 8];
    let n = gpu::list_adapters(sh.gpu_query, &mut adapters)
        .map_err(|e| format!("gpu: list_adapters failed ({})", sys::status(e)))?;
    if n == 0 {
        sh.write(&show::ok_line("no graphics adapters detected (VGA text mode)"));
        return Ok(Vec::new());
    }
    let mut rs = Vec::new();
    for a in &adapters[..n] {
        let pci = if a.vendor != 0 {
            format!("{:04x}:{:04x}", a.vendor, a.device)
        } else {
            String::from("platform")
        };
        let mut features = Vec::new();
        if (a.caps & gpu::CAP_IOMMU) != 0 {
            features.push("iommu");
        }
        if (a.caps & gpu::CAP_WC) != 0 {
            features.push("wc");
        }
        if (a.caps & gpu::CAP_ATOMIC_KMS) != 0 {
            features.push("atomic-kms");
        }
        if (a.caps & gpu::CAP_GEM_VM) != 0 {
            features.push("gem-vm");
        }
        if (a.caps & gpu::CAP_SYNCOBJ_TIMELINE) != 0 {
            features.push("syncobj");
        }
        if (a.caps & gpu::CAP_EDID) != 0 {
            features.push("edid");
        }
        if (a.caps & gpu::CAP_HW_CURSOR) != 0 {
            features.push("cursor");
        }
        if (a.caps & gpu::CAP_NATIVE_KMS) != 0 {
            features.push("native");
        }
        if (a.caps & gpu::CAP_VRR) != 0 {
            features.push("vrr");
        }
        if (a.caps & gpu::CAP_HDR) != 0 {
            features.push("hdr");
        }
        if (a.caps & gpu::CAP_DSC) != 0 {
            features.push("dsc");
        }
        if (a.caps & gpu::CAP_VIRGL_3D) != 0 {
            features.push("virgl3d");
        }
        if (a.caps & gpu::CAP_VENUS_VK) != 0 {
            features.push("venus");
        }
        if (a.caps & gpu::CAP_SYS_FIRMWARE) != 0 {
            features.push("fw");
        }
        if (a.caps & gpu::CAP_GSP_RPC) != 0 {
            features.push("gsp");
        }
        rs.push(
            Record::new()
                .with("id", Value::Int(i64::from(a.id)))
                .with("driver", text(a.kind_name()))
                .with("name", Value::Text(String::from(a.name_str())))
                .with("pci", Value::Text(pci))
                .with("mode", Value::Text(format!("{}x{}", a.width, a.height)))
                .with("vram", Value::Size(u64::from(a.vram_mib) << 20))
                .with("features", Value::Text(features.join(",")))
                .with("frames", Value::Int(a.frames as i64)),
        );
    }
    Ok(rs)
}

fn identity_cmd(sh: &mut Shell, args: &[String]) -> Res {
    use libd::identity::{self, IdentityInfo};
    let q = if sh.identity_query != 0 { sh.identity_query } else { sh.identity_admin };
    let admin = || {
        if sh.identity_admin == 0 {
            Err(String::from("identity: no identity.admin grant in this session"))
        } else {
            Ok(sh.identity_admin)
        }
    };
    match args.first().map(String::as_str) {
        None => {
            if q == 0 {
                return Err(String::from("identity: no identity.query grant in this session"));
            }
            let a = identity::active(q).map_err(|e| format!("identity: {}", sys::status(e)))?;
            let pol = identity::policy(q).unwrap_or_default();
            Ok(alloc::vec![
                Record::new()
                    .with("name", Value::Text(String::from(a.name_str())))
                    .with("display", Value::Text(String::from(a.display_str())))
                    .with("role", text(a.role_str()))
                    .with("home", Value::Text(format!("/home ({})", a.home_str())))
                    .with("seal", text(a.seal_str()))
                    .with("idle_s", Value::Int(i64::from(pol.idle_timeout_secs)))
                    .with("tpm", text(if pol.tpm_available { "yes" } else { "no" })),
            ])
        }
        Some("list") => {
            if q == 0 {
                return Err(String::from("identity: no identity.query grant in this session"));
            }
            let mut list = [IdentityInfo::default(); 8];
            let n = identity::list(q, &mut list).map_err(|e| format!("identity: {}", sys::status(e)))?;
            let mut rs = Vec::new();
            for id in &list[..n] {
                rs.push(
                    Record::new()
                        .with("id", Value::Int(i64::from(id.id)))
                        .with("name", Value::Text(String::from(id.name_str())))
                        .with("display", Value::Text(String::from(id.display_str())))
                        .with("role", text(id.role_str()))
                        .with("seal", text(id.seal_str()))
                        .with("active", text(if id.active { "*" } else { "" })),
                );
            }
            Ok(rs)
        }
        Some("enroll") => {
            let Some(pass) = args.get(1) else {
                return Err(String::from("identity: usage: identity enroll <passphrase>"));
            };
            let kind = identity::enroll(admin()?, 0, pass.as_bytes())
                .map_err(|e| format!("identity: enroll failed ({})", sys::status(e)))?;
            sh.write(&show::ok_line(if kind == identity::SEAL_TPM2 {
                "passphrase enrolled (TPM 2.0 sealed)"
            } else {
                "passphrase enrolled (software AEAD)"
            }));
            Ok(Vec::new())
        }
        Some("create") => {
            let (Some(name), Some(display)) = (args.get(1), args.get(2)) else {
                return Err(String::from("identity: usage: identity create <name> <display> [standard|operator]"));
            };
            if name.eq_ignore_ascii_case("root") {
                return Err(String::from("identity: D-OS has no root user"));
            }
            let role = match args.get(3).map(String::as_str) {
                None | Some("standard") => identity::ROLE_STANDARD,
                Some("operator") => identity::ROLE_OPERATOR,
                Some(other) => return Err(format!("identity: unknown role '{}' (standard or operator)", other)),
            };
            let uid = identity::create(admin()?, name, display, role)
                .map_err(|e| format!("identity: create failed ({})", sys::status(e)))?;
            sh.write(&show::ok_line(&format!("created identity '{}' (#{})", name, uid)));
            Ok(Vec::new())
        }
        Some("switch") => {
            let Some(name) = args.get(1) else {
                return Err(String::from("identity: usage: identity switch <name> [passphrase]"));
            };
            let pass = args.get(2).map_or(&[][..], |s| s.as_bytes());
            identity::switch_user(admin()?, name, pass)
                .map_err(|e| format!("identity: switch failed ({})", sys::status(e)))?;
            sh.refresh_home_scope();
            sh.write(&show::ok_line(&format!("active identity switched to '{}'", name)));
            Ok(Vec::new())
        }
        Some("policy") => {
            let mut pol = identity::policy(q).map_err(|e| format!("identity: {}", sys::status(e)))?;
            if args.len() == 1 {
                return Ok(alloc::vec![
                    Record::new()
                        .with("idle_timeout_secs", Value::Int(i64::from(pol.idle_timeout_secs)))
                        .with("lock_on_sleep", text(if pol.lock_on_sleep { "on" } else { "off" }))
                        .with("lock_at_boot", text(if pol.lock_at_boot { "on" } else { "off" }))
                        .with("tpm", text(if pol.tpm_available { "yes" } else { "no" })),
                ]);
            }
            match (args.get(1).map(String::as_str), args.get(2).map(String::as_str)) {
                (Some("idle"), Some(v)) => {
                    pol.idle_timeout_secs = v.parse::<u32>().map_err(|_| String::from("identity: idle seconds must be a number"))?;
                }
                (Some("sleep"), Some("on")) => pol.lock_on_sleep = true,
                (Some("sleep"), Some("off")) => pol.lock_on_sleep = false,
                (Some("boot"), Some("on")) => pol.lock_at_boot = true,
                (Some("boot"), Some("off")) => pol.lock_at_boot = false,
                _ => return Err(String::from("identity: usage: identity policy [idle <sec> | sleep on|off | boot on|off]")),
            }
            identity::set_policy(admin()?, pol.idle_timeout_secs, pol.lock_on_sleep, pol.lock_at_boot)
                .map_err(|e| format!("identity: set policy failed ({})", sys::status(e)))?;
            if sh.awmi_admin != 0 {
                let _ = libd::awmi::set_lock_policy(sh.awmi_admin, pol.idle_timeout_secs, pol.lock_on_sleep);
            }
            sh.write(&show::ok_line("lock policy updated"));
            Ok(Vec::new())
        }
        Some(other) => Err(format!("identity: unknown subcommand '{}'", other)),
    }
}

fn apps_cmd(sh: &Shell, args: &[String]) -> Res {
    use dosapp::{Permission, format_perm_mask};
    use libd::appmgr::{self, AppInfo, DECISION_DENIED, DECISION_GRANTED, MAX_APPS};
    let q = if sh.appmgr_query != 0 { sh.appmgr_query } else { sh.appmgr_admin };
    let admin = || {
        if sh.appmgr_admin == 0 {
            Err(String::from("apps: no appmgr.admin grant in this session"))
        } else {
            Ok(sh.appmgr_admin)
        }
    };
    match args.first().map(String::as_str) {
        None | Some("list") => {
            if q == 0 {
                return Err(String::from("apps: no appmgr.query grant in this session"));
            }
            let mut list = [AppInfo::default(); MAX_APPS];
            let n = appmgr::list(q, &mut list).map_err(|e| format!("apps: {}", sys::status(e)))?;
            let mut rs = Vec::new();
            for a in &list[..n] {
                rs.push(
                    Record::new()
                        .with("name", Value::Text(String::from(a.name_str())))
                        .with("title", Value::Text(String::from(a.title_str())))
                        .with("version", Value::Text(String::from(a.version_str())))
                        .with("running", Value::Int(i64::from(a.running)))
                        .with("permissions", Value::Text(format_perm_mask(a.effective_perms))),
                );
            }
            Ok(rs)
        }
        Some("launch") => {
            let Some(name) = args.get(1) else {
                return Err(String::from("apps: usage: apps launch <name>"));
            };
            let st = appmgr::launch(admin()?, name).map_err(|e| format!("apps: launch {} failed ({})", name, sys::status(e)))?;
            sh.write(&show::ok_line(if st == 2 {
                "permission prompt opened in compositor"
            } else {
                "application launched"
            }));
            Ok(Vec::new())
        }
        Some("stop") => {
            let Some(name) = args.get(1) else {
                return Err(String::from("apps: usage: apps stop <name>"));
            };
            let k = appmgr::stop(admin()?, name).map_err(|e| format!("apps: stop {} failed ({})", name, sys::status(e)))?;
            sh.write(&show::ok_line(&format!("stopped {} instance(s) of {}", k, name)));
            Ok(Vec::new())
        }
        Some("perms") => {
            let Some(name) = args.get(1) else {
                return Err(String::from("apps: usage: apps perms <name>"));
            };
            if q == 0 {
                return Err(String::from("apps: no appmgr.query grant in this session"));
            }
            let (eff, denied) = appmgr::perms(q, name).map_err(|e| format!("apps: {}", sys::status(e)))?;
            Ok(alloc::vec![
                Record::new()
                    .with("app", Value::Text(name.clone()))
                    .with("effective", Value::Text(format_perm_mask(eff)))
                    .with("revoked", Value::Text(format_perm_mask(denied))),
            ])
        }
        Some("grant" | "revoke") => {
            let grant = args[0] == "grant";
            let (Some(name), Some(pstr)) = (args.get(1), args.get(2)) else {
                return Err(format!("apps: usage: apps {} <name> <permission>", args[0]));
            };
            let Some(perm) = Permission::parse(pstr) else {
                return Err(format!("apps: unknown permission '{}'", pstr));
            };
            let dec = if grant { DECISION_GRANTED } else { DECISION_DENIED };
            appmgr::set_perm(admin()?, name, perm as u8, dec)
                .map_err(|e| format!("apps: {} failed ({})", args[0], sys::status(e)))?;
            sh.write(&show::ok_line(&format!("{} {} for {}", if grant { "granted" } else { "revoked" }, perm.as_str(), name)));
            Ok(Vec::new())
        }
        Some("verify") => {
            let Some(path) = args.get(1) else {
                return Err(String::from("apps: usage: apps verify <path>"));
            };
            let abs = normalize(&sh.place, path);
            appmgr::install_check(admin()?, &abs)
                .map_err(|e| format!("apps: {} rejected ({})", abs, sys::status(e)))?;
            sh.write(&show::ok_line(&format!("{} signature valid (Ed25519)", abs)));
            Ok(Vec::new())
        }
        Some(other) => Err(format!("apps: unknown subcommand '{}'", other)),
    }
}

fn parse_install_mode(args: &[String]) -> Result<(u8, bool), String> {
    use libd::install::{MODE_DUAL_BOOT, MODE_WHOLE_DISK, MODE_WIPE_DISK};
    let mut mode = MODE_DUAL_BOOT;
    let mut confirm = false;
    for a in args {
        match a.as_str() {
            "dual" | "dual-boot" => mode = MODE_DUAL_BOOT,
            "whole" | "blank" => mode = MODE_WHOLE_DISK,
            "wipe" | "repartition" => mode = MODE_WIPE_DISK,
            "--confirm" => confirm = true,
            other => {
                return Err(format!(
                    "install: unknown option '{}' (expected dual, whole, wipe, or --confirm)",
                    other
                ));
            }
        }
    }
    Ok((mode, confirm))
}

fn install_cmd(sh: &Shell, args: &[String]) -> Res {
    use libd::install::{self, DiskSummary, MAX_DISKS};
    if sh.storaged_admin == 0 {
        return Err(String::from("install: no storaged.admin grant in this session"));
    }
    match args.first().map(String::as_str) {
        None | Some("disks" | "list") => {
            let mut disks = [DiskSummary::default(); MAX_DISKS];
            let n = install::list_disks(sh.storaged_admin, &mut disks)
                .map_err(|e| format!("install: list disks failed ({})", sys::status(e)))?;
            let mut rs = Vec::new();
            for d in &disks[..n] {
                let table = if d.is_blank() {
                    "blank"
                } else if d.has_gpt() {
                    "gpt"
                } else if d.has_mbr() {
                    "mbr"
                } else {
                    "unknown"
                };
                let mut flags = Vec::new();
                if d.is_live_boot() {
                    flags.push("live");
                }
                if d.is_optical() {
                    flags.push("optical");
                }
                if d.has_esp() {
                    flags.push("esp");
                }
                rs.push(
                    Record::new()
                        .with("disk", Value::Text(String::from(d.name_str())))
                        .with("model", Value::Text(String::from(d.model_str())))
                        .with("size", Value::Size(d.sectors * 512))
                        .with("table", text(table))
                        .with("parts", Value::Int(i64::from(d.part_count)))
                        .with("free_mib", Value::Int(i64::from(d.largest_free_mib)))
                        .with("flags", Value::Text(flags.join(","))),
                );
            }
            Ok(rs)
        }
        Some("parts") => {
            let Some(target) = args.get(1) else {
                return Err(String::from("install: usage: install parts <disk>"));
            };
            let mut disks = [DiskSummary::default(); MAX_DISKS];
            let n = install::list_disks(sh.storaged_admin, &mut disks)
                .map_err(|e| format!("install: list disks failed ({})", sys::status(e)))?;
            let Some(d) = disks[..n].iter().find(|d| d.name_str() == target) else {
                return Err(format!("install: disk '{}' not found", target));
            };
            let mut rs = Vec::new();
            for p in d.parts_slice() {
                rs.push(
                    Record::new()
                        .with("index", Value::Int(i64::from(p.index)))
                        .with("name", Value::Text(String::from(p.name_str())))
                        .with("fs", Value::Text(String::from(p.fs_str())))
                        .with("size_mib", Value::Int(i64::from(p.size_mib)))
                        .with("first", Value::Int(p.first as i64))
                        .with("last", Value::Int(p.last as i64)),
                );
            }
            Ok(rs)
        }
        Some("plan") => {
            let Some(target) = args.get(1) else {
                return Err(String::from("install: usage: install plan <disk> [dual|whole|wipe [--confirm]]"));
            };
            let (mode, confirm) = parse_install_mode(&args[2..])?;
            let mut out = alloc::vec![0u8; 4096];
            match install::plan(sh.storaged_admin, target, mode, confirm, &mut out) {
                Ok(n) => {
                    let s = String::from_utf8_lossy(&out[..n]).into_owned();
                    sh.write(&format!("{}\n", s));
                    Ok(Vec::new())
                }
                Err((e, n)) => {
                    if n > 0 {
                        Err(format!("install: {}", String::from_utf8_lossy(&out[..n])))
                    } else {
                        Err(format!("install: plan failed ({})", sys::status(e)))
                    }
                }
            }
        }
        Some("delete-part") => {
            let (Some(target), Some(idx_s)) = (args.get(1), args.get(2)) else {
                return Err(String::from("install: usage: install delete-part <disk> <index> --confirm"));
            };
            let idx = idx_s
                .parse::<u32>()
                .map_err(|_| format!("install: invalid partition index '{}'", idx_s))?;
            let confirm = args.get(3).is_some_and(|a| a == "--confirm");
            let mut out = alloc::vec![0u8; 4096];
            match install::delete_part(sh.storaged_admin, target, idx, confirm, &mut out) {
                Ok(n) => {
                    let s = String::from_utf8_lossy(&out[..n]).into_owned();
                    libd::println!("shell: install delete-part: {}", s);
                    sh.write(&show::ok_line(&s));
                    Ok(Vec::new())
                }
                Err((e, n)) => {
                    if n > 0 {
                        let s = String::from_utf8_lossy(&out[..n]).into_owned();
                        libd::println!("shell: install delete-part refused: {}", s);
                        Err(format!("install: {}", s))
                    } else {
                        Err(format!("install: delete-part failed ({})", sys::status(e)))
                    }
                }
            }
        }
        Some("run") => {
            let Some(target) = args.get(1) else {
                return Err(String::from("install: usage: install run <disk> [dual|whole|wipe [--confirm]]"));
            };
            let (mode, confirm) = parse_install_mode(&args[2..])?;
            let mut out = alloc::vec![0u8; 4096];
            match install::execute(sh.storaged_admin, target, mode, confirm, &mut out) {
                Ok(n) => {
                    let s = String::from_utf8_lossy(&out[..n]).into_owned();
                    libd::println!("shell: install ok: {}", s);
                    sh.write(&show::ok_line(&s));
                    Ok(Vec::new())
                }
                Err((e, n)) => {
                    if n > 0 {
                        let s = String::from_utf8_lossy(&out[..n]).into_owned();
                        libd::println!("shell: install refused: {}", s);
                        Err(format!("install: {}", s))
                    } else {
                        Err(format!("install: failed ({})", sys::status(e)))
                    }
                }
            }
        }
        Some(other) => Err(format!("install: unknown subcommand '{}'", other)),
    }
}

fn setup_cmd(sh: &Shell, args: &[String]) -> Res {
    use dosid::{KEYBOARDS, LANGUAGES, OobeConfig, TIMEZONES};
    match args.first().map(String::as_str) {
        None | Some("status") => {
            if !sh.has_home_volume() {
                sh.write(&show::ok_line("live media (no dedicated /home volume; first-boot setup runs on installed disks)"));
                return Ok(Vec::new());
            }
            let cfg = sh
                .home_dot_dos_read(b"oobe.toml")
                .and_then(|b| OobeConfig::from_toml(&b).ok())
                .unwrap_or_default();
            Ok(alloc::vec![
                Record::new()
                    .with("completed", text(if cfg.completed { "yes" } else { "no" }))
                    .with("skipped", text(if cfg.skipped { "yes" } else { "no" }))
                    .with("language", Value::Text(cfg.language))
                    .with("keyboard", Value::Text(cfg.keyboard))
                    .with("timezone", Value::Text(cfg.timezone))
                    .with("network", Value::Text(cfg.net_mode)),
            ])
        }
        Some("skip") => {
            let mut cfg = sh
                .home_dot_dos_read(b"oobe.toml")
                .and_then(|b| OobeConfig::from_toml(&b).ok())
                .unwrap_or_default();
            cfg.completed = true;
            cfg.skipped = true;
            sh.home_dot_dos_write(b"oobe.toml", cfg.to_toml().as_bytes())?;
            libd::println!("setup: first-boot setup skipped and persisted");
            sh.write(&show::ok_line("first-boot setup skipped and persisted to /home/.dos/oobe.toml"));
            Ok(Vec::new())
        }
        Some("complete") => {
            let lang = args.get(1).map_or("en-US", String::as_str);
            let kbd = args.get(2).map_or("us", String::as_str);
            let tz = args.get(3).map_or("UTC", String::as_str);
            let net_mode = args.get(4).map_or("skip", String::as_str);
            if !LANGUAGES.iter().any(|(c, _)| *c == lang) {
                return Err(format!("setup: unsupported language '{}'", lang));
            }
            if !KEYBOARDS.iter().any(|(c, _)| *c == kbd) {
                return Err(format!("setup: unsupported keyboard '{}'", kbd));
            }
            if !TIMEZONES.iter().any(|(z, _)| *z == tz) {
                return Err(format!("setup: unsupported timezone '{}'", tz));
            }
            if !matches!(net_mode, "skip" | "dhcp" | "static") {
                return Err(format!("setup: unsupported network mode '{}' (skip|dhcp|static)", net_mode));
            }
            let cfg = OobeConfig {
                completed: true,
                skipped: false,
                language: String::from(lang),
                keyboard: String::from(kbd),
                timezone: String::from(tz),
                net_mode: String::from(net_mode),
                ..OobeConfig::default()
            };
            sh.home_dot_dos_write(b"oobe.toml", cfg.to_toml().as_bytes())?;
            if sh.awmi_admin != 0 {
                let lang_id = dosid::Language::from_code(lang).id();
                let kbd_id = dosid::KeyboardLayout::from_code(kbd).id();
                let tz_min = dosid::timezone_offset_minutes(tz) as i16;
                let _ = libd::awmi::set_locale(sh.awmi_admin, lang_id, kbd_id, tz_min);
            }
            libd::println!("setup: first-boot setup completed (lang={}, kbd={}, tz={}, net={})", lang, kbd, tz, net_mode);
            sh.write(&show::ok_line(&format!(
                "first-boot setup completed (lang={}, kbd={}, tz={}, net={})",
                lang, kbd, tz, net_mode
            )));
            Ok(Vec::new())
        }
        Some(other) => Err(format!("setup: unknown subcommand '{}' (expected status, skip, or complete)", other)),
    }
}
