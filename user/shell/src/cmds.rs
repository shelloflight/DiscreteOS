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
    Builtin { name: "go", aliases: &["cd"], usage: "go [place]", description: "change the current place (no place: the list of places)" },
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
    Builtin { name: "net", aliases: &["ip"], usage: "net", description: "network interface, IP address, gateway, DNS and counters" },
    Builtin { name: "ping", aliases: &[], usage: "ping <host> [count]", description: "send ICMP echo requests to a host" },
    Builtin { name: "tls", aliases: &[], usage: "tls <host> [port]", description: "verify a TLS 1.3 connection using the system root CAs" },
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
        "ping" | "tls" => 2,
        "audio" => 3,
        _ => 0,
    };
    if args.len() > max_args {
        return Some(Err(format!("{}: too many arguments; usage: {}", b.name, b.usage)));
    }
    let arg = args.first().map(String::as_str);
    Some(match b.name {
        "help" => help(sh, arg),
        "go" => go(sh, arg.unwrap_or("/")),
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
        "net" => net_cmd(sh),
        "ping" => ping_cmd(sh, args),
        "tls" => tls_cmd(sh, args),
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
    let state = if st.dhcp_bound {
        "up (dhcp)"
    } else if st.link_up {
        "link up (acquiring dhcp)"
    } else {
        "down"
    };
    Ok(alloc::vec![
        Record::new()
            .with("interface", Value::Text(String::from(st.name_str())))
            .with("state", text(state))
            .with("ip", Value::Text(fmt_ip(st.ip)))
            .with("gateway", Value::Text(fmt_ip(st.gateway)))
            .with("dns", Value::Text(fmt_ip(st.dns)))
            .with("mac", Value::Text(mac))
            .with("rx", Value::Int(st.rx_packets as i64))
            .with("tx", Value::Int(st.tx_packets as i64)),
    ])
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
