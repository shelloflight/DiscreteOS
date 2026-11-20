//! D-OS service manifests (`.dman`). Reference: docs/services.md.
//!
//! A manifest says what one service is (`name`, `image`, `args`), when it starts (`group`,
//! `after`), what it offers others (`[provides]`), every capability it gets (`[grants]`), its
//! limits (`[quota]`) and what happens when it ends (`[restart]`). The service manager gives a
//! service exactly what its manifest grants and nothing else; anything this module does not know
//! refuses the whole manifest (fail closed), and the error names the line and the key.
//!
//! ```toml
//! name = "devmgr"
//! image = "devmgr.dx"
//! group = "system"
//! after = ["storaged"]
//!
//! [grants]
//! log = true
//! devices = ["all"]
//! programs = ["*.ddrv"]
//! connect = ["storaged.disks"]
//!
//! [quota]
//! memory = "96M"
//! handles = 2048
//! threads = 48
//!
//! [restart]
//! policy = "always"
//! limit = 3
//! backoff = 100
//! ```

#![no_std]

extern crate alloc;

pub mod tool;
pub mod toml;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use toml::Error;
use toml::{Entry, Value, err};

/// Longest service, endpoint or volume name.
pub const MAX_NAME: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// Started at boot.
    System,
    /// Started only by the service manager's test run.
    Test,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Restart whenever it ends.
    Always,
    /// Restart unless it exited with code 0.
    OnFailure,
    /// Never restart.
    Never,
}

/// Devices a service may get, by kind and class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceSel {
    All,
    /// Every PCI function (`pci`).
    AllPci,
    /// A PCI class, optionally narrowed to a subclass and programming interface.
    Pci { class: u8, sub: Option<u8>, prog: Option<u8> },
    /// A platform device by name (e.g. `ps2`).
    Platform(String),
}

impl DeviceSel {
    /// `pci`: a PCI function with (class, subclass, programming interface); otherwise a platform
    /// device named `name`.
    pub fn matches(&self, pci: bool, class: u8, sub: u8, prog: u8, name: &str) -> bool {
        match self {
            DeviceSel::All => true,
            DeviceSel::AllPci => pci,
            DeviceSel::Pci { class: c, sub: s, prog: p } => {
                pci && *c == class && s.is_none_or(|s| s == sub) && p.is_none_or(|p| p == prog)
            }
            DeviceSel::Platform(n) => !pci && n == name,
        }
    }
}

/// Rights on a granted directory (the file protocol's R_READ, R_WRITE, R_ADMIN bits).
pub const NS_READ: u8 = 1;
pub const NS_WRITE: u8 = 2;
pub const NS_ADMIN: u8 = 4;

/// A volume (or the whole of it) placed in the service's namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NsGrant {
    /// Where the service sees it, e.g. `/system`; `*` with volume `*`: every volume, each at
    /// `/<volume>`, with at most the rights the volume has.
    pub path: String,
    /// The volume's name, as the storage service announces it.
    pub volume: String,
    pub rights: u8,
}

/// A connection to another service's endpoint (`service.endpoint`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connect {
    pub service: String,
    pub endpoint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    pub memory: u64,
    pub handles: u64,
    pub threads: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restart {
    pub policy: Policy,
    /// Restarts before the manager gives up.
    pub limit: u32,
    /// Milliseconds before the first restart; doubled for each further one (at most 10 s).
    pub backoff_ms: u64,
}

impl Restart {
    /// The delay before restart number `n` (1-based).
    pub fn delay_ms(&self, n: u32) -> u64 {
        let shift = n.saturating_sub(1).min(16);
        (self.backoff_ms << shift).min(10_000)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub image: String,
    pub args: String,
    pub description: String,
    pub group: Group,
    pub after: Vec<String>,
    /// Lowest level of this service's log records the log service keeps (`LEVEL_*`).
    pub log_level: u8,
    // [provides]
    pub endpoints: Vec<String>,
    pub volumes: bool,
    // [grants]
    pub log: bool,
    pub devices: Vec<DeviceSel>,
    pub programs: Vec<String>,
    pub connect: Vec<Connect>,
    pub namespace: Vec<NsGrant>,
    pub vmex: bool,
    pub power: bool,
    /// The kernel log reader (the log service).
    pub kernel_log: bool,
    /// The boot-time record (wall clock captured by the loader; the clock service).
    pub boot_time: bool,
    /// A channel to the service manager (`grants.manager`): list, stop and restart services.
    pub manage_services: bool,
    /// ... and switch the machine off or restart it (a clean shutdown first).
    pub manage_power: bool,
    /// The tool manifests and the tools' program images (the shell).
    pub tools: bool,
    /// Audio capabilities (`grants.audio`: `playback`, `capture`, `control`).
    pub audio_playback: bool,
    pub audio_capture: bool,
    pub audio_control: bool,
    /// Network capabilities (`grants.net`: `client`, `icmp`, `control`).
    pub net_client: bool,
    pub net_icmp: bool,
    pub net_control: bool,
    /// GPU & display capabilities (`grants.gpu`: `query`, `display`, `render`).
    pub gpu_query: bool,
    pub gpu_display: bool,
    pub gpu_render: bool,
    pub quota: Quota,
    pub restart: Restart,
}

/// Log levels (the kernel's: 0 error .. 3 debug).
pub const LEVEL_ERROR: u8 = 0;
pub const LEVEL_WARN: u8 = 1;
pub const LEVEL_INFO: u8 = 2;
pub const LEVEL_DEBUG: u8 = 3;

pub const DEFAULT_QUOTA: Quota = Quota { memory: 32 << 20, handles: 512, threads: 16 };
pub const DEFAULT_RESTART: Restart = Restart { policy: Policy::OnFailure, limit: 3, backoff_ms: 100 };

/// A service, endpoint or volume name: 1..=24 of `a-z 0-9 -`, starting with a letter.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= MAX_NAME && b[0].is_ascii_lowercase() && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// A program file name: a valid name, then `.dx`, `.dsvc`, or `.ddrv`.
pub fn valid_program(s: &str) -> bool {
    match s.rsplit_once('.') {
        Some((n, "dx" | "dsvc" | "ddrv")) => valid_name(n),
        _ => false,
    }
}

/// Does program `name` match `pattern` (an exact program name, or `*.ext`)?
pub fn program_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_prefix('*') {
        Some(ext) => name.ends_with(ext) && name.len() > ext.len(),
        None => pattern == name,
    }
}

fn parse_size(s: &str) -> Option<u64> {
    let (num, mul) = match s.as_bytes().last()? {
        b'K' => (&s[..s.len() - 1], 1u64 << 10),
        b'M' => (&s[..s.len() - 1], 1 << 20),
        b'G' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    if num.is_empty() || num.len() > 12 || !num.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    num.parse::<u64>().ok()?.checked_mul(mul)
}

fn parse_device(s: &str) -> Option<DeviceSel> {
    if s == "all" {
        return Some(DeviceSel::All);
    }
    if s == "pci" {
        return Some(DeviceSel::AllPci);
    }
    if let Some(n) = s.strip_prefix("platform:") {
        return valid_name(n).then(|| DeviceSel::Platform(n.to_string()));
    }
    let hex = s.strip_prefix("pci:")?;
    if !matches!(hex.len(), 2 | 4 | 6) || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    Some(DeviceSel::Pci { class: byte(0)?, sub: if hex.len() >= 4 { byte(2) } else { None }, prog: if hex.len() == 6 { byte(4) } else { None } })
}

fn parse_ns(s: &str) -> Option<NsGrant> {
    if let Some(r) = s.strip_prefix('*') {
        let rights = match r {
            "" | ":rw" => NS_READ | NS_WRITE,
            ":r" => NS_READ,
            _ => return None,
        };
        return Some(NsGrant { path: "*".to_string(), volume: "*".to_string(), rights });
    }
    let (path, rest) = s.split_once('=')?;
    let (volume, rights) = rest.split_once(':')?;
    let p = path.strip_prefix('/')?;
    if !valid_name(p) || !valid_name(volume) {
        return None;
    }
    let rights = match rights {
        "r" => NS_READ,
        "rw" => NS_READ | NS_WRITE,
        "rwa" => NS_READ | NS_WRITE | NS_ADMIN,
        _ => return None,
    };
    Some(NsGrant { path: path.to_string(), volume: volume.to_string(), rights })
}

fn parse_connect(s: &str) -> Option<Connect> {
    let (service, endpoint) = s.split_once('.')?;
    (valid_name(service) && valid_name(endpoint)).then(|| Connect { service: service.to_string(), endpoint: endpoint.to_string() })
}

/// What each key must hold, so one table of keys drives both the type check and the error text.
#[derive(Clone, Copy)]
enum Want {
    Str,
    Bool,
    Int,
    Strings,
    Size,
}

const KEYS: &[(&str, &str, Want)] = &[
    ("", "name", Want::Str),
    ("", "image", Want::Str),
    ("", "args", Want::Str),
    ("", "description", Want::Str),
    ("", "group", Want::Str),
    ("", "after", Want::Strings),
    ("", "log-level", Want::Str),
    ("provides", "endpoints", Want::Strings),
    ("provides", "volumes", Want::Bool),
    ("grants", "log", Want::Bool),
    ("grants", "devices", Want::Strings),
    ("grants", "programs", Want::Strings),
    ("grants", "connect", Want::Strings),
    ("grants", "namespace", Want::Strings),
    ("grants", "vmex", Want::Bool),
    ("grants", "power", Want::Bool),
    ("grants", "kernel-log", Want::Bool),
    ("grants", "boot-time", Want::Bool),
    ("grants", "manager", Want::Strings),
    ("grants", "tools", Want::Bool),
    ("grants", "audio", Want::Strings),
    ("grants", "net", Want::Strings),
    ("grants", "gpu", Want::Strings),
    ("quota", "memory", Want::Size),
    ("quota", "handles", Want::Int),
    ("quota", "threads", Want::Int),
    ("restart", "policy", Want::Str),
    ("restart", "limit", Want::Int),
    ("restart", "backoff", Want::Int),
];

fn full_key(e: &Entry) -> String {
    if e.table.is_empty() { e.key.clone() } else { format!("{}.{}", e.table, e.key) }
}

fn strings(e: &Entry) -> Result<Vec<String>, Error> {
    let Value::Array(a) = &e.value else { return Err(err(e.line, format!("'{}' must be an array of strings", full_key(e)))) };
    a.iter()
        .map(|v| match v {
            Value::Str(s) => Ok(s.clone()),
            _ => Err(err(e.line, format!("'{}' must be an array of strings", full_key(e)))),
        })
        .collect()
}

/// Read a manifest. Every key is checked against the schema; the first problem refuses it.
pub fn parse(src: &[u8]) -> Result<Manifest, Error> {
    let doc = toml::parse(src)?;
    if let Some((t, line)) = doc.tables.iter().find(|(t, _)| !KEYS.iter().any(|(k, _, _)| k == t) || t.is_empty()) {
        return Err(err(*line, format!("unknown table [{}]", t)));
    }
    let entries = doc.entries;
    let mut m = Manifest {
        name: String::new(),
        image: String::new(),
        args: String::new(),
        description: String::new(),
        group: Group::System,
        after: Vec::new(),
        log_level: LEVEL_INFO,
        endpoints: Vec::new(),
        volumes: false,
        log: false,
        devices: Vec::new(),
        programs: Vec::new(),
        connect: Vec::new(),
        namespace: Vec::new(),
        vmex: false,
        power: false,
        kernel_log: false,
        boot_time: false,
        manage_services: false,
        manage_power: false,
        tools: false,
        audio_playback: false,
        audio_capture: false,
        audio_control: false,
        net_client: false,
        net_icmp: false,
        net_control: false,
        gpu_query: false,
        gpu_display: false,
        gpu_render: false,
        quota: DEFAULT_QUOTA,
        restart: DEFAULT_RESTART,
    };
    let mut have_group = false;
    for e in &entries {
        let fk = full_key(e);
        let Some(&(_, _, want)) = KEYS.iter().find(|(t, k, _)| *t == e.table && *k == e.key) else {
            let known_table = KEYS.iter().any(|(t, _, _)| *t == e.table);
            return Err(err(e.line, if known_table { format!("unknown key '{}'", fk) } else { format!("unknown table [{}]", e.table) }));
        };
        let bad = |what: &str| err(e.line, format!("'{}' must be {}", fk, what));
        let line = e.line;
        let invalid = |why: &str, v: &str| err(line, format!("'{}': {} '{}'", fk, why, v));
        match (want, &e.value) {
            (Want::Str, Value::Str(s)) => match e.key.as_str() {
                "name" if !valid_name(s) => return Err(invalid("not a valid name (a-z 0-9 -, at most 24)", s)),
                "name" => m.name = s.clone(),
                "image" if !valid_program(s) => return Err(invalid("not a program name (<name>.dx, <name>.dsvc or <name>.ddrv)", s)),
                "image" => m.image = s.clone(),
                "args" => m.args = s.clone(),
                "description" => m.description = s.clone(),
                "log-level" => {
                    m.log_level = match s.as_str() {
                        "error" => LEVEL_ERROR,
                        "warn" => LEVEL_WARN,
                        "info" => LEVEL_INFO,
                        "debug" => LEVEL_DEBUG,
                        _ => return Err(invalid("unknown level (error, warn, info, debug)", s)),
                    }
                }
                "group" => {
                    m.group = match s.as_str() {
                        "system" => Group::System,
                        "test" => Group::Test,
                        _ => return Err(invalid("unknown group (system, test)", s)),
                    };
                    have_group = true;
                }
                "policy" => {
                    m.restart.policy = match s.as_str() {
                        "always" => Policy::Always,
                        "on-failure" => Policy::OnFailure,
                        "never" => Policy::Never,
                        _ => return Err(invalid("unknown policy (always, on-failure, never)", s)),
                    }
                }
                _ => return Err(bad("known")),
            },
            (Want::Str, v) => return Err(bad(&format!("a string, not {}", v.type_name()))),
            (Want::Bool, Value::Bool(b)) => match fk.as_str() {
                "provides.volumes" => m.volumes = *b,
                "grants.log" => m.log = *b,
                "grants.vmex" => m.vmex = *b,
                "grants.power" => m.power = *b,
                "grants.kernel-log" => m.kernel_log = *b,
                "grants.boot-time" => m.boot_time = *b,
                "grants.tools" => m.tools = *b,
                _ => return Err(bad("known")),
            },
            (Want::Bool, v) => return Err(bad(&format!("true or false, not {}", v.type_name()))),
            (Want::Int, Value::Int(n)) => {
                let n = *n;
                let range = |lo: u64, hi: u64| if (lo..=hi).contains(&n) { Ok(n) } else { Err(err(e.line, format!("'{}' must be between {} and {}", fk, lo, hi))) };
                match fk.as_str() {
                    "quota.handles" => m.quota.handles = range(16, 4096)?,
                    "quota.threads" => m.quota.threads = range(1, 256)?,
                    "restart.limit" => m.restart.limit = range(0, 100)? as u32,
                    "restart.backoff" => m.restart.backoff_ms = range(10, 60_000)?,
                    _ => return Err(bad("known")),
                }
            }
            (Want::Int, v) => return Err(bad(&format!("an integer, not {}", v.type_name()))),
            (Want::Size, Value::Str(s)) => {
                let v = parse_size(s).ok_or_else(|| invalid("not a size (bytes, or a number with K, M or G)", s))?;
                if !(64 << 10..=1 << 30).contains(&v) {
                    return Err(err(e.line, format!("'{}' must be between 64K and 1G", fk)));
                }
                m.quota.memory = v;
            }
            (Want::Size, Value::Int(v)) => {
                if !(64 << 10..=1 << 30).contains(v) {
                    return Err(err(e.line, format!("'{}' must be between 64K and 1G", fk)));
                }
                m.quota.memory = *v;
            }
            (Want::Size, v) => return Err(bad(&format!("a size such as \"32M\", not {}", v.type_name()))),
            (Want::Strings, _) => {
                let list = strings(e)?;
                let mut seen: Vec<&str> = Vec::new();
                for s in &list {
                    if seen.contains(&s.as_str()) {
                        return Err(invalid("listed twice:", s));
                    }
                    seen.push(s);
                }
                match fk.as_str() {
                    "after" => {
                        if let Some(s) = list.iter().find(|s| !valid_name(s)) {
                            return Err(invalid("not a service name", s));
                        }
                        m.after = list;
                    }
                    "provides.endpoints" => {
                        if let Some(s) = list.iter().find(|s| !valid_name(s)) {
                            return Err(invalid("not an endpoint name", s));
                        }
                        m.endpoints = list;
                    }
                    "grants.devices" => {
                        for s in &list {
                            m.devices.push(parse_device(s).ok_or_else(|| invalid("not a device selector (all, pci, pci:CC[SS[PP]], platform:<name>)", s))?);
                        }
                    }
                    "grants.programs" => {
                        for s in &list {
                            let ok = match s.strip_prefix("*.") {
                                Some(ext) => matches!(ext, "dx" | "dsvc" | "ddrv"),
                                None => valid_program(s),
                            };
                            if !ok {
                                return Err(invalid("not a program name or pattern (<name>.dx, <name>.dsvc, *.ddrv)", s));
                            }
                        }
                        m.programs = list;
                    }
                    "grants.connect" => {
                        for s in &list {
                            let c = parse_connect(s).ok_or_else(|| invalid("not an endpoint (<service>.<endpoint>)", s))?;
                            if !m.connect.contains(&c) {
                                m.connect.push(c);
                            }
                        }
                    }
                    "grants.namespace" => {
                        for s in &list {
                            let g = parse_ns(s).ok_or_else(|| invalid("not a namespace entry (/<path>=<volume>:r|rw|rwa, or * / *:r for every volume)", s))?;
                            if m.namespace.iter().any(|x| x.path == g.path) {
                                return Err(invalid("path granted twice:", &g.path));
                            }
                            m.namespace.push(g);
                        }
                        if m.namespace.len() > 1 && m.namespace.iter().any(|g| g.path == "*") {
                            return Err(err(e.line, format!("'{}': '*' (every volume) must be the only entry", fk)));
                        }
                    }
                    "grants.manager" => {
                        for s in &list {
                            match s.as_str() {
                                "services" => m.manage_services = true,
                                "power" => m.manage_power = true,
                                _ => return Err(invalid("unknown manager right (services, power)", s)),
                            }
                        }
                    }
                    "grants.audio" => {
                        for s in &list {
                            let ep = match s.as_str() {
                                "playback" => {
                                    m.audio_playback = true;
                                    "playback"
                                }
                                "capture" => {
                                    m.audio_capture = true;
                                    "capture"
                                }
                                "control" => {
                                    m.audio_control = true;
                                    "control"
                                }
                                _ => return Err(invalid("unknown audio right (playback, capture, control)", s)),
                            };
                            let c = Connect { service: "audio".to_string(), endpoint: ep.to_string() };
                            if !m.connect.contains(&c) {
                                m.connect.push(c);
                            }
                        }
                    }
                    "grants.net" => {
                        for s in &list {
                            let ep = match s.as_str() {
                                "client" => {
                                    m.net_client = true;
                                    "client"
                                }
                                "icmp" => {
                                    m.net_icmp = true;
                                    "icmp"
                                }
                                "control" => {
                                    m.net_control = true;
                                    "control"
                                }
                                _ => return Err(invalid("unknown net right (client, icmp, control)", s)),
                            };
                            let c = Connect { service: "net".to_string(), endpoint: ep.to_string() };
                            if !m.connect.contains(&c) {
                                m.connect.push(c);
                            }
                        }
                    }
                    "grants.gpu" => {
                        for s in &list {
                            let ep = match s.as_str() {
                                "query" => {
                                    m.gpu_query = true;
                                    "query"
                                }
                                "display" => {
                                    m.gpu_display = true;
                                    "display"
                                }
                                "render" => {
                                    m.gpu_render = true;
                                    "render"
                                }
                                _ => return Err(invalid("unknown gpu right (query, display, render)", s)),
                            };
                            let c = Connect { service: "gpu".to_string(), endpoint: ep.to_string() };
                            if !m.connect.contains(&c) {
                                m.connect.push(c);
                            }
                        }
                    }
                    _ => return Err(bad("known")),
                }
            }
        }
    }
    if m.name.is_empty() {
        return Err(err(0, "missing 'name'"));
    }
    if m.image.is_empty() {
        return Err(err(0, "missing 'image'"));
    }
    if !have_group {
        return Err(err(0, "missing 'group' (system or test)"));
    }
    if m.after.contains(&m.name) || m.connect.iter().any(|c| c.service == m.name) {
        return Err(err(0, "a service cannot depend on or connect to itself"));
    }
    if m.connect.len() > 16 || m.namespace.len() > 16 || m.endpoints.len() > 16 || m.devices.len() > 16 || m.programs.len() > 16 {
        return Err(err(0, "more than 16 entries in one grant"));
    }
    Ok(m)
}

/// A one-line summary of the grants (log lines, the measurement text's detail).
pub fn summary(m: &Manifest) -> String {
    let mut s = String::new();
    let mut add = |part: &str| {
        if !s.is_empty() {
            s.push_str(", ");
        }
        s.push_str(part);
    };
    if m.log {
        add("log");
    }
    if !m.devices.is_empty() {
        add(&format!("{} device selector(s)", m.devices.len()));
    }
    if !m.programs.is_empty() {
        add(&format!("programs {}", m.programs.join(" ")));
    }
    for c in &m.connect {
        add(&format!("{}.{}", c.service, c.endpoint));
    }
    for n in &m.namespace {
        if n.path == "*" {
            add("every volume");
        } else {
            add(&format!("{}={}", n.path, n.volume));
        }
    }
    if m.vmex {
        add("VMEX");
    }
    if m.power {
        add("POWER");
    }
    if m.kernel_log {
        add("kernel log");
    }
    if m.boot_time {
        add("boot time");
    }
    if m.manage_services || m.manage_power {
        add(&format!("manager ({}{}{})", if m.manage_services { "services" } else { "" }, if m.manage_services && m.manage_power { ", " } else { "" }, if m.manage_power { "power" } else { "" }));
    }
    if m.tools {
        add("tools");
    }
    if m.audio_playback || m.audio_capture || m.audio_control {
        let mut parts: Vec<&str> = Vec::new();
        if m.audio_playback {
            parts.push("playback");
        }
        if m.audio_capture {
            parts.push("capture");
        }
        if m.audio_control {
            parts.push("control");
        }
        add(&format!("audio ({})", parts.join(", ")));
    }
    if m.net_client || m.net_icmp || m.net_control {
        let mut parts: Vec<&str> = Vec::new();
        if m.net_client {
            parts.push("client");
        }
        if m.net_icmp {
            parts.push("icmp");
        }
        if m.net_control {
            parts.push("control");
        }
        add(&format!("net ({})", parts.join(", ")));
    }
    if m.gpu_query || m.gpu_display || m.gpu_render {
        let mut parts: Vec<&str> = Vec::new();
        if m.gpu_query {
            parts.push("query");
        }
        if m.gpu_display {
            parts.push("display");
        }
        if m.gpu_render {
            parts.push("render");
        }
        add(&format!("gpu ({})", parts.join(", ")));
    }
    if s.is_empty() {
        s.push_str("nothing");
    }
    s
}
