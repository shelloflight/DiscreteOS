//! The service manager (docs/services.md).
//!
//! - **Manifests** come from two places only: embedded in the verified kernel image (startup tag
//!   MANIFEST) or a volume's `DOS/SERVICES` directory with a valid `.dsig` of kind manifest by
//!   the D-OS key (checked by the kernel, `vmo_verify`). Each is parsed strictly (`dman`), then
//!   checked against the others: the image must be an embedded program, every `after` a known
//!   service, every endpoint it connects to provided by one. Every decision (accept or refuse) is
//!   measured into PCR 10 (`measure`), so an attestation shows what was granted.
//! - **Exact grants**: a service gets the handles its manifest names and nothing else: the log,
//!   devices by class, program images by name, VMEX, POWER, directories of volumes (narrowed to
//!   the rights granted) and channels to other services' endpoints; plus its control channel to
//!   the manager. Its quota is the manifest's.
//! - **Supervision**: services start in dependency order (`after`, endpoints, volumes). When one
//!   ends it is restarted per its policy, after a delay that doubles each time, up to its limit;
//!   then the manager gives up and says so. A restarted provider is linked to its running clients
//!   again (both get a new channel); a restarted client gets fresh endpoints at its start.
//! - **Shutdown**: services stop in the reverse order of their start (SHUTDOWN, then a deadline).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use dman::{Group, Manifest, Policy};
use doscrypt::sha2::sha256;
use libd::fs::{self as fp, NsBuilder, Node};
use libd::handle::Owned;
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle, MsgHandle, SpawnHandle};
use libd::{Port, println, svc};

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;
const KEY_PROC: u64 = 1;
const KEY_CTL: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Accepted, waiting for what it depends on.
    Waiting,
    Running,
    /// Ended; restarts at this time (clock_ns).
    Backoff(u64),
    /// Ended for good with this exit code (policy, or a one-shot service done).
    Done(i64),
    /// Restarted `limit` times and ended again.
    GaveUp,
    /// Could not be started (a grant could not be made); see the log.
    Failed,
}

pub struct Service {
    pub m: Manifest,
    /// Where the manifest came from (log lines), its SHA-256, and whether the decision to accept
    /// it is in the measurement log yet (after the set's cross-checks).
    pub source: String,
    digest: [u8; 32],
    measured: bool,
    pub state: State,
    pub proc: Owned,
    /// The manager's end of the service's control channel.
    pub ctl: Owned,
    pub starts: u32,
    pub restarts: u32,
    pub last_code: i64,
    /// Arguments replacing the manifest's (test modes: `storage test` runs storaged with `test`).
    pub args: Option<String>,
}

/// A volume a provider announced: name and a channel to its root with every right.
pub struct Volume {
    pub name: String,
    pub root: Node,
}

pub struct Mgr {
    pub svcs: Vec<Service>,
    port: Port,
    pub volumes: Vec<Volume>,
    pub volumes_done: bool,
    /// Start order (indices), for shutdown in reverse.
    order: Vec<usize>,
    /// Connections whose provider is not in the set (`devmgr test`): skipped instead of refused.
    pub standalone: bool,
    pub refused: u32,
}

fn startup(tag: u32) -> Handle {
    libd::startup_handle(tag)
}

fn dup(h: Handle) -> Option<Handle> {
    if h == 0 { None } else { sys::handle_duplicate(h, sys::RIGHTS_SAME).ok() }
}

fn exit_text(code: i64) -> &'static str {
    match code as i32 {
        sys::EXIT_KILLED => " (KILLED)",
        sys::EXIT_FAULT => " (FAULT)",
        _ => "",
    }
}

/// The name of a startup VMO (program or manifest).
pub fn object_name(h: Handle) -> String {
    let mut buf = [0u8; 64];
    let n = sys::object_name(h, &mut buf);
    if n <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..(n as usize).min(64)]).into_owned()
}

/// The contents of an embedded manifest's VMO (its size is rounded up to whole pages: the zero
/// bytes after the text are not part of it).
fn vmo_bytes(h: Handle, max: usize) -> Option<Vec<u8>> {
    let size = sys::vmo_size(h).ok()? as usize;
    let mut b = alloc::vec![0u8; size];
    if sys::vmo_read(h, 0, &mut b) != 0 {
        return None;
    }
    while b.last() == Some(&0) {
        b.pop();
    }
    (b.len() <= max).then_some(b)
}

/// Record a decision in PCR 10 (`svc <text>` in the measurement log).
fn measure(digest: &[u8; 32], text: &str) {
    let r = startup(sys::TAG_MEASURE);
    let t: Vec<u8> = text.bytes().map(|c| if (b' '..=b'~').contains(&c) { c } else { b'?' }).take(sys::MEASURE_TEXT).collect();
    if r == 0 || sys::measure(r, digest, &t) < 0 {
        println!("init: could not measure '{}'", text);
    }
}

impl Mgr {
    pub fn new() -> Result<Mgr, &'static str> {
        Ok(Mgr {
            svcs: Vec::new(),
            port: Port::new(256).map_err(|_| "cannot create a port")?,
            volumes: Vec::new(),
            volumes_done: false,
            order: Vec::new(),
            standalone: false,
            refused: 0,
        })
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        self.svcs.iter().position(|s| s.m.name == name)
    }

    fn refuse(&mut self, source: &str, digest: &[u8; 32], why: &str) {
        println!("init: manifest {} refused: {}", source, why);
        measure(digest, &format!("refuse {}", source));
        self.refused += 1;
    }

    /// Parse and check one manifest; on success it joins the set (Waiting) and is measured.
    pub fn offer(&mut self, source: &str, bytes: &[u8], groups: &[Group]) -> bool {
        let digest = sha256(bytes);
        let m = match dman::parse(bytes) {
            Ok(m) => m,
            Err(e) => {
                self.refuse(source, &digest, &e.to_string());
                return false;
            }
        };
        if !groups.contains(&m.group) {
            return false; // not for this run (e.g. a test service at boot): neither started nor refused
        }
        if self.find(&m.name).is_some() {
            self.refuse(source, &digest, &format!("a service named '{}' already exists", m.name));
            return false;
        }
        if libd::find_program(m.image.as_bytes()).is_none() {
            self.refuse(source, &digest, &format!("image {} is not an embedded program", m.image));
            return false;
        }
        self.svcs.push(Service {
            m,
            source: source.to_string(),
            digest,
            measured: false,
            state: State::Waiting,
            proc: Owned::default(),
            ctl: Owned::default(),
            starts: 0,
            restarts: 0,
            last_code: 0,
            args: None,
        });
        true
    }

    /// The embedded manifests (startup tag MANIFEST), of the given groups.
    pub fn load_embedded(&mut self, groups: &[Group]) {
        let hs: Vec<Handle> = libd::startup_handles().filter(|&(_, t)| t == sys::TAG_MANIFEST).map(|(h, _)| h).collect();
        for h in hs {
            let name = object_name(h);
            match vmo_bytes(h, dman::toml::MAX_SIZE) {
                Some(b) => {
                    self.offer(&name, &b, groups);
                }
                None => self.refuse(&name, &[0; 32], "unreadable or larger than 16 KiB"),
            }
        }
    }

    /// Cross-checks over the whole set: dependencies that exist, endpoints someone provides.
    /// A refused service takes the services needing it along (repeated until nothing changes).
    pub fn check_set(&mut self) {
        loop {
            let mut bad: Option<(usize, String)> = None;
            for (i, s) in self.svcs.iter().enumerate() {
                if s.state != State::Waiting {
                    continue;
                }
                if let Some(d) = s.m.after.iter().find(|d| self.find(d).is_none()) {
                    bad = Some((i, format!("it starts after '{}', which is not a service", d)));
                    break;
                }
                if let Some(c) = s.m.connect.iter().find(|c| !self.svcs.iter().any(|p| p.m.name == c.service && p.m.endpoints.contains(&c.endpoint))) {
                    if self.standalone {
                        continue;
                    }
                    bad = Some((i, format!("it asks for endpoint {}.{}, which no service provides", c.service, c.endpoint)));
                    break;
                }
            }
            let Some((i, why)) = bad else { break };
            let s = self.svcs.remove(i);
            self.refuse(&s.source, &s.digest, &why);
        }
        // What survived is accepted: measured once, with the manifest's hash.
        for k in 0..self.svcs.len() {
            if !self.svcs[k].measured {
                self.svcs[k].measured = true;
                measure(&self.svcs[k].digest, &format!("accept {}", self.svcs[k].m.name));
                for to in 0..self.svcs.len() {
                    if self.svcs[to].m.kernel_log && self.svcs[to].state == State::Running {
                        self.send_level(to, k);
                    }
                }
                println!("init: service {} accepted ({}): {}", self.svcs[k].m.name, self.svcs[k].source, dman::summary(&self.svcs[k].m));
            }
        }
    }

    // ---- starting -------------------------------------------------------------------------------

    fn ready_to_start(&self, i: usize) -> bool {
        let s = &self.svcs[i];
        let dep_ok = |name: &str| self.find(name).is_some_and(|d| matches!(self.svcs[d].state, State::Running | State::Done(_)));
        s.m.after.iter().all(|d| dep_ok(d))
            && s.m.connect.iter().all(|c| self.find(&c.service).is_none_or(|p| self.svcs[p].state == State::Running) || self.standalone)
            && (s.m.namespace.is_empty() || self.volumes_done)
    }

    /// Start every waiting service whose dependencies are met (and restarts that are due).
    pub fn start_ready(&mut self) {
        let now = sys::clock_ns();
        loop {
            let next = (0..self.svcs.len()).find(|&i| match self.svcs[i].state {
                State::Waiting => self.ready_to_start(i),
                State::Backoff(t) => t <= now && self.ready_to_start(i),
                _ => false,
            });
            let Some(i) = next else { return };
            if let Err(why) = self.start(i) {
                println!("init: cannot start {}: {}", self.svcs[i].m.name, why);
                self.svcs[i].state = State::Failed;
            }
        }
    }

    /// A new channel between client `ci` and provider `pi`'s `endpoint`: the provider's end goes
    /// over its control channel; the client's end is returned (for its start) or, if `send`, sent
    /// over the client's control channel too (the provider was restarted).
    fn link(&self, ci: usize, pi: usize, endpoint: &str, send: bool) -> Option<Handle> {
        let (mine, theirs) = sys::channel_pair().ok()?;
        let p = &self.svcs[pi];
        let mut msg = [0u8; HEADER + 64];
        Header { txid: 0, op: svc::CONNECT, status: 0, a: 0, b: 0 }.put(&mut msg);
        let n = endpoint.len().min(64);
        msg[HEADER..HEADER + n].copy_from_slice(&endpoint.as_bytes()[..n]);
        if sys::channel_write_h(p.ctl.raw(), &msg[..HEADER + n], &[MsgHandle { handle: theirs, rights: sys::RIGHTS_SAME }]) < 0 {
            sys::handle_close(mine);
            return None;
        }
        if !send {
            return Some(mine);
        }
        let full = format!("{}.{}", p.m.name, endpoint);
        let n = full.len().min(64);
        msg[HEADER..HEADER + n].copy_from_slice(&full.as_bytes()[..n]);
        let r = sys::channel_write_h(self.svcs[ci].ctl.raw(), &msg[..HEADER + n], &[MsgHandle { handle: mine, rights: sys::RIGHTS_SAME }]);
        (r >= 0).then_some(0)
    }

    fn start(&mut self, i: usize) -> Result<(), String> {
        let image = libd::find_program(self.svcs[i].m.image.as_bytes()).ok_or("image missing")?;
        let m = self.svcs[i].m.clone();
        let mut hs: Vec<SpawnHandle> = Vec::new();
        let give = |hs: &mut Vec<SpawnHandle>, h: Handle, tag: u32| hs.push(SpawnHandle { handle: h, rights: sys::RIGHTS_SAME, tag, reserved: 0 });
        let close_all = |hs: &[SpawnHandle]| hs.iter().for_each(|h| { sys::handle_close(h.handle); });
        // The control channel to the manager: always.
        let (ours, theirs) = sys::channel_pair().map_err(|e| format!("no channel: {}", sys::status(e)))?;
        give(&mut hs, theirs, proto::TAG_CONTROL);
        if m.log
            && let Some(h) = dup(startup(sys::TAG_LOG))
        {
            give(&mut hs, h, sys::TAG_LOG);
        }
        if m.vmex
            && let Some(h) = dup(startup(sys::TAG_VMEX))
        {
            give(&mut hs, h, sys::TAG_VMEX);
        }
        if m.power
            && let Some(h) = dup(startup(sys::TAG_POWER))
        {
            give(&mut hs, h, sys::TAG_POWER);
        }
        if m.kernel_log
            && let Some(h) = dup(startup(sys::TAG_KLOG))
        {
            give(&mut hs, h, sys::TAG_KLOG);
        }
        if m.boot_time
            && let Some(h) = dup(startup(sys::TAG_BOOT_TIME))
        {
            give(&mut hs, h, sys::TAG_BOOT_TIME);
        }
        let mut ndev = 0;
        let mut left_out = 0;
        let starts: Vec<(Handle, u32)> = libd::startup_handles().collect();
        for &(h, tag) in &starts {
            let wanted = match tag {
                sys::TAG_DEVICE if !m.devices.is_empty() => sys::device_info(h).is_ok_and(|d| {
                    let pci = d.kind == sys::DEV_KIND_PCI;
                    m.devices.iter().any(|sel| sel.matches(pci, d.class, d.subclass, d.progif, d.name()))
                }),
                sys::TAG_PROGRAM if !m.programs.is_empty() => {
                    let n = object_name(h);
                    m.programs.iter().any(|p| dman::program_matches(p, &n))
                }
                _ => false,
            };
            if !wanted {
                continue;
            }
            if hs.len() + 2 + m.connect.len() + m.namespace.len() >= sys_spawn_max() {
                left_out += 1; // never silently: reported below
                continue;
            }
            if let Some(d) = dup(h) {
                give(&mut hs, d, tag);
                ndev += usize::from(tag == sys::TAG_DEVICE);
            }
        }
        if left_out > 0 {
            println!("init: {}: {} devices/programs left out: a spawn passes at most {} handles", m.name, left_out, sys_spawn_max());
        }
        // Endpoints: one channel per connection, the provider's end over its control channel.
        if !m.connect.is_empty() {
            let mut names: Vec<u8> = Vec::new();
            let mut k = 0u32;
            for c in &m.connect {
                let Some(pi) = self.find(&c.service).filter(|&p| self.svcs[p].state == State::Running) else {
                    if self.standalone {
                        continue;
                    }
                    close_all(&hs);
                    return Err(format!("endpoint {}.{} is not available", c.service, c.endpoint));
                };
                let Some(h) = self.link(i, pi, &c.endpoint, false) else {
                    close_all(&hs);
                    return Err(format!("cannot connect to {}.{}", c.service, c.endpoint));
                };
                names.extend_from_slice(format!("{}.{}", c.service, c.endpoint).as_bytes());
                names.push(0);
                give(&mut hs, h, svc::TAG_ENDPOINT + k);
                k += 1;
            }
            if k > 0 {
                let v = sys::vmo_create(names.len() as u64).map_err(|e| format!("no memory: {}", sys::status(e)))?;
                sys::vmo_write(v, 0, &names);
                hs.push(SpawnHandle { handle: v, rights: sys::RIGHT_READ, tag: svc::TAG_ENDPOINT_NAMES, reserved: 0 });
            }
        }
        // Namespace: the granted volumes, each narrowed to the rights granted.
        if !m.namespace.is_empty() {
            let mut ns = NsBuilder::new();
            for g in &m.namespace {
                let Some(v) = self.volumes.iter().find(|v| v.name == g.volume) else {
                    close_all(&hs);
                    return Err(format!("volume '{}' does not exist", g.volume));
                };
                let rights = u64::from(g.rights);
                match v.root.clone_with(rights) {
                    Ok(n) => {
                        ns.add(g.path.as_bytes(), n);
                    }
                    Err(e) => {
                        close_all(&hs);
                        return Err(format!("cannot open volume '{}': {}", g.volume, fp::status(e)));
                    }
                }
            }
            let mut out = [SpawnHandle::default(); fp::MAX_NS + 1];
            let n = ns.finish(&mut out).map_err(|e| format!("namespace: {}", sys::status(e)))?;
            hs.extend_from_slice(&out[..n]);
        }
        let limits = sys::Limits { memory: m.quota.memory, handles: m.quota.handles, threads: m.quota.threads };
        let args = self.svcs[i].args.clone().unwrap_or_else(|| m.args.clone());
        let p = sys::spawn(startup(sys::TAG_PROC_SELF), image, m.name.as_bytes(), args.as_bytes(), &hs, &limits)
            .map_err(|e| format!("spawn failed: {}", sys::status(e)))?;
        let s = &mut self.svcs[i];
        s.proc = Owned::from_raw(p);
        s.ctl = Owned::from_raw(ours);
        s.state = State::Running;
        s.starts += 1;
        self.port.arm(p, sys::TERMINATED, (i as u64) << 8 | KEY_PROC);
        self.port.arm(ours, sys::READABLE | sys::PEER_CLOSED, (i as u64) << 8 | KEY_CTL);
        self.order.retain(|&x| x != i);
        self.order.push(i);
        if m.kernel_log {
            // The log service: every service's level (its own manifest's, or info).
            for k in 0..self.svcs.len() {
                self.send_level(i, k);
            }
        }
        if ndev > 0 {
            println!("init: started {} with {} devices", m.name, ndev);
        } else {
            println!("init: started {}", m.name);
        }
        // A restarted provider: its volumes are announced again; its running clients get linked
        // to the new instance.
        if self.svcs[i].starts > 1 {
            if m.volumes {
                self.volumes.clear();
                self.volumes_done = false;
            }
            for ci in 0..self.svcs.len() {
                if self.svcs[ci].state != State::Running || ci == i {
                    continue;
                }
                for c in self.svcs[ci].m.connect.clone() {
                    if c.service == m.name && self.link(ci, i, &c.endpoint, true).is_some() {
                        println!("init: {} linked to {}.{} again", self.svcs[ci].m.name, c.service, c.endpoint);
                    }
                }
            }
        }
        Ok(())
    }

    /// Tell kernel-log holder `to` the log level of service `k` (svc::LOG_LEVEL).
    fn send_level(&self, to: usize, k: usize) {
        let ctl = self.svcs[to].ctl.raw();
        if ctl == 0 {
            return;
        }
        let name = self.svcs[k].m.name.as_bytes();
        let mut msg = [0u8; HEADER + 32];
        Header { txid: 0, op: svc::LOG_LEVEL, status: 0, a: u64::from(self.svcs[k].m.log_level), b: 0 }.put(&mut msg);
        msg[HEADER..HEADER + name.len()].copy_from_slice(name);
        sys::channel_write(ctl, &msg[..HEADER + name.len()]);
    }

    // ---- events ---------------------------------------------------------------------------------

    /// Wait for one event (or until a restart is due, or `timeout`), handle it, start what can
    /// start. False on timeout.
    pub fn pump(&mut self, timeout: u64) -> bool {
        self.start_ready();
        let now = sys::clock_ns();
        let due = self.svcs.iter().filter_map(|s| if let State::Backoff(t) = s.state { Some(t.saturating_sub(now).max(1)) } else { None }).min();
        let wait = due.map_or(timeout, |d| d.min(timeout));
        let Some((key, _)) = self.port.wait(wait) else {
            self.start_ready();
            return due.is_some_and(|d| d <= timeout);
        };
        let i = (key >> 8) as usize;
        if i < self.svcs.len() {
            match key & 0xFF {
                KEY_PROC => self.ended(i),
                KEY_CTL => self.control(i),
                _ => {}
            }
        }
        self.start_ready();
        true
    }

    /// Pump until `done(self)` or `timeout` ns pass. True if `done`.
    pub fn run_until(&mut self, timeout: u64, mut done: impl FnMut(&Mgr) -> bool) -> bool {
        let deadline = sys::clock_ns().saturating_add(timeout);
        loop {
            if done(self) {
                return true;
            }
            let now = sys::clock_ns();
            if now >= deadline {
                return false;
            }
            self.pump(deadline - now);
        }
    }

    fn ended(&mut self, i: usize) {
        let s = &mut self.svcs[i];
        if s.state != State::Running || s.proc.raw() == 0 {
            return;
        }
        let code = sys::process_exit_code(s.proc.raw());
        s.proc = Owned::default();
        s.ctl = Owned::default();
        s.last_code = code;
        let name = s.m.name.clone();
        println!("init: {} exited with code {}{}", name, code, exit_text(code));
        let restart = match s.m.restart.policy {
            Policy::Always => true,
            Policy::OnFailure => code != 0,
            Policy::Never => false,
        };
        if !restart {
            s.state = State::Done(code);
            return;
        }
        if s.restarts >= s.m.restart.limit {
            s.state = State::GaveUp;
            println!("init: {} keeps failing: given up after {} restart(s)", name, s.restarts);
            return;
        }
        s.restarts += 1;
        let delay = s.m.restart.delay_ms(s.restarts);
        s.state = State::Backoff(sys::clock_ns() + delay * MS);
        println!("init: restarting {} in {} ms (restart {} of {})", name, delay, s.restarts, s.m.restart.limit);
    }

    /// Messages from a service: volume announcements from a volume provider; anything else is
    /// dropped (with any handle it carried).
    fn control(&mut self, i: usize) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let ch = self.svcs[i].ctl.raw();
            if ch == 0 {
                return;
            }
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(ch, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let handle = if nh > 0 { hs[0] } else { 0 };
                    let h = Header::get(&buf[..n]);
                    let provider = self.svcs[i].m.volumes;
                    match h {
                        Some(h) if provider && h.op == fp::VOLUME && handle != 0 => {
                            let name = String::from_utf8_lossy(&buf[HEADER..n]).into_owned();
                            self.volumes.retain(|v| v.name != name);
                            self.volumes.push(Volume { name, root: Node::from(handle) });
                        }
                        Some(h) if provider && h.op == fp::VOLUMES_DONE => {
                            self.volumes_done = true;
                            let names: Vec<&str> = self.volumes.iter().map(|v| v.name.as_str()).collect();
                            println!("init: {} volume(s): {}", self.volumes.len(), names.join(" "));
                        }
                        _ => {
                            if handle != 0 {
                                sys::handle_close(handle);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, (i as u64) << 8 | KEY_CTL);
                    return;
                }
                Err(_) => return, // gone: the process watch handles it
            }
        }
    }

    /// End a service on purpose (tests): it is restarted like after any other exit.
    pub fn kill(&mut self, name: &str) -> bool {
        let Some(i) = self.find(name) else { return false };
        let p = self.svcs[i].proc.raw();
        p != 0 && sys::process_kill(p) == 0
    }

    // ---- shutdown -------------------------------------------------------------------------------

    /// Stop every running service: first every volume provider makes its volumes durable (while
    /// the drivers under it still run), then the services stop, each after every service that
    /// depends on it (the last started first among those free to stop): SHUTDOWN, then up to 5 s,
    /// then kill.
    pub fn shutdown(&mut self) {
        for s in self.svcs.iter().filter(|s| s.state == State::Running && s.m.volumes) {
            println!("init: syncing {}", s.m.name);
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: svc::SYNC, status: 0, a: 0, b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            if sys::channel_call(s.ctl.raw(), &req, &mut rep, 10 * SEC).is_err() {
                println!("init: {} did not confirm its volumes are durable", s.m.name);
            }
        }
        loop {
            // Next: a running service no other running service depends on (`after` or
            // `connect`), the last started first; with a cycle, simply the last started.
            let running: Vec<usize> = self.order.iter().rev().copied().filter(|&i| self.svcs[i].state == State::Running).collect();
            let needed = |d: usize| {
                let name = &self.svcs[d].m.name;
                running.iter().any(|&s| s != d && (self.svcs[s].m.after.contains(name) || self.svcs[s].m.connect.iter().any(|c| &c.service == name)))
            };
            let Some(&i) = running.iter().find(|&&i| !needed(i)).or(running.first()) else { break };
            let name = self.svcs[i].m.name.clone();
            println!("init: stopping {}", name);
            let mut msg = [0u8; HEADER];
            Header { txid: 0, op: svc::SHUTDOWN, status: 0, a: 0, b: 0 }.put(&mut msg);
            sys::channel_write(self.svcs[i].ctl.raw(), &msg);
            let p = self.svcs[i].proc.raw();
            if sys::object_wait(p, sys::TERMINATED, 5 * SEC).is_err() {
                println!("init: {} did not stop in time: ended", name);
                sys::process_kill(p);
                let _ = sys::object_wait(p, sys::TERMINATED, SEC);
            }
            let code = sys::process_exit_code(p);
            println!("init: {} stopped (code {}{})", name, code, exit_text(code));
            let s = &mut self.svcs[i];
            s.proc = Owned::default();
            s.ctl = Owned::default();
            s.state = State::Done(code);
        }
        println!("init: shutdown: every service stopped");
    }

    // ---- manifests from disk --------------------------------------------------------------------

    /// Signed manifests in `DOS/SERVICES` of volume `vol`: `<NAME>.DMAN` with `<NAME>.DSIG` (a
    /// `.dsig` of kind manifest, by the D-OS key, for this name). Anything else is refused.
    pub fn load_from_volume(&mut self, vol: &str, groups: &[Group]) -> u32 {
        let Some(root) = self.volumes.iter().find(|v| v.name == vol).and_then(|v| v.root.clone_with(fp::R_READ).ok()) else { return 0 };
        let Ok((dir, _, _)) = root.open(b"DOS/SERVICES", fp::O_DIRECTORY, fp::R_READ) else { return 0 };
        let mut names: Vec<Vec<u8>> = Vec::new();
        let _ = dir.list(|n, kind| {
            if kind == fp::KIND_FILE && n.len() > 5 && n[n.len() - 5..].eq_ignore_ascii_case(b".dman") {
                names.push(n.to_vec());
            }
        });
        names.sort();
        let mut accepted = 0;
        for n in names {
            let file = String::from_utf8_lossy(&n).into_owned();
            let source = format!("{}:/DOS/SERVICES/{}", vol, file);
            let read = |name: &[u8]| -> Option<Vec<u8>> {
                let (f, _, size) = dir.open(name, 0, fp::R_READ).ok()?;
                if size as usize > dman::toml::MAX_SIZE {
                    return None;
                }
                let mut b = alloc::vec![0u8; size as usize];
                let got = f.read(0, &mut b).ok()?;
                b.truncate(got);
                Some(b)
            };
            let Some(bytes) = read(&n) else {
                self.refuse(&source, &[0; 32], "unreadable or larger than 16 KiB");
                continue;
            };
            let digest = sha256(&bytes);
            let mut sig_name = n[..n.len() - 5].to_vec();
            sig_name.extend_from_slice(if n[n.len() - 4].is_ascii_uppercase() { b".DSIG" } else { b".dsig" });
            let Some(sig) = read(&sig_name) else {
                self.refuse(&source, &digest, "not signed (no .dsig next to it)");
                continue;
            };
            if let Err(why) = verify_signed(&bytes, &sig, &file) {
                self.refuse(&source, &digest, &why);
                continue;
            }
            if self.offer(&source, &bytes, groups) {
                accepted += 1;
            }
        }
        accepted
    }
}

/// The kernel checks a signed manifest (`vmo_verify`: seals it, checks the `.dsig` against the
/// D-OS key, measures it); the `.dsig` must also be of kind manifest and name this file.
fn verify_signed(bytes: &[u8], sig: &[u8], file: &str) -> Result<(), String> {
    use doscrypt::dsig;
    if sig.len() != dsig::SIZE {
        return Err("the .dsig is not a signature".into());
    }
    let h = dsig::parse(sig).map_err(|_| String::from("the .dsig is not a signature"))?;
    if h.kind != dsig::KIND_MANIFEST {
        return Err(format!("the .dsig is not for a manifest (kind {})", h.kind));
    }
    if !h.name_str().eq_ignore_ascii_case(file) {
        return Err(format!("the .dsig is for '{}', not this file", h.name_str()));
    }
    let v = sys::vmo_create(bytes.len().max(1) as u64).map_err(|e| format!("no memory: {}", sys::status(e)))?;
    let v = Owned::from_raw(v);
    let d = Owned::from_raw(sys::vmo_create(sig.len() as u64).map_err(|e| format!("no memory: {}", sys::status(e)))?);
    if sys::vmo_write(v.raw(), 0, bytes) != 0 || sys::vmo_write(d.raw(), 0, sig) != 0 {
        return Err("cannot copy it".into());
    }
    match sys::vmo_verify(v.raw(), d.raw()) {
        0 => Ok(()),
        e => Err(format!("signature check failed ({})", sys::status(e))),
    }
}

fn sys_spawn_max() -> usize {
    256
}
