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
//! - **Identity**: a provider whose manifest says `provides.identify` gets, with each client's
//!   channel, that client's service name (verified: it is its accepted manifest's) and trust tier
//!   (`trust_tier`), so it can show who it serves in a way no client can forge.
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
use libd::rec::{Record, Value};
use libd::{Port, println, svc, tool};

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;
const KEY_PROC: u64 = 1;
const KEY_CTL: u64 = 2;
const KEY_MGR: u64 = 3;
/// The power-button event (startup tag POWER_BUTTON) fired.
const KEY_BUTTON: u64 = 4;
/// Read-only manager channel granted to a verified `.dapp` (e.g. System Monitor).
const KEY_APP_MGR: u64 = 5;
const MAX_APP_MGRS: usize = 32;

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
    /// The manager's end of its manager channel (`grants.manager`).
    mgr: Owned,
    /// Asked to stop or restart (`MGR_STOP`, `MGR_RESTART`): what happens at its exit, and when
    /// it is ended if it has not stopped by then (clock_ns; 0 = no deadline).
    on_exit: OnExit,
    kill_by: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OnExit {
    /// Its restart policy decides.
    Policy,
    /// Stopped for good.
    Stop,
    /// Started again at once (not counted as a restart).
    Restart,
}

/// An accepted tool manifest: what it says, and its VMO (handed to holders of `grants.tools`).
pub struct ToolEntry {
    pub t: dman::tool::Tool,
    vmo: Owned,
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
    pub tools: Vec<ToolEntry>,
    /// Verified read-only program VMOs loaded from the immutable `sys` volume (`/bin`).
    pub disk_programs: Vec<(String, Owned)>,
    pub sys_loaded: bool,
    embedded_seen: Vec<Handle>,
    /// A manager channel asked for the power (`MGR_POWER`): a clean shutdown, then this action.
    pub power_request: Option<u64>,
    /// Read-only manager channels handed to verified `.dapp` apps via `MGR_LINK` (`manager.services-ro`).
    app_mgrs: Vec<Option<Owned>>,
}

fn startup(tag: u32) -> Handle {
    libd::startup_handle(tag)
}

/// The trust tier of a service, as a provider with `provides.identify` is told it: sandbox for
/// anything that may run foreign code (VMEX or the D-CMPL program), system for the system's own
/// services, native for the rest.
fn trust_tier(m: &Manifest) -> u64 {
    if m.vmex || m.programs.iter().any(|p| p == "dcmpl.dx") {
        u64::from(libd::awmi::TRUST_SANDBOX)
    } else if m.group == Group::System {
        u64::from(libd::awmi::TRUST_SYSTEM)
    } else {
        u64::from(libd::awmi::TRUST_NATIVE)
    }
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
        let port = Port::new(256).map_err(|_| "cannot create a port")?;
        // The machine's power button (ACPI): a press is a clean shutdown and power-off.
        let button = startup(sys::TAG_POWER_BUTTON);
        if button != 0 {
            port.arm(button, sys::SIGNALED, KEY_BUTTON);
        }
        Ok(Mgr {
            svcs: Vec::new(),
            port,
            volumes: Vec::new(),
            volumes_done: false,
            order: Vec::new(),
            standalone: false,
            refused: 0,
            tools: Vec::new(),
            disk_programs: Vec::new(),
            sys_loaded: false,
            embedded_seen: Vec::new(),
            power_request: None,
            app_mgrs: Vec::new(),
        })
    }

    /// Look up a program image by name: embedded bootstrap VMOs first, then verified VMOs from `sys:/bin`.
    pub fn find_program(&self, name: &str) -> Option<Handle> {
        if let Some(h) = libd::find_program(name.as_bytes()) {
            return Some(h);
        }
        self.disk_programs.iter().find(|(n, _)| n == name).map(|(_, h)| h.raw())
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
        if self.find_program(&m.image).is_none() {
            self.refuse(source, &digest, &format!("image {} is not available", m.image));
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
            mgr: Owned::default(),
            on_exit: OnExit::Policy,
            kill_by: 0,
        });
        true
    }

    /// A tool manifest (`kind = "tool"`): accepted if it parses, its image is available
    /// and neither its name nor an alias is taken; measured either way.
    fn offer_tool(&mut self, source: &str, bytes: &[u8], vmo: Owned) -> bool {
        let digest = sha256(bytes);
        let t = match dman::tool::parse(bytes) {
            Ok(t) => t,
            Err(e) => {
                self.refuse(source, &digest, &e.to_string());
                return false;
            }
        };
        if self.find_program(&t.image).is_none() {
            self.refuse(source, &digest, &format!("image {} is not available", t.image));
            return false;
        }
        let names = |x: &dman::tool::Tool| -> Vec<String> { core::iter::once(x.name.clone()).chain(x.aliases.iter().cloned()).collect() };
        let mine = names(&t);
        if let Some(n) = self.tools.iter().flat_map(|e| names(&e.t)).find(|n| mine.contains(n)) {
            self.refuse(source, &digest, &format!("the name '{}' is taken by another tool", n));
            return false;
        }
        measure(&digest, &format!("tool {}", t.name));
        println!("init: tool {} accepted ({}): {}", t.name, source, t.usage());
        self.tools.push(ToolEntry { t, vmo });
        true
    }

    /// The embedded manifests (startup tag MANIFEST), of the given groups.
    pub fn load_embedded(&mut self, groups: &[Group]) {
        let hs: Vec<Handle> = libd::startup_handles().filter(|&(_, t)| t == sys::TAG_MANIFEST).map(|(h, _)| h).collect();
        for h in hs {
            if self.embedded_seen.contains(&h) {
                continue;
            }
            let name = object_name(h);
            match vmo_bytes(h, dman::toml::MAX_SIZE) {
                Some(b) if dman::tool::is_tool(&b) => {
                    self.embedded_seen.push(h);
                    if let Some(d) = dup(h) {
                        self.offer_tool(&name, &b, Owned::from_raw(d));
                    }
                }
                Some(b) => {
                    let before = self.refused;
                    let accepted = self.offer(&name, &b, groups);
                    if accepted || self.refused > before {
                        self.embedded_seen.push(h);
                    }
                }
                None => {
                    self.embedded_seen.push(h);
                    self.refuse(&name, &[0; 32], "unreadable or larger than 16 KiB");
                }
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
        let c = &self.svcs[ci].m;
        let mut msg = [0u8; HEADER + 64 + 1 + 32];
        let tier = if p.m.identify { trust_tier(c) } else { 0 };
        Header { txid: 0, op: svc::CONNECT, status: 0, a: 0, b: tier }.put(&mut msg);
        let mut n = endpoint.len().min(64);
        msg[HEADER..HEADER + n].copy_from_slice(&endpoint.as_bytes()[..n]);
        if p.m.identify {
            // `<endpoint>\0<client service name>`: who this channel serves, as accepted.
            let name = &c.name.as_bytes()[..c.name.len().min(32)];
            msg[HEADER + n] = 0;
            msg[HEADER + n + 1..HEADER + n + 1 + name.len()].copy_from_slice(name);
            n += 1 + name.len();
        }
        if sys::channel_write_h(p.ctl.raw(), &msg[..HEADER + n], &[MsgHandle { handle: theirs, rights: sys::RIGHTS_SAME }]) < 0 {
            sys::handle_close(mine);
            return None;
        }
        if !send {
            return Some(mine);
        }
        Header { txid: 0, op: svc::CONNECT, status: 0, a: 0, b: 0 }.put(&mut msg);
        let full = format!("{}.{}", p.m.name, endpoint);
        let n = full.len().min(64);
        msg[HEADER..HEADER + n].copy_from_slice(&full.as_bytes()[..n]);
        let r = sys::channel_write_h(self.svcs[ci].ctl.raw(), &msg[..HEADER + n], &[MsgHandle { handle: mine, rights: sys::RIGHTS_SAME }]);
        (r >= 0).then_some(0)
    }

    fn start(&mut self, i: usize) -> Result<(), String> {
        let image = self.find_program(&self.svcs[i].m.image).ok_or("image missing")?;
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
        if m.tpm_seal
            && let Some(h) = dup(startup(sys::TAG_TPM_SEAL))
        {
            give(&mut hs, h, sys::TAG_TPM_SEAL);
        }
        // The tools: their manifests (read-only) and their program images.
        if m.tools {
            for e in &self.tools {
                if let Ok(h) = sys::handle_duplicate(e.vmo.raw(), sys::RIGHT_READ | sys::RIGHT_TRANSFER) {
                    give(&mut hs, h, tool::TAG_TOOL_MANIFEST);
                }
                if let Some(h) = self.find_program(&e.t.image).and_then(dup) {
                    give(&mut hs, h, sys::TAG_PROGRAM);
                }
            }
        }
        // A channel to the manager itself (list, stop and restart services; power; app linking).
        let mut mgr_end = Owned::default();
        if m.manage_services || m.manage_power || m.manage_apps {
            let (mine, theirs) = sys::channel_pair().map_err(|e| format!("no channel: {}", sys::status(e)))?;
            give(&mut hs, theirs, tool::TAG_MANAGER);
            mgr_end = Owned::from_raw(mine);
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
        // Also grant verified disk programs matching `grants.programs` (not already embedded).
        if !m.programs.is_empty() {
            for (n, vmo) in &self.disk_programs {
                if !m.programs.iter().any(|p| dman::program_matches(p, n)) {
                    continue;
                }
                if hs.len() + 3 + m.connect.len() + m.namespace.len() >= sys_spawn_max() {
                    left_out += 1;
                    continue;
                }
                if let Some(d) = dup(vmo.raw()) {
                    give(&mut hs, d, sys::TAG_PROGRAM);
                }
            }
        }
        // If `sys:` is already mounted and this service manages `.ddrv` drivers (`devmgr`),
        // pass a read-only `sys:/firmware` directory handle directly in its startup block.
        if m.programs.iter().any(|p| p == "*.ddrv")
            && let Some(sys_vol) = self.volumes.iter().find(|v| v.name == "sys")
            && let Ok((fw_dir, kind, _)) = sys_vol.root.open(b"firmware", fp::O_DIRECTORY, fp::R_READ)
            && kind == fp::KIND_DIR
        {
            give(&mut hs, fw_dir.into_handle(), proto::TAG_FIRMWARE);
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
            if m.namespace.first().is_some_and(|g| g.path == "*") {
                // Every volume at /<name>, with at most the rights the volume has (read-only on
                // a normal boot: the storage service hands out read rights only).
                let want = u64::from(m.namespace[0].rights);
                for v in &self.volumes {
                    let have = v.root.stat().map_or(fp::R_READ, |st| st.rights);
                    if let Ok(n) = v.root.clone_with(want & have) {
                        ns.add(format!("/{}", v.name).as_bytes(), n);
                    }
                }
            }
            for g in m.namespace.iter().filter(|g| g.path != "*") {
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
        s.on_exit = OnExit::Policy;
        s.kill_by = 0;
        if mgr_end.raw() != 0 {
            self.port.arm(mgr_end.raw(), sys::READABLE | sys::PEER_CLOSED, (i as u64) << 8 | KEY_MGR);
        }
        s.mgr = mgr_end;
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
        // If `sys:` is already mounted and this service spawns `.ddrv` drivers (`devmgr`),
        // hand it a read-only directory capability rooted at `sys:/firmware`.
        if m.programs.iter().any(|p| p == "*.ddrv") {
            self.send_firmware_dir(i);
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
        // Services asked to stop that are still running at their deadline are ended.
        for s in self.svcs.iter_mut().filter(|s| s.kill_by != 0 && s.kill_by <= now && s.state == State::Running) {
            println!("init: {} did not stop in time: ended", s.m.name);
            sys::process_kill(s.proc.raw());
            s.kill_by = 0;
        }
        let due = self
            .svcs
            .iter()
            .filter_map(|s| match s.state {
                State::Backoff(t) => Some(t.saturating_sub(now).max(1)),
                State::Running if s.kill_by > now => Some(s.kill_by - now),
                _ => None,
            })
            .min();
        let wait = due.map_or(timeout, |d| d.min(timeout));
        let Some((key, _)) = self.port.wait(wait) else {
            self.start_ready();
            return due.is_some_and(|d| d <= timeout);
        };
        if key == KEY_BUTTON {
            let button = startup(sys::TAG_POWER_BUTTON);
            sys::event_signal(button, sys::SIGNALED, 0);
            self.port.arm(button, sys::SIGNALED, KEY_BUTTON);
            if self.power_request.is_none() {
                println!("init: power button pressed: shutting down");
                self.power_request = Some(sys::POWER_OFF);
            }
            self.start_ready();
            return true;
        }
        let i = (key >> 8) as usize;
        if (key & 0xFF) == KEY_APP_MGR {
            self.manage_app_ro(i);
            self.start_ready();
            return true;
        }
        if i < self.svcs.len() {
            match key & 0xFF {
                KEY_PROC => self.ended(i),
                KEY_CTL => self.control(i),
                KEY_MGR => self.manage(i),
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
        s.mgr = Owned::default();
        s.last_code = code;
        s.kill_by = 0;
        let name = s.m.name.clone();
        println!("init: {} exited with code {}{}", name, code, exit_text(code));
        match core::mem::replace(&mut s.on_exit, OnExit::Policy) {
            OnExit::Stop => {
                s.state = State::Done(code);
                println!("init: {} stopped on request", name);
                return;
            }
            OnExit::Restart => {
                s.state = State::Backoff(sys::clock_ns());
                println!("init: restarting {} on request", name);
                return;
            }
            OnExit::Policy => {}
        }
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
                            if self.sys_loaded {
                                for k in 0..self.svcs.len() {
                                    if self.svcs[k].state == State::Running
                                        && self.svcs[k].m.programs.iter().any(|p| p == "*.ddrv")
                                    {
                                        self.send_firmware_dir(k);
                                    }
                                }
                            }
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

    /// Link a verified `.dapp` (on behalf of `appmgr` with `grants.manager = ["apps"]`) to a
    /// safe whitelisted service endpoint, attaching verified identity `app_name` and `TRUST_NATIVE`.
    fn link_app(&mut self, endpoint: &str, app_name: &str) -> Result<Handle, i64> {
        const ALLOWED: &[&str] = &[
            "awmi.window",
            "awmi.admin",
            "awmi.query",
            "terminal.view",
            "gpu.query",
            "audio.control",
            "audio.playback",
            "net.status",
            "net.control",
            "log.read",
            "clock.time",
            "identity.query",
            "identity.admin",
            "appmgr.query",
            "appmgr.admin",
            "storaged.admin",
            "manager.services-ro",
        ];
        if !dman::valid_name(app_name) || !ALLOWED.contains(&endpoint) {
            return Err(sys::ERR_ACCESS_DENIED);
        }
        if endpoint == "manager.services-ro" {
            let (client, ours) = sys::channel_pair()?;
            let slot = if let Some(pos) = self.app_mgrs.iter().position(Option::is_none) {
                self.app_mgrs[pos] = Some(Owned::from_raw(ours));
                pos
            } else if self.app_mgrs.len() < MAX_APP_MGRS {
                let pos = self.app_mgrs.len();
                self.app_mgrs.push(Some(Owned::from_raw(ours)));
                pos
            } else {
                sys::handle_close(client);
                sys::handle_close(ours);
                return Err(sys::ERR_NO_RESOURCES);
            };
            self.port.arm(ours, sys::READABLE | sys::PEER_CLOSED, (slot as u64) << 8 | KEY_APP_MGR);
            return Ok(client);
        }
        let Some((svc_name, ep_name)) = endpoint.split_once('.') else {
            return Err(sys::ERR_INVALID_ARGS);
        };
        let Some(pi) = self
            .find(svc_name)
            .filter(|&p| self.svcs[p].state == State::Running && self.svcs[p].m.endpoints.iter().any(|e| e == ep_name))
        else {
            return Err(fp::ERR_NOT_FOUND);
        };
        let (mine, theirs) = sys::channel_pair()?;
        let p = &self.svcs[pi];
        let mut msg = [0u8; HEADER + 64 + 1 + 32];
        let tier = if p.m.identify { u64::from(libd::awmi::TRUST_NATIVE) } else { 0 };
        Header { txid: 0, op: svc::CONNECT, status: 0, a: 0, b: tier }.put(&mut msg);
        let mut n = ep_name.len().min(64);
        msg[HEADER..HEADER + n].copy_from_slice(&ep_name.as_bytes()[..n]);
        if p.m.identify {
            let name = &app_name.as_bytes()[..app_name.len().min(32)];
            msg[HEADER + n] = 0;
            msg[HEADER + n + 1..HEADER + n + 1 + name.len()].copy_from_slice(name);
            n += 1 + name.len();
        }
        if sys::channel_write_h(p.ctl.raw(), &msg[..HEADER + n], &[MsgHandle { handle: theirs, rights: sys::RIGHTS_SAME }]) < 0 {
            sys::handle_close(mine);
            return Err(sys::ERR_BAD_STATE);
        }
        Ok(mine)
    }

    /// Read-only manager requests from a verified `.dapp` (`manager.services-ro`): only `MGR_LIST`
    /// and `MGR_OBJECTS` are permitted; stop, restart, power, and link are always refused.
    fn manage_app_ro(&mut self, slot: usize) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let Some(ch) = self.app_mgrs.get(slot).and_then(|o| o.as_ref()).map(Owned::raw) else { return };
            let n = match sys::channel_read(ch, &mut buf, 0) {
                Ok(n) => n as usize,
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, (slot as u64) << 8 | KEY_APP_MGR);
                    return;
                }
                Err(_) => {
                    if let Some(s) = self.app_mgrs.get_mut(slot) {
                        *s = None;
                    }
                    return;
                }
            };
            let Some(h) = Header::get(&buf[..n]) else { continue };
            let arg = String::from_utf8_lossy(&buf[HEADER..n]).into_owned();
            let (status, payload) = match h.op {
                svc::MGR_LIST => (0, self.list_records()),
                svc::MGR_OBJECTS => match self.find(&arg) {
                    Some(k) if self.svcs[k].proc.raw() != 0 => (0, objects_records(self.svcs[k].proc.raw())),
                    Some(_) => (sys::ERR_BAD_STATE, b"it is not running".to_vec()),
                    None => (fp::ERR_NOT_FOUND, b"no such service".to_vec()),
                },
                _ => (sys::ERR_ACCESS_DENIED, b"read-only manager channel".to_vec()),
            };
            let mut out = alloc::vec![0u8; HEADER];
            Header { txid: h.txid, op: h.op, status: status as i32, a: 0, b: 0 }.put(&mut out);
            out.extend_from_slice(&payload[..payload.len().min(libd::rec::MAX_PAYLOAD)]);
            sys::channel_write(ch, &out);
        }
    }

    /// Requests on service `i`'s manager channel (`svc::MGR_*`), each answered with the same op.
    fn manage(&mut self, i: usize) {
        let mut buf = [0u8; HEADER + 128];
        loop {
            let ch = self.svcs[i].mgr.raw();
            if ch == 0 {
                return;
            }
            let n = match sys::channel_read(ch, &mut buf, 0) {
                Ok(n) => n as usize,
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, (i as u64) << 8 | KEY_MGR);
                    return;
                }
                Err(_) => return,
            };
            let Some(h) = Header::get(&buf[..n]) else { continue };
            if h.op == svc::MGR_LINK {
                let mut rep = [0u8; HEADER];
                if !self.svcs[i].m.manage_apps {
                    Header { txid: h.txid, op: h.op, status: sys::ERR_ACCESS_DENIED as i32, a: 0, b: 0 }.put(&mut rep);
                    sys::channel_write(ch, &rep);
                    continue;
                }
                let body = &buf[HEADER..n];
                let res = match body.iter().position(|&b| b == 0) {
                    Some(nul) => match (core::str::from_utf8(&body[..nul]), core::str::from_utf8(&body[nul + 1..])) {
                        (Ok(ep), Ok(app)) => self.link_app(ep, app),
                        _ => Err(sys::ERR_INVALID_ARGS),
                    },
                    None => Err(sys::ERR_INVALID_ARGS),
                };
                match res {
                    Ok(handle) => {
                        Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                        sys::channel_write_h(ch, &rep, &[MsgHandle { handle, rights: sys::RIGHTS_SAME }]);
                    }
                    Err(e) => {
                        Header { txid: h.txid, op: h.op, status: e as i32, a: 0, b: 0 }.put(&mut rep);
                        sys::channel_write(ch, &rep);
                    }
                }
                continue;
            }
            let arg = String::from_utf8_lossy(&buf[HEADER..n]).into_owned();
            let (status, payload) = self.request(i, &h, &arg);
            let mut out = alloc::vec![0u8; HEADER];
            Header { txid: h.txid, op: h.op, status: status as i32, a: 0, b: 0 }.put(&mut out);
            out.extend_from_slice(&payload[..payload.len().min(libd::rec::MAX_PAYLOAD)]);
            sys::channel_write(ch, &out);
        }
    }

    /// One manager request from service `i`: (status, payload).
    fn request(&mut self, i: usize, h: &Header, arg: &str) -> (i64, Vec<u8>) {
        let (services, power) = (self.svcs[i].m.manage_services, self.svcs[i].m.manage_power);
        let who = self.svcs[i].m.name.clone();
        let refuse = |st: i64, why: &str| (st, why.as_bytes().to_vec());
        match h.op {
            svc::MGR_LIST if services => (0, self.list_records()),
            svc::MGR_OBJECTS if services => match self.find(arg) {
                Some(k) if self.svcs[k].proc.raw() != 0 => (0, objects_records(self.svcs[k].proc.raw())),
                Some(_) => refuse(sys::ERR_BAD_STATE, "it is not running"),
                None => refuse(fp::ERR_NOT_FOUND, "no such service"),
            },
            svc::MGR_STOP | svc::MGR_RESTART if services => {
                let stop = h.op == svc::MGR_STOP;
                let Some(k) = self.find(arg) else { return refuse(fp::ERR_NOT_FOUND, "no such service") };
                if stop && k == i {
                    return refuse(sys::ERR_ACCESS_DENIED, "it cannot stop itself (restart it instead)");
                }
                let s = &mut self.svcs[k];
                match s.state {
                    State::Running => {
                        s.on_exit = if stop { OnExit::Stop } else { OnExit::Restart };
                        s.kill_by = sys::clock_ns() + 5 * SEC;
                        println!("init: {} {} (asked by {})", if stop { "stopping" } else { "restarting" }, s.m.name, who);
                        let mut msg = [0u8; HEADER];
                        Header { txid: 0, op: svc::SHUTDOWN, status: 0, a: 0, b: 0 }.put(&mut msg);
                        if sys::channel_write(s.ctl.raw(), &msg) < 0 {
                            sys::process_kill(s.proc.raw());
                        }
                        (0, Vec::new())
                    }
                    State::Done(_) | State::GaveUp | State::Failed if !stop => {
                        s.restarts = 0;
                        s.state = State::Waiting;
                        println!("init: starting {} again (asked by {})", s.m.name, who);
                        (0, Vec::new())
                    }
                    _ => refuse(sys::ERR_BAD_STATE, "it is not running"),
                }
            }
            svc::MGR_POWER if power && matches!(h.a, sys::POWER_OFF | sys::POWER_REBOOT | sys::POWER_SUSPEND) => {
                let act = match h.a {
                    sys::POWER_OFF => "switch off",
                    sys::POWER_REBOOT => "restart the machine",
                    _ => "suspend the machine",
                };
                println!("init: {} asked to {}", who, act);
                self.power_request = Some(h.a);
                (0, Vec::new())
            }
            svc::MGR_LIST | svc::MGR_OBJECTS | svc::MGR_STOP | svc::MGR_RESTART | svc::MGR_POWER => {
                refuse(sys::ERR_ACCESS_DENIED, "not granted by its manifest")
            }
            _ => (sys::ERR_NOT_SUPPORTED, Vec::new()),
        }
    }

    /// Every service as a record (`MGR_LIST`).
    fn list_records(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for s in &self.svcs {
            let state = match s.state {
                State::Waiting => "waiting",
                State::Running if s.on_exit != OnExit::Policy => "stopping",
                State::Running => "running",
                State::Backoff(_) => "restarting",
                State::Done(0) => "done",
                State::Done(_) => "stopped",
                State::GaveUp => "given up",
                State::Failed => "failed",
            };
            let q = if s.proc.raw() != 0 { sys::process_quota(s.proc.raw()).ok() } else { None };
            let none = || Value::Text(String::new());
            Record::new()
                .with("name", Value::Text(s.m.name.clone()))
                .with("state", Value::Text(state.into()))
                .with("restarts", Value::Int(i64::from(s.restarts)))
                .with("memory", q.map_or_else(none, |q| Value::Size(q.used.memory)))
                .with("quota", Value::Size(s.m.quota.memory))
                .with("handles", q.map_or_else(none, |q| Value::Int(q.used.handles as i64)))
                .with("threads", q.map_or_else(none, |q| Value::Int(q.used.threads as i64)))
                .with("description", Value::Text(s.m.description.clone()))
                .encode(&mut out);
        }
        out
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

    /// Suspend to ACPI S3: sync volumes, stop/quiesce drivers via `devmgr`, enter S3, then
    /// restart drivers on wake so storage and input recover transparently.
    pub fn suspend(&mut self, power_res: Handle) -> i64 {
        for s in self.svcs.iter().filter(|s| s.state == State::Running && s.m.volumes) {
            println!("init: syncing {}", s.m.name);
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: svc::SYNC, status: 0, a: 0, b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            if sys::channel_call(s.ctl.raw(), &req, &mut rep, 10 * SEC).is_err() {
                println!("init: {} did not confirm its volumes are durable", s.m.name);
            }
        }
        let awmi_ctl = self
            .find("awmi")
            .filter(|&i| self.svcs[i].state == State::Running)
            .map(|i| self.svcs[i].ctl.raw())
            .unwrap_or(0);
        if awmi_ctl != 0 {
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: svc::SUSPEND, status: 0, a: 0, b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            let _ = sys::channel_call(awmi_ctl, &req, &mut rep, 5 * SEC);
        }
        let devmgr_ctl = self
            .find("devmgr")
            .filter(|&i| self.svcs[i].state == State::Running)
            .map(|i| self.svcs[i].ctl.raw())
            .unwrap_or(0);
        if devmgr_ctl != 0 {
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: svc::SUSPEND, status: 0, a: 0, b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            if sys::channel_call(devmgr_ctl, &req, &mut rep, 15 * SEC).is_err() {
                println!("init: devmgr did not confirm driver suspend");
            }
        }
        let r = sys::system_power(power_res, sys::POWER_SUSPEND);
        if devmgr_ctl != 0 {
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: svc::RESUME, status: 0, a: 0, b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            if sys::channel_call(devmgr_ctl, &req, &mut rep, 15 * SEC).is_err() {
                println!("init: devmgr did not confirm driver resume");
            }
        }
        r
    }

    /// Send a read-only `sys:/firmware` directory channel (`svc::GIVE_FIRMWARE`) to running service `i`.
    fn send_firmware_dir(&self, i: usize) {
        let ctl = self.svcs[i].ctl.raw();
        if ctl == 0 {
            return;
        }
        let Some(sys_vol) = self.volumes.iter().find(|v| v.name == "sys") else {
            return;
        };
        let Ok((fw_dir, kind, _)) = sys_vol.root.open(b"firmware", fp::O_DIRECTORY, fp::R_READ) else {
            return;
        };
        if kind != fp::KIND_DIR {
            return;
        }
        let mut msg = [0u8; HEADER];
        Header { txid: 0, op: svc::GIVE_FIRMWARE, status: 0, a: 0, b: 0 }.put(&mut msg);
        let h = fw_dir.into_handle();
        let _ = sys::channel_write_h(ctl, &msg, &[MsgHandle { handle: h, rights: sys::RIGHTS_SAME }]);
    }

    // ---- manifests from disk --------------------------------------------------------------------

    /// Load signed programs (`/bin`), tools (`/tools`) and services (`/services`) from the
    /// immutable `sys` volume. Every file is verified with its `.dsig` via `vmo_verify` (Ed25519).
    pub fn load_sys_volume(&mut self, groups: &[Group]) -> u32 {
        if self.sys_loaded {
            return 0;
        }
        let Some(root) = self.volumes.iter().find(|v| v.name == "sys").and_then(|v| v.root.clone_with(fp::R_READ).ok()) else {
            return 0;
        };
        self.sys_loaded = true;
        // Deliver read-only `sys:/firmware` directory capability to any already-running `.ddrv`
        // manager (`devmgr`) before handing over late `sys:/bin/*.ddrv` driver VMOs.
        for k in 0..self.svcs.len() {
            if self.svcs[k].state == State::Running && self.svcs[k].m.programs.iter().any(|p| p == "*.ddrv") {
                self.send_firmware_dir(k);
            }
        }
        let mut progs = 0u32;
        if let Ok((dir, _, _)) = root.open(b"bin", fp::O_DIRECTORY, fp::R_READ) {
            let mut names: Vec<Vec<u8>> = Vec::new();
            let _ = dir.list(|n, kind| {
                if kind == fp::KIND_FILE && !n.ends_with(b".dsig") {
                    names.push(n.to_vec());
                }
            });
            names.sort();
            for n in names {
                let file = String::from_utf8_lossy(&n).into_owned();
                if self.find_program(&file).is_some() {
                    continue;
                }
                let mut sig_name = n.clone();
                sig_name.extend_from_slice(b".dsig");
                match load_verified_program(&dir, &n, &sig_name, &file) {
                    Ok(vmo) => {
                        let raw_vmo = vmo.raw();
                        self.disk_programs.push((file.clone(), vmo));
                        progs += 1;
                        // Forward newly verified `.ddrv` / matching program VMOs to running bootstrap services (`devmgr`).
                        for s in &self.svcs {
                            if s.state == State::Running
                                && s.ctl.raw() != 0
                                && s.m.programs.iter().any(|pat| dman::program_matches(pat, &file))
                                && let Some(dup_vmo) = dup(raw_vmo)
                            {
                                let nb = file.as_bytes();
                                let nl = nb.len().min(48);
                                let mut msg = [0u8; HEADER + 48];
                                Header { txid: 0, op: svc::GIVE_PROGRAM, status: 0, a: 0, b: 0 }.put(&mut msg);
                                msg[HEADER..HEADER + nl].copy_from_slice(&nb[..nl]);
                                let _ = sys::channel_write_h(
                                    s.ctl.raw(),
                                    &msg[..HEADER + nl],
                                    &[MsgHandle { handle: dup_vmo, rights: sys::RIGHTS_SAME }],
                                );
                            }
                        }
                    }
                    Err(why) => println!("init: sys:/bin/{} refused: {}", file, why),
                }
            }
        }
        let mut tools = 0u32;
        if let Ok((dir, _, _)) = root.open(b"tools", fp::O_DIRECTORY, fp::R_READ) {
            let mut names: Vec<Vec<u8>> = Vec::new();
            let _ = dir.list(|n, kind| {
                if kind == fp::KIND_FILE && n.len() > 5 && n[n.len() - 5..].eq_ignore_ascii_case(b".dman") {
                    names.push(n.to_vec());
                }
            });
            names.sort();
            for n in names {
                let file = String::from_utf8_lossy(&n).into_owned();
                let source = format!("sys:/tools/{}", file);
                let mut sig_name = n[..n.len() - 5].to_vec();
                sig_name.extend_from_slice(b".dsig");
                let Some(bytes) = read_small(&dir, &n) else {
                    self.refuse(&source, &[0; 32], "unreadable or larger than 16 KiB");
                    continue;
                };
                let digest = sha256(&bytes);
                let Some(sig) = read_small(&dir, &sig_name) else {
                    self.refuse(&source, &digest, "not signed (no .dsig next to it)");
                    continue;
                };
                match verify_signed(&bytes, &sig, &file) {
                    Ok(vmo) => {
                        if self.offer_tool(&source, &bytes, vmo) {
                            tools += 1;
                        }
                    }
                    Err(why) => self.refuse(&source, &digest, &why),
                }
            }
        }
        let mut svcs = 0u32;
        if let Ok((dir, _, _)) = root.open(b"services", fp::O_DIRECTORY, fp::R_READ) {
            let mut names: Vec<Vec<u8>> = Vec::new();
            let _ = dir.list(|n, kind| {
                if kind == fp::KIND_FILE && n.len() > 5 && n[n.len() - 5..].eq_ignore_ascii_case(b".dman") {
                    names.push(n.to_vec());
                }
            });
            names.sort();
            for n in names {
                let file = String::from_utf8_lossy(&n).into_owned();
                let source = format!("sys:/services/{}", file);
                let mut sig_name = n[..n.len() - 5].to_vec();
                sig_name.extend_from_slice(b".dsig");
                let Some(bytes) = read_small(&dir, &n) else {
                    self.refuse(&source, &[0; 32], "unreadable or larger than 16 KiB");
                    continue;
                };
                let digest = sha256(&bytes);
                let Some(sig) = read_small(&dir, &sig_name) else {
                    self.refuse(&source, &digest, "not signed (no .dsig next to it)");
                    continue;
                };
                if let Err(why) = verify_signed(&bytes, &sig, &file) {
                    self.refuse(&source, &digest, &why);
                    continue;
                }
                if self.offer(&source, &bytes, groups) {
                    svcs += 1;
                }
            }
        }
        println!("init: sys volume: {} program(s), {} service(s), {} tool(s) verified (Ed25519)", progs, svcs, tools);
        svcs + tools
    }

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
            let Some(bytes) = read_small(&dir, &n) else {
                self.refuse(&source, &[0; 32], "unreadable or larger than 16 KiB");
                continue;
            };
            let digest = sha256(&bytes);
            let mut sig_name = n[..n.len() - 5].to_vec();
            sig_name.extend_from_slice(if n[n.len() - 4].is_ascii_uppercase() { b".DSIG" } else { b".dsig" });
            let Some(sig) = read_small(&dir, &sig_name) else {
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

fn read_small(dir: &Node, name: &[u8]) -> Option<Vec<u8>> {
    let (f, _, size) = dir.open(name, 0, fp::R_READ).ok()?;
    if size as usize > dman::toml::MAX_SIZE {
        return None;
    }
    let mut b = alloc::vec![0u8; size as usize];
    let got = f.read(0, &mut b).ok()?;
    b.truncate(got);
    Some(b)
}

/// Read a signed program from `dir` into a sealed, verified read-only VMO (`vmo_verify`).
fn load_verified_program(dir: &Node, name: &[u8], sig_name: &[u8], file: &str) -> Result<Owned, String> {
    use doscrypt::dsig;
    let sig = read_small(dir, sig_name).ok_or_else(|| String::from("not signed (no .dsig next to it)"))?;
    if sig.len() != dsig::SIZE {
        return Err("the .dsig is not a signature".into());
    }
    let h = dsig::parse(&sig).map_err(|_| String::from("the .dsig is not a signature"))?;
    if h.kind != dsig::KIND_PROGRAM && h.kind != dsig::KIND_DRIVER {
        return Err(format!("the .dsig is not for a program (kind {})", h.kind));
    }
    if !h.name_str().eq_ignore_ascii_case(file) {
        return Err(format!("the .dsig is for '{}', not this file", h.name_str()));
    }
    let (f, _, size) = dir.open(name, 0, fp::R_READ).map_err(|e| format!("cannot open: {}", fp::status(e)))?;
    if size == 0 || size > 16 << 20 {
        return Err("invalid program size".into());
    }
    let v = Owned::from_raw(sys::vmo_create(size).map_err(|e| format!("no memory: {}", sys::status(e)))?);
    let mut buf = alloc::vec![0u8; fp::MAX_IO];
    let mut off = 0u64;
    while off < size {
        let want = ((size - off) as usize).min(buf.len());
        let got = f.read(off, &mut buf[..want]).map_err(|e| format!("read failed: {}", fp::status(e)))?;
        if got == 0 {
            return Err("unexpected end of file".into());
        }
        if sys::vmo_write(v.raw(), off, &buf[..got]) != 0 {
            return Err("cannot write VMO".into());
        }
        off += got as u64;
    }
    let d = Owned::from_raw(sys::vmo_create(sig.len() as u64).map_err(|e| format!("no memory: {}", sys::status(e)))?);
    if sys::vmo_write(d.raw(), 0, &sig) != 0 {
        return Err("cannot copy .dsig".into());
    }
    match sys::vmo_verify(v.raw(), d.raw()) {
        0 => {
            // Drop WRITE right on the handle we keep/duplicate (VMO is already sealed).
            let ro = sys::handle_replace(
                v.into_raw(),
                sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_DUPLICATE | sys::RIGHT_TRANSFER | sys::RIGHT_INSPECT,
            )
            .map_err(|e| format!("replace failed: {}", sys::status(e)))?;
            Ok(Owned::from_raw(ro))
        }
        e => Err(format!("signature check failed ({})", sys::status(e))),
    }
}

/// The kernel checks a signed manifest (`vmo_verify`: seals it, checks the `.dsig` against the
/// D-OS key, measures it); the `.dsig` must also be of kind manifest and name this file.
fn verify_signed(bytes: &[u8], sig: &[u8], file: &str) -> Result<Owned, String> {
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
        0 => Ok(v),
        e => Err(format!("signature check failed ({})", sys::status(e))),
    }
}

fn sys_spawn_max() -> usize {
    256
}

/// The handles a process holds, as records (`MGR_OBJECTS`, the shell's `objects`).
pub fn objects_records(p: Handle) -> Vec<u8> {
    let mut buf = alloc::vec![sys::HandleEntry::default(); 256];
    let n = sys::process_handles(p, &mut buf).map_or(0, |n| (n as usize).min(buf.len()));
    let mut out = Vec::new();
    for e in &buf[..n] {
        Record::new()
            .with("type", Value::Text(object_type(e.ty).into()))
            .with("name", Value::Text(e.name().into()))
            .with("rights", Value::Text(rights_text(e.rights)))
            .with("koid", Value::Int(e.koid as i64))
            .encode(&mut out);
    }
    out
}

pub fn object_type(t: u32) -> &'static str {
    const N: [&str; 15] = ["?", "process", "thread", "vmo", "vmar", "event", "timer", "log", "channel", "port", "exception", "resource", "device", "interrupt", "pin"];
    N.get(t as usize).copied().unwrap_or("?")
}

/// Rights as letters: read, write, execute, map, transfer, duplicate, wait, signal, inspect,
/// manage (a dash where missing).
pub fn rights_text(r: u32) -> String {
    let bits = [
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
    bits.iter().map(|&(b, c)| if r & b != 0 { c } else { '-' }).collect()
}
