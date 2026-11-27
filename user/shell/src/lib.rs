//! The shell (`shell.dx`, docs/shell.md): one session on the terminal.
//!
//! Commands exchange typed records (`libd::rec`), not byte streams; filters in plain words
//! (`where size > 1M | sort modified | take 5`) work on them, and they become a table only at the
//! end of the line. Built-in commands use the session's own grants (its manifest: every volume,
//! the log, the clock, the service manager). Tools are separate programs with a manifest that
//! declares their parameters: the shell resolves the paths typed and gives a tool exactly those
//! nodes with exactly the declared rights, plus an output channel. A tool never gets the session's
//! namespace, endpoints or any other handle of the shell.

#![no_std]

extern crate alloc;

mod cmds;
mod filter;
mod parse;
mod show;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

use dman::tool::{ParamKind, Tool};
use libd::fs::{self as fp, Namespace, Node};
use libd::handle::Owned;
use libd::proto::{self, HEADER, Header};
use libd::rec::{self, Record};
use libd::sys::{self, Handle, SpawnHandle};
use libd::{Port, Startup, println, svc, term, tool};

libd::entry!(_start, main);

const KEY_TERM: u64 = 1;
const KEY_CTL: u64 = 2;
const KEY_JOB_OUT: u64 = 3;
const KEY_JOB_END: u64 = 4;
const KEY_NOTICES: u64 = 5;

/// Until the first key arrives, keyboard notices from the log are shown on the screen (a keyboard
/// that is found but never types can be diagnosed without one): every this often, at most
/// `NOTICES_MAX` lines.
const NOTICES_EVERY: u64 = 1_000_000_000;
const NOTICES_MAX: u32 = 40;

const MAX_JOBS: usize = 16;
/// What a tool may use (its share of the session's own quota).
const TOOL_LIMITS: sys::Limits = sys::Limits { memory: 16 << 20, handles: 128, threads: 4 };
/// What a foreign program may use, D-CMPL included (Windows threads have 1 MiB stacks).
const FOREIGN_LIMITS: sys::Limits = sys::Limits { memory: 128 << 20, handles: 256, threads: 16 };
/// The largest foreign program `run` reads.
const MAX_FOREIGN: u64 = 64 << 20;

/// A granted directory at a path (`/data`), with the rights the session has on it.
pub struct Place {
    pub path: String,
    pub h: Handle,
    pub rights: u64,
}

/// What a command printed, in order.
pub enum Item {
    Text(String),
    Error(String),
}

pub struct Job {
    pub id: u32,
    pub line: String,
    pub name: String,
    pub proc: Owned,
    out: Owned,
    /// Records collected (filtered and shown when the job ends).
    pub records: Vec<Record>,
    /// Text and errors not shown yet (background jobs, or waiting behind filters).
    pub items: Vec<Item>,
    pub filters: Vec<Vec<String>>,
    pub background: bool,
    pub started: u64,
    /// The exit code once it ended.
    pub code: Option<i64>,
    /// An error was shown already (no second "exited with code" line).
    pub said_error: bool,
}

pub struct Shell {
    term: Handle,
    pub cols: usize,
    pub places: Vec<Place>,
    /// The current place: an absolute path ("/" is the list of places).
    pub place: String,
    pub tools: Vec<Tool>,
    pub mgr: Handle,
    pub log: Handle,
    pub clock: Handle,
    pub audio_play: Handle,
    pub audio_ctl: Handle,
    pub net_client: Handle,
    pub net_icmp: Handle,
    pub net_ctl: Handle,
    pub gpu_query: Handle,
    pub awmi_admin: Handle,
    pub awmi_query: Handle,
    pub identity_admin: Handle,
    pub identity_query: Handle,
    pub appmgr_admin: Handle,
    pub appmgr_query: Handle,
    pub storaged_admin: Handle,
    /// Raw `/home` volume root (private; used only to re-scope `/home` per active identity and
    /// read/write `.dos/oobe.toml` for Operator sessions).
    home_vol: Handle,
    home_rights: u64,
    scoped_home_handle: Handle,
    data_vol: Handle,
    data_rights: u64,
    pub jobs: Vec<Job>,
    next_job: u32,
    /// The job whose output the terminal is waiting for.
    fg: Option<u32>,
    port: Port,
    reading: bool,
    /// Keyboard notices (until the first key): the timer and the next log sequence number.
    notices: Option<(libd::Timer, u64)>,
    notices_shown: u32,
}

/// A node handle we hold, used without giving it up.
fn borrow(h: Handle) -> ManuallyDrop<Node> {
    ManuallyDrop::new(Node::from(h))
}

/// `p` made absolute against `base`, with `.` and `..` worked out (never above `/`).
pub fn normalize(base: &str, p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let full = if p.starts_with('/') { String::from(p) } else { format!("{}/{}", base, p) };
    for c in full.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut s = String::new();
    for c in parts {
        s.push('/');
        s.push_str(c);
    }
    if s.is_empty() { String::from("/") } else { s }
}

fn split_parent(abs: &str) -> (&str, &str) {
    match abs.rsplit_once('/') {
        Some(("", leaf)) => ("/", leaf),
        Some((p, leaf)) => (p, leaf),
        None => ("/", abs),
    }
}

/// The edit distance between two short words (for "did you mean").
fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = alloc::vec![i + 1; b.len() + 1];
        for (j, &cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != cb)).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

impl Shell {
    // ---- the terminal ----------------------------------------------------------------------------

    fn send(&self, op: u32, a: u64, payload: &[u8]) {
        if self.term == 0 {
            return;
        }
        let mut m = Vec::with_capacity(HEADER + payload.len());
        m.resize(HEADER, 0);
        Header { txid: 0, op, status: 0, a, b: 0 }.put(&mut m);
        m.extend_from_slice(payload);
        let mut tries = 0;
        while sys::channel_write(self.term, &m) == sys::ERR_SHOULD_WAIT && tries < 50 {
            let _ = sys::object_wait(self.term, sys::WRITABLE | sys::PEER_CLOSED, 100_000_000);
            tries += 1;
        }
    }

    /// Show text (style markers allowed), in pieces a message can carry.
    pub fn write(&self, s: &str) {
        let b = s.as_bytes();
        let mut at = 0;
        while at < b.len() {
            let mut end = (at + 32 * 1024).min(b.len());
            while end < b.len() && !s.is_char_boundary(end) {
                end -= 1;
            }
            self.send(term::WRITE, 0, &b[at..end]);
            at = end;
        }
    }

    pub fn error(&self, s: &str) {
        self.write(&show::err_line(s));
    }

    fn prompt(&mut self) {
        // Background jobs that ended since the last prompt.
        let ended: Vec<u32> = self.jobs.iter().filter(|j| j.background && j.code.is_some()).map(|j| j.id).collect();
        for id in ended {
            if let Some(j) = self.jobs.iter().find(|j| j.id == id) {
                let code = j.code.unwrap_or(0);
                let what = format!("job {} ended: {} ({})", id, j.line, if code == 0 { String::from("ok") } else { format!("exit code {}", code) });
                let pending = !j.records.is_empty() || !j.items.is_empty();
                let msg = if pending { format!("{}; 'wait {}' shows its output", what, id) } else { what };
                self.write(&if code == 0 { show::ok_line(&msg) } else { show::err_line(&msg) });
                if !pending {
                    self.jobs.retain(|j| j.id != id);
                } else if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
                    j.background = false; // reported; kept for `wait`
                    j.started = 0;
                }
            }
        }
        let place = if self.place == "/" { String::from("/") } else { String::from(&self.place[1..]) };
        let p = format!("{}{} {}{}", show::style(term::LIGHT_CYAN), place, show::coloured(term::LIGHT_GREEN, "▸"), " ");
        self.send(term::READ, 0, p.as_bytes());
        self.reading = true;
    }

    // ---- places and paths ------------------------------------------------------------------------

    /// The place holding absolute path `abs` and the rest below it.
    pub fn resolve(&self, abs: &str) -> Option<(&Place, String)> {
        let mut best: Option<&Place> = None;
        for p in &self.places {
            let inside = abs == p.path || (abs.starts_with(&p.path) && abs.as_bytes().get(p.path.len()) == Some(&b'/'));
            if inside && best.is_none_or(|b| p.path.len() > b.path.len()) {
                best = Some(p);
            }
        }
        best.map(|p| (p, String::from(abs[p.path.len()..].trim_start_matches('/'))))
    }

    pub fn not_granted(&self, what: &str, abs: &str) -> String {
        let granted: Vec<String> = self.places.iter().map(|p| format!("{} ({})", p.path, rights_word(p.rights))).collect();
        format!("{}: {} is not in this session's namespace\n  granted: {}", what, abs, if granted.is_empty() { String::from("nothing") } else { granted.join(", ") })
    }

    /// Open `abs` (read-only, or with `rights`): the node and its kind.
    pub fn open(&self, what: &str, abs: &str, flags: u64, rights: u64) -> Result<(Node, u64), String> {
        let Some((pl, rest)) = self.resolve(abs) else { return Err(self.not_granted(what, abs)) };
        if rights & fp::R_WRITE != 0 && pl.rights & fp::R_WRITE == 0 {
            return Err(format!("{}: {} is read-only in this session", what, pl.path));
        }
        let dir = borrow(pl.h);
        let r = if rest.is_empty() {
            dir.clone_with(rights).and_then(|n| n.stat().map(|st| (n, st.kind)))
        } else {
            dir.open(rest.as_bytes(), flags, rights).map(|(n, k, _)| (n, k))
        };
        r.map_err(|e| format!("{}: {}: {}", what, abs, fp::message(e)))
    }

    // ---- tools -----------------------------------------------------------------------------------

    pub fn find_tool(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.name == name || t.aliases.iter().any(|a| a == name))
    }

    /// Start tool `t` with `args`: resolve every path with the rights its manifest declares.
    fn launch(&mut self, t: &Tool, args: &[String], line: &str, background: bool, filters: Vec<Vec<String>>) -> Result<(), String> {
        if self.jobs.len() >= MAX_JOBS {
            return Err(format!("{}: too many jobs ({}); end one first", t.name, MAX_JOBS));
        }
        let usage = format!("usage: {}", t.usage());
        // (parameter, shown, Some(rel) for paths, node)
        let mut items: Vec<(String, String, Option<String>, Option<Node>)> = Vec::new();
        let mut ai = 0;
        let mut first_path: Option<String> = None;
        for p in &t.params {
            let values: Vec<String> = if p.many {
                let v = args[ai.min(args.len())..].to_vec();
                ai = args.len();
                v
            } else if ai < args.len() {
                ai += 1;
                alloc::vec![args[ai - 1].clone()]
            } else {
                Vec::new()
            };
            let values = if values.is_empty() {
                match (p.optional, p.kind) {
                    (true, ParamKind::Path) => alloc::vec![String::from(".")],
                    (true, _) => continue,
                    (false, _) => return Err(format!("{}: missing <{}>; {}", t.name, p.name, usage)),
                }
            } else {
                values
            };
            for v in values {
                match p.kind {
                    ParamKind::Text => items.push((p.name.clone(), v, None, None)),
                    ParamKind::Number => {
                        if v.parse::<i64>().is_err() {
                            return Err(format!("{}: <{}> must be a number, not '{}'", t.name, p.name, v));
                        }
                        items.push((p.name.clone(), v, None, None));
                    }
                    ParamKind::Path => {
                        let mut abs = normalize(&self.place, &v);
                        if abs == "/" {
                            return Err(format!("{}: / is the list of places, not a directory (see 'places')", t.name));
                        }
                        if !p.write {
                            let (n, _) = self.open(&t.name, &abs, 0, fp::R_READ)?;
                            first_path.get_or_insert_with(|| abs.clone());
                            items.push((p.name.clone(), abs, Some(String::new()), Some(n)));
                            continue;
                        }
                        // Written (or created): the tool gets the directory it is in, and its name.
                        if p.create
                            && let Some(first) = &first_path
                        {
                            // An existing directory (or a path ending in '/') receives the first
                            // path under its own name.
                            let is_dir = v.ends_with('/') || self.open(&t.name, &abs, 0, fp::R_READ).is_ok_and(|(_, k)| k == fp::KIND_DIR);
                            if is_dir {
                                abs = normalize(&abs, split_parent(first).1);
                            }
                        }
                        let (pl_path, rest) = match self.resolve(&abs) {
                            Some((pl, rest)) => (pl.path.clone(), rest),
                            None => return Err(self.not_granted(&t.name, &abs)),
                        };
                        let (dir, leaf) = if rest.is_empty() {
                            (pl_path, String::new()) // the place itself (refused by tools that need a name)
                        } else {
                            let (parent, leaf) = split_parent(&abs);
                            (String::from(parent), String::from(leaf))
                        };
                        let (n, kind) = self.open(&t.name, &dir, fp::O_DIRECTORY, fp::R_READ | fp::R_WRITE)?;
                        if kind != fp::KIND_DIR {
                            return Err(format!("{}: {}: {}", t.name, dir, fp::message(fp::ERR_NOT_DIR)));
                        }
                        first_path.get_or_insert_with(|| abs.clone());
                        items.push((p.name.clone(), abs, Some(leaf), Some(n)));
                    }
                }
            }
        }
        if ai < args.len() {
            return Err(format!("{}: too many arguments ('{}'); {}", t.name, args[ai], usage));
        }
        if items.len() > tool::MAX_ITEMS {
            return Err(format!("{}: more than {} arguments", t.name, tool::MAX_ITEMS));
        }
        // The arguments, and the handles: output, one node per path, the log.
        let (mine, theirs) = sys::channel_pair().map_err(|e| format!("{}: {}", t.name, sys::status(e)))?;
        let mut hs: Vec<SpawnHandle> = alloc::vec![SpawnHandle { handle: theirs, rights: sys::RIGHTS_SAME, tag: tool::TAG_OUTPUT, reserved: 0 }];
        let mut argv: Vec<u8> = Vec::new();
        for (k, (name, shown, rel, node)) in items.into_iter().enumerate() {
            argv.extend_from_slice(name.as_bytes());
            argv.push(b'=');
            argv.extend_from_slice(shown.as_bytes());
            if let Some(rel) = rel {
                argv.push(tool::SEP);
                argv.extend_from_slice(rel.as_bytes());
            }
            argv.push(0);
            if let Some(n) = node {
                hs.push(SpawnHandle { handle: n.into_handle(), rights: sys::RIGHTS_SAME, tag: tool::TAG_PARAM + k as u32, reserved: 0 });
            }
        }
        if let Ok(l) = sys::handle_duplicate(libd::startup_handle(sys::TAG_LOG), sys::RIGHTS_SAME) {
            hs.push(SpawnHandle { handle: l, rights: sys::RIGHTS_SAME, tag: sys::TAG_LOG, reserved: 0 });
        }
        let Some(image) = libd::find_program(t.image.as_bytes()) else {
            hs.iter().for_each(|h| {
                sys::handle_close(h.handle);
            });
            sys::handle_close(mine);
            return Err(format!("{}: its program {} is not here", t.name, t.image));
        };
        let p = sys::spawn(libd::startup_handle(sys::TAG_PROC_SELF), image, t.name.as_bytes(), &argv, &hs, &TOOL_LIMITS).map_err(|e| {
            sys::handle_close(mine);
            format!("{}: cannot start: {}", t.name, sys::status(e))
        })?;
        self.add_job(&t.name, p, mine, line, background, filters);
        Ok(())
    }

    /// A started job: its process and output channel, watched from now on.
    fn add_job(&mut self, name: &str, p: Handle, mine: Handle, line: &str, background: bool, filters: Vec<Vec<String>>) {
        let id = self.next_job;
        self.next_job += 1;
        self.port.arm(mine, sys::READABLE | sys::PEER_CLOSED, u64::from(id) << 8 | KEY_JOB_OUT);
        self.port.arm(p, sys::TERMINATED, u64::from(id) << 8 | KEY_JOB_END);
        self.jobs.push(Job {
            id,
            line: String::from(line),
            name: String::from(name),
            proc: Owned::from_raw(p),
            out: Owned::from_raw(mine),
            records: Vec::new(),
            items: Vec::new(),
            filters,
            background,
            started: sys::clock_ns(),
            code: None,
            said_error: false,
        });
        if background {
            self.write(&show::ok_line(&format!("job {} started: {}", id, line)));
        } else {
            self.fg = Some(id);
        }
    }

    /// `run <file> [arguments]` for a program that is not a tool: a Windows (PE) or Linux (ELF)
    /// program, told apart by its header, run by D-CMPL. It gets the current place (with the
    /// session's rights there) as its working directory, an output channel and the wall clock;
    /// nothing else of the session (no other place, no endpoint, no manager).
    fn launch_foreign(&mut self, prog: &str, args: &[String], line: &str, background: bool, filters: Vec<Vec<String>>) -> Result<(), String> {
        if self.jobs.len() >= MAX_JOBS {
            return Err(format!("run: too many jobs ({}); end one first", MAX_JOBS));
        }
        let abs = normalize(&self.place, prog);
        let (file, kind) = self.open("run", &abs, 0, fp::R_READ)?;
        if kind != fp::KIND_FILE {
            return Err(format!("run: {} is a directory", abs));
        }
        let size = file.stat().map_err(|e| format!("run: {}: {}", abs, fp::message(e)))?.size;
        if size > MAX_FOREIGN {
            return Err(format!("run: {} is larger than {} MiB", abs, MAX_FOREIGN >> 20));
        }
        let mut data = alloc::vec![0u8; size as usize];
        let got = file.read(0, &mut data).map_err(|e| format!("run: {}: {}", abs, fp::message(e)))?;
        data.truncate(got);
        drop(file);
        let personality = if data.starts_with(b"MZ") {
            "win"
        } else if data.starts_with(&[0x7F, b'E', b'L', b'F']) {
            "linux"
        } else {
            return Err(format!("run: {} is not a program D-CMPL runs (a Windows .exe or a Linux ELF executable)", abs));
        };
        let Some(dcmpl) = libd::find_program(b"dcmpl.dx") else {
            return Err(String::from("run: D-CMPL (dcmpl.dx) is not available to this session"));
        };
        let vmex = libd::startup_handle(sys::TAG_VMEX);
        if vmex == 0 {
            return Err(String::from("run: this session may not run foreign programs (no VMEX grant)"));
        }
        let leaf = split_parent(&abs).1.to_string();
        // Every handle it gets (closed again if something fails before the spawn).
        let mut hs: Vec<SpawnHandle> = Vec::new();
        let close_all = |hs: &[SpawnHandle]| {
            for h in hs {
                sys::handle_close(h.handle);
            }
        };
        let fail = |hs: &[SpawnHandle], e: i64| -> String {
            close_all(hs);
            format!("run: {}: {}", leaf, sys::status(e))
        };
        let image = sys::vmo_create(data.len().max(1) as u64).map_err(|e| fail(&hs, e))?;
        hs.push(SpawnHandle { handle: image, rights: sys::RIGHTS_SAME, tag: tool::TAG_IMAGE, reserved: 0 });
        let r = sys::vmo_write(image, 0, &data);
        if r < 0 {
            return Err(fail(&hs, r));
        }
        drop(data);
        let x = sys::handle_duplicate(vmex, sys::RIGHTS_SAME).map_err(|e| fail(&hs, e))?;
        hs.push(SpawnHandle { handle: x, rights: sys::RIGHTS_SAME, tag: sys::TAG_VMEX, reserved: 0 });
        if let Ok(l) = sys::handle_duplicate(libd::startup_handle(sys::TAG_LOG), sys::RIGHTS_SAME) {
            hs.push(SpawnHandle { handle: l, rights: sys::RIGHTS_SAME, tag: sys::TAG_LOG, reserved: 0 });
        }
        let now = libd::time::now();
        if now.0 != 0
            && let Ok(v) = sys::vmo_create(16)
        {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&now.0.to_le_bytes());
            b[8..].copy_from_slice(&sys::clock_ns().to_le_bytes());
            sys::vmo_write(v, 0, &b);
            hs.push(SpawnHandle { handle: v, rights: sys::RIGHT_READ, tag: tool::TAG_TIME_BASE, reserved: 0 });
        }
        // The current place, with the session's rights there: its working directory.
        if self.place != "/" {
            let place = self.place.clone();
            let rights = self.resolve(&place).map_or(fp::R_READ, |(pl, _)| pl.rights & (fp::R_READ | fp::R_WRITE));
            let (dir, _) = self.open("run", &place, fp::O_DIRECTORY, rights).inspect_err(|_| close_all(&hs))?;
            let mut ns = fp::NsBuilder::new();
            ns.add(place.as_bytes(), dir);
            let mut nh = [SpawnHandle::default(); 2];
            let n = ns.finish(&mut nh).map_err(|e| fail(&hs, e))?;
            hs.extend_from_slice(&nh[..n]);
        }
        let (mine, theirs) = sys::channel_pair().map_err(|e| fail(&hs, e))?;
        hs.push(SpawnHandle { handle: theirs, rights: sys::RIGHTS_SAME, tag: tool::TAG_OUTPUT, reserved: 0 });
        let mut argv = format!("{} {}", personality, leaf);
        for a in args {
            argv.push(' ');
            argv.push_str(a);
        }
        let p = sys::spawn(libd::startup_handle(sys::TAG_PROC_SELF), dcmpl, leaf.as_bytes(), argv.as_bytes(), &hs, &FOREIGN_LIMITS).map_err(|e| {
            sys::handle_close(mine);
            format!("run: {}: cannot start: {}", leaf, sys::status(e))
        })?;
        println!("shell: run {} ({}, under D-CMPL) in {}", abs, if personality == "win" { "Windows" } else { "Linux" }, self.place);
        self.add_job(&leaf, p, mine, line, background, filters);
        Ok(())
    }

    /// Read what job `id` sent so far. Text and errors of the foreground job without filters are
    /// shown at once; the rest waits.
    fn job_output(&mut self, id: u32) {
        let Some(k) = self.jobs.iter().position(|j| j.id == id) else { return };
        let ch = self.jobs[k].out.raw();
        let mut buf = alloc::vec![0u8; HEADER + rec::MAX_PAYLOAD];
        loop {
            match sys::channel_read(ch, &mut buf, 0) {
                Ok(n) => {
                    let n = n as usize;
                    let Some(h) = Header::get(&buf[..n]) else { continue };
                    let payload = &buf[HEADER..n];
                    let now = self.fg == Some(id) && self.jobs[k].filters.is_empty();
                    match h.op {
                        rec::BATCH => self.jobs[k].records.extend(rec::decode_all(payload)),
                        rec::TEXT => {
                            let s = String::from_utf8_lossy(payload).into_owned();
                            if now {
                                self.write(&s);
                            } else {
                                self.jobs[k].items.push(Item::Text(s));
                            }
                        }
                        rec::ERROR => {
                            let s = String::from_utf8_lossy(payload).into_owned();
                            self.jobs[k].said_error = true;
                            if now {
                                self.error(&s);
                            } else {
                                self.jobs[k].items.push(Item::Error(s));
                            }
                        }
                        _ => {}
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, u64::from(id) << 8 | KEY_JOB_OUT);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn job_ended(&mut self, id: u32) {
        self.job_output(id); // whatever it sent before it ended
        let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) else { return };
        if j.code.is_none() {
            j.code = Some(sys::process_exit_code(j.proc.raw()));
        }
        if self.fg == Some(id) {
            self.fg = None;
            self.finish(id);
            self.prompt();
        }
    }

    /// Show everything job `id` produced (filtered) and forget it.
    pub fn finish(&mut self, id: u32) {
        let Some(k) = self.jobs.iter().position(|j| j.id == id) else { return };
        let j = self.jobs.remove(k);
        for it in &j.items {
            match it {
                Item::Text(s) => self.write(s),
                Item::Error(s) => self.error(s),
            }
        }
        let mut rs = j.records;
        for f in &j.filters {
            match filter::apply(f, rs) {
                Ok(r) => rs = r,
                Err(e) => {
                    self.error(&e);
                    return;
                }
            }
        }
        self.write(&show::records(&rs, self.cols));
        let code = j.code.unwrap_or(0);
        if code != 0 && !j.said_error {
            let why = match code as i32 {
                sys::EXIT_KILLED => String::from("stopped"),
                sys::EXIT_FAULT => String::from("crashed"),
                _ => format!("exit code {}", code),
            };
            self.error(&format!("{}: {}", j.name, why));
        }
    }

    /// Ctrl+C: end the foreground job.
    fn interrupt(&mut self) {
        if let Some(id) = self.fg
            && let Some(j) = self.jobs.iter().find(|j| j.id == id)
        {
            sys::process_kill(j.proc.raw());
        }
    }

    // ---- a line ----------------------------------------------------------------------------------

    fn run_line(&mut self, line: &str) {
        let l = match parse::parse(line) {
            Ok(l) => l,
            Err(e) => return self.error(&e),
        };
        if l.stages.is_empty() {
            return;
        }
        let head = &l.stages[0];
        let filters: Vec<Vec<String>> = l.stages[1..].to_vec();
        if let Some(f) = filters.iter().find(|s| !filter::is_filter(&s[0])) {
            return self.error(&format!(
                "'{}' cannot follow '|': only filters can ({})",
                f[0],
                filter::NAMES.join(", ")
            ));
        }
        let name = head[0].as_str();
        let args = &head[1..];
        if filter::is_filter(name) {
            return self.error(&format!("{} works on the records of a command before it, e.g. list | {}", name, filter::usage(name)));
        }
        let shown = line.trim_start().trim_start_matches("start").trim();
        if let Some(t) = self.find_tool(name).cloned() {
            if let Err(e) = self.launch(&t, args, shown, l.background, filters) {
                self.error(&e);
            }
            return;
        }
        if name == "run" {
            let Some(first) = args.first() else {
                return self.error("run: run what? (run <tool or program> [arguments])");
            };
            let r = match self.find_tool(first).cloned() {
                Some(t) => self.launch(&t, &args[1..], shown, l.background, filters),
                None => self.launch_foreign(first, &args[1..], shown, l.background, filters),
            };
            if let Err(e) = r {
                self.error(&e);
            }
            return;
        }
        match cmds::run(self, name, args) {
            Some(Ok(rs)) => {
                let mut rs = rs;
                for f in &filters {
                    match filter::apply(f, rs) {
                        Ok(r) => rs = r,
                        Err(e) => return self.error(&e),
                    }
                }
                self.write(&show::records(&rs, self.cols));
            }
            Some(Err(e)) => self.error(&e),
            None => {
                let mut best: Option<(usize, String)> = None;
                for n in self.command_names() {
                    let d = distance(name, &n);
                    let near = if name.chars().count() >= 5 { 2 } else { 1 };
                    if d <= near && best.as_ref().is_none_or(|(bd, _)| d < *bd) {
                        best = Some((d, n));
                    }
                }
                match best {
                    Some((_, n)) => self.error(&format!("unknown command '{}' — did you mean '{}'?", name, n)),
                    None => self.error(&format!("unknown command '{}' (type help for the commands)", name)),
                }
            }
        }
    }

    /// Every command name and alias (built-ins, tools, filters).
    pub fn command_names(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for c in cmds::BUILTINS {
            v.push(String::from(c.name));
            v.extend(c.aliases.iter().map(|a| String::from(*a)));
        }
        for t in &self.tools {
            v.push(t.name.clone());
            v.extend(t.aliases.iter().cloned());
        }
        v.extend(filter::NAMES.iter().map(|n| String::from(*n)));
        v.push(String::from("run"));
        v.push(String::from("start"));
        v
    }

    /// Tab: candidates for the last word of `before`.
    fn complete(&self, before: &str) -> Vec<String> {
        let (start, word) = parse::last_word(before);
        let mut out: Vec<String> = Vec::new();
        if parse::is_command_position(before, start) {
            let after_pipe = before[..start].trim_end().ends_with('|');
            for n in self.command_names() {
                if n.starts_with(word) && (!after_pipe || filter::is_filter(&n)) && !out.contains(&n) {
                    out.push(n);
                }
            }
            out.sort();
            return out;
        }
        // A path: the directory part as typed, then names in it.
        let (dir_typed, prefix) = match word.rfind('/') {
            Some(p) => (&word[..=p], &word[p + 1..]),
            None => ("", word),
        };
        let dir_abs = normalize(&self.place, if dir_typed.is_empty() { "." } else { dir_typed });
        if dir_abs == "/" {
            for p in &self.places {
                let n = &p.path[1..];
                if n.starts_with(prefix) {
                    out.push(format!("{}{}/", dir_typed, n));
                }
            }
        } else if let Ok((d, fp::KIND_DIR)) = self.open("", &dir_abs, fp::O_DIRECTORY, fp::R_READ) {
            let _ = d.list(|n, k| {
                if let Ok(n) = core::str::from_utf8(n)
                    && n.starts_with(prefix)
                    && out.len() < 200
                {
                    out.push(format!("{}{}{}", dir_typed, n, if k == fp::KIND_DIR { "/" } else { "" }));
                }
            });
        }
        out.sort();
        out
    }

    // ---- events ----------------------------------------------------------------------------------

    fn term_msg(&mut self, buf: &[u8]) {
        let Some(h) = Header::get(buf) else { return };
        let payload = &buf[HEADER..];
        if h.op != term::SIZE && self.notices.take().is_some() {
            println!("shell: a key arrived; keyboard notices are no longer shown");
        }
        match h.op {
            term::SIZE => self.cols = (h.a as usize).clamp(20, 400),
            term::LINE => {
                self.reading = false;
                if h.a == 0 {
                    let line = String::from_utf8_lossy(payload).into_owned();
                    self.run_line(&line);
                }
                if self.fg.is_none() && !self.reading && self.term != 0 {
                    self.prompt();
                }
            }
            term::INTERRUPT => self.interrupt(),
            term::COMPLETE => {
                let before = String::from_utf8_lossy(payload).into_owned();
                let c = self.complete(&before);
                let mut p: Vec<u8> = Vec::new();
                for s in c {
                    p.extend_from_slice(s.as_bytes());
                    p.push(0);
                }
                self.send(term::COMPLETIONS, 0, &p);
            }
            _ => {}
        }
    }

    /// Start showing keyboard notices (until the first key).
    fn start_notices(&mut self) {
        if self.log == 0 || self.notices.is_some() {
            return;
        }
        if let Ok(t) = libd::Timer::new() {
            t.set(NOTICES_EVERY);
            self.port.arm(t.0.raw(), sys::SIGNALED, KEY_NOTICES);
            self.notices = Some((t, 0));
        }
    }

    /// New log records about keyboards (the keyboard drivers, lines that mention a keyboard) and
    /// every warning or error, shown dimmed above the prompt.
    fn show_notices(&mut self) {
        let Some((t, mut seq)) = self.notices.take() else { return };
        let mut out = String::new();
        while self.notices_shown < NOTICES_MAX {
            let Ok(b) = libd::log::read(self.log, seq, libd::log::MAX_PER_READ, false, 500_000_000) else { break };
            for r in &b.records[..b.count] {
                let src = String::from_utf8_lossy(r.source()).into_owned();
                let text = String::from_utf8_lossy(r.text()).trim_end().to_string();
                // The terminal's own mirrored lines (`mirror`) are what is shown: never shown again.
                let echo = src == "terminal" && text.starts_with("terminal|");
                let about_keys = matches!(src.as_str(), "xhci" | "ps2" | "virtio-input") || text.contains("keyboard");
                if !echo && (about_keys || u32::from(r.level) <= sys::LOG_WARN) && self.notices_shown < NOTICES_MAX {
                    out.push_str(&show::coloured(term::DARK_GREY, &format!("  · {}\n", text)));
                    self.notices_shown += 1;
                }
            }
            if b.count == 0 || b.next <= seq {
                break;
            }
            seq = b.next;
        }
        if !out.is_empty() {
            self.write(&out);
        }
        if self.notices_shown < NOTICES_MAX {
            t.set(NOTICES_EVERY);
            self.port.arm(t.0.raw(), sys::SIGNALED, KEY_NOTICES);
            self.notices = Some((t, seq));
        }
    }

    fn welcome(&mut self) {
        let now = if self.clock != 0 { libd::time::query(self.clock).map_or(0, |b| b.now().0) } else { 0 };
        let when = if now != 0 { format!(" · {}", show::time(now)) } else { String::new() };
        self.write(&format!("{}D-OS{} · terminal 1{}{}\n", show::style(term::WHITE), show::plain(), when, " UTC"));
        self.write(&show::coloured(term::DARK_GREY, "Type help for the commands. Tab completes, Up/Down recall, PgUp/PgDn scroll.\n"));
    }

    pub fn clear(&self) {
        self.send(term::CLEAR, 0, &[]);
    }

    pub fn self_process() -> Handle {
        libd::startup_handle(sys::TAG_PROC_SELF)
    }

    /// Re-scope the shell's `/home` place to the active identity's private directory (`home:/<name>`)
    /// when a dedicated `/home` volume is mounted, and restrict `/data` to Operator identities.
    pub fn refresh_home_scope(&mut self) {
        if self.home_vol == 0 {
            return;
        }
        let ep = if self.identity_query != 0 { self.identity_query } else { self.identity_admin };
        let (name, role) = if ep != 0
            && let Ok(a) = libd::identity::active(ep)
        {
            (String::from(a.name_str()), a.role)
        } else {
            (String::from("user"), libd::identity::ROLE_OPERATOR)
        };
        let d = borrow(self.home_vol);
        let opened = if (self.home_rights & fp::R_WRITE) != 0 {
            d.open(name.as_bytes(), fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE).ok()
        } else {
            d.open(name.as_bytes(), fp::O_DIRECTORY, fp::R_READ).ok()
        };
        if let Some((node, _, _)) = opened {
            let new_h = node.into_handle();
            if self.scoped_home_handle != 0 {
                sys::handle_close(self.scoped_home_handle);
            }
            self.scoped_home_handle = new_h;
            if let Some(p) = self.places.iter_mut().find(|p| p.path == "/home") {
                p.h = new_h;
                p.rights = self.home_rights;
            }
        }
        if role == libd::identity::ROLE_STANDARD {
            self.places.retain(|p| p.path != "/data");
            if self.place == "/data" || self.place.starts_with("/data/") {
                self.place = String::from("/home");
            }
        } else if self.data_vol != 0 && !self.places.iter().any(|p| p.path == "/data") {
            self.places.push(Place { path: String::from("/data"), h: self.data_vol, rights: self.data_rights });
            self.places.sort_by(|a, b| a.path.cmp(&b.path));
        }
        if self.place.starts_with("/home/") {
            self.place = String::from("/home");
        }
    }

    pub fn has_home_volume(&self) -> bool {
        self.home_vol != 0
    }

    pub fn home_dot_dos_read(&self, leaf: &[u8]) -> Option<Vec<u8>> {
        if self.home_vol == 0 {
            return None;
        }
        let d = borrow(self.home_vol);
        let (cfg_dir, _, _) = d.open(b".dos", fp::O_DIRECTORY, fp::R_READ).ok()?;
        let (f, _, size) = cfg_dir.open(leaf, 0, fp::R_READ).ok()?;
        let size = usize::try_from(size).ok()?;
        if size == 0 || size > 64 * 1024 {
            return None;
        }
        let mut buf = alloc::vec![0u8; size];
        let n = f.read(0, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    pub fn home_dot_dos_write(&self, leaf: &[u8], data: &[u8]) -> Result<(), String> {
        if self.home_vol == 0 {
            return Err(String::from("setup: no dedicated /home volume is mounted (running on live media?)"));
        }
        if (self.home_rights & fp::R_WRITE) == 0 {
            return Err(String::from("setup: /home is read-only in this session"));
        }
        let ep = if self.identity_query != 0 { self.identity_query } else { self.identity_admin };
        if ep != 0
            && let Ok(a) = libd::identity::active(ep)
            && a.role != libd::identity::ROLE_OPERATOR
        {
            return Err(String::from("setup: only an Operator identity may modify system setup configuration"));
        }
        let d = borrow(self.home_vol);
        let (cfg_dir, _, _) = d
            .open(b".dos", fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)
            .map_err(|e| format!("setup: cannot open /home/.dos ({})", fp::message(e)))?;
        let (f, _, _) = cfg_dir
            .open(leaf, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            .map_err(|e| format!("setup: cannot open config file ({})", fp::message(e)))?;
        f.write(0, data).map_err(|e| format!("setup: write failed ({})", fp::message(e)))?;
        drop(f);
        let _ = cfg_dir.sync();
        let _ = d.sync();
        Ok(())
    }
}

pub fn rights_word(r: u64) -> &'static str {
    if r & fp::R_WRITE != 0 { "read-write" } else { "read" }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "shell") } {
        return 1;
    }
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(port) = Port::new(128) else { return 1 };
    // The places: every granted directory, with its rights.
    let mut places: Vec<Place> = Namespace::get()
        .entries()
        .map(|(p, h)| Place { path: String::from_utf8_lossy(p).into_owned(), h, rights: borrow(h).stat().map_or(fp::R_READ, |st| st.rights) })
        .collect();
    places.sort_by(|a, b| a.path.cmp(&b.path));
    let home_vol = places.iter().find(|p| p.path == "/home").map_or(0, |p| p.h);
    let home_rights = places.iter().find(|p| p.path == "/home").map_or(0, |p| p.rights);
    let data_vol = places.iter().find(|p| p.path == "/data").map_or(0, |p| p.h);
    let data_rights = places.iter().find(|p| p.path == "/data").map_or(0, |p| p.rights);
    // The tools: their manifests (handed over by the service manager).
    let mut tools: Vec<Tool> = Vec::new();
    for (h, t) in libd::startup_handles() {
        if t != tool::TAG_TOOL_MANIFEST {
            continue;
        }
        let size = sys::vmo_size(h).unwrap_or(0).min(dman::toml::MAX_SIZE as u64) as usize;
        let mut b = alloc::vec![0u8; size];
        if sys::vmo_read(h, 0, &mut b) != 0 {
            continue;
        }
        while b.last() == Some(&0) {
            b.pop();
        }
        match dman::tool::parse(&b) {
            Ok(t) if !cmds::BUILTINS.iter().any(|c| c.name == t.name || c.aliases.contains(&t.name.as_str())) => tools.push(t),
            Ok(t) => println!("shell: tool {} left out: a built-in command has that name", t.name),
            Err(e) => println!("shell: a tool manifest is not valid: {}", e),
        }
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    let mut sh = Shell {
        term: svc::endpoint(b"terminal.session"),
        cols: 80,
        places,
        place: String::from("/"),
        tools,
        mgr: libd::startup_handle(tool::TAG_MANAGER),
        log: svc::endpoint(b"log.read"),
        clock: svc::endpoint(b"clock.time"),
        audio_play: svc::endpoint(b"audio.playback"),
        audio_ctl: svc::endpoint(b"audio.control"),
        net_client: svc::endpoint(b"net.client"),
        net_icmp: svc::endpoint(b"net.icmp"),
        net_ctl: svc::endpoint(b"net.control"),
        gpu_query: svc::endpoint(b"gpu.query"),
        awmi_admin: svc::endpoint(b"awmi.admin"),
        awmi_query: svc::endpoint(b"awmi.query"),
        identity_admin: svc::endpoint(b"identity.admin"),
        identity_query: svc::endpoint(b"identity.query"),
        appmgr_admin: svc::endpoint(b"appmgr.admin"),
        appmgr_query: svc::endpoint(b"appmgr.query"),
        storaged_admin: svc::endpoint(b"storaged.admin"),
        home_vol,
        home_rights,
        scoped_home_handle: 0,
        data_vol,
        data_rights,
        jobs: Vec::new(),
        next_job: 1,
        fg: None,
        port,
        reading: false,
        notices: None,
        notices_shown: 0,
    };
    if sh.clock != 0
        && let Some(b) = libd::time::query(sh.clock)
    {
        libd::time::set_base(&b);
    }
    sh.refresh_home_scope();
    if sh.places.iter().any(|p| p.path == "/home") {
        sh.place = String::from("/home");
    }
    let names: Vec<String> = sh.places.iter().map(|p| format!("{} ({})", p.path, rights_word(p.rights))).collect();
    println!("shell: ready: {} place(s): {}; {} tool(s)", sh.places.len(), names.join(", "), sh.tools.len());
    if ctl != 0 {
        sh.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if sh.term != 0 {
        sh.port.arm(sh.term, sys::READABLE | sys::PEER_CLOSED, KEY_TERM);
        sh.welcome();
        sh.start_notices();
        sh.prompt();
    }
    let mut buf = alloc::vec![0u8; 64 * 1024];
    loop {
        let Some((key, _)) = sh.port.wait(sys::WAIT_FOREVER) else { continue };
        match key & 0xFF {
            KEY_TERM => loop {
                match sys::channel_read(sh.term, &mut buf, 0) {
                    Ok(n) => {
                        let m = buf[..n as usize].to_vec();
                        sh.term_msg(&m);
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        sh.port.arm(sh.term, sys::READABLE | sys::PEER_CLOSED, KEY_TERM);
                        break;
                    }
                    Err(_) => {
                        // The terminal is gone; the service manager connects us to the next one.
                        sys::handle_close(sh.term);
                        sh.term = 0;
                        break;
                    }
                }
            },
            KEY_JOB_OUT => sh.job_output((key >> 8) as u32),
            KEY_JOB_END => sh.job_ended((key >> 8) as u32),
            KEY_NOTICES => sh.show_notices(),
            _ => loop {
                let mut hs = [0 as Handle; 1];
                match sys::channel_read_h(ctl, &mut buf, &mut hs, 0) {
                    Ok((n, nh)) => {
                        let handle = if nh > 0 { hs[0] } else { 0 };
                        match Header::get(&buf[..n]) {
                            Some(h) if h.op == svc::CONNECT && handle != 0 => {
                                let which = &buf[HEADER..n];
                                let slot = match which {
                                    b"terminal.session" => &mut sh.term,
                                    b"log.read" => &mut sh.log,
                                    b"clock.time" => &mut sh.clock,
                                    b"audio.playback" => &mut sh.audio_play,
                                    b"audio.control" => &mut sh.audio_ctl,
                                    b"net.client" => &mut sh.net_client,
                                    b"net.icmp" => &mut sh.net_icmp,
                                    b"net.control" => &mut sh.net_ctl,
                                    b"gpu.query" => &mut sh.gpu_query,
                                    b"awmi.admin" => &mut sh.awmi_admin,
                                    b"awmi.query" => &mut sh.awmi_query,
                                    b"identity.admin" => &mut sh.identity_admin,
                                    b"identity.query" => &mut sh.identity_query,
                                    b"appmgr.admin" => &mut sh.appmgr_admin,
                                    b"appmgr.query" => &mut sh.appmgr_query,
                                    b"storaged.admin" => &mut sh.storaged_admin,
                                    _ => {
                                        sys::handle_close(handle);
                                        continue;
                                    }
                                };
                                if *slot != 0 {
                                    sys::handle_close(*slot);
                                }
                                *slot = handle;
                                if which == b"terminal.session" {
                                    sh.port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_TERM);
                                    sh.welcome();
                                    if sh.fg.is_none() {
                                        sh.prompt();
                                    }
                                }
                            }
                            Some(h) if h.op == svc::SHUTDOWN => {
                                for j in &sh.jobs {
                                    sys::process_kill(j.proc.raw());
                                }
                                return 0;
                            }
                            _ => {
                                if handle != 0 {
                                    sys::handle_close(handle);
                                }
                            }
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        sh.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                        break;
                    }
                    Err(_) => break,
                }
            },
        }
    }
}
