//! D-OS System Monitor (`sysmon.dapp`).
//!
//! Read-only system observability over explicit capability handles:
//! - Services, memory/quota usage, and per-service handle inspector via read-only `TAG_MANAGER`
//!   (`manager.services-ro`: only `MGR_LIST` and `MGR_OBJECTS` are permitted).
//! - Installed & running `.dapp` bundles via `appmgr.query`.
//! - Filtered system log viewer via `log.read`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosapp::format_perm_mask;
use dosui::{Length, Node, Tone, button, caption, column, divider, heading, item, label, mono, panel, progress, row, scroll, spacer, text};
use libd::appmgr::{self, AppInfo, MAX_APPS};
use libd::proto::{HEADER, Header};
use libd::rec::{self, Record, Value};
use libd::sys::{self, Handle};
use libd::{Startup, svc, tool};

use crate::common::{App, run_app};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Services,
    Apps,
    Log,
}

#[derive(Clone)]
enum Msg {
    SelectTab(Tab),
    Refresh,
    SelectService(usize),
    LogFilter(u8),
}

struct SvcRow {
    name: String,
    state: String,
    mem: u64,
    quota: u64,
    handles: i64,
    restarts: i64,
}

struct ObjRow {
    ty: String,
    name: String,
    rights: String,
}

struct LogRow {
    level: u8,
    source: String,
    text: String,
}

struct SysMonApp {
    tab: Tab,
    mgr: Handle,
    log_ep: Handle,
    app_q: Handle,
    svcs: Vec<SvcRow>,
    sel_svc: Option<usize>,
    objs: Vec<ObjRow>,
    apps: Vec<AppInfo>,
    logs: Vec<LogRow>,
    log_max_level: u8,
}

fn rec_str(r: &Record, key: &str) -> String {
    match r.get(key) {
        Some(Value::Text(s) | Value::Path(s)) => s.clone(),
        _ => String::new(),
    }
}

fn rec_u64(r: &Record, key: &str) -> u64 {
    match r.get(key) {
        Some(Value::Size(n)) => *n,
        Some(Value::Int(n)) => (*n).max(0) as u64,
        _ => 0,
    }
}

fn rec_i64(r: &Record, key: &str) -> i64 {
    match r.get(key) {
        Some(Value::Int(n)) => *n,
        _ => 0,
    }
}

impl SysMonApp {
    fn new() -> Self {
        let mut s = Self {
            tab: Tab::Overview,
            mgr: libd::startup_handle(tool::TAG_MANAGER),
            log_ep: svc::endpoint(b"log.read"),
            app_q: appmgr::query_endpoint(),
            svcs: Vec::new(),
            sel_svc: None,
            objs: Vec::new(),
            apps: Vec::new(),
            logs: Vec::new(),
            log_max_level: 3,
        };
        s.refresh_all();
        s
    }

    fn mgr_call(&self, op: u32, arg: &[u8]) -> Option<Vec<u8>> {
        if self.mgr == 0 {
            return None;
        }
        let mut req = alloc::vec![0u8; HEADER + arg.len()];
        Header { txid: 0, op, status: 0, a: 0, b: 0 }.put(&mut req);
        req[HEADER..].copy_from_slice(arg);
        let mut rep = alloc::vec![0u8; HEADER + rec::MAX_PAYLOAD];
        let n = sys::channel_call(self.mgr, &req, &mut rep, 5_000_000_000).ok()? as usize;
        let h = Header::get(&rep[..n])?;
        if h.status != 0 {
            return None;
        }
        Some(rep[HEADER..n].to_vec())
    }

    fn refresh_all(&mut self) {
        self.svcs.clear();
        if let Some(bytes) = self.mgr_call(svc::MGR_LIST, &[]) {
            for r in rec::decode_all(&bytes) {
                self.svcs.push(SvcRow {
                    name: rec_str(&r, "name"),
                    state: rec_str(&r, "state"),
                    mem: rec_u64(&r, "memory"),
                    quota: rec_u64(&r, "quota").max(1),
                    handles: rec_i64(&r, "handles"),
                    restarts: rec_i64(&r, "restarts"),
                });
            }
        }
        if let Some(i) = self.sel_svc {
            self.load_objects(i);
        }
        self.apps.clear();
        if self.app_q != 0 {
            let mut buf = [AppInfo::default(); MAX_APPS];
            if let Ok(n) = appmgr::list(self.app_q, &mut buf) {
                self.apps.extend_from_slice(&buf[..n]);
            }
        }
        self.logs.clear();
        if self.log_ep != 0 {
            let mut from = 0u64;
            let mut all: Vec<LogRow> = Vec::new();
            for _ in 0..8 {
                let Ok(b) = libd::log::read(self.log_ep, from, libd::log::MAX_PER_READ, false, 1_000_000_000) else {
                    break;
                };
                for r in &b.records[..b.count] {
                    all.push(LogRow {
                        level: r.level,
                        source: String::from_utf8_lossy(r.source()).into_owned(),
                        text: String::from_utf8_lossy(r.text()).trim_end().into(),
                    });
                }
                if b.count == 0 || b.next <= from {
                    break;
                }
                from = b.next;
            }
            let keep = all.len().saturating_sub(80);
            self.logs = all.split_off(keep);
        }
    }

    fn load_objects(&mut self, idx: usize) {
        self.objs.clear();
        let Some(s) = self.svcs.get(idx) else { return };
        if let Some(bytes) = self.mgr_call(svc::MGR_OBJECTS, s.name.as_bytes()) {
            for r in rec::decode_all(&bytes) {
                self.objs.push(ObjRow {
                    ty: rec_str(&r, "type"),
                    name: rec_str(&r, "name"),
                    rights: rec_str(&r, "rights"),
                });
            }
        }
    }

    fn view_overview(&self) -> Node<Msg> {
        let up = sys::clock_ns() / 1_000_000_000;
        let running_svcs = self.svcs.iter().filter(|s| s.state == "running").count();
        let total_mem: u64 = self.svcs.iter().map(|s| s.mem).sum();
        let running_apps: u32 = self.apps.iter().map(|a| u32::from(a.running)).sum();
        column([
            heading("System Overview"),
            panel([
                label(format!("Uptime: {} min {:02} s", up / 60, up % 60)),
                text(format!("Services: {} running / {} total", running_svcs, self.svcs.len())),
                text(format!("Service memory accounted: {} MiB", total_mem >> 20)),
                text(format!("Verified .dapp apps: {} installed, {} running", self.apps.len(), running_apps)),
                caption("System Monitor holds read-only capabilities only and cannot terminate services."),
            ]),
        ])
        .gap(10)
    }

    fn view_services(&self) -> Node<Msg> {
        let mut rows: Vec<Node<Msg>> = alloc::vec![label("System Services")];
        for (i, s) in self.svcs.iter().enumerate() {
            let pct = ((s.mem.saturating_mul(1000)) / s.quota.max(1)).min(1000) as u16;
            rows.push(
                item(format!("{} [{}]", s.name, s.state), self.sel_svc == Some(i))
                    .detail(format!("{} KiB | {} h", s.mem >> 10, s.handles))
                    .on_select(Msg::SelectService(i)),
            );
            if self.sel_svc == Some(i) {
                rows.push(
                    row([
                        caption(format!("Memory quota ({} KiB / {} MiB, {} restarts)", s.mem >> 10, s.quota >> 20, s.restarts)),
                        spacer(),
                        progress(pct).width(Length::Px(140)),
                    ])
                    .gap(8),
                );
            }
        }
        let mut handle_rows: Vec<Node<Msg>> = alloc::vec![label("Service Handles (read-only inspection)")];
        if self.sel_svc.is_none() {
            handle_rows.push(caption("Select a service to inspect its kernel capability handles."));
        } else if self.objs.is_empty() {
            handle_rows.push(caption("No handles reported."));
        } else {
            for o in self.objs.iter().take(24) {
                handle_rows.push(mono(format!("{:<10} {:<10} {}", o.ty, o.rights, o.name)));
            }
        }
        column([heading("Services & Capability Handles"), panel(rows), panel(handle_rows)]).gap(10)
    }

    fn view_apps(&self) -> Node<Msg> {
        let mut rows: Vec<Node<Msg>> = alloc::vec![label("Verified Applications")];
        for a in &self.apps {
            rows.push(
                item(format!("{} v{}", a.title_str(), a.version_str()), a.running > 0)
                    .detail(format!("{} running", a.running)),
            );
            rows.push(caption(format!("  perms: {}", format_perm_mask(a.effective_perms))));
        }
        column([heading("Applications"), panel(rows)]).gap(10)
    }

    fn view_log(&self) -> Node<Msg> {
        let filter_bar = row([
            button("All").on_press(Msg::LogFilter(3)),
            button("Info+").on_press(Msg::LogFilter(2)),
            button("Warn+").on_press(Msg::LogFilter(1)),
            button("Errors").on_press(Msg::LogFilter(0)),
            spacer(),
            caption(format!("{} recent record(s)", self.logs.len())),
        ])
        .gap(8);
        let mut lines: Vec<Node<Msg>> = Vec::new();
        for l in self.logs.iter().rev() {
            if l.level <= self.log_max_level {
                let tag = match l.level {
                    0 => "ERR",
                    1 => "WRN",
                    2 => "INF",
                    _ => "DBG",
                };
                let tone = match l.level {
                    0 => Tone::Danger,
                    1 => Tone::Accent,
                    _ => Tone::Primary,
                };
                lines.push(mono(format!("[{}] {}: {}", tag, l.source, l.text)).tone(tone).wrap());
            }
        }
        column([heading("System Log"), filter_bar, panel(lines)]).gap(8)
    }
}

impl App for SysMonApp {
    type Msg = Msg;

    fn title(&self) -> &str {
        "System Monitor"
    }

    fn size(&self) -> (u32, u32) {
        (840, 560)
    }

    fn tick(&mut self) -> bool {
        self.refresh_all();
        true
    }

    fn view(&self) -> Node<Msg> {
        let sidebar = panel([
            heading("Monitor"),
            item("Overview", self.tab == Tab::Overview).on_select(Msg::SelectTab(Tab::Overview)),
            item("Services", self.tab == Tab::Services).on_select(Msg::SelectTab(Tab::Services)),
            item("Applications", self.tab == Tab::Apps).on_select(Msg::SelectTab(Tab::Apps)),
            item("System Log", self.tab == Tab::Log).on_select(Msg::SelectTab(Tab::Log)),
            spacer(),
            button("Refresh").on_press(Msg::Refresh),
        ])
        .width(Length::Px(170))
        .height(Length::Fill);

        let body = match self.tab {
            Tab::Overview => self.view_overview(),
            Tab::Services => self.view_services(),
            Tab::Apps => self.view_apps(),
            Tab::Log => self.view_log(),
        };

        column([
            row([sidebar, scroll(body.padding(4)).fill()]).gap(12).fill(),
            divider(),
            caption("D-OS System Monitor (read-only observability)"),
        ])
        .padding(12)
        .gap(8)
        .fill()
    }

    fn update(&mut self, msg: Msg) {
        match msg {
            Msg::SelectTab(t) => {
                self.tab = t;
                self.refresh_all();
            }
            Msg::Refresh => self.refresh_all(),
            Msg::SelectService(i) => {
                self.sel_svc = Some(i);
                self.load_objects(i);
            }
            Msg::LogFilter(lvl) => self.log_max_level = lvl,
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "sysmon") } {
        return 1;
    }
    run_app("sysmon", SysMonApp::new(), 2000)
}
