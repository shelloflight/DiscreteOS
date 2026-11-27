//! DiscreteOS Unified Installer & First-Boot Setup (`oobe.dapp`).
//!
//! One guided window covering the entire live-media installation and first-boot setup flow:
//! 1. Welcome menu (Install DiscreteOS or Try Live Desktop)
//! 2. Installation prompts (target drive, partition manager, Dual Boot / Whole Disk / Wipe & Repartition, execute)
//! 3. Language & Keyboard layout (live-applied across all keyboard drivers & UI, with interactive test box)
//! 4. Timezone (live-applied to desktop clock)
//! 5. Optional Network Setup (Set Up Later / Automatic DHCP / Static IPv4 + DNS)
//! 6. Optional Local Account Creation (no root; TPM 2.0 SRK or software AEAD sealing; optional passphrase)
//! 7. Unplug USB & Reboot (persists config directly to target disk with always-on login screen + Reboot Now button)
//!
//! When launched on a CLI-installed disk whose `/config/oobe.toml` still has `completed = false`,
//! starts directly at Step 3 (Language & Keyboard) and persists to `/config/oobe.toml`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosid::{
    KEYBOARDS, KeyboardLayout, L10n, LANGUAGES, Language, NetworkSettings, OobeConfig, TIMEZONES,
    timezone_offset_minutes,
};
use dosui::{
    Length, Node, Tone, button, caption, column, divider, heading, input, item, label, mono, panel,
    row, scroll, spacer, text, toggle,
};
use libd::awmi;
use libd::fs::{self as fp, Namespace};
use libd::identity;
use libd::install::{
    self, DiskSummary, MAX_DISKS, MODE_DUAL_BOOT, MODE_WHOLE_DISK, MODE_WIPE_DISK,
};
use libd::net::{self, NetConfig, NetStatus};
use libd::proto::{HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Startup, println, svc, tool};

use crate::common::{App, run_app};

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let mut out = [0u8; 4];
    let mut n = 0usize;
    for part in t.split('.') {
        if n >= 4 || part.is_empty() || part.len() > 3 {
            return None;
        }
        out[n] = part.parse::<u8>().ok()?;
        n += 1;
    }
    (n == 4).then_some(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Welcome,
    Install,
    Locale,
    Timezone,
    Network,
    Account,
    Finish,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NetChoice {
    Skip,
    Dhcp,
    Static,
}

#[derive(Clone)]
enum Msg {
    StartInstall,
    TryLive,
    RefreshDisks,
    SelectDisk(usize),
    SelectPart(u32),
    SelectMode(u8),
    ToggleConfirmDelete,
    DeleteSelectedPart,
    ToggleConfirmWipe,
    PreviewPlan,
    RunInstall,
    SelectLang(usize),
    SelectKbd(usize),
    KbdTest(String),
    SelectTz(usize),
    SelectNet(NetChoice),
    NetIp(String),
    NetMask(String),
    NetGw(String),
    NetDns(String),
    UserName(String),
    DisplayName(String),
    Passphrase(String),
    ToggleOperator,
    Back,
    Next,
    SkipAccount,
    CompleteSetup,
    RebootNow,
}

struct SetupApp {
    /// True when booted from an already-installed disk (writable `/config` mounted by `appmgr`).
    installed_mode: bool,
    step: Step,

    // Disk installer state (live mode)
    install_ep: Handle,
    disks: Vec<DiskSummary>,
    sel_disk: usize,
    sel_part: Option<u32>,
    mode: u8,
    confirm_delete: bool,
    confirm_wipe: bool,
    plan_text: String,
    plan_ok: bool,
    installed_disk: Option<String>,
    install_summary: String,

    // Locale, keyboard & timezone state
    lang_idx: usize,
    kbd_idx: usize,
    kbd_test: String,
    tz_idx: usize,

    // Network state
    net_choice: NetChoice,
    net_ip: String,
    net_mask: String,
    net_gw: String,
    net_dns: String,
    net_status: Option<NetStatus>,

    // Account state
    username: String,
    display_name: String,
    passphrase: String,
    is_operator: bool,

    // General & capabilities
    status: String,
    done: bool,
    rebooting: bool,
    awmi_admin: Handle,
    id_admin: Handle,
    net_st_ep: Handle,
    net_ctl_ep: Handle,
    power_mgr: Handle,
}

fn config_is_writable() -> bool {
    let ns = Namespace::get();
    let Some((dir, _)) = ns.resolve(b"/config") else {
        return false;
    };
    let d = fp::Node::from(dir);
    let writable = d.stat().is_ok_and(|st| (st.rights & fp::R_WRITE) != 0);
    let _ = d.into_handle();
    writable
}

fn load_oobe_config() -> OobeConfig {
    let ns = Namespace::get();
    let Some((dir, _)) = ns.resolve(b"/config") else {
        return OobeConfig::default();
    };
    let d = fp::Node::from(dir);
    let parsed = (|| {
        let (f, _, size) = d.open(b"oobe.toml", 0, fp::R_READ).ok()?;
        let size = usize::try_from(size).ok()?;
        if size == 0 || size > 16 * 1024 {
            return None;
        }
        let mut buf = alloc::vec![0u8; size];
        let n = f.read(0, &mut buf).ok()?;
        OobeConfig::from_toml(&buf[..n]).ok()
    })();
    let _ = d.into_handle();
    parsed.unwrap_or_default()
}

fn save_oobe_config_local(cfg: &OobeConfig) -> Result<(), i64> {
    let ns = Namespace::get();
    let Some((dir, _)) = ns.resolve(b"/config") else {
        return Err(fp::ERR_NOT_FOUND);
    };
    let d = fp::Node::from(dir);
    let res = (|| {
        let text = cfg.to_toml();
        let (f, _, _) = d.open(b"oobe.toml", fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)?;
        f.write(0, text.as_bytes())?;
        drop(f);
        let _ = d.sync();
        Ok(())
    })();
    let _ = d.into_handle();
    res
}

impl SetupApp {
    fn new() -> Self {
        let installed_mode = config_is_writable();
        let cfg = load_oobe_config();
        let lang_idx = LANGUAGES.iter().position(|(c, _)| *c == cfg.language).unwrap_or(0);
        let kbd_idx = KEYBOARDS.iter().position(|(c, _)| *c == cfg.keyboard).unwrap_or(0);
        let tz_idx = TIMEZONES.iter().position(|(z, _)| *z == cfg.timezone).unwrap_or(0);
        let net_st_ep = net::status_endpoint();
        let net_ctl_ep = net::control_endpoint();
        let net_status = if net_st_ep != 0 { net::status(net_st_ep).ok() } else { None };
        let install_ep = install::admin_endpoint();
        let awmi_admin = awmi::admin_endpoint();
        let id_admin = identity::admin_endpoint();
        let power_mgr = libd::startup_handle(tool::TAG_MANAGER);
        let mut app = Self {
            installed_mode,
            step: if installed_mode { Step::Locale } else { Step::Welcome },
            install_ep,
            disks: Vec::new(),
            sel_disk: 0,
            sel_part: None,
            mode: MODE_DUAL_BOOT,
            confirm_delete: false,
            confirm_wipe: false,
            plan_text: String::new(),
            plan_ok: false,
            installed_disk: None,
            install_summary: String::new(),
            lang_idx,
            kbd_idx,
            kbd_test: String::new(),
            tz_idx,
            net_choice: NetChoice::Skip,
            net_ip: String::new(),
            net_mask: String::from("255.255.255.0"),
            net_gw: String::new(),
            net_dns: String::from("1.1.1.1"),
            net_status,
            username: String::new(),
            display_name: String::new(),
            passphrase: String::new(),
            is_operator: true,
            status: String::new(),
            done: false,
            rebooting: false,
            awmi_admin,
            id_admin,
            net_st_ep,
            net_ctl_ep,
            power_mgr,
        };
        if !installed_mode {
            app.refresh_disks();
        }
        app
    }

    fn lang(&self) -> Language {
        Language::from_id(self.lang_idx as u8)
    }

    fn kbd(&self) -> KeyboardLayout {
        KeyboardLayout::from_id(self.kbd_idx as u8)
    }

    fn l10n(&self) -> &'static L10n {
        L10n::for_lang(self.lang())
    }

    fn apply_locale_live(&self) {
        if self.awmi_admin != 0 {
            let tz_min = timezone_offset_minutes(TIMEZONES[self.tz_idx].0) as i16;
            let _ = awmi::set_locale(self.awmi_admin, self.lang().id(), self.kbd().id(), tz_min);
        }
    }

    fn selected_disk(&self) -> Option<&DiskSummary> {
        self.disks.get(self.sel_disk)
    }

    fn auto_pick_mode(&mut self) {
        self.confirm_wipe = false;
        self.confirm_delete = false;
        self.sel_part = None;
        if let Some(d) = self.selected_disk() {
            self.mode = if d.is_blank() { MODE_WHOLE_DISK } else { MODE_DUAL_BOOT };
        }
    }

    fn refresh_disks(&mut self) {
        self.disks.clear();
        if self.install_ep == 0 {
            return;
        }
        let mut buf = [DiskSummary::default(); MAX_DISKS];
        match install::list_disks(self.install_ep, &mut buf) {
            Ok(n) => {
                self.disks.extend_from_slice(&buf[..n]);
                if self.sel_disk >= self.disks.len()
                    || self.disks[self.sel_disk].is_live_boot()
                    || self.disks[self.sel_disk].is_optical()
                {
                    if let Some(i) = self.disks.iter().position(|d| !d.is_live_boot() && !d.is_optical()) {
                        self.sel_disk = i;
                    } else {
                        self.sel_disk = 0;
                    }
                }
                self.auto_pick_mode();
                self.refresh_plan();
            }
            Err(e) => {
                self.status = format!("Failed to list disks: {}", sys::status(e));
            }
        }
    }

    fn refresh_plan(&mut self) {
        self.plan_text.clear();
        self.plan_ok = false;
        if self.install_ep == 0 {
            self.plan_text = String::from("storage:admin permission not granted (Operator identity required).");
            return;
        }
        let Some(d) = self.selected_disk() else {
            self.plan_text = String::from("No target disks detected.");
            return;
        };
        if d.is_live_boot() {
            self.plan_text = String::from("This disk is the active live boot media and cannot be overwritten.");
            return;
        }
        if d.is_optical() {
            self.plan_text = String::from("Optical CD-ROM media is read-only.");
            return;
        }
        let disk_name = String::from(d.name_str());
        let mut out = [0u8; 4096];
        match install::plan(self.install_ep, &disk_name, self.mode, self.confirm_wipe, &mut out) {
            Ok(n) => {
                self.plan_text = String::from_utf8_lossy(&out[..n]).into_owned();
                self.plan_ok = true;
            }
            Err((e, n)) => {
                self.plan_text = if n > 0 {
                    String::from_utf8_lossy(&out[..n]).into_owned()
                } else {
                    format!("Plan unavailable: {}", sys::status(e))
                };
                self.plan_ok = false;
            }
        }
    }

    fn build_oobe_config(&self, skipped: bool) -> OobeConfig {
        let net_mode = match self.net_choice {
            NetChoice::Skip => "skip",
            NetChoice::Dhcp => "dhcp",
            NetChoice::Static => "static",
        };
        OobeConfig {
            completed: true,
            skipped,
            language: String::from(LANGUAGES[self.lang_idx].0),
            keyboard: String::from(KEYBOARDS[self.kbd_idx].0),
            timezone: String::from(TIMEZONES[self.tz_idx].0),
            net_mode: String::from(net_mode),
            net_ip: self.net_ip.clone(),
            net_mask: self.net_mask.clone(),
            net_gw: self.net_gw.clone(),
            net_dns1: self.net_dns.clone(),
            net_dns2: String::new(),
        }
    }

    fn build_net_settings(&self) -> Result<Option<NetworkSettings>, String> {
        if self.net_choice == NetChoice::Skip {
            return Ok(None);
        }
        let dns1 = if self.net_dns.trim().is_empty() {
            [0; 4]
        } else {
            parse_ipv4(&self.net_dns).ok_or_else(|| String::from("Invalid DNS IPv4 address"))?
        };
        let cfg = match self.net_choice {
            NetChoice::Dhcp => NetworkSettings {
                dhcp: true,
                ip: [0; 4],
                netmask: [0; 4],
                gateway: [0; 4],
                dns1,
                dns2: [0; 4],
                dns_port: 53,
                dns_fallback: true,
            },
            NetChoice::Static => {
                let ip = parse_ipv4(&self.net_ip)
                    .filter(|&a| a != [0; 4])
                    .ok_or_else(|| String::from("Static IPv4 address is required"))?;
                let netmask = parse_ipv4(&self.net_mask)
                    .filter(|&m| m != [0; 4])
                    .ok_or_else(|| String::from("Invalid subnet mask"))?;
                let gateway = if self.net_gw.trim().is_empty() {
                    [0; 4]
                } else {
                    parse_ipv4(&self.net_gw).ok_or_else(|| String::from("Invalid gateway IPv4"))?
                };
                NetworkSettings {
                    dhcp: false,
                    ip,
                    netmask,
                    gateway,
                    dns1,
                    dns2: [0; 4],
                    dns_port: 53,
                    dns_fallback: true,
                }
            }
            NetChoice::Skip => return Ok(None),
        };
        Ok(Some(cfg))
    }

    fn apply_network(&mut self) -> Result<Option<NetworkSettings>, String> {
        let Some(ns) = self.build_net_settings()? else {
            return Ok(None);
        };
        if self.net_ctl_ep != 0 {
            let cfg = NetConfig {
                dhcp: ns.dhcp,
                ip: ns.ip,
                netmask: ns.netmask,
                gateway: ns.gateway,
                dns1: ns.dns1,
                dns2: ns.dns2,
                dns_port: ns.dns_port,
                dns_fallback: ns.dns_fallback,
            };
            net::set_config(self.net_ctl_ep, &cfg)
                .map_err(|e| format!("Network setup failed: {}", sys::status(e)))?;
        }
        Ok(Some(ns))
    }

    fn apply_account(&mut self, skip_create: bool) -> Result<String, String> {
        let mut pass = self.passphrase.as_bytes().to_vec();
        self.passphrase.clear();
        let wipe = |buf: &mut Vec<u8>| {
            buf.fill(0);
            core::hint::black_box(&*buf);
        };
        let uname = if skip_create { "" } else { self.username.trim() };

        // Always enable boot login screen regardless of whether a personal account was created.
        let enable_boot_login = |id_admin: Handle| {
            if id_admin != 0 {
                let pol = identity::policy(id_admin).unwrap_or_default();
                let _ = identity::set_policy(id_admin, pol.idle_timeout_secs, pol.lock_on_sleep, true);
            }
        };

        if uname.is_empty() {
            if !skip_create && !pass.is_empty() && self.id_admin != 0 {
                let res = identity::enroll(self.id_admin, 0, &pass);
                wipe(&mut pass);
                res.map_err(|e| format!("Passphrase enrollment failed: {}", sys::status(e)))?;
            } else {
                wipe(&mut pass);
            }
            enable_boot_login(self.id_admin);
            return Ok(String::new());
        }
        if uname.eq_ignore_ascii_case("root") {
            wipe(&mut pass);
            return Err(String::from("Refused: D-OS has no root user. Choose a personal account name."));
        }
        if self.id_admin == 0 {
            wipe(&mut pass);
            return Err(String::from("identity:admin permission not granted."));
        }
        let disp = if self.display_name.trim().is_empty() { uname } else { self.display_name.trim() };
        let role = if self.is_operator { identity::ROLE_OPERATOR } else { identity::ROLE_STANDARD };
        let uid = match identity::create(self.id_admin, uname, disp, role) {
            Ok(id) => id,
            Err(e) => {
                wipe(&mut pass);
                return Err(format!("Could not create account '{}': {}", uname, sys::status(e)));
            }
        };
        if !pass.is_empty() {
            let res = identity::enroll(self.id_admin, uid, &pass);
            if let Err(e) = res {
                wipe(&mut pass);
                return Err(format!("Passphrase enrollment failed: {}", sys::status(e)));
            }
            let _ = identity::switch_user(self.id_admin, uname, &pass);
            wipe(&mut pass);
        } else {
            let _ = identity::switch_user(self.id_admin, uname, b"");
        }
        enable_boot_login(self.id_admin);
        Ok(String::from(uname))
    }

    fn finalize_setup(&mut self, skip_account: bool) {
        self.apply_locale_live();
        let net_settings = match self.apply_network() {
            Ok(ns) => ns,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let extra_user = match self.apply_account(skip_account) {
            Ok(u) => u,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let oobe_cfg = self.build_oobe_config(false);
        let oobe_toml = oobe_cfg.to_toml();

        if let Some(target_disk) = self.installed_disk.clone() {
            let net_toml = net_settings.map_or_else(String::new, |ns| ns.to_toml());
            let mut id_buf = [0u8; 8192];
            let id_toml = if self.id_admin != 0 {
                match identity::export_store(self.id_admin, &mut id_buf) {
                    Ok(n) => String::from_utf8_lossy(&id_buf[..n]).into_owned(),
                    Err(_) => String::new(),
                }
            } else {
                String::new()
            };
            if let Err(e) = install::commit_oobe(
                self.install_ep,
                &target_disk,
                &oobe_toml,
                &net_toml,
                &id_toml,
                &extra_user,
            ) {
                self.status = format!("Failed to save setup onto {}: {}", target_disk, sys::status(e));
                return;
            }
            println!(
                "oobe: unified setup committed to {} (lang={}, kbd={}, tz={}, net={}, account={})",
                target_disk,
                oobe_cfg.language,
                oobe_cfg.keyboard,
                oobe_cfg.timezone,
                oobe_cfg.net_mode,
                if extra_user.is_empty() { "default" } else { &extra_user }
            );
            self.status = String::new();
            self.step = Step::Finish;
        } else {
            match save_oobe_config_local(&oobe_cfg) {
                Ok(()) => {
                    println!(
                        "oobe: first-boot setup completed (lang={}, kbd={}, tz={}, net={})",
                        oobe_cfg.language, oobe_cfg.keyboard, oobe_cfg.timezone, oobe_cfg.net_mode
                    );
                    self.done = true;
                }
                Err(e) => {
                    self.status = format!("Could not save setup state: {}", fp::message(e));
                }
            }
        }
    }

    fn trigger_reboot(&mut self) {
        if self.power_mgr == 0 {
            self.status = String::from("Please reboot manually (or run 'power restart' in Terminal).");
            return;
        }
        self.rebooting = true;
        self.status = String::from("Syncing disks and restarting...");
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: svc::MGR_POWER, status: 0, a: sys::POWER_REBOOT, b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER + 64];
        if let Err(e) = sys::channel_call(self.power_mgr, &req, &mut rep, 10_000_000_000) {
            self.rebooting = false;
            self.status = format!("Reboot request failed: {}", sys::status(e));
        }
    }

    fn view_welcome(&self) -> Node<Msg> {
        let l = self.l10n();
        let lang_pills: Vec<Node<Msg>> = LANGUAGES
            .iter()
            .enumerate()
            .map(|(i, (code, _))| {
                let b = if i == self.lang_idx { button(*code).primary() } else { button(*code) };
                b.on_press(Msg::SelectLang(i))
            })
            .collect();

        column([
            row([heading(l.welcome_heading), spacer(), row(lang_pills).gap(6)]).gap(12),
            caption(l.welcome_subtitle),
            divider(),
            row([
                panel([
                    heading(l.welcome_install_btn),
                    text(l.welcome_install_desc).wrap(),
                    spacer(),
                    button(l.welcome_install_btn).primary().on_press(Msg::StartInstall),
                ])
                .width(Length::Fill)
                .height(Length::Fill),
                panel([
                    heading(l.welcome_live_btn),
                    text(l.welcome_live_desc).wrap(),
                    spacer(),
                    button(l.welcome_live_btn).on_press(Msg::TryLive),
                ])
                .width(Length::Fill)
                .height(Length::Fill),
            ])
            .gap(14)
            .height(Length::Fill),
        ])
        .padding(18)
        .gap(12)
        .width(Length::Fill)
        .height(Length::Fill)
    }

    fn view_install(&self) -> Node<Msg> {
        let l = self.l10n();
        let mut disk_items: Vec<Node<Msg>> = Vec::new();
        for (i, d) in self.disks.iter().enumerate() {
            let tag = if d.is_live_boot() {
                " [Live]"
            } else if d.is_optical() {
                " [CD-ROM]"
            } else if d.is_blank() {
                " [Blank]"
            } else if d.has_gpt() {
                " [GPT]"
            } else if d.has_mbr() {
                " [MBR]"
            } else {
                ""
            };
            let title = format!("{} ({} MiB){}", d.name_str(), d.size_mib(), tag);
            disk_items.push(item(title, i == self.sel_disk).on_select(Msg::SelectDisk(i)));
        }
        if disk_items.is_empty() {
            disk_items.push(caption("No block devices detected."));
        }

        let left = panel([
            label(l.target_drives),
            caption("Live and optical media are protected."),
            divider(),
            scroll(column(disk_items).gap(4)).height(Length::Fill),
            divider(),
            button(l.refresh_drives).on_press(Msg::RefreshDisks),
        ])
        .width(Length::Px(250))
        .height(Length::Fill);

        let right = if let Some(d) = self.selected_disk() {
            let mut rows: Vec<Node<Msg>> = Vec::new();
            let tbl = if d.is_blank() {
                "Unpartitioned (blank)"
            } else if d.has_gpt() {
                "GPT"
            } else if d.has_mbr() {
                "Legacy MBR"
            } else {
                "Unknown"
            };
            rows.push(panel([
                label(format!(
                    "{} — {}",
                    d.name_str(),
                    if d.model_len > 0 { d.model_str() } else { "Block Device" }
                )),
                mono(format!(
                    "Capacity: {} MiB | Table: {} | Free: {} MiB (largest {} MiB)",
                    d.size_mib(),
                    tbl,
                    d.total_free_mib,
                    d.largest_free_mib
                )),
            ]));

            let mut part_nodes: Vec<Node<Msg>> = alloc::vec![label(format!("Existing Partitions ({})", d.part_count))];
            let parts = d.parts_slice();
            if parts.is_empty() {
                part_nodes.push(caption("No partitions on this drive."));
            } else {
                for p in parts {
                    let line = format!(
                        "#{}  {}  [{}]  {} MiB",
                        p.index,
                        if p.name_len > 0 { p.name_str() } else { "(unnamed)" },
                        p.fs_str(),
                        p.size_mib
                    );
                    part_nodes.push(item(line, self.sel_part == Some(p.index)).on_select(Msg::SelectPart(p.index)));
                }
                if !d.is_live_boot() && !d.is_optical() && d.has_gpt() {
                    part_nodes.push(divider());
                    let del_btn = if self.sel_part.is_some() && self.confirm_delete {
                        button("Delete Partition").danger().on_press(Msg::DeleteSelectedPart)
                    } else {
                        button("Delete Partition").danger()
                    };
                    part_nodes.push(
                        row([
                            toggle("Confirm partition deletion", self.confirm_delete).on_toggle(Msg::ToggleConfirmDelete),
                            spacer(),
                            del_btn,
                        ])
                        .gap(8),
                    );
                }
            }
            rows.push(panel(part_nodes));

            let dual_btn = if self.mode == MODE_DUAL_BOOT {
                button(l.mode_dual).primary()
            } else {
                button(l.mode_dual)
            }
            .on_press(Msg::SelectMode(MODE_DUAL_BOOT));
            let whole_btn = if self.mode == MODE_WHOLE_DISK {
                button(l.mode_whole).primary()
            } else {
                button(l.mode_whole)
            }
            .on_press(Msg::SelectMode(MODE_WHOLE_DISK));
            let wipe_btn = if self.mode == MODE_WIPE_DISK {
                button(l.mode_wipe).danger()
            } else {
                button(l.mode_wipe)
            }
            .on_press(Msg::SelectMode(MODE_WIPE_DISK));

            let mut mode_nodes: Vec<Node<Msg>> = alloc::vec![
                label(l.install_mode),
                row([dual_btn, whole_btn, wipe_btn]).gap(8),
            ];
            if self.mode == MODE_WIPE_DISK {
                mode_nodes.push(
                    toggle("I understand: wipe ALL existing partitions and data on this drive", self.confirm_wipe)
                        .on_toggle(Msg::ToggleConfirmWipe),
                );
            }
            rows.push(panel(mode_nodes));

            let mut plan_nodes: Vec<Node<Msg>> = alloc::vec![
                row([label(l.install_plan), spacer(), button("Re-check").on_press(Msg::PreviewPlan)]).gap(8),
            ];
            let shown = if !self.install_summary.is_empty() { &self.install_summary } else { &self.plan_text };
            for line in shown.lines() {
                plan_nodes.push(mono(line));
            }
            rows.push(panel(plan_nodes));

            let can_install = self.install_ep != 0
                && !d.is_live_boot()
                && !d.is_optical()
                && self.plan_ok
                && self.installed_disk.is_none()
                && (self.mode != MODE_WIPE_DISK || self.confirm_wipe);
            let base_btn = if self.mode == MODE_WIPE_DISK {
                button(l.wipe_and_install).danger()
            } else {
                button(l.install_now).primary()
            };
            let inst_btn = if can_install { base_btn.on_press(Msg::RunInstall) } else { base_btn };
            rows.push(row([spacer(), inst_btn]).gap(8));

            scroll(column(rows).gap(8)).width(Length::Fill).height(Length::Fill)
        } else {
            panel([caption("No target drive selected.")]).width(Length::Fill).height(Length::Fill)
        };

        row([left, right]).gap(12).height(Length::Fill)
    }

    fn view_locale(&self) -> Node<Msg> {
        let l = self.l10n();
        let lang_items: Vec<Node<Msg>> = LANGUAGES
            .iter()
            .enumerate()
            .map(|(i, (code, name))| item(format!("{} ({})", name, code), i == self.lang_idx).on_select(Msg::SelectLang(i)))
            .collect();
        let kbd_items: Vec<Node<Msg>> = KEYBOARDS
            .iter()
            .enumerate()
            .map(|(i, (code, name))| item(format!("{} ({})", name, code), i == self.kbd_idx).on_select(Msg::SelectKbd(i)))
            .collect();

        column([
            row([
                panel([label(l.lang_label), divider(), scroll(column(lang_items).gap(4)).height(Length::Fill)])
                    .width(Length::Fill)
                    .height(Length::Fill),
                panel([label(l.kbd_label), divider(), scroll(column(kbd_items).gap(4)).height(Length::Fill)])
                    .width(Length::Fill)
                    .height(Length::Fill),
            ])
            .gap(12)
            .height(Length::Fill),
            panel([
                row([label(l.kbd_test_label), spacer(), caption(self.kbd().sample_hint())]).gap(8),
                input(&self.kbd_test)
                    .placeholder(l.kbd_test_placeholder)
                    .width(Length::Fill)
                    .on_change(Msg::KbdTest),
            ]),
        ])
        .gap(10)
        .height(Length::Fill)
    }

    fn view_timezone(&self) -> Node<Msg> {
        let l = self.l10n();
        let tz_items: Vec<Node<Msg>> = TIMEZONES
            .iter()
            .enumerate()
            .map(|(i, (_, tz_label))| item(*tz_label, i == self.tz_idx).on_select(Msg::SelectTz(i)))
            .collect();
        panel([
            label(l.tz_heading),
            caption(l.tz_caption),
            divider(),
            scroll(column(tz_items).gap(4)).height(Length::Fill),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
    }

    fn view_network(&self) -> Node<Msg> {
        let l = self.l10n();
        let mut nodes: Vec<Node<Msg>> = alloc::vec![
            label(l.net_heading),
            caption(l.net_caption),
            row([
                if self.net_choice == NetChoice::Skip { button(l.net_skip).primary() } else { button(l.net_skip) }
                    .on_press(Msg::SelectNet(NetChoice::Skip)),
                if self.net_choice == NetChoice::Dhcp { button(l.net_dhcp).primary() } else { button(l.net_dhcp) }
                    .on_press(Msg::SelectNet(NetChoice::Dhcp)),
                if self.net_choice == NetChoice::Static { button(l.net_static).primary() } else { button(l.net_static) }
                    .on_press(Msg::SelectNet(NetChoice::Static)),
            ])
            .gap(8),
        ];
        if let Some(st) = self.net_status {
            nodes.push(mono(format!(
                "Interface: {} | IPv4: {}.{}.{}.{}",
                if st.name_len > 0 { st.name_str() } else { "none" },
                st.ip[0], st.ip[1], st.ip[2], st.ip[3]
            )));
        }
        if self.net_choice == NetChoice::Static {
            nodes.push(divider());
            nodes.push(row([caption("IPv4 Address").width(Length::Px(120)), input(&self.net_ip).placeholder("192.168.1.50").width(Length::Fill).on_change(Msg::NetIp)]).gap(8));
            nodes.push(row([caption("Subnet Mask").width(Length::Px(120)), input(&self.net_mask).placeholder("255.255.255.0").width(Length::Fill).on_change(Msg::NetMask)]).gap(8));
            nodes.push(row([caption("Gateway").width(Length::Px(120)), input(&self.net_gw).placeholder("192.168.1.1").width(Length::Fill).on_change(Msg::NetGw)]).gap(8));
        }
        if self.net_choice != NetChoice::Skip {
            nodes.push(row([caption("Primary DNS").width(Length::Px(120)), input(&self.net_dns).placeholder("1.1.1.1").width(Length::Fill).on_change(Msg::NetDns)]).gap(8));
        }
        panel(nodes).width(Length::Fill).height(Length::Fill)
    }

    fn view_account(&self) -> Node<Msg> {
        let l = self.l10n();
        panel([
            label(l.acct_heading),
            caption(l.acct_caption),
            caption(l.acct_optional_hint),
            divider(),
            row([caption(l.acct_username).width(Length::Px(130)), input(&self.username).placeholder("e.g. alice (lowercase, no 'root')").width(Length::Fill).on_change(Msg::UserName)]).gap(8),
            row([caption(l.acct_display).width(Length::Px(130)), input(&self.display_name).placeholder("e.g. Alice").width(Length::Fill).on_change(Msg::DisplayName)]).gap(8),
            row([caption(l.acct_passphrase).width(Length::Px(130)), input(&self.passphrase).secret().placeholder("Optional — sealed by TPM 2.0 SRK or software AEAD").width(Length::Fill).on_change(Msg::Passphrase)]).gap(8),
            toggle(l.acct_operator, self.is_operator).on_toggle(Msg::ToggleOperator),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
    }

    fn view_finish(&self) -> Node<Msg> {
        let l = self.l10n();
        let disk = self.installed_disk.as_deref().unwrap_or("target disk");
        let reboot_btn = if self.rebooting {
            button(l.reboot_now).primary()
        } else {
            button(l.reboot_now).primary().on_press(Msg::RebootNow)
        };
        panel([
            heading(l.finish_heading),
            divider(),
            text(l.finish_unplug).wrap(),
            caption(l.finish_login_note).wrap(),
            mono(format!(
                "Installed disk: {} | Language: {} | Keyboard: {} | Timezone: {}",
                disk,
                LANGUAGES[self.lang_idx].0,
                KEYBOARDS[self.kbd_idx].0,
                TIMEZONES[self.tz_idx].0
            )),
            spacer(),
            row([text(&self.status).tone(Tone::Muted), spacer(), reboot_btn]).gap(8),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
    }
}

impl App for SetupApp {
    type Msg = Msg;

    fn title(&self) -> &str {
        self.l10n().app_title
    }

    fn size(&self) -> (u32, u32) {
        (880, 620)
    }

    fn should_exit(&self) -> bool {
        self.done
    }

    fn view(&self) -> Node<Msg> {
        if self.step == Step::Welcome {
            return self.view_welcome();
        }
        let l = self.l10n();
        let step_title = match self.step {
            Step::Welcome => l.welcome_heading,
            Step::Install => l.step_install,
            Step::Locale => l.step_locale,
            Step::Timezone => l.step_timezone,
            Step::Network => l.step_network,
            Step::Account => l.step_account,
            Step::Finish => l.step_finish,
        };
        let body = match self.step {
            Step::Welcome => unreachable!(),
            Step::Install => self.view_install(),
            Step::Locale => self.view_locale(),
            Step::Timezone => self.view_timezone(),
            Step::Network => self.view_network(),
            Step::Account => self.view_account(),
            Step::Finish => self.view_finish(),
        };

        if self.step == Step::Finish {
            return column([
                heading(l.app_title),
                label(step_title),
                divider(),
                body,
            ])
            .padding(16)
            .gap(10)
            .width(Length::Fill)
            .height(Length::Fill);
        }

        let can_back = match self.step {
            Step::Install => !self.installed_mode && self.installed_disk.is_none(),
            Step::Locale => !self.installed_mode && self.installed_disk.is_none(),
            Step::Timezone | Step::Network | Step::Account => true,
            _ => false,
        };
        let back_btn = if can_back {
            button(l.back).on_press(Msg::Back)
        } else {
            button(l.back)
        };

        let nav_right: Node<Msg> = match self.step {
            Step::Install => {
                if self.installed_disk.is_some() {
                    button(l.next).primary().on_press(Msg::Next)
                } else {
                    button(l.next).primary()
                }
            }
            Step::Account => row([
                button(l.skip_for_now).on_press(Msg::SkipAccount),
                button(l.apply_and_finish).primary().on_press(Msg::CompleteSetup),
            ])
            .gap(8),
            _ => button(l.next).primary().on_press(Msg::Next),
        };

        column([
            row([heading(l.app_title), spacer(), caption(step_title)]).gap(12),
            divider(),
            body,
            divider(),
            row([
                back_btn,
                text(&self.status).tone(if self.installed_disk.is_some() { Tone::Ok } else { Tone::Muted }),
                spacer(),
                nav_right,
            ])
            .gap(8),
        ])
        .padding(14)
        .gap(10)
        .width(Length::Fill)
        .height(Length::Fill)
    }

    fn update(&mut self, msg: Msg) {
        match msg {
            Msg::StartInstall => {
                self.step = Step::Install;
                self.refresh_disks();
            }
            Msg::TryLive => {
                self.done = true;
            }
            Msg::RefreshDisks => {
                self.status = String::from("Refreshed drive list.");
                self.refresh_disks();
            }
            Msg::SelectDisk(i) => {
                if i < self.disks.len() && self.installed_disk.is_none() {
                    self.sel_disk = i;
                    self.auto_pick_mode();
                    self.refresh_plan();
                }
            }
            Msg::SelectPart(idx) => {
                self.sel_part = Some(idx);
                self.confirm_delete = false;
            }
            Msg::SelectMode(m) => {
                if self.installed_disk.is_none() {
                    self.mode = m;
                    self.confirm_wipe = false;
                    self.refresh_plan();
                }
            }
            Msg::ToggleConfirmDelete => self.confirm_delete = !self.confirm_delete,
            Msg::DeleteSelectedPart => {
                if !self.confirm_delete {
                    return;
                }
                let (Some(d), Some(pidx)) = (self.selected_disk(), self.sel_part) else {
                    return;
                };
                let dname = String::from(d.name_str());
                let mut out = [0u8; 4096];
                match install::delete_part(self.install_ep, &dname, pidx, true, &mut out) {
                    Ok(n) => {
                        self.status = String::from_utf8_lossy(&out[..n]).into_owned();
                        self.confirm_delete = false;
                        self.sel_part = None;
                        self.refresh_disks();
                    }
                    Err((e, n)) => {
                        self.status = if n > 0 {
                            String::from_utf8_lossy(&out[..n]).into_owned()
                        } else {
                            format!("Delete partition failed: {}", sys::status(e))
                        };
                    }
                }
            }
            Msg::ToggleConfirmWipe => {
                self.confirm_wipe = !self.confirm_wipe;
                self.refresh_plan();
            }
            Msg::PreviewPlan => self.refresh_plan(),
            Msg::RunInstall => {
                let Some(d) = self.selected_disk() else { return };
                let dname = String::from(d.name_str());
                self.status = format!("Installing DiscreteOS to {}...", dname);
                println!("oobe: starting install to {} (mode={})", dname, self.mode);
                let mut out = [0u8; 4096];
                match install::execute(self.install_ep, &dname, self.mode, self.confirm_wipe, &mut out) {
                    Ok(n) => {
                        let summary = String::from_utf8_lossy(&out[..n]).into_owned();
                        println!("oobe: {}", summary);
                        self.install_summary = summary;
                        self.installed_disk = Some(dname);
                        self.status = String::from("Installed & verified! Proceed to Language & Keyboard.");
                        // Automatically advance to Step 2 (Language & Keyboard) after successful install!
                        self.step = Step::Locale;
                    }
                    Err((e, n)) => {
                        self.status = if n > 0 {
                            String::from_utf8_lossy(&out[..n]).into_owned()
                        } else {
                            format!("Install failed: {}", sys::status(e))
                        };
                        println!("oobe: install error: {}", self.status);
                    }
                }
            }
            Msg::SelectLang(i) => {
                self.lang_idx = i.min(LANGUAGES.len() - 1);
                // Match suggested keyboard layout for convenience (user can override freely).
                self.kbd_idx = self.lang().default_keyboard().id() as usize;
                self.apply_locale_live();
            }
            Msg::SelectKbd(i) => {
                self.kbd_idx = i.min(KEYBOARDS.len() - 1);
                self.apply_locale_live();
            }
            Msg::KbdTest(s) => self.kbd_test = s,
            Msg::SelectTz(i) => {
                self.tz_idx = i.min(TIMEZONES.len() - 1);
                self.apply_locale_live();
            }
            Msg::SelectNet(c) => {
                self.net_choice = c;
                if self.net_st_ep != 0 {
                    self.net_status = net::status(self.net_st_ep).ok();
                }
            }
            Msg::NetIp(s) => self.net_ip = s,
            Msg::NetMask(s) => self.net_mask = s,
            Msg::NetGw(s) => self.net_gw = s,
            Msg::NetDns(s) => self.net_dns = s,
            Msg::UserName(s) => self.username = s,
            Msg::DisplayName(s) => self.display_name = s,
            Msg::Passphrase(s) => self.passphrase = s,
            Msg::ToggleOperator => self.is_operator = !self.is_operator,
            Msg::Back => {
                self.step = match self.step {
                    Step::Install if !self.installed_mode => Step::Welcome,
                    Step::Locale if !self.installed_mode && self.installed_disk.is_none() => Step::Install,
                    Step::Timezone => Step::Locale,
                    Step::Network => Step::Timezone,
                    Step::Account => Step::Network,
                    other => other,
                };
            }
            Msg::Next => {
                self.step = match self.step {
                    Step::Welcome => Step::Install,
                    Step::Install => Step::Locale,
                    Step::Locale => Step::Timezone,
                    Step::Timezone => Step::Network,
                    Step::Network => Step::Account,
                    other => other,
                };
            }
            Msg::SkipAccount => self.finalize_setup(true),
            Msg::CompleteSetup => self.finalize_setup(false),
            Msg::RebootNow => self.trigger_reboot(),
        }
    }

    fn on_key(&mut self, k: u32) -> bool {
        if self.step == Step::Welcome
            && (k & libd::proto::key::RELEASE) == 0
            && (k & libd::proto::key::MASK) == 0x1B
        {
            self.done = true;
            return true;
        }
        false
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "oobe") } {
        return 1;
    }
    run_app("oobe", SetupApp::new(), 0)
}
