//! D-OS Minimal First-Boot Setup (OOBE) (`oobe.dapp`).
//!
//! Automatically launched once on newly installed disks (when `/home/.dos/oobe.toml` has
//! `completed = false`). Fully skippable at any time; covers language & keyboard layout,
//! timezone, optional network setup (skip / DHCP / static IPv4), and local non-root account
//! creation with TPM 2.0 SRK or software AEAD credential sealing.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosid::{KEYBOARDS, LANGUAGES, OobeConfig, TIMEZONES};
use dosui::{Length, Node, Tone, button, caption, column, divider, heading, input, item, label, mono, panel, row, scroll, spacer, text, toggle};
use libd::fs::{self as fp, Namespace};
use libd::identity;
use libd::net::{self, NetConfig, NetStatus};
use libd::sys::{self, Handle};
use libd::{Startup, println};

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
    Locale,
    Timezone,
    Network,
    Account,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NetChoice {
    Skip,
    Dhcp,
    Static,
}

#[derive(Clone)]
enum Msg {
    SelectLang(usize),
    SelectKbd(usize),
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
    SkipSetup,
    Finish,
}

struct OobeApp {
    step: Step,
    lang_idx: usize,
    kbd_idx: usize,
    tz_idx: usize,
    net_choice: NetChoice,
    net_ip: String,
    net_mask: String,
    net_gw: String,
    net_dns: String,
    net_status: Option<NetStatus>,
    username: String,
    display_name: String,
    passphrase: String,
    is_operator: bool,
    status: String,
    done: bool,
    id_admin: Handle,
    net_st_ep: Handle,
    net_ctl_ep: Handle,
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

fn save_oobe_config(cfg: &OobeConfig) -> Result<(), i64> {
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

impl OobeApp {
    fn new() -> Self {
        let cfg = load_oobe_config();
        let lang_idx = LANGUAGES.iter().position(|(c, _)| *c == cfg.language).unwrap_or(0);
        let kbd_idx = KEYBOARDS.iter().position(|(c, _)| *c == cfg.keyboard).unwrap_or(0);
        let tz_idx = TIMEZONES.iter().position(|(z, _)| *z == cfg.timezone).unwrap_or(0);
        let net_st_ep = net::status_endpoint();
        let net_ctl_ep = net::control_endpoint();
        let net_status = if net_st_ep != 0 { net::status(net_st_ep).ok() } else { None };
        Self {
            step: Step::Locale,
            lang_idx,
            kbd_idx,
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
            status: String::from("All steps are optional. You can skip setup at any time."),
            done: false,
            id_admin: identity::admin_endpoint(),
            net_st_ep,
            net_ctl_ep,
        }
    }

    fn build_config(&self, skipped: bool) -> OobeConfig {
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

    fn apply_network(&mut self) -> Result<(), String> {
        if self.net_choice == NetChoice::Skip || self.net_ctl_ep == 0 {
            return Ok(());
        }
        let dns1 = if self.net_dns.trim().is_empty() {
            [0; 4]
        } else {
            parse_ipv4(&self.net_dns).ok_or_else(|| String::from("Invalid DNS IPv4 address"))?
        };
        let cfg = match self.net_choice {
            NetChoice::Dhcp => NetConfig {
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
                NetConfig {
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
            NetChoice::Skip => return Ok(()),
        };
        net::set_config(self.net_ctl_ep, &cfg).map_err(|e| format!("Network setup failed: {}", sys::status(e)))
    }

    fn apply_account(&mut self) -> Result<(), String> {
        let uname = self.username.trim();
        let mut pass = self.passphrase.as_bytes().to_vec();
        self.passphrase.clear();
        let wipe = |buf: &mut Vec<u8>| {
            buf.fill(0);
            core::hint::black_box(&*buf);
        };
        if uname.is_empty() {
            // Optional: enroll passphrase for the existing default `user` account if provided.
            if !pass.is_empty() && self.id_admin != 0 {
                let res = identity::enroll(self.id_admin, 0, &pass);
                wipe(&mut pass);
                res.map_err(|e| format!("Passphrase enrollment failed: {}", sys::status(e)))?;
                if let Ok(pol) = identity::policy(self.id_admin) {
                    let _ = identity::set_policy(self.id_admin, pol.idle_timeout_secs, pol.lock_on_sleep, true);
                }
            } else {
                wipe(&mut pass);
            }
            return Ok(());
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
        // Enable the boot sign-in screen once the user creates a personal account in OOBE.
        let pol = identity::policy(self.id_admin).unwrap_or_default();
        let _ = identity::set_policy(self.id_admin, pol.idle_timeout_secs, pol.lock_on_sleep, true);
        Ok(())
    }
}

impl App for OobeApp {
    type Msg = Msg;

    fn title(&self) -> &str {
        "Welcome to DiscreteOS"
    }

    fn size(&self) -> (u32, u32) {
        (780, 560)
    }

    fn should_exit(&self) -> bool {
        self.done
    }

    fn view(&self) -> Node<Msg> {
        let step_num = match self.step {
            Step::Locale => 1,
            Step::Timezone => 2,
            Step::Network => 3,
            Step::Account => 4,
        };
        let step_title = match self.step {
            Step::Locale => "Step 1 of 4 — Language & Keyboard",
            Step::Timezone => "Step 2 of 4 — Timezone",
            Step::Network => "Step 3 of 4 — Network (Optional)",
            Step::Account => "Step 4 of 4 — Local Account (No Root)",
        };

        let body = match self.step {
            Step::Locale => {
                let lang_items: Vec<Node<Msg>> = LANGUAGES
                    .iter()
                    .enumerate()
                    .map(|(i, (code, name))| {
                        item(format!("{} ({})", name, code), i == self.lang_idx).on_select(Msg::SelectLang(i))
                    })
                    .collect();
                let kbd_items: Vec<Node<Msg>> = KEYBOARDS
                    .iter()
                    .enumerate()
                    .map(|(i, (code, name))| {
                        item(format!("{} ({})", name, code), i == self.kbd_idx).on_select(Msg::SelectKbd(i))
                    })
                    .collect();
                row([
                    panel([label("Language"), divider(), scroll(column(lang_items).gap(4)).height(Length::Fill)])
                        .width(Length::Fill)
                        .height(Length::Fill),
                    panel([label("Keyboard Layout"), divider(), scroll(column(kbd_items).gap(4)).height(Length::Fill)])
                        .width(Length::Fill)
                        .height(Length::Fill),
                ])
                .gap(12)
                .height(Length::Fill)
            }
            Step::Timezone => {
                let tz_items: Vec<Node<Msg>> = TIMEZONES
                    .iter()
                    .enumerate()
                    .map(|(i, (_, tz_label))| item(*tz_label, i == self.tz_idx).on_select(Msg::SelectTz(i)))
                    .collect();
                panel([
                    label("Select Your Timezone"),
                    caption("System hardware clock stays UTC; apps format local times using this zone."),
                    divider(),
                    scroll(column(tz_items).gap(4)).height(Length::Fill),
                ])
                .width(Length::Fill)
                .height(Length::Fill)
            }
            Step::Network => {
                let mut nodes: Vec<Node<Msg>> = alloc::vec![
                    label("Network Configuration (Optional)"),
                    caption("DiscreteOS works completely offline. Choose Skip, Automatic DHCP, or Static IPv4."),
                    row([
                        if self.net_choice == NetChoice::Skip { button("Skip (Offline)").primary() } else { button("Skip (Offline)") }
                            .on_press(Msg::SelectNet(NetChoice::Skip)),
                        if self.net_choice == NetChoice::Dhcp { button("Automatic (DHCP)").primary() } else { button("Automatic (DHCP)") }
                            .on_press(Msg::SelectNet(NetChoice::Dhcp)),
                        if self.net_choice == NetChoice::Static { button("Static IPv4").primary() } else { button("Static IPv4") }
                            .on_press(Msg::SelectNet(NetChoice::Static)),
                    ])
                    .gap(8),
                ];
                if let Some(st) = self.net_status {
                    nodes.push(mono(format!(
                        "Detected interface: {} | IPv4: {}.{}.{}.{}",
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
            Step::Account => {
                panel([
                    label("Create a Local Account"),
                    caption("DiscreteOS has no root user. Each identity receives an isolated /home/<user> directory and explicit capabilities."),
                    caption("Leave username blank to keep the default 'user' identity."),
                    divider(),
                    row([caption("Username").width(Length::Px(130)), input(&self.username).placeholder("e.g. alice (lowercase, no 'root')").width(Length::Fill).on_change(Msg::UserName)]).gap(8),
                    row([caption("Display Name").width(Length::Px(130)), input(&self.display_name).placeholder("e.g. Alice").width(Length::Fill).on_change(Msg::DisplayName)]).gap(8),
                    row([caption("Passphrase").width(Length::Px(130)), input(&self.passphrase).secret().placeholder("Optional — sealed by TPM 2.0 SRK or software AEAD").width(Length::Fill).on_change(Msg::Passphrase)]).gap(8),
                    toggle("Operator role (may manage system settings, apps, and disks)", self.is_operator).on_toggle(Msg::ToggleOperator),
                ])
                .width(Length::Fill)
                .height(Length::Fill)
            }
        };

        let nav_right = if self.step == Step::Account {
            button("Finish Setup").primary().on_press(Msg::Finish)
        } else {
            button("Next").primary().on_press(Msg::Next)
        };

        let back_btn = if self.step != Step::Locale {
            button("Back").on_press(Msg::Back)
        } else {
            button("Back")
        };

        column([
            row([
                heading("Welcome to DiscreteOS"),
                spacer(),
                button("Skip Setup").on_press(Msg::SkipSetup),
            ])
            .gap(12),
            row([
                label(step_title),
                spacer(),
                caption(format!("{} / 4", step_num)),
            ])
            .gap(8),
            divider(),
            body,
            divider(),
            row([
                back_btn,
                text(&self.status).tone(Tone::Muted),
                spacer(),
                nav_right,
            ])
            .gap(8),
        ])
        .padding(16)
        .gap(10)
        .width(Length::Fill)
        .height(Length::Fill)
    }

    fn update(&mut self, msg: Msg) {
        match msg {
            Msg::SelectLang(i) => self.lang_idx = i.min(LANGUAGES.len() - 1),
            Msg::SelectKbd(i) => self.kbd_idx = i.min(KEYBOARDS.len() - 1),
            Msg::SelectTz(i) => self.tz_idx = i.min(TIMEZONES.len() - 1),
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
                    Step::Locale => Step::Locale,
                    Step::Timezone => Step::Locale,
                    Step::Network => Step::Timezone,
                    Step::Account => Step::Network,
                };
            }
            Msg::Next => {
                self.step = match self.step {
                    Step::Locale => Step::Timezone,
                    Step::Timezone => Step::Network,
                    Step::Network => Step::Account,
                    Step::Account => Step::Account,
                };
            }
            Msg::SkipSetup => {
                let cfg = self.build_config(true);
                match save_oobe_config(&cfg) {
                    Ok(()) => {
                        println!("oobe: first-boot setup skipped and persisted");
                        self.done = true;
                    }
                    Err(e) => {
                        self.status = format!("Could not save skip state: {}", fp::message(e));
                    }
                }
            }
            Msg::Finish => {
                if let Err(e) = self.apply_network() {
                    self.status = e;
                    return;
                }
                if let Err(e) = self.apply_account() {
                    self.status = e;
                    return;
                }
                let cfg = self.build_config(false);
                match save_oobe_config(&cfg) {
                    Ok(()) => {
                        println!(
                            "oobe: first-boot setup completed (lang={}, kbd={}, tz={}, net={})",
                            cfg.language, cfg.keyboard, cfg.timezone, cfg.net_mode
                        );
                        self.done = true;
                    }
                    Err(e) => {
                        self.status = format!("Could not save setup state: {}", fp::message(e));
                    }
                }
            }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "oobe") } {
        return 1;
    }
    run_app("oobe", OobeApp::new(), 0)
}
