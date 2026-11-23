//! D-OS System Settings (`settings.dapp`).
//!
//! Six sections covering every desktop, hardware, identity, and application control:
//! 1. Display: adapter list, resolution/Hz mode switching, VRR, HDR10, and per-output scale
//!    via `awmi.admin` (`OP_SET_DISPLAY`).
//! 2. Appearance: Dark Slate / High Contrast theme, text scale (100-200%), Reduce Motion.
//! 3. Audio: device routing, output volume slider, mute toggle, microphone capture gate.
//! 4. Network: live link, IPv4, gateway, DNS, and packet counters.
//! 5. Identity & Lock: active identity, TPM 2.0 / software sealing badge, passphrase enrollment
//!    (masked `.secret()` input), idle timeout, sleep/boot lock policy, Lock Now, and Create User.
//! 6. Apps & Permissions: list verified `.dapp` bundles and toggle/revoke individual permissions live.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosapp::Permission;
use dosaudio::route::DeviceKind;
use dosawmi::UiSettings;
use dosui::{Length, Node, Tone, button, caption, column, divider, heading, input, item, label, mono, panel, row, scroll, slider, spacer, text, toggle};
use libd::appmgr::{self, AppInfo, DECISION_DENIED, DECISION_GRANTED, MAX_APPS};
use libd::audio::{self, DeviceEntry};
use libd::awmi;
use libd::gpu::{self, AdapterInfo, DisplayProbeInfo, ModeEntry};
use libd::identity::{self, IdentityInfo, LockPolicyInfo};
use libd::net::{self, NetConfig, NetStatus};
use libd::sys::{self, Handle};
use libd::Startup;

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

fn fmt_ipv4(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Display,
    Appearance,
    Audio,
    Network,
    Identity,
    Apps,
}

#[derive(Clone)]
enum Msg {
    SelectTab(Tab),
    Refresh,
    // Display
    SelectAdapter(usize),
    SetMode(usize),
    ToggleVrr,
    ToggleHdr,
    SetOutputScale(u16),
    // Appearance
    SetTheme(u8),
    SetTextScale(u16),
    ToggleMotion,
    // Audio
    SetAudioVol(i32),
    ToggleMute,
    SelectAudioOut(u32),
    ToggleMicGate,
    // Network
    SetNetMode(bool), // true = static, false = DHCP
    NetIpChanged(String),
    NetMaskChanged(String),
    NetGwChanged(String),
    NetDns1Changed(String),
    NetDns2Changed(String),
    ToggleNetFallback,
    PresetDns(&'static str, &'static str),
    ApplyNetwork,
    RenewDhcp,
    // Identity & Lock
    PassChanged(String),
    EnrollPass,
    SetIdleSecs(u32),
    ToggleLockSleep,
    ToggleLockBoot,
    LockNow,
    NewUserChanged(String),
    NewDisplayChanged(String),
    ToggleNewOperator,
    CreateUser,
    // Apps & Permissions
    SelectApp(usize),
    ToggleAppPerm(u8),
}

struct SettingsApp {
    tab: Tab,
    status: String,
    // Endpoints (strictly granted by appmgr)
    gpu_q: Handle,
    awmi_admin: Handle,
    audio_ctl: Handle,
    net_status: Handle,
    net_ctl: Handle,
    id_q: Handle,
    id_admin: Handle,
    app_q: Handle,
    app_admin: Handle,
    // Display state
    adapters: Vec<AdapterInfo>,
    sel_adapter: usize,
    adapter_picked: bool,
    modes: Vec<ModeEntry>,
    probe: Option<DisplayProbeInfo>,
    vrr_on: bool,
    hdr_on: bool,
    // Appearance state
    ui_settings: UiSettings,
    // Audio state
    audio_devs: Vec<DeviceEntry>,
    audio_vol: i32,
    audio_muted: bool,
    mic_allowed: bool,
    // Network state
    net_info: Option<NetStatus>,
    net_fields_loaded: bool,
    net_static: bool,
    net_ip: String,
    net_mask: String,
    net_gw: String,
    net_dns1: String,
    net_dns2: String,
    net_dns_fallback: bool,
    // Identity & Lock state
    identities: Vec<IdentityInfo>,
    lock_policy: LockPolicyInfo,
    pass_input: String,
    new_user: String,
    new_display: String,
    new_operator: bool,
    // Apps state
    apps: Vec<AppInfo>,
    sel_app: usize,
}

impl SettingsApp {
    fn new() -> Self {
        let mut s = Self {
            tab: Tab::Display,
            status: String::from("Ready"),
            gpu_q: gpu::query_endpoint(),
            awmi_admin: awmi::admin_endpoint(),
            audio_ctl: audio::control_endpoint(),
            net_status: net::status_endpoint(),
            net_ctl: net::control_endpoint(),
            id_q: identity::query_endpoint(),
            id_admin: identity::admin_endpoint(),
            app_q: appmgr::query_endpoint(),
            app_admin: appmgr::admin_endpoint(),
            adapters: Vec::new(),
            sel_adapter: 0,
            adapter_picked: false,
            modes: Vec::new(),
            probe: None,
            vrr_on: false,
            hdr_on: false,
            ui_settings: UiSettings::DEFAULT,
            audio_devs: Vec::new(),
            audio_vol: 80,
            audio_muted: false,
            mic_allowed: true,
            net_info: None,
            net_fields_loaded: false,
            net_static: false,
            net_ip: String::new(),
            net_mask: String::from("255.255.255.0"),
            net_gw: String::new(),
            net_dns1: String::new(),
            net_dns2: String::new(),
            net_dns_fallback: true,
            identities: Vec::new(),
            lock_policy: LockPolicyInfo::default(),
            pass_input: String::new(),
            new_user: String::new(),
            new_display: String::new(),
            new_operator: false,
            apps: Vec::new(),
            sel_app: 0,
        };
        s.refresh_all();
        s
    }

    fn refresh_all(&mut self) {
        self.refresh_display();
        self.refresh_appearance();
        self.refresh_audio();
        self.refresh_net();
        self.refresh_identity();
        self.refresh_apps();
    }

    fn refresh_display(&mut self) {
        self.adapters.clear();
        self.modes.clear();
        self.probe = None;
        if self.gpu_q == 0 {
            return;
        }
        let mut buf = [AdapterInfo::empty(); 8];
        if let Ok(n) = gpu::list_adapters(self.gpu_q, &mut buf) {
            self.adapters.extend_from_slice(&buf[..n]);
        }
        if !self.adapter_picked || self.sel_adapter >= self.adapters.len() {
            self.sel_adapter = self
                .adapters
                .iter()
                .position(|a| a.kind != gpu::KIND_GOP && (a.caps & gpu::CAP_NATIVE_GOP_MATCH) != 0)
                .or_else(|| self.adapters.iter().position(|a| a.online && a.width > 0 && a.height > 0))
                .unwrap_or(0);
        }
        if let Some(ad) = self.adapters.get(self.sel_adapter) {
            let mut m = [ModeEntry::default(); 16];
            if let Ok(mn) = gpu::get_modes(self.gpu_q, ad.id, &mut m) {
                self.modes.extend_from_slice(&m[..mn]);
            }
            if let Ok(p) = gpu::get_display_info(self.gpu_q, ad.id) {
                self.vrr_on = (p.flags & gpu::PROBE_VRR_ENABLED) != 0;
                self.hdr_on = (p.flags & gpu::PROBE_HDR_ENABLED) != 0;
                self.probe = Some(p);
            }
        }
    }

    fn refresh_appearance(&mut self) {
        if self.awmi_admin != 0
            && let Ok(st) = awmi::status(self.awmi_admin)
        {
            self.ui_settings = UiSettings::unpack(u64::from(st.settings));
        }
    }

    fn refresh_audio(&mut self) {
        self.audio_devs.clear();
        if self.audio_ctl == 0 {
            return;
        }
        let mut devs = [DeviceEntry::empty(); 16];
        if let Ok(n) = audio::list_devices(self.audio_ctl, &mut devs) {
            self.audio_devs.extend_from_slice(&devs[..n]);
            if let Some(a) = self.audio_devs.iter().find(|d| d.active_out) {
                self.audio_vol = i32::from(a.volume);
                self.audio_muted = a.muted;
            }
        }
    }

    fn refresh_net(&mut self) {
        let ep = if self.net_ctl != 0 { self.net_ctl } else { self.net_status };
        if ep != 0 {
            self.net_info = net::status(ep).ok();
            if let Some(st) = self.net_info
                && !self.net_fields_loaded
            {
                self.sync_net_fields(st);
            }
        }
    }

    fn sync_net_fields(&mut self, st: NetStatus) {
        self.net_fields_loaded = true;
        self.net_static = st.static_mode;
        self.net_ip = if st.ip != [0; 4] { fmt_ipv4(st.ip) } else { String::new() };
        self.net_mask = if st.netmask != [0; 4] { fmt_ipv4(st.netmask) } else { String::from("255.255.255.0") };
        self.net_gw = if st.gateway != [0; 4] { fmt_ipv4(st.gateway) } else { String::new() };
        self.net_dns1 = if st.dns != [0; 4] { fmt_ipv4(st.dns) } else { String::new() };
        self.net_dns2 = if st.dns2 != [0; 4] { fmt_ipv4(st.dns2) } else { String::new() };
        self.net_dns_fallback = st.dns_fallback;
    }

    fn refresh_identity(&mut self) {
        self.identities.clear();
        let ep = if self.id_admin != 0 { self.id_admin } else { self.id_q };
        if ep == 0 {
            return;
        }
        let mut buf = [IdentityInfo::default(); 8];
        if let Ok(n) = identity::list(ep, &mut buf) {
            self.identities.extend_from_slice(&buf[..n]);
        }
        if let Ok(pol) = identity::policy(ep) {
            self.lock_policy = pol;
        }
    }

    fn refresh_apps(&mut self) {
        self.apps.clear();
        let ep = if self.app_admin != 0 { self.app_admin } else { self.app_q };
        if ep == 0 {
            return;
        }
        let mut buf = [AppInfo::default(); MAX_APPS];
        if let Ok(n) = appmgr::list(ep, &mut buf) {
            self.apps.extend_from_slice(&buf[..n]);
        }
        if self.sel_app >= self.apps.len() {
            self.sel_app = 0;
        }
    }

    fn view_display(&self) -> Node<Msg> {
        let mut items: Vec<Node<Msg>> = alloc::vec![heading("Display"), caption("Configure resolution, refresh rate, VRR, HDR, and per-output UI scaling.")];
        if self.adapters.is_empty() {
            items.push(caption("No display adapters reported (display:query not granted).").tone(Tone::Muted));
            return column(items).gap(10);
        }
        let mut ad_rows = Vec::new();
        for (i, a) in self.adapters.iter().enumerate() {
            ad_rows.push(
                item(format!("#{} {} ({})", a.id, a.name_str(), a.kind_name()), i == self.sel_adapter)
                    .detail(format!("{}x{}", a.width, a.height))
                    .on_select(Msg::SelectAdapter(i)),
            );
        }
        items.push(panel(ad_rows));

        if let Some(ad) = self.adapters.get(self.sel_adapter) {
            if let Some(p) = self.probe {
                let dcn_lbl = if p.dcn_major > 0 {
                    format!("DCN {}.{}.{} pipe {}", p.dcn_major, p.dcn_minor, p.dcn_rev, p.pipe)
                } else {
                    String::from(ad.kind_name())
                };
                let link_lbl = if p.dp_lanes > 0 && p.dp_rate_mbps > 0 {
                    format!("DP {}x {} Mbps", p.dp_lanes, p.dp_rate_mbps)
                } else if p.edid_blocks > 0 {
                    format!("EDID {} blk", p.edid_blocks)
                } else {
                    String::from("CVT-RB modes")
                };
                let vrr_lbl = if p.vrr_min_hz > 0 && p.vrr_max_hz > 0 {
                    if self.vrr_on {
                        format!("VRR ON {}-{} Hz", p.vrr_min_hz, p.vrr_max_hz)
                    } else {
                        format!("VRR {}-{} Hz", p.vrr_min_hz, p.vrr_max_hz)
                    }
                } else {
                    String::from("VRR n/a")
                };
                let note = p.note_str();
                let summary = if note.is_empty() {
                    format!("{} • {} • {}", dcn_lbl, link_lbl, vrr_lbl)
                } else {
                    format!("{} • {} • {} • {}", dcn_lbl, link_lbl, vrr_lbl, note)
                };
                items.push(caption(summary).wrap());
            }
            items.push(label("Per-Output UI Scale"));
            items.push(
                row([
                    button("Auto").on_press(Msg::SetOutputScale(0)),
                    button("100%").on_press(Msg::SetOutputScale(100)),
                    button("125%").on_press(Msg::SetOutputScale(125)),
                    button("150%").on_press(Msg::SetOutputScale(150)),
                    button("175%").on_press(Msg::SetOutputScale(175)),
                    button("200%").on_press(Msg::SetOutputScale(200)),
                ])
                .gap(6),
            );
            items.push(
                row([
                    toggle("Variable Refresh Rate (VRR)", self.vrr_on).on_toggle(Msg::ToggleVrr),
                    toggle("HDR10 (10-bit)", self.hdr_on).on_toggle(Msg::ToggleHdr),
                ])
                .gap(16),
            );
            items.push(label(format!("Available Modes for Adapter #{}", ad.id)));
            let mut mode_rows = Vec::new();
            for (i, m) in self.modes.iter().enumerate() {
                let cur = (m.flags & gpu::MODE_FLAG_CURRENT) != 0;
                mode_rows.push(
                    item(format!("{}x{} @ {}.{:02} Hz", m.width, m.height, m.refresh_mhz / 1000, (m.refresh_mhz % 1000) / 10), cur)
                        .detail(if cur { "current" } else { "apply" })
                        .on_select(Msg::SetMode(i)),
                );
            }
            if mode_rows.is_empty() {
                mode_rows.push(caption("No switchable EDID modes reported on this adapter."));
            }
            items.push(panel(mode_rows));
        }
        column(items).gap(10)
    }

    fn view_appearance(&self) -> Node<Msg> {
        let dark = self.ui_settings.theme == dosawmi::ThemeId::DarkSlate;
        column([
            heading("Appearance & Accessibility"),
            caption("Changes take effect across the compositor and every open native window."),
            panel([
                label("Theme"),
                row([
                    if dark { button("Dark Slate").primary() } else { button("Dark Slate") }.on_press(Msg::SetTheme(0)),
                    if !dark { button("High Contrast").primary() } else { button("High Contrast") }.on_press(Msg::SetTheme(1)),
                ])
                .gap(8),
                divider(),
                label(format!("Text Size ({}%)", self.ui_settings.text_scale)),
                row([
                    button("100%").on_press(Msg::SetTextScale(100)),
                    button("125%").on_press(Msg::SetTextScale(125)),
                    button("150%").on_press(Msg::SetTextScale(150)),
                    button("175%").on_press(Msg::SetTextScale(175)),
                    button("200%").on_press(Msg::SetTextScale(200)),
                ])
                .gap(6),
                divider(),
                toggle("Reduce motion (disable animations)", self.ui_settings.reduce_motion).on_toggle(Msg::ToggleMotion),
            ]),
        ])
        .gap(10)
    }

    fn view_audio(&self) -> Node<Msg> {
        let mut dev_rows: Vec<Node<Msg>> = alloc::vec![label("Audio Devices")];
        if self.audio_devs.is_empty() {
            dev_rows.push(caption("No audio devices detected (or audio:control not granted)."));
        } else {
            for d in &self.audio_devs {
                let kind = DeviceKind::from_u8(d.kind).label();
                dev_rows.push(
                    item(format!("#{} {} ({})", d.id, d.name_str(), kind), d.active_out)
                        .detail(format!("{}%{}", d.volume, if d.muted { " muted" } else { "" }))
                        .on_select(Msg::SelectAudioOut(d.id)),
                );
            }
        }
        column([
            heading("Audio"),
            panel([
                label(format!("Output Volume: {}%", self.audio_vol)),
                slider(self.audio_vol, 0, 100).step(5).on_slide(Msg::SetAudioVol),
                row([
                    toggle("Mute output", self.audio_muted).on_toggle(Msg::ToggleMute),
                    toggle("Allow microphone capture", self.mic_allowed).on_toggle(Msg::ToggleMicGate),
                ])
                .gap(16),
            ]),
            panel(dev_rows),
        ])
        .gap(10)
    }

    fn view_network(&self) -> Node<Msg> {
        let status_card = if let Some(st) = self.net_info {
            let state = if st.static_mode && st.ip != [0; 4] {
                "Online (Static IPv4)"
            } else if st.dhcp_bound {
                "Online (DHCP)"
            } else if st.link_up {
                "Link up (acquiring DHCP)"
            } else {
                "Offline"
            };
            let mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                st.mac[0], st.mac[1], st.mac[2], st.mac[3], st.mac[4], st.mac[5]
            );
            let dns_line = if st.dns2 != [0; 4] {
                format!("DNS:     {} , {}", fmt_ipv4(st.dns), fmt_ipv4(st.dns2))
            } else {
                format!("DNS:     {}", fmt_ipv4(st.dns))
            };
            panel([
                label(format!("Interface: {} ({})", if st.name_len > 0 { st.name_str() } else { "none" }, mac)),
                text(format!("State: {}", state)),
                mono(format!("IPv4:    {} / {}", fmt_ipv4(st.ip), fmt_ipv4(st.netmask))),
                mono(format!("Gateway: {}", fmt_ipv4(st.gateway))),
                mono(dns_line),
                mono(format!("Packets: {} RX / {} TX", st.rx_packets, st.tx_packets)),
            ])
        } else {
            panel([caption("Network status unavailable (net:status not granted).")])
        };

        let mut cfg_rows: Vec<Node<Msg>> = alloc::vec![
            label("IPv4 & DNS Configuration"),
            caption("Switch between automatic DHCP and static IPv4, or override DNS servers directly."),
            row([
                if !self.net_static { button("DHCP (Auto)").primary() } else { button("DHCP (Auto)") }
                    .on_press(Msg::SetNetMode(false)),
                if self.net_static { button("Static IPv4").primary() } else { button("Static IPv4") }
                    .on_press(Msg::SetNetMode(true)),
                spacer(),
                button("Renew DHCP").on_press(Msg::RenewDhcp),
            ])
            .gap(8),
        ];
        if self.net_static {
            cfg_rows.push(divider());
            cfg_rows.push(
                row([
                    caption("IPv4 Address").width(Length::Px(120)),
                    input(&self.net_ip).placeholder("e.g. 192.168.1.50").width(Length::Fill).on_change(Msg::NetIpChanged),
                ])
                .gap(8),
            );
            cfg_rows.push(
                row([
                    caption("Subnet Mask").width(Length::Px(120)),
                    input(&self.net_mask).placeholder("255.255.255.0").width(Length::Fill).on_change(Msg::NetMaskChanged),
                ])
                .gap(8),
            );
            cfg_rows.push(
                row([
                    caption("Gateway").width(Length::Px(120)),
                    input(&self.net_gw).placeholder("e.g. 192.168.1.1").width(Length::Fill).on_change(Msg::NetGwChanged),
                ])
                .gap(8),
            );
        }
        cfg_rows.push(divider());
        cfg_rows.push(
            row([
                caption("Primary DNS").width(Length::Px(120)),
                input(&self.net_dns1).placeholder("blank = DHCP auto, or 1.1.1.1").width(Length::Fill).on_change(Msg::NetDns1Changed),
            ])
            .gap(8),
        );
        cfg_rows.push(
            row([
                caption("Secondary DNS").width(Length::Px(120)),
                input(&self.net_dns2).placeholder("optional, e.g. 8.8.8.8").width(Length::Fill).on_change(Msg::NetDns2Changed),
            ])
            .gap(8),
        );
        cfg_rows.push(
            row([
                caption("DNS Presets:").width(Length::Px(120)),
                button("Auto").on_press(Msg::PresetDns("", "")),
                button("Cloudflare").on_press(Msg::PresetDns("1.1.1.1", "1.0.0.1")),
                button("Google").on_press(Msg::PresetDns("8.8.8.8", "8.8.4.4")),
                button("Quad9").on_press(Msg::PresetDns("9.9.9.9", "149.112.112.112")),
            ])
            .gap(6),
        );
        cfg_rows.push(
            toggle("Fall back to public DNS (1.1.1.1 / 9.9.9.9 / 8.8.8.8) if unreachable", self.net_dns_fallback)
                .on_toggle(Msg::ToggleNetFallback),
        );
        if self.net_ctl == 0 {
            cfg_rows.push(caption("Network editing unavailable (grant net:control in Apps & Permissions).").tone(Tone::Muted));
        } else {
            cfg_rows.push(row([spacer(), button("Apply Network Settings").primary().on_press(Msg::ApplyNetwork)]));
        }

        column([heading("Network"), status_card, panel(cfg_rows)]).gap(10)
    }

    fn view_identity(&self) -> Node<Msg> {
        let active = self.identities.iter().find(|i| i.active);
        let mut active_rows: Vec<Node<Msg>> = Vec::new();
        if let Some(a) = active {
            active_rows.push(label(format!("{} ({})", a.display_str(), a.name_str())));
            active_rows.push(text(format!("Role: {} | Isolated home: /home -> {}", a.role_str(), a.home_str())));
            let seal_badge = match a.seal {
                identity::SEAL_TPM2 => "Credential sealing: TPM 2.0 Storage Root Key",
                identity::SEAL_SOFTWARE => "Credential sealing: Software AEAD (PBKDF2 + ChaCha20-Poly1305)",
                _ => "Credential sealing: Not enrolled yet",
            };
            active_rows.push(caption(seal_badge).tone(if a.seal == identity::SEAL_TPM2 { Tone::Ok } else { Tone::Primary }));
        } else {
            active_rows.push(caption("Identity service unavailable."));
        }
        active_rows.push(divider());
        active_rows.push(label("Enroll / Update Passphrase"));
        active_rows.push(
            row([
                input(&self.pass_input)
                    .secret()
                    .placeholder("Enter new passphrase")
                    .width(Length::Fill)
                    .on_change(Msg::PassChanged)
                    .on_submit(Msg::EnrollPass),
                button("Enroll").primary().on_press(Msg::EnrollPass),
            ])
            .gap(8),
        );

        let lock_panel = panel([
            label(format!("Session Lock Policy (Idle: {} s)", self.lock_policy.idle_timeout_secs)),
            row([
                button("Off").on_press(Msg::SetIdleSecs(0)),
                button("1 min").on_press(Msg::SetIdleSecs(60)),
                button("5 min").on_press(Msg::SetIdleSecs(300)),
                button("15 min").on_press(Msg::SetIdleSecs(900)),
                spacer(),
                button("Lock Now").primary().on_press(Msg::LockNow),
            ])
            .gap(6),
            toggle("Lock automatically before sleep", self.lock_policy.lock_on_sleep).on_toggle(Msg::ToggleLockSleep),
            toggle("Require sign-in at boot", self.lock_policy.lock_at_boot).on_toggle(Msg::ToggleLockBoot),
        ]);

        let create_panel = panel([
            label("Create New User Identity (no root user)"),
            row([
                input(&self.new_user).placeholder("username (e.g. alice)").width(Length::Px(190)).on_change(Msg::NewUserChanged),
                input(&self.new_display).placeholder("Display Name").width(Length::Fill).on_change(Msg::NewDisplayChanged),
            ])
            .gap(8),
            row([
                toggle("Operator role (device & system admin)", self.new_operator).on_toggle(Msg::ToggleNewOperator),
                spacer(),
                button("Create User").on_press(Msg::CreateUser),
            ])
            .gap(8),
        ]);

        column([heading("Identity & Lock Screen"), panel(active_rows), lock_panel, create_panel]).gap(10)
    }

    fn view_apps(&self) -> Node<Msg> {
        let mut app_rows: Vec<Node<Msg>> = alloc::vec![label("Verified .dapp Applications")];
        for (i, a) in self.apps.iter().enumerate() {
            app_rows.push(
                item(format!("{} (v{})", a.title_str(), a.version_str()), i == self.sel_app)
                    .detail(if a.running > 0 { format!("{} running", a.running) } else { String::from("verified") })
                    .on_select(Msg::SelectApp(i)),
            );
        }
        let mut perm_rows: Vec<Node<Msg>> = Vec::new();
        if let Some(a) = self.apps.get(self.sel_app) {
            perm_rows.push(label(format!("Permissions for {} ({})", a.title_str(), a.name_str())));
            perm_rows.push(caption("Revoking a permission immediately stops running instances holding it."));
            let declared = a.required_perms | a.optional_perms | a.prompt_perms;
            for p in Permission::ALL {
                if declared & p.bit() != 0 {
                    let granted = (a.effective_perms & p.bit()) != 0;
                    perm_rows.push(
                        toggle(format!("{} - {}", p.label(), p.description()), granted).on_toggle(Msg::ToggleAppPerm(p as u8)),
                    );
                }
            }
        } else {
            perm_rows.push(caption("No verified applications found."));
        }
        column([
            heading("Apps & Revocable Permissions"),
            panel(app_rows),
            panel(perm_rows),
        ])
        .gap(10)
    }
}

impl App for SettingsApp {
    type Msg = Msg;

    fn title(&self) -> &str {
        "Settings"
    }

    fn size(&self) -> (u32, u32) {
        (860, 580)
    }

    fn view(&self) -> Node<Msg> {
        let tabs = [
            (Tab::Display, "Display"),
            (Tab::Appearance, "Appearance"),
            (Tab::Audio, "Audio"),
            (Tab::Network, "Network"),
            (Tab::Identity, "Identity & Lock"),
            (Tab::Apps, "Apps & Permissions"),
        ];
        let mut nav: Vec<Node<Msg>> = alloc::vec![heading("Settings")];
        for (t, name) in tabs {
            nav.push(item(name, self.tab == t).on_select(Msg::SelectTab(t)));
        }
        nav.push(spacer());
        nav.push(button("Refresh").on_press(Msg::Refresh));
        let sidebar = panel(nav).width(Length::Px(195)).height(Length::Fill);

        let page = match self.tab {
            Tab::Display => self.view_display(),
            Tab::Appearance => self.view_appearance(),
            Tab::Audio => self.view_audio(),
            Tab::Network => self.view_network(),
            Tab::Identity => self.view_identity(),
            Tab::Apps => self.view_apps(),
        };

        column([
            row([sidebar, scroll(page.padding(4)).fill()]).gap(12).fill(),
            divider(),
            row([caption(&self.status), spacer(), caption("D-OS System Settings")]),
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
            Msg::Refresh => {
                self.net_fields_loaded = false;
                self.refresh_all();
                self.status = String::from("Refreshed");
            }
            Msg::SelectAdapter(i) => {
                self.sel_adapter = i;
                self.adapter_picked = true;
                self.refresh_display();
            }
            Msg::SetMode(i) => {
                if let (Some(ad), Some(m)) = (self.adapters.get(self.sel_adapter), self.modes.get(i)) {
                    match awmi::set_display_mode(self.awmi_admin, ad.id, m.width, m.height, m.refresh_mhz, 3) {
                        Ok(()) => {
                            self.status = format!("Mode set to {}x{} @ {} Hz", m.width, m.height, m.refresh_mhz / 1000);
                            self.refresh_display();
                        }
                        Err(e) => {
                            self.refresh_display();
                            let note = self.probe.map(|p| String::from(p.note_str())).unwrap_or_default();
                            self.status = if note.is_empty() {
                                format!("Mode change refused: {}", sys::status(e))
                            } else {
                                format!("Mode kept: {} ({})", note, sys::status(e))
                            };
                        }
                    }
                }
            }
            Msg::ToggleVrr => {
                if let Some(ad) = self.adapters.get(self.sel_adapter) {
                    let want = !self.vrr_on;
                    match awmi::set_display_vrr(self.awmi_admin, ad.id, want, 0, 0) {
                        Ok(()) => {
                            self.vrr_on = want;
                            self.refresh_display();
                            self.status = format!("VRR {}", if want { "enabled" } else { "disabled" });
                        }
                        Err(e) => self.status = format!("VRR refused: {}", sys::status(e)),
                    }
                }
            }
            Msg::ToggleHdr => {
                if let Some(ad) = self.adapters.get(self.sel_adapter) {
                    let want = !self.hdr_on;
                    match awmi::set_display_hdr(self.awmi_admin, ad.id, want) {
                        Ok(()) => {
                            self.hdr_on = want;
                            self.refresh_display();
                            self.status = format!("HDR10 {}", if want { "enabled" } else { "disabled" });
                        }
                        Err(e) => self.status = format!("HDR10 refused: {}", sys::status(e)),
                    }
                }
            }
            Msg::SetOutputScale(sc) => {
                let id = self.adapters.get(self.sel_adapter).map_or(0, |a| a.id);
                match awmi::set_output_scale(self.awmi_admin, id, sc) {
                    Ok(()) => self.status = if sc == 0 { String::from("Output scale set to Auto") } else { format!("Output scale set to {}%", sc) },
                    Err(e) => self.status = format!("Scale failed: {}", sys::status(e)),
                }
            }
            Msg::SetTheme(t) => {
                match awmi::set_settings(self.awmi_admin, u64::from(t), awmi::SET_THEME) {
                    Ok(p) => {
                        self.ui_settings = UiSettings::unpack(p);
                        self.status = format!("Theme set to {}", self.ui_settings.theme.name());
                    }
                    Err(e) => self.status = format!("Theme failed: {}", sys::status(e)),
                }
            }
            Msg::SetTextScale(sc) => {
                match awmi::set_settings(self.awmi_admin, u64::from(sc) << 8, awmi::SET_TEXT_SCALE) {
                    Ok(p) => {
                        self.ui_settings = UiSettings::unpack(p);
                        self.status = format!("Text size set to {}%", sc);
                    }
                    Err(e) => self.status = format!("Text size failed: {}", sys::status(e)),
                }
            }
            Msg::ToggleMotion => {
                let want = !self.ui_settings.reduce_motion;
                match awmi::set_settings(self.awmi_admin, u64::from(want) << 24, awmi::SET_MOTION) {
                    Ok(p) => {
                        self.ui_settings = UiSettings::unpack(p);
                        self.status = format!("Reduce motion {}", if want { "on" } else { "off" });
                    }
                    Err(e) => self.status = format!("Motion toggle failed: {}", sys::status(e)),
                }
            }
            Msg::SetAudioVol(v) => {
                self.audio_vol = v.clamp(0, 100);
                let _ = audio::control_call(self.audio_ctl, audio::OP_SET_VOL, 0, self.audio_vol as u64);
                self.status = format!("Volume set to {}%", self.audio_vol);
            }
            Msg::ToggleMute => {
                let want = !self.audio_muted;
                let b = audio::VOL_FLAG_MUTE_ONLY | (u64::from(want) << 8);
                if audio::control_call(self.audio_ctl, audio::OP_SET_VOL, 0, b).is_ok() {
                    self.audio_muted = want;
                    self.status = String::from(if want { "Audio muted" } else { "Audio unmuted" });
                }
            }
            Msg::SelectAudioOut(id) => {
                if audio::control_call(self.audio_ctl, audio::OP_SET_DEFAULT, u64::from(id), 0).is_ok() {
                    self.refresh_audio();
                    self.status = format!("Switched default audio output to #{}", id);
                }
            }
            Msg::ToggleMicGate => {
                let want = !self.mic_allowed;
                if audio::control_call(self.audio_ctl, audio::OP_SET_MIC_GRANT, u64::from(want), 0).is_ok() {
                    self.mic_allowed = want;
                    self.status = String::from(if want { "Microphone capture allowed" } else { "Microphone capture revoked" });
                }
            }
            Msg::SetNetMode(is_static) => {
                self.net_static = is_static;
                if is_static && self.net_ip.is_empty()
                    && let Some(st) = self.net_info
                    && st.ip != [0; 4]
                {
                    self.net_ip = fmt_ipv4(st.ip);
                    if st.netmask != [0; 4] {
                        self.net_mask = fmt_ipv4(st.netmask);
                    }
                    if st.gateway != [0; 4] {
                        self.net_gw = fmt_ipv4(st.gateway);
                    }
                }
            }
            Msg::NetIpChanged(s) => self.net_ip = s,
            Msg::NetMaskChanged(s) => self.net_mask = s,
            Msg::NetGwChanged(s) => self.net_gw = s,
            Msg::NetDns1Changed(s) => self.net_dns1 = s,
            Msg::NetDns2Changed(s) => self.net_dns2 = s,
            Msg::ToggleNetFallback => self.net_dns_fallback = !self.net_dns_fallback,
            Msg::PresetDns(d1, d2) => {
                self.net_dns1 = String::from(d1);
                self.net_dns2 = String::from(d2);
            }
            Msg::RenewDhcp => {
                if self.net_ctl == 0 {
                    self.status = String::from("Network control not granted");
                    return;
                }
                let dns1 = if self.net_dns1.trim().is_empty() { [0; 4] } else {
                    match parse_ipv4(&self.net_dns1) {
                        Some(ip) => ip,
                        None => { self.status = String::from("Invalid Primary DNS IPv4"); return; }
                    }
                };
                let dns2 = if self.net_dns2.trim().is_empty() { [0; 4] } else {
                    match parse_ipv4(&self.net_dns2) {
                        Some(ip) => ip,
                        None => { self.status = String::from("Invalid Secondary DNS IPv4"); return; }
                    }
                };
                let cfg = NetConfig {
                    dhcp: true,
                    ip: [0; 4],
                    netmask: [0; 4],
                    gateway: [0; 4],
                    dns1,
                    dns2,
                    dns_port: 53,
                    dns_fallback: self.net_dns_fallback,
                };
                match net::set_config(self.net_ctl, &cfg) {
                    Ok(()) => {
                        self.net_static = false;
                        self.net_fields_loaded = false;
                        self.refresh_net();
                        self.status = String::from("DHCP lease renewal requested");
                    }
                    Err(e) => self.status = format!("DHCP renew failed: {}", sys::status(e)),
                }
            }
            Msg::ApplyNetwork => {
                if self.net_ctl == 0 {
                    self.status = String::from("Network control not granted");
                    return;
                }
                let dns1 = if self.net_dns1.trim().is_empty() {
                    [0; 4]
                } else {
                    match parse_ipv4(&self.net_dns1) {
                        Some(ip) => ip,
                        None => {
                            self.status = String::from("Invalid Primary DNS (expected a.b.c.d)");
                            return;
                        }
                    }
                };
                let dns2 = if self.net_dns2.trim().is_empty() {
                    [0; 4]
                } else {
                    match parse_ipv4(&self.net_dns2) {
                        Some(ip) => ip,
                        None => {
                            self.status = String::from("Invalid Secondary DNS (expected a.b.c.d)");
                            return;
                        }
                    }
                };
                let cfg = if self.net_static {
                    let Some(ip) = parse_ipv4(&self.net_ip).filter(|&a| a != [0; 4]) else {
                        self.status = String::from("Invalid Static IPv4 address (expected a.b.c.d)");
                        return;
                    };
                    let mask = if self.net_mask.trim().is_empty() {
                        [255, 255, 255, 0]
                    } else {
                        match parse_ipv4(&self.net_mask) {
                            Some(m) if m != [0; 4] => m,
                            _ => {
                                self.status = String::from("Invalid Subnet Mask (e.g. 255.255.255.0)");
                                return;
                            }
                        }
                    };
                    let gw = if self.net_gw.trim().is_empty() {
                        [0; 4]
                    } else {
                        match parse_ipv4(&self.net_gw) {
                            Some(g) => g,
                            None => {
                                self.status = String::from("Invalid Gateway IPv4 (expected a.b.c.d)");
                                return;
                            }
                        }
                    };
                    NetConfig {
                        dhcp: false,
                        ip,
                        netmask: mask,
                        gateway: gw,
                        dns1,
                        dns2,
                        dns_port: 53,
                        dns_fallback: self.net_dns_fallback,
                    }
                } else {
                    NetConfig {
                        dhcp: true,
                        ip: [0; 4],
                        netmask: [0; 4],
                        gateway: [0; 4],
                        dns1,
                        dns2,
                        dns_port: 53,
                        dns_fallback: self.net_dns_fallback,
                    }
                };
                match net::set_config(self.net_ctl, &cfg) {
                    Ok(()) => {
                        self.net_fields_loaded = false;
                        self.refresh_net();
                        self.status = if cfg.dhcp {
                            String::from("Applied DHCP + DNS configuration")
                        } else {
                            format!("Applied static IPv4 {}", fmt_ipv4(cfg.ip))
                        };
                    }
                    Err(e) => self.status = format!("Network apply failed: {}", sys::status(e)),
                }
            }
            Msg::PassChanged(p) => self.pass_input = p,
            Msg::EnrollPass => {
                if self.pass_input.is_empty() {
                    self.status = String::from("Passphrase cannot be empty.");
                    return;
                }
                let res = identity::enroll(self.id_admin, 0, self.pass_input.as_bytes());
                // Wipe passphrase buffer from UI state immediately after enrollment.
                self.pass_input.clear();
                match res {
                    Ok(kind) => {
                        self.refresh_identity();
                        self.status = format!(
                            "Passphrase enrolled ({})",
                            if kind == identity::SEAL_TPM2 { "TPM 2.0 sealed" } else { "software AEAD" }
                        );
                    }
                    Err(e) => self.status = format!("Enrollment failed: {}", sys::status(e)),
                }
            }
            Msg::SetIdleSecs(secs) => {
                let _ = identity::set_policy(self.id_admin, secs, self.lock_policy.lock_on_sleep, self.lock_policy.lock_at_boot);
                let _ = awmi::set_lock_policy(self.awmi_admin, secs, self.lock_policy.lock_on_sleep);
                self.refresh_identity();
                self.status = format!("Idle lock timeout set to {} s", secs);
            }
            Msg::ToggleLockSleep => {
                let want = !self.lock_policy.lock_on_sleep;
                let _ = identity::set_policy(self.id_admin, self.lock_policy.idle_timeout_secs, want, self.lock_policy.lock_at_boot);
                let _ = awmi::set_lock_policy(self.awmi_admin, self.lock_policy.idle_timeout_secs, want);
                self.refresh_identity();
                self.status = format!("Lock on sleep {}", if want { "enabled" } else { "disabled" });
            }
            Msg::ToggleLockBoot => {
                let want = !self.lock_policy.lock_at_boot;
                let _ = identity::set_policy(self.id_admin, self.lock_policy.idle_timeout_secs, self.lock_policy.lock_on_sleep, want);
                self.refresh_identity();
                self.status = format!("Lock at boot {}", if want { "enabled" } else { "disabled" });
            }
            Msg::LockNow => {
                if let Err(e) = awmi::lock_session(self.awmi_admin, awmi::LOCK_REASON_MANUAL, awmi::LOCK_MODE_LOCKED) {
                    self.status = format!("Lock failed: {}", sys::status(e));
                }
            }
            Msg::NewUserChanged(s) => self.new_user = s,
            Msg::NewDisplayChanged(s) => self.new_display = s,
            Msg::ToggleNewOperator => self.new_operator = !self.new_operator,
            Msg::CreateUser => {
                let u = self.new_user.trim();
                let d = if self.new_display.trim().is_empty() { u } else { self.new_display.trim() };
                if u.eq_ignore_ascii_case("root") {
                    self.status = String::from("Refused: D-OS has no root user");
                    return;
                }
                let role = if self.new_operator { identity::ROLE_OPERATOR } else { identity::ROLE_STANDARD };
                match identity::create(self.id_admin, u, d, role) {
                    Ok(uid) => {
                        self.new_user.clear();
                        self.new_display.clear();
                        self.refresh_identity();
                        self.status = format!("Created identity #{}", uid);
                    }
                    Err(e) => self.status = format!("Create user failed: {}", sys::status(e)),
                }
            }
            Msg::SelectApp(i) => self.sel_app = i,
            Msg::ToggleAppPerm(bit) => {
                if let Some(a) = self.apps.get(self.sel_app).cloned() {
                    let was_on = (a.effective_perms & (1u32 << bit)) != 0;
                    let dec = if was_on { DECISION_DENIED } else { DECISION_GRANTED };
                    match appmgr::set_perm(self.app_admin, a.name_str(), bit, dec) {
                        Ok(()) => {
                            self.refresh_apps();
                            let pname = Permission::from_u8(bit).map_or("?", Permission::as_str);
                            self.status = format!("{} {} for {}", if was_on { "Revoked" } else { "Granted" }, pname, a.name_str());
                        }
                        Err(e) => self.status = format!("Permission update failed: {}", sys::status(e)),
                    }
                }
            }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "settings") } {
        return 1;
    }
    run_app("settings", SettingsApp::new(), 0)
}
