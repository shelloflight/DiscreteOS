//! D-OS Disk Installer (`installer.dapp`).
//!
//! Capability-gated via `storage:admin` (`storaged.admin`, Operator-only).
//! Supports three explicit installation modes:
//! 1. Dual Boot (Recommended): installs into unallocated GPT free space without modifying any
//!    existing OS partition, adding `\EFI\DOS\BOOTX64.EFI` non-destructively to an existing ESP.
//! 2. Use Entire Disk: formats an unpartitioned / blank disk with GPT (`bios-boot` + `esp` + `sys` + `home`).
//! 3. Wipe & Repartition: explicitly confirmed full wipe + fresh GPT layout, plus individual
//!    partition deletion so users can free space on existing drives like Linux/Windows installers.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosui::{Length, Node, Tone, button, caption, column, divider, heading, item, label, mono, panel, row, scroll, spacer, text, toggle};
use libd::install::{
    self, DiskSummary, MAX_DISKS, MODE_DUAL_BOOT, MODE_WHOLE_DISK, MODE_WIPE_DISK,
};
use libd::sys::{self, Handle};
use libd::{Startup, println};

use crate::common::{App, run_app};

#[derive(Clone)]
enum Msg {
    Refresh,
    SelectDisk(usize),
    SelectPart(u32),
    SelectMode(u8),
    ToggleConfirmDelete,
    DeleteSelectedPart,
    ToggleConfirmWipe,
    PreviewPlan,
    RunInstall,
}

struct InstallerApp {
    ep: Handle,
    disks: Vec<DiskSummary>,
    sel_disk: usize,
    sel_part: Option<u32>,
    mode: u8,
    confirm_delete: bool,
    confirm_wipe: bool,
    plan_text: String,
    plan_ok: bool,
    status: String,
    installed_ok: bool,
}

impl InstallerApp {
    fn new() -> Self {
        let ep = install::admin_endpoint();
        let mut app = Self {
            ep,
            disks: Vec::new(),
            sel_disk: 0,
            sel_part: None,
            mode: MODE_DUAL_BOOT,
            confirm_delete: false,
            confirm_wipe: false,
            plan_text: String::new(),
            plan_ok: false,
            status: if ep == 0 {
                String::from("storage:admin permission not granted (Operator identity required).")
            } else {
                String::from("Select a target disk to preview an installation plan.")
            },
            installed_ok: false,
        };
        app.refresh();
        app
    }

    fn selected_disk(&self) -> Option<&DiskSummary> {
        self.disks.get(self.sel_disk)
    }

    fn auto_pick_mode(&mut self) {
        self.confirm_wipe = false;
        self.confirm_delete = false;
        self.sel_part = None;
        if let Some(d) = self.selected_disk() {
            if d.is_blank() {
                self.mode = MODE_WHOLE_DISK;
            } else {
                self.mode = MODE_DUAL_BOOT;
            }
        }
    }

    fn refresh(&mut self) {
        self.disks.clear();
        if self.ep == 0 {
            return;
        }
        let mut buf = [DiskSummary::default(); MAX_DISKS];
        match install::list_disks(self.ep, &mut buf) {
            Ok(n) => {
                self.disks.extend_from_slice(&buf[..n]);
                if self.sel_disk >= self.disks.len() || self.disks[self.sel_disk].is_live_boot() || self.disks[self.sel_disk].is_optical() {
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
        if self.ep == 0 {
            return;
        }
        let Some(d) = self.selected_disk() else {
            self.plan_text = String::from("No disks detected.");
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
        match install::plan(self.ep, &disk_name, self.mode, self.confirm_wipe, &mut out) {
            Ok(n) => {
                self.plan_text = String::from_utf8_lossy(&out[..n]).into_owned();
                self.plan_ok = true;
            }
            Err((e, n)) => {
                if n > 0 {
                    self.plan_text = String::from_utf8_lossy(&out[..n]).into_owned();
                } else {
                    self.plan_text = format!("Plan unavailable: {}", sys::status(e));
                }
                self.plan_ok = false;
            }
        }
    }
}

impl App for InstallerApp {
    type Msg = Msg;

    fn title(&self) -> &str {
        "Install DiscreteOS"
    }

    fn size(&self) -> (u32, u32) {
        (880, 620)
    }

    fn view(&self) -> Node<Msg> {
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
            label("Target Drives"),
            caption("Live and optical media are protected."),
            divider(),
            scroll(column(disk_items).gap(4)).height(Length::Fill),
            divider(),
            button("Refresh Drives").on_press(Msg::Refresh),
        ])
        .width(Length::Px(260))
        .height(Length::Fill);

        let right_content = if let Some(d) = self.selected_disk() {
            let mut rows: Vec<Node<Msg>> = Vec::new();
            let tbl = if d.is_blank() {
                "Unpartitioned (blank disk)"
            } else if d.has_gpt() {
                "GPT"
            } else if d.has_mbr() {
                "Legacy MBR"
            } else {
                "Unknown"
            };
            rows.push(panel([
                label(format!("{} — {}", d.name_str(), if d.model_len > 0 { d.model_str() } else { "Block Device" })),
                mono(format!(
                    "Capacity: {} MiB ({} sectors) | Table: {} | Free: {} MiB (largest {} MiB)",
                    d.size_mib(),
                    d.sectors,
                    tbl,
                    d.total_free_mib,
                    d.largest_free_mib
                )),
            ]));

            // Existing partitions + optional delete (for freeing space / repartitioning).
            let mut part_nodes: Vec<Node<Msg>> = alloc::vec![
                label(format!("Existing Partitions ({})", d.part_count)),
                caption("Existing OS partitions are untouched in Dual Boot mode. Delete unused partitions to reclaim GPT space."),
            ];
            let parts = d.parts_slice();
            if parts.is_empty() {
                part_nodes.push(caption("No partitions on this drive."));
            } else {
                for p in parts {
                    let line = format!(
                        "#{}  {}  [{}]  {} MiB  (LBA {}..{})",
                        p.index,
                        if p.name_len > 0 { p.name_str() } else { "(unnamed)" },
                        p.fs_str(),
                        p.size_mib,
                        p.first,
                        p.last
                    );
                    part_nodes.push(
                        item(line, self.sel_part == Some(p.index))
                            .on_select(Msg::SelectPart(p.index)),
                    );
                }
                if !d.is_live_boot() && !d.is_optical() && d.has_gpt() {
                    part_nodes.push(divider());
                    let del_btn = if self.sel_part.is_some() && self.confirm_delete {
                        button("Delete Selected Partition").danger().on_press(Msg::DeleteSelectedPart)
                    } else {
                        button("Delete Selected Partition").danger()
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

            // Installation Mode selector.
            let dual_btn = if self.mode == MODE_DUAL_BOOT {
                button("Dual Boot (Recommended)").primary()
            } else {
                button("Dual Boot (Recommended)")
            }
            .on_press(Msg::SelectMode(MODE_DUAL_BOOT));

            let whole_btn = if self.mode == MODE_WHOLE_DISK {
                button("Use Entire Disk").primary()
            } else {
                button("Use Entire Disk")
            }
            .on_press(Msg::SelectMode(MODE_WHOLE_DISK));

            let wipe_btn = if self.mode == MODE_WIPE_DISK {
                button("Wipe & Repartition").danger()
            } else {
                button("Wipe & Repartition")
            }
            .on_press(Msg::SelectMode(MODE_WIPE_DISK));

            let mode_desc = match self.mode {
                MODE_DUAL_BOOT => "Installs into unallocated GPT free space without touching existing Windows/Linux partitions. Adds \\EFI\\DOS\\BOOTX64.EFI alongside existing bootloaders.",
                MODE_WHOLE_DISK => "Uses the entire unpartitioned disk (refuses disks that already have a partition table). Creates bios-boot, ESP, immutable sys, and writable home.",
                _ => "DESTRUCTIVE: Erases every existing partition on the selected drive and installs a fresh GPT layout (bios-boot, ESP, immutable sys, writable home).",
            };

            let mut mode_nodes: Vec<Node<Msg>> = alloc::vec![
                label("Installation Mode"),
                row([dual_btn, whole_btn, wipe_btn]).gap(8),
                caption(mode_desc),
            ];
            if self.mode == MODE_WIPE_DISK {
                mode_nodes.push(
                    toggle("I understand: wipe ALL existing partitions and data on this drive", self.confirm_wipe)
                        .on_toggle(Msg::ToggleConfirmWipe),
                );
            }
            rows.push(panel(mode_nodes));

            // Plan preview box.
            let mut plan_nodes: Vec<Node<Msg>> = alloc::vec![
                row([
                    label("Installation Plan"),
                    spacer(),
                    button("Re-check Plan").on_press(Msg::PreviewPlan),
                ])
                .gap(8),
            ];
            for line in self.plan_text.lines() {
                plan_nodes.push(mono(line));
            }
            rows.push(panel(plan_nodes));

            let can_install = self.ep != 0
                && !d.is_live_boot()
                && !d.is_optical()
                && self.plan_ok
                && (self.mode != MODE_WIPE_DISK || self.confirm_wipe);

            let base_btn = if self.mode == MODE_WIPE_DISK {
                button("Wipe & Install DiscreteOS").danger()
            } else {
                button("Install DiscreteOS").primary()
            };
            let install_btn = if can_install { base_btn.on_press(Msg::RunInstall) } else { base_btn };

            rows.push(
                row([
                    text(&self.status).tone(if self.installed_ok { Tone::Primary } else { Tone::Muted }),
                    spacer(),
                    install_btn,
                ])
                .gap(8),
            );

            scroll(column(rows).gap(10)).width(Length::Fill).height(Length::Fill)
        } else {
            panel([caption("No target drive selected.")]).width(Length::Fill).height(Length::Fill)
        };

        column([
            row([
                heading("DiscreteOS Disk Installer"),
                spacer(),
                caption("Immutable sys + persistent multi-user /home"),
            ])
            .gap(12),
            divider(),
            row([left, right_content]).gap(12).height(Length::Fill),
        ])
        .padding(14)
        .gap(10)
        .width(Length::Fill)
        .height(Length::Fill)
    }

    fn update(&mut self, msg: Msg) {
        match msg {
            Msg::Refresh => {
                self.status = String::from("Refreshed drive list.");
                self.refresh();
            }
            Msg::SelectDisk(i) => {
                if i < self.disks.len() {
                    self.sel_disk = i;
                    self.installed_ok = false;
                    self.auto_pick_mode();
                    self.refresh_plan();
                }
            }
            Msg::SelectPart(idx) => {
                self.sel_part = Some(idx);
                self.confirm_delete = false;
            }
            Msg::SelectMode(m) => {
                self.mode = m;
                self.confirm_wipe = false;
                self.installed_ok = false;
                self.refresh_plan();
            }
            Msg::ToggleConfirmDelete => {
                self.confirm_delete = !self.confirm_delete;
            }
            Msg::DeleteSelectedPart => {
                if !self.confirm_delete {
                    return;
                }
                let (Some(d), Some(pidx)) = (self.selected_disk(), self.sel_part) else {
                    return;
                };
                let dname = String::from(d.name_str());
                let mut out = [0u8; 4096];
                match install::delete_part(self.ep, &dname, pidx, true, &mut out) {
                    Ok(n) => {
                        self.status = String::from_utf8_lossy(&out[..n]).into_owned();
                        self.confirm_delete = false;
                        self.sel_part = None;
                        self.refresh();
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
            Msg::PreviewPlan => {
                self.refresh_plan();
            }
            Msg::RunInstall => {
                let Some(d) = self.selected_disk() else {
                    return;
                };
                let dname = String::from(d.name_str());
                self.status = format!("Installing DiscreteOS to {}...", dname);
                println!("installer: starting install to {} (mode={})", dname, self.mode);
                let mut out = [0u8; 4096];
                match install::execute(self.ep, &dname, self.mode, self.confirm_wipe, &mut out) {
                    Ok(n) => {
                        let summary = String::from_utf8_lossy(&out[..n]).into_owned();
                        println!("installer: {}", summary);
                        self.plan_text = summary;
                        self.installed_ok = true;
                        self.status = if self.plan_text.contains("(reused)") {
                            String::from("Installed & verified! Reboot once with live media attached to register 'DiscreteOS' in BIOS NVRAM, then remove live media.")
                        } else {
                            String::from("Installed & verified! Reboot and select this drive in BIOS (or reboot once with live media attached to register 'DiscreteOS' in NVRAM).")
                        };
                    }
                    Err((e, n)) => {
                        self.installed_ok = false;
                        self.status = if n > 0 {
                            String::from_utf8_lossy(&out[..n]).into_owned()
                        } else {
                            format!("Install failed: {}", sys::status(e))
                        };
                        println!("installer: error: {}", self.status);
                    }
                }
            }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "installer") } {
        return 1;
    }
    run_app("installer", InstallerApp::new(), 0)
}
