//! D-OS application manager (`appmgr.dsvc`).
//!
//! Discovers `.dapp` bundles in `/sys/apps/`, cryptographically verifies every bundle (outer
//! `KIND_APP` `.dsig` + inner `KIND_PROGRAM` `.dsig`) via the kernel's `vmo_verify` syscall,
//! registers verified apps with `awmi.launcher`, enforces per-identity revocable permissions
//! (`dosapp::PermissionLedger`), drives the compositor's unforgeable permission prompt, and
//! spawns verified apps with exact granted endpoint channels and per-identity namespaces.
//!
//! Holds NO `vmex` grant: only kernel-verified signed binaries can ever be spawned.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosapp::{AppManifest, PermDecision, Permission, PermissionLedger, ResourcePack};
use doscrypt::dsig;
use libd::appmgr::{self as wire, APP_INFO_BYTES, AppInfo, MAX_APPS, TAG_APP_RESOURCES};
use libd::awmi::{self, Event};
use libd::fs::{self as fp, NsBuilder};
use libd::handle::Owned;
use libd::identity::{self as idwire, IdentityInfo};
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle, SpawnHandle};
use libd::{Port, Startup, println, svc, tool};

libd::entry!(dsvc_appmgr, main);

const KEY_CTL: u64 = 1;
const KEY_AWMI: u64 = 2;
const KEY_CLIENT_BASE: u64 = 0x1000;
const KEY_PROC_BASE: u64 = 0x1_0000;

const MAX_CLIENTS: usize = 32;
const MAX_BUNDLE_BYTES: usize = 8 << 20;
const CALL_NS: u64 = 10_000_000_000;
const LEDGER_DIR: &[u8] = b"apps";
const LEDGER_FILE: &[u8] = b"apps/permissions.toml";
const LEDGER_TMP: &[u8] = b"apps/permissions.tmp";
const HOME_CFG_DIR: &[u8] = b".dos";
const HOME_LEDGER_FILE: &[u8] = b".dos/permissions.toml";
const HOME_LEDGER_TMP: &[u8] = b".dos/permissions.tmp";
const HOME_OOBE_FILE: &[u8] = b".dos/oobe.toml";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Query,
    Admin,
}

struct Client {
    id: u32,
    ch: Handle,
    role: Role,
}

struct InstalledApp {
    manifest: AppManifest,
    prog_vmo: Owned,
    res_vmo: Owned,
    entry_idx: u8,
    pinned: bool,
}

struct RunningApp {
    inst_id: u32,
    app_name: String,
    proc: Owned,
    granted_perms: u32,
}

struct PendingPrompt {
    request_id: u32,
    app_idx: usize,
    effective: u32,
    pending_mask: u32,
    launch_arg: Vec<u8>,
}

struct AppMgr {
    port: Port,
    ctl: Handle,
    mgr: Handle,
    awmi: Handle,
    identity: Handle,
    apps: Vec<InstalledApp>,
    running: Vec<RunningApp>,
    next_inst: u32,
    ledger: PermissionLedger,
    pending: Option<PendingPrompt>,
    next_req: u32,
    clients: Vec<Client>,
    next_client: u32,
}

fn split_connect(payload: &[u8]) -> &[u8] {
    match payload.iter().position(|&b| b == 0) {
        Some(i) => &payload[..i],
        None => payload,
    }
}

fn read_ns_file(path: &[u8], max: usize) -> Result<Vec<u8>, i64> {
    let ns = fp::Namespace::get();
    let Some((dir, rest)) = ns.resolve(path) else {
        return Err(fp::ERR_NOT_FOUND);
    };
    let d = fp::Node::from(dir);
    let res = (|| {
        let (f, _, size) = d.open(rest, 0, fp::R_READ)?;
        let size = usize::try_from(size).map_err(|_| sys::ERR_INVALID_ARGS)?;
        if size == 0 || size > max {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let mut buf = alloc::vec![0u8; size];
        let n = f.read(0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    })();
    let _ = d.into_handle();
    res
}

fn kernel_verify_vmo(data: &[u8], sig: &[u8], expected_kind: u32, expected_name: Option<&str>) -> Result<Owned, i64> {
    if sig.len() != dsig::SIZE {
        return Err(sys::ERR_BAD_SIGNATURE);
    }
    let h = dsig::parse(sig).map_err(|_| sys::ERR_BAD_SIGNATURE)?;
    if h.kind != expected_kind {
        return Err(sys::ERR_BAD_SIGNATURE);
    }
    if let Some(want) = expected_name
        && !h.name_str().eq_ignore_ascii_case(want)
    {
        return Err(sys::ERR_BAD_SIGNATURE);
    }
    let v = Owned::from_raw(sys::vmo_create(data.len().max(1) as u64)?);
    if sys::vmo_write(v.raw(), 0, data) != 0 {
        return Err(sys::ERR_BAD_STATE);
    }
    let d = Owned::from_raw(sys::vmo_create(sig.len() as u64)?);
    if sys::vmo_write(d.raw(), 0, sig) != 0 {
        return Err(sys::ERR_BAD_STATE);
    }
    let r = sys::vmo_verify(v.raw(), d.raw());
    if r != 0 {
        return Err(r);
    }
    let ro = sys::handle_replace(
        v.into_raw(),
        sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_DUPLICATE | sys::RIGHT_TRANSFER | sys::RIGHT_INSPECT,
    )?;
    Ok(Owned::from_raw(ro))
}

fn verify_bundle_bytes(bytes: &[u8]) -> Result<(AppManifest, Owned, Owned), i64> {
    let b = dosapp::parse_bundle(bytes).map_err(|_| sys::ERR_BAD_SIGNATURE)?;
    // 1. Verify outer .dapp payload signature (KIND_APP) via kernel vmo_verify.
    let _outer = kernel_verify_vmo(b.signed_payload, b.bundle_dsig, dsig::KIND_APP, None)?;
    // 2. Parse app manifest strictly (fail-closed) and cross-check binary entry name.
    let manifest = dosapp::parse_manifest(b.manifest.data).map_err(|_| sys::ERR_INVALID_ARGS)?;
    if manifest.binary != b.binary.name {
        return Err(sys::ERR_BAD_SIGNATURE);
    }
    // 3. Verify inner binary signature (KIND_PROGRAM) via kernel vmo_verify; keep sealed VMO.
    let prog_vmo = kernel_verify_vmo(b.binary.data, b.binary_sig.data, dsig::KIND_PROGRAM, Some(&manifest.binary))?;
    // 4. Pack read-only DRES resources into a read-only VMO for the app.
    let pairs: Vec<(&str, &[u8])> = b.resources.iter().map(|r| (r.name, r.data)).collect();
    let pack = ResourcePack::build(&pairs);
    let rv = Owned::from_raw(sys::vmo_create(pack.len().max(1) as u64)?);
    if sys::vmo_write(rv.raw(), 0, &pack) != 0 {
        return Err(sys::ERR_BAD_STATE);
    }
    let res_ro = sys::handle_replace(
        rv.into_raw(),
        sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_DUPLICATE | sys::RIGHT_TRANSFER,
    )?;
    Ok((manifest, prog_vmo, Owned::from_raw(res_ro)))
}

fn discover_apps() -> Vec<InstalledApp> {
    let mut out = Vec::new();
    let ns = fp::Namespace::get();
    let Some((dir, rest)) = ns.resolve(b"/sys/apps") else {
        return out;
    };
    let d = fp::Node::from(dir);
    let mut names: Vec<Vec<u8>> = Vec::new();
    if let Ok((apps_dir, _, _)) = d.open(rest, fp::O_DIRECTORY, fp::R_READ) {
        let _ = apps_dir.list(|n, kind| {
            if kind == fp::KIND_FILE && n.len() > 5 && n[n.len() - 5..].eq_ignore_ascii_case(b".dapp") {
                names.push(n.to_vec());
            }
        });
        names.sort();
        for n in names {
            if out.len() >= MAX_APPS {
                break;
            }
            let file = String::from_utf8_lossy(&n).into_owned();
            let full = format!("/sys/apps/{}", file);
            match read_ns_file(full.as_bytes(), MAX_BUNDLE_BYTES).and_then(|b| verify_bundle_bytes(&b)) {
                Ok((manifest, prog_vmo, res_vmo)) => {
                    let entry_idx = out.len() as u8;
                    let pinned = manifest.pinned;
                    println!(
                        "appmgr: verified {} ({} v{}, binary {})",
                        manifest.name, manifest.title, manifest.version, manifest.binary
                    );
                    out.push(InstalledApp { manifest, prog_vmo, res_vmo, entry_idx, pinned });
                }
                Err(e) => {
                    println!("appmgr: {} rejected ({})", full, sys::status(e));
                }
            }
        }
    }
    let _ = d.into_handle();
    out
}

fn load_ledger() -> PermissionLedger {
    let ns = fp::Namespace::get();
    for (vol, path) in [(b"/home" as &[u8], HOME_LEDGER_FILE), (b"/data" as &[u8], LEDGER_FILE)] {
        let Some((dir, _)) = ns.resolve(vol) else { continue };
        let d = fp::Node::from(dir);
        let parsed = (|| {
            let (f, _, size) = d.open(path, 0, fp::R_READ).ok()?;
            let size = usize::try_from(size).ok()?;
            if size == 0 || size > 64 * 1024 {
                return None;
            }
            let mut buf = alloc::vec![0u8; size];
            let n = f.read(0, &mut buf).ok()?;
            PermissionLedger::from_toml(&buf[..n]).ok()
        })();
        let _ = d.into_handle();
        if let Some(l) = parsed {
            return l;
        }
    }
    PermissionLedger::new()
}

fn write_ledger_at(dir_h: Handle, dir_name: &[u8], tmp_path: &[u8], dst_path: &[u8], text: &str) -> bool {
    let d = fp::Node::from(dir_h);
    let mut wrote = false;
    if d.stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0) {
        let _ = d.open(dir_name, fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE);
        if let Ok((f, _, _)) = d.open(tmp_path, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            && f.write(0, text.as_bytes()).is_ok()
        {
            drop(f);
            if d.rename(tmp_path, dst_path, true).is_err()
                && let Ok((f2, _, _)) = d.open(dst_path, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            {
                let _ = f2.write(0, text.as_bytes());
            }
            let _ = d.sync();
            wrote = true;
        }
    }
    let _ = d.into_handle();
    wrote
}

fn save_ledger(ledger: &PermissionLedger) {
    let ns = fp::Namespace::get();
    let text = ledger.to_toml();
    if let Some((dir, _)) = ns.resolve(b"/home")
        && write_ledger_at(dir, HOME_CFG_DIR, HOME_LEDGER_TMP, HOME_LEDGER_FILE, &text)
    {
        return;
    }
    if let Some((dir, _)) = ns.resolve(b"/data") {
        let _ = write_ledger_at(dir, LEDGER_DIR, LEDGER_TMP, LEDGER_FILE, &text);
    }
}

/// Returns `Some(true)` if `/home` is writable and OOBE is completed, `Some(false)` if OOBE is
/// pending on a newly installed disk, or `None` on live media / read-only `/home`.
fn oobe_status() -> Option<bool> {
    let ns = fp::Namespace::get();
    let (dir, _) = ns.resolve(b"/home")?;
    let d = fp::Node::from(dir);
    let res = (|| {
        let st = d.stat().ok()?;
        if st.rights & fp::R_WRITE == 0 {
            return None;
        }
        let (f, _, size) = d.open(HOME_OOBE_FILE, 0, fp::R_READ).ok()?;
        let size = usize::try_from(size).ok()?;
        if size == 0 || size > 16 * 1024 {
            return None;
        }
        let mut buf = alloc::vec![0u8; size];
        let n = f.read(0, &mut buf).ok()?;
        dosid::OobeConfig::from_toml(&buf[..n]).ok().map(|c| c.completed)
    })();
    let _ = d.into_handle();
    res
}

impl AppMgr {
    fn register_all_with_awmi(&self) {
        if self.awmi == 0 {
            return;
        }
        for app in &self.apps {
            let _ = awmi::register_launcher_app(
                self.awmi,
                app.entry_idx,
                app.manifest.title.as_bytes(),
                app.manifest.name.as_bytes(),
                app.pinned,
            );
        }
    }

    fn active_identity(&self) -> IdentityInfo {
        if self.identity != 0
            && let Ok(info) = idwire::active(self.identity)
        {
            return info;
        }
        let mut fallback = IdentityInfo {
            id: 1,
            role: idwire::ROLE_OPERATOR,
            seal: idwire::SEAL_NONE,
            active: true,
            enrolled: false,
            caps: dosid::caps::OPERATOR_DEFAULT,
            ..IdentityInfo::default()
        };
        fallback.name[..4].copy_from_slice(b"user");
        fallback.name_len = 4;
        fallback.home[..9].copy_from_slice(b"home/user");
        fallback.home_len = 9;
        fallback
    }

    fn mgr_link(&self, endpoint: &str, app_name: &str) -> Option<Handle> {
        if self.mgr == 0 {
            return None;
        }
        let ep = endpoint.as_bytes();
        let nm = app_name.as_bytes();
        if ep.len() + 1 + nm.len() > 96 {
            return None;
        }
        let mut req = [0u8; HEADER + 96];
        Header { txid: 0, op: svc::MGR_LINK, status: 0, a: 0, b: 0 }.put(&mut req);
        req[HEADER..HEADER + ep.len()].copy_from_slice(ep);
        req[HEADER + ep.len()] = 0;
        req[HEADER + ep.len() + 1..HEADER + ep.len() + 1 + nm.len()].copy_from_slice(nm);
        let mut rep = [0u8; HEADER];
        let mut hs = [0 as Handle; 1];
        let (n, nh) = sys::channel_call_h(self.mgr, &req[..HEADER + ep.len() + 1 + nm.len()], &[], &mut rep, &mut hs, CALL_NS).ok()?;
        let h = Header::get(&rep[..n])?;
        if h.status == 0 && nh > 0 && hs[0] != 0 {
            Some(hs[0])
        } else {
            if nh > 0 && hs[0] != 0 {
                sys::handle_close(hs[0]);
            }
            None
        }
    }

    fn spawn_app(&mut self, app_idx: usize, effective: u32, active: &IdentityInfo, launch_arg: &[u8]) -> Result<(), i64> {
        let Some(app) = self.apps.get(app_idx) else {
            return Err(fp::ERR_NOT_FOUND);
        };
        let app_name = app.manifest.name.clone();
        let prog_vmo = app.prog_vmo.raw();
        let res_vmo = app.res_vmo.raw();
        let limits = sys::Limits {
            memory: app.manifest.quota.memory,
            handles: app.manifest.quota.handles,
            threads: app.manifest.quota.threads,
        };

        let mut hs: Vec<SpawnHandle> = Vec::new();
        let push_h = |hs: &mut Vec<SpawnHandle>, handle: Handle, tag: u32| {
            hs.push(SpawnHandle { handle, rights: sys::RIGHTS_SAME, tag, reserved: 0 });
        };
        let close_all = |hs: &[SpawnHandle]| {
            for h in hs {
                sys::handle_close(h.handle);
            }
        };

        // 1. Log handle + read-only DRES resource pack VMO.
        let log = libd::startup_handle(sys::TAG_LOG);
        if log != 0
            && let Ok(d) = sys::handle_duplicate(log, sys::RIGHTS_SAME)
        {
            push_h(&mut hs, d, sys::TAG_LOG);
        }
        if let Ok(d) = sys::handle_duplicate(res_vmo, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER) {
            push_h(&mut hs, d, TAG_APP_RESOURCES);
        }

        // 2. Exact granted service endpoints (linked via `init` with verified identity = `app_name`).
        let mut ep_specs: Vec<&'static str> = Vec::new();
        let has = |p: Permission| (effective & p.bit()) != 0;
        if has(Permission::Window) {
            ep_specs.push("awmi.window");
        }
        if has(Permission::Terminal) {
            ep_specs.push("terminal.view");
        }
        if has(Permission::DisplayQuery) {
            ep_specs.push("gpu.query");
        }
        if has(Permission::DisplayAdmin) {
            ep_specs.push("awmi.admin");
        }
        if has(Permission::AudioControl) {
            ep_specs.push("audio.control");
        }
        if has(Permission::AudioPlayback) {
            ep_specs.push("audio.playback");
        }
        if has(Permission::NetStatus) {
            ep_specs.push("net.status");
        }
        if has(Permission::NetControl) {
            ep_specs.push("net.control");
        }
        if has(Permission::SystemQuery) {
            ep_specs.push("log.read");
            ep_specs.push("clock.time");
            if let Some(mch) = self.mgr_link("manager.services-ro", &app_name) {
                push_h(&mut hs, mch, tool::TAG_MANAGER);
            }
        }
        if has(Permission::IdentityQuery) {
            ep_specs.push("identity.query");
        }
        if has(Permission::IdentityAdmin) {
            ep_specs.push("identity.admin");
        }
        if has(Permission::AppsQuery) {
            ep_specs.push("appmgr.query");
        }
        if has(Permission::AppsAdmin) {
            ep_specs.push("appmgr.admin");
        }
        if has(Permission::StorageAdmin) {
            ep_specs.push("storaged.admin");
            if app_name == "oobe"
                && let Some(pch) = self.mgr_link("manager.power-reboot", &app_name)
            {
                push_h(&mut hs, pch, tool::TAG_MANAGER);
            }
        }

        let mut ep_names = Vec::new();
        let mut ep_k = 0u32;
        for ep in ep_specs {
            if let Some(ch) = self.mgr_link(ep, &app_name) {
                ep_names.extend_from_slice(ep.as_bytes());
                ep_names.push(0);
                push_h(&mut hs, ch, svc::TAG_ENDPOINT + ep_k);
                ep_k += 1;
            }
        }
        if ep_k > 0 {
            match sys::vmo_create(ep_names.len() as u64) {
                Ok(v) => {
                    sys::vmo_write(v, 0, &ep_names);
                    hs.push(SpawnHandle { handle: v, rights: sys::RIGHT_READ, tag: svc::TAG_ENDPOINT_NAMES, reserved: 0 });
                }
                Err(e) => {
                    close_all(&hs);
                    return Err(e);
                }
            }
        }

        // 3. Per-identity isolated namespace (files:read / files:write, or `/config` for OOBE).
        let need_files = has(Permission::FilesRead) || has(Permission::FilesWrite);
        let is_oobe = app_name == "oobe";
        if need_files || is_oobe {
            let want = fp::R_READ | if has(Permission::FilesWrite) { fp::R_WRITE } else { 0 };
            let ns = fp::Namespace::get();
            let mut nsb = NsBuilder::new();
            let mut added = 0usize;

            if is_oobe
                && let Some((home_h, _)) = ns.resolve(b"/home")
            {
                let h = fp::Node::from(home_h);
                let have = h.stat().map_or(fp::R_READ, |st| st.rights);
                let cfg_node = if (have & fp::R_WRITE) != 0 {
                    h.open(HOME_CFG_DIR, fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)
                        .ok()
                        .map(|(cd, _, _)| cd)
                } else {
                    h.open(HOME_CFG_DIR, fp::O_DIRECTORY, fp::R_READ).ok().map(|(cd, _, _)| cd)
                };
                if let Some(cn) = cfg_node {
                    nsb.add(b"/config", cn);
                    added += 1;
                }
                let _ = h.into_handle();
            }

            if need_files {
                // `/home` -> dedicated `/home/<active_identity_name>` volume when installed,
                // otherwise `/data/home/<active_identity_name>` fallback (always isolated per identity!).
                let mut home_added = false;
                if let Some((home_h, _)) = ns.resolve(b"/home") {
                    let h = fp::Node::from(home_h);
                    let have = h.stat().map_or(fp::R_READ, |st| st.rights);
                    let eff_r = want & have;
                    let home_node = if (have & fp::R_WRITE) != 0 {
                        h.open(active.name_str().as_bytes(), fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)
                            .ok()
                            .and_then(|(uh, _, _)| uh.clone_with(eff_r).ok())
                    } else {
                        h.open(active.name_str().as_bytes(), fp::O_DIRECTORY, fp::R_READ)
                            .ok()
                            .map(|(uh, _, _)| uh)
                    };
                    if let Some(hn) = home_node {
                        nsb.add(b"/home", hn);
                        added += 1;
                        home_added = true;
                    }
                    let _ = h.into_handle();
                }

                if let Some((data_h, _)) = ns.resolve(b"/data") {
                    let d = fp::Node::from(data_h);
                    let have = d.stat().map_or(fp::R_READ, |st| st.rights);
                    let eff_r = want & have;
                    if !home_added {
                        let home_node = if (have & fp::R_WRITE) != 0 {
                            d.open(b"home", fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)
                                .ok()
                                .and_then(|(hd, _, _)| {
                                    hd.open(active.name_str().as_bytes(), fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)
                                        .ok()
                                        .and_then(|(uh, _, _)| uh.clone_with(eff_r).ok())
                                })
                        } else {
                            let sub = format!("home/{}", active.name_str());
                            d.open(sub.as_bytes(), fp::O_DIRECTORY, fp::R_READ).ok().map(|(uh, _, _)| uh)
                        };
                        if let Some(hn) = home_node {
                            nsb.add(b"/home", hn);
                            added += 1;
                        }
                    }
                    // Only Operator identities receive `/data`.
                    if active.role == idwire::ROLE_OPERATOR
                        && let Ok(dn) = d.clone_with(eff_r)
                    {
                        nsb.add(b"/data", dn);
                        added += 1;
                    }
                    let _ = d.into_handle();
                }

                // Read-only `/system` and `/sys` when present.
                for vol in [b"/system" as &[u8], b"/sys"] {
                    if let Some((vh, _)) = ns.resolve(vol) {
                        let v = fp::Node::from(vh);
                        if let Ok(vn) = v.clone_with(fp::R_READ) {
                            nsb.add(vol, vn);
                            added += 1;
                        }
                        let _ = v.into_handle();
                    }
                }
            }

            if added > 0 {
                let mut out = [SpawnHandle::default(); fp::MAX_NS + 1];
                match nsb.finish(&mut out) {
                    Ok(n) => hs.extend_from_slice(&out[..n]),
                    Err(e) => {
                        close_all(&hs);
                        return Err(e);
                    }
                }
            }
        }

        let proc = sys::spawn(libd::startup_handle(sys::TAG_PROC_SELF), prog_vmo, app_name.as_bytes(), launch_arg, &hs, &limits)?;
        let inst_id = self.next_inst;
        self.next_inst = self.next_inst.wrapping_add(1).max(1);
        self.port.arm(proc, sys::TERMINATED, KEY_PROC_BASE + u64::from(inst_id));
        self.running.push(RunningApp {
            inst_id,
            app_name: app_name.clone(),
            proc: Owned::from_raw(proc),
            granted_perms: effective,
        });
        println!(
            "appmgr: launched {} for '{}' (perms: {})",
            app_name,
            active.name_str(),
            dosapp::format_perm_mask(effective)
        );
        Ok(())
    }

    /// Launch `app_idx`. Returns `Ok(1)` if spawned immediately, `Ok(2)` if awaiting prompt.
    fn launch_app(&mut self, app_idx: usize, allow_prompt: bool, launch_arg: &[u8]) -> Result<u64, i64> {
        let active = self.active_identity();
        let Some(app) = self.apps.get(app_idx) else {
            return Err(fp::ERR_NOT_FOUND);
        };
        let (effective, pending) = self.ledger.evaluate(
            active.name_str(),
            active.caps,
            &app.manifest.name,
            app.manifest.required_perms,
            app.manifest.optional_perms,
            app.manifest.prompt_perms,
        );
        if pending != 0 && allow_prompt && self.awmi != 0 {
            let req_id = self.next_req;
            self.next_req = self.next_req.wrapping_add(1).max(1);
            awmi::open_perm_prompt(self.awmi, req_id, pending, app.manifest.name.as_bytes(), app.manifest.title.as_bytes())?;
            self.pending = Some(PendingPrompt {
                request_id: req_id,
                app_idx,
                effective,
                pending_mask: pending,
                launch_arg: launch_arg.to_vec(),
            });
            println!("appmgr: requesting permission prompt #{} for {}", req_id, app.manifest.name);
            return Ok(2);
        }
        self.spawn_app(app_idx, effective, &active, launch_arg)?;
        Ok(1)
    }

    fn stop_app(&mut self, name: &str) -> u64 {
        let mut killed = 0u64;
        for r in &self.running {
            if r.app_name == name && r.proc.raw() != 0 {
                sys::process_kill(r.proc.raw());
                killed += 1;
            }
        }
        killed
    }

    fn reap(&mut self, inst_id: u32) {
        self.running.retain(|r| r.inst_id != inst_id);
    }

    fn on_ctl(&mut self) -> bool {
        let mut buf = [0u8; HEADER + 128];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        svc::CONNECT if hnd != 0 => {
                            let ep = split_connect(&buf[HEADER..n]);
                            match ep {
                                b"awmi.launcher" => {
                                    if self.awmi != 0 {
                                        sys::handle_close(self.awmi);
                                    }
                                    self.awmi = hnd;
                                    self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_AWMI);
                                    self.register_all_with_awmi();
                                }
                                b"identity.query" => {
                                    if self.identity != 0 {
                                        sys::handle_close(self.identity);
                                    }
                                    self.identity = hnd;
                                }
                                b"query" | b"admin" => {
                                    let role = if ep == b"admin" { Role::Admin } else { Role::Query };
                                    self.clients.retain(|c| c.ch != 0);
                                    if self.clients.len() < MAX_CLIENTS {
                                        let id = self.next_client;
                                        self.next_client = self.next_client.wrapping_add(1).max(1);
                                        self.clients.push(Client { id, ch: hnd, role });
                                        self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + u64::from(id));
                                    } else {
                                        sys::handle_close(hnd);
                                    }
                                }
                                _ => {
                                    sys::handle_close(hnd);
                                }
                            }
                        }
                        svc::SHUTDOWN => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            for r in &self.running {
                                if r.proc.raw() != 0 {
                                    sys::process_kill(r.proc.raw());
                                }
                            }
                            self.running.clear();
                            save_ledger(&self.ledger);
                            return false;
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    return true;
                }
                Err(_) => return true,
            }
        }
    }

    fn on_awmi(&mut self) {
        loop {
            match awmi::next_event(self.awmi, 0) {
                Ok(Some(ev)) => match ev {
                    Event::Session { active: true, desktop: true, .. } => {
                        for idx in 0..self.apps.len() {
                            if self.apps[idx].manifest.autostart {
                                let name = self.apps[idx].manifest.name.clone();
                                if !self.running.iter().any(|r| r.app_name == name) {
                                    let _ = self.launch_app(idx, false, b"");
                                }
                            }
                        }
                        match oobe_status() {
                            None => {
                                // Live media first boot: auto-launch unified Installer + OOBE window.
                                if let Some(idx) = self.apps.iter().position(|a| a.manifest.name == "oobe")
                                    && !self.running.iter().any(|r| r.app_name == "oobe")
                                {
                                    println!("appmgr: live boot detected, launching unified setup (oobe)");
                                    let _ = self.launch_app(idx, false, b"");
                                }
                            }
                            Some(false) => {
                                if let Some(idx) = self.apps.iter().position(|a| a.manifest.name == "oobe")
                                    && !self.running.iter().any(|r| r.app_name == "oobe")
                                {
                                    println!("appmgr: first-boot setup pending, launching oobe");
                                    let _ = self.launch_app(idx, false, b"");
                                }
                            }
                            Some(true) => {
                                println!("appmgr: OOBE completed, bypassing first-boot setup");
                            }
                        }
                    }
                    Event::Launch { app, arg, arg_len } => {
                        if let Some(idx) = self.apps.iter().position(|a| a.entry_idx == app) {
                            let len = usize::from(arg_len).min(arg.len());
                            let _ = self.launch_app(idx, true, &arg[..len]);
                        }
                    }
                    Event::AppPin { app, pinned } => {
                        if let Some(entry) = self.apps.iter_mut().find(|a| a.entry_idx == app) {
                            entry.pinned = pinned;
                        }
                    }
                    Event::PermResult { request_id, choice } => {
                        if let Some(p) = self.pending.take()
                            && p.request_id == request_id
                        {
                            let active = self.active_identity();
                            if let Some(app) = self.apps.get(p.app_idx) {
                                let app_name = app.manifest.name.clone();
                                match choice {
                                    1 => {
                                        self.ledger.apply_prompt(active.name_str(), &app_name, p.pending_mask, 0);
                                        save_ledger(&self.ledger);
                                        let _ = self.spawn_app(p.app_idx, p.effective | p.pending_mask, &active, &p.launch_arg);
                                    }
                                    2 => {
                                        self.ledger.apply_prompt(active.name_str(), &app_name, 0, p.pending_mask);
                                        save_ledger(&self.ledger);
                                        let _ = self.spawn_app(p.app_idx, p.effective, &active, &p.launch_arg);
                                    }
                                    _ => {
                                        println!("appmgr: launch of {} cancelled at permission prompt", app_name);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                },
                Ok(None) => {
                    self.port.arm(self.awmi, sys::READABLE | sys::PEER_CLOSED, KEY_AWMI);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn on_client(&mut self, id: u32) {
        let mut buf = [0u8; HEADER + 256];
        loop {
            let Some((ch, role)) = self.clients.iter().find(|c| c.id == id && c.ch != 0).map(|c| (c.ch, c.role)) else {
                return;
            };
            match sys::channel_read(ch, &mut buf, 0) {
                Ok(n) => {
                    let n = n as usize;
                    let Some(h) = Header::get(&buf[..n]) else { continue };
                    let (status, a, b, body) = self.handle(role, h, &buf[HEADER..n]);
                    if h.txid != 0 {
                        let mut rep = alloc::vec![0u8; HEADER + body.len()];
                        Header { txid: h.txid, op: h.op, status: status as i32, a, b }.put(&mut rep);
                        rep[HEADER..].copy_from_slice(&body);
                        sys::channel_write(ch, &rep);
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + u64::from(id));
                    return;
                }
                Err(_) => {
                    sys::handle_close(ch);
                    if let Some(c) = self.clients.iter_mut().find(|c| c.id == id) {
                        c.ch = 0;
                    }
                    return;
                }
            }
        }
    }

    fn handle(&mut self, role: Role, h: Header, payload: &[u8]) -> (i64, u64, u64, Vec<u8>) {
        let name = core::str::from_utf8(payload).unwrap_or("");
        match h.op {
            wire::OP_LIST => {
                let active = self.active_identity();
                let mut out = Vec::with_capacity(self.apps.len() * APP_INFO_BYTES);
                for app in &self.apps {
                    let (eff, _) = self.ledger.evaluate(
                        active.name_str(),
                        active.caps,
                        &app.manifest.name,
                        app.manifest.required_perms,
                        app.manifest.optional_perms,
                        app.manifest.prompt_perms,
                    );
                    let denied = self.ledger.record(active.name_str(), &app.manifest.name).map_or(0, |r| r.denied);
                    let run = self.running.iter().filter(|r| r.app_name == app.manifest.name).count() as u16;
                    let mut info = AppInfo {
                        required_perms: app.manifest.required_perms,
                        optional_perms: app.manifest.optional_perms,
                        prompt_perms: app.manifest.prompt_perms,
                        effective_perms: eff,
                        denied_perms: denied,
                        running: run,
                        pinned: app.pinned,
                        autostart: app.manifest.autostart,
                        verified: true,
                        ..AppInfo::default()
                    };
                    let nb = app.manifest.name.as_bytes();
                    let nl = nb.len().min(24);
                    info.name[..nl].copy_from_slice(&nb[..nl]);
                    info.name_len = nl as u8;
                    let tb = app.manifest.title.as_bytes();
                    let tl = tb.len().min(32);
                    info.title[..tl].copy_from_slice(&tb[..tl]);
                    info.title_len = tl as u8;
                    let vb = app.manifest.version.as_bytes();
                    let vl = vb.len().min(16);
                    info.version[..vl].copy_from_slice(&vb[..vl]);
                    info.version_len = vl as u8;
                    let mut enc = [0u8; APP_INFO_BYTES];
                    info.encode(&mut enc);
                    out.extend_from_slice(&enc);
                }
                (0, self.apps.len() as u64, 0, out)
            }
            wire::OP_PERMS => {
                let active = self.active_identity();
                let Some(app) = self.apps.iter().find(|a| a.manifest.name == name) else {
                    return (fp::ERR_NOT_FOUND, 0, 0, Vec::new());
                };
                let (eff, _) = self.ledger.evaluate(
                    active.name_str(),
                    active.caps,
                    &app.manifest.name,
                    app.manifest.required_perms,
                    app.manifest.optional_perms,
                    app.manifest.prompt_perms,
                );
                let denied = self.ledger.record(active.name_str(), &app.manifest.name).map_or(0, |r| r.denied);
                (0, u64::from(eff) | (u64::from(denied) << 32), 0, Vec::new())
            }
            wire::OP_RUNNING => {
                let cnt = self.running.iter().filter(|r| r.app_name == name).count() as u64;
                (0, cnt, 0, Vec::new())
            }
            wire::OP_LAUNCH if role == Role::Admin => {
                let Some(idx) = self.apps.iter().position(|a| a.manifest.name == name) else {
                    return (fp::ERR_NOT_FOUND, 0, 0, Vec::new());
                };
                match self.launch_app(idx, true, b"") {
                    Ok(code) => (0, code, 0, Vec::new()),
                    Err(e) => (e, 0, 0, Vec::new()),
                }
            }
            wire::OP_STOP if role == Role::Admin => {
                let k = self.stop_app(name);
                (0, k, 0, Vec::new())
            }
            wire::OP_SET_PERM if role == Role::Admin => {
                let Some(perm) = Permission::from_u8((h.a & 0xFF) as u8) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                let Some(dec) = PermDecision::from_u8(((h.a >> 8) & 0xFF) as u8) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                if !self.apps.iter().any(|a| a.manifest.name == name) {
                    return (fp::ERR_NOT_FOUND, 0, 0, Vec::new());
                }
                let active = self.active_identity();
                self.ledger.set_decision(active.name_str(), name, perm, dec);
                save_ledger(&self.ledger);
                if dec == PermDecision::Denied {
                    // Immediate live revocation: terminate any running instance holding this permission.
                    let mut revoked = 0u32;
                    for r in &self.running {
                        if r.app_name == name && (r.granted_perms & perm.bit()) != 0 && r.proc.raw() != 0 {
                            sys::process_kill(r.proc.raw());
                            revoked += 1;
                        }
                    }
                    println!(
                        "appmgr: revoked {} from {} for '{}' (stopped {} running instance(s))",
                        perm.as_str(),
                        name,
                        active.name_str(),
                        revoked
                    );
                } else {
                    println!(
                        "appmgr: updated {} for {} ({}) -> {:?}",
                        perm.as_str(),
                        name,
                        active.name_str(),
                        dec
                    );
                }
                (0, 0, 0, Vec::new())
            }
            wire::OP_INSTALL_CHECK if role == Role::Admin => {
                if payload.is_empty() {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                }
                match read_ns_file(payload, MAX_BUNDLE_BYTES).and_then(|b| verify_bundle_bytes(&b)) {
                    Ok((m, _, _)) => {
                        println!("appmgr: verify {}: valid ({} v{})", name, m.name, m.version);
                        (0, 0, 0, Vec::new())
                    }
                    Err(e) => {
                        println!("appmgr: verify {}: rejected ({})", name, sys::status(e));
                        (e, 0, 0, Vec::new())
                    }
                }
            }
            wire::OP_SET_PIN if role == Role::Admin => {
                let pinned = h.a != 0;
                let Some(app) = self.apps.iter_mut().find(|a| a.manifest.name == name) else {
                    return (fp::ERR_NOT_FOUND, 0, 0, Vec::new());
                };
                app.pinned = pinned;
                if self.awmi != 0 {
                    let _ = awmi::register_launcher_app_ex(
                        self.awmi,
                        app.entry_idx,
                        app.manifest.title.as_bytes(),
                        app.manifest.name.as_bytes(),
                        pinned,
                        true,
                    );
                }
                println!("appmgr: {} {} taskbar", if pinned { "pinned" } else { "unpinned" }, name);
                (0, 0, 0, Vec::new())
            }
            wire::OP_LAUNCH | wire::OP_STOP | wire::OP_SET_PERM | wire::OP_INSTALL_CHECK | wire::OP_SET_PIN => {
                (sys::ERR_ACCESS_DENIED, 0, 0, Vec::new())
            }
            _ => (sys::ERR_NOT_SUPPORTED, 0, 0, Vec::new()),
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "appmgr") } {
        return 1;
    }
    let Ok(port) = Port::new(128) else { return 1 };
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let mgr = libd::startup_handle(tool::TAG_MANAGER);
    let awmi = awmi::launcher_endpoint();
    let identity = idwire::query_endpoint();
    let mut apps = discover_apps();
    // On an installed system: once OOBE is completed, hide the installer/setup app completely
    // (no Install D-OS app in dock, launcher, or app list). While OOBE is pending on a CLI-installed
    // disk, keep `oobe` unpinned for its one-time run.
    match oobe_status() {
        Some(true) => {
            apps.retain(|a| a.manifest.name != "oobe" && a.manifest.name != "installer");
            for (idx, a) in apps.iter_mut().enumerate() {
                a.entry_idx = idx as u8;
            }
        }
        Some(false) => {
            apps.retain(|a| a.manifest.name != "installer");
            for (idx, a) in apps.iter_mut().enumerate() {
                a.entry_idx = idx as u8;
                if a.manifest.name == "oobe" {
                    a.pinned = false;
                }
            }
        }
        None => {}
    }
    let ledger = load_ledger();
    let mut state = AppMgr {
        port,
        ctl,
        mgr,
        awmi,
        identity,
        apps,
        running: Vec::new(),
        next_inst: 1,
        ledger,
        pending: None,
        next_req: 1,
        clients: Vec::new(),
        next_client: 1,
    };
    if state.ctl != 0 {
        state.port.arm(state.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if state.awmi != 0 {
        state.port.arm(state.awmi, sys::READABLE | sys::PEER_CLOSED, KEY_AWMI);
        state.register_all_with_awmi();
    }
    println!("appmgr: ready, {} verified .dapp bundle(s)", state.apps.len());
    loop {
        let Some((k, _)) = state.port.wait(sys::WAIT_FOREVER) else { continue };
        match k {
            KEY_CTL => {
                if !state.on_ctl() {
                    return 0;
                }
            }
            KEY_AWMI => state.on_awmi(),
            k if k >= KEY_PROC_BASE => state.reap((k - KEY_PROC_BASE) as u32),
            k if k >= KEY_CLIENT_BASE => state.on_client((k - KEY_CLIENT_BASE) as u32),
            _ => {}
        }
    }
}
