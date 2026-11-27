//! D-OS user identity & TPM 2.0 credential sealing service (`identity.dsvc`).
//!
//! Holds the `TPM_SEAL` kernel resource (`grants.tpm-seal = true`) and serves three separated
//! endpoints:
//! - `identity.query`: read active identity, list identities, read lock policy and test counters.
//! - `identity.admin`: enroll passphrases (TPM 2.0 SRK-sealed when present, software AEAD fallback
//!   otherwise), create non-root identities, switch active identity, and configure lock policy.
//! - `identity.session`: authenticate passphrases with exponential backoff throttling (granted only
//!   to `awmi` so no app can probe or brute-force credentials).

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use doscrypt::ct::wipe_bytes;
use dosid::{
    AuthThrottle, Credential, IDENTITY_WIRE_BYTES, IdentityError, IdentityRole, IdentityStore, IdentityWire,
    LOCK_POLICY_WIRE_BYTES, LockPolicyWire, SealKind,
};
use libd::fs as fp;
use libd::identity as wire;
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Port, Startup, println, svc};

libd::entry!(dsvc_identity, main);

const KEY_CTL: u64 = 1;
const KEY_CLIENT_BASE: u64 = 0x1000;
const MAX_CLIENTS: usize = 64;
const PBKDF2_ITER: u32 = 16_000;
const STORE_DIR: &[u8] = b"identities";
const STORE_FILE: &[u8] = b"identities/store.toml";
const STORE_TMP: &[u8] = b"identities/store.tmp";
const HOME_CFG_DIR: &[u8] = b".dos";
const HOME_STORE_FILE: &[u8] = b".dos/identities.toml";
const HOME_STORE_TMP: &[u8] = b".dos/identities.tmp";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Session,
    Admin,
    Query,
}

struct Client {
    id: u32,
    ch: Handle,
    role: Role,
}

struct IdSvc {
    port: Port,
    ctl: Handle,
    tpm_res: Handle,
    tpm_available: bool,
    tpm_seal_ops: u16,
    tpm_unseal_ops: u16,
    auth_failures: u16,
    store: IdentityStore,
    throttles: Vec<(u32, AuthThrottle)>,
    clients: Vec<Client>,
    next_client: u32,
}

fn split_connect(payload: &[u8]) -> &[u8] {
    match payload.iter().position(|&b| b == 0) {
        Some(i) => &payload[..i],
        None => payload,
    }
}

fn probe_tpm(tpm_res: Handle) -> bool {
    if tpm_res == 0 {
        return false;
    }
    let mut auth = [0u8; 16];
    let mut secret = [0u8; 16];
    if sys::get_random(&mut auth, 0).is_err() || sys::get_random(&mut secret, 0).is_err() {
        return false;
    }
    let mut blob = [0u8; sys::TPM_SEAL_BLOB_MAX];
    let mut unsealed = [0u8; 32];
    let ok = match sys::tpm_seal(tpm_res, &auth, &secret, &mut blob) {
        Ok(blen) => match sys::tpm_unseal(tpm_res, &auth, &blob[..blen], &mut unsealed) {
            Ok(ulen) => ulen == secret.len() && doscrypt::ct::ct_eq(&unsealed[..ulen], &secret),
            Err(_) => false,
        },
        Err(_) => false,
    };
    wipe_bytes(&mut auth);
    wipe_bytes(&mut secret);
    wipe_bytes(&mut blob);
    wipe_bytes(&mut unsealed);
    ok
}

fn load_store() -> IdentityStore {
    let ns = fp::Namespace::get();
    for (vol, path, label) in [
        (b"/home" as &[u8], HOME_STORE_FILE, "/home/.dos/identities.toml"),
        (b"/data" as &[u8], STORE_FILE, "/data/identities/store.toml"),
        (b"/system" as &[u8], STORE_FILE, "/system/identities/store.toml"),
    ] {
        let Some((dir, _)) = ns.resolve(vol) else { continue };
        let d = fp::Node::from(dir);
        let parsed = (|| {
            let (f, _, size) = d.open(path, 0, fp::R_READ).ok()?;
            let size = usize::try_from(size).ok()?;
            if size == 0 || size > 64 * 1024 {
                println!("identity: ignoring {} (size {} out of range)", label, size);
                return None;
            }
            let mut buf = alloc::vec![0u8; size];
            let n = f.read(0, &mut buf).ok()?;
            match IdentityStore::from_toml(&buf[..n]) {
                Ok(store) => {
                    println!(
                        "identity: loaded {} ({} identity(s), lock_at_boot={})",
                        label,
                        store.identities.len(),
                        store.lock_policy.lock_at_boot
                    );
                    Some(store)
                }
                Err(e) => {
                    println!("identity: failed to parse {} ({} bytes): {}", label, n, e.message());
                    None
                }
            }
        })();
        let _ = d.into_handle();
        if let Some(s) = parsed {
            return s;
        }
    }
    IdentityStore::default_store()
}

fn write_store_at(dir_h: Handle, dir_name: &[u8], tmp_path: &[u8], dst_path: &[u8], text: &str) -> bool {
    let d = fp::Node::from(dir_h);
    let can_write = d.stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0);
    let mut wrote = false;
    if can_write {
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

fn save_store(store: &IdentityStore) {
    let ns = fp::Namespace::get();
    let text = store.to_toml();
    if let Some((dir, _)) = ns.resolve(b"/home")
        && write_store_at(dir, HOME_CFG_DIR, HOME_STORE_TMP, HOME_STORE_FILE, &text)
    {
        return;
    }
    if let Some((dir, _)) = ns.resolve(b"/data") {
        let _ = write_store_at(dir, STORE_DIR, STORE_TMP, STORE_FILE, &text);
    }
}

fn ensure_home_dir(name: &str) {
    let ns = fp::Namespace::get();
    if let Some((dir, _)) = ns.resolve(b"/home") {
        let d = fp::Node::from(dir);
        let ok = if d.stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0) {
            let _ = d.open(name.as_bytes(), fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE);
            let _ = d.sync();
            true
        } else {
            false
        };
        let _ = d.into_handle();
        if ok {
            return;
        }
    }
    let Some((dir, _)) = ns.resolve(b"/data") else { return };
    let d = fp::Node::from(dir);
    if d.stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0)
        && let Ok((home, _, _)) = d.open(b"home", fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)
    {
        let _ = home.open(name.as_bytes(), fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE);
        let _ = home.sync();
    }
    let _ = d.into_handle();
}

fn map_id_err(e: IdentityError) -> i64 {
    match e {
        IdentityError::RootForbidden | IdentityError::PermissionDenied | IdentityError::InvalidCredentials => sys::ERR_ACCESS_DENIED,
        IdentityError::NotFound => fp::ERR_NOT_FOUND,
        IdentityError::DuplicateName => fp::ERR_EXISTS,
        IdentityError::TooManyIdentities => sys::ERR_NO_RESOURCES,
        IdentityError::Throttled(_) => sys::ERR_SHOULD_WAIT,
        _ => sys::ERR_INVALID_ARGS,
    }
}

impl IdSvc {
    fn throttle_mut(&mut self, id: u32) -> &mut AuthThrottle {
        if let Some(pos) = self.throttles.iter().position(|(x, _)| *x == id) {
            return &mut self.throttles[pos].1;
        }
        self.throttles.push((id, AuthThrottle::default()));
        &mut self.throttles.last_mut().unwrap().1
    }

    fn verify_passphrase(&mut self, id_num: u32, pass: &[u8]) -> Result<u32, (i64, u64)> {
        let now = sys::clock_ns();
        let retry_ns = self.throttle_mut(id_num).retry_after_ns(now);
        if retry_ns > 0 {
            let secs = retry_ns.div_ceil(1_000_000_000).max(1);
            return Err((sys::ERR_SHOULD_WAIT, secs));
        }
        let Some(ident) = self.store.find_by_id(id_num).cloned() else {
            return Err((fp::ERR_NOT_FOUND, 0));
        };
        if !ident.cred.is_enrolled() {
            self.throttle_mut(id_num).reset();
            self.store.active_id = ident.id;
            save_store(&self.store);
            return Ok(ident.id);
        }
        let verified = match ident.cred.seal {
            SealKind::None => true,
            SealKind::Software => match ident.cred.open_software(ident.id, &ident.name, pass) {
                Ok(mut sec) => {
                    wipe_bytes(&mut sec);
                    true
                }
                Err(_) => false,
            },
            SealKind::Tpm2 => {
                if !self.tpm_available || self.tpm_res == 0 {
                    false
                } else if let Ok(mut auth) = ident.cred.tpm_auth_for(pass) {
                    let mut out = [0u8; 64];
                    let res = sys::tpm_unseal(self.tpm_res, &auth, &ident.cred.blob, &mut out);
                    wipe_bytes(&mut auth);
                    self.tpm_unseal_ops = self.tpm_unseal_ops.saturating_add(1);
                    let ok = match res {
                        Ok(n) => ident.cred.verify_tpm_unsealed(ident.id, &ident.name, &out[..n]),
                        Err(_) => false,
                    };
                    wipe_bytes(&mut out);
                    ok
                } else {
                    false
                }
            }
        };
        if verified {
            self.throttle_mut(id_num).reset();
            if self.store.active_id != ident.id {
                self.store.active_id = ident.id;
                save_store(&self.store);
            }
            ensure_home_dir(&ident.name);
            Ok(ident.id)
        } else {
            self.auth_failures = self.auth_failures.saturating_add(1);
            let delay = self.throttle_mut(id_num).record_failure(now);
            let secs = delay.div_ceil(1_000_000_000);
            Err((sys::ERR_ACCESS_DENIED, secs))
        }
    }

    fn enroll_passphrase(&mut self, id_num: u32, pass: &[u8]) -> Result<u8, i64> {
        let target_id = if id_num == 0 { self.store.active_id } else { id_num };
        let Some(ident) = self.store.find_by_id(target_id).cloned() else {
            return Err(fp::ERR_NOT_FOUND);
        };
        if pass.is_empty() || pass.len() > dosid::model::MAX_PASSPHRASE {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let mut salt = [0u8; 16];
        let mut secret = [0u8; 32];
        sys::get_random(&mut salt, 0)?;
        sys::get_random(&mut secret, 0)?;

        let cred = if self.tpm_available && self.tpm_res != 0 {
            let (mut auth, verifier, iter) = Credential::prepare_tpm(ident.id, &ident.name, pass, salt, &secret, PBKDF2_ITER)
                .map_err(map_id_err)?;
            let mut blob = [0u8; sys::TPM_SEAL_BLOB_MAX];
            let sealed = sys::tpm_seal(self.tpm_res, &auth, &secret, &mut blob);
            wipe_bytes(&mut auth);
            match sealed {
                Ok(blen) => {
                    self.tpm_seal_ops = self.tpm_seal_ops.saturating_add(1);
                    let c = Credential::from_tpm_blob(salt, iter, verifier, blob[..blen].to_vec()).map_err(map_id_err)?;
                    wipe_bytes(&mut blob);
                    c
                }
                Err(_) => {
                    wipe_bytes(&mut blob);
                    let mut nonce = [0u8; 12];
                    sys::get_random(&mut nonce, 0)?;
                    Credential::seal_software(ident.id, &ident.name, pass, salt, nonce, &secret, PBKDF2_ITER).map_err(map_id_err)?
                }
            }
        } else {
            let mut nonce = [0u8; 12];
            sys::get_random(&mut nonce, 0)?;
            Credential::seal_software(ident.id, &ident.name, pass, salt, nonce, &secret, PBKDF2_ITER).map_err(map_id_err)?
        };
        wipe_bytes(&mut secret);
        let kind = cred.seal as u8;
        if let Some(slot) = self.store.find_by_id_mut(target_id) {
            slot.cred = cred;
        }
        self.throttle_mut(target_id).reset();
        save_store(&self.store);
        println!(
            "identity: enrolled credential for '{}' ({})",
            ident.name,
            if kind == wire::SEAL_TPM2 { "TPM 2.0 sealed" } else { "software AEAD" }
        );
        Ok(kind)
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
                            let role = match ep {
                                b"session" => Some(Role::Session),
                                b"admin" => Some(Role::Admin),
                                b"query" => Some(Role::Query),
                                _ => None,
                            };
                            self.clients.retain(|c| c.ch != 0);
                            if let Some(role) = role
                                && self.clients.len() < MAX_CLIENTS
                            {
                                let id = self.next_client;
                                self.next_client = self.next_client.wrapping_add(1).max(1);
                                self.clients.push(Client { id, ch: hnd, role });
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + u64::from(id));
                            } else {
                                sys::handle_close(hnd);
                            }
                        }
                        svc::SHUTDOWN => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            save_store(&self.store);
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
                    // Wipe any passphrase bytes that may have arrived in `buf`.
                    buf[HEADER..n].fill(0);
                    core::hint::black_box(&buf);
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
        match h.op {
            wire::OP_ACTIVE => {
                let Some(id) = self.store.active() else {
                    return (sys::ERR_BAD_STATE, 0, 0, Vec::new());
                };
                let mut enc = [0u8; IDENTITY_WIRE_BYTES];
                IdentityWire::from_identity(id, true).encode(&mut enc);
                (0, u64::from(id.id), 0, enc.to_vec())
            }
            wire::OP_LIST => {
                let mut out = Vec::with_capacity(self.store.identities.len() * IDENTITY_WIRE_BYTES);
                for id in &self.store.identities {
                    let mut enc = [0u8; IDENTITY_WIRE_BYTES];
                    IdentityWire::from_identity(id, id.id == self.store.active_id).encode(&mut enc);
                    out.extend_from_slice(&enc);
                }
                (0, self.store.identities.len() as u64, 0, out)
            }
            wire::OP_POLICY => {
                let mut enc = [0u8; LOCK_POLICY_WIRE_BYTES];
                LockPolicyWire { policy: self.store.lock_policy, tpm_available: self.tpm_available }.encode(&mut enc);
                (0, 0, 0, enc.to_vec())
            }
            wire::OP_TEST_STATUS => {
                let a = u64::from(self.tpm_available)
                    | (u64::from(self.tpm_seal_ops) << 8)
                    | (u64::from(self.tpm_unseal_ops) << 24)
                    | (u64::from(self.auth_failures) << 40);
                (0, a, 0, Vec::new())
            }
            wire::OP_AUTHENTICATE if role == Role::Session => {
                let target = if h.a == 0 { self.store.active_id } else { h.a as u32 };
                match self.verify_passphrase(target, payload) {
                    Ok(uid) => (0, u64::from(uid), 0, Vec::new()),
                    Err((st, retry_secs)) => (st, retry_secs, 0, Vec::new()),
                }
            }
            wire::OP_ENROLL if role == Role::Admin => match self.enroll_passphrase(h.a as u32, payload) {
                Ok(kind) => (0, u64::from(kind), 0, Vec::new()),
                Err(e) => (e, 0, 0, Vec::new()),
            },
            wire::OP_CREATE if role == Role::Admin => {
                let Some(id_role) = IdentityRole::from_u8(h.a as u8) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                let Some(nul) = payload.iter().position(|&b| b == 0) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                let Ok(name) = core::str::from_utf8(&payload[..nul]) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                let Ok(display) = core::str::from_utf8(&payload[nul + 1..]) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                match self.store.create_identity(name, display, id_role) {
                    Ok(uid) => {
                        ensure_home_dir(name);
                        save_store(&self.store);
                        println!("identity: created {} identity '{}' (#{})", id_role.as_str(), name, uid);
                        (0, u64::from(uid), 0, Vec::new())
                    }
                    Err(e) => {
                        if e == IdentityError::RootForbidden {
                            println!("identity: refused '{}': {}", name, e.message());
                        }
                        (map_id_err(e), 0, 0, e.message().as_bytes().to_vec())
                    }
                }
            }
            wire::OP_SET_POLICY if role == Role::Admin => {
                self.store.lock_policy.idle_timeout_secs = (h.a as u32).min(86_400);
                self.store.lock_policy.lock_on_sleep = ((h.a >> 32) & 1) != 0;
                self.store.lock_policy.lock_at_boot = ((h.a >> 33) & 1) != 0;
                save_store(&self.store);
                (0, 0, 0, Vec::new())
            }
            wire::OP_SWITCH if role == Role::Admin => {
                let Some(nul) = payload.iter().position(|&b| b == 0) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                let Ok(name) = core::str::from_utf8(&payload[..nul]) else {
                    return (sys::ERR_INVALID_ARGS, 0, 0, Vec::new());
                };
                let pass = &payload[nul + 1..];
                let Some(target) = self.store.find_by_name(name).map(|i| (i.id, i.cred.is_enrolled())) else {
                    return (fp::ERR_NOT_FOUND, 0, 0, Vec::new());
                };
                let (uid, enrolled) = target;
                if enrolled {
                    match self.verify_passphrase(uid, pass) {
                        Ok(u) => {
                            println!("identity: switched active identity to '{}'", name);
                            (0, u64::from(u), 0, Vec::new())
                        }
                        Err((st, retry)) => (st, retry, 0, Vec::new()),
                    }
                } else {
                    self.store.active_id = uid;
                    ensure_home_dir(name);
                    save_store(&self.store);
                    println!("identity: switched active identity to '{}'", name);
                    (0, u64::from(uid), 0, Vec::new())
                }
            }
            wire::OP_AUTHENTICATE | wire::OP_ENROLL | wire::OP_CREATE | wire::OP_SET_POLICY | wire::OP_SWITCH => {
                (sys::ERR_ACCESS_DENIED, 0, 0, Vec::new())
            }
            _ => (sys::ERR_NOT_SUPPORTED, 0, 0, Vec::new()),
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "identity") } {
        return 1;
    }
    let Ok(port) = Port::new(128) else { return 1 };
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let tpm_res = libd::startup_handle(sys::TAG_TPM_SEAL);
    let tpm_available = probe_tpm(tpm_res);
    let store = load_store();
    if let Some(a) = store.active() {
        ensure_home_dir(&a.name);
    }
    let active_name: String = store.active().map_or_else(|| String::from("user"), |a| a.name.clone());
    let mut svc_state = IdSvc {
        port,
        ctl,
        tpm_res,
        tpm_available,
        tpm_seal_ops: 0,
        tpm_unseal_ops: 0,
        auth_failures: 0,
        store,
        throttles: Vec::new(),
        clients: Vec::new(),
        next_client: 1,
    };
    if svc_state.ctl != 0 {
        svc_state.port.arm(svc_state.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    println!(
        "identity: ready, active '{}', {} identity(s), sealing: {}",
        active_name,
        svc_state.store.identities.len(),
        if tpm_available { "TPM 2.0 SRK" } else { "software AEAD" }
    );
    loop {
        let Some((k, _)) = svc_state.port.wait(sys::WAIT_FOREVER) else { continue };
        match k {
            KEY_CTL => {
                if !svc_state.on_ctl() {
                    return 0;
                }
            }
            k if k >= KEY_CLIENT_BASE => svc_state.on_client((k - KEY_CLIENT_BASE) as u32),
            _ => {}
        }
    }
}
