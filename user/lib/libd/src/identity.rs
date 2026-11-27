//! D-OS user identity service client protocol (`libd::identity`).
//!
//! Capability separation (`grants.identity` in a manifest):
//! - `identity.query`: read active identity, identity list, lock policy, and test counters.
//! - `identity.admin`: enroll passphrases (TPM 2.0 or software fallback), create non-root
//!   identities, switch active identity, and configure lock policy.
//! - `identity.session`: authenticate passphrases and unlock/sign-in (granted ONLY to `awmi`).

use crate::proto::{HEADER, Header};
use crate::svc;
use crate::sys::{self, Handle};

pub const OP_ACTIVE: u32 = 1100;
pub const OP_LIST: u32 = 1101;
pub const OP_POLICY: u32 = 1102;
pub const OP_AUTHENTICATE: u32 = 1103;
pub const OP_ENROLL: u32 = 1104;
pub const OP_CREATE: u32 = 1105;
pub const OP_SET_POLICY: u32 = 1106;
pub const OP_SWITCH: u32 = 1107;
pub const OP_TEST_STATUS: u32 = 1108;
/// `identity.admin`: export the sealed TOML identity store for persisting onto a newly installed disk.
pub const OP_EXPORT_STORE: u32 = 1109;

pub const ROLE_STANDARD: u8 = 1;
pub const ROLE_OPERATOR: u8 = 2;

pub const SEAL_NONE: u8 = 0;
pub const SEAL_SOFTWARE: u8 = 1;
pub const SEAL_TPM2: u8 = 2;

pub const IDENTITY_BYTES: usize = 128;
pub const POLICY_BYTES: usize = 16;

const CALL_TIMEOUT_NS: u64 = 15_000_000_000;

pub fn session_endpoint() -> Handle {
    svc::endpoint(b"identity.session")
}
pub fn admin_endpoint() -> Handle {
    svc::endpoint(b"identity.admin")
}
pub fn query_endpoint() -> Handle {
    svc::endpoint(b"identity.query")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityInfo {
    pub id: u32,
    pub role: u8,
    pub seal: u8,
    pub active: bool,
    pub enrolled: bool,
    pub caps: u32,
    pub name: [u8; 24],
    pub name_len: u8,
    pub display: [u8; 32],
    pub display_len: u8,
    pub home: [u8; 32],
    pub home_len: u8,
}

impl Default for IdentityInfo {
    fn default() -> Self {
        Self {
            id: 0,
            role: ROLE_STANDARD,
            seal: SEAL_NONE,
            active: false,
            enrolled: false,
            caps: 0,
            name: [0; 24],
            name_len: 0,
            display: [0; 32],
            display_len: 0,
            home: [0; 32],
            home_len: 0,
        }
    }
}

impl IdentityInfo {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len).min(24)]).unwrap_or("")
    }
    pub fn display_str(&self) -> &str {
        core::str::from_utf8(&self.display[..usize::from(self.display_len).min(32)]).unwrap_or("")
    }
    pub fn home_str(&self) -> &str {
        core::str::from_utf8(&self.home[..usize::from(self.home_len).min(32)]).unwrap_or("")
    }
    pub fn role_str(&self) -> &'static str {
        if self.role == ROLE_OPERATOR { "operator" } else { "standard" }
    }
    pub fn seal_str(&self) -> &'static str {
        match self.seal {
            SEAL_TPM2 => "tpm2",
            SEAL_SOFTWARE => "software",
            _ => "none",
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < IDENTITY_BYTES {
            return None;
        }
        let id = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let role = b[4];
        let seal = b[5];
        let active = b[6] != 0;
        let enrolled = b[7] != 0;
        let caps = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let name_len = b[12].min(24);
        let display_len = b[13].min(32);
        let home_len = b[14].min(32);
        let mut name = [0u8; 24];
        name.copy_from_slice(&b[16..40]);
        let mut display = [0u8; 32];
        display.copy_from_slice(&b[40..72]);
        let mut home = [0u8; 32];
        home.copy_from_slice(&b[72..104]);
        Some(Self { id, role, seal, active, enrolled, caps, name, name_len, display, display_len, home, home_len })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockPolicyInfo {
    pub idle_timeout_secs: u32,
    pub lock_on_sleep: bool,
    pub lock_at_boot: bool,
    pub tpm_available: bool,
}

impl LockPolicyInfo {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < POLICY_BYTES {
            return None;
        }
        Some(Self {
            idle_timeout_secs: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            lock_on_sleep: b[4] != 0,
            lock_at_boot: b[5] != 0,
            tpm_available: b[6] != 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestStatus {
    pub tpm_available: bool,
    pub tpm_seal_ops: u16,
    pub tpm_unseal_ops: u16,
    pub auth_failures: u16,
}

fn call(ep: Handle, op: u32, a: u64, b: u64, payload: &[u8], reply: &mut [u8]) -> Result<(Header, usize), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    if payload.len() > 256 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let mut req = [0u8; HEADER + 256];
    Header { txid: 0, op, status: 0, a, b }.put(&mut req);
    req[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    let n = sys::channel_call(ep, &req[..HEADER + payload.len()], reply, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&reply[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok((h, n))
}

pub fn active(ep: Handle) -> Result<IdentityInfo, i64> {
    let mut rep = [0u8; HEADER + IDENTITY_BYTES];
    let (_, n) = call(ep, OP_ACTIVE, 0, 0, &[], &mut rep)?;
    IdentityInfo::decode(&rep[HEADER..n]).ok_or(sys::ERR_INVALID_ARGS)
}

pub fn list(ep: Handle, out: &mut [IdentityInfo]) -> Result<usize, i64> {
    let mut rep = [0u8; HEADER + 8 * IDENTITY_BYTES];
    let (_, n) = call(ep, OP_LIST, 0, 0, &[], &mut rep)?;
    let body = &rep[HEADER..n];
    let cnt = (body.len() / IDENTITY_BYTES).min(out.len());
    for (i, slot) in out.iter_mut().take(cnt).enumerate() {
        *slot = IdentityInfo::decode(&body[i * IDENTITY_BYTES..]).unwrap_or_default();
    }
    Ok(cnt)
}

pub fn policy(ep: Handle) -> Result<LockPolicyInfo, i64> {
    let mut rep = [0u8; HEADER + POLICY_BYTES];
    let (_, n) = call(ep, OP_POLICY, 0, 0, &[], &mut rep)?;
    LockPolicyInfo::decode(&rep[HEADER..n]).ok_or(sys::ERR_INVALID_ARGS)
}

/// Authenticate on `identity.session`. Returns `Ok(identity_id)` or `Err((status, retry_after_secs))`.
pub fn authenticate(ep: Handle, identity_id: u32, passphrase: &[u8]) -> Result<u32, (i64, u64)> {
    if ep == 0 {
        return Err((sys::ERR_BAD_HANDLE, 0));
    }
    if passphrase.len() > 128 {
        return Err((sys::ERR_INVALID_ARGS, 0));
    }
    let mut req = [0u8; HEADER + 128];
    Header { txid: 0, op: OP_AUTHENTICATE, status: 0, a: u64::from(identity_id), b: 0 }.put(&mut req);
    req[HEADER..HEADER + passphrase.len()].copy_from_slice(passphrase);
    let mut rep = [0u8; HEADER + 64];
    let res = sys::channel_call(ep, &req[..HEADER + passphrase.len()], &mut rep, CALL_TIMEOUT_NS);
    req[HEADER..].fill(0);
    core::hint::black_box(&req);
    let n = res.map_err(|e| (e, 0))? as usize;
    let h = Header::get(&rep[..n]).ok_or((sys::ERR_INVALID_ARGS, 0))?;
    if h.status != 0 {
        return Err((i64::from(h.status), h.a));
    }
    Ok(h.a as u32)
}

/// Enroll or update the passphrase for `identity_id` (0 = active). Returns `SEAL_TPM2` or `SEAL_SOFTWARE`.
pub fn enroll(ep: Handle, identity_id: u32, passphrase: &[u8]) -> Result<u8, i64> {
    if passphrase.len() > 128 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let mut rep = [0u8; HEADER + 64];
    let (h, _) = call(ep, OP_ENROLL, u64::from(identity_id), 0, passphrase, &mut rep)?;
    Ok(h.a as u8)
}

/// Create a new non-root identity. Returns its id or an error (`ERR_ACCESS_DENIED` for `"root"`).
pub fn create(ep: Handle, name: &str, display: &str, role: u8) -> Result<u32, i64> {
    let mut p = [0u8; 64];
    let nb = name.as_bytes();
    let db = display.as_bytes();
    if nb.len() + 1 + db.len() > p.len() {
        return Err(sys::ERR_INVALID_ARGS);
    }
    p[..nb.len()].copy_from_slice(nb);
    p[nb.len()] = 0;
    p[nb.len() + 1..nb.len() + 1 + db.len()].copy_from_slice(db);
    let mut rep = [0u8; HEADER + 64];
    let (h, _) = call(ep, OP_CREATE, u64::from(role), 0, &p[..nb.len() + 1 + db.len()], &mut rep)?;
    Ok(h.a as u32)
}

/// Update lock policy (`idle_timeout_secs`, `lock_on_sleep`, `lock_at_boot`).
pub fn set_policy(ep: Handle, idle_timeout_secs: u32, lock_on_sleep: bool, lock_at_boot: bool) -> Result<(), i64> {
    let a = u64::from(idle_timeout_secs) | (u64::from(lock_on_sleep) << 32) | (u64::from(lock_at_boot) << 33);
    let mut rep = [0u8; HEADER];
    call(ep, OP_SET_POLICY, a, 0, &[], &mut rep).map(|_| ())
}

/// Switch active identity to `name` (passing `passphrase` when enrolled).
pub fn switch_user(ep: Handle, name: &str, passphrase: &[u8]) -> Result<u32, i64> {
    let nb = name.as_bytes();
    if nb.len() + 1 + passphrase.len() > 160 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let mut p = [0u8; 160];
    p[..nb.len()].copy_from_slice(nb);
    p[nb.len()] = 0;
    p[nb.len() + 1..nb.len() + 1 + passphrase.len()].copy_from_slice(passphrase);
    let mut rep = [0u8; HEADER + 64];
    let res = call(ep, OP_SWITCH, 0, 0, &p[..nb.len() + 1 + passphrase.len()], &mut rep);
    p.fill(0);
    core::hint::black_box(&p);
    res.map(|(h, _)| h.a as u32)
}

pub fn test_status(ep: Handle) -> Result<TestStatus, i64> {
    let mut rep = [0u8; HEADER];
    let (h, _) = call(ep, OP_TEST_STATUS, 0, 0, &[], &mut rep)?;
    Ok(TestStatus {
        tpm_available: (h.a & 1) != 0,
        tpm_seal_ops: ((h.a >> 8) & 0xFFFF) as u16,
        tpm_unseal_ops: ((h.a >> 24) & 0xFFFF) as u16,
        auth_failures: ((h.a >> 40) & 0xFFFF) as u16,
    })
}

/// Export the current sealed TOML identity store (`identity.admin` required).
pub fn export_store(ep: Handle, out: &mut [u8]) -> Result<usize, i64> {
    let mut rep = [0u8; HEADER + 8192];
    let (_, n) = call(ep, OP_EXPORT_STORE, 0, 0, &[], &mut rep)?;
    let body = &rep[HEADER..n];
    let copy = body.len().min(out.len());
    out[..copy].copy_from_slice(&body[..copy]);
    Ok(copy)
}
