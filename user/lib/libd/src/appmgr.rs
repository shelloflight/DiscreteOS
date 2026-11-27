//! D-OS application manager client protocol (`libd::appmgr`).
//!
//! Capability separation (`grants.appmgr` in a manifest):
//! - `appmgr.query`: list installed `.dapp` bundles, their verified permissions, and running counts.
//! - `appmgr.admin`: launch/stop `.dapp` apps, grant or revoke permissions live, and verify `.dapp` bundles.

use crate::proto::{HEADER, Header};
use crate::svc;
use crate::sys::{self, Handle};

/// Read-only `DRES` resource pack VMO passed to spawned `.dapp` apps.
pub const TAG_APP_RESOURCES: u32 = sys::TAG_USER + 0x300;

pub const OP_LIST: u32 = 1200;
pub const OP_LAUNCH: u32 = 1201;
pub const OP_STOP: u32 = 1202;
pub const OP_SET_PERM: u32 = 1203;
pub const OP_INSTALL_CHECK: u32 = 1204;
pub const OP_PERMS: u32 = 1205;
pub const OP_RUNNING: u32 = 1206;
pub const OP_SET_PIN: u32 = 1207;

pub const DECISION_ASK: u8 = 0;
pub const DECISION_GRANTED: u8 = 1;
pub const DECISION_DENIED: u8 = 2;

pub const APP_INFO_BYTES: usize = 160;
pub const MAX_APPS: usize = 16;

const CALL_TIMEOUT_NS: u64 = 15_000_000_000;

pub fn query_endpoint() -> Handle {
    svc::endpoint(b"appmgr.query")
}
pub fn admin_endpoint() -> Handle {
    svc::endpoint(b"appmgr.admin")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AppInfo {
    pub name: [u8; 24],
    pub name_len: u8,
    pub title: [u8; 32],
    pub title_len: u8,
    pub version: [u8; 16],
    pub version_len: u8,
    pub required_perms: u32,
    pub optional_perms: u32,
    pub prompt_perms: u32,
    pub effective_perms: u32,
    pub denied_perms: u32,
    pub running: u16,
    pub pinned: bool,
    pub autostart: bool,
    pub verified: bool,
}

impl AppInfo {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len).min(24)]).unwrap_or("")
    }
    pub fn title_str(&self) -> &str {
        core::str::from_utf8(&self.title[..usize::from(self.title_len).min(32)]).unwrap_or("")
    }
    pub fn version_str(&self) -> &str {
        core::str::from_utf8(&self.version[..usize::from(self.version_len).min(16)]).unwrap_or("")
    }

    pub fn encode(&self, out: &mut [u8; APP_INFO_BYTES]) {
        out.fill(0);
        out[0] = self.name_len;
        out[1] = self.title_len;
        out[2] = self.version_len;
        out[3] = u8::from(self.pinned) | (u8::from(self.autostart) << 1) | (u8::from(self.verified) << 2);
        out[4..8].copy_from_slice(&self.required_perms.to_le_bytes());
        out[8..12].copy_from_slice(&self.optional_perms.to_le_bytes());
        out[12..16].copy_from_slice(&self.prompt_perms.to_le_bytes());
        out[16..20].copy_from_slice(&self.effective_perms.to_le_bytes());
        out[20..24].copy_from_slice(&self.denied_perms.to_le_bytes());
        out[24..26].copy_from_slice(&self.running.to_le_bytes());
        out[32..56].copy_from_slice(&self.name);
        out[56..88].copy_from_slice(&self.title);
        out[88..104].copy_from_slice(&self.version);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < APP_INFO_BYTES {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let mut a = Self {
            name_len: b[0].min(24),
            title_len: b[1].min(32),
            version_len: b[2].min(16),
            pinned: (b[3] & 1) != 0,
            autostart: (b[3] & 2) != 0,
            verified: (b[3] & 4) != 0,
            required_perms: u32_at(4),
            optional_perms: u32_at(8),
            prompt_perms: u32_at(12),
            effective_perms: u32_at(16),
            denied_perms: u32_at(20),
            running: u16::from_le_bytes([b[24], b[25]]),
            ..Self::default()
        };
        a.name.copy_from_slice(&b[32..56]);
        a.title.copy_from_slice(&b[56..88]);
        a.version.copy_from_slice(&b[88..104]);
        Some(a)
    }
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

pub fn list(ep: Handle, out: &mut [AppInfo]) -> Result<usize, i64> {
    let mut rep = [0u8; HEADER + MAX_APPS * APP_INFO_BYTES];
    let (_, n) = call(ep, OP_LIST, 0, 0, &[], &mut rep)?;
    let body = &rep[HEADER..n];
    let cnt = (body.len() / APP_INFO_BYTES).min(out.len());
    for (i, slot) in out.iter_mut().take(cnt).enumerate() {
        *slot = AppInfo::decode(&body[i * APP_INFO_BYTES..]).unwrap_or_default();
    }
    Ok(cnt)
}

/// Launch an installed `.dapp` by name. Returns `1` if spawned immediately, `2` if awaiting compositor permission prompt.
pub fn launch(ep: Handle, app: &str) -> Result<u64, i64> {
    let mut rep = [0u8; HEADER];
    call(ep, OP_LAUNCH, 0, 0, app.as_bytes(), &mut rep).map(|(h, _)| h.a)
}

pub fn stop(ep: Handle, app: &str) -> Result<u64, i64> {
    let mut rep = [0u8; HEADER];
    call(ep, OP_STOP, 0, 0, app.as_bytes(), &mut rep).map(|(h, _)| h.a)
}

/// Grant, revoke (deny), or reset to ask a single permission bit (`perm_bit: 0..15`) for `app`.
pub fn set_perm(ep: Handle, app: &str, perm_bit: u8, decision: u8) -> Result<(), i64> {
    let a = u64::from(perm_bit) | (u64::from(decision) << 8);
    let mut rep = [0u8; HEADER];
    call(ep, OP_SET_PERM, a, 0, app.as_bytes(), &mut rep).map(|_| ())
}

/// Verify a `.dapp` bundle at `path` (used to validate bundles and prove tampered/unsigned bundles are refused).
pub fn install_check(ep: Handle, path: &str) -> Result<(), i64> {
    let mut rep = [0u8; HEADER];
    call(ep, OP_INSTALL_CHECK, 0, 0, path.as_bytes(), &mut rep).map(|_| ())
}

/// Return `(effective_perms, denied_perms)` for `app`.
pub fn perms(ep: Handle, app: &str) -> Result<(u32, u32), i64> {
    let mut rep = [0u8; HEADER];
    call(ep, OP_PERMS, 0, 0, app.as_bytes(), &mut rep).map(|(h, _)| (h.a as u32, (h.a >> 32) as u32))
}

pub fn running_count(ep: Handle, app: &str) -> Result<u64, i64> {
    let mut rep = [0u8; HEADER];
    call(ep, OP_RUNNING, 0, 0, app.as_bytes(), &mut rep).map(|(h, _)| h.a)
}

/// Pin or unpin an application on the floating taskbar (`appmgr.admin`).
pub fn set_pin(ep: Handle, app: &str, pinned: bool) -> Result<(), i64> {
    let mut rep = [0u8; HEADER];
    call(ep, OP_SET_PIN, u64::from(pinned), 0, app.as_bytes(), &mut rep).map(|_| ())
}
