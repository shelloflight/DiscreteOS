//! Fixed-size, zero-panic wire codecs for `identity.dsvc` IPC messages.

use crate::model::{Identity, IdentityRole, LockPolicy, MAX_DISPLAY, MAX_NAME, SealKind};

pub const IDENTITY_WIRE_BYTES: usize = 128;
pub const LOCK_POLICY_WIRE_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityWire {
    pub id: u32,
    pub role: IdentityRole,
    pub seal: SealKind,
    pub active: bool,
    pub enrolled: bool,
    pub caps: u32,
    pub name: [u8; MAX_NAME],
    pub name_len: u8,
    pub display: [u8; MAX_DISPLAY],
    pub display_len: u8,
    pub home: [u8; 32],
    pub home_len: u8,
}

impl IdentityWire {
    pub fn from_identity(id: &Identity, active: bool) -> Self {
        let mut w = Self {
            id: id.id,
            role: id.role,
            seal: id.cred.seal,
            active,
            enrolled: id.cred.is_enrolled(),
            caps: id.caps,
            name: [0; MAX_NAME],
            name_len: 0,
            display: [0; MAX_DISPLAY],
            display_len: 0,
            home: [0; 32],
            home_len: 0,
        };
        let nb = id.name.as_bytes();
        let nl = nb.len().min(MAX_NAME);
        w.name[..nl].copy_from_slice(&nb[..nl]);
        w.name_len = nl as u8;
        let db = id.display_name.as_bytes();
        let dl = db.len().min(MAX_DISPLAY);
        w.display[..dl].copy_from_slice(&db[..dl]);
        w.display_len = dl as u8;
        let hb = id.home_subdir().as_bytes();
        let hl = hb.len().min(32);
        w.home[..hl].copy_from_slice(&hb[..hl]);
        w.home_len = hl as u8;
        w
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len).min(MAX_NAME)]).unwrap_or("")
    }

    pub fn display_str(&self) -> &str {
        core::str::from_utf8(&self.display[..usize::from(self.display_len).min(MAX_DISPLAY)]).unwrap_or("")
    }

    pub fn home_str(&self) -> &str {
        core::str::from_utf8(&self.home[..usize::from(self.home_len).min(32)]).unwrap_or("")
    }

    pub fn encode(&self, out: &mut [u8; IDENTITY_WIRE_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&self.id.to_le_bytes());
        out[4] = self.role as u8;
        out[5] = self.seal as u8;
        out[6] = u8::from(self.active);
        out[7] = u8::from(self.enrolled);
        out[8..12].copy_from_slice(&self.caps.to_le_bytes());
        out[12] = self.name_len;
        out[13] = self.display_len;
        out[14] = self.home_len;
        out[16..40].copy_from_slice(&self.name);
        out[40..72].copy_from_slice(&self.display);
        out[72..104].copy_from_slice(&self.home);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < IDENTITY_WIRE_BYTES {
            return None;
        }
        let id = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let role = IdentityRole::from_u8(b[4])?;
        let seal = SealKind::from_u8(b[5])?;
        let active = b[6] != 0;
        let enrolled = b[7] != 0;
        let caps = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let name_len = b[12];
        let display_len = b[13];
        let home_len = b[14];
        if usize::from(name_len) > MAX_NAME || usize::from(display_len) > MAX_DISPLAY || usize::from(home_len) > 32 {
            return None;
        }
        let mut name = [0u8; MAX_NAME];
        name.copy_from_slice(&b[16..40]);
        let mut display = [0u8; MAX_DISPLAY];
        display.copy_from_slice(&b[40..72]);
        let mut home = [0u8; 32];
        home.copy_from_slice(&b[72..104]);
        Some(Self { id, role, seal, active, enrolled, caps, name, name_len, display, display_len, home, home_len })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockPolicyWire {
    pub policy: LockPolicy,
    pub tpm_available: bool,
}

impl LockPolicyWire {
    pub fn encode(&self, out: &mut [u8; LOCK_POLICY_WIRE_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&self.policy.idle_timeout_secs.to_le_bytes());
        out[4] = u8::from(self.policy.lock_on_sleep);
        out[5] = u8::from(self.policy.lock_at_boot);
        out[6] = u8::from(self.tpm_available);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < LOCK_POLICY_WIRE_BYTES {
            return None;
        }
        let idle_timeout_secs = u32::from_le_bytes([b[0], b[1], b[2], b[3]]).min(86_400);
        Some(Self {
            policy: LockPolicy {
                idle_timeout_secs,
                lock_on_sleep: b[4] != 0,
                lock_at_boot: b[5] != 0,
            },
            tpm_available: b[6] != 0,
        })
    }
}
