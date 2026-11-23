//! Auditable, revocable per-identity application permissions.
//!
//! Every permission maps to an explicit kernel/IPC capability and an explicit `dosid::caps` bit.
//! Revoking a permission immediately drops the app's handles (the app manager stops running
//! instances holding that permission and omits the handles on relaunch).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use dosid::caps;

/// Every explicit permission a `.dapp` manifest may declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Permission {
    Window = 0,
    FilesRead = 1,
    FilesWrite = 2,
    Terminal = 3,
    DisplayQuery = 4,
    DisplayAdmin = 5,
    AudioControl = 6,
    AudioPlayback = 7,
    NetStatus = 8,
    NetControl = 9,
    SystemQuery = 10,
    IdentityQuery = 11,
    IdentityAdmin = 12,
    AppsQuery = 13,
    AppsAdmin = 14,
}

impl Permission {
    pub const ALL: [Permission; 15] = [
        Self::Window,
        Self::FilesRead,
        Self::FilesWrite,
        Self::Terminal,
        Self::DisplayQuery,
        Self::DisplayAdmin,
        Self::AudioControl,
        Self::AudioPlayback,
        Self::NetStatus,
        Self::NetControl,
        Self::SystemQuery,
        Self::IdentityQuery,
        Self::IdentityAdmin,
        Self::AppsQuery,
        Self::AppsAdmin,
    ];

    pub const ALL_MASK: u32 = (1u32 << 15) - 1;

    pub const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Window),
            1 => Some(Self::FilesRead),
            2 => Some(Self::FilesWrite),
            3 => Some(Self::Terminal),
            4 => Some(Self::DisplayQuery),
            5 => Some(Self::DisplayAdmin),
            6 => Some(Self::AudioControl),
            7 => Some(Self::AudioPlayback),
            8 => Some(Self::NetStatus),
            9 => Some(Self::NetControl),
            10 => Some(Self::SystemQuery),
            11 => Some(Self::IdentityQuery),
            12 => Some(Self::IdentityAdmin),
            13 => Some(Self::AppsQuery),
            14 => Some(Self::AppsAdmin),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Window => "window",
            Self::FilesRead => "files:read",
            Self::FilesWrite => "files:write",
            Self::Terminal => "terminal",
            Self::DisplayQuery => "display:query",
            Self::DisplayAdmin => "display:admin",
            Self::AudioControl => "audio:control",
            Self::AudioPlayback => "audio:playback",
            Self::NetStatus => "net:status",
            Self::NetControl => "net:control",
            Self::SystemQuery => "system:query",
            Self::IdentityQuery => "identity:query",
            Self::IdentityAdmin => "identity:admin",
            Self::AppsQuery => "apps:query",
            Self::AppsAdmin => "apps:admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == s)
    }

    /// Plain-language title shown in Settings and the compositor permission prompt.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Window => "Display windows",
            Self::FilesRead => "Read files",
            Self::FilesWrite => "Modify files",
            Self::Terminal => "Terminal session",
            Self::DisplayQuery => "Read display modes",
            Self::DisplayAdmin => "Change display & theme",
            Self::AudioControl => "Audio volume & devices",
            Self::AudioPlayback => "Play audio",
            Self::NetStatus => "Read network status",
            Self::NetControl => "Change network settings",
            Self::SystemQuery => "Inspect services & logs",
            Self::IdentityQuery => "Read user identity",
            Self::IdentityAdmin => "Manage identities & lock",
            Self::AppsQuery => "List installed apps",
            Self::AppsAdmin => "Manage app permissions",
        }
    }

    /// Plain-language explanation of what granting this permission allows.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Window => "Create and draw windows on your desktop",
            Self::FilesRead => "Read files inside your identity namespace",
            Self::FilesWrite => "Create, save, and delete files inside your identity namespace",
            Self::Terminal => "Attach to the interactive shell session",
            Self::DisplayQuery => "Inspect connected monitors, modes, and refresh rates",
            Self::DisplayAdmin => "Change display mode, Hz, VRR, HDR, scale, and desktop theme",
            Self::AudioControl => "Inspect audio devices and change volume or mute",
            Self::AudioPlayback => "Play sound through the audio mixer",
            Self::NetStatus => "View network link, IP, and DNS status",
            Self::NetControl => "Configure DNS servers and network settings",
            Self::SystemQuery => "View running services, memory, handles, and system logs",
            Self::IdentityQuery => "View the active user identity and lock policy",
            Self::IdentityAdmin => "Enroll passphrases, create users, and lock the session",
            Self::AppsQuery => "View installed applications and their permission states",
            Self::AppsAdmin => "Grant or revoke permissions for installed applications",
        }
    }

    /// Identity capability bit required for this permission (0 = allowed for every identity).
    pub const fn required_identity_cap(self) -> u32 {
        match self {
            Self::Window | Self::Terminal | Self::IdentityQuery | Self::AppsQuery | Self::NetStatus => 0,
            Self::FilesRead => caps::FILES_READ,
            Self::FilesWrite => caps::FILES_WRITE,
            Self::DisplayQuery => caps::DISPLAY_QUERY,
            Self::DisplayAdmin => caps::DISPLAY_ADMIN,
            Self::AudioControl => caps::AUDIO_CONTROL,
            Self::AudioPlayback => caps::AUDIO_PLAYBACK,
            Self::NetControl => caps::NET_CONTROL,
            Self::SystemQuery => caps::SYSTEM_QUERY,
            Self::IdentityAdmin => caps::IDENTITY_ADMIN,
            Self::AppsAdmin => caps::APP_ADMIN,
        }
    }
}

/// Format a permission bitmask as a comma-separated string (`files:read, files:write`).
pub fn format_perm_mask(mask: u32) -> String {
    let mut out = String::new();
    for p in Permission::ALL {
        if mask & p.bit() != 0 {
            if !out.is_empty() {
                out.push_str(", ");
            }
            out.push_str(p.as_str());
        }
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
}

/// Per-permission user decision stored in the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PermDecision {
    /// Reset to manifest default (prompted if in `prompt`, granted if in `required`, off if `optional`).
    Ask = 0,
    Granted = 1,
    Denied = 2,
}

impl PermDecision {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ask),
            1 => Some(Self::Granted),
            2 => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Stored permission overrides for one `(identity, app)` pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPermRecord {
    pub identity: String,
    pub app: String,
    /// Permissions explicitly granted by the user (bitmask of `Permission::bit()`).
    pub granted: u32,
    /// Permissions explicitly revoked/denied by the user (bitmask; takes precedence over `required`).
    pub denied: u32,
}

/// Per-identity revocable permission ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermissionLedger {
    pub records: Vec<AppPermRecord>,
}

impl PermissionLedger {
    pub const fn new() -> Self {
        Self { records: Vec::new() }
    }

    pub fn record(&self, identity: &str, app: &str) -> Option<&AppPermRecord> {
        self.records.iter().find(|r| r.identity == identity && r.app == app)
    }

    /// Update a single permission decision for `(identity, app)`.
    pub fn set_decision(&mut self, identity: &str, app: &str, perm: Permission, decision: PermDecision) {
        let bit = perm.bit();
        if let Some(rec) = self.records.iter_mut().find(|r| r.identity == identity && r.app == app) {
            rec.granted &= !bit;
            rec.denied &= !bit;
            match decision {
                PermDecision::Granted => rec.granted |= bit,
                PermDecision::Denied => rec.denied |= bit,
                PermDecision::Ask => {}
            }
            return;
        }
        if decision == PermDecision::Ask {
            return;
        }
        self.records.push(AppPermRecord {
            identity: identity.to_string(),
            app: app.to_string(),
            granted: if decision == PermDecision::Granted { bit } else { 0 },
            denied: if decision == PermDecision::Denied { bit } else { 0 },
        });
    }

    /// Record bulk user prompt choice: `allow_mask` granted, `deny_mask` denied.
    pub fn apply_prompt(&mut self, identity: &str, app: &str, allow_mask: u32, deny_mask: u32) {
        for p in Permission::ALL {
            let b = p.bit();
            if allow_mask & b != 0 {
                self.set_decision(identity, app, p, PermDecision::Granted);
            } else if deny_mask & b != 0 {
                self.set_decision(identity, app, p, PermDecision::Denied);
            }
        }
    }

    /// Compute `(effective_granted, pending_prompt)` for launching an app with manifest permissions
    /// `(required, optional, prompt)` under `identity` holding `identity_caps`.
    ///
    /// Rules (fail-closed, zero ambient authority):
    /// 1. Only permissions declared in the manifest (`required | optional | prompt`) can ever be granted.
    /// 2. Any permission whose `required_identity_cap()` is missing from `identity_caps` is stripped.
    /// 3. Any permission explicitly in `record.denied` is stripped (even if `required`!).
    /// 4. Permissions in `prompt` not yet in `record.granted` or `record.denied` are returned in
    ///    `pending_prompt` so the compositor prompts the user before launch.
    /// 5. Permissions in `required` (not in `prompt` and not denied) are granted by default, and
    ///    explicitly `granted` optional/prompt permissions are included.
    pub fn evaluate(
        &self,
        identity: &str,
        identity_caps: u32,
        app: &str,
        required: u32,
        optional: u32,
        prompt: u32,
    ) -> (u32, u32) {
        let declared = (required | optional | prompt) & Permission::ALL_MASK;
        let mut cap_allowed = 0u32;
        for p in Permission::ALL {
            let b = p.bit();
            if declared & b != 0 {
                let need = p.required_identity_cap();
                if need == 0 || (identity_caps & need) == need {
                    cap_allowed |= b;
                }
            }
        }
        let (rec_granted, rec_denied) = self
            .record(identity, app)
            .map_or((0, 0), |r| (r.granted & Permission::ALL_MASK, r.denied & Permission::ALL_MASK));
        let promptable = prompt & cap_allowed;
        let pending_prompt = promptable & !(rec_granted | rec_denied);
        let base_granted = ((required & !prompt) | rec_granted) & cap_allowed;
        let effective = base_granted & !rec_denied;
        (effective, pending_prompt)
    }

    /// Serialize to deterministic flat-table TOML (parsed by `dman::toml`).
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("# D-OS per-identity application permission ledger\nversion = 1\n");
        for (idx, r) in self.records.iter().enumerate() {
            out.push_str(&format!("\n[entry-{}]\n", idx + 1));
            out.push_str(&format!("identity = \"{}\"\n", r.identity));
            out.push_str(&format!("app = \"{}\"\n", r.app));
            out.push_str(&format!("granted = {}\n", r.granted & Permission::ALL_MASK));
            out.push_str(&format!("denied = {}\n", r.denied & Permission::ALL_MASK));
        }
        out
    }

    /// Fail-closed TOML parser for the permission ledger.
    pub fn from_toml(src: &[u8]) -> Result<Self, &'static str> {
        use dman::toml::{self, Value};
        let doc = toml::parse(src).map_err(|_| "malformed permission ledger")?;
        let mut version = 0u64;
        struct Partial {
            key: String,
            identity: Option<String>,
            app: Option<String>,
            granted: Option<u32>,
            denied: Option<u32>,
        }
        let mut parts: Vec<Partial> = Vec::new();
        for (tbl, _) in &doc.tables {
            if !tbl.starts_with("entry-") || parts.len() >= 128 {
                return Err("unknown ledger table");
            }
            parts.push(Partial { key: tbl.clone(), identity: None, app: None, granted: None, denied: None });
        }
        for e in &doc.entries {
            match (e.table.as_str(), e.key.as_str(), &e.value) {
                ("", "version", Value::Int(v)) => version = *v,
                (tbl, key, val) if tbl.starts_with("entry-") => {
                    let Some(p) = parts.iter_mut().find(|p| p.key == tbl) else {
                        return Err("unknown ledger table");
                    };
                    match (key, val) {
                        ("identity", Value::Str(s)) => {
                            dosid::validate_name(s).map_err(|_| "invalid identity in ledger")?;
                            p.identity = Some(s.clone());
                        }
                        ("app", Value::Str(s)) => {
                            if !dman::valid_name(s) {
                                return Err("invalid app in ledger");
                            }
                            p.app = Some(s.clone());
                        }
                        ("granted", Value::Int(v)) => {
                            let m = u32::try_from(*v).map_err(|_| "bad mask")?;
                            if m & !Permission::ALL_MASK != 0 {
                                return Err("unknown permission bit");
                            }
                            p.granted = Some(m);
                        }
                        ("denied", Value::Int(v)) => {
                            let m = u32::try_from(*v).map_err(|_| "bad mask")?;
                            if m & !Permission::ALL_MASK != 0 {
                                return Err("unknown permission bit");
                            }
                            p.denied = Some(m);
                        }
                        _ => return Err("unknown ledger key"),
                    }
                }
                _ => return Err("unknown ledger entry"),
            }
        }
        if version != 1 {
            return Err("unsupported ledger version");
        }
        let mut records = Vec::with_capacity(parts.len());
        for p in parts {
            let identity = p.identity.ok_or("missing identity")?;
            let app = p.app.ok_or("missing app")?;
            let granted = p.granted.ok_or("missing granted")?;
            let denied = p.denied.ok_or("missing denied")?;
            if granted & denied != 0 {
                return Err("conflicting permission bits");
            }
            records.push(AppPermRecord { identity, app, granted, denied });
        }
        Ok(PermissionLedger { records })
    }
}
