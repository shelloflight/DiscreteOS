//! D-OS user identities, explicit capabilities, per-identity namespaces, credential sealing,
//! authentication backoff throttling, and fail-closed TOML persistence.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use doscrypt::chacha20::{open_in_place, seal_in_place};
use doscrypt::ct::{ct_eq, wipe_bytes};

use crate::kdf::{MAX_ITERATIONS, MIN_ITERATIONS, derive_seal_key, derive_verifier};

pub const MAX_IDENTITIES: usize = 8;
pub const MAX_NAME: usize = 24;
pub const MAX_DISPLAY: usize = 32;
pub const MAX_PASSPHRASE: usize = 128;
pub const SOFTWARE_BLOB_LEN: usize = 12 + 16 + 32; // nonce(12) || tag(16) || ct(32)
pub const MAX_BLOB_LEN: usize = 1024;

/// Names explicitly forbidden by policy. `"root"` receives its own dedicated error message.
pub const RESERVED_NAMES: &[&str] = &["superuser", "su", "sudo", "wheel", "system", "kernel", "init", "nobody"];

/// Explicit capability bitmask for a D-OS identity (never ambient).
pub mod caps {
    pub const FILES_READ: u32 = 1 << 0;
    pub const FILES_WRITE: u32 = 1 << 1;
    pub const NET_CLIENT: u32 = 1 << 2;
    pub const NET_CONTROL: u32 = 1 << 3;
    pub const AUDIO_PLAYBACK: u32 = 1 << 4;
    pub const AUDIO_CAPTURE: u32 = 1 << 5;
    pub const AUDIO_CONTROL: u32 = 1 << 6;
    pub const DISPLAY_QUERY: u32 = 1 << 7;
    pub const DISPLAY_ADMIN: u32 = 1 << 8;
    pub const SYSTEM_QUERY: u32 = 1 << 9;
    pub const SYSTEM_ADMIN: u32 = 1 << 10;
    pub const APP_ADMIN: u32 = 1 << 11;
    pub const IDENTITY_ADMIN: u32 = 1 << 12;

    pub const ALL_VALID: u32 = (1 << 13) - 1;

    pub const STANDARD_DEFAULT: u32 =
        FILES_READ | FILES_WRITE | NET_CLIENT | AUDIO_PLAYBACK | AUDIO_CAPTURE | AUDIO_CONTROL | DISPLAY_QUERY | SYSTEM_QUERY;

    pub const OPERATOR_DEFAULT: u32 =
        STANDARD_DEFAULT | NET_CONTROL | DISPLAY_ADMIN | SYSTEM_ADMIN | APP_ADMIN | IDENTITY_ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    RootForbidden,
    ReservedName,
    InvalidName,
    InvalidDisplayName,
    DuplicateName,
    TooManyIdentities,
    NotFound,
    EmptyPassphrase,
    PassphraseTooLong,
    InvalidCredentials,
    Throttled(u64),
    NotEnrolled,
    PermissionDenied,
    InvalidFormat,
}

impl IdentityError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::RootForbidden => "D-OS has no root user",
            Self::ReservedName => "reserved identity name",
            Self::InvalidName => "invalid identity name (a-z 0-9 -, 1..=24 chars, starting with a letter)",
            Self::InvalidDisplayName => "invalid display name",
            Self::DuplicateName => "identity already exists",
            Self::TooManyIdentities => "identity limit reached",
            Self::NotFound => "identity not found",
            Self::EmptyPassphrase => "passphrase cannot be empty",
            Self::PassphraseTooLong => "passphrase too long",
            Self::InvalidCredentials => "invalid passphrase",
            Self::Throttled(_) => "too many failed attempts; wait before retrying",
            Self::NotEnrolled => "identity has no enrolled credential",
            Self::PermissionDenied => "identity lacks required capability",
            Self::InvalidFormat => "malformed identity store",
        }
    }
}

/// Validate a D-OS identity name. `"root"` is always refused with `RootForbidden`.
pub fn validate_name(name: &str) -> Result<(), IdentityError> {
    if name.eq_ignore_ascii_case("root") {
        return Err(IdentityError::RootForbidden);
    }
    let b = name.as_bytes();
    if b.is_empty() || b.len() > MAX_NAME || !b[0].is_ascii_lowercase() {
        return Err(IdentityError::InvalidName);
    }
    if !b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
        return Err(IdentityError::InvalidName);
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(IdentityError::ReservedName);
    }
    Ok(())
}

pub fn validate_display(display: &str) -> Result<(), IdentityError> {
    let b = display.as_bytes();
    if b.is_empty() || b.len() > MAX_DISPLAY || !b.iter().all(|&c| (0x20..=0x7E).contains(&c)) {
        return Err(IdentityError::InvalidDisplayName);
    }
    Ok(())
}

/// Role template (determines default capability set and default namespace, never ambient `root`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentityRole {
    Standard = 1,
    Operator = 2,
}

impl IdentityRole {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Standard),
            2 => Some(Self::Operator),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Operator => "operator",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(Self::Standard),
            "operator" => Some(Self::Operator),
            _ => None,
        }
    }
    pub const fn default_caps(self) -> u32 {
        match self {
            Self::Standard => caps::STANDARD_DEFAULT,
            Self::Operator => caps::OPERATOR_DEFAULT,
        }
    }
}

/// How an identity's 32-byte master secret is sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SealKind {
    /// No passphrase enrolled yet (live / fresh install; unlocks automatically until enrolled).
    None = 0,
    /// Software AEAD fallback (PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305) when no TPM 2.0 is present.
    Software = 1,
    /// Hardware TPM 2.0 sealed under the owner ECC P-256 Storage Root Key.
    Tpm2 = 2,
}

impl SealKind {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Software),
            2 => Some(Self::Tpm2),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Software => "software",
            Self::Tpm2 => "tpm2",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "software" => Some(Self::Software),
            "tpm2" => Some(Self::Tpm2),
            _ => None,
        }
    }
}

/// Per-identity filesystem namespace binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityNsEntry {
    /// Mount path visible inside apps launched under this identity (e.g. `/home`, `/system`, `/data`).
    pub mount: String,
    /// Backing storage volume name (`data`, `system`).
    pub volume: String,
    /// Optional subdirectory inside `volume` (e.g. `home/alice` — confines the identity strictly to its home).
    pub subdir: String,
    pub read: bool,
    pub write: bool,
}

/// Sealed credential material for an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub seal: SealKind,
    pub salt: [u8; 16],
    pub iterations: u32,
    pub verifier: [u8; 32],
    pub blob: Vec<u8>,
}

impl Credential {
    pub fn none() -> Self {
        Self { seal: SealKind::None, salt: [0; 16], iterations: 0, verifier: [0; 32], blob: Vec::new() }
    }

    pub fn is_enrolled(&self) -> bool {
        self.seal != SealKind::None && !self.blob.is_empty()
    }

    /// Seal `secret` in software (PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305) bound to `(identity_id, name)`.
    pub fn seal_software(
        identity_id: u32,
        name: &str,
        passphrase: &[u8],
        salt: [u8; 16],
        nonce: [u8; 12],
        secret: &[u8; 32],
        iterations: u32,
    ) -> Result<Self, IdentityError> {
        if passphrase.is_empty() {
            return Err(IdentityError::EmptyPassphrase);
        }
        if passphrase.len() > MAX_PASSPHRASE {
            return Err(IdentityError::PassphraseTooLong);
        }
        let iter = iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS);
        let mut key = derive_seal_key(passphrase, &salt, iter);
        let verifier = derive_verifier(secret, identity_id, name);
        let mut aad = Vec::with_capacity(16 + name.len());
        aad.extend_from_slice(b"dos-sw-seal:");
        aad.extend_from_slice(&identity_id.to_le_bytes());
        aad.extend_from_slice(name.as_bytes());
        let mut ct = *secret;
        let tag = seal_in_place(&key, &nonce, &aad, &mut ct);
        wipe_bytes(&mut key);
        let mut blob = Vec::with_capacity(SOFTWARE_BLOB_LEN);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&tag);
        blob.extend_from_slice(&ct);
        Ok(Self { seal: SealKind::Software, salt, iterations: iter, verifier, blob })
    }

    /// Verify `passphrase` against a software-sealed credential; returns the unsealed 32-byte secret.
    pub fn open_software(&self, identity_id: u32, name: &str, passphrase: &[u8]) -> Result<[u8; 32], IdentityError> {
        if self.seal != SealKind::Software || self.blob.len() != SOFTWARE_BLOB_LEN {
            return Err(IdentityError::InvalidCredentials);
        }
        if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE {
            return Err(IdentityError::InvalidCredentials);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.blob[0..12]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&self.blob[12..28]);
        let mut plain = [0u8; 32];
        plain.copy_from_slice(&self.blob[28..60]);
        let mut key = derive_seal_key(passphrase, &self.salt, self.iterations);
        let mut aad = Vec::with_capacity(16 + name.len());
        aad.extend_from_slice(b"dos-sw-seal:");
        aad.extend_from_slice(&identity_id.to_le_bytes());
        aad.extend_from_slice(name.as_bytes());
        let ok = open_in_place(&key, &nonce, &aad, &mut plain, &tag);
        wipe_bytes(&mut key);
        if !ok {
            wipe_bytes(&mut plain);
            return Err(IdentityError::InvalidCredentials);
        }
        let expected = derive_verifier(&plain, identity_id, name);
        if !ct_eq(&expected, &self.verifier) {
            wipe_bytes(&mut plain);
            return Err(IdentityError::InvalidCredentials);
        }
        Ok(plain)
    }

    /// Derive `(tpm_auth, verifier)` for enrolling a TPM 2.0 sealed credential.
    pub fn prepare_tpm(
        identity_id: u32,
        name: &str,
        passphrase: &[u8],
        salt: [u8; 16],
        secret: &[u8; 32],
        iterations: u32,
    ) -> Result<([u8; 32], [u8; 32], u32), IdentityError> {
        if passphrase.is_empty() {
            return Err(IdentityError::EmptyPassphrase);
        }
        if passphrase.len() > MAX_PASSPHRASE {
            return Err(IdentityError::PassphraseTooLong);
        }
        let iter = iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS);
        let auth = derive_seal_key(passphrase, &salt, iter);
        let verifier = derive_verifier(secret, identity_id, name);
        Ok((auth, verifier, iter))
    }

    /// Construct a `SealKind::Tpm2` credential from a kernel-sealed `DTPM` blob.
    pub fn from_tpm_blob(salt: [u8; 16], iterations: u32, verifier: [u8; 32], blob: Vec<u8>) -> Result<Self, IdentityError> {
        if blob.len() < 10 || blob.len() > MAX_BLOB_LEN || &blob[..4] != b"DTPM" {
            return Err(IdentityError::InvalidFormat);
        }
        Ok(Self { seal: SealKind::Tpm2, salt, iterations: iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS), verifier, blob })
    }

    /// Derive the TPM `userAuth` for an unlock attempt.
    pub fn tpm_auth_for(&self, passphrase: &[u8]) -> Result<[u8; 32], IdentityError> {
        if self.seal != SealKind::Tpm2 || passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE {
            return Err(IdentityError::InvalidCredentials);
        }
        Ok(derive_seal_key(passphrase, &self.salt, self.iterations))
    }

    /// Verify bytes returned by `sys::tpm_unseal` against this identity's verifier.
    pub fn verify_tpm_unsealed(&self, identity_id: u32, name: &str, unsealed: &[u8]) -> bool {
        if self.seal != SealKind::Tpm2 || unsealed.len() != 32 {
            return false;
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(unsealed);
        let v = derive_verifier(&s, identity_id, name);
        wipe_bytes(&mut s);
        ct_eq(&v, &self.verifier)
    }
}

/// Session lock policy (applied by `awmi` and `init` suspend).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockPolicy {
    /// Seconds of input idle before auto-lock (0 = disabled; clamped to 0..=86400).
    pub idle_timeout_secs: u32,
    /// Lock the compositor before ACPI S3 sleep.
    pub lock_on_sleep: bool,
    /// Require login screen at boot even before a passphrase is enrolled (or always when enrolled).
    pub lock_at_boot: bool,
}

impl LockPolicy {
    pub const DEFAULT: Self = Self { idle_timeout_secs: 300, lock_on_sleep: true, lock_at_boot: false };
}

/// Failed-attempt authentication throttle (exponential backoff).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthThrottle {
    pub failures: u32,
    pub locked_until_ns: u64,
}

impl AuthThrottle {
    /// Backoff schedule in seconds after 1, 2, 3, 4, 5, 6, 7+ consecutive failures.
    const BACKOFF_SECS: [u64; 7] = [0, 0, 0, 2, 5, 15, 30];

    /// Remaining cooldown in nanoseconds at monotonic time `now_ns` (0 = allowed now).
    pub fn retry_after_ns(&self, now_ns: u64) -> u64 {
        self.locked_until_ns.saturating_sub(now_ns)
    }

    /// Record a failed unlock attempt; returns the new cooldown duration in nanoseconds.
    pub fn record_failure(&mut self, now_ns: u64) -> u64 {
        self.failures = self.failures.saturating_add(1);
        let idx = (self.failures as usize).saturating_sub(1).min(Self::BACKOFF_SECS.len() - 1);
        let delay = Self::BACKOFF_SECS[idx] * 1_000_000_000;
        self.locked_until_ns = now_ns.saturating_add(delay);
        delay
    }

    /// Clear consecutive failures after a successful unlock.
    pub fn reset(&mut self) {
        self.failures = 0;
        self.locked_until_ns = 0;
    }
}

/// One D-OS user identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub id: u32,
    pub name: String,
    pub display_name: String,
    pub role: IdentityRole,
    pub caps: u32,
    pub cred: Credential,
    pub namespace: Vec<IdentityNsEntry>,
}

impl Identity {
    /// Default per-identity namespace: isolated `/home` under `data:home/<name>`, read-only `/system`,
    /// and `/data` only for `Operator` identities.
    pub fn default_namespace(name: &str, role: IdentityRole) -> Vec<IdentityNsEntry> {
        let mut ns = Vec::new();
        ns.push(IdentityNsEntry {
            mount: "/home".to_string(),
            volume: "data".to_string(),
            subdir: format!("home/{}", name),
            read: true,
            write: true,
        });
        ns.push(IdentityNsEntry {
            mount: "/system".to_string(),
            volume: "system".to_string(),
            subdir: String::new(),
            read: true,
            write: false,
        });
        if role == IdentityRole::Operator {
            ns.push(IdentityNsEntry {
                mount: "/data".to_string(),
                volume: "data".to_string(),
                subdir: String::new(),
                read: true,
                write: true,
            });
        }
        ns
    }

    pub fn home_subdir(&self) -> &str {
        self.namespace
            .iter()
            .find(|e| e.mount == "/home")
            .map_or("", |e| e.subdir.as_str())
    }
}

/// Complete persisted identity registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityStore {
    pub active_id: u32,
    pub lock_policy: LockPolicy,
    pub identities: Vec<Identity>,
    pub next_id: u32,
}

impl IdentityStore {
    /// Fresh default store: one local Operator identity `"user"` with no passphrase enrolled yet.
    pub fn default_store() -> Self {
        let id = Identity {
            id: 1,
            name: "user".to_string(),
            display_name: "Local User".to_string(),
            role: IdentityRole::Operator,
            caps: caps::OPERATOR_DEFAULT,
            cred: Credential::none(),
            namespace: Identity::default_namespace("user", IdentityRole::Operator),
        };
        Self { active_id: 1, lock_policy: LockPolicy::DEFAULT, identities: alloc::vec![id], next_id: 2 }
    }

    pub fn active(&self) -> Option<&Identity> {
        self.identities.iter().find(|i| i.id == self.active_id).or_else(|| self.identities.first())
    }

    pub fn active_mut(&mut self) -> Option<&mut Identity> {
        let aid = self.active_id;
        if self.identities.iter().any(|i| i.id == aid) {
            self.identities.iter_mut().find(|i| i.id == aid)
        } else {
            self.identities.first_mut()
        }
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Identity> {
        self.identities.iter().find(|i| i.name == name)
    }

    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut Identity> {
        self.identities.iter_mut().find(|i| i.name == name)
    }

    pub fn find_by_id(&self, id: u32) -> Option<&Identity> {
        self.identities.iter().find(|i| i.id == id)
    }

    pub fn find_by_id_mut(&mut self, id: u32) -> Option<&mut Identity> {
        self.identities.iter_mut().find(|i| i.id == id)
    }

    /// Create a new non-root identity with its own isolated namespace and explicit capability set.
    pub fn create_identity(&mut self, name: &str, display_name: &str, role: IdentityRole) -> Result<u32, IdentityError> {
        validate_name(name)?;
        validate_display(display_name)?;
        if self.identities.len() >= MAX_IDENTITIES {
            return Err(IdentityError::TooManyIdentities);
        }
        if self.find_by_name(name).is_some() {
            return Err(IdentityError::DuplicateName);
        }
        let id = self.next_id.max(1);
        self.next_id = id.wrapping_add(1).max(1);
        self.identities.push(Identity {
            id,
            name: name.to_string(),
            display_name: display_name.to_string(),
            role,
            caps: role.default_caps(),
            cred: Credential::none(),
            namespace: Identity::default_namespace(name, role),
        });
        Ok(id)
    }

    /// Switch the active identity by name.
    pub fn set_active_by_name(&mut self, name: &str) -> Result<u32, IdentityError> {
        let id = self.find_by_name(name).ok_or(IdentityError::NotFound)?.id;
        self.active_id = id;
        Ok(id)
    }

    /// Serialize to deterministic flat-table TOML (parsed by `dman::toml`).
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("# D-OS identity store (no root user; explicit capabilities)\n");
        out.push_str(&format!("version = 1\nactive = {}\nnext-id = {}\n\n", self.active_id, self.next_id));
        out.push_str("[policy]\n");
        out.push_str(&format!(
            "idle-timeout = {}\nlock-on-sleep = {}\nlock-at-boot = {}\n",
            self.lock_policy.idle_timeout_secs, self.lock_policy.lock_on_sleep, self.lock_policy.lock_at_boot
        ));
        for id in &self.identities {
            out.push_str(&format!("\n[identity-{}]\n", id.id));
            out.push_str(&format!("name = \"{}\"\n", id.name));
            out.push_str(&format!("display = \"{}\"\n", escape_str(&id.display_name)));
            out.push_str(&format!("role = \"{}\"\n", id.role.as_str()));
            out.push_str(&format!("caps = {}\n", id.caps & caps::ALL_VALID));
            out.push_str(&format!("seal = \"{}\"\n", id.cred.seal.as_str()));
            out.push_str(&format!("iterations = {}\n", id.cred.iterations));
            out.push_str(&format!("salt = \"{}\"\n", encode_hex(&id.cred.salt)));
            out.push_str(&format!("verifier = \"{}\"\n", encode_hex(&id.cred.verifier)));
            out.push_str(&format!("blob = \"{}\"\n", encode_hex(&id.cred.blob)));
        }
        out
    }

    /// Fail-closed parser: refuses unknown tables/keys, `"root"`, invalid hex, or missing fields.
    pub fn from_toml(src: &[u8]) -> Result<Self, IdentityError> {
        use dman::toml::{self, Value};
        // Hardware TPM 2.0 sealed blobs can reach `MAX_BLOB_LEN` raw bytes (`MAX_BLOB_LEN * 2` hex).
        let doc = toml::parse_with_limits(src, 32 * 1024, MAX_BLOB_LEN * 2)
            .map_err(|_| IdentityError::InvalidFormat)?;
        let mut version = 0u64;
        let mut active_id = 0u32;
        let mut next_id = 0u32;
        let mut policy = LockPolicy::DEFAULT;

        struct Partial {
            id: u32,
            name: Option<String>,
            display: Option<String>,
            role: Option<IdentityRole>,
            caps: Option<u32>,
            seal: Option<SealKind>,
            iterations: Option<u32>,
            salt: Option<[u8; 16]>,
            verifier: Option<[u8; 32]>,
            blob: Option<Vec<u8>>,
        }
        let mut partials: Vec<Partial> = Vec::new();
        for (tbl, _) in &doc.tables {
            if tbl == "policy" {
                continue;
            }
            let Some(rest) = tbl.strip_prefix("identity-") else {
                return Err(IdentityError::InvalidFormat);
            };
            let id: u32 = rest.parse().ok().filter(|&v| v > 0).ok_or(IdentityError::InvalidFormat)?;
            if partials.len() >= MAX_IDENTITIES || partials.iter().any(|p| p.id == id) {
                return Err(IdentityError::InvalidFormat);
            }
            partials.push(Partial {
                id,
                name: None,
                display: None,
                role: None,
                caps: None,
                seal: None,
                iterations: None,
                salt: None,
                verifier: None,
                blob: None,
            });
        }

        for e in &doc.entries {
            match (e.table.as_str(), e.key.as_str(), &e.value) {
                ("", "version", Value::Int(v)) => version = *v,
                ("", "active", Value::Int(v)) => active_id = u32::try_from(*v).map_err(|_| IdentityError::InvalidFormat)?,
                ("", "next-id", Value::Int(v)) => next_id = u32::try_from(*v).map_err(|_| IdentityError::InvalidFormat)?,
                ("policy", "idle-timeout", Value::Int(v)) => {
                    policy.idle_timeout_secs = u32::try_from(*v).map_err(|_| IdentityError::InvalidFormat)?.min(86_400);
                }
                ("policy", "lock-on-sleep", Value::Bool(b)) => policy.lock_on_sleep = *b,
                ("policy", "lock-at-boot", Value::Bool(b)) => policy.lock_at_boot = *b,
                (tbl, key, val) if tbl.starts_with("identity-") => {
                    let id: u32 = tbl.strip_prefix("identity-").and_then(|r| r.parse().ok()).ok_or(IdentityError::InvalidFormat)?;
                    let p = partials.iter_mut().find(|p| p.id == id).ok_or(IdentityError::InvalidFormat)?;
                    match (key, val) {
                        ("name", Value::Str(s)) => p.name = Some(s.clone()),
                        ("display", Value::Str(s)) => p.display = Some(s.clone()),
                        ("role", Value::Str(s)) => p.role = Some(IdentityRole::parse(s).ok_or(IdentityError::InvalidFormat)?),
                        ("caps", Value::Int(v)) => {
                            let c = u32::try_from(*v).map_err(|_| IdentityError::InvalidFormat)?;
                            if c & !caps::ALL_VALID != 0 {
                                return Err(IdentityError::InvalidFormat);
                            }
                            p.caps = Some(c);
                        }
                        ("seal", Value::Str(s)) => p.seal = Some(SealKind::parse(s).ok_or(IdentityError::InvalidFormat)?),
                        ("iterations", Value::Int(v)) => {
                            p.iterations = Some(u32::try_from(*v).map_err(|_| IdentityError::InvalidFormat)?);
                        }
                        ("salt", Value::Str(s)) => {
                            let raw = decode_hex(s).ok_or(IdentityError::InvalidFormat)?;
                            if raw.len() != 16 {
                                return Err(IdentityError::InvalidFormat);
                            }
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&raw);
                            p.salt = Some(arr);
                        }
                        ("verifier", Value::Str(s)) => {
                            let raw = decode_hex(s).ok_or(IdentityError::InvalidFormat)?;
                            if raw.len() != 32 {
                                return Err(IdentityError::InvalidFormat);
                            }
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&raw);
                            p.verifier = Some(arr);
                        }
                        ("blob", Value::Str(s)) => {
                            let raw = decode_hex(s).ok_or(IdentityError::InvalidFormat)?;
                            if raw.len() > MAX_BLOB_LEN {
                                return Err(IdentityError::InvalidFormat);
                            }
                            p.blob = Some(raw);
                        }
                        _ => return Err(IdentityError::InvalidFormat),
                    }
                }
                _ => return Err(IdentityError::InvalidFormat),
            }
        }
        if version != 1 || partials.is_empty() {
            return Err(IdentityError::InvalidFormat);
        }
        let mut identities = Vec::with_capacity(partials.len());
        let mut max_id = 0u32;
        for p in partials {
            let name = p.name.ok_or(IdentityError::InvalidFormat)?;
            validate_name(&name)?;
            if identities.iter().any(|i: &Identity| i.name == name) {
                return Err(IdentityError::DuplicateName);
            }
            let display_name = p.display.ok_or(IdentityError::InvalidFormat)?;
            validate_display(&display_name)?;
            let role = p.role.ok_or(IdentityError::InvalidFormat)?;
            let caps = p.caps.ok_or(IdentityError::InvalidFormat)?;
            let seal = p.seal.ok_or(IdentityError::InvalidFormat)?;
            let iterations = p.iterations.unwrap_or(0);
            let salt = p.salt.unwrap_or([0; 16]);
            let verifier = p.verifier.unwrap_or([0; 32]);
            let blob = p.blob.unwrap_or_default();
            match seal {
                SealKind::None => {
                    if !blob.is_empty() {
                        return Err(IdentityError::InvalidFormat);
                    }
                }
                SealKind::Software => {
                    if blob.len() != SOFTWARE_BLOB_LEN || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
                        return Err(IdentityError::InvalidFormat);
                    }
                }
                SealKind::Tpm2 => {
                    if blob.len() < 10 || &blob[..4] != b"DTPM" || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
                        return Err(IdentityError::InvalidFormat);
                    }
                }
            }
            max_id = max_id.max(p.id);
            let namespace = Identity::default_namespace(&name, role);
            identities.push(Identity {
                id: p.id,
                name,
                display_name,
                role,
                caps,
                cred: Credential { seal, salt, iterations, verifier, blob },
                namespace,
            });
        }
        if !identities.iter().any(|i| i.id == active_id) {
            return Err(IdentityError::InvalidFormat);
        }
        let next_id = next_id.max(max_id.saturating_add(1));
        Ok(IdentityStore { active_id, lock_policy: policy, identities, next_id })
    }
}

fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0xF) as usize]));
    }
    out
}

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.as_chunks::<2>().0 {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}
