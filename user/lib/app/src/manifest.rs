//! Fail-closed `kind = "app"` manifest parser for `.dapp` bundles.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dman::toml::{self, Entry, Error, Value, err};
use dman::{Quota, valid_name};

use crate::perm::Permission;

pub const DEFAULT_APP_QUOTA: Quota = Quota { memory: 32 << 20, handles: 256, threads: 8 };

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppManifest {
    pub name: String,
    pub title: String,
    pub version: String,
    pub binary: String,
    pub description: String,
    pub pinned: bool,
    pub autostart: bool,
    /// Core permissions requested by the app (granted unless explicitly denied/revoked or capped by identity).
    pub required_perms: u32,
    /// Optional permissions (off until enabled by the user).
    pub optional_perms: u32,
    /// Permissions that trigger a compositor modal prompt on first launch.
    pub prompt_perms: u32,
    pub quota: Quota,
}

impl AppManifest {
    pub fn declared_perms(&self) -> u32 {
        self.required_perms | self.optional_perms | self.prompt_perms
    }
}

fn parse_size(s: &str) -> Option<u64> {
    let (num, mul) = match s.as_bytes().last()? {
        b'K' => (&s[..s.len() - 1], 1u64 << 10),
        b'M' => (&s[..s.len() - 1], 1 << 20),
        b'G' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    if num.is_empty() || num.len() > 12 || !num.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    num.parse::<u64>().ok()?.checked_mul(mul)
}

fn valid_label(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= max && b.iter().all(|&c| (0x20..=0x7E).contains(&c))
}

fn parse_perm_list(e: &Entry) -> Result<u32, Error> {
    let Value::Array(arr) = &e.value else {
        return Err(err(e.line, format!("'permissions.{}' must be an array of strings", e.key)));
    };
    let mut mask = 0u32;
    for v in arr {
        let Value::Str(s) = v else {
            return Err(err(e.line, format!("'permissions.{}' must be an array of strings", e.key)));
        };
        let Some(p) = Permission::parse(s) else {
            return Err(err(e.line, format!("'permissions.{}': unknown permission '{}'", e.key, s)));
        };
        if mask & p.bit() != 0 {
            return Err(err(e.line, format!("'permissions.{}': permission '{}' listed twice", e.key, s)));
        }
        mask |= p.bit();
    }
    Ok(mask)
}

/// Fail-closed parser for `.dapp` internal `manifest.dman` (`kind = "app"`).
pub fn parse_manifest(src: &[u8]) -> Result<AppManifest, Error> {
    let doc = toml::parse(src)?;
    for (t, line) in &doc.tables {
        if !matches!(t.as_str(), "permissions" | "quota") {
            return Err(err(*line, format!("unknown table [{}]", t)));
        }
    }
    let mut kind = String::new();
    let mut m = AppManifest {
        name: String::new(),
        title: String::new(),
        version: String::new(),
        binary: String::new(),
        description: String::new(),
        pinned: false,
        autostart: false,
        required_perms: 0,
        optional_perms: 0,
        prompt_perms: 0,
        quota: DEFAULT_APP_QUOTA,
    };
    for e in &doc.entries {
        match (e.table.as_str(), e.key.as_str(), &e.value) {
            ("", "kind", Value::Str(s)) => {
                if s != "app" {
                    return Err(err(e.line, format!("'kind' must be \"app\", not \"{}\"", s)));
                }
                kind = s.clone();
            }
            ("", "name", Value::Str(s)) => {
                if !valid_name(s) {
                    return Err(err(e.line, format!("'name': not a valid app name '{}'", s)));
                }
                m.name = s.clone();
            }
            ("", "title", Value::Str(s)) => {
                if !valid_label(s, 32) {
                    return Err(err(e.line, "'title' must be 1..=32 printable ASCII characters"));
                }
                m.title = s.clone();
            }
            ("", "version", Value::Str(s)) => {
                if !valid_label(s, 16) {
                    return Err(err(e.line, "'version' must be 1..=16 printable ASCII characters"));
                }
                m.version = s.clone();
            }
            ("", "binary", Value::Str(s)) => {
                let ok = matches!(s.rsplit_once('.'), Some((stem, "dx")) if valid_name(stem));
                if !ok {
                    return Err(err(e.line, format!("'binary' must be '<name>.dx', not '{}'", s)));
                }
                m.binary = s.clone();
            }
            ("", "description", Value::Str(s)) => {
                if !valid_label(s, 96) {
                    return Err(err(e.line, "'description' must be 1..=96 printable ASCII characters"));
                }
                m.description = s.clone();
            }
            ("", "pinned", Value::Bool(b)) => m.pinned = *b,
            ("", "autostart", Value::Bool(b)) => m.autostart = *b,
            ("permissions", "required", _) => m.required_perms = parse_perm_list(e)?,
            ("permissions", "optional", _) => m.optional_perms = parse_perm_list(e)?,
            ("permissions", "prompt", _) => m.prompt_perms = parse_perm_list(e)?,
            ("quota", "memory", Value::Str(s)) => {
                let v = parse_size(s).ok_or_else(|| err(e.line, format!("'quota.memory': invalid size '{}'", s)))?;
                if !(64 << 10..=256 << 20).contains(&v) {
                    return Err(err(e.line, "'quota.memory' must be between 64K and 256M"));
                }
                m.quota.memory = v;
            }
            ("quota", "memory", Value::Int(v)) => {
                if !(64 << 10..=256 << 20).contains(v) {
                    return Err(err(e.line, "'quota.memory' must be between 64K and 256M"));
                }
                m.quota.memory = *v;
            }
            ("quota", "handles", Value::Int(v)) => {
                if !(16..=512).contains(v) {
                    return Err(err(e.line, "'quota.handles' must be between 16 and 512"));
                }
                m.quota.handles = *v;
            }
            ("quota", "threads", Value::Int(v)) => {
                if !(1..=32).contains(v) {
                    return Err(err(e.line, "'quota.threads' must be between 1 and 32"));
                }
                m.quota.threads = *v;
            }
            ("", k, _) => return Err(err(e.line, format!("unknown or mistyped key '{}'", k))),
            (t, k, _) => return Err(err(e.line, format!("unknown or mistyped key '{}.{}'", t, k))),
        }
    }
    if kind.is_empty() {
        return Err(err(0, "missing 'kind = \"app\"'"));
    }
    if m.name.is_empty() {
        return Err(err(0, "missing 'name'"));
    }
    if m.title.is_empty() {
        return Err(err(0, "missing 'title'"));
    }
    if m.version.is_empty() {
        return Err(err(0, "missing 'version'"));
    }
    if m.binary.is_empty() {
        return Err(err(0, "missing 'binary'"));
    }
    if m.required_perms & m.optional_perms != 0 {
        return Err(err(0, "a permission cannot be both required and optional"));
    }
    if m.prompt_perms & m.optional_perms != 0 {
        return Err(err(0, "a permission cannot be both prompt and optional"));
    }
    // Check that all requested permissions are valid bits (already ensured by parse_perm_list).
    let _ = Vec::<u8>::new();
    Ok(m)
}
