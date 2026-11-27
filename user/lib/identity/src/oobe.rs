//! First-boot setup (OOBE) configuration persistence (`dosid::oobe`).
//!
//! Stored once at `/home/.dos/oobe.toml` on installed systems. Once `completed = true`
//! (either by finishing setup or skipping it), first-boot setup is bypassed on every
//! subsequent boot. Fail-closed TOML parser with zero unsafe code.

use alloc::format;
use alloc::string::{String, ToString};

use crate::model::IdentityError;

pub const LANGUAGES: &[(&str, &str)] = &[
    ("en-US", "English (United States)"),
    ("en-GB", "English (United Kingdom)"),
    ("de-DE", "German (Germany)"),
    ("fr-FR", "French (France)"),
    ("es-ES", "Spanish (Spain)"),
];

pub const KEYBOARDS: &[(&str, &str)] = &[
    ("us", "US QWERTY"),
    ("uk", "UK QWERTY"),
    ("de", "German QWERTZ"),
    ("fr", "French AZERTY"),
    ("es", "Spanish QWERTY"),
];

pub const TIMEZONES: &[(&str, &str)] = &[
    ("UTC", "UTC (Coordinated Universal Time)"),
    ("UTC-8", "UTC-8 (Pacific)"),
    ("UTC-7", "UTC-7 (Mountain)"),
    ("UTC-6", "UTC-6 (Central)"),
    ("UTC-5", "UTC-5 (Eastern)"),
    ("UTC+0", "UTC+0 (London)"),
    ("UTC+1", "UTC+1 (Berlin / Paris)"),
    ("UTC+9", "UTC+9 (Tokyo)"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OobeConfig {
    pub completed: bool,
    pub skipped: bool,
    pub language: String,
    pub keyboard: String,
    pub timezone: String,
    pub net_mode: String,
    pub net_ip: String,
    pub net_mask: String,
    pub net_gw: String,
    pub net_dns1: String,
    pub net_dns2: String,
}

impl Default for OobeConfig {
    fn default() -> Self {
        Self {
            completed: false,
            skipped: false,
            language: "en-US".to_string(),
            keyboard: "us".to_string(),
            timezone: "UTC".to_string(),
            net_mode: "dhcp".to_string(),
            net_ip: String::new(),
            net_mask: String::new(),
            net_gw: String::new(),
            net_dns1: String::new(),
            net_dns2: String::new(),
        }
    }
}

fn valid_ascii_field(s: &str, max: usize) -> bool {
    s.len() <= max && s.bytes().all(|b| (0x20..=0x7E).contains(&b) && b != b'"' && b != b'\\')
}

impl OobeConfig {
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("# D-OS first-boot setup state\n");
        out.push_str("version = 1\n");
        out.push_str(&format!("completed = {}\n", self.completed));
        out.push_str(&format!("skipped = {}\n", self.skipped));
        out.push_str(&format!("language = \"{}\"\n", self.language));
        out.push_str(&format!("keyboard = \"{}\"\n", self.keyboard));
        out.push_str(&format!("timezone = \"{}\"\n", self.timezone));
        out.push_str(&format!("net-mode = \"{}\"\n", self.net_mode));
        if !self.net_ip.is_empty() {
            out.push_str(&format!("net-ip = \"{}\"\n", self.net_ip));
        }
        if !self.net_mask.is_empty() {
            out.push_str(&format!("net-mask = \"{}\"\n", self.net_mask));
        }
        if !self.net_gw.is_empty() {
            out.push_str(&format!("net-gw = \"{}\"\n", self.net_gw));
        }
        if !self.net_dns1.is_empty() {
            out.push_str(&format!("net-dns1 = \"{}\"\n", self.net_dns1));
        }
        if !self.net_dns2.is_empty() {
            out.push_str(&format!("net-dns2 = \"{}\"\n", self.net_dns2));
        }
        out
    }

    pub fn from_toml(src: &[u8]) -> Result<Self, IdentityError> {
        use dman::toml::{self, Value};
        let doc = toml::parse(src).map_err(|_| IdentityError::InvalidFormat)?;
        if !doc.tables.is_empty() {
            return Err(IdentityError::InvalidFormat);
        }
        let mut version = 0u64;
        let mut cfg = Self::default();
        for e in &doc.entries {
            match (e.table.as_str(), e.key.as_str(), &e.value) {
                ("", "version", Value::Int(v)) => version = *v,
                ("", "completed", Value::Bool(b)) => cfg.completed = *b,
                ("", "skipped", Value::Bool(b)) => cfg.skipped = *b,
                ("", "language", Value::Str(s)) if valid_ascii_field(s, 16) => cfg.language = s.clone(),
                ("", "keyboard", Value::Str(s)) if valid_ascii_field(s, 16) => cfg.keyboard = s.clone(),
                ("", "timezone", Value::Str(s)) if valid_ascii_field(s, 24) => cfg.timezone = s.clone(),
                ("", "net-mode", Value::Str(s)) if matches!(s.as_str(), "dhcp" | "static" | "skip") => {
                    cfg.net_mode = s.clone()
                }
                ("", "net-ip", Value::Str(s)) if valid_ascii_field(s, 24) => cfg.net_ip = s.clone(),
                ("", "net-mask", Value::Str(s)) if valid_ascii_field(s, 24) => cfg.net_mask = s.clone(),
                ("", "net-gw", Value::Str(s)) if valid_ascii_field(s, 24) => cfg.net_gw = s.clone(),
                ("", "net-dns1", Value::Str(s)) if valid_ascii_field(s, 24) => cfg.net_dns1 = s.clone(),
                ("", "net-dns2", Value::Str(s)) if valid_ascii_field(s, 24) => cfg.net_dns2 = s.clone(),
                _ => return Err(IdentityError::InvalidFormat),
            }
        }
        if version != 1 {
            return Err(IdentityError::InvalidFormat);
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oobe_config_roundtrip_and_fail_closed() {
        let cfg = OobeConfig {
            completed: true,
            skipped: false,
            language: "de-DE".into(),
            keyboard: "de".into(),
            timezone: "UTC+1".into(),
            net_mode: "static".into(),
            net_ip: "10.0.2.15".into(),
            net_mask: "255.255.255.0".into(),
            net_gw: "10.0.2.2".into(),
            net_dns1: "1.1.1.1".into(),
            net_dns2: "9.9.9.9".into(),
        };
        let toml = cfg.to_toml();
        let parsed = OobeConfig::from_toml(toml.as_bytes()).unwrap();
        assert_eq!(parsed, cfg);

        // Unknown keys and invalid net-mode are refused.
        assert!(OobeConfig::from_toml(b"version = 1\nevil = true\n").is_err());
        assert!(OobeConfig::from_toml(b"version = 1\nnet-mode = \"bogus\"\n").is_err());
        assert!(OobeConfig::from_toml(b"version = 2\ncompleted = true\n").is_err());
    }
}
