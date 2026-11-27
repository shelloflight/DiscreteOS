//! Persistent D-OS system settings registry (`dosid::settings`).
//!
//! Stored in `/home/.dos/` on installed systems as fail-closed TOML files:
//! - `/home/.dos/settings.toml` (`DesktopSettings`): theme, text scale, reduce motion, per-output
//!   scale, confirmed display mode, VRR, HDR10, and customized taskbar pinned apps.
//! - `/home/.dos/audio.toml` (`AudioSettings`): output volume, mute state, microphone capture
//!   policy, and preferred output device.
//! - `/home/.dos/network.toml` (`NetworkSettings`): DHCP vs static IPv4, DNS servers, and public
//!   DNS fallback policy.
//!
//! Pure `no_std` (with `alloc`), `#![forbid(unsafe_code)]`, zero external crates.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use dman::toml::{self, Value};

use crate::model::IdentityError;

const VALID_SCALES: [u16; 5] = [100, 125, 150, 175, 200];

fn valid_ascii(s: &str, max: usize) -> bool {
    s.len() <= max && s.bytes().all(|b| (0x20..=0x7E).contains(&b) && b != b'"' && b != b'\\')
}

fn valid_app_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 24
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn fmt_ipv4(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let t = s.trim();
    if t.is_empty() {
        return Some([0; 4]);
    }
    let mut out = [0u8; 4];
    let mut n = 0usize;
    for part in t.split('.') {
        if n >= 4 || part.is_empty() || part.len() > 3 {
            return None;
        }
        out[n] = part.parse::<u8>().ok()?;
        n += 1;
    }
    (n == 4).then_some(out)
}

/// Persisted desktop, appearance, display, and taskbar settings (`/home/.dos/settings.toml`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopSettings {
    /// Theme name: `"dark-slate"` or `"high-contrast"`.
    pub theme: String,
    /// Explicitly chosen text scale percentage (`100..=200` in 25% steps), or `None` for auto.
    pub text_scale: Option<u16>,
    /// Reduce compositor animations.
    pub reduce_motion: bool,
    /// Per-output primary UI scale (`0` = auto, or `100..=200`).
    pub output_scale: u16,
    /// Confirmed display mode (`width`, `height`, `refresh_mhz`); `None` uses firmware/boot mode.
    pub display_mode: Option<(u32, u32, u32)>,
    /// Variable Refresh Rate (FreeSync / Adaptive-Sync) preference.
    pub display_vrr: bool,
    /// HDR10 (10-bit) preference.
    pub display_hdr: bool,
    /// User-customized taskbar pin list; `None` uses manifest defaults.
    pub pinned_apps: Option<Vec<String>>,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            theme: "dark-slate".to_string(),
            text_scale: None,
            reduce_motion: false,
            output_scale: 0,
            display_mode: None,
            display_vrr: false,
            display_hdr: false,
            pinned_apps: None,
        }
    }
}

impl DesktopSettings {
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("# D-OS desktop and display settings\n");
        out.push_str("version = 1\n");
        let theme = if self.theme == "high-contrast" { "high-contrast" } else { "dark-slate" };
        out.push_str(&format!("theme = \"{}\"\n", theme));
        if let Some(sc) = self.text_scale {
            out.push_str(&format!("text-scale = {}\n", sc));
        }
        out.push_str(&format!("reduce-motion = {}\n", self.reduce_motion));
        out.push_str(&format!("output-scale = {}\n", self.output_scale));
        if let Some((w, h, hz)) = self.display_mode {
            out.push_str(&format!("display-width = {}\n", w));
            out.push_str(&format!("display-height = {}\n", h));
            out.push_str(&format!("display-refresh-mhz = {}\n", hz));
        }
        out.push_str(&format!("display-vrr = {}\n", self.display_vrr));
        out.push_str(&format!("display-hdr = {}\n", self.display_hdr));
        if let Some(pins) = &self.pinned_apps {
            out.push_str("pinned-apps = [");
            for (i, p) in pins.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push('"');
                out.push_str(p);
                out.push('"');
            }
            out.push_str("]\n");
        }
        out
    }

    pub fn from_toml(src: &[u8]) -> Result<Self, IdentityError> {
        let doc = toml::parse(src).map_err(|_| IdentityError::InvalidFormat)?;
        if !doc.tables.is_empty() {
            return Err(IdentityError::InvalidFormat);
        }
        let mut version = 0u64;
        let mut cfg = Self::default();
        let mut dw = 0u32;
        let mut dh = 0u32;
        let mut dhz = 0u32;
        for e in &doc.entries {
            match (e.table.as_str(), e.key.as_str(), &e.value) {
                ("", "version", Value::Int(v)) => version = *v,
                ("", "theme", Value::Str(s)) if matches!(s.as_str(), "dark-slate" | "high-contrast") => {
                    cfg.theme = s.clone();
                }
                ("", "text-scale", Value::Int(v)) if u16::try_from(*v).is_ok_and(|s| VALID_SCALES.contains(&s)) => {
                    cfg.text_scale = Some(*v as u16);
                }
                ("", "reduce-motion", Value::Bool(b)) => cfg.reduce_motion = *b,
                ("", "output-scale", Value::Int(v))
                    if u16::try_from(*v).is_ok_and(|s| s == 0 || VALID_SCALES.contains(&s)) =>
                {
                    cfg.output_scale = *v as u16;
                }
                ("", "display-width", Value::Int(v)) if (320..=7680).contains(v) => dw = *v as u32,
                ("", "display-height", Value::Int(v)) if (200..=4320).contains(v) => dh = *v as u32,
                ("", "display-refresh-mhz", Value::Int(v)) if (24_000..=1_000_000).contains(v) => dhz = *v as u32,
                ("", "display-vrr", Value::Bool(b)) => cfg.display_vrr = *b,
                ("", "display-hdr", Value::Bool(b)) => cfg.display_hdr = *b,
                ("", "pinned-apps", Value::Array(arr)) if arr.len() <= 16 => {
                    let mut pins = Vec::with_capacity(arr.len());
                    for item in arr {
                        let Value::Str(s) = item else {
                            return Err(IdentityError::InvalidFormat);
                        };
                        if !valid_app_name(s) {
                            return Err(IdentityError::InvalidFormat);
                        }
                        if !pins.iter().any(|x| x == s) {
                            pins.push(s.clone());
                        }
                    }
                    cfg.pinned_apps = Some(pins);
                }
                _ => return Err(IdentityError::InvalidFormat),
            }
        }
        if version != 1 {
            return Err(IdentityError::InvalidFormat);
        }
        if dw > 0 && dh > 0 && dhz > 0 {
            cfg.display_mode = Some((dw, dh, dhz));
        } else if dw != 0 || dh != 0 || dhz != 0 {
            return Err(IdentityError::InvalidFormat);
        }
        Ok(cfg)
    }
}

/// Persisted audio mixer and policy settings (`/home/.dos/audio.toml`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudioSettings {
    pub volume: u8,
    pub muted: bool,
    pub mic_allowed: bool,
    pub default_output: String,
}

impl Default for AudioSettings {
    fn default() -> Self {
        Self {
            volume: 100,
            muted: false,
            mic_allowed: true,
            default_output: String::new(),
        }
    }
}

impl AudioSettings {
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("# D-OS audio settings\n");
        out.push_str("version = 1\n");
        out.push_str(&format!("volume = {}\n", self.volume.min(100)));
        out.push_str(&format!("muted = {}\n", self.muted));
        out.push_str(&format!("mic-allowed = {}\n", self.mic_allowed));
        if !self.default_output.is_empty() && valid_ascii(&self.default_output, 40) {
            out.push_str(&format!("default-output = \"{}\"\n", self.default_output));
        }
        out
    }

    pub fn from_toml(src: &[u8]) -> Result<Self, IdentityError> {
        let doc = toml::parse(src).map_err(|_| IdentityError::InvalidFormat)?;
        if !doc.tables.is_empty() {
            return Err(IdentityError::InvalidFormat);
        }
        let mut version = 0u64;
        let mut cfg = Self::default();
        for e in &doc.entries {
            match (e.table.as_str(), e.key.as_str(), &e.value) {
                ("", "version", Value::Int(v)) => version = *v,
                ("", "volume", Value::Int(v)) if *v <= 100 => cfg.volume = *v as u8,
                ("", "muted", Value::Bool(b)) => cfg.muted = *b,
                ("", "mic-allowed", Value::Bool(b)) => cfg.mic_allowed = *b,
                ("", "default-output", Value::Str(s)) if valid_ascii(s, 40) => cfg.default_output = s.clone(),
                _ => return Err(IdentityError::InvalidFormat),
            }
        }
        if version != 1 {
            return Err(IdentityError::InvalidFormat);
        }
        Ok(cfg)
    }
}

/// Persisted network configuration (`/home/.dos/network.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkSettings {
    pub dhcp: bool,
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns1: [u8; 4],
    pub dns2: [u8; 4],
    pub dns_port: u16,
    pub dns_fallback: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            dhcp: true,
            ip: [0; 4],
            netmask: [0; 4],
            gateway: [0; 4],
            dns1: [0; 4],
            dns2: [0; 4],
            dns_port: 53,
            dns_fallback: true,
        }
    }
}

impl NetworkSettings {
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("# D-OS network settings\n");
        out.push_str("version = 1\n");
        out.push_str(&format!("dhcp = {}\n", self.dhcp));
        if self.ip != [0; 4] {
            out.push_str(&format!("ip = \"{}\"\n", fmt_ipv4(self.ip)));
        }
        if self.netmask != [0; 4] {
            out.push_str(&format!("netmask = \"{}\"\n", fmt_ipv4(self.netmask)));
        }
        if self.gateway != [0; 4] {
            out.push_str(&format!("gateway = \"{}\"\n", fmt_ipv4(self.gateway)));
        }
        if self.dns1 != [0; 4] {
            out.push_str(&format!("dns1 = \"{}\"\n", fmt_ipv4(self.dns1)));
        }
        if self.dns2 != [0; 4] {
            out.push_str(&format!("dns2 = \"{}\"\n", fmt_ipv4(self.dns2)));
        }
        out.push_str(&format!("dns-port = {}\n", if self.dns_port == 0 { 53 } else { self.dns_port }));
        out.push_str(&format!("dns-fallback = {}\n", self.dns_fallback));
        out
    }

    pub fn from_toml(src: &[u8]) -> Result<Self, IdentityError> {
        let doc = toml::parse(src).map_err(|_| IdentityError::InvalidFormat)?;
        if !doc.tables.is_empty() {
            return Err(IdentityError::InvalidFormat);
        }
        let mut version = 0u64;
        let mut cfg = Self::default();
        for e in &doc.entries {
            match (e.table.as_str(), e.key.as_str(), &e.value) {
                ("", "version", Value::Int(v)) => version = *v,
                ("", "dhcp", Value::Bool(b)) => cfg.dhcp = *b,
                ("", "ip", Value::Str(s)) => cfg.ip = parse_ipv4(s).ok_or(IdentityError::InvalidFormat)?,
                ("", "netmask", Value::Str(s)) => cfg.netmask = parse_ipv4(s).ok_or(IdentityError::InvalidFormat)?,
                ("", "gateway", Value::Str(s)) => cfg.gateway = parse_ipv4(s).ok_or(IdentityError::InvalidFormat)?,
                ("", "dns1", Value::Str(s)) => cfg.dns1 = parse_ipv4(s).ok_or(IdentityError::InvalidFormat)?,
                ("", "dns2", Value::Str(s)) => cfg.dns2 = parse_ipv4(s).ok_or(IdentityError::InvalidFormat)?,
                ("", "dns-port", Value::Int(v)) if (1..=65535).contains(v) => cfg.dns_port = *v as u16,
                ("", "dns-fallback", Value::Bool(b)) => cfg.dns_fallback = *b,
                _ => return Err(IdentityError::InvalidFormat),
            }
        }
        if version != 1 || (!cfg.dhcp && cfg.ip == [0; 4]) {
            return Err(IdentityError::InvalidFormat);
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn desktop_settings_roundtrip_and_fail_closed() {
        let s = DesktopSettings {
            theme: "high-contrast".into(),
            text_scale: Some(125),
            reduce_motion: true,
            output_scale: 150,
            display_mode: Some((1920, 1080, 240_000)),
            display_vrr: true,
            display_hdr: false,
            pinned_apps: Some(vec!["terminal".into(), "files".into(), "settings".into()]),
        };
        let toml = s.to_toml();
        let parsed = DesktopSettings::from_toml(toml.as_bytes()).unwrap();
        assert_eq!(parsed, s);

        // Empty pin list is preserved distinctly from None (defaults).
        let empty_pins = DesktopSettings { pinned_apps: Some(Vec::new()), ..DesktopSettings::default() };
        assert_eq!(DesktopSettings::from_toml(empty_pins.to_toml().as_bytes()).unwrap(), empty_pins);

        // Malformed / unknown keys rejected (fail-closed).
        assert!(DesktopSettings::from_toml(b"version = 1\nevil = 1\n").is_err());
        assert!(DesktopSettings::from_toml(b"version = 1\ntheme = \"neon\"\n").is_err());
        assert!(DesktopSettings::from_toml(b"version = 1\ntext-scale = 133\n").is_err());
        assert!(DesktopSettings::from_toml(b"version = 1\ndisplay-width = 1920\n").is_err());
        assert!(DesktopSettings::from_toml(b"version = 1\npinned-apps = [\"../bad\"]\n").is_err());
    }

    #[test]
    fn audio_and_network_settings_roundtrip_and_fail_closed() {
        let a = AudioSettings {
            volume: 65,
            muted: true,
            mic_allowed: false,
            default_output: "HDMI/DP Output".into(),
        };
        assert_eq!(AudioSettings::from_toml(a.to_toml().as_bytes()).unwrap(), a);
        assert!(AudioSettings::from_toml(b"version = 1\nvolume = 200\n").is_err());

        let n = NetworkSettings {
            dhcp: false,
            ip: [192, 168, 1, 50],
            netmask: [255, 255, 255, 0],
            gateway: [192, 168, 1, 1],
            dns1: [1, 1, 1, 1],
            dns2: [9, 9, 9, 9],
            dns_port: 53,
            dns_fallback: false,
        };
        assert_eq!(NetworkSettings::from_toml(n.to_toml().as_bytes()).unwrap(), n);
        // Static mode without IP is refused.
        assert!(NetworkSettings::from_toml(b"version = 1\ndhcp = false\n").is_err());
        assert!(NetworkSettings::from_toml(b"version = 1\ndns1 = \"999.0.0.1\"\n").is_err());
    }
}
