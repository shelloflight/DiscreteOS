//! Audio device classification and automatic output switching policy.
//!
//! Automatic output priority (highest to lowest):
//!   1. Headphones (plugged in)
//!   2. USB headset / USB audio (present/plugged)
//!   3. HDMI / DisplayPort audio (plugged in and ELD valid, or plugged)
//!   4. Speakers / Line-out / Virtual / Other

/// Physical or logical audio endpoint kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Unknown = 0,
    Speaker = 1,
    LineOut = 2,
    Headphones = 3,
    HdmiDp = 4,
    UsbAudio = 5,
    Virtual = 6,
    Microphone = 7,
    LineIn = 8,
}

impl DeviceKind {
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Speaker,
            2 => Self::LineOut,
            3 => Self::Headphones,
            4 => Self::HdmiDp,
            5 => Self::UsbAudio,
            6 => Self::Virtual,
            7 => Self::Microphone,
            8 => Self::LineIn,
            _ => Self::Unknown,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Speaker => "speaker",
            Self::LineOut => "line-out",
            Self::Headphones => "headphones",
            Self::HdmiDp => "hdmi/dp",
            Self::UsbAudio => "usb-audio",
            Self::Virtual => "virtual",
            Self::Microphone => "microphone",
            Self::LineIn => "line-in",
        }
    }
}

/// Capability and live-connection flags for an audio endpoint.
pub const FLAG_PLAYBACK: u32 = 1 << 0;
pub const FLAG_CAPTURE: u32 = 1 << 1;
pub const FLAG_PLUGGED: u32 = 1 << 2;
pub const FLAG_ELD_VALID: u32 = 1 << 3;
pub const FLAG_INTERNAL: u32 = 1 << 4;

/// Candidate device considered by the automatic routing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteDevice {
    pub id: u32,
    pub kind: DeviceKind,
    pub flags: u32,
    pub online: bool,
}

/// Priority score for automatic output selection (higher wins; 0 = ineligible).
pub const fn output_priority(d: &RouteDevice) -> u32 {
    if !d.online || (d.flags & FLAG_PLAYBACK) == 0 {
        return 0;
    }
    let plugged = (d.flags & FLAG_PLUGGED) != 0;
    let eld = (d.flags & FLAG_ELD_VALID) != 0;
    let internal = (d.flags & FLAG_INTERNAL) != 0;
    match d.kind {
        // 1. Headphones (only when plugged in)
        DeviceKind::Headphones if plugged => 500,
        // 2. USB headset / USB audio
        DeviceKind::UsbAudio if plugged => 400,
        // 3. HDMI / DisplayPort (prefer ELD-valid sink)
        DeviceKind::HdmiDp if plugged && eld => 320,
        DeviceKind::HdmiDp if plugged => 300,
        // 4. Line-out (plugged) & internal speakers
        DeviceKind::LineOut if plugged => 220,
        DeviceKind::Speaker if plugged || internal => 200,
        DeviceKind::Virtual if plugged => 150,
        // Fallbacks when jack sense is absent/unplugged but device is online
        DeviceKind::LineOut => 120,
        DeviceKind::Speaker => 110,
        DeviceKind::Virtual => 100,
        DeviceKind::Unknown if plugged => 80,
        DeviceKind::Unknown => 50,
        // Unplugged removable outputs are ineligible if anything else exists,
        // except as a last-resort fallback (score 10) when no plugged output exists.
        DeviceKind::Headphones | DeviceKind::UsbAudio | DeviceKind::HdmiDp => 10,
        DeviceKind::Microphone | DeviceKind::LineIn => 0,
    }
}

/// Priority score for automatic input (microphone) selection.
pub const fn input_priority(d: &RouteDevice) -> u32 {
    if !d.online || (d.flags & FLAG_CAPTURE) == 0 {
        return 0;
    }
    let plugged = (d.flags & FLAG_PLUGGED) != 0;
    let internal = (d.flags & FLAG_INTERNAL) != 0;
    match d.kind {
        DeviceKind::UsbAudio if plugged => 400,
        DeviceKind::Microphone if plugged && !internal => 350,
        DeviceKind::Microphone if plugged || internal => 300,
        DeviceKind::LineIn if plugged => 250,
        DeviceKind::Virtual if plugged => 200,
        DeviceKind::Microphone => 150,
        DeviceKind::LineIn => 120,
        DeviceKind::Virtual => 100,
        _ => 50,
    }
}

/// Select the active output device ID.
/// If `manual_override` is `Some(id)` and that device is online with playback capability, it wins.
/// Otherwise, chooses the highest-priority output (tie-breaking by lowest device ID for determinism).
pub fn select_output(devices: &[RouteDevice], manual_override: Option<u32>) -> Option<u32> {
    if let Some(id) = manual_override
        && devices
            .iter()
            .any(|d| d.id == id && d.online && (d.flags & FLAG_PLAYBACK) != 0)
    {
        return Some(id);
    }
    let mut best: Option<(u32, u32)> = None; // (priority, id)
    for d in devices {
        let prio = output_priority(d);
        if prio == 0 {
            continue;
        }
        let better = match best {
            None => true,
            Some((bp, bid)) => prio > bp || (prio == bp && d.id < bid),
        };
        if better {
            best = Some((prio, d.id));
        }
    }
    best.map(|(_, id)| id)
}

/// Select the active input (capture) device ID.
pub fn select_input(devices: &[RouteDevice], manual_override: Option<u32>) -> Option<u32> {
    if let Some(id) = manual_override
        && devices
            .iter()
            .any(|d| d.id == id && d.online && (d.flags & FLAG_CAPTURE) != 0)
    {
        return Some(id);
    }
    let mut best: Option<(u32, u32)> = None;
    for d in devices {
        let prio = input_priority(d);
        if prio == 0 {
            continue;
        }
        let better = match best {
            None => true,
            Some((bp, bid)) => prio > bp || (prio == bp && d.id < bid),
        };
        if better {
            best = Some((prio, d.id));
        }
    }
    best.map(|(_, id)| id)
}
