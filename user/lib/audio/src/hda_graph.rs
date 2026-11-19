//! Dynamic Intel HD Audio codec/widget/pin graph discovery (zero board tables)
//! and HDMI/DisplayPort ELD (EDID-Like Data) parser.

use crate::route::{DeviceKind, FLAG_CAPTURE, FLAG_ELD_VALID, FLAG_INTERNAL, FLAG_PLAYBACK, FLAG_PLUGGED};

pub const MAX_WIDGETS: usize = 64;
pub const MAX_CONNS: usize = 16;
pub const MAX_PATHS: usize = 16;
pub const MAX_PATH_HOPS: usize = 8;

/// HDA Audio Widget types (bits 23:20 of Widget Capabilities parameter 0x09).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WidgetType {
    AudioOutput = 0x0,
    AudioInput = 0x1,
    AudioMixer = 0x2,
    AudioSelector = 0x3,
    PinComplex = 0x4,
    Power = 0x5,
    VolumeKnob = 0x6,
    BeepGen = 0x7,
    Vendor = 0xF,
}

impl WidgetType {
    pub const fn from_caps(wcaps: u32) -> Self {
        match ((wcaps >> 20) & 0xF) as u8 {
            0x0 => Self::AudioOutput,
            0x1 => Self::AudioInput,
            0x2 => Self::AudioMixer,
            0x3 => Self::AudioSelector,
            0x4 => Self::PinComplex,
            0x5 => Self::Power,
            0x6 => Self::VolumeKnob,
            0x7 => Self::BeepGen,
            _ => Self::Vendor,
        }
    }
}

/// Decoded Pin Default Configuration register (verb 0xF1C00).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PinDefault {
    pub raw: u32,
}

impl PinDefault {
    pub const fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// 0 = Jack, 1 = No physical connection, 2 = Fixed (internal), 3 = Both.
    pub const fn connectivity(self) -> u8 {
        ((self.raw >> 30) & 0x3) as u8
    }

    pub const fn is_unconnected(self) -> bool {
        self.connectivity() == 1
    }

    pub const fn is_internal(self) -> bool {
        self.connectivity() == 2
    }

    /// Default device nibble (bits 23:20).
    pub const fn default_device(self) -> u8 {
        ((self.raw >> 20) & 0xF) as u8
    }

    /// Connection type nibble (bits 19:16).
    pub const fn conn_type(self) -> u8 {
        ((self.raw >> 16) & 0xF) as u8
    }

    /// Misc bit 0 = Jack Detect Override (1 means presence sense is not wired).
    pub const fn jack_detect_override(self) -> bool {
        ((self.raw >> 8) & 1) != 0
    }

    pub const fn association(self) -> u8 {
        ((self.raw >> 4) & 0xF) as u8
    }

    pub const fn sequence(self) -> u8 {
        (self.raw & 0xF) as u8
    }
}

/// Raw information queried from one HDA codec widget.
#[derive(Clone, Copy, Debug)]
pub struct Widget {
    pub nid: u8,
    pub wcaps: u32,
    pub pin_caps: u32,
    pub pin_default: PinDefault,
    pub out_amp_caps: u32,
    pub in_amp_caps: u32,
    pub conns: [u8; MAX_CONNS],
    pub conn_len: u8,
}

impl Widget {
    pub const fn empty() -> Self {
        Self {
            nid: 0,
            wcaps: 0,
            pin_caps: 0,
            pin_default: PinDefault { raw: 0 },
            out_amp_caps: 0,
            in_amp_caps: 0,
            conns: [0; MAX_CONNS],
            conn_len: 0,
        }
    }

    pub const fn kind(&self) -> WidgetType {
        WidgetType::from_caps(self.wcaps)
    }

    pub const fn has_in_amp(&self) -> bool {
        (self.wcaps & (1 << 1)) != 0
    }

    pub const fn has_out_amp(&self) -> bool {
        (self.wcaps & (1 << 2)) != 0
    }

    pub const fn is_digital(&self) -> bool {
        (self.wcaps & (1 << 9)) != 0
    }

    pub const fn unsol_capable(&self) -> bool {
        (self.wcaps & (1 << 7)) != 0
    }

    pub const fn has_power_ctrl(&self) -> bool {
        (self.wcaps & (1 << 10)) != 0
    }

    pub const fn pin_out_capable(&self) -> bool {
        (self.pin_caps & (1 << 4)) != 0
    }

    pub const fn pin_in_capable(&self) -> bool {
        (self.pin_caps & (1 << 5)) != 0
    }

    pub const fn pin_hp_drive(&self) -> bool {
        (self.pin_caps & (1 << 3)) != 0
    }

    pub const fn pin_presence_detect(&self) -> bool {
        (self.pin_caps & (1 << 2)) != 0 && !self.pin_default.jack_detect_override()
    }

    pub const fn pin_is_hdmi_or_dp(&self) -> bool {
        (self.pin_caps & ((1 << 7) | (1 << 24))) != 0
            || (self.is_digital()
                && matches!(self.pin_default.default_device(), 0x4 | 0x5)
                && self.pin_default.conn_type() == 0x7)
    }

    pub const fn pin_has_eapd(&self) -> bool {
        (self.pin_caps & (1 << 16)) != 0
    }

    pub fn connections(&self) -> &[u8] {
        let n = (self.conn_len as usize).min(MAX_CONNS);
        &self.conns[..n]
    }
}

/// One hop along an HDA signal path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathHop {
    pub nid: u8,
    /// Selected connection list index on this widget (for Selectors/Pins/Mixers).
    pub conn_index: u8,
}

/// A discovered signal path between a converter (DAC or ADC) and a Pin Complex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioPath {
    /// True for playback (DAC -> ... -> Pin), false for capture (Pin -> ... -> ADC).
    pub is_output: bool,
    pub converter_nid: u8,
    pub pin_nid: u8,
    pub kind: DeviceKind,
    pub initial_flags: u32,
    pub hp_amp: bool,
    pub eapd: bool,
    pub jack_detect: bool,
    pub is_hdmi_dp: bool,
    /// Ordered hops from Pin back toward DAC (for output) or from ADC back toward Pin (for input).
    /// `hops[0]` is always the sink end (Pin for output, ADC for input); last hop is the source.
    pub hops: [PathHop; MAX_PATH_HOPS],
    pub hop_len: u8,
}

impl AudioPath {
    pub const fn empty() -> Self {
        Self {
            is_output: true,
            converter_nid: 0,
            pin_nid: 0,
            kind: DeviceKind::Unknown,
            initial_flags: 0,
            hp_amp: false,
            eapd: false,
            jack_detect: false,
            is_hdmi_dp: false,
            hops: [PathHop { nid: 0, conn_index: 0 }; MAX_PATH_HOPS],
            hop_len: 0,
        }
    }

    pub fn hops(&self) -> &[PathHop] {
        let n = (self.hop_len as usize).min(MAX_PATH_HOPS);
        &self.hops[..n]
    }
}

/// Classify a Pin Complex into `(is_output_pin, is_input_pin, DeviceKind)`.
pub const fn classify_pin(w: &Widget) -> (bool, bool, DeviceKind) {
    if w.pin_default.is_unconnected() {
        return (false, false, DeviceKind::Unknown);
    }
    let dev = w.pin_default.default_device();
    if w.pin_is_hdmi_or_dp() && w.pin_out_capable() {
        return (true, false, DeviceKind::HdmiDp);
    }
    match dev {
        0x0 => (w.pin_out_capable(), false, DeviceKind::LineOut),
        0x1 => (w.pin_out_capable(), false, DeviceKind::Speaker),
        0x2 => (w.pin_out_capable(), false, DeviceKind::Headphones),
        0x4 | 0x5 => (w.pin_out_capable(), false, if w.pin_is_hdmi_or_dp() { DeviceKind::HdmiDp } else { DeviceKind::LineOut }),
        0x8 | 0x9 => (false, w.pin_in_capable(), DeviceKind::LineIn),
        0xA | 0xB => (false, w.pin_in_capable(), DeviceKind::Microphone),
        0xC | 0xD => (false, w.pin_in_capable(), DeviceKind::LineIn),
        _ => {
            if w.pin_out_capable() {
                (true, false, DeviceKind::LineOut)
            } else if w.pin_in_capable() {
                (false, true, DeviceKind::LineIn)
            } else {
                (false, false, DeviceKind::Unknown)
            }
        }
    }
}

fn find_widget(widgets: &[Widget], nid: u8) -> Option<&Widget> {
    widgets.iter().find(|w| w.nid == nid && w.nid != 0)
}

/// Depth-first search from `cur_nid` upstream along connection lists until `target_kind` is found.
/// Prefers unused converters first when `avoid_converters` is non-empty.
#[allow(clippy::too_many_arguments)]
fn find_upstream(
    widgets: &[Widget],
    cur_nid: u8,
    target_kind: WidgetType,
    want_digital: Option<bool>,
    avoid_nids: &[u8],
    visited: &mut [u8; MAX_PATH_HOPS],
    depth: usize,
    out_hops: &mut [PathHop; MAX_PATH_HOPS],
) -> Option<(u8, usize)> {
    if depth >= MAX_PATH_HOPS {
        return None;
    }
    let w = find_widget(widgets, cur_nid)?;
    // Cycle guard.
    if visited[..depth].contains(&cur_nid) {
        return None;
    }
    visited[depth] = cur_nid;

    // Two passes: first try connections that do not hit `avoid_nids`, then allow sharing.
    for allow_shared in [false, true] {
        for (idx, &src_nid) in w.connections().iter().enumerate() {
            let Some(src) = find_widget(widgets, src_nid) else {
                continue;
            };
            if src.kind() == target_kind {
                if let Some(dig) = want_digital
                    && src.is_digital() != dig
                {
                    continue;
                }
                if !allow_shared && avoid_nids.contains(&src_nid) {
                    continue;
                }
                if depth + 1 < MAX_PATH_HOPS {
                    out_hops[depth] = PathHop { nid: cur_nid, conn_index: idx as u8 };
                    out_hops[depth + 1] = PathHop { nid: src_nid, conn_index: 0 };
                    return Some((src_nid, depth + 2));
                }
            }
        }
        // Recurse through intermediate Mixers / Selectors / Power / Volume widgets.
        for (idx, &src_nid) in w.connections().iter().enumerate() {
            let Some(src) = find_widget(widgets, src_nid) else {
                continue;
            };
            if !matches!(src.kind(), WidgetType::AudioMixer | WidgetType::AudioSelector) {
                continue;
            }
            out_hops[depth] = PathHop { nid: cur_nid, conn_index: idx as u8 };
            if let Some(found) = find_upstream(
                widgets,
                src_nid,
                target_kind,
                want_digital,
                if allow_shared { &[] } else { avoid_nids },
                visited,
                depth + 1,
                out_hops,
            ) {
                return Some(found);
            }
        }
    }
    None
}

/// Dynamically discover all valid playback (DAC -> Pin) and capture (Pin -> ADC) paths
/// from an HDA Audio Function Group's widget table. Returns number of paths written to `out`.
pub fn discover_paths(widgets: &[Widget], out: &mut [AudioPath; MAX_PATHS]) -> usize {
    let mut count = 0usize;
    let mut used_dacs = [0u8; MAX_PATHS];
    let mut used_dacs_len = 0usize;
    let mut used_adcs = [0u8; MAX_PATHS];
    let mut used_adcs_len = 0usize;

    // 1. Discover playback paths: start at each output Pin Complex and walk upstream to a DAC.
    for w in widgets {
        if count >= MAX_PATHS || w.nid == 0 || w.kind() != WidgetType::PinComplex {
            continue;
        }
        let (is_out, _, kind) = classify_pin(w);
        if !is_out {
            continue;
        }
        let mut hops = [PathHop::default(); MAX_PATH_HOPS];
        let mut visited = [0u8; MAX_PATH_HOPS];
        let want_dig = Some(w.is_digital());
        let found = find_upstream(
            widgets,
            w.nid,
            WidgetType::AudioOutput,
            want_dig,
            &used_dacs[..used_dacs_len],
            &mut visited,
            0,
            &mut hops,
        )
        .or_else(|| {
            // Fallback: allow any DAC if digital flag didn't match.
            find_upstream(
                widgets,
                w.nid,
                WidgetType::AudioOutput,
                None,
                &used_dacs[..used_dacs_len],
                &mut visited,
                0,
                &mut hops,
            )
        });

        if let Some((dac_nid, hop_len)) = found {
            if used_dacs_len < MAX_PATHS {
                used_dacs[used_dacs_len] = dac_nid;
                used_dacs_len += 1;
            }
            let internal = w.pin_default.is_internal();
            let jack_detect = w.pin_presence_detect() && !internal;
            let mut flags = FLAG_PLAYBACK;
            if internal {
                flags |= FLAG_INTERNAL | FLAG_PLUGGED;
            } else if !jack_detect {
                flags |= FLAG_PLUGGED;
            }
            out[count] = AudioPath {
                is_output: true,
                converter_nid: dac_nid,
                pin_nid: w.nid,
                kind,
                initial_flags: flags,
                hp_amp: w.pin_hp_drive() && kind == DeviceKind::Headphones,
                eapd: w.pin_has_eapd(),
                jack_detect,
                is_hdmi_dp: w.pin_is_hdmi_or_dp(),
                hops,
                hop_len: hop_len as u8,
            };
            count += 1;
        }
    }

    // 2. Discover capture paths: start at each ADC and walk upstream to an input Pin Complex.
    for adc in widgets {
        if count >= MAX_PATHS || adc.nid == 0 || adc.kind() != WidgetType::AudioInput {
            continue;
        }
        if used_adcs[..used_adcs_len].contains(&adc.nid) {
            continue;
        }
        let mut hops = [PathHop::default(); MAX_PATH_HOPS];
        let mut visited = [0u8; MAX_PATH_HOPS];
        if let Some((pin_nid, hop_len)) = find_upstream(
            widgets,
            adc.nid,
            WidgetType::PinComplex,
            None,
            &[],
            &mut visited,
            0,
            &mut hops,
        ) {
            let Some(pin) = find_widget(widgets, pin_nid) else {
                continue;
            };
            let (_, is_in, kind) = classify_pin(pin);
            if !is_in {
                continue;
            }
            if used_adcs_len < MAX_PATHS {
                used_adcs[used_adcs_len] = adc.nid;
                used_adcs_len += 1;
            }
            let internal = pin.pin_default.is_internal();
            let jack_detect = pin.pin_presence_detect() && !internal;
            let mut flags = FLAG_CAPTURE;
            if internal {
                flags |= FLAG_INTERNAL | FLAG_PLUGGED;
            } else if !jack_detect {
                flags |= FLAG_PLUGGED;
            }
            out[count] = AudioPath {
                is_output: false,
                converter_nid: adc.nid,
                pin_nid,
                kind,
                initial_flags: flags,
                hp_amp: false,
                eapd: false,
                jack_detect,
                is_hdmi_dp: false,
                hops,
                hop_len: hop_len as u8,
            };
            count += 1;
        }
    }

    count
}

// ---- HDMI / DisplayPort ELD Parser ----------------------------------------------------------

/// Decoded CEA-861 Short Audio Descriptor (LPCM subset).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EldSad {
    /// Format code (1 = LPCM).
    pub format_code: u8,
    pub max_channels: u8,
    /// Bitmask: bit 0=32k, 1=44.1k, 2=48k, 3=88.2k, 4=96k, 5=176.4k, 6=192k.
    pub rates_mask: u8,
    /// For LPCM: bit 0=16-bit, 1=20-bit, 2=24-bit.
    pub bits_mask: u8,
}

/// Parsed HDMI / DisplayPort EDID-Like Data (ELD v2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EldInfo {
    pub version: u8,
    /// 0 = HDMI, 1 = DisplayPort.
    pub conn_type: u8,
    pub hdcp: bool,
    pub monitor_name: [u8; 16],
    pub monitor_name_len: u8,
    pub sads: [EldSad; 15],
    pub sad_count: u8,
}

impl EldInfo {
    pub fn monitor_name(&self) -> &str {
        let n = (self.monitor_name_len as usize).min(self.monitor_name.len());
        core::str::from_utf8(&self.monitor_name[..n]).unwrap_or("")
    }

    pub fn supports_lpcm_48k_stereo_16(&self) -> bool {
        let n = (self.sad_count as usize).min(self.sads.len());
        if n == 0 {
            // Basic audio fallback (HDMI/DP spec mandates 2ch 32/44.1/48 kHz 16-bit LPCM).
            return true;
        }
        self.sads[..n]
            .iter()
            .any(|s| s.format_code == 1 && s.max_channels >= 2 && (s.rates_mask & (1 << 2)) != 0 && (s.bits_mask & 1) != 0)
    }

    /// Flags to OR onto the HDMI/DP pin state when ELD is valid.
    pub const fn flags(&self) -> u32 {
        FLAG_PLUGGED | FLAG_ELD_VALID
    }
}

/// Strictly parse an untrusted HDA ELD byte buffer (Intel HDA ECN ELD v2).
pub fn parse_eld(data: &[u8]) -> Option<EldInfo> {
    // Baseline ELD header is at least 20 bytes (4-byte header + 16-byte baseline fields).
    if data.len() < 20 {
        return None;
    }
    let version = (data[0] >> 3) & 0x1F;
    if version != 2 {
        return None;
    }
    let baseline_len = (data[2] as usize) * 4;
    let total_baseline = 4usize.checked_add(baseline_len)?;
    let limit = data.len().min(total_baseline);
    if limit < 20 {
        return None;
    }
    let mnl = (data[4] & 0x1F) as usize;
    if mnl > 16 {
        return None;
    }
    let sad_count = ((data[5] >> 4) & 0x0F) as usize;
    let conn_type = (data[5] >> 2) & 0x03;
    let hdcp = (data[5] & 1) != 0;

    let name_end = 20usize.checked_add(mnl)?;
    let sads_end = name_end.checked_add(sad_count.checked_mul(3)?)?;
    if sads_end > limit {
        return None;
    }

    let mut monitor_name = [0u8; 16];
    let mut clean_len = 0usize;
    for &b in &data[20..name_end] {
        if (0x20..=0x7E).contains(&b) {
            monitor_name[clean_len] = b;
            clean_len += 1;
        }
    }
    while clean_len > 0 && monitor_name[clean_len - 1] == b' ' {
        clean_len -= 1;
    }

    let mut sads = [EldSad::default(); 15];
    let n_sads = sad_count.min(sads.len());
    for (i, slot) in sads.iter_mut().take(n_sads).enumerate() {
        let o = name_end + i * 3;
        let b0 = data[o];
        let b1 = data[o + 1];
        let b2 = data[o + 2];
        *slot = EldSad {
            format_code: (b0 >> 3) & 0x0F,
            max_channels: (b0 & 0x07) + 1,
            rates_mask: b1 & 0x7F,
            bits_mask: b2 & 0x07,
        };
    }

    Some(EldInfo {
        version,
        conn_type,
        hdcp,
        monitor_name,
        monitor_name_len: clean_len as u8,
        sads,
        sad_count: n_sads as u8,
    })
}
