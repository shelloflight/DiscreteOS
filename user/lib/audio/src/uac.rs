//! Strict, bounds-checked USB Audio Class (UAC 1.0 and UAC 2.0) configuration descriptor parser.
//!
//! Zero heap allocation, zero unsafe code. Parses untrusted USB configuration descriptors
//! to discover AudioControl entities (terminals, feature units, clock sources) and
//! AudioStreaming alt-settings (PCM format, channels, sample rates, isochronous endpoints).

use crate::pcm::SampleFormat;

pub const MAX_STREAMS: usize = 8;
pub const MAX_RATES: usize = 12;

/// USB Audio Class version detected from the AudioControl interface protocol.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UacVersion {
    Uac1 = 1,
    Uac2 = 2,
}

/// Discovered USB Audio Streaming alt-setting backed by an isochronous endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbAudioStream {
    pub version: UacVersion,
    /// True for playback (OUT from host -> device), false for capture (IN from device -> host).
    pub is_output: bool,
    pub iface: u8,
    pub alt: u8,
    /// USB endpoint address (includes bit 7 direction; ep number = `ep_addr & 0x0F`).
    pub ep_addr: u8,
    /// Base max packet size in bytes (`wMaxPacketSize & 0x07FF`).
    pub max_packet: u16,
    /// Additional transactions per microframe (`(wMaxPacketSize >> 11) & 3`, 0..=2 for HS).
    pub mult: u8,
    /// Raw `bInterval` from the endpoint descriptor.
    pub interval: u8,
    /// True if UAC 1.0 CS_ENDPOINT `bmAttributes` bit 0 (Sampling Frequency Control) is set.
    pub ep_freq_ctrl: bool,
    pub terminal_link: u8,
    pub feature_unit_id: u8,
    pub clock_source_id: u8,
    pub channels: u8,
    pub subslot_bytes: u8,
    pub bit_resolution: u8,
    pub format: SampleFormat,
    /// Discrete supported sample rates (Hz); empty if continuous or UAC 2.0 clock-controlled.
    pub rates: [u32; MAX_RATES],
    pub rate_count: u8,
    /// Continuous rate range (`[min_hz, max_hz]`), or `[0, 0]` if discrete.
    pub rate_min: u32,
    pub rate_max: u32,
}

impl UsbAudioStream {
    pub const fn empty() -> Self {
        Self {
            version: UacVersion::Uac1,
            is_output: true,
            iface: 0,
            alt: 0,
            ep_addr: 0,
            max_packet: 0,
            mult: 0,
            interval: 1,
            ep_freq_ctrl: false,
            terminal_link: 0,
            feature_unit_id: 0,
            clock_source_id: 0,
            channels: 0,
            subslot_bytes: 0,
            bit_resolution: 0,
            format: SampleFormat::S16Le,
            rates: [0; MAX_RATES],
            rate_count: 0,
            rate_min: 0,
            rate_max: 0,
        }
    }

    pub fn rates(&self) -> &[u32] {
        let n = (self.rate_count as usize).min(MAX_RATES);
        &self.rates[..n]
    }

    /// Pick the best sample rate, preferring `preferred_hz` (typically 48000 Hz).
    pub fn choose_rate(&self, preferred_hz: u32) -> u32 {
        if self.rate_min != 0 && self.rate_max >= self.rate_min {
            return preferred_hz.clamp(self.rate_min, self.rate_max);
        }
        let rs = self.rates();
        if rs.is_empty() {
            return preferred_hz;
        }
        if rs.contains(&preferred_hz) {
            return preferred_hz;
        }
        if rs.contains(&48_000) {
            return 48_000;
        }
        if rs.contains(&44_100) {
            return 44_100;
        }
        rs[0]
    }
}

/// Parsed summary of a USB Audio Class device's configuration descriptor.
#[derive(Clone, Copy, Debug)]
pub struct UsbAudioConfig {
    pub config_value: u8,
    pub version: UacVersion,
    pub ac_iface: u8,
    pub streams: [UsbAudioStream; MAX_STREAMS],
    pub stream_count: usize,
}

impl UsbAudioConfig {
    pub fn streams(&self) -> &[UsbAudioStream] {
        &self.streams[..self.stream_count.min(MAX_STREAMS)]
    }

    /// Choose the best playback or capture alt-setting (preferring 48 kHz, stereo, S16_LE).
    pub fn best_stream(&self, is_output: bool) -> Option<UsbAudioStream> {
        let mut best: Option<(u32, UsbAudioStream)> = None;
        for &s in self.streams() {
            if s.is_output != is_output {
                continue;
            }
            let mut score = 100u32;
            if s.format == SampleFormat::S16Le {
                score += 40;
            } else if s.format == SampleFormat::S24Le || s.format == SampleFormat::S32Le {
                score += 20;
            }
            if s.channels == 2 {
                score += 30;
            } else if s.channels == 1 {
                score += 15;
            }
            let r = s.choose_rate(48_000);
            if r == 48_000 {
                score += 50;
            } else if r == 44_100 {
                score += 30;
            }
            if best.is_none_or(|(bs, _)| score > bs) {
                best = Some((score, s));
            }
        }
        best.map(|(_, s)| s)
    }
}

#[derive(Clone, Copy, Default)]
struct EntityLink {
    id: u8,
    source_id: u8,
    clock_id: u8,
    is_feature_unit: bool,
}

fn infer_pcm_format(subslot_bytes: u8, bit_res: u8) -> Option<SampleFormat> {
    match (subslot_bytes, bit_res) {
        (1, 8) => Some(SampleFormat::U8),
        (2, 16) => Some(SampleFormat::S16Le),
        (3, 24) => Some(SampleFormat::S24Le),
        (4, 24 | 32) => Some(SampleFormat::S32Le),
        _ => None,
    }
}

/// Strictly parse an untrusted USB configuration descriptor for UAC 1.0 or UAC 2.0 streams.
pub fn parse_config(desc: &[u8]) -> Option<UsbAudioConfig> {
    if desc.len() < 9 || desc[0] < 9 || desc[1] != 0x02 {
        return None;
    }
    let total_len = u16::from_le_bytes([desc[2], desc[3]]) as usize;
    let limit = desc.len().min(total_len);
    let config_value = desc[5];

    let mut found_ac = false;
    let mut version = UacVersion::Uac1;
    let mut ac_iface = 0u8;

    // Lightweight AudioControl entity map (to associate terminal -> feature unit & clock source).
    let mut entities = [EntityLink::default(); 32];
    let mut entity_count = 0usize;
    let mut default_clock_id = 0u8;

    let mut streams = [UsbAudioStream::empty(); MAX_STREAMS];
    let mut stream_count = 0usize;

    // Current interface parser state.
    let mut cur_class = 0u8;
    let mut cur_subclass = 0u8;
    let mut cur_proto = 0u8;
    let mut cur_iface = 0u8;
    let mut cur_alt = 0u8;

    // Pending AudioStreaming alt-setting fields (flushed when isochronous endpoint is seen).
    let mut pending_pcm = false;
    let mut pending_term_link = 0u8;
    let mut pending_channels = 0u8;
    let mut pending_subslot = 0u8;
    let mut pending_bits = 0u8;
    let mut pending_rates = [0u32; MAX_RATES];
    let mut pending_rate_count = 0u8;
    let mut pending_rate_min = 0u32;
    let mut pending_rate_max = 0u32;
    let mut last_stream_idx: Option<usize> = None;

    let mut off = 0usize;
    while off + 2 <= limit {
        let len = desc[off] as usize;
        let ty = desc[off + 1];
        if len < 2 || off + len > limit {
            break;
        }
        let d = &desc[off..off + len];
        off += len;

        match ty {
            // Interface descriptor
            0x04 if len >= 9 => {
                cur_iface = d[2];
                cur_alt = d[3];
                cur_class = d[5];
                cur_subclass = d[6];
                cur_proto = d[7];

                pending_pcm = false;
                pending_term_link = 0;
                pending_channels = 0;
                pending_subslot = 0;
                pending_bits = 0;
                pending_rates = [0; MAX_RATES];
                pending_rate_count = 0;
                pending_rate_min = 0;
                pending_rate_max = 0;
                last_stream_idx = None;

                if cur_class == 0x01 && cur_subclass == 0x01 {
                    found_ac = true;
                    ac_iface = cur_iface;
                    version = if cur_proto == 0x20 { UacVersion::Uac2 } else { UacVersion::Uac1 };
                }
            }
            // Class-specific Interface descriptor (CS_INTERFACE)
            0x24 if cur_class == 0x01 && len >= 3 => {
                let subtype = d[2];
                if cur_subclass == 0x01 {
                    // AudioControl entities
                    match (version, subtype) {
                        // INPUT_TERMINAL
                        (UacVersion::Uac1, 0x02) if len >= 12 => {
                            if entity_count < entities.len() {
                                entities[entity_count] = EntityLink { id: d[3], source_id: 0, clock_id: 0, is_feature_unit: false };
                                entity_count += 1;
                            }
                        }
                        (UacVersion::Uac2, 0x02) if len >= 17 => {
                            if entity_count < entities.len() {
                                entities[entity_count] = EntityLink { id: d[3], source_id: 0, clock_id: d[7], is_feature_unit: false };
                                entity_count += 1;
                            }
                        }
                        // OUTPUT_TERMINAL
                        (UacVersion::Uac1, 0x03) if len >= 9 => {
                            if entity_count < entities.len() {
                                entities[entity_count] = EntityLink { id: d[3], source_id: d[7], clock_id: 0, is_feature_unit: false };
                                entity_count += 1;
                            }
                        }
                        (UacVersion::Uac2, 0x03) if len >= 12 => {
                            if entity_count < entities.len() {
                                entities[entity_count] = EntityLink { id: d[3], source_id: d[7], clock_id: d[8], is_feature_unit: false };
                                entity_count += 1;
                            }
                        }
                        // FEATURE_UNIT
                        (_, 0x06) if len >= 6 => {
                            if entity_count < entities.len() {
                                entities[entity_count] = EntityLink { id: d[3], source_id: d[4], clock_id: 0, is_feature_unit: true };
                                entity_count += 1;
                            }
                        }
                        // UAC 2.0 CLOCK_SOURCE
                        (UacVersion::Uac2, 0x0A) if len >= 8 && default_clock_id == 0 => {
                            default_clock_id = d[3];
                        }
                        _ => {}
                    }
                } else if cur_subclass == 0x02 && cur_alt > 0 {
                    // AudioStreaming descriptors
                    let as_ver = if cur_proto == 0x20 || version == UacVersion::Uac2 {
                        UacVersion::Uac2
                    } else {
                        UacVersion::Uac1
                    };
                    match (as_ver, subtype) {
                        // AS_GENERAL (UAC 1.0)
                        (UacVersion::Uac1, 0x01) if len >= 7 => {
                            pending_term_link = d[3];
                            let fmt_tag = u16::from_le_bytes([d[5], d[6]]);
                            pending_pcm = fmt_tag == 0x0001;
                        }
                        // AS_GENERAL (UAC 2.0)
                        (UacVersion::Uac2, 0x01) if len >= 16 => {
                            pending_term_link = d[3];
                            let fmt_type = d[5];
                            let bm_formats = u32::from_le_bytes([d[6], d[7], d[8], d[9]]);
                            pending_channels = d[10];
                            pending_pcm = fmt_type == 1 && (bm_formats & 1) != 0;
                        }
                        // FORMAT_TYPE (UAC 1.0 Type I)
                        (UacVersion::Uac1, 0x02) if len >= 8 && d[3] == 1 => {
                            pending_channels = d[4];
                            pending_subslot = d[5];
                            pending_bits = d[6];
                            let sam_freq_type = d[7];
                            if sam_freq_type == 0 {
                                // Continuous range: 2 x 3-byte frequencies at +8..+14
                                if len >= 14 {
                                    pending_rate_min = u32::from(d[8]) | (u32::from(d[9]) << 8) | (u32::from(d[10]) << 16);
                                    pending_rate_max = u32::from(d[11]) | (u32::from(d[12]) << 8) | (u32::from(d[13]) << 16);
                                }
                            } else {
                                let mut n = 0usize;
                                for i in 0..(sam_freq_type as usize) {
                                    let p = 8 + i * 3;
                                    if p + 3 > len || n >= MAX_RATES {
                                        break;
                                    }
                                    let hz = u32::from(d[p]) | (u32::from(d[p + 1]) << 8) | (u32::from(d[p + 2]) << 16);
                                    if hz > 0 {
                                        pending_rates[n] = hz;
                                        n += 1;
                                    }
                                }
                                pending_rate_count = n as u8;
                            }
                        }
                        // FORMAT_TYPE (UAC 2.0 Type I)
                        (UacVersion::Uac2, 0x02) if len >= 6 && d[3] == 1 => {
                            pending_subslot = d[4];
                            pending_bits = d[5];
                        }
                        _ => {}
                    }
                }
            }
            // Standard Endpoint descriptor inside an AudioStreaming alt-setting
            0x05 if cur_class == 0x01 && cur_subclass == 0x02 && cur_alt > 0 && len >= 7 => {
                let ep_addr = d[2];
                let attrs = d[3];
                let transfer_type = attrs & 0x03;
                // Only Isochronous audio data endpoints (skip feedback endpoints with usage bits 0x10/0x20).
                let usage = (attrs >> 4) & 0x03;
                if transfer_type == 0x01
                    && usage == 0
                    && pending_pcm
                    && stream_count < MAX_STREAMS
                    && let Some(format) = infer_pcm_format(pending_subslot, pending_bits)
                    && (1..=8).contains(&pending_channels)
                {
                    let raw_mps = u16::from_le_bytes([d[4], d[5]]);
                    let max_packet = raw_mps & 0x07FF;
                    let mult = ((raw_mps >> 11) & 0x03) as u8;
                    let interval = d[6].max(1);
                    let is_output = (ep_addr & 0x80) == 0;
                    let as_ver = if cur_proto == 0x20 || version == UacVersion::Uac2 {
                        UacVersion::Uac2
                    } else {
                        UacVersion::Uac1
                    };
                    if max_packet > 0 {
                        streams[stream_count] = UsbAudioStream {
                            version: as_ver,
                            is_output,
                            iface: cur_iface,
                            alt: cur_alt,
                            ep_addr,
                            max_packet,
                            mult,
                            interval,
                            ep_freq_ctrl: false,
                            terminal_link: pending_term_link,
                            feature_unit_id: 0,
                            clock_source_id: default_clock_id,
                            channels: pending_channels,
                            subslot_bytes: pending_subslot,
                            bit_resolution: pending_bits,
                            format,
                            rates: pending_rates,
                            rate_count: pending_rate_count,
                            rate_min: pending_rate_min,
                            rate_max: pending_rate_max,
                        };
                        last_stream_idx = Some(stream_count);
                        stream_count += 1;
                    }
                }
            }
            // Class-specific Endpoint descriptor (CS_ENDPOINT)
            0x25 if cur_class == 0x01 && cur_subclass == 0x02 && len >= 4 => {
                if let Some(idx) = last_stream_idx
                    && d[2] == 0x01
                {
                    streams[idx].ep_freq_ctrl = (d[3] & 1) != 0;
                }
            }
            _ => {}
        }
    }

    if !found_ac || stream_count == 0 {
        return None;
    }

    // Resolve feature unit & clock source for each discovered stream from the AC entity graph.
    let ents = &entities[..entity_count];
    for s in streams.iter_mut().take(stream_count) {
        if let Some(t) = ents.iter().find(|e| e.id == s.terminal_link)
            && t.clock_id != 0
        {
            s.clock_source_id = t.clock_id;
        }
        // Find a Feature Unit whose source is `terminal_link` (playback) or that feeds `terminal_link` (capture).
        if let Some(fu) = ents.iter().find(|e| e.is_feature_unit && e.source_id == s.terminal_link) {
            s.feature_unit_id = fu.id;
        } else if let Some(t) = ents.iter().find(|e| e.id == s.terminal_link)
            && let Some(fu) = ents.iter().find(|e| e.is_feature_unit && e.id == t.source_id)
        {
            s.feature_unit_id = fu.id;
        }
    }

    Some(UsbAudioConfig {
        config_value,
        version,
        ac_iface,
        streams,
        stream_count,
    })
}
