//! Strict bounds-checked EDID 1.3/1.4 + CTA-861 + DisplayID 1.3/2.0 parser.
//!
//! Handles untrusted monitor data from DP AUX / I2C / VirtIO-GPU:
//! - Base 128-byte EDID block (4 DTDs, product name, monitor range limits for VRR, established timings).
//! - CTA-861 extension blocks (`0x02`): extra DTDs, HDR Static Metadata (ST2084/PQ), AMD FreeSync VSDB.
//! - DisplayID 1.3/2.0 extension blocks (`0x70`): Type I (`0x03`) & Type VII (`0x22`) detailed timings
//!   where high-refresh (240 Hz / 360 Hz / 540 Hz) and >655 MHz pixel-clock modes live.

use crate::{DisplayMode, MAX_DIM, rd_u16};

pub const EDID_BLOCK_LEN: usize = 128;
pub const MAX_EDID_BLOCKS: usize = 4;
pub const MAX_EDID_MODES: usize = 16;
const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Full video timing parameters decoded from a DTD or DisplayID timing block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DetailedTiming {
    /// Pixel clock in kHz (up to ~16.7 GHz for DisplayID Type VII).
    pub pixel_clock_khz: u32,
    pub h_active: u32,
    pub h_blank: u32,
    pub h_front_porch: u32,
    pub h_sync_width: u32,
    pub v_active: u32,
    pub v_blank: u32,
    pub v_front_porch: u32,
    pub v_sync_width: u32,
    pub h_sync_pos: bool,
    pub v_sync_pos: bool,
    pub refresh_mhz: u32,
    pub preferred: bool,
}

impl DetailedTiming {
    pub const fn h_total(&self) -> u32 {
        self.h_active.saturating_add(self.h_blank)
    }

    pub const fn v_total(&self) -> u32 {
        self.v_active.saturating_add(self.v_blank)
    }

    pub const fn h_back_porch(&self) -> u32 {
        self.h_blank.saturating_sub(self.h_front_porch.saturating_add(self.h_sync_width))
    }

    pub const fn v_back_porch(&self) -> u32 {
        self.v_blank.saturating_sub(self.v_front_porch.saturating_add(self.v_sync_width))
    }

    pub const fn to_display_mode(&self) -> DisplayMode {
        DisplayMode::new(self.h_active, self.v_active, self.refresh_mhz, self.preferred)
    }

    /// Required uncompressed pixel bandwidth in kbit/s for `bpc` bits per colour component (RGB 4:4:4).
    pub const fn raw_bandwidth_kbps(&self, bpc: u8) -> u64 {
        (self.pixel_clock_khz as u64).saturating_mul(3 * (bpc as u64))
    }

    /// Synthesize a VESA CVT 1.2 Reduced Blanking v2 timing for `(width, height)` at `refresh_mhz`.
    /// Pure integer math, suitable for high-refresh LCD/OLED panels over DisplayPort or HDMI.
    pub fn cvt_rb(width: u32, height: u32, refresh_mhz: u32) -> Option<Self> {
        if !(320..=MAX_DIM).contains(&width)
            || !(200..=MAX_DIM).contains(&height)
            || !(24_000..=1_000_000).contains(&refresh_mhz)
        {
            return None;
        }
        // CVT-RB v2 fixed horizontal blanking: 80 pixels (8 FP, 32 sync, 40 BP).
        const H_BLANK: u32 = 80;
        const H_FP: u32 = 8;
        const H_SYNC: u32 = 32;
        // CVT-RB v2 fixed vertical sync (8 lines) & back porch (6 lines), minimum 460 us VBI.
        const V_SYNC: u32 = 8;
        const V_BP: u32 = 6;
        const MIN_VBI_US: u128 = 460;

        let rf = u128::from(refresh_mhz);
        let denom = 1_000_000_000u128.saturating_sub(MIN_VBI_US.saturating_mul(rf));
        let vbi = if denom > 100_000_000 {
            let num = MIN_VBI_US.saturating_mul(u128::from(height)).saturating_mul(rf);
            (num.div_ceil(denom) as u32).max(V_SYNC + V_BP + 1)
        } else {
            (height / 8).max(V_SYNC + V_BP + 1)
        };
        let v_blank = vbi.min(2048);
        let v_front_porch = v_blank.saturating_sub(V_SYNC + V_BP).max(1);
        let h_total = width.saturating_add(H_BLANK);
        let v_total = height.saturating_add(v_blank);
        let pclk = ((u128::from(h_total) * u128::from(v_total) * rf + 500_000) / 1_000_000) as u32;
        if pclk == 0 {
            return None;
        }
        let actual_mhz = compute_refresh_mhz(pclk, h_total, v_total);
        Some(Self {
            pixel_clock_khz: pclk,
            h_active: width,
            h_blank: H_BLANK,
            h_front_porch: H_FP,
            h_sync_width: H_SYNC,
            v_active: height,
            v_blank,
            v_front_porch,
            v_sync_width: V_SYNC,
            h_sync_pos: true,
            v_sync_pos: false,
            refresh_mhz: actual_mhz,
            preferred: false,
        })
    }
}

/// Parsed summary of an EDID 1.x image (1 to 4 128-byte blocks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdidInfo {
    /// 3-letter PNP manufacturer ID (e.g. `b"RHT"`, `b"DEL"`, `b"SAM"`).
    pub manufacturer: [u8; 3],
    pub product_code: u16,
    pub serial: u32,
    pub version: u8,
    pub revision: u8,
    pub width_cm: u8,
    pub height_cm: u8,
    pub name: [u8; 13],
    pub name_len: u8,
    pub ext_blocks: u8,
    pub vrr_min_hz: u16,
    pub vrr_max_hz: u16,
    pub hdr_supported: bool,
    pub hdr_max_nits: u16,
    pub modes: [DisplayMode; MAX_EDID_MODES],
    pub mode_count: usize,
    pub timings: [DetailedTiming; MAX_EDID_MODES],
    pub timing_count: usize,
}

impl EdidInfo {
    pub fn name_str(&self) -> &str {
        let n = (self.name_len as usize).min(self.name.len());
        core::str::from_utf8(&self.name[..n]).unwrap_or("")
    }

    pub fn manufacturer_str(&self) -> &str {
        core::str::from_utf8(&self.manufacturer).unwrap_or("???")
    }

    pub fn modes(&self) -> &[DisplayMode] {
        &self.modes[..self.mode_count]
    }

    pub fn timings(&self) -> &[DetailedTiming] {
        &self.timings[..self.timing_count]
    }

    /// Find the highest-refresh detailed timing matching `(width, height)`.
    pub fn highest_refresh_for(&self, width: u32, height: u32) -> Option<DetailedTiming> {
        let mut best: Option<DetailedTiming> = None;
        for &t in self.timings() {
            if t.h_active == width && t.v_active == height && best.is_none_or(|b| t.refresh_mhz > b.refresh_mhz) {
                best = Some(t);
            }
        }
        best
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidError {
    TooShort,
    BadHeader,
    BadChecksum,
    UnsupportedVersion,
}

fn block_checksum_ok(blk: &[u8]) -> bool {
    blk.len() == EDID_BLOCK_LEN && blk.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

/// Parse an EDID 1.x image (128-byte base block plus any CTA-861 / DisplayID extension blocks present).
/// Rejects bad magic, bad base checksum, or non-1.x versions; malformed extension blocks are skipped.
pub fn parse_edid(raw: &[u8]) -> Result<EdidInfo, EdidError> {
    if raw.len() < EDID_BLOCK_LEN {
        return Err(EdidError::TooShort);
    }
    let blk = &raw[..EDID_BLOCK_LEN];
    if blk[0..8] != EDID_HEADER {
        return Err(EdidError::BadHeader);
    }
    if !block_checksum_ok(blk) {
        return Err(EdidError::BadChecksum);
    }
    let version = blk[18];
    let revision = blk[19];
    if version != 1 {
        return Err(EdidError::UnsupportedVersion);
    }
    // 3-letter PNP ID packed into 16-bit big-endian word at bytes 8..10 (5 bits per letter, 1='A').
    let mfg_raw = u16::from_be_bytes([blk[8], blk[9]]);
    let ch = |shift: u32| -> u8 {
        let v = ((mfg_raw >> shift) & 0x1F) as u8;
        if (1..=26).contains(&v) { b'A' + (v - 1) } else { b'?' }
    };
    let manufacturer = [ch(10), ch(5), ch(0)];
    let product_code = rd_u16(blk, 10).unwrap_or(0);
    let serial = u32::from_le_bytes([blk[12], blk[13], blk[14], blk[15]]);
    let width_cm = blk[21];
    let height_cm = blk[22];
    let ext_blocks = blk[126];

    let mut info = EdidInfo {
        manufacturer,
        product_code,
        serial,
        version,
        revision,
        width_cm,
        height_cm,
        name: [0; 13],
        name_len: 0,
        ext_blocks,
        vrr_min_hz: 0,
        vrr_max_hz: 0,
        hdr_supported: false,
        hdr_max_nits: 0,
        modes: [DisplayMode::default(); MAX_EDID_MODES],
        mode_count: 0,
        timings: [DetailedTiming::default(); MAX_EDID_MODES],
        timing_count: 0,
    };

    // Four 18-byte descriptor blocks at offsets 54, 72, 90, 108.
    for slot in 0..4usize {
        let off = 54 + slot * 18;
        let d = &blk[off..off + 18];
        if let Some(t) = parse_dtd(d, slot == 0) {
            push_timing(&mut info, t);
        } else if d[0] == 0 && d[1] == 0 && d[2] == 0 && d[3] == 0xFC && d[4] == 0 {
            // Display Product Name descriptor (up to 13 ASCII bytes, terminated by 0x0A or spaces).
            let raw_name = &d[5..18];
            let mut len = 0usize;
            for &c in raw_name {
                if c == 0x0A || c == 0x00 {
                    break;
                }
                if (0x20..=0x7E).contains(&c) {
                    info.name[len] = c;
                    len += 1;
                }
            }
            while len > 0 && info.name[len - 1] == b' ' {
                len -= 1;
            }
            info.name_len = len as u8;
        } else if d[0] == 0 && d[1] == 0 && d[2] == 0 && d[3] == 0xFD {
            // Display Range Limits descriptor (vertical refresh range, including EDID 1.4 +255 offset bits).
            let flags = d[4];
            let min_off = if (flags & 0x03) == 0x03 { 255u16 } else { 0u16 };
            let max_off = if (flags & 0x03) >= 0x02 { 255u16 } else { 0u16 };
            let vmin = u16::from(d[5]).saturating_add(min_off);
            let vmax = u16::from(d[6]).saturating_add(max_off);
            if vmin >= 24 && vmax >= vmin && vmax <= 1000 {
                info.vrr_min_hz = vmin;
                info.vrr_max_hz = vmax;
            }
        }
    }

    // Parse any CTA-861 (`0x02`) and DisplayID (`0x70`) extension blocks present in `raw`.
    let total_blocks = (raw.len() / EDID_BLOCK_LEN).min(MAX_EDID_BLOCKS).min(1 + usize::from(ext_blocks));
    for bidx in 1..total_blocks {
        let ext = &raw[bidx * EDID_BLOCK_LEN..(bidx + 1) * EDID_BLOCK_LEN];
        if !block_checksum_ok(ext) {
            continue;
        }
        match ext[0] {
            0x02 => parse_cta861_ext(ext, &mut info),
            0x70 => parse_displayid_ext(ext, &mut info),
            _ => {}
        }
    }

    // Standard timings (bytes 38..53: eight 2-byte descriptors) synthesized via CVT-RB v2.
    for slot in 0..8usize {
        let b0 = blk[38 + slot * 2];
        let b1 = blk[39 + slot * 2];
        if (b0 == 0x01 && b1 == 0x01) || (b0 == 0x00 && b1 == 0x00) {
            continue;
        }
        let w = (u32::from(b0) + 31) * 8;
        let h = match b1 >> 6 {
            0 => if version == 1 && revision >= 3 { (w * 10) / 16 } else { w },
            1 => (w * 3) / 4,
            2 => (w * 4) / 5,
            _ => (w * 9) / 16,
        };
        let hz = (u32::from(b1 & 0x3F) + 60) * 1000;
        if let Some(t) = DetailedTiming::cvt_rb(w, h, hz) {
            push_timing(&mut info, t);
        }
    }

    // Established timings (bytes 35..37) as fallback modes if space remains.
    let est = [
        (35usize, 1u8 << 0, 800u32, 600u32, 60_000u32),
        (35, 1 << 5, 640, 480, 60_000),
        (36, 1 << 3, 1024, 768, 60_000),
        (36, 1 << 0, 1280, 1024, 75_000),
    ];
    for (byte_i, bit, w, h, hz) in est {
        if blk[byte_i] & bit != 0 {
            let pref = info.mode_count == 0;
            push_mode(&mut info, DisplayMode::new(w, h, hz, pref));
        }
    }

    Ok(info)
}

fn compute_refresh_mhz(pix_clk_khz: u32, h_total: u32, v_total: u32) -> u32 {
    let denom = u64::from(h_total).saturating_mul(u64::from(v_total));
    u64::from(pix_clk_khz)
        .saturating_mul(1_000_000)
        .checked_div(denom)
        .map_or(60_000, |mhz| (mhz as u32).clamp(24_000, 1_000_000))
}

fn parse_dtd(d: &[u8], preferred: bool) -> Option<DetailedTiming> {
    if d.len() < 18 {
        return None;
    }
    let pix_clk_10khz = u16::from_le_bytes([d[0], d[1]]);
    if pix_clk_10khz == 0 {
        return None;
    }
    let h_active = u32::from(d[2]) | (u32::from(d[4] >> 4) << 8);
    let h_blank = u32::from(d[3]) | (u32::from(d[4] & 0x0F) << 8);
    let v_active = u32::from(d[5]) | (u32::from(d[7] >> 4) << 8);
    let v_blank = u32::from(d[6]) | (u32::from(d[7] & 0x0F) << 8);
    if !(320..=MAX_DIM).contains(&h_active) || !(200..=MAX_DIM).contains(&v_active) || h_blank == 0 || v_blank == 0 {
        return None;
    }
    let h_front_porch = u32::from(d[8]) | (u32::from((d[11] >> 6) & 0x03) << 8);
    let h_sync_width = u32::from(d[9]) | (u32::from((d[11] >> 4) & 0x03) << 8);
    let v_front_porch = u32::from(d[10] >> 4) | (u32::from((d[11] >> 2) & 0x03) << 4);
    let v_sync_width = u32::from(d[10] & 0x0F) | (u32::from(d[11] & 0x03) << 4);
    let flags = d[17];
    // Separate digital sync polarity bits when bits[4:3] == 0b11.
    let h_sync_pos = (flags & 0x02) != 0;
    let v_sync_pos = (flags & 0x04) != 0;
    let pixel_clock_khz = u32::from(pix_clk_10khz).saturating_mul(10);
    let refresh_mhz = compute_refresh_mhz(
        pixel_clock_khz,
        h_active.saturating_add(h_blank),
        v_active.saturating_add(v_blank),
    );
    Some(DetailedTiming {
        pixel_clock_khz,
        h_active,
        h_blank,
        h_front_porch,
        h_sync_width,
        v_active,
        v_blank,
        v_front_porch,
        v_sync_width,
        h_sync_pos,
        v_sync_pos,
        refresh_mhz,
        preferred,
    })
}

fn parse_cta861_ext(ext: &[u8], info: &mut EdidInfo) {
    let dtd_off = usize::from(ext[2]);
    if !(4..=127).contains(&dtd_off) {
        return;
    }
    // Walk CTA-861 data block collection [4..dtd_off].
    let mut pos = 4usize;
    while pos < dtd_off {
        let hdr = ext[pos];
        let tag = (hdr >> 5) & 0x07;
        let len = usize::from(hdr & 0x1F);
        let data_start = pos + 1;
        let Some(data_end) = data_start.checked_add(len) else {
            break;
        };
        if data_end > dtd_off {
            break;
        }
        let body = &ext[data_start..data_end];
        if tag == 2 {
            // CTA-861 Video Data Block: Short Video Descriptors (VICs).
            for &svd in body {
                let vic = svd & 0x7F;
                let native = (svd & 0x80) != 0;
                let mode = match vic {
                    4 => Some((1280u32, 720u32, 60_000u32)),
                    16 => Some((1920, 1080, 60_000)),
                    47 => Some((1280, 720, 120_000)),
                    63 => Some((1920, 1080, 120_000)),
                    95 => Some((3840, 2160, 30_000)),
                    97 => Some((3840, 2160, 60_000)),
                    118 => Some((3840, 2160, 120_000)),
                    _ => None,
                };
                if let Some((w, h, hz)) = mode
                    && let Some(mut t) = DetailedTiming::cvt_rb(w, h, hz)
                {
                    t.preferred = native && info.timing_count == 0;
                    push_timing(info, t);
                }
            }
        } else if tag == 3 && body.len() >= 7 {
            // Vendor-Specific Data Block: AMD FreeSync IEEE OUI = 0x00001A (bytes [0x1A, 0x00, 0x00]).
            if body[0] == 0x1A && body[1] == 0x00 && body[2] == 0x00 {
                let vmin = u16::from(body[5]);
                let vmax = u16::from(body[6]);
                if vmin >= 24 && vmax >= vmin {
                    info.vrr_min_hz = vmin;
                    info.vrr_max_hz = vmax;
                }
            }
        } else if tag == 7 && body.len() >= 3 && body[0] == 0x06 {
            // Extended Tag 0x06: HDR Static Metadata Data Block.
            let eotf = body[1];
            // Bit 2 = SMPTE ST 2084 (HDR10 PQ).
            if (eotf & 0x04) != 0 {
                info.hdr_supported = true;
                if body.len() >= 4 && body[3] != 0 {
                    // CTA-861 max luminance approximation: 50 * 2^(CV/32) nits.
                    let cv = u32::from(body[3]);
                    let whole = (cv / 32).min(10);
                    let frac = cv % 32;
                    let base = 50u32 << whole;
                    // Linear interpolation of 2^(frac/32) ≈ 1 + frac/32.
                    let nits = base.saturating_add((base.saturating_mul(frac)) / 32);
                    info.hdr_max_nits = nits.min(10_000) as u16;
                }
            }
        }
        pos = data_end;
    }

    // Parse CTA-861 DTDs starting at `dtd_off`.
    let mut off = dtd_off;
    while off + 18 <= 127 {
        let d = &ext[off..off + 18];
        if d[0] == 0 && d[1] == 0 {
            break;
        }
        if let Some(t) = parse_dtd(d, false) {
            push_timing(info, t);
        }
        off += 18;
    }
}

fn parse_displayid_ext(ext: &[u8], info: &mut EdidInfo) {
    // Byte 0 = 0x70 (DisplayID extension tag), byte 1 = DisplayID version, byte 2 = payload len,
    // byte 3 = product type, byte 4 = ext count, bytes 5..5+len = data blocks.
    let payload_len = usize::from(ext[2]).min(121);
    let end = (5 + payload_len).min(126);
    let mut pos = 5usize;
    while pos + 3 <= end {
        let block_tag = ext[pos];
        let block_len = usize::from(ext[pos + 2]);
        let start = pos + 3;
        let Some(next) = start.checked_add(block_len) else {
            break;
        };
        if next > end {
            break;
        }
        let body = &ext[start..next];
        match block_tag {
            // 0x03 = DisplayID 1.3 Type I Detailed Timing (10 kHz clock units, 20 bytes per descriptor)
            // 0x22 = DisplayID 2.0 Type VII Detailed Timing (1 kHz clock units, 20 bytes per descriptor)
            0x03 | 0x22 => {
                let khz_scale = if block_tag == 0x03 { 10u32 } else { 1u32 };
                let mut off = 0usize;
                while off + 20 <= body.len() {
                    let d = &body[off..off + 20];
                    let pclk_raw = u32::from(d[0]) | (u32::from(d[1]) << 8) | (u32::from(d[2]) << 16);
                    let pixel_clock_khz = pclk_raw.saturating_add(1).saturating_mul(khz_scale);
                    let preferred = (d[3] & 0x80) != 0;
                    let h_active = u32::from(u16::from_le_bytes([d[4], d[5]])).saturating_add(1);
                    let h_blank = u32::from(u16::from_le_bytes([d[6], d[7]])).saturating_add(1);
                    let h_fp_raw = u16::from_le_bytes([d[8], d[9]]);
                    let h_front_porch = u32::from(h_fp_raw & 0x7FFF).saturating_add(1);
                    let h_sync_pos = (h_fp_raw & 0x8000) != 0;
                    let h_sync_width = u32::from(u16::from_le_bytes([d[10], d[11]])).saturating_add(1);
                    let v_active = u32::from(u16::from_le_bytes([d[12], d[13]])).saturating_add(1);
                    let v_blank = u32::from(u16::from_le_bytes([d[14], d[15]])).saturating_add(1);
                    let v_fp_raw = u16::from_le_bytes([d[16], d[17]]);
                    let v_front_porch = u32::from(v_fp_raw & 0x7FFF).saturating_add(1);
                    let v_sync_pos = (v_fp_raw & 0x8000) != 0;
                    let v_sync_width = u32::from(u16::from_le_bytes([d[18], d[19]])).saturating_add(1);

                    if (320..=MAX_DIM).contains(&h_active) && (200..=MAX_DIM).contains(&v_active) {
                        let refresh_mhz = compute_refresh_mhz(
                            pixel_clock_khz,
                            h_active.saturating_add(h_blank),
                            v_active.saturating_add(v_blank),
                        );
                        push_timing(
                            info,
                            DetailedTiming {
                                pixel_clock_khz,
                                h_active,
                                h_blank,
                                h_front_porch,
                                h_sync_width,
                                v_active,
                                v_blank,
                                v_front_porch,
                                v_sync_width,
                                h_sync_pos,
                                v_sync_pos,
                                refresh_mhz,
                                preferred,
                            },
                        );
                    }
                    off += 20;
                }
            }
            _ => {}
        }
        pos = next;
    }
}

fn push_timing(info: &mut EdidInfo, t: DetailedTiming) {
    push_mode(info, t.to_display_mode());
    if info.timing_count >= info.timings.len() {
        return;
    }
    for existing in &info.timings[..info.timing_count] {
        if existing.h_active == t.h_active
            && existing.v_active == t.v_active
            && existing.refresh_mhz == t.refresh_mhz
        {
            return;
        }
    }
    info.timings[info.timing_count] = t;
    info.timing_count += 1;
}

fn push_mode(info: &mut EdidInfo, m: DisplayMode) {
    if info.mode_count >= info.modes.len() {
        return;
    }
    for existing in &info.modes[..info.mode_count] {
        if existing.width == m.width && existing.height == m.height && existing.refresh_mhz == m.refresh_mhz {
            return;
        }
    }
    info.modes[info.mode_count] = m;
    info.mode_count += 1;
}
