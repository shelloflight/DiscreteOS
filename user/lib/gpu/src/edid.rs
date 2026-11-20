//! Strict bounds-checked EDID 1.3/1.4 parser (untrusted monitor/QEMU data).

use crate::{DisplayMode, MAX_DIM, rd_u16};

pub const EDID_BLOCK_LEN: usize = 128;
const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Parsed summary of an EDID base block.
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
    pub modes: [DisplayMode; 8],
    pub mode_count: usize,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidError {
    TooShort,
    BadHeader,
    BadChecksum,
    UnsupportedVersion,
}

/// Parse an EDID 1.x 128-byte base block. Rejects bad magic, bad checksum, or non-1.x versions.
pub fn parse_edid(raw: &[u8]) -> Result<EdidInfo, EdidError> {
    if raw.len() < EDID_BLOCK_LEN {
        return Err(EdidError::TooShort);
    }
    let blk = &raw[..EDID_BLOCK_LEN];
    if blk[0..8] != EDID_HEADER {
        return Err(EdidError::BadHeader);
    }
    let sum = blk.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum != 0 {
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
        modes: [DisplayMode::default(); 8],
        mode_count: 0,
    };

    // Four 18-byte descriptor blocks at offsets 54, 72, 90, 108.
    for slot in 0..4usize {
        let off = 54 + slot * 18;
        let d = &blk[off..off + 18];
        let pix_clk_10khz = u16::from_le_bytes([d[0], d[1]]);
        if pix_clk_10khz != 0 {
            // Detailed Timing Descriptor (DTD).
            let h_active = u32::from(d[2]) | (u32::from(d[4] >> 4) << 8);
            let h_blank = u32::from(d[3]) | (u32::from(d[4] & 0x0F) << 8);
            let v_active = u32::from(d[5]) | (u32::from(d[7] >> 4) << 8);
            let v_blank = u32::from(d[6]) | (u32::from(d[7] & 0x0F) << 8);
            if (320..=MAX_DIM).contains(&h_active) && (200..=MAX_DIM).contains(&v_active) {
                let h_total = h_active.saturating_add(h_blank);
                let v_total = v_active.saturating_add(v_blank);
                let denom = u64::from(h_total).saturating_mul(u64::from(v_total));
                let refresh_mhz = u64::from(pix_clk_10khz)
                    .saturating_mul(10_000_000)
                    .checked_div(denom)
                    .map_or(60_000, |mhz| (mhz as u32).clamp(24_000, 480_000));
                push_mode(&mut info, DisplayMode::new(h_active, v_active, refresh_mhz, slot == 0));
            }
        } else if d[2] == 0 && d[3] == 0xFC && d[4] == 0 {
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
