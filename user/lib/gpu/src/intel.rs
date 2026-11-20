//! Intel Xe / i915 core (pure safe Rust, `#![forbid(unsafe_code)]`).
//!
//! Covers:
//! - PCI Device ID classification: Xe2-HPG (Arc Battlemage / Lunar Lake), Xe-HPG (Arc Alchemist),
//!   Xe-LP (Tiger/Alder/Raptor/Meteor Lake), and Gen9/Gen11 UHD Graphics.
//! - GMD_ID (Graphics/Media/Display IP version) register decoding.
//! - Display Engine Pipe A-D register offsets (`TRANS_CONF`, `PIPE_SRCSZ`, `PLANE_CTL`,
//!   `PLANE_STRIDE`, `PLANE_SURF`, `PIPE_FRMCOUNT_G4X`) and GGTT PTE encoding.
//! - MI & XY Blitter command ring packet encoder & strict validator (`BCS0`).

use crate::{CsError, rd_u32};

pub const VENDOR_INTEL: u16 = 0x8086;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntelGen {
    Gen9,
    XeLp,
    XeHpg,
    Xe2,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntelGpuInfo {
    pub arch: IntelGen,
    pub discrete: bool,
    pub name: &'static str,
}

/// Classify an Intel PCI display controller (`8086:device`).
pub const fn identify_pci(device_id: u16) -> IntelGpuInfo {
    match device_id {
        // Arc Battlemage (Xe2-HPG discrete)
        0xE202 | 0xE20B | 0xE20C | 0xE20D | 0xE212 => {
            IntelGpuInfo { arch: IntelGen::Xe2, discrete: true, name: "Intel Arc Battlemage (Xe2)" }
        }
        // Lunar Lake (Xe2-LPG integrated)
        0x64A0 | 0x6420 | 0x64B0 => {
            IntelGpuInfo { arch: IntelGen::Xe2, discrete: false, name: "Intel Arc Xe2 (Lunar Lake)" }
        }
        // Arc Alchemist (Xe-HPG discrete: A770/A750/A580/A380)
        0x56A0..=0x56AF | 0x5690..=0x5697 | 0x56B0..=0x56B3 => {
            IntelGpuInfo { arch: IntelGen::XeHpg, discrete: true, name: "Intel Arc Alchemist (Xe-HPG)" }
        }
        // Meteor Lake / Arrow Lake (Xe-LPG)
        0x7D40..=0x7D67 => {
            IntelGpuInfo { arch: IntelGen::XeHpg, discrete: false, name: "Intel Arc Xe-LPG (Meteor/Arrow Lake)" }
        }
        // Alder Lake / Raptor Lake / Tiger Lake (Xe-LP / Gen12)
        0x4680..=0x46BF | 0xA780..=0xA7AF | 0x9A40..=0x9A7F => {
            IntelGpuInfo { arch: IntelGen::XeLp, discrete: false, name: "Intel Iris Xe / UHD (Gen12)" }
        }
        // Skylake / Kaby Lake / Coffee Lake / Comet Lake (Gen9)
        0x1900..=0x193F | 0x5900..=0x593F | 0x3E90..=0x3E9F | 0x9B40..=0x9BCF => {
            IntelGpuInfo { arch: IntelGen::Gen9, discrete: false, name: "Intel UHD Graphics (Gen9)" }
        }
        _ => IntelGpuInfo { arch: IntelGen::Unknown, discrete: false, name: "Intel GPU" },
    }
}

/// Decoded `GMD_ID` register (`0xD8C` on Xe/Meteor/Lunar/Battlemage).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GmdId {
    pub arch: u8,
    pub release: u8,
    pub step: u8,
}

pub const fn decode_gmd_id(raw: u32) -> GmdId {
    GmdId {
        arch: ((raw >> 22) & 0x3FF) as u8,
        release: ((raw >> 14) & 0xFF) as u8,
        step: (raw & 0x3F) as u8,
    }
}

// ---- MMIO Register Offsets (BAR 0 GTTMMADR) -----------------------------------------------------

pub const REG_GMD_ID: u64 = 0x0000_0D8C;
pub const REG_FORCEWAKE_RENDER_GEN9: u64 = 0x0000_A278;
pub const REG_FORCEWAKE_ACK_RENDER_GEN9: u64 = 0x0000_0D84;

// Display Pipes A..D (`pipe` in 0..4).
pub const fn reg_pipe_srcsz(pipe: u32) -> u64 {
    0x0006_001C + (pipe as u64) * 0x1000
}
pub const fn reg_trans_conf(pipe: u32) -> u64 {
    0x0007_0008 + (pipe as u64) * 0x1000
}
pub const fn reg_pipe_frmcount(pipe: u32) -> u64 {
    0x0007_0040 + (pipe as u64) * 0x1000
}
pub const fn reg_plane_ctl_1(pipe: u32) -> u64 {
    0x0007_0180 + (pipe as u64) * 0x1000
}
pub const fn reg_plane_stride_1(pipe: u32) -> u64 {
    0x0007_0188 + (pipe as u64) * 0x1000
}
pub const fn reg_plane_size_1(pipe: u32) -> u64 {
    0x0007_0190 + (pipe as u64) * 0x1000
}
pub const fn reg_plane_surf_1(pipe: u32) -> u64 {
    0x0007_019C + (pipe as u64) * 0x1000
}

pub const TRANS_CONF_ENABLE: u32 = 1 << 31;
pub const PLANE_CTL_ENABLE: u32 = 1 << 31;

/// Decode `PIPE_SRCSZ`: `(width, height)` (each field is `value - 1`).
pub const fn decode_pipe_srcsz(val: u32) -> (u32, u32) {
    let w = ((val >> 16) & 0x1FFF) + 1;
    let h = (val & 0x1FFF) + 1;
    (w, h)
}

/// Encode a 64-bit GGTT Page Table Entry (valid bit 0 set).
pub const fn ggtt_pte(dma_addr: u64) -> u64 {
    (dma_addr & !0xFFF) | 1
}

// Blitter Command Streamer (`BCS0`, MMIO base 0x22000).
pub const BCS0_BASE: u64 = 0x0002_2000;
pub const RING_TAIL: u64 = 0x30;
pub const RING_HEAD: u64 = 0x34;
pub const RING_START: u64 = 0x38;
pub const RING_CTL: u64 = 0x3C;
pub const RING_HWS_PGA: u64 = 0x80;

// ---- MI & XY Blitter Commands + Strict Validator ------------------------------------------------

pub const MI_NOOP: u32 = 0x00 << 23;
pub const MI_BATCH_BUFFER_END: u32 = 0x0A << 23;
pub const MI_STORE_DATA_IMM: u32 = (0x20 << 23) | 2;
pub const MI_FLUSH_DW: u32 = (0x26 << 23) | 2;
pub const XY_FAST_COLOR_BLT_OP: u32 = (2 << 29) | (0x44 << 22);
pub const INTEL_MAX_CS_BYTES: usize = 32 * 1024;

/// Encode `MI_NOOP` (1 dword).
pub fn mi_noop(out: &mut [u32]) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    out[0] = MI_NOOP;
    Some(1)
}

/// Encode `MI_STORE_DATA_IMM` 32-bit fence write (4 dwords).
pub fn mi_store_data_imm(out: &mut [u32], ggtt_addr: u64, value: u32) -> Option<usize> {
    if out.len() < 4 || !ggtt_addr.is_multiple_of(4) {
        return None;
    }
    out[0] = MI_STORE_DATA_IMM | (1 << 22); // Use Global GTT
    out[1] = ggtt_addr as u32;
    out[2] = (ggtt_addr >> 32) as u32;
    out[3] = value;
    Some(4)
}

/// Encode `MI_FLUSH_DW` (4 dwords).
pub fn mi_flush_dw(out: &mut [u32]) -> Option<usize> {
    if out.len() < 4 {
        return None;
    }
    out[0] = MI_FLUSH_DW;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    Some(4)
}

/// Validate an untrusted Intel MI/Blitter command stream before BCS0 ring submission.
/// Rejects privileged `MI_LOAD_REGISTER_*`, arbitrary `MI_BATCH_BUFFER_START`, and truncated commands.
pub fn validate_mi_cs(bytes: &[u8]) -> Result<usize, CsError> {
    if bytes.is_empty() {
        return Err(CsError::Empty);
    }
    if bytes.len() > INTEL_MAX_CS_BYTES {
        return Err(CsError::TooLarge);
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(CsError::Unaligned);
    }
    let mut off = 0usize;
    let mut pkts = 0usize;
    while off < bytes.len() {
        let hdr = rd_u32(bytes, off).ok_or(CsError::Truncated)?;
        let client = (hdr >> 29) & 0x7;
        let dwords = match client {
            // MI client (0)
            0 => {
                let op = (hdr >> 23) & 0x3F;
                match op {
                    0x00 => 1,                                   // MI_NOOP
                    0x0A => 1,                                   // MI_BATCH_BUFFER_END
                    0x20 => ((hdr & 0x3FF) as usize) + 2,        // MI_STORE_DATA_IMM
                    0x26 => ((hdr & 0x3F) as usize) + 2,         // MI_FLUSH_DW
                    _ => return Err(CsError::UnknownOpcode),
                }
            }
            // 2D Blitter client (2)
            2 => {
                let op = (hdr >> 22) & 0x7F;
                match op {
                    0x44 | 0x42 => ((hdr & 0xFF) as usize) + 2, // XY_FAST_COLOR_BLT / XY_FAST_COPY_BLT
                    _ => return Err(CsError::UnknownOpcode),
                }
            }
            _ => return Err(CsError::UnknownOpcode),
        };
        let pkt_bytes = dwords.checked_mul(4).ok_or(CsError::TooLarge)?;
        if off.checked_add(pkt_bytes).is_none_or(|e| e > bytes.len()) {
            return Err(CsError::Truncated);
        }
        off += pkt_bytes;
        pkts += 1;
    }
    Ok(pkts)
}
