//! AMD RDNA / AMDGPU core (pure safe Rust, `#![forbid(unsafe_code)]`).
//!
//! Covers:
//! - PCI Device ID classification: RDNA 4 (Navi 48 — Radeon RX 9070 / RX 9070 XT, Navi 44),
//!   RDNA 3 (Navi 31/32/33 — RX 7000), RDNA 2 (Navi 21/22/23/24 — RX 6000 & Ryzen 7000/9000
//!   Raphael/Granite Ridge iGPU), and fallback AMD display adapters (`1002:*`).
//! - AMD IP Discovery binary table parser + checksum verifier (`VRAM_SIZE - 64 KiB`).
//! - DCN (Display Core Next 2/3/4) HUBP/OTG surface & timing register definitions.
//! - PM4 Type-3 graphics/compute command packet encoder & strict validator.
//! - SDMA v5/v6 DMA blit/fill/fence command packet encoder & strict validator.

use crate::{CsError, rd_u16, rd_u32};

pub const VENDOR_AMD: u16 = 0x1002;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmdFamily {
    Rdna2,
    Rdna3,
    Rdna4,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmdGpuInfo {
    pub family: AmdFamily,
    pub gfx_major: u8,
    pub dcn_major: u8,
    pub sdma_major: u8,
    pub name: &'static str,
    pub is_apu: bool,
}

/// Classify an AMD PCI device ID (`1002:device`).
pub const fn identify_pci(device_id: u16) -> AmdGpuInfo {
    match device_id {
        // RDNA 4 — Navi 48 (Radeon RX 9070 / RX 9070 XT, GFX12.0.1, DCN 4.0.1, SDMA 7.0)
        0x7550 => AmdGpuInfo { family: AmdFamily::Rdna4, gfx_major: 12, dcn_major: 4, sdma_major: 7, name: "AMD Radeon RX 9070 (Navi 48)", is_apu: false },
        0x7551 => AmdGpuInfo { family: AmdFamily::Rdna4, gfx_major: 12, dcn_major: 4, sdma_major: 7, name: "AMD Radeon Navi 48", is_apu: false },
        // RDNA 4 — Navi 44 (Radeon RX 9060 series, GFX12.0.0, DCN 4.0.1)
        0x7590 | 0x7591 => AmdGpuInfo { family: AmdFamily::Rdna4, gfx_major: 12, dcn_major: 4, sdma_major: 7, name: "AMD Radeon Navi 44 (RDNA 4)", is_apu: false },
        // RDNA 3 — Navi 31/32/33 (Radeon RX 7900 / 7800 / 7700 / 7600, GFX11, DCN 3.2)
        0x744C | 0x7448 => AmdGpuInfo { family: AmdFamily::Rdna3, gfx_major: 11, dcn_major: 3, sdma_major: 6, name: "AMD Radeon RX 7900 (Navi 31)", is_apu: false },
        0x747E | 0x7470 => AmdGpuInfo { family: AmdFamily::Rdna3, gfx_major: 11, dcn_major: 3, sdma_major: 6, name: "AMD Radeon RX 7800/7700 (Navi 32)", is_apu: false },
        0x7480 | 0x7483 | 0x7489 => AmdGpuInfo { family: AmdFamily::Rdna3, gfx_major: 11, dcn_major: 3, sdma_major: 6, name: "AMD Radeon RX 7600 (Navi 33)", is_apu: false },
        // RDNA 2 — Navi 21/22/23/24 (Radeon RX 6000, GFX10.3, DCN 3.0)
        0x73BF | 0x73A5 => AmdGpuInfo { family: AmdFamily::Rdna2, gfx_major: 10, dcn_major: 3, sdma_major: 5, name: "AMD Radeon RX 6800/6900 (Navi 21)", is_apu: false },
        0x73DF => AmdGpuInfo { family: AmdFamily::Rdna2, gfx_major: 10, dcn_major: 3, sdma_major: 5, name: "AMD Radeon RX 6700 (Navi 22)", is_apu: false },
        0x73FF | 0x73EF => AmdGpuInfo { family: AmdFamily::Rdna2, gfx_major: 10, dcn_major: 3, sdma_major: 5, name: "AMD Radeon RX 6600 (Navi 23)", is_apu: false },
        0x743F => AmdGpuInfo { family: AmdFamily::Rdna2, gfx_major: 10, dcn_major: 3, sdma_major: 5, name: "AMD Radeon RX 6500/6400 (Navi 24)", is_apu: false },
        // Ryzen 7000 / 9000 Desktop iGPU (Raphael / Granite Ridge, RDNA 2, DCN 3.1.5)
        0x164E | 0x13C0 => AmdGpuInfo { family: AmdFamily::Rdna2, gfx_major: 10, dcn_major: 3, sdma_major: 5, name: "AMD Ryzen iGPU (RDNA 2)", is_apu: true },
        // Ryzen Mobile RDNA 3 / 3.5 iGPU (Phoenix / Hawk Point / Strix)
        0x15BF | 0x15C8 | 0x150E => AmdGpuInfo { family: AmdFamily::Rdna3, gfx_major: 11, dcn_major: 3, sdma_major: 6, name: "AMD Ryzen iGPU (RDNA 3)", is_apu: true },
        _ => AmdGpuInfo { family: AmdFamily::Unknown, gfx_major: 10, dcn_major: 3, sdma_major: 5, name: "AMD Radeon GPU", is_apu: false },
    }
}

// ---- Indirect MMIO & Common NBIO Registers (byte offsets in BAR 5 RMMIO) ------------------------

pub const MM_INDEX: u64 = 0x0000;
pub const MM_DATA: u64 = 0x0004;
pub const MM_INDEX_HI: u64 = 0x0018;
/// Bit 31 of `MM_INDEX` selects VRAM space instead of MMIO space.
pub const MM_INDEX_VRAM_BIT: u32 = 1 << 31;

/// `RCC_CONFIG_MEMSIZE` (NBIO dword 0x0DE3 = byte 0x378C): VRAM size in MiB on RDNA 2/3/4.
pub const REG_RCC_CONFIG_MEMSIZE: u64 = 0x0DE3 * 4;
/// Alternate `NBIF_RCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE` dword offset on some NBIO 7.x / 4.x parts.
pub const REG_RCC_CONFIG_MEMSIZE_ALT: u64 = 0x0DC3 * 4;

/// Size of the IP Discovery binary region at `VRAM_SIZE - 64 KiB`.
pub const IP_DISCOVERY_OFFSET_FROM_TOP: u64 = 64 * 1024;
pub const IP_DISCOVERY_BINARY_SIG: u32 = 0x282114;
pub const IP_DISCOVERY_TABLE_SIG: u32 = 0x4950_4449; // "IDPI" little-endian (or "IPD " = 0x20445049)

// Known AMD IP Hardware IDs (from AMD IP Discovery spec).
pub const HWID_GC: u16 = 1;
pub const HWID_SDMA0: u16 = 2;
pub const HWID_SDMA1: u16 = 3;
pub const HWID_OSSSYS: u16 = 10;
pub const HWID_MMHUB: u16 = 12;
pub const HWID_NBIO: u16 = 14;
pub const HWID_MP0: u16 = 16;
pub const HWID_MP1: u16 = 17;
pub const HWID_DCE: u16 = 20; // DCN display block

/// One parsed IP block base from AMD IP Discovery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpBlock {
    pub hw_id: u16,
    pub instance: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u8,
    /// First register segment base (dword offset from BAR 5 RMMIO).
    pub base_dword: u32,
}

/// Summary of discovered AMD IP blocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiscoverySummary {
    pub version: u16,
    pub blocks: [IpBlock; 16],
    pub count: usize,
}

impl DiscoverySummary {
    pub fn find(&self, hw_id: u16, instance: u8) -> Option<IpBlock> {
        self.blocks[..self.count]
            .iter()
            .copied()
            .find(|b| b.hw_id == hw_id && b.instance == instance)
    }

    pub fn blocks(&self) -> &[IpBlock] {
        &self.blocks[..self.count]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    TooShort,
    BadSignature,
    BadChecksum,
    BadOffset,
}

/// Compute AMD IP Discovery 16-bit byte-sum checksum.
pub fn discovery_checksum(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0u16, |acc, &b| acc.wrapping_add(u16::from(b)))
}

/// Parse an AMD IP Discovery binary image (read from `VRAM_SIZE - 64 KiB`).
/// Verifies binary header signature, binary checksum, IP discovery table offset/size, and
/// extracts GC, DCN/DCE, SDMA, NBIO, OSSSYS, MMHUB, MP0/MP1 register bases safely.
pub fn parse_ip_discovery(raw: &[u8]) -> Result<DiscoverySummary, DiscoveryError> {
    // Binary header is at least 48 bytes (signature, version, checksum, table_list[0]).
    if raw.len() < 48 {
        return Err(DiscoveryError::TooShort);
    }
    let sig = rd_u32(raw, 0).ok_or(DiscoveryError::TooShort)?;
    if sig != IP_DISCOVERY_BINARY_SIG {
        return Err(DiscoveryError::BadSignature);
    }
    let version = rd_u16(raw, 4).ok_or(DiscoveryError::TooShort)?;
    let bin_size = rd_u16(raw, 6).ok_or(DiscoveryError::TooShort)? as usize;
    let expected_csum = rd_u16(raw, 10).ok_or(DiscoveryError::TooShort)?;
    if bin_size < 48 || bin_size > raw.len() {
        return Err(DiscoveryError::BadOffset);
    }
    // Checksum covers bytes [12..bin_size] (everything after the checksum field in the header).
    if discovery_checksum(&raw[12..bin_size]) != expected_csum {
        return Err(DiscoveryError::BadChecksum);
    }
    // Table 0 (IP_DISCOVERY) info entry at offset 12: offset(u16), checksum(u16), size(u16), pad(u16).
    let ip_off = rd_u16(raw, 12).ok_or(DiscoveryError::TooShort)? as usize;
    let ip_csum = rd_u16(raw, 14).ok_or(DiscoveryError::TooShort)?;
    let ip_size = rd_u16(raw, 16).ok_or(DiscoveryError::TooShort)? as usize;
    if ip_size < 32 || ip_off.checked_add(ip_size).is_none_or(|e| e > raw.len()) {
        return Err(DiscoveryError::BadOffset);
    }
    let ip_tbl = &raw[ip_off..ip_off + ip_size];
    if discovery_checksum(ip_tbl) != ip_csum {
        return Err(DiscoveryError::BadChecksum);
    }
    let num_dies = rd_u16(ip_tbl, 10).ok_or(DiscoveryError::TooShort)? as usize;
    let mut summary = DiscoverySummary { version, blocks: [IpBlock::default(); 16], count: 0 };

    // Die info entries start at offset 12 in ip_tbl (4 bytes each: die_id(u16), die_offset(u16)).
    for d in 0..num_dies.min(8) {
        let entry_off = 12 + d * 4;
        let Some(die_off) = rd_u16(ip_tbl, entry_off + 2).map(usize::from) else {
            break;
        };
        if die_off + 4 > raw.len() {
            continue;
        }
        let Some(num_ips) = rd_u16(raw, die_off + 2).map(usize::from) else {
            continue;
        };
        let mut cursor = die_off + 4;
        for _ in 0..num_ips.min(128) {
            if cursor + 8 > raw.len() {
                break;
            }
            let hw_id = rd_u16(raw, cursor).unwrap_or(0);
            let instance = raw[cursor + 2];
            let num_bases = raw[cursor + 3] as usize;
            let major = raw[cursor + 4];
            let minor = raw[cursor + 5];
            let revision = raw[cursor + 6];
            let rec_bytes = 8usize.saturating_add(num_bases.saturating_mul(4));
            if cursor.checked_add(rec_bytes).is_none_or(|e| e > raw.len()) {
                break;
            }
            let base_dword = if num_bases > 0 {
                rd_u32(raw, cursor + 8).unwrap_or(0)
            } else {
                0
            };
            let wanted = matches!(
                hw_id,
                HWID_GC | HWID_SDMA0 | HWID_SDMA1 | HWID_OSSSYS | HWID_MMHUB | HWID_NBIO | HWID_MP0 | HWID_MP1 | HWID_DCE
            );
            if wanted && summary.count < summary.blocks.len() {
                summary.blocks[summary.count] = IpBlock {
                    hw_id,
                    instance,
                    major,
                    minor,
                    revision,
                    base_dword,
                };
                summary.count += 1;
            }
            cursor += rec_bytes;
        }
    }
    Ok(summary)
}

// ---- DCN (Display Core Next) Surface & OTG Helpers ----------------------------------------------

/// DCN 3.x / 4.x HUBP0 primary surface register offsets relative to DCN base (in dwords).
/// Used for reading the live UEFI GOP scanout address and atomic double-buffered VRAM page flips.
pub mod dcn {
    pub const HUBP0_DCSURF_SURFACE_CONFIG: u32 = 0x0580;
    pub const HUBP0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH: u32 = 0x0584;
    pub const HUBP0_DCSURF_PRIMARY_SURFACE_ADDRESS: u32 = 0x0585;
    pub const HUBP0_DCSURF_FLIP_CONTROL: u32 = 0x058A;
    pub const HUBP0_DCSURF_SURFACE_CONTROL: u32 = 0x058B;

    /// Format code in `DCSURF_SURFACE_CONFIG[6:0]` for ARGB8888 / XRGB8888.
    pub const SURFACE_PIXEL_FORMAT_ARGB8888: u32 = 8;

    /// Combine DCN primary surface low/high registers into a 64-bit VRAM GPU virtual/FB address.
    pub const fn decode_surface_addr(lo: u32, hi: u32) -> u64 {
        (lo as u64 & !0xFF) | ((hi as u64 & 0xFFFF) << 32)
    }

    /// Split a 256-byte-aligned VRAM address into `(lo, hi)` register values.
    pub const fn encode_surface_addr(addr: u64) -> (u32, u32) {
        ((addr as u32) & !0xFF, ((addr >> 32) & 0xFFFF) as u32)
    }
}

// ---- PM4 Type-3 Command Packets & Validator -----------------------------------------------------

pub const PM4_TYPE3: u32 = 3 << 30;
pub const PM4_NOP: u32 = 0x10;
pub const PM4_SET_UCONFIG_REG: u32 = 0x79;
pub const PM4_SET_SH_REG: u32 = 0x76;
pub const PM4_WAIT_REG_MEM: u32 = 0x3C;
pub const PM4_WRITE_DATA: u32 = 0x37;
pub const PM4_RELEASE_MEM: u32 = 0x49;
pub const PM4_COPY_DATA: u32 = 0x40;
pub const PM4_DISPATCH_DIRECT: u32 = 0x15;
pub const PM4_DRAW_INDEX_AUTO: u32 = 0x2D;
pub const PM4_MAX_CS_BYTES: usize = 64 * 1024;

/// Build a PM4 Type-3 packet header: `count` is the number of payload dwords (encoded as `count - 1`).
#[inline]
pub const fn pm4_hdr(opcode: u32, payload_dwords: u32) -> u32 {
    let cnt = if payload_dwords > 0 { payload_dwords - 1 } else { 0 };
    PM4_TYPE3 | ((cnt & 0x3FFF) << 16) | ((opcode & 0xFF) << 8)
}

/// Encode a PM4 `NOP` packet (1 dword header + 1 dword payload = 2 dwords).
pub fn pm4_nop(out: &mut [u32], tag: u32) -> Option<usize> {
    if out.len() < 2 {
        return None;
    }
    out[0] = pm4_hdr(PM4_NOP, 1);
    out[1] = tag;
    Some(2)
}

/// Encode a PM4 `RELEASE_MEM` fence writeback packet (7 dwords total: header + 6 payload words).
pub fn pm4_release_mem_fence(out: &mut [u32], gpu_addr: u64, seq: u64) -> Option<usize> {
    if out.len() < 7 || !gpu_addr.is_multiple_of(8) {
        return None;
    }
    // Event type 0x14 (CACHE_FLUSH_AND_INV_TS_EVENT), event_index=5 (EOP), data_sel=2 (64-bit data),
    // int_sel=2 (SEND_INT_AFTER_WRITE_CONFIRM), dst_sel=0 (MEM).
    out[0] = pm4_hdr(PM4_RELEASE_MEM, 6);
    out[1] = 0x14 | (5 << 8) | (1 << 12) | (1 << 15);
    out[2] = (2 << 29) | (2 << 24);
    out[3] = gpu_addr as u32;
    out[4] = (gpu_addr >> 32) as u32;
    out[5] = seq as u32;
    out[6] = (seq >> 32) as u32;
    Some(7)
}

/// Validate an untrusted user/service PM4 command stream before ring submission.
/// Only permits Type-3 safe compute/render/sync opcodes; blocks privileged register writes and malformed sizes.
pub fn validate_pm4_cs(bytes: &[u8]) -> Result<usize, CsError> {
    if bytes.is_empty() {
        return Err(CsError::Empty);
    }
    if bytes.len() > PM4_MAX_CS_BYTES {
        return Err(CsError::TooLarge);
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(CsError::Unaligned);
    }
    let mut off = 0usize;
    let mut pkts = 0usize;
    while off < bytes.len() {
        let hdr = rd_u32(bytes, off).ok_or(CsError::Truncated)?;
        // Special single-dword NOP filler (0xFFFF_1000).
        if hdr == 0xFFFF_1000 {
            off += 4;
            pkts += 1;
            continue;
        }
        if (hdr >> 30) != 3 {
            return Err(CsError::UnknownOpcode);
        }
        let op = (hdr >> 8) & 0xFF;
        let payload_dwords = (((hdr >> 16) & 0x3FFF) as usize) + 1;
        let pkt_bytes = 4usize.checked_add(payload_dwords * 4).ok_or(CsError::TooLarge)?;
        if off.checked_add(pkt_bytes).is_none_or(|e| e > bytes.len()) {
            return Err(CsError::Truncated);
        }
        match op {
            PM4_NOP | PM4_DISPATCH_DIRECT | PM4_DRAW_INDEX_AUTO => {}
            PM4_SET_SH_REG => {
                // Only shader-stage registers inside [0x0000..0x0C00] offset from SH base.
                let reg_off = rd_u32(bytes, off + 4).ok_or(CsError::Truncated)? & 0xFFFF;
                if reg_off >= 0x0C00 {
                    return Err(CsError::DisallowedRegister);
                }
            }
            PM4_RELEASE_MEM if payload_dwords == 6 => {}
            PM4_WAIT_REG_MEM if payload_dwords == 6 => {}
            _ => return Err(CsError::UnknownOpcode),
        }
        off += pkt_bytes;
        pkts += 1;
    }
    Ok(pkts)
}

// ---- SDMA v5/v6/v7 Packet Encoder & Validator ---------------------------------------------------

pub const SDMA_OP_NOP: u32 = 0;
pub const SDMA_OP_COPY: u32 = 1;
pub const SDMA_OP_FENCE: u32 = 5;
pub const SDMA_OP_TRAP: u32 = 6;
pub const SDMA_OP_CONST_FILL: u32 = 11;
pub const SDMA_MAX_CS_BYTES: usize = 32 * 1024;

/// Encode an SDMA `NOP` packet (1 dword).
pub fn sdma_nop(out: &mut [u32]) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    out[0] = SDMA_OP_NOP;
    Some(1)
}

/// Encode an SDMA linear copy packet (7 dwords).
pub fn sdma_copy_linear(out: &mut [u32], src_gpu: u64, dst_gpu: u64, bytes: u32) -> Option<usize> {
    if out.len() < 7 || bytes == 0 || bytes > (1 << 22) {
        return None;
    }
    out[0] = SDMA_OP_COPY; // sub_op=0 (linear)
    out[1] = bytes - 1;
    out[2] = 0;
    out[3] = src_gpu as u32;
    out[4] = (src_gpu >> 32) as u32;
    out[5] = dst_gpu as u32;
    out[6] = (dst_gpu >> 32) as u32;
    Some(7)
}

/// Encode an SDMA constant-fill packet (5 dwords, 32-bit fill pattern).
pub fn sdma_const_fill(out: &mut [u32], dst_gpu: u64, value: u32, bytes: u32) -> Option<usize> {
    if out.len() < 5 || bytes == 0 || !bytes.is_multiple_of(4) || bytes > (1 << 22) {
        return None;
    }
    out[0] = SDMA_OP_CONST_FILL | (2 << 30); // fillsize=2 (32-bit dword)
    out[1] = dst_gpu as u32;
    out[2] = (dst_gpu >> 32) as u32;
    out[3] = value;
    out[4] = bytes - 1;
    Some(5)
}

/// Encode an SDMA fence writeback packet (4 dwords).
pub fn sdma_fence(out: &mut [u32], fence_gpu: u64, seq: u32) -> Option<usize> {
    if out.len() < 4 || !fence_gpu.is_multiple_of(4) {
        return None;
    }
    out[0] = SDMA_OP_FENCE;
    out[1] = fence_gpu as u32;
    out[2] = (fence_gpu >> 32) as u32;
    out[3] = seq;
    Some(4)
}

/// Validate an untrusted SDMA command buffer before ring submission.
pub fn validate_sdma_cs(bytes: &[u8]) -> Result<usize, CsError> {
    if bytes.is_empty() {
        return Err(CsError::Empty);
    }
    if bytes.len() > SDMA_MAX_CS_BYTES {
        return Err(CsError::TooLarge);
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(CsError::Unaligned);
    }
    let mut off = 0usize;
    let mut pkts = 0usize;
    while off < bytes.len() {
        let hdr = rd_u32(bytes, off).ok_or(CsError::Truncated)?;
        let op = hdr & 0xFF;
        let sub = (hdr >> 8) & 0xFF;
        let dwords = match (op, sub) {
            (SDMA_OP_NOP, 0) => 1 + ((hdr >> 16) & 0x3FFF) as usize,
            (SDMA_OP_COPY, 0) => 7,
            (SDMA_OP_FENCE, 0) => 4,
            (SDMA_OP_TRAP, 0) => 2,
            (SDMA_OP_CONST_FILL, 0) => 5,
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
