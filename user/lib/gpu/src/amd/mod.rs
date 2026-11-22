//! AMD RDNA / AMDGPU core (pure safe Rust, `#![forbid(unsafe_code)]`).
//!
//! Covers:
//! - PCI Device ID classification: RDNA 4 (Navi 48 — Radeon RX 9070 / RX 9070 XT, Navi 44),
//!   RDNA 3 (Navi 31/32/33 — RX 7000), RDNA 2 (Navi 21/22/23/24 — RX 6000 & Ryzen 7000/9000
//!   Raphael/Granite Ridge iGPU), and fallback AMD display adapters (`1002:*`).
//! - AMD IP Discovery binary table parser (v1/v2/v4, 32-bit & 64-bit multi-segment bases,
//!   checksum verification, `MEM_RESERVED_INFO` parsing).
//! - Version-keyed DCN display engine tables (`dcn401`, `dcn315`, `dcn32`, `dcn30`), MMHUB
//!   MC↔VRAM address translation, active multi-pipe probing, scanout allocation, DP AUX
//!   (DPCD/EDID/link training), tear-free vsync flipping with buffer-age damage, hardware cursor,
//!   OSSSYS IH ring interrupt handling, mode-setting (OTG/DCCG/MSA/DSC), VRR, and HDR10.
//! - PM4 Type-3 and SDMA v5/v6/v7 command packet encoders & strict validators.

pub mod dp_aux;
pub mod dcn;
pub mod dcn30;
pub mod dcn315;
pub mod dcn32;
pub mod dcn401;
pub mod flip;
#[cfg(test)]
pub mod sim;

use crate::{CsError, DamageRect, rd_u16, rd_u32, rd_u64};

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

impl AmdGpuInfo {
    /// Expected DCN version before IP Discovery refines it.
    pub const fn dcn_hint(&self) -> dcn::DcnVersion {
        match (self.family, self.is_apu) {
            (AmdFamily::Rdna4, _) => dcn::DcnVersion::Dcn401,
            (AmdFamily::Rdna3, _) => dcn::DcnVersion::Dcn32,
            (AmdFamily::Rdna2, true) => dcn::DcnVersion::Dcn315,
            _ => dcn::DcnVersion::Dcn30,
        }
    }
}

/// Classify an AMD PCI device ID (`1002:device`).
pub const fn identify_pci(device_id: u16) -> AmdGpuInfo {
    match device_id {
        // RDNA 4 — Navi 48 (Radeon RX 9070 / RX 9070 XT, GFX12.0.1, DCN 4.0.1, SDMA 7.0)
        0x7550 => AmdGpuInfo {
            family: AmdFamily::Rdna4,
            gfx_major: 12,
            dcn_major: 4,
            sdma_major: 7,
            name: "AMD Radeon RX 9070 (Navi 48)",
            is_apu: false,
        },
        0x7551 => AmdGpuInfo {
            family: AmdFamily::Rdna4,
            gfx_major: 12,
            dcn_major: 4,
            sdma_major: 7,
            name: "AMD Radeon Navi 48",
            is_apu: false,
        },
        // RDNA 4 — Navi 44 (Radeon RX 9060 series, GFX12.0.0, DCN 4.0.1)
        0x7590 | 0x7591 => AmdGpuInfo {
            family: AmdFamily::Rdna4,
            gfx_major: 12,
            dcn_major: 4,
            sdma_major: 7,
            name: "AMD Radeon Navi 44 (RDNA 4)",
            is_apu: false,
        },
        // RDNA 3 — Navi 31/32/33 (Radeon RX 7900 / 7800 / 7700 / 7600, GFX11, DCN 3.2)
        0x744C | 0x7448 => AmdGpuInfo {
            family: AmdFamily::Rdna3,
            gfx_major: 11,
            dcn_major: 3,
            sdma_major: 6,
            name: "AMD Radeon RX 7900 (Navi 31)",
            is_apu: false,
        },
        0x747E | 0x7470 => AmdGpuInfo {
            family: AmdFamily::Rdna3,
            gfx_major: 11,
            dcn_major: 3,
            sdma_major: 6,
            name: "AMD Radeon RX 7800/7700 (Navi 32)",
            is_apu: false,
        },
        0x7480 | 0x7483 | 0x7489 => AmdGpuInfo {
            family: AmdFamily::Rdna3,
            gfx_major: 11,
            dcn_major: 3,
            sdma_major: 6,
            name: "AMD Radeon RX 7600 (Navi 33)",
            is_apu: false,
        },
        // RDNA 2 — Navi 21/22/23/24 (Radeon RX 6000, GFX10.3, DCN 3.0)
        0x73BF | 0x73A5 => AmdGpuInfo {
            family: AmdFamily::Rdna2,
            gfx_major: 10,
            dcn_major: 3,
            sdma_major: 5,
            name: "AMD Radeon RX 6800/6900 (Navi 21)",
            is_apu: false,
        },
        0x73DF => AmdGpuInfo {
            family: AmdFamily::Rdna2,
            gfx_major: 10,
            dcn_major: 3,
            sdma_major: 5,
            name: "AMD Radeon RX 6700 (Navi 22)",
            is_apu: false,
        },
        0x73FF | 0x73EF => AmdGpuInfo {
            family: AmdFamily::Rdna2,
            gfx_major: 10,
            dcn_major: 3,
            sdma_major: 5,
            name: "AMD Radeon RX 6600 (Navi 23)",
            is_apu: false,
        },
        0x743F => AmdGpuInfo {
            family: AmdFamily::Rdna2,
            gfx_major: 10,
            dcn_major: 3,
            sdma_major: 5,
            name: "AMD Radeon RX 6500/6400 (Navi 24)",
            is_apu: false,
        },
        // Ryzen 7000 / 9000 Desktop iGPU (Raphael / Granite Ridge, RDNA 2, DCN 3.1.5)
        0x164E | 0x13C0 => AmdGpuInfo {
            family: AmdFamily::Rdna2,
            gfx_major: 10,
            dcn_major: 3,
            sdma_major: 5,
            name: "AMD Ryzen iGPU (RDNA 2)",
            is_apu: true,
        },
        // Ryzen Mobile RDNA 3 / 3.5 iGPU (Phoenix / Hawk Point / Strix)
        0x15BF | 0x15C8 | 0x150E => AmdGpuInfo {
            family: AmdFamily::Rdna3,
            gfx_major: 11,
            dcn_major: 3,
            sdma_major: 6,
            name: "AMD Ryzen iGPU (RDNA 3)",
            is_apu: true,
        },
        _ => AmdGpuInfo {
            family: AmdFamily::Unknown,
            gfx_major: 10,
            dcn_major: 3,
            sdma_major: 5,
            name: "AMD Radeon GPU",
            is_apu: false,
        },
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
/// Alternate `NBIF_RCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE` dword offset on NBIF 6.3.1 / 7.x parts.
pub const REG_RCC_CONFIG_MEMSIZE_ALT: u64 = 0x0DC3 * 4;
/// NBIF 6.3.1 `RCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE` (BASE_IDX 2, dword `0x00C3`).
pub const NBIF631_RCC_CONFIG_MEMSIZE_OFF: u32 = 0x00C3;

// ---- AMD IP Discovery Binary Format (from AMD MIT `discovery.h` & `soc15_hw_ip.h`) --------------

/// Default IP Discovery binary offset from top of VRAM (`VRAM_SIZE - 64 KiB`).
pub const IP_DISCOVERY_OFFSET_FROM_TOP: u64 = 64 * 1024;
/// Maximum IP Discovery binary size (64 KiB).
pub const IP_DISCOVERY_MAX_SIZE: usize = 64 * 1024;
/// `BINARY_SIGNATURE` at offset 0 of `struct binary_header`.
pub const IP_DISCOVERY_BINARY_SIG: u32 = 0x2821_1407;
/// `DISCOVERY_TABLE_SIGNATURE` (`"IPDS"` little-endian) at offset 0 of `struct ip_discovery_header`.
pub const IP_DISCOVERY_TABLE_SIG: u32 = 0x5344_5049;

/// Table indices in `binary_header.table_list[]`.
pub const TABLE_IP_DISCOVERY: usize = 0;
pub const TABLE_GC: usize = 1;
pub const TABLE_HARVEST_INFO: usize = 2;
pub const TABLE_VCN_INFO: usize = 3;
pub const TABLE_MALL_INFO: usize = 4;
pub const TABLE_NPS_INFO: usize = 5;
pub const TABLE_MEM_RESERVED_INFO: usize = 6;

// Official AMD IP Hardware IDs (`soc15_hw_ip.h`).
pub const HWID_MP1: u16 = 1;
pub const HWID_GC: u16 = 11;
pub const HWID_VCN: u16 = 12;
pub const HWID_DCI: u16 = 15;
pub const HWID_MMHUB: u16 = 34;
pub const HWID_ATHUB: u16 = 35;
pub const HWID_OSSSYS: u16 = 40;
pub const HWID_HDP: u16 = 41;
pub const HWID_SDMA0: u16 = 42;
pub const HWID_SDMA1: u16 = 43;
pub const HWID_NBIO: u16 = 108; // NBIF_HWID
pub const HWID_MP0: u16 = 255;
pub const HWID_DCE: u16 = 271; // DMU_HWID (DCN display engine)
pub const HWID_DIO: u16 = 272;

pub const MAX_IP_BASES: usize = 8;
pub const MAX_IP_BLOCKS: usize = 64;
pub const MAX_RESERVED_REGIONS: usize = 8;

/// One parsed IP block from AMD IP Discovery with all its MMIO register segment bases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpBlock {
    pub hw_id: u16,
    pub instance: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u8,
    pub num_bases: u8,
    /// Register segment bases in dwords from BAR 5 RMMIO (`BASE_IDX` indexes this array).
    pub bases: [u32; MAX_IP_BASES],
}

impl IpBlock {
    /// Segment base in dwords for `base_idx`.
    #[inline]
    pub const fn base(&self, base_idx: usize) -> Option<u32> {
        if base_idx < self.num_bases as usize && base_idx < MAX_IP_BASES {
            Some(self.bases[base_idx])
        } else {
            None
        }
    }

    /// Compute the BAR 5 RMMIO byte offset for register `(base_idx, offset_dword)`.
    #[inline]
    pub const fn reg_byte(&self, base_idx: usize, offset_dword: u32) -> Option<u64> {
        let Some(base) = self.base(base_idx) else {
            return None;
        };
        let Some(dw) = base.checked_add(offset_dword) else {
            return None;
        };
        Some((dw as u64) * 4)
    }
}

/// One firmware-reserved VRAM region from `MEM_RESERVED_INFO` (must never be overwritten by scanout).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReservedMemRegion {
    pub offset: u64,
    pub size: u64,
}

/// Summary of discovered AMD IP blocks and reserved VRAM regions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoverySummary {
    pub version_major: u16,
    pub version_minor: u16,
    pub blocks: [IpBlock; MAX_IP_BLOCKS],
    pub count: usize,
    pub reserved: [ReservedMemRegion; MAX_RESERVED_REGIONS],
    pub reserved_count: usize,
}

impl Default for DiscoverySummary {
    fn default() -> Self {
        Self {
            version_major: 0,
            version_minor: 0,
            blocks: [IpBlock::default(); MAX_IP_BLOCKS],
            count: 0,
            reserved: [ReservedMemRegion::default(); MAX_RESERVED_REGIONS],
            reserved_count: 0,
        }
    }
}

impl DiscoverySummary {
    pub fn find(&self, hw_id: u16, instance: u8) -> Option<IpBlock> {
        self.blocks[..self.count]
            .iter()
            .copied()
            .find(|b| b.hw_id == hw_id && b.instance == instance)
    }

    pub fn find_first(&self, hw_id: u16) -> Option<IpBlock> {
        self.blocks[..self.count]
            .iter()
            .copied()
            .find(|b| b.hw_id == hw_id)
    }

    pub fn blocks(&self) -> &[IpBlock] {
        &self.blocks[..self.count]
    }

    pub fn reserved(&self) -> &[ReservedMemRegion] {
        &self.reserved[..self.reserved_count]
    }

    /// Determine the DCN register-table version from the discovered `HWID_DCE` (`DMU_HWID`) block.
    pub fn dcn_version(&self) -> Option<dcn::DcnVersion> {
        let b = self.find(HWID_DCE, 0).or_else(|| self.find_first(HWID_DCE))?;
        dcn::DcnVersion::from_ip(b.major, b.minor, b.revision)
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
///
/// Follows AMD's `struct binary_header` + `struct ip_discovery_header` layout:
/// - `binary_header`: `sig@0(u32)`, `ver_maj@4(u16)`, `ver_min@6(u16)`, `checksum@8(u16)`,
///   `binary_size@10(u16)`, followed by `table_list[]` at offset 12 (v1) or 16 (v2, after `num_tables@12`).
/// - Binary checksum covers `raw[10..binary_size]` (from `binary_size` field to end of binary).
/// - `ip_discovery_header`: `sig@0(u32) == 0x53445049 ("IPDS")`, `ver@4(u16)`, `size@6(u16)`,
///   `id@8(u32)`, `num_dies@12(u16)`, `die_info[16]@14` (4 bytes each), `flags@78` (`bit 0 = 64-bit bases`).
pub fn parse_ip_discovery(raw: &[u8]) -> Result<DiscoverySummary, DiscoveryError> {
    if raw.len() < 48 {
        return Err(DiscoveryError::TooShort);
    }
    let sig = rd_u32(raw, 0).ok_or(DiscoveryError::TooShort)?;
    if sig != IP_DISCOVERY_BINARY_SIG {
        return Err(DiscoveryError::BadSignature);
    }
    let version_major = rd_u16(raw, 4).ok_or(DiscoveryError::TooShort)?;
    let version_minor = rd_u16(raw, 6).ok_or(DiscoveryError::TooShort)?;
    let expected_csum = rd_u16(raw, 8).ok_or(DiscoveryError::TooShort)?;
    let bin_size = rd_u16(raw, 10).ok_or(DiscoveryError::TooShort)? as usize;
    if bin_size < 48 || bin_size > raw.len() {
        return Err(DiscoveryError::BadOffset);
    }
    // Checksum covers bytes starting immediately after `binary_checksum` (offset 10..bin_size).
    if discovery_checksum(&raw[10..bin_size]) != expected_csum {
        return Err(DiscoveryError::BadChecksum);
    }

    // Table list starts at offset 12 for v1, or offset 16 for v2 (preceded by `num_tables: u16, pad: u16`).
    let (tbl_list_off, num_tables) = if version_major >= 2 {
        let nt = usize::from(rd_u16(raw, 12).ok_or(DiscoveryError::TooShort)?).min(16);
        (16usize, nt.max(1))
    } else {
        (12usize, 8usize)
    };

    let read_table_info = |idx: usize| -> Option<(usize, u16, usize)> {
        if idx >= num_tables {
            return None;
        }
        let off = tbl_list_off.checked_add(idx * 8)?;
        let t_off = usize::from(rd_u16(raw, off)?);
        let t_csum = rd_u16(raw, off + 2)?;
        let t_size = usize::from(rd_u16(raw, off + 4)?);
        if t_off == 0 || t_size == 0 {
            return None;
        }
        Some((t_off, t_csum, t_size))
    };

    let (ip_off, ip_csum, ip_size) = read_table_info(TABLE_IP_DISCOVERY).ok_or(DiscoveryError::BadOffset)?;
    if ip_size < 18 || ip_off.checked_add(ip_size).is_none_or(|e| e > raw.len()) {
        return Err(DiscoveryError::BadOffset);
    }
    let ip_tbl = &raw[ip_off..ip_off + ip_size];
    if discovery_checksum(ip_tbl) != ip_csum {
        return Err(DiscoveryError::BadChecksum);
    }
    let tbl_sig = rd_u32(ip_tbl, 0).ok_or(DiscoveryError::TooShort)?;
    if tbl_sig != IP_DISCOVERY_TABLE_SIG {
        return Err(DiscoveryError::BadSignature);
    }
    let ip_ver = rd_u16(ip_tbl, 4).unwrap_or(0);
    let num_dies = usize::from(rd_u16(ip_tbl, 12).ok_or(DiscoveryError::TooShort)?);
    // `flags` field (`base_addr_64_bit`, bit 0) sits at byte offset 78 inside
    // `ip_discovery_header` starting with header version 4 (earlier versions keep padding there).
    let base_addr_64_bit = ip_ver >= 4 && ip_tbl.get(78).is_some_and(|&f| (f & 1) != 0);

    let mut summary = DiscoverySummary {
        version_major,
        version_minor,
        blocks: [IpBlock::default(); MAX_IP_BLOCKS],
        count: 0,
        reserved: [ReservedMemRegion::default(); MAX_RESERVED_REGIONS],
        reserved_count: 0,
    };

    // Walk `die_info[0..num_dies]` starting at offset 14 inside `ip_tbl` (4 bytes each).
    for d in 0..num_dies.min(16) {
        let entry_off = 14 + d * 4;
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
        for _ in 0..num_ips.min(256) {
            if cursor + 8 > raw.len() {
                break;
            }
            let hw_id = rd_u16(raw, cursor).unwrap_or(0);
            let instance = raw[cursor + 2];
            let num_bases = raw[cursor + 3] as usize;
            let major = raw[cursor + 4];
            let minor = raw[cursor + 5];
            let revision = raw[cursor + 6];
            let stride = if base_addr_64_bit { 8usize } else { 4usize };
            let rec_bytes = 8usize.saturating_add(num_bases.saturating_mul(stride));
            if cursor.checked_add(rec_bytes).is_none_or(|e| e > raw.len()) {
                break;
            }
            let wanted = matches!(
                hw_id,
                HWID_MP1
                    | HWID_GC
                    | HWID_VCN
                    | HWID_DCI
                    | HWID_MMHUB
                    | HWID_ATHUB
                    | HWID_OSSSYS
                    | HWID_HDP
                    | HWID_SDMA0
                    | HWID_SDMA1
                    | HWID_NBIO
                    | HWID_MP0
                    | HWID_DCE
                    | HWID_DIO
            );
            if wanted && summary.count < MAX_IP_BLOCKS {
                let mut bases = [0u32; MAX_IP_BASES];
                let stored = num_bases.min(MAX_IP_BASES);
                for (bi, slot) in bases.iter_mut().take(stored).enumerate() {
                    let b_off = cursor + 8 + bi * stride;
                    *slot = if base_addr_64_bit {
                        (rd_u64(raw, b_off).unwrap_or(0) & 0x3FFF_FFFF) as u32
                    } else {
                        rd_u32(raw, b_off).unwrap_or(0)
                    };
                }
                summary.blocks[summary.count] = IpBlock {
                    hw_id,
                    instance,
                    major,
                    minor,
                    revision,
                    num_bases: stored as u8,
                    bases,
                };
                summary.count += 1;
            }
            cursor += rec_bytes;
        }
    }

    // Optional Table 6: `MEM_RESERVED_INFO` (firmware-reserved VRAM regions to avoid).
    if let Some((r_off, r_csum, r_size)) = read_table_info(TABLE_MEM_RESERVED_INFO)
        && r_size >= 32
        && r_off.checked_add(r_size).is_some_and(|e| e <= raw.len())
    {
        let r_tbl = &raw[r_off..r_off + r_size];
        if discovery_checksum(r_tbl) == r_csum {
            // `gpu_info_header` is 32 bytes, followed by `reserved_mem_info` entries (16 bytes each:
            // offset_lo(u32), offset_hi(u32), size_lo(u32), size_hi(u32) — or offset(u64), size(u64)).
            let mut off = 32usize;
            while off + 16 <= r_tbl.len() && summary.reserved_count < MAX_RESERVED_REGIONS {
                let r_start = rd_u64(r_tbl, off).unwrap_or(0);
                let r_len = rd_u64(r_tbl, off + 8).unwrap_or(0);
                if r_len > 0 {
                    summary.reserved[summary.reserved_count] = ReservedMemRegion {
                        offset: r_start,
                        size: r_len,
                    };
                    summary.reserved_count += 1;
                }
                off += 16;
            }
        }
    }

    Ok(summary)
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

// ---- SDMA v5/v6/v7 Packet Encoder, GPU Composition Builder & Validator --------------------------

pub const SDMA_OP_NOP: u32 = 0;
pub const SDMA_OP_COPY: u32 = 1;
pub const SDMA_SUBOP_COPY_LINEAR: u32 = 0;
pub const SDMA_SUBOP_COPY_LINEAR_SUB_WINDOW: u32 = 4;
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

/// Encode an SDMA 2D linear sub-window copy packet (13 dwords) for hardware damage-rect composition
/// once SDMA/PSP firmware is active.
#[allow(clippy::too_many_arguments)]
pub fn sdma_copy_sub_window(
    out: &mut [u32],
    src_gpu: u64,
    src_pitch_px: u32,
    dst_gpu: u64,
    dst_pitch_px: u32,
    rect: DamageRect,
) -> Option<usize> {
    if out.len() < 13
        || rect.is_empty()
        || src_pitch_px == 0
        || dst_pitch_px == 0
        || rect.x > 0x3FFF
        || rect.y > 0x3FFF
        || rect.w > 0x3FFF
        || rect.h > 0x3FFF
        || src_pitch_px > 0x4000
        || dst_pitch_px > 0x4000
    {
        return None;
    }
    // Header: op=COPY(1), subop=LINEAR_SUB_WINDOW(4), element_size=2 (4 bytes/pixel in bits 31:29).
    out[0] = SDMA_OP_COPY | (SDMA_SUBOP_COPY_LINEAR_SUB_WINDOW << 8) | (2 << 29);
    out[1] = src_gpu as u32;
    out[2] = (src_gpu >> 32) as u32;
    out[3] = (rect.x & 0x3FFF) | ((rect.y & 0x3FFF) << 16);
    out[4] = (src_pitch_px - 1) & 0x3FFF;
    out[5] = 0; // src slice pitch (2D)
    out[6] = dst_gpu as u32;
    out[7] = (dst_gpu >> 32) as u32;
    out[8] = (rect.x & 0x3FFF) | ((rect.y & 0x3FFF) << 16);
    out[9] = (dst_pitch_px - 1) & 0x3FFF;
    out[10] = 0; // dst slice pitch (2D)
    out[11] = ((rect.w - 1) & 0x3FFF) | (((rect.h - 1) & 0x3FFF) << 16);
    out[12] = 0; // depth = 1 (encoded as 0)
    Some(13)
}

/// Build an SDMA command sequence copying a list of damage rectangles from `src_gpu` into `dst_gpu`
/// followed by a completion fence at `fence_gpu`. Returns total dwords written.
#[allow(clippy::too_many_arguments)]
pub fn build_sdma_composite_rects(
    out: &mut [u32],
    src_gpu: u64,
    src_pitch_px: u32,
    dst_gpu: u64,
    dst_pitch_px: u32,
    width: u32,
    height: u32,
    rects: &[DamageRect],
    fence_gpu: u64,
    fence_seq: u32,
) -> Option<usize> {
    let mut pos = 0usize;
    for &r in rects {
        let Some(c) = r.clip(width, height) else {
            continue;
        };
        let n = sdma_copy_sub_window(&mut out[pos..], src_gpu, src_pitch_px, dst_gpu, dst_pitch_px, c)?;
        pos += n;
    }
    if pos == 0 {
        return None;
    }
    let f = sdma_fence(&mut out[pos..], fence_gpu, fence_seq)?;
    Some(pos + f)
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
            (SDMA_OP_COPY, SDMA_SUBOP_COPY_LINEAR) => 7,
            (SDMA_OP_COPY, SDMA_SUBOP_COPY_LINEAR_SUB_WINDOW) => 13,
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
