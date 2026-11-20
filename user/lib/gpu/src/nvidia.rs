//! NVIDIA Open-GSP GPU core (pure safe Rust, `#![forbid(unsafe_code)]`).
//!
//! Targets NVIDIA's open GPU architecture (Turing TU10x, Ampere GA10x, Ada Lovelace AD10x,
//! Blackwell GB20x) where hardware initialization and modesetting are mediated by the
//! GPU System Processor (GSP-RM) over shared DMA RPC message queues, with BAR 1 WC VRAM
//! scanout baseline.

use crate::{CsError, rd_u32, wr_u32, wr_u64};

pub const VENDOR_NVIDIA: u16 = 0x10DE;

// Core BAR 0 MMIO offsets.
pub const NV_PMC_BOOT_0: u64 = 0x0000_0000;
pub const NV_PMC_BOOT_42: u64 = 0x0000_0A00;
pub const NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE: u64 = 0x0010_0CE0;
pub const NV_PGSP_BASE: u64 = 0x0011_0000;
pub const NV_PGSP_FALCON_MAILBOX0: u64 = NV_PGSP_BASE + 0x0040;
pub const NV_PGSP_FALCON_MAILBOX1: u64 = NV_PGSP_BASE + 0x0044;
pub const NV_PGSP_FALCON_CPUCTL: u64 = NV_PGSP_BASE + 0x0100;
pub const NV_PGSP_QUEUE_HEAD0: u64 = NV_PGSP_BASE + 0x0C00;
pub const NV_PGSP_QUEUE_TAIL0: u64 = NV_PGSP_BASE + 0x0C80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvidiaArch {
    Turing,
    Ampere,
    Ada,
    Blackwell,
    Legacy,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvidiaGpuInfo {
    pub arch: NvidiaArch,
    pub chipset: u16,
    pub gsp_capable: bool,
    pub name: &'static str,
}

/// Decode `NV_PMC_BOOT_0` (legacy/Turing/Ampere) and `NV_PMC_BOOT_42` (Ampere/Ada/Blackwell).
pub const fn decode_boot_regs(boot0: u32, boot42: u32) -> NvidiaGpuInfo {
    // On Turing+, BOOT_42 bits [28:20] hold architecture + implementation if non-zero.
    let raw_chip = if boot42 != 0 && boot42 != 0xFFFF_FFFF {
        ((boot42 >> 20) & 0x1FF) as u16
    } else if boot0 != 0 && boot0 != 0xFFFF_FFFF {
        ((boot0 >> 20) & 0x1FF) as u16
    } else {
        0
    };
    let arch_hi = raw_chip & 0x1F0;
    match arch_hi {
        0x160 => NvidiaGpuInfo { arch: NvidiaArch::Turing, chipset: raw_chip, gsp_capable: true, name: "NVIDIA Turing (Open GSP)" },
        0x170 => NvidiaGpuInfo { arch: NvidiaArch::Ampere, chipset: raw_chip, gsp_capable: true, name: "NVIDIA Ampere (Open GSP)" },
        0x190 => NvidiaGpuInfo { arch: NvidiaArch::Ada, chipset: raw_chip, gsp_capable: true, name: "NVIDIA Ada Lovelace (Open GSP)" },
        0x1B0 => NvidiaGpuInfo { arch: NvidiaArch::Blackwell, chipset: raw_chip, gsp_capable: true, name: "NVIDIA Blackwell (Open GSP)" },
        0x110..=0x150 => NvidiaGpuInfo { arch: NvidiaArch::Legacy, chipset: raw_chip, gsp_capable: false, name: "NVIDIA Pre-Turing GPU" },
        _ => NvidiaGpuInfo { arch: NvidiaArch::Unknown, chipset: raw_chip, gsp_capable: false, name: "NVIDIA GPU" },
    }
}

/// Decode `NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE` into VRAM size in MiB (Turing+).
pub const fn decode_local_memory_mib(reg: u32) -> u32 {
    if reg == 0 || reg == 0xFFFF_FFFF {
        return 0;
    }
    let lower_scale = reg & 0xF;
    let lower_mag = (reg >> 4) & 0x3F;
    let ecc = (reg >> 30) & 1;
    let shift = lower_scale.saturating_add(20);
    let shift = if shift > 48 { 48 } else { shift };
    let bytes = (lower_mag as u64) << shift;
    let adjusted = if ecc != 0 { bytes * 15 / 16 } else { bytes };
    (adjusted >> 20) as u32
}

// ---- Open-GSP RPC Queue Element Framing (40-byte header + payload) ------------------------------

pub const GSP_MSG_HDR_SIZE: usize = 40;
pub const GSP_RPC_HDR_SIZE: usize = 20;
pub const GSP_RPC_SIG: u32 = 0x4350_5256; // "VRPC"
pub const GSP_MAX_RPC_BYTES: usize = 16 * 1024;

// Selected Open-GSP RPC function numbers (from NVIDIA Open GPU Kernel Modules).
pub const NV_VGPU_MSG_FUNCTION_NOP: u32 = 0;
pub const NV_VGPU_MSG_FUNCTION_SET_GUEST_SYSTEM_INFO: u32 = 1;
pub const NV_VGPU_MSG_FUNCTION_ALLOC_ROOT: u32 = 2;
pub const NV_VGPU_MSG_FUNCTION_GSP_SET_SYSTEM_INFO: u32 = 72;
pub const NV_VGPU_MSG_FUNCTION_GSP_RM_CONTROL: u32 = 76;

/// Compute the 32-bit XOR checksum used by NVIDIA Open-GSP `GspMsgElement` framing.
pub fn gsp_checksum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let w = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        sum ^= w;
        i += 4;
    }
    if i < bytes.len() {
        let mut tail = [0u8; 4];
        let rem = bytes.len() - i;
        tail[..rem].copy_from_slice(&bytes[i..]);
        sum ^= u32::from_le_bytes(tail);
    }
    sum
}

/// Encode an Open-GSP queue element wrapping a `GspRpcMessage` into `out`.
pub fn encode_gsp_rpc(out: &mut [u8], seq: u32, function: u32, payload: &[u8]) -> Option<usize> {
    let rpc_len = GSP_RPC_HDR_SIZE.checked_add(payload.len())?;
    let total = GSP_MSG_HDR_SIZE.checked_add(rpc_len)?;
    if total > out.len() || total > GSP_MAX_RPC_BYTES {
        return None;
    }
    out[..total].fill(0);
    // Element header: [0..4] auth_tag, [4..8] seq, [8..12] elem_count, [12..16] pad,
    // [16..20] checksum (computed after fill), [20..24] rpc_len, [24..32] pad, [32..40] rpc_sig_pad.
    wr_u32(out, 4, seq);
    wr_u32(out, 8, 1);
    wr_u32(out, 20, rpc_len as u32);
    // RPC header at offset 40: [0..4] sig, [4..8] hdr_ver, [8..12] function, [12..16] length, [16..20] result.
    wr_u32(out, GSP_MSG_HDR_SIZE, GSP_RPC_SIG);
    wr_u32(out, GSP_MSG_HDR_SIZE + 4, 0x0003_0000);
    wr_u32(out, GSP_MSG_HDR_SIZE + 8, function);
    wr_u32(out, GSP_MSG_HDR_SIZE + 12, rpc_len as u32);
    wr_u32(out, GSP_MSG_HDR_SIZE + 16, 0);
    out[GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE..total].copy_from_slice(payload);
    // Zero checksum slot and compute XOR checksum over entire element.
    wr_u64(out, 16, 0);
    wr_u32(out, 20, rpc_len as u32);
    let csum = gsp_checksum(&out[..total]);
    wr_u32(out, 16, csum);
    Some(total)
}

/// Validate an Open-GSP RPC message element (used for both incoming GSP messages and outbound CS).
pub fn validate_gsp_rpc(bytes: &[u8]) -> Result<(u32, u32), CsError> {
    if bytes.is_empty() {
        return Err(CsError::Empty);
    }
    if bytes.len() > GSP_MAX_RPC_BYTES {
        return Err(CsError::TooLarge);
    }
    if bytes.len() < GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE {
        return Err(CsError::Truncated);
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(CsError::Unaligned);
    }
    // XOR of all words including the checksum word must equal 0.
    if gsp_checksum(bytes) != 0 {
        return Err(CsError::BadArgument);
    }
    let rpc_len = rd_u32(bytes, 20).ok_or(CsError::Truncated)? as usize;
    if rpc_len < GSP_RPC_HDR_SIZE || GSP_MSG_HDR_SIZE.checked_add(rpc_len) != Some(bytes.len()) {
        return Err(CsError::Truncated);
    }
    let sig = rd_u32(bytes, GSP_MSG_HDR_SIZE).ok_or(CsError::Truncated)?;
    if sig != GSP_RPC_SIG {
        return Err(CsError::BadArgument);
    }
    let func = rd_u32(bytes, GSP_MSG_HDR_SIZE + 8).ok_or(CsError::Truncated)?;
    let inner_len = rd_u32(bytes, GSP_MSG_HDR_SIZE + 12).ok_or(CsError::Truncated)? as usize;
    if inner_len != rpc_len {
        return Err(CsError::BadArgument);
    }
    let seq = rd_u32(bytes, 4).ok_or(CsError::Truncated)?;
    // Allowlist safe RPC functions for unprivileged submission.
    match func {
        NV_VGPU_MSG_FUNCTION_NOP
        | NV_VGPU_MSG_FUNCTION_SET_GUEST_SYSTEM_INFO
        | NV_VGPU_MSG_FUNCTION_ALLOC_ROOT
        | NV_VGPU_MSG_FUNCTION_GSP_SET_SYSTEM_INFO
        | NV_VGPU_MSG_FUNCTION_GSP_RM_CONTROL => Ok((seq, func)),
        _ => Err(CsError::UnknownOpcode),
    }
}
