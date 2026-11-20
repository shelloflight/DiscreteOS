//! VirtIO-GPU 2D & 3D (VirGL) protocol encoders, decoders, and strict command validators
//! (VirtIO 1.2 specification §5.7).

use crate::{CsError, rd_u32, rd_u64, wr_u32, wr_u64};

// Feature bits.
pub const F_VIRGL: u64 = 1 << 0;
pub const F_EDID: u64 = 1 << 1;
pub const F_RESOURCE_UUID: u64 = 1 << 2;
pub const F_RESOURCE_BLOB: u64 = 1 << 3;

// Control header size.
pub const CTRL_HDR_SIZE: usize = 24;
pub const MAX_SCANOUTS: usize = 16;

// 2D commands.
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const CMD_GET_CAPSET_INFO: u32 = 0x0108;
pub const CMD_GET_CAPSET: u32 = 0x0109;
pub const CMD_GET_EDID: u32 = 0x010A;

// 3D (VirGL) commands.
pub const CMD_CTX_CREATE: u32 = 0x0200;
pub const CMD_CTX_DESTROY: u32 = 0x0201;
pub const CMD_CTX_ATTACH_RESOURCE: u32 = 0x0202;
pub const CMD_CTX_DETACH_RESOURCE: u32 = 0x0203;
pub const CMD_RESOURCE_CREATE_3D: u32 = 0x0204;
pub const CMD_TRANSFER_TO_HOST_3D: u32 = 0x0205;
pub const CMD_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
pub const CMD_SUBMIT_3D: u32 = 0x0207;

// Cursor commands (cursorq).
pub const CMD_UPDATE_CURSOR: u32 = 0x0300;
pub const CMD_MOVE_CURSOR: u32 = 0x0301;

// Success responses.
pub const RESP_OK_NODATA: u32 = 0x1100;
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const RESP_OK_CAPSET_INFO: u32 = 0x1102;
pub const RESP_OK_CAPSET: u32 = 0x1103;
pub const RESP_OK_EDID: u32 = 0x1104;

// Error responses.
pub const RESP_ERR_UNSPEC: u32 = 0x1200;
pub const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

// Formats.
pub const FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const FORMAT_R8G8B8A8_UNORM: u32 = 67;
pub const FORMAT_R8G8B8X8_UNORM: u32 = 68;

// Capset IDs.
pub const CAPSET_VIRGL: u32 = 1;
pub const CAPSET_VIRGL2: u32 = 2;

// Flags.
pub const FLAG_FENCE: u32 = 1 << 0;

/// Common 24-byte control header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CtrlHdr {
    pub ty: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
}

impl CtrlHdr {
    pub const fn new(ty: u32) -> Self {
        Self { ty, flags: 0, fence_id: 0, ctx_id: 0, ring_idx: 0 }
    }

    pub const fn with_ctx(ty: u32, ctx_id: u32) -> Self {
        Self { ty, flags: 0, fence_id: 0, ctx_id, ring_idx: 0 }
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < CTRL_HDR_SIZE {
            return None;
        }
        wr_u32(out, 0, self.ty);
        wr_u32(out, 4, self.flags);
        wr_u64(out, 8, self.fence_id);
        wr_u32(out, 16, self.ctx_id);
        out[20] = self.ring_idx;
        out[21] = 0;
        out[22] = 0;
        out[23] = 0;
        Some(CTRL_HDR_SIZE)
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < CTRL_HDR_SIZE {
            return None;
        }
        Some(Self {
            ty: rd_u32(b, 0)?,
            flags: rd_u32(b, 4)?,
            fence_id: rd_u64(b, 8)?,
            ctx_id: rd_u32(b, 16)?,
            ring_idx: b[20],
        })
    }
}

/// One VirtIO-GPU scanout descriptor (`virtio_gpu_display_one`, 24 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayOne {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub enabled: bool,
    pub flags: u32,
}

/// Parsed `RESP_OK_DISPLAY_INFO`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayInfoResp {
    pub pmodes: [DisplayOne; MAX_SCANOUTS],
}

pub const RESP_DISPLAY_INFO_SIZE: usize = CTRL_HDR_SIZE + MAX_SCANOUTS * 24;

pub fn decode_display_info(b: &[u8]) -> Option<DisplayInfoResp> {
    let hdr = CtrlHdr::decode(b)?;
    if hdr.ty != RESP_OK_DISPLAY_INFO || b.len() < RESP_DISPLAY_INFO_SIZE {
        return None;
    }
    let mut pmodes = [DisplayOne::default(); MAX_SCANOUTS];
    for (i, slot) in pmodes.iter_mut().enumerate() {
        let o = CTRL_HDR_SIZE + i * 24;
        *slot = DisplayOne {
            x: rd_u32(b, o)?,
            y: rd_u32(b, o + 4)?,
            width: rd_u32(b, o + 8)?,
            height: rd_u32(b, o + 12)?,
            enabled: rd_u32(b, o + 16)? != 0,
            flags: rd_u32(b, o + 20)?,
        };
    }
    Some(DisplayInfoResp { pmodes })
}

/// Encode `CMD_GET_DISPLAY_INFO` (24 bytes).
pub fn encode_get_display_info(out: &mut [u8]) -> Option<usize> {
    CtrlHdr::new(CMD_GET_DISPLAY_INFO).encode(out)
}

/// Encode `CMD_GET_EDID` (32 bytes).
pub fn encode_get_edid(out: &mut [u8], scanout: u32) -> Option<usize> {
    if out.len() < 32 {
        return None;
    }
    CtrlHdr::new(CMD_GET_EDID).encode(out)?;
    wr_u32(out, 24, scanout);
    wr_u32(out, 28, 0);
    Some(32)
}

/// Decode `RESP_OK_EDID` (24 hdr + 4 size + 4 pad + up to 1024 bytes): returns the valid EDID slice.
pub fn decode_edid_resp(b: &[u8]) -> Option<&[u8]> {
    let hdr = CtrlHdr::decode(b)?;
    if hdr.ty != RESP_OK_EDID || b.len() < 32 {
        return None;
    }
    let size = rd_u32(b, 24)? as usize;
    if size > 1024 || 32 + size > b.len() {
        return None;
    }
    Some(&b[32..32 + size])
}

/// Encode `CMD_RESOURCE_CREATE_2D` (40 bytes).
pub fn encode_resource_create_2d(out: &mut [u8], res_id: u32, format: u32, width: u32, height: u32) -> Option<usize> {
    if out.len() < 40 {
        return None;
    }
    CtrlHdr::new(CMD_RESOURCE_CREATE_2D).encode(out)?;
    wr_u32(out, 24, res_id);
    wr_u32(out, 28, format);
    wr_u32(out, 32, width);
    wr_u32(out, 36, height);
    Some(40)
}

/// Encode `CMD_RESOURCE_UNREF` (32 bytes).
pub fn encode_resource_unref(out: &mut [u8], res_id: u32) -> Option<usize> {
    if out.len() < 32 {
        return None;
    }
    CtrlHdr::new(CMD_RESOURCE_UNREF).encode(out)?;
    wr_u32(out, 24, res_id);
    wr_u32(out, 28, 0);
    Some(32)
}

/// Encode `CMD_RESOURCE_DETACH_BACKING` (32 bytes).
pub fn encode_resource_detach_backing(out: &mut [u8], res_id: u32) -> Option<usize> {
    if out.len() < 32 {
        return None;
    }
    CtrlHdr::new(CMD_RESOURCE_DETACH_BACKING).encode(out)?;
    wr_u32(out, 24, res_id);
    wr_u32(out, 28, 0);
    Some(32)
}

/// Encode `CMD_RESOURCE_ATTACH_BACKING` header (32 bytes) followed by `entries` of `(addr, len)`.
pub fn encode_resource_attach_backing(out: &mut [u8], res_id: u32, entries: &[(u64, u32)]) -> Option<usize> {
    let need = 32usize.checked_add(entries.len().checked_mul(16)?)?;
    if out.len() < need {
        return None;
    }
    CtrlHdr::new(CMD_RESOURCE_ATTACH_BACKING).encode(out)?;
    wr_u32(out, 24, res_id);
    wr_u32(out, 28, entries.len() as u32);
    for (i, &(addr, len)) in entries.iter().enumerate() {
        let o = 32 + i * 16;
        wr_u64(out, o, addr);
        wr_u32(out, o + 8, len);
        wr_u32(out, o + 12, 0);
    }
    Some(need)
}

/// Encode `CMD_SET_SCANOUT` (48 bytes).
pub fn encode_set_scanout(out: &mut [u8], x: u32, y: u32, w: u32, h: u32, scanout_id: u32, res_id: u32) -> Option<usize> {
    if out.len() < 48 {
        return None;
    }
    CtrlHdr::new(CMD_SET_SCANOUT).encode(out)?;
    wr_u32(out, 24, x);
    wr_u32(out, 28, y);
    wr_u32(out, 32, w);
    wr_u32(out, 36, h);
    wr_u32(out, 40, scanout_id);
    wr_u32(out, 44, res_id);
    Some(48)
}

/// Encode `CMD_TRANSFER_TO_HOST_2D` (56 bytes).
pub fn encode_transfer_to_host_2d(
    out: &mut [u8],
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    offset: u64,
    res_id: u32,
) -> Option<usize> {
    if out.len() < 56 {
        return None;
    }
    CtrlHdr::new(CMD_TRANSFER_TO_HOST_2D).encode(out)?;
    wr_u32(out, 24, x);
    wr_u32(out, 28, y);
    wr_u32(out, 32, w);
    wr_u32(out, 36, h);
    wr_u64(out, 40, offset);
    wr_u32(out, 48, res_id);
    wr_u32(out, 52, 0);
    Some(56)
}

/// Encode `CMD_RESOURCE_FLUSH` (48 bytes).
pub fn encode_resource_flush(out: &mut [u8], x: u32, y: u32, w: u32, h: u32, res_id: u32) -> Option<usize> {
    if out.len() < 48 {
        return None;
    }
    CtrlHdr::new(CMD_RESOURCE_FLUSH).encode(out)?;
    wr_u32(out, 24, x);
    wr_u32(out, 28, y);
    wr_u32(out, 32, w);
    wr_u32(out, 36, h);
    wr_u32(out, 40, res_id);
    wr_u32(out, 44, 0);
    Some(48)
}

/// Encode `CMD_UPDATE_CURSOR` or `CMD_MOVE_CURSOR` (56 bytes).
#[allow(clippy::too_many_arguments)]
pub fn encode_cursor(
    out: &mut [u8],
    update: bool,
    scanout_id: u32,
    x: u32,
    y: u32,
    res_id: u32,
    hot_x: u32,
    hot_y: u32,
) -> Option<usize> {
    if out.len() < 56 {
        return None;
    }
    CtrlHdr::new(if update { CMD_UPDATE_CURSOR } else { CMD_MOVE_CURSOR }).encode(out)?;
    wr_u32(out, 24, scanout_id);
    wr_u32(out, 28, x);
    wr_u32(out, 32, y);
    wr_u32(out, 36, 0);
    wr_u32(out, 40, res_id);
    wr_u32(out, 44, hot_x);
    wr_u32(out, 48, hot_y);
    wr_u32(out, 52, 0);
    Some(56)
}

/// Encode `CMD_GET_CAPSET_INFO` (32 bytes).
pub fn encode_get_capset_info(out: &mut [u8], capset_index: u32) -> Option<usize> {
    if out.len() < 32 {
        return None;
    }
    CtrlHdr::new(CMD_GET_CAPSET_INFO).encode(out)?;
    wr_u32(out, 24, capset_index);
    wr_u32(out, 28, 0);
    Some(32)
}

/// Parsed `RESP_OK_CAPSET_INFO`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapsetInfoResp {
    pub capset_id: u32,
    pub capset_max_version: u32,
    pub capset_max_size: u32,
}

pub fn decode_capset_info(b: &[u8]) -> Option<CapsetInfoResp> {
    let hdr = CtrlHdr::decode(b)?;
    if hdr.ty != RESP_OK_CAPSET_INFO || b.len() < 40 {
        return None;
    }
    Some(CapsetInfoResp {
        capset_id: rd_u32(b, 24)?,
        capset_max_version: rd_u32(b, 28)?,
        capset_max_size: rd_u32(b, 32)?,
    })
}

/// Encode `CMD_CTX_CREATE` (96 bytes).
pub fn encode_ctx_create(out: &mut [u8], ctx_id: u32, name: &[u8]) -> Option<usize> {
    if out.len() < 96 {
        return None;
    }
    CtrlHdr::with_ctx(CMD_CTX_CREATE, ctx_id).encode(out)?;
    let nlen = name.len().min(64);
    wr_u32(out, 24, nlen as u32);
    wr_u32(out, 28, 0); // context_init = 0
    out[32..96].fill(0);
    out[32..32 + nlen].copy_from_slice(&name[..nlen]);
    Some(96)
}

/// Encode `CMD_CTX_DESTROY` (24 bytes).
pub fn encode_ctx_destroy(out: &mut [u8], ctx_id: u32) -> Option<usize> {
    CtrlHdr::with_ctx(CMD_CTX_DESTROY, ctx_id).encode(out)
}

/// Encode `CMD_CTX_ATTACH_RESOURCE` / `CMD_CTX_DETACH_RESOURCE` (32 bytes).
pub fn encode_ctx_resource(out: &mut [u8], attach: bool, ctx_id: u32, res_id: u32) -> Option<usize> {
    if out.len() < 32 {
        return None;
    }
    let ty = if attach { CMD_CTX_ATTACH_RESOURCE } else { CMD_CTX_DETACH_RESOURCE };
    CtrlHdr::with_ctx(ty, ctx_id).encode(out)?;
    wr_u32(out, 24, res_id);
    wr_u32(out, 28, 0);
    Some(32)
}

/// Encode `CMD_SUBMIT_3D` header (32 bytes) followed by `cmd_bytes` (must be 4-byte aligned).
pub fn encode_submit_3d(out: &mut [u8], ctx_id: u32, cmd_bytes: &[u8]) -> Option<usize> {
    if !cmd_bytes.len().is_multiple_of(4) {
        return None;
    }
    let need = 32usize.checked_add(cmd_bytes.len())?;
    if out.len() < need {
        return None;
    }
    CtrlHdr::with_ctx(CMD_SUBMIT_3D, ctx_id).encode(out)?;
    wr_u32(out, 24, cmd_bytes.len() as u32);
    wr_u32(out, 28, 0);
    out[32..32 + cmd_bytes.len()].copy_from_slice(cmd_bytes);
    Some(need)
}

// ---- VirGL 3D command stream framing & strict validator -----------------------------------------

pub const VIRGL_CCMD_NOP: u32 = 0;
pub const VIRGL_CCMD_CREATE_OBJECT: u32 = 1;
pub const VIRGL_CCMD_BIND_OBJECT: u32 = 2;
pub const VIRGL_CCMD_DESTROY_OBJECT: u32 = 3;
pub const VIRGL_CCMD_SET_VIEWPORT_STATE: u32 = 4;
pub const VIRGL_CCMD_SET_FRAMEBUFFER_STATE: u32 = 5;
pub const VIRGL_CCMD_SET_VERTEX_BUFFERS: u32 = 6;
pub const VIRGL_CCMD_CLEAR: u32 = 7;
pub const VIRGL_CCMD_DRAW_VBO: u32 = 8;
pub const VIRGL_CCMD_RESOURCE_INLINE_WRITE: u32 = 9;
pub const VIRGL_CCMD_SET_SAMPLER_VIEWS: u32 = 10;
pub const VIRGL_CCMD_SET_INDEX_BUFFER: u32 = 11;
pub const VIRGL_CCMD_SET_CONSTANT_BUFFER: u32 = 12;
pub const VIRGL_CCMD_SET_STENCIL_REF: u32 = 13;
pub const VIRGL_CCMD_SET_BLEND_COLOR: u32 = 14;
pub const VIRGL_CCMD_SET_SCISSOR_STATE: u32 = 15;
pub const VIRGL_CCMD_BLIT: u32 = 16;
pub const VIRGL_CCMD_RESOURCE_COPY_REGION: u32 = 17;
pub const VIRGL_CCMD_SET_SUB_CTX: u32 = 34;
pub const VIRGL_CCMD_CREATE_SUB_CTX: u32 = 35;
pub const VIRGL_CCMD_DESTROY_SUB_CTX: u32 = 36;
pub const VIRGL_MAX_CS_BYTES: usize = 64 * 1024;

/// Build a VirGL packet header word: `(len_dwords << 16) | (obj_type << 8) | cmd`.
#[inline]
pub const fn virgl_hdr(cmd: u32, obj_type: u32, len_dwords: u32) -> u32 {
    ((len_dwords & 0xFFFF) << 16) | ((obj_type & 0xFF) << 8) | (cmd & 0xFF)
}

/// Build a VirGL `NOP` command (1 dword).
pub fn virgl_cmd_nop(out: &mut [u32]) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    out[0] = virgl_hdr(VIRGL_CCMD_NOP, 0, 0);
    Some(1)
}

/// Build a VirGL `CLEAR` command (9 dwords: header + buffers + 4 color floats + depth_lo/hi + stencil).
pub fn virgl_cmd_clear(out: &mut [u32], buffers: u32, rgba: [f32; 4], depth: f64, stencil: u32) -> Option<usize> {
    if out.len() < 9 {
        return None;
    }
    let d = depth.to_bits();
    out[0] = virgl_hdr(VIRGL_CCMD_CLEAR, 0, 8);
    out[1] = buffers;
    out[2] = rgba[0].to_bits();
    out[3] = rgba[1].to_bits();
    out[4] = rgba[2].to_bits();
    out[5] = rgba[3].to_bits();
    out[6] = d as u32;
    out[7] = (d >> 32) as u32;
    out[8] = stencil;
    Some(9)
}

/// Validate a raw VirGL command buffer before DMA submission.
/// Checks alignment, total size cap, per-packet length bounds, and known command opcodes.
pub fn validate_virgl_cs(bytes: &[u8]) -> Result<usize, CsError> {
    if bytes.is_empty() {
        return Err(CsError::Empty);
    }
    if bytes.len() > VIRGL_MAX_CS_BYTES {
        return Err(CsError::TooLarge);
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(CsError::Unaligned);
    }
    let mut off = 0usize;
    let mut packets = 0usize;
    while off < bytes.len() {
        let hdr = rd_u32(bytes, off).ok_or(CsError::Truncated)?;
        let cmd = hdr & 0xFF;
        let payload_dwords = (hdr >> 16) as usize;
        let pkt_bytes = 4usize.checked_add(payload_dwords.checked_mul(4).ok_or(CsError::TooLarge)?).ok_or(CsError::TooLarge)?;
        if off.checked_add(pkt_bytes).is_none_or(|e| e > bytes.len()) {
            return Err(CsError::Truncated);
        }
        match cmd {
            VIRGL_CCMD_NOP
            | VIRGL_CCMD_CREATE_OBJECT
            | VIRGL_CCMD_BIND_OBJECT
            | VIRGL_CCMD_DESTROY_OBJECT
            | VIRGL_CCMD_SET_VIEWPORT_STATE
            | VIRGL_CCMD_SET_FRAMEBUFFER_STATE
            | VIRGL_CCMD_SET_VERTEX_BUFFERS
            | VIRGL_CCMD_CLEAR
            | VIRGL_CCMD_DRAW_VBO
            | VIRGL_CCMD_RESOURCE_INLINE_WRITE
            | VIRGL_CCMD_SET_SAMPLER_VIEWS
            | VIRGL_CCMD_SET_INDEX_BUFFER
            | VIRGL_CCMD_SET_CONSTANT_BUFFER
            | VIRGL_CCMD_SET_STENCIL_REF
            | VIRGL_CCMD_SET_BLEND_COLOR
            | VIRGL_CCMD_SET_SCISSOR_STATE
            | VIRGL_CCMD_BLIT
            | VIRGL_CCMD_RESOURCE_COPY_REGION
            | VIRGL_CCMD_SET_SUB_CTX
            | VIRGL_CCMD_CREATE_SUB_CTX
            | VIRGL_CCMD_DESTROY_SUB_CTX => {}
            _ => return Err(CsError::UnknownOpcode),
        }
        if cmd == VIRGL_CCMD_CLEAR && payload_dwords != 8 {
            return Err(CsError::BadArgument);
        }
        off += pkt_bytes;
        packets += 1;
    }
    Ok(packets)
}
