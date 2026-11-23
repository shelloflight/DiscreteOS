//! Version-keyed AMD Display Core Next (DCN) register abstraction, MMHUB MC↔VRAM
//! translation, active multi-pipe probing, refresh measurement, and scanout VRAM allocation.
//!
//! All register tables (`dcn401`, `dcn315`, `dcn32`, `dcn30`) are transcribed from AMD's
//! MIT-licensed ASIC register headers; no shared guessed offsets are used.

use crate::PixelFormat;
use crate::amd::{DiscoverySummary, HWID_DCE, HWID_MMHUB, HWID_NBIO, HWID_OSSSYS, IpBlock, ReservedMemRegion};

/// Register address within an IP block: `(segment BASE_IDX, dword offset)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegAddr {
    pub base_idx: u8,
    pub off: u32,
}

impl RegAddr {
    pub const fn new(base_idx: u8, off: u32) -> Self {
        Self { base_idx, off }
    }
}

/// Abstract MMIO register I/O (implemented by `amdgpu.ddrv` over BAR 5 and by `sim::DcnSim` in tests).
pub trait RegIo {
    fn r32(&self, byte_off: u64) -> Option<u32>;
    fn w32(&mut self, byte_off: u64, val: u32);
}

/// Supported DCN hardware generations with verified per-generation register maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcnVersion {
    /// DCN 4.0.1 (RDNA 4 / Navi 48 RX 9070, Navi 44; `dcn_4_1_0` + `mmhub_4_1_0` + `osssys_7_0_0`).
    Dcn401,
    /// DCN 3.1.5 (Ryzen 7000/9000 Raphael/Granite Ridge iGPU; `dcn_3_1_5` + `mmhub_3_0_1` + `osssys_6_0_0`).
    Dcn315,
    /// DCN 3.2 / 3.2.1 (RDNA 3 / Navi 31/32/33 RX 7000; `dcn_3_2_0` + `mmhub_3_0_0` + `osssys_6_0_0`).
    Dcn32,
    /// DCN 3.0 / 3.0.1 / 3.0.2 (RDNA 2 / Navi 21/22/23/24 RX 6000; `dcn_3_0_0` + `mmhub_2_0_0` + `osssys_5_0_0`).
    Dcn30,
}

impl DcnVersion {
    /// Select the register table matching IP Discovery `(major, minor, revision)` for `HWID_DCE`.
    pub const fn from_ip(major: u8, minor: u8, _revision: u8) -> Option<Self> {
        match (major, minor) {
            (4, _) => Some(Self::Dcn401),
            (3, 1) => Some(Self::Dcn315),
            (3, 2) | (3, 5) => Some(Self::Dcn32),
            (3, 0) => Some(Self::Dcn30),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Dcn401 => "DCN 4.0.1",
            Self::Dcn315 => "DCN 3.1.5",
            Self::Dcn32 => "DCN 3.2",
            Self::Dcn30 => "DCN 3.0",
        }
    }

    pub const fn regs(self) -> &'static dyn DcnRegs {
        match self {
            Self::Dcn401 => &super::dcn401::DCN401,
            Self::Dcn315 => &super::dcn315::DCN315,
            Self::Dcn32 => &super::dcn32::DCN32,
            Self::Dcn30 => &super::dcn30::DCN30,
        }
    }
}

/// OSSSYS Interrupt Handler (IH) register offsets for a specific generation (5.0 / 6.0 / 7.0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IhRegMap {
    pub rb_cntl: RegAddr,
    pub rb_base: RegAddr,
    pub rb_base_hi: RegAddr,
    pub rb_rptr: RegAddr,
    pub rb_wptr: RegAddr,
    pub rb_wptr_addr_hi: RegAddr,
    pub rb_wptr_addr_lo: RegAddr,
    pub doorbell_rptr: RegAddr,
    pub ih_cntl: RegAddr,
    pub ih_chicken: RegAddr,
}

/// Version-keyed register map trait implemented per DCN generation (`dcn401`, `dcn315`, `dcn32`, `dcn30`).
pub trait DcnRegs: Sync {
    fn version(&self) -> DcnVersion;
    fn max_pipes(&self) -> u8;
    fn max_aux(&self) -> u8;

    // ---- HUBP / HUBPREQ / HUBPRET (primary surface, pitch, viewport, flip) ----
    fn hubp_surface_config(&self, pipe: u8) -> RegAddr;
    fn hubp_tiling_config(&self, pipe: u8) -> RegAddr;
    fn hubp_viewport_start(&self, pipe: u8) -> RegAddr;
    fn hubp_viewport_dim(&self, pipe: u8) -> RegAddr;
    fn hubp_cntl(&self, pipe: u8) -> RegAddr;
    fn hubp_surface_pitch(&self, pipe: u8) -> RegAddr;
    fn hubp_primary_addr(&self, pipe: u8) -> RegAddr;
    fn hubp_primary_addr_hi(&self, pipe: u8) -> RegAddr;
    fn hubp_surface_control(&self, pipe: u8) -> RegAddr;
    fn hubp_flip_control(&self, pipe: u8) -> RegAddr;
    fn hubp_flip_interrupt(&self, pipe: u8) -> RegAddr;
    fn hubp_earliest_inuse(&self, pipe: u8) -> RegAddr;
    fn hubp_earliest_inuse_hi(&self, pipe: u8) -> RegAddr;
    fn hubp_cursor_settings(&self, pipe: u8) -> RegAddr;
    fn hubp_ret_control(&self, pipe: u8) -> RegAddr;

    // ---- HUBP + DPP hardware cursor ----
    fn cursor_control(&self, pipe: u8) -> RegAddr;
    fn cursor_addr(&self, pipe: u8) -> RegAddr;
    fn cursor_addr_hi(&self, pipe: u8) -> RegAddr;
    fn cursor_size(&self, pipe: u8) -> RegAddr;
    fn cursor_position(&self, pipe: u8) -> RegAddr;
    fn cursor_hot_spot(&self, pipe: u8) -> RegAddr;
    fn cursor_dst_offset(&self, pipe: u8) -> RegAddr;
    fn cnvc_pixel_format(&self, pipe: u8) -> RegAddr;
    fn dpp_cursor_control(&self, pipe: u8) -> RegAddr;
    fn cm_hdr_mult(&self, pipe: u8) -> RegAddr;

    // ---- OTG timing, frame counter, status, VRR, vertical interrupt ----
    fn otg_h_total(&self, pipe: u8) -> RegAddr;
    fn otg_h_blank(&self, pipe: u8) -> RegAddr;
    fn otg_h_sync_a(&self, pipe: u8) -> RegAddr;
    fn otg_h_sync_a_cntl(&self, pipe: u8) -> RegAddr;
    fn otg_v_total(&self, pipe: u8) -> RegAddr;
    fn otg_v_total_min(&self, pipe: u8) -> RegAddr;
    fn otg_v_total_max(&self, pipe: u8) -> RegAddr;
    fn otg_v_total_control(&self, pipe: u8) -> RegAddr;
    fn otg_v_blank(&self, pipe: u8) -> RegAddr;
    fn otg_v_sync_a(&self, pipe: u8) -> RegAddr;
    fn otg_v_sync_a_cntl(&self, pipe: u8) -> RegAddr;
    fn otg_control(&self, pipe: u8) -> RegAddr;
    fn otg_status(&self, pipe: u8) -> RegAddr;
    fn otg_status_position(&self, pipe: u8) -> RegAddr;
    fn otg_status_frame_count(&self, pipe: u8) -> RegAddr;
    fn otg_double_buffer_control(&self, pipe: u8) -> RegAddr;
    fn otg_vert_int0_pos(&self, pipe: u8) -> RegAddr;
    fn otg_vert_int0_ctrl(&self, pipe: u8) -> RegAddr;
    fn otg_master_update_lock(&self, pipe: u8) -> RegAddr;

    // ---- DCCG pixel rate DTO (BASE_IDX 1) ----
    fn dccg_otg_pixel_rate_div(&self) -> Option<RegAddr>;
    fn dccg_otg_pixel_rate_cntl(&self, pipe: u8) -> RegAddr;
    fn dccg_dp_dto_phase(&self, pipe: u8) -> RegAddr;
    fn dccg_dp_dto_modulo(&self, pipe: u8) -> RegAddr;

    // ---- DP AUX engine ----
    fn aux_control(&self, aux: u8) -> RegAddr;
    fn aux_sw_control(&self, aux: u8) -> RegAddr;
    fn aux_arb_control(&self, aux: u8) -> RegAddr;
    fn aux_interrupt_control(&self, aux: u8) -> RegAddr;
    fn aux_sw_status(&self, aux: u8) -> RegAddr;
    fn aux_sw_data(&self, aux: u8) -> RegAddr;

    // ---- DIG / DP stream encoder / MSA / DSC ----
    fn dig_fe_cntl(&self, enc: u8) -> RegAddr;
    fn dig_be_en_cntl(&self, enc: u8) -> RegAddr;
    fn dp_pixel_format(&self, enc: u8) -> RegAddr;
    fn dp_msa_colorimetry(&self, enc: u8) -> RegAddr;
    fn dp_steer_fifo(&self, enc: u8) -> RegAddr;
    fn dp_msa_misc(&self, enc: u8) -> RegAddr;
    fn dp_vid_timing(&self, enc: u8) -> RegAddr;
    fn dp_vid_n(&self, enc: u8) -> RegAddr;
    fn dp_vid_m(&self, enc: u8) -> RegAddr;
    fn dp_msa_timing_param1(&self, enc: u8) -> RegAddr;
    fn dp_msa_timing_param2(&self, enc: u8) -> RegAddr;
    fn dp_msa_timing_param3(&self, enc: u8) -> RegAddr;
    fn dp_msa_timing_param4(&self, enc: u8) -> RegAddr;
    fn dsc_forward_config(&self, pipe: u8) -> Option<RegAddr>;
    fn dscc_config0(&self) -> Option<RegAddr>;
    fn dscc_pps_config(&self, idx: u8) -> Option<RegAddr>;

    // ---- MMHUB / OSSSYS IH / NBIF ----
    fn mmhub_fb_offset(&self) -> RegAddr;
    fn mmhub_fb_location_base(&self) -> RegAddr;
    fn mmhub_fb_location_top(&self) -> RegAddr;
    fn ih_regs(&self) -> IhRegMap;
    fn nbif_interrupt_cntl(&self) -> RegAddr;
    fn nbif_interrupt_cntl2(&self) -> RegAddr;
}

/// Resolved IP Discovery blocks + version-keyed register map for live register access.
#[derive(Clone, Copy)]
pub struct DcnAccess {
    pub version: DcnVersion,
    pub dcn: IpBlock,
    pub mmhub: Option<IpBlock>,
    pub osssys: Option<IpBlock>,
    pub nbif: Option<IpBlock>,
    pub regs: &'static dyn DcnRegs,
}

impl DcnAccess {
    /// Construct from a parsed IP Discovery table (using `fallback` only if IP version is unrecognized).
    pub fn from_discovery(disc: &DiscoverySummary, fallback: DcnVersion) -> Option<Self> {
        let dcn = disc.find(HWID_DCE, 0).or_else(|| disc.find_first(HWID_DCE))?;
        let version = DcnVersion::from_ip(dcn.major, dcn.minor, dcn.revision).unwrap_or(fallback);
        Some(Self {
            version,
            dcn,
            mmhub: disc.find(HWID_MMHUB, 0).or_else(|| disc.find_first(HWID_MMHUB)),
            osssys: disc.find(HWID_OSSSYS, 0).or_else(|| disc.find_first(HWID_OSSSYS)),
            nbif: disc.find(HWID_NBIO, 0).or_else(|| disc.find_first(HWID_NBIO)),
            regs: version.regs(),
        })
    }

    /// Construct directly from explicit IP blocks (useful in tests or pre-resolved setups).
    pub const fn new(
        version: DcnVersion,
        dcn: IpBlock,
        mmhub: Option<IpBlock>,
        osssys: Option<IpBlock>,
        nbif: Option<IpBlock>,
    ) -> Self {
        Self { version, dcn, mmhub, osssys, nbif, regs: version.regs() }
    }

    #[inline]
    pub fn r_dcn<I: RegIo>(&self, io: &I, reg: RegAddr) -> Option<u32> {
        let off = self.dcn.reg_byte(usize::from(reg.base_idx), reg.off)?;
        io.r32(off)
    }

    #[inline]
    pub fn w_dcn<I: RegIo>(&self, io: &mut I, reg: RegAddr, val: u32) -> bool {
        let Some(off) = self.dcn.reg_byte(usize::from(reg.base_idx), reg.off) else {
            return false;
        };
        io.w32(off, val);
        true
    }

    #[inline]
    pub fn r_mmhub<I: RegIo>(&self, io: &I, reg: RegAddr) -> Option<u32> {
        let off = self.mmhub?.reg_byte(usize::from(reg.base_idx), reg.off)?;
        io.r32(off)
    }

    #[inline]
    pub fn r_ih<I: RegIo>(&self, io: &I, reg: RegAddr) -> Option<u32> {
        let off = self.osssys?.reg_byte(usize::from(reg.base_idx), reg.off)?;
        io.r32(off)
    }

    #[inline]
    pub fn w_ih<I: RegIo>(&self, io: &mut I, reg: RegAddr, val: u32) -> bool {
        let Some(off) = self.osssys.and_then(|b| b.reg_byte(usize::from(reg.base_idx), reg.off)) else {
            return false;
        };
        io.w32(off, val);
        true
    }

    #[inline]
    pub fn r_nbif<I: RegIo>(&self, io: &I, reg: RegAddr) -> Option<u32> {
        let off = self.nbif?.reg_byte(usize::from(reg.base_idx), reg.off)?;
        io.r32(off)
    }

    #[inline]
    pub fn w_nbif<I: RegIo>(&self, io: &mut I, reg: RegAddr, val: u32) -> bool {
        let Some(off) = self.nbif.and_then(|b| b.reg_byte(usize::from(reg.base_idx), reg.off)) else {
            return false;
        };
        io.w32(off, val);
        true
    }
}

// ---- DCN Surface Address Encoding ---------------------------------------------------------------

/// Combine DCN primary surface low/high registers into a 64-bit MC address (256-byte aligned).
#[inline]
pub const fn decode_surface_addr(lo: u32, hi: u32) -> u64 {
    (lo as u64 & !0xFF) | ((hi as u64 & 0xFFFF) << 32)
}

/// Split a 256-byte-aligned 64-bit MC address into `(lo, hi)` HUBPREQ register values.
#[inline]
pub const fn encode_surface_addr(addr: u64) -> (u32, u32) {
    ((addr as u32) & !0xFF, ((addr >> 32) & 0xFFFF) as u32)
}

// ---- MMHUB Memory-Controller <-> VRAM Translation -----------------------------------------------

/// Live MMHUB VRAM address aperture read from `MMMC_VM_FB_LOCATION_{BASE,TOP}` and `MMMC_VM_FB_OFFSET`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FbWindow {
    /// Start of VRAM in GPU memory-controller (MC) address space (`BASE[23:0] << 24`).
    pub fb_base: u64,
    /// Inclusive top byte of VRAM in MC address space (`(TOP[23:0] << 24) | 0xFF_FFFF`).
    pub fb_top: u64,
    /// Physical offset programmed into `MMMC_VM_FB_OFFSET` (`OFFSET[23:0] << 24`, non-zero on APUs).
    pub mc_fb_offset: u64,
    /// Total VRAM size in bytes.
    pub vram_size: u64,
}

impl FbWindow {
    /// Read the MMHUB FB location window from hardware registers.
    pub fn read<I: RegIo>(io: &I, dcn: &DcnAccess, vram_size: u64) -> Option<Self> {
        let raw_base = dcn.r_mmhub(io, dcn.regs.mmhub_fb_location_base())?;
        let raw_top = dcn.r_mmhub(io, dcn.regs.mmhub_fb_location_top())?;
        let raw_off = dcn.r_mmhub(io, dcn.regs.mmhub_fb_offset()).unwrap_or(0);
        if raw_base == 0xFFFF_FFFF || raw_top == 0xFFFF_FFFF {
            return None;
        }
        let fb_base = u64::from(raw_base & 0x00FF_FFFF) << 24;
        let fb_top = (u64::from(raw_top & 0x00FF_FFFF) << 24) | 0x00FF_FFFF;
        if fb_top <= fb_base {
            return None;
        }
        let mc_fb_offset = u64::from(raw_off & 0x00FF_FFFF) << 24;
        let win_size = fb_top.saturating_sub(fb_base).saturating_add(1);
        let eff_vram = if vram_size > 0 { vram_size.min(win_size) } else { win_size };
        Some(Self { fb_base, fb_top, mc_fb_offset, vram_size: eff_vram })
    }

    /// Translate a DCN memory-controller (MC) scanout address into a BAR 0 VRAM byte offset.
    pub const fn mc_to_vram(&self, mc_addr: u64) -> Option<u64> {
        if mc_addr < self.fb_base || mc_addr > self.fb_top {
            return None;
        }
        let off = mc_addr - self.fb_base;
        if self.vram_size > 0 && off >= self.vram_size {
            return None;
        }
        Some(off)
    }

    /// Translate a BAR 0 VRAM byte offset into a GPU memory-controller (MC) address for HUBP scanout.
    pub const fn vram_to_mc(&self, vram_off: u64) -> Option<u64> {
        if self.vram_size > 0 && vram_off >= self.vram_size {
            return None;
        }
        let Some(mc) = self.fb_base.checked_add(vram_off) else {
            return None;
        };
        if mc > self.fb_top {
            return None;
        }
        Some(mc)
    }
}

/// Firmware UEFI GOP framebuffer metadata supplied by `gpu.dsvc` for exact display identity proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GopInfo {
    pub phys_base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

// ---- OTG Timing & Active Pipe Probing -----------------------------------------------------------

/// Active timing decoded directly from OTG registers (`dcn10_optc.c` conventions).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OtgTiming {
    pub h_active: u32,
    pub h_total: u32,
    pub h_blank_start: u32,
    pub h_blank_end: u32,
    pub h_front_porch: u32,
    pub h_sync_width: u32,
    pub h_sync_pos: bool,
    pub v_active: u32,
    pub v_total: u32,
    pub v_blank_start: u32,
    pub v_blank_end: u32,
    pub v_front_porch: u32,
    pub v_sync_width: u32,
    pub v_sync_pos: bool,
}

impl OtgTiming {
    pub fn read<I: RegIo>(io: &I, dcn: &DcnAccess, pipe: u8) -> Option<Self> {
        let r = dcn.regs;
        let h_tot_raw = dcn.r_dcn(io, r.otg_h_total(pipe))?;
        let h_blk = dcn.r_dcn(io, r.otg_h_blank(pipe))?;
        let h_sync = dcn.r_dcn(io, r.otg_h_sync_a(pipe))?;
        let h_sync_c = dcn.r_dcn(io, r.otg_h_sync_a_cntl(pipe))?;
        let v_tot_raw = dcn.r_dcn(io, r.otg_v_total(pipe))?;
        let v_blk = dcn.r_dcn(io, r.otg_v_blank(pipe))?;
        let v_sync = dcn.r_dcn(io, r.otg_v_sync_a(pipe))?;
        let v_sync_c = dcn.r_dcn(io, r.otg_v_sync_a_cntl(pipe))?;

        let h_total = (h_tot_raw & 0x7FFF).saturating_add(1);
        let v_total = (v_tot_raw & 0x7FFF).saturating_add(1);
        let h_blank_start = h_blk & 0x7FFF;
        let h_blank_end = (h_blk >> 16) & 0x7FFF;
        let v_blank_start = v_blk & 0x7FFF;
        let v_blank_end = (v_blk >> 16) & 0x7FFF;

        let h_active = h_blank_start.saturating_sub(h_blank_end);
        let v_active = v_blank_start.saturating_sub(v_blank_end);
        if h_active < 320 || v_active < 200 || h_total <= h_active || v_total <= v_active {
            return None;
        }

        let h_sync_start = h_sync & 0x7FFF;
        let h_sync_end = (h_sync >> 16) & 0x7FFF;
        let v_sync_start = v_sync & 0x7FFF;
        let v_sync_end = (v_sync >> 16) & 0x7FFF;

        Some(Self {
            h_active,
            h_total,
            h_blank_start,
            h_blank_end,
            h_front_porch: h_total.saturating_sub(h_blank_start),
            h_sync_width: h_sync_end.saturating_sub(h_sync_start),
            h_sync_pos: (h_sync_c & 1) == 0,
            v_active,
            v_total,
            v_blank_start,
            v_blank_end,
            v_front_porch: v_total.saturating_sub(v_blank_start),
            v_sync_width: v_sync_end.saturating_sub(v_sync_start),
            v_sync_pos: (v_sync_c & 1) == 0,
        })
    }

    /// Encode OTG blank/sync coordinates from a `DetailedTiming` (matching `dcn10_optc.c`).
    pub const fn from_detailed(t: &crate::edid::DetailedTiming) -> Self {
        let h_total = t.h_total();
        let v_total = t.v_total();
        let h_back = t.h_back_porch();
        let v_back = t.v_back_porch();
        let h_blank_end = t.h_sync_width.saturating_add(h_back);
        let h_blank_start = h_blank_end.saturating_add(t.h_active);
        let v_blank_end = t.v_sync_width.saturating_add(v_back);
        let v_blank_start = v_blank_end.saturating_add(t.v_active);
        Self {
            h_active: t.h_active,
            h_total,
            h_blank_start,
            h_blank_end,
            h_front_porch: t.h_front_porch,
            h_sync_width: t.h_sync_width,
            h_sync_pos: t.h_sync_pos,
            v_active: t.v_active,
            v_total,
            v_blank_start,
            v_blank_end,
            v_front_porch: t.v_front_porch,
            v_sync_width: t.v_sync_width,
            v_sync_pos: t.v_sync_pos,
        }
    }
}

/// DCN `DCSURF_SURFACE_CONFIG.SURFACE_PIXEL_FORMAT` codes (`dcn10_hubp.c`).
pub const DCN_FMT_ARGB8888: u32 = 8;
pub const DCN_FMT_ARGB2101010: u32 = 10;
pub const DCN_FMT_ARGB16161616F: u32 = 24;

/// Decoded live state of one active DCN display pipe (HUBP + OTG).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivePipe {
    pub pipe: u8,
    pub timing: OtgTiming,
    pub viewport_w: u32,
    pub viewport_h: u32,
    pub pitch_pixels: u32,
    pub pitch_bytes: u32,
    pub raw_format: u32,
    pub pixel_format: Option<PixelFormat>,
    pub bgr_swapped: bool,
    pub mc_addr: u64,
    pub earliest_inuse_mc: u64,
    pub vram_off: Option<u64>,
    pub flip_pending: bool,
    pub frame_count: u32,
    pub vrr_enabled: bool,
    pub gop_matched: bool,
}

impl ActivePipe {
    /// Width of the active scanout surface (viewport if set, otherwise OTG active width).
    pub const fn width(&self) -> u32 {
        if self.viewport_w >= 320 { self.viewport_w } else { self.timing.h_active }
    }

    /// Height of the active scanout surface (viewport if set, otherwise OTG active height).
    pub const fn height(&self) -> u32 {
        if self.viewport_h >= 200 { self.viewport_h } else { self.timing.v_active }
    }

    /// Verify that this pipe is scanning out the exact UEFI GOP framebuffer.
    pub fn check_gop_match(&self, bar0_phys: u64, gop: &GopInfo) -> bool {
        let Some(vram_off) = self.vram_off else {
            return false;
        };
        if gop.width == 0 || gop.height == 0 || gop.pitch == 0 {
            return false;
        }
        if self.width() != gop.width || self.height() != gop.height || self.pitch_bytes != gop.pitch {
            return false;
        }
        let fb_bytes = u64::from(self.pitch_bytes).saturating_mul(u64::from(self.height()));
        if fb_bytes == 0 || fb_bytes > gop.size {
            return false;
        }
        if bar0_phys != 0 && gop.phys_base != 0 {
            let Some(scanout_phys) = bar0_phys.checked_add(vram_off) else {
                return false;
            };
            scanout_phys == gop.phys_base
        } else {
            // Without physical BAR0 base (e.g. unit tests without BAR phys), match on size/pitch/dims.
            true
        }
    }
}

/// Probe all active DCN pipes (`OTG_MASTER_EN` set and `HUBP_BLANK_EN` clear).
/// Purely read-only: performs zero register writes.
pub fn probe_active_pipes<I: RegIo>(
    io: &I,
    dcn: &DcnAccess,
    fb_win: Option<FbWindow>,
    bar0_phys: u64,
    gop: Option<&GopInfo>,
    out: &mut [ActivePipe],
) -> usize {
    let r = dcn.regs;
    let mut found = 0usize;
    for pipe in 0..r.max_pipes() {
        if found >= out.len() {
            break;
        }
        let Some(otg_ctl) = dcn.r_dcn(io, r.otg_control(pipe)) else {
            continue;
        };
        if otg_ctl == 0xFFFF_FFFF {
            continue;
        }
        // OTG_MASTER_EN (bit 0) or OTG_CURRENT_MASTER_EN_STATE (bit 16).
        let otg_on = (otg_ctl & (1 | (1 << 16))) != 0;
        if !otg_on {
            continue;
        }
        let Some(hubp_ctl) = dcn.r_dcn(io, r.hubp_cntl(pipe)) else {
            continue;
        };
        // HUBP_BLANK_EN (bit 0): skip blanked pipes.
        if hubp_ctl == 0xFFFF_FFFF || (hubp_ctl & 1) != 0 {
            continue;
        }
        let Some(timing) = OtgTiming::read(io, dcn, pipe) else {
            continue;
        };
        let vp_dim = dcn.r_dcn(io, r.hubp_viewport_dim(pipe)).unwrap_or(0);
        let viewport_w = vp_dim & 0x3FFF;
        let viewport_h = (vp_dim >> 16) & 0x3FFF;

        let surf_cfg = dcn.r_dcn(io, r.hubp_surface_config(pipe)).unwrap_or(0);
        let raw_format = surf_cfg & 0x7F;
        let hubpret = dcn.r_dcn(io, r.hubp_ret_control(pipe)).unwrap_or(0);
        // CROSSBAR_SRC_CB_B [21:20] and CROSSBAR_SRC_CR_R [23:22]: swap (2/0) indicates ABGR/XBGR.
        let cr_r = (hubpret >> 22) & 0x3;
        let cb_b = (hubpret >> 20) & 0x3;
        let bgr_swapped = cr_r == 2 && cb_b == 0;
        let pixel_format = match raw_format {
            DCN_FMT_ARGB8888 => Some(if bgr_swapped { PixelFormat::Xbgr8888 } else { PixelFormat::Xrgb8888 }),
            DCN_FMT_ARGB2101010 => Some(PixelFormat::Argb2101010),
            _ => None,
        };
        let bpp = match raw_format {
            DCN_FMT_ARGB16161616F | 26 => 8u32,
            1 | 3 => 2u32,
            _ => 4u32,
        };

        let pitch_reg = dcn.r_dcn(io, r.hubp_surface_pitch(pipe)).unwrap_or(0);
        let pitch_pixels = (pitch_reg & 0x3FFF).saturating_add(1);
        let pitch_bytes = pitch_pixels.saturating_mul(bpp);

        let lo = dcn.r_dcn(io, r.hubp_primary_addr(pipe)).unwrap_or(0);
        let hi = dcn.r_dcn(io, r.hubp_primary_addr_hi(pipe)).unwrap_or(0);
        let mc_addr = decode_surface_addr(lo, hi);

        let e_lo = dcn.r_dcn(io, r.hubp_earliest_inuse(pipe)).unwrap_or(lo);
        let e_hi = dcn.r_dcn(io, r.hubp_earliest_inuse_hi(pipe)).unwrap_or(hi);
        let earliest_inuse_mc = decode_surface_addr(e_lo, e_hi);

        let flip_ctl = dcn.r_dcn(io, r.hubp_flip_control(pipe)).unwrap_or(0);
        let flip_pending = (flip_ctl & (1 << 8)) != 0;
        let frame_count = dcn.r_dcn(io, r.otg_status_frame_count(pipe)).unwrap_or(0) & 0x00FF_FFFF;
        let vtot_ctl = dcn.r_dcn(io, r.otg_v_total_control(pipe)).unwrap_or(0);
        let vrr_enabled = (vtot_ctl & 0x3) == 0x3;

        let active_mc = if earliest_inuse_mc != 0 { earliest_inuse_mc } else { mc_addr };
        let vram_off = fb_win.and_then(|w| w.mc_to_vram(active_mc));

        let mut ap = ActivePipe {
            pipe,
            timing,
            viewport_w,
            viewport_h,
            pitch_pixels,
            pitch_bytes,
            raw_format,
            pixel_format,
            bgr_swapped,
            mc_addr,
            earliest_inuse_mc,
            vram_off,
            flip_pending,
            frame_count,
            vrr_enabled,
            gop_matched: false,
        };
        if let Some(g) = gop {
            ap.gop_matched = ap.check_gop_match(bar0_phys, g);
        }
        out[found] = ap;
        found += 1;
    }
    found
}

/// Compute exact refresh rate in millihertz from an OTG frame-counter delta and elapsed nanoseconds.
pub const fn measure_refresh_mhz(delta_frames: u32, delta_ns: u64) -> Option<u32> {
    if delta_frames == 0 || delta_ns < 500_000 {
        return None;
    }
    let num = (delta_frames as u128) * 1_000_000_000_000u128;
    let mhz = num / (delta_ns as u128);
    if mhz < 20_000 || mhz > 1_000_000 {
        return None;
    }
    Some(mhz as u32)
}

/// Read live OTG 24-bit frame counter for `pipe`.
#[inline]
pub fn read_frame_count<I: RegIo>(io: &I, dcn: &DcnAccess, pipe: u8) -> u32 {
    dcn.r_dcn(io, dcn.regs.otg_status_frame_count(pipe)).unwrap_or(0) & 0x00FF_FFFF
}

/// Wrapping difference between two 24-bit OTG frame counter samples.
#[inline]
pub const fn frame_count_diff(now: u32, before: u32) -> u32 {
    now.wrapping_sub(before) & 0x00FF_FFFF
}

/// Locate the active DIG stream encoder fed by `pipe` (matching `DIG_ENABLE` and `DIG_SOURCE_SELECT`).
/// Falls back to `pipe` if no active DIG encoder explicitly selects `pipe`.
pub fn find_pipe_dig_encoder<I: RegIo>(io: &I, dcn: &DcnAccess, pipe: u8) -> u8 {
    let r = dcn.regs;
    for enc in 0..r.max_pipes() {
        let Some(be) = dcn.r_dcn(io, r.dig_be_en_cntl(enc)) else {
            continue;
        };
        if be == 0xFFFF_FFFF || (be & 1) == 0 {
            continue;
        }
        let Some(fe) = dcn.r_dcn(io, r.dig_fe_cntl(enc)) else {
            continue;
        };
        if (fe & 0xF) == u32::from(pipe) {
            return enc;
        }
    }
    pipe
}

/// Read-only scan of the DPP block for `pipe` (`cnvc_pixel_format..cm_hdr_mult`) to locate
/// active geometry registers (`DSCL_RECOUT_SIZE`, `DSCL_MPC_SIZE`) holding `(height << 16) | width`.
/// Returns `(reg_offsets, count)`; capped to `<= 4` matches so ambiguous patterns are ignored.
pub fn probe_pipe_dpp_size_regs<I: RegIo>(
    io: &I,
    dcn: &DcnAccess,
    pipe: u8,
    width: u32,
    height: u32,
) -> ([u32; 4], usize) {
    let mut out = [0u32; 4];
    if width < 320 || height < 200 || width > 0x3FFF || height > 0x3FFF {
        return (out, 0);
    }
    let target = (width & 0x3FFF) | ((height & 0x3FFF) << 16);
    let r = dcn.regs;
    let start = r.cnvc_pixel_format(pipe);
    let end = r.cm_hdr_mult(pipe);
    if start.base_idx != end.base_idx || end.off <= start.off + 1 || end.off - start.off > 512 {
        return (out, 0);
    }
    let mut n = 0usize;
    for off in (start.off + 1)..end.off {
        let reg = RegAddr::new(start.base_idx, off);
        if dcn.r_dcn(io, reg) == Some(target) {
            if n >= out.len() {
                return ([0; 4], 0);
            }
            out[n] = off;
            n += 1;
        }
    }
    (out, n)
}

// ---- Scanout + Cursor VRAM Allocator ------------------------------------------------------------

/// Top-of-VRAM safety margin (16 MiB) reserved for IP Discovery (-64 KiB), PSP TMR, and VBIOS tables.
pub const TOP_VRAM_RESERVE: u64 = 16 << 20;
/// Alignment for DCN scanout buffers (64 KiB — meets all DCN tiling/DCC/MC requirements).
pub const SCANOUT_ALIGN: u64 = 64 * 1024;
/// Space reserved for the hardware cursor surface (256x256x4 = 256 KiB, holds 64x64 or 256x256).
pub const CURSOR_VRAM_BYTES: u64 = 256 * 1024;

/// Allocated scanout and hardware-cursor VRAM layout adjacent to the firmware GOP framebuffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanoutLayout {
    /// Page-aligned BAR 0 VRAM offset to map Write-Combining.
    pub map_vram_off: u64,
    /// Page-aligned length of the Write-Combining BAR 0 mapping.
    pub map_len: u64,
    /// Original firmware GOP framebuffer VRAM offset (kept intact for instant hand-back).
    pub gop_vram_off: u64,
    /// Size of the firmware GOP framebuffer in bytes.
    pub gop_size: u64,
    /// VRAM offsets of the 2 or 3 native scanout buffers.
    pub buffers: [u64; 3],
    /// Number of allocated scanout buffers (2 or 3).
    pub buf_count: usize,
    /// Stride in bytes between scanout buffers (64 KiB aligned).
    pub buf_stride_bytes: u64,
    /// VRAM offset of the 64x64 / 256x256 ARGB hardware cursor image.
    pub cursor_vram_off: u64,
    /// Size of the cursor VRAM allocation (256 KiB).
    pub cursor_size_bytes: u64,
}

impl ScanoutLayout {
    /// Convert a BAR 0 VRAM offset inside our mapped WC window into a mapping-relative offset.
    #[inline]
    pub const fn to_map_off(&self, vram_off: u64) -> Option<u64> {
        if vram_off < self.map_vram_off {
            return None;
        }
        let rel = vram_off - self.map_vram_off;
        if rel >= self.map_len {
            return None;
        }
        Some(rel)
    }

    /// True if `vram_off` matches one of our allocated scanout buffers (used for crash-recovery detection).
    pub fn is_own_scanout_buffer(&self, vram_off: u64) -> bool {
        self.buffers[..self.buf_count].contains(&vram_off)
    }
}

const fn align_up(v: u64, align: u64) -> u64 {
    let mask = align - 1;
    v.saturating_add(mask) & !mask
}

const fn align_down(v: u64, align: u64) -> u64 {
    v & !(align - 1)
}

fn overlaps_any(start: u64, len: u64, gop_start: u64, gop_len: u64, reserved: &[ReservedMemRegion]) -> bool {
    let Some(end) = start.checked_add(len) else {
        return true;
    };
    let gop_end = gop_start.saturating_add(gop_len);
    if gop_len > 0 && start < gop_end && gop_start < end {
        return true;
    }
    for r in reserved {
        if r.size == 0 {
            continue;
        }
        let r_end = r.offset.saturating_add(r.size);
        if start < r_end && r.offset < end {
            return true;
        }
    }
    false
}

/// Allocate 3 (or fallback 2) scanout buffers + 256 KiB cursor surface in visible BAR 0 VRAM
/// adjacent to the firmware GOP framebuffer, strictly avoiding the GOP FB itself, top-of-VRAM
/// firmware regions (IP Discovery, PSP TMR), and any `MEM_RESERVED_INFO` regions.
#[allow(clippy::too_many_arguments)]
pub fn allocate_scanout_buffers(
    gop_vram_off: u64,
    gop_size: u64,
    pitch_bytes: u32,
    height: u32,
    bar0_size: u64,
    vram_size: u64,
    reserved: &[ReservedMemRegion],
    prefer_triple: bool,
) -> Option<ScanoutLayout> {
    let fb_bytes = u64::from(pitch_bytes).checked_mul(u64::from(height))?;
    if fb_bytes == 0 || bar0_size == 0 {
        return None;
    }
    let buf_stride = align_up(fb_bytes, SCANOUT_ALIGN);
    let gop_span = align_up(gop_size.max(fb_bytes), SCANOUT_ALIGN);

    // Safe upper bound: must stay inside CPU-visible BAR 0 and below top-of-VRAM reserved area.
    let top_limit = if vram_size > TOP_VRAM_RESERVE {
        vram_size - TOP_VRAM_RESERVE
    } else {
        vram_size.saturating_sub(64 * 1024)
    };
    let safe_top = bar0_size.min(if top_limit > 0 { top_limit } else { bar0_size });

    let try_counts: [usize; 2] = if prefer_triple { [3, 2] } else { [2, 2] };

    for &cnt in &try_counts {
        let total_needed = buf_stride.checked_mul(cnt as u64)?.checked_add(CURSOR_VRAM_BYTES)?;
        // Candidate 1: immediately after the firmware GOP framebuffer, stepping past any overlapping
        // firmware-reserved regions (`MEM_RESERVED_INFO`).
        let mut after_gop = align_up(gop_vram_off.saturating_add(gop_span), SCANOUT_ALIGN);
        for _ in 0..=reserved.len() {
            let mut bumped = false;
            let end = after_gop.saturating_add(total_needed);
            for r in reserved {
                if r.size == 0 {
                    continue;
                }
                let r_end = r.offset.saturating_add(r.size);
                if after_gop < r_end && r.offset < end {
                    after_gop = align_up(r_end, SCANOUT_ALIGN);
                    bumped = true;
                    break;
                }
            }
            if !bumped {
                break;
            }
        }
        // Candidate 2: immediately before the firmware GOP framebuffer if GOP is placed high in BAR 0.
        let before_gop = if gop_vram_off >= total_needed + SCANOUT_ALIGN {
            Some(align_down(gop_vram_off - total_needed, SCANOUT_ALIGN))
        } else {
            None
        };

        let candidates = [Some(after_gop), before_gop, Some(SCANOUT_ALIGN)];
        for cand in candidates.into_iter().flatten() {
            if cand.checked_add(total_needed).is_none_or(|e| e > safe_top) {
                continue;
            }
            if overlaps_any(cand, total_needed, gop_vram_off, gop_span, reserved) {
                continue;
            }
            let mut buffers = [0u64; 3];
            for (i, slot) in buffers.iter_mut().take(cnt).enumerate() {
                *slot = cand + (i as u64) * buf_stride;
            }
            let cursor_vram_off = cand + (cnt as u64) * buf_stride;

            // Map a single page-aligned WC range spanning both our scanout/cursor buffers and
            // (when adjacent within 256 MiB) the GOP FB so self-check can copy the live screen.
            let region_end = cursor_vram_off + CURSOR_VRAM_BYTES;
            let gop_end = gop_vram_off.saturating_add(gop_span).min(bar0_size);
            let combined_lo = cand.min(gop_vram_off);
            let combined_hi = region_end.max(gop_end);
            let (map_lo, map_hi) = if combined_hi.saturating_sub(combined_lo) <= (256 << 20) {
                (combined_lo, combined_hi)
            } else {
                (cand, region_end)
            };
            let map_vram_off = align_down(map_lo, 4096);
            let map_len = align_up(map_hi.saturating_sub(map_vram_off), 4096);
            if map_vram_off.saturating_add(map_len) > bar0_size {
                continue;
            }
            return Some(ScanoutLayout {
                map_vram_off,
                map_len,
                gop_vram_off,
                gop_size: gop_span,
                buffers,
                buf_count: cnt,
                buf_stride_bytes: buf_stride,
                cursor_vram_off,
                cursor_size_bytes: CURSOR_VRAM_BYTES,
            });
        }
    }
    None
}
