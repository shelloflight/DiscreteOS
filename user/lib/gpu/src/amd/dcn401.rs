//! DCN 4.0.1 register table (RDNA 4 / Navi 48 RX 9070, Navi 44).
//!
//! Transcribed from AMD's MIT-licensed ASIC register headers:
//! `dcn_4_1_0_offset.h`, `mmhub_4_1_0_offset.h`, `osssys_7_0_0_offset.h`, `nbif_6_3_1_offset.h`.

use super::dcn::{DcnRegs, DcnVersion, IhRegMap, RegAddr};

pub struct Dcn401;
pub static DCN401: Dcn401 = Dcn401;

// Pipe strides (dwords) verified across instances 0..3 in `dcn_4_1_0_offset.h`.
const HUBP_STRIDE: u32 = 0x00DC;
const DPP_STRIDE: u32 = 0x016B;
const OTG_STRIDE: u32 = 0x0080;
const AUX_STRIDE: u32 = 0x001C;
const DIG_DP_STRIDE: u32 = 0x0124;

// DCN segment BASE_IDX values.
const DCCG_BASE: u8 = 1;
const DCN_BASE: u8 = 2;

impl DcnRegs for Dcn401 {
    fn version(&self) -> DcnVersion {
        DcnVersion::Dcn401
    }
    fn max_pipes(&self) -> u8 {
        4
    }
    fn max_aux(&self) -> u8 {
        5
    }

    // ---- HUBP / HUBPREQ / HUBPRET ----
    fn hubp_surface_config(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x05e5 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_tiling_config(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x05e7 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_viewport_start(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x05e9 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_viewport_dim(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x05eb + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_cntl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x05f4 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_surface_pitch(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0607 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_primary_addr(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x060a + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_primary_addr_hi(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x060b + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_surface_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0612 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_flip_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0613 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_flip_interrupt(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0617 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_earliest_inuse(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x061c + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_earliest_inuse_hi(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x061d + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_cursor_settings(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0653 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_ret_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x066d + u32::from(pipe) * HUBP_STRIDE)
    }

    // ---- HUBP + DPP Cursor (`CURSOR0_n_*` & `CM_CURn_CURSOR0_CONTROL`) ----
    fn cursor_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0679 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_addr(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067a + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_addr_hi(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067b + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_size(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067c + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_position(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067d + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_hot_spot(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067e + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_dst_offset(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0680 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cnvc_pixel_format(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0ccf + u32::from(pipe) * DPP_STRIDE)
    }
    fn dpp_cursor_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0cf1 + u32::from(pipe) * DPP_STRIDE)
    }
    fn cm_hdr_mult(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0dc1 + u32::from(pipe) * DPP_STRIDE)
    }

    // ---- OTG ----
    fn otg_h_total(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b2a + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_h_blank(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b2b + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_h_sync_a(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b2c + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_h_sync_a_cntl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b2d + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_total(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b2f + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_total_min(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b30 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_total_max(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b31 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_total_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b33 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_blank(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b38 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_sync_a(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b39 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_sync_a_cntl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b3a + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b43 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_status(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b49 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_status_position(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b4a + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_status_frame_count(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b4d + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_double_buffer_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b5c + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_vert_int0_pos(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b5f + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_vert_int0_ctrl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b60 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_master_update_lock(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b89 + u32::from(pipe) * OTG_STRIDE)
    }

    // ---- DCCG (BASE_IDX 1) ----
    fn dccg_otg_pixel_rate_div(&self) -> Option<RegAddr> {
        Some(RegAddr::new(DCCG_BASE, 0x006f))
    }
    fn dccg_otg_pixel_rate_cntl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCCG_BASE, 0x0080 + u32::from(pipe) * 4)
    }
    fn dccg_dp_dto_phase(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCCG_BASE, 0x0081 + u32::from(pipe) * 4)
    }
    fn dccg_dp_dto_modulo(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCCG_BASE, 0x0082 + u32::from(pipe) * 4)
    }

    // ---- DP AUX ----
    fn aux_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x16b2 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_sw_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x16b3 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_arb_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x16b4 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_interrupt_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x16b5 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_sw_status(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x16b6 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_sw_data(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x16b8 + u32::from(aux) * AUX_STRIDE)
    }

    // ---- DIG / DP / DSC ----
    fn dig_fe_cntl(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2093 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dig_be_en_cntl(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x20bd + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_pixel_format(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x211f + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_colorimetry(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2120 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_steer_fifo(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2123 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_misc(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2124 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_vid_timing(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2126 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_vid_n(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2127 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_vid_m(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2128 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param1(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2162 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param2(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2163 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param3(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2164 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param4(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2165 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dsc_forward_config(&self, pipe: u8) -> Option<RegAddr> {
        Some(RegAddr::new(DCN_BASE, 0x1a64 + u32::from(pipe)))
    }
    fn dscc_config0(&self) -> Option<RegAddr> {
        Some(RegAddr::new(DCN_BASE, 0x300a))
    }
    fn dscc_pps_config(&self, idx: u8) -> Option<RegAddr> {
        (idx <= 22).then_some(RegAddr::new(DCN_BASE, 0x3012 + u32::from(idx)))
    }

    // ---- MMHUB 4.1.0 (BASE_IDX 0) ----
    fn mmhub_fb_offset(&self) -> RegAddr {
        RegAddr::new(0, 0x04c7)
    }
    fn mmhub_fb_location_base(&self) -> RegAddr {
        RegAddr::new(0, 0x0554)
    }
    fn mmhub_fb_location_top(&self) -> RegAddr {
        RegAddr::new(0, 0x0555)
    }

    // ---- OSSSYS 7.0.0 IH (BASE_IDX 0) — note RPTR/WPTR precede BASE/BASE_HI ----
    fn ih_regs(&self) -> IhRegMap {
        IhRegMap {
            rb_cntl: RegAddr::new(0, 0x0080),
            rb_rptr: RegAddr::new(0, 0x0081),
            rb_wptr: RegAddr::new(0, 0x0082),
            rb_base: RegAddr::new(0, 0x0083),
            rb_base_hi: RegAddr::new(0, 0x0084),
            rb_wptr_addr_hi: RegAddr::new(0, 0x0085),
            rb_wptr_addr_lo: RegAddr::new(0, 0x0086),
            doorbell_rptr: RegAddr::new(0, 0x0087),
            ih_cntl: RegAddr::new(0, 0x00a8),
            ih_chicken: RegAddr::new(0, 0x018a),
        }
    }

    // ---- NBIF 6.3.1 (BASE_IDX 2) ----
    fn nbif_interrupt_cntl(&self) -> RegAddr {
        RegAddr::new(2, 0x00f1)
    }
    fn nbif_interrupt_cntl2(&self) -> RegAddr {
        RegAddr::new(2, 0x00f2)
    }
}
