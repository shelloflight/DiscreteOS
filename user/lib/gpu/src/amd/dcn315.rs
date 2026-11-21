//! DCN 3.1.5 register table (Ryzen 7000/9000 Raphael / Granite Ridge iGPU).
//!
//! Transcribed from AMD's MIT-licensed ASIC register headers:
//! `dcn_3_1_5_offset.h`, `mmhub_3_0_1_offset.h`, `osssys_6_0_0_offset.h`, `nbif_6_3_1_offset.h`.

use super::dcn::{DcnRegs, DcnVersion, IhRegMap, RegAddr};

pub struct Dcn315;
pub static DCN315: Dcn315 = Dcn315;

const HUBP_STRIDE: u32 = 0x00DC;
const DPP_STRIDE: u32 = 0x016B;
const OTG_STRIDE: u32 = 0x0080;
const AUX_STRIDE: u32 = 0x001C;
const DIG_DP_STRIDE: u32 = 0x0100;

const DCCG_BASE: u8 = 1;
const DCN_BASE: u8 = 2;

impl DcnRegs for Dcn315 {
    fn version(&self) -> DcnVersion {
        DcnVersion::Dcn315
    }
    fn max_pipes(&self) -> u8 {
        4
    }
    fn max_aux(&self) -> u8 {
        4
    }

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
        RegAddr::new(DCN_BASE, 0x05ea + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_cntl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x05f3 + u32::from(pipe) * HUBP_STRIDE)
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
        RegAddr::new(DCN_BASE, 0x061a + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_flip_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x061b + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_flip_interrupt(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0620 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_earliest_inuse(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0625 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_earliest_inuse_hi(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0626 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_cursor_settings(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x065c + u32::from(pipe) * HUBP_STRIDE)
    }
    fn hubp_ret_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x066c + u32::from(pipe) * HUBP_STRIDE)
    }

    fn cursor_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0678 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_addr(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0679 + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_addr_hi(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067a + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_size(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067b + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_position(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067c + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_hot_spot(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067d + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cursor_dst_offset(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x067f + u32::from(pipe) * HUBP_STRIDE)
    }
    fn cnvc_pixel_format(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0ccf + u32::from(pipe) * DPP_STRIDE)
    }
    fn dpp_cursor_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0cf1 + u32::from(pipe) * DPP_STRIDE)
    }
    fn cm_hdr_mult(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x0dd1 + u32::from(pipe) * DPP_STRIDE)
    }

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
        RegAddr::new(DCN_BASE, 0x1b36 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_sync_a(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b37 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_v_sync_a_cntl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b38 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b41 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_status(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b49 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_status_position(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b4a + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_status_frame_count(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b4c + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_double_buffer_control(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b5b + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_vert_int0_pos(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b62 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_vert_int0_ctrl(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b63 + u32::from(pipe) * OTG_STRIDE)
    }
    fn otg_master_update_lock(&self, pipe: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1b8b + u32::from(pipe) * OTG_STRIDE)
    }

    fn dccg_otg_pixel_rate_div(&self) -> Option<RegAddr> {
        None
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

    fn aux_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1f50 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_sw_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1f51 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_arb_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1f52 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_interrupt_control(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1f53 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_sw_status(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1f54 + u32::from(aux) * AUX_STRIDE)
    }
    fn aux_sw_data(&self, aux: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x1f56 + u32::from(aux) * AUX_STRIDE)
    }

    fn dig_fe_cntl(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x208b + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dig_be_en_cntl(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x20b1 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_pixel_format(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2109 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_colorimetry(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x210a + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_steer_fifo(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x210d + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_misc(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x210e + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_vid_timing(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2110 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_vid_n(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2111 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_vid_m(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x2112 + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param1(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x214c + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param2(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x214d + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param3(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x214e + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dp_msa_timing_param4(&self, enc: u8) -> RegAddr {
        RegAddr::new(DCN_BASE, 0x214f + u32::from(enc) * DIG_DP_STRIDE)
    }
    fn dsc_forward_config(&self, _pipe: u8) -> Option<RegAddr> {
        None
    }
    fn dscc_config0(&self) -> Option<RegAddr> {
        None
    }
    fn dscc_pps_config(&self, _idx: u8) -> Option<RegAddr> {
        None
    }

    // ---- MMHUB 3.0.1 (BASE_IDX 1 on Ryzen 7000/9000 APU) ----
    fn mmhub_fb_offset(&self) -> RegAddr {
        RegAddr::new(1, 0x08d7)
    }
    fn mmhub_fb_location_base(&self) -> RegAddr {
        RegAddr::new(1, 0x08ec)
    }
    fn mmhub_fb_location_top(&self) -> RegAddr {
        RegAddr::new(1, 0x08ed)
    }

    // ---- OSSSYS 6.0.0 IH (BASE_IDX 0) ----
    fn ih_regs(&self) -> IhRegMap {
        IhRegMap {
            rb_cntl: RegAddr::new(0, 0x0080),
            rb_base: RegAddr::new(0, 0x0081),
            rb_base_hi: RegAddr::new(0, 0x0082),
            rb_rptr: RegAddr::new(0, 0x0083),
            rb_wptr: RegAddr::new(0, 0x0084),
            rb_wptr_addr_hi: RegAddr::new(0, 0x0085),
            rb_wptr_addr_lo: RegAddr::new(0, 0x0086),
            doorbell_rptr: RegAddr::new(0, 0x0087),
            ih_cntl: RegAddr::new(0, 0x00c0),
            ih_chicken: RegAddr::new(0, 0x018d),
        }
    }

    fn nbif_interrupt_cntl(&self) -> RegAddr {
        RegAddr::new(2, 0x00f1)
    }
    fn nbif_interrupt_cntl2(&self) -> RegAddr {
        RegAddr::new(2, 0x00f2)
    }
}
