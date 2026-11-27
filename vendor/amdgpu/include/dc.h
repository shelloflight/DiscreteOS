#ifndef _AMDGPU_DC_H
#define _AMDGPU_DC_H

#include <linux/types.h>
#include <amdgpu_hw.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DC_MAX_PIPES                       4u
#define DC_MAX_CONNECTORS                  5u
#define DC_MAX_MODES                       16u
#define DC_MAX_SCANOUT_BUFS                3u
#define DC_EDID_MAX_BYTES                  512u
#define DC_DSC_PPS_BYTES                   128u

/* Link protocols supported by Display Core (`dc_link.c`). */
enum dc_link_type {
    DC_LINK_NONE    = 0,
    DC_LINK_DP_1_4  = 1, /* 8b/10b: RBR, HBR, HBR2, HBR3 */
    DC_LINK_DP_2_1  = 2, /* 128b/132b: UHBR10, UHBR13.5, UHBR20 */
    DC_LINK_HDMI_21 = 3, /* HDMI 2.0 TMDS / HDMI 2.1 FRL 3G3L..12G4L */
    DC_LINK_EDP     = 4,
};

/* DP link rates in Mbps per lane (wire rate). */
#define DC_DP_RATE_RBR_MBPS                1620u
#define DC_DP_RATE_HBR_MBPS                2700u
#define DC_DP_RATE_HBR2_MBPS               5400u
#define DC_DP_RATE_HBR3_MBPS               8100u
#define DC_DP_RATE_UHBR10_MBPS             10000u
#define DC_DP_RATE_UHBR13_5_MBPS           13500u
#define DC_DP_RATE_UHBR20_MBPS             20000u

/* HDMI 2.1 FRL rates in Mbps per lane. */
#define DC_HDMI_FRL_3G_MBPS                3000u
#define DC_HDMI_FRL_6G_MBPS                6000u
#define DC_HDMI_FRL_8G_MBPS                8000u
#define DC_HDMI_FRL_10G_MBPS               10000u
#define DC_HDMI_FRL_12G_MBPS               12000u

struct dc_reg_addr {
    u8 base_idx;
    u32 off;
};

/* Version-keyed DCN register table (`dc_regs.c`), matching AMD MIT ASIC headers. */
struct dc_reg_table {
    enum dc_dcn_version version;
    const char *name;
    u8 max_pipes;
    u8 max_aux;
    u32 hubp_stride;
    u32 dpp_stride;
    u32 otg_stride;
    u32 aux_stride;
    u32 dig_stride;
    u32 dsc_stride;
    u32 hpd_stride;

    /* HUBP (base 2) */
    u32 hubp_surface_config;
    u32 hubp_tiling_config;
    u32 hubp_viewport_start;
    u32 hubp_viewport_dim;
    u32 hubp_cntl;
    u32 hubp_surface_pitch;
    u32 hubp_primary_addr;
    u32 hubp_primary_addr_hi;
    u32 hubp_surface_control;
    u32 hubp_flip_control;
    u32 hubp_flip_interrupt;
    u32 hubp_earliest_inuse;
    u32 hubp_earliest_inuse_hi;
    u32 hubp_cursor_settings;
    u32 hubp_ret_control;
    u32 hubp_blank_offset_0;
    u32 hubp_blank_offset_1;
    u32 hubp_dst_dimensions;
    u32 hubp_ref_freq_to_pix_freq;
    u32 hubp_per_line_delivery_pre;
    u32 hubp_per_line_delivery;
    u32 hubp_ttu_global_cntl;
    u32 hubp_surf0_ttu_cntl0;
    u32 hubp_surf0_ttu_cntl1;

    /* Cursor (base 2) */
    u32 cursor_control;
    u32 cursor_addr;
    u32 cursor_addr_hi;
    u32 cursor_size;
    u32 cursor_position;
    u32 cursor_hot_spot;
    u32 cursor_dst_offset;

    /* DPP + DSCL scaler (base 2) */
    u32 cnvc_pixel_format;
    u32 dpp_cursor_control;
    u32 cm_hdr_mult;
    u32 dscl_scl_mode;
    u32 dscl_h_scale_ratio;
    u32 dscl_v_scale_ratio;
    u32 dscl_recout_start;
    u32 dscl_recout_size;
    u32 dscl_mpc_size;

    /* OTG / OPTC (base 2) */
    u32 otg_h_total;
    u32 otg_h_blank;
    u32 otg_h_sync_a;
    u32 otg_h_sync_a_cntl;
    u32 otg_v_total;
    u32 otg_v_total_min;
    u32 otg_v_total_max;
    u32 otg_v_total_control;
    u32 otg_v_blank;
    u32 otg_v_sync_a;
    u32 otg_v_sync_a_cntl;
    u32 otg_control;
    u32 otg_status;
    u32 otg_status_position;
    u32 otg_status_frame_count;
    u32 otg_double_buffer_control;
    u32 otg_vert_int0_pos;
    u32 otg_vert_int0_ctrl;
    u32 otg_vstartup_param;
    u32 otg_master_update_lock;
    u32 vtg_control;
    u32 optc_input_global_ctrl;
    u32 optc_input_stride;

    /* DCCG (base 1) */
    bool has_otg_pixel_rate_div;
    u32 dccg_dentist_dispclk_cntl;
    u32 dccg_otg_pixel_rate_div;
    u32 dccg_otg_pixel_rate_cntl;
    u32 dccg_dp_dto_phase;
    u32 dccg_dp_dto_modulo;
    u32 dccg_dppclk_dto_param;
    u32 dccg_dppclk_ctrl;

    /* DP AUX (base 2) */
    u32 aux_control;
    u32 aux_sw_control;
    u32 aux_arb_control;
    u32 aux_interrupt_control;
    u32 aux_sw_status;
    u32 aux_sw_data;

    /* DIG / DP (base 2) */
    bool has_dig_fifo_ctrl;
    u32 dig_fe_cntl;
    u32 dig_be_en_cntl;
    u32 dig_fifo_ctrl0;
    u32 dp_pixel_format;
    u32 dp_msa_colorimetry;
    u32 dp_vid_stream_cntl;
    u32 dp_steer_fifo;
    u32 dp_msa_misc;
    u32 dp_vid_timing;
    u32 dp_vid_n;
    u32 dp_vid_m;
    u32 dp_msa_timing_param1;
    u32 dp_msa_timing_param2;
    u32 dp_msa_timing_param3;
    u32 dp_msa_timing_param4;

    /* HPD (base 2) */
    u32 hpd_int_status;
    u32 hpd_control;

    /* DSC 1.2a (base 2) */
    u32 dsc_top_control;
    u32 dscc_pps_config0;
    u32 optc_dsc_forward_config;

    /* DMCUB (base 2) */
    u32 dmcub_inbox1_base;
    u32 dmcub_inbox1_size;
    u32 dmcub_inbox1_wptr;
    u32 dmcub_inbox1_rptr;
    u32 dmcub_outbox1_base;
    u32 dmcub_outbox1_size;
    u32 dmcub_outbox1_wptr;
    u32 dmcub_outbox1_rptr;
    u32 dmcub_scratch0;
    u32 dmcub_cntl;
    u32 dmcub_gpint_datain1;
    u32 dmcub_gpint_dataout;
};

/* Detailed video timing descriptor. */
struct dc_timing {
    u32 pixel_clock_khz;
    u32 h_active;
    u32 h_blank;
    u32 h_front_porch;
    u32 h_sync_width;
    u32 v_active;
    u32 v_blank;
    u32 v_front_porch;
    u32 v_sync_width;
    bool h_sync_pos;
    bool v_sync_pos;
    u32 refresh_mhz;
    bool preferred;
};

/* DML2 mode & clock validation output (`dc_dml2.c`). */
struct dc_dml2_plan {
    bool supported;
    bool requires_dsc;
    bool requires_pipe_split;
    bool requires_uhbr;
    u8 bpc;
    u16 dsc_target_bpp_x16; /* 1/16 bpp fixed point (e.g. 8.0 bpp = 128) */
    u8 dsc_slice_count;
    u32 dispclk_mhz;
    u32 dppclk_mhz;
    u32 dcfclk_mhz;
    u32 dtbclk_mhz;
    u32 uclk_mhz;
    u32 det_buffer_kb;
    u32 urgent_watermark_ns;
    u32 stutter_watermark_ns;
    u64 raw_bandwidth_kbps;
    u64 effective_link_kbps;
    u8 req_lanes;
    u32 req_rate_mbps;
    u32 pixel_rate_div;
};

/* VESA DSC 1.2a Picture Parameter Set (`dc_dsc.c`). */
struct dc_dsc_pps {
    bool valid;
    u8 bpc;
    u16 bpp_x16;
    u16 pic_width;
    u16 pic_height;
    u16 slice_width;
    u16 slice_height;
    u8 slice_count;
    u8 raw[DC_DSC_PPS_BYTES];
};

/* DMCUB controller state (`dc_dmub.c`). */
struct dc_dmub_state {
    bool initialized;
    bool fw_alive;
    bool ring_owned;
    u32 fw_version;
    u32 inbox1_wptr;
    u32 cmds_submitted;
    struct dosdrm_dma_buf ring_dma; /* 8 KiB: Inbox1 (4 KiB) + Outbox1 (4 KiB) */
};

/* Per-connector DP/HDMI link state (`dc_link.c`). */
struct dc_connector {
    bool present;
    bool connected;
    u8 index;
    u8 aux_idx;
    u8 dig_idx;
    u8 hpd_idx;
    enum dc_link_type link_type;
    u8 max_lanes;
    u32 max_rate_mbps;
    u8 trained_lanes;
    u32 trained_rate_mbps;
    bool dp_uhbr_capable;
    bool dsc_capable;
    bool vrr_capable;
    bool hdr_capable;
    bool hdmi_frl_capable;
    u8 hdmi_max_frl_rate;
    u16 vrr_min_hz;
    u16 vrr_max_hz;
    u16 hdr_max_nits;
    u8 edid_blocks;
    u8 edid_raw[DC_EDID_MAX_BYTES];
    char monitor_name[24];
    u32 mode_count;
    struct dc_timing modes[DC_MAX_MODES];
};

/* Saved hardware register snapshot for instant rollback, GOP hand-back, and S3 suspend/resume. */
struct dc_pipe_reg_snapshot {
    bool valid;
    u8 pipe;
    u8 dig;
    u32 otg_h_total;
    u32 otg_h_blank;
    u32 otg_h_sync_a;
    u32 otg_h_sync_a_cntl;
    u32 otg_v_total;
    u32 otg_v_blank;
    u32 otg_v_sync_a;
    u32 otg_v_sync_a_cntl;
    u32 otg_v_total_min;
    u32 otg_v_total_max;
    u32 otg_v_total_control;
    u32 otg_double_buffer_control;
    u32 otg_vstartup_param;
    u32 vtg_control;
    u32 dccg_dentist_dispclk_cntl;
    u32 dccg_pixel_rate_div;
    u32 dccg_pixel_rate_cntl;
    u32 dccg_dto_phase;
    u32 dccg_dto_modulo;
    u32 dccg_dppclk_dto_param;
    u32 dccg_dppclk_ctrl;
    u32 hubp_cntl;
    u32 hubp_blank_offset_0;
    u32 hubp_blank_offset_1;
    u32 hubp_dst_dimensions;
    u32 hubp_ref_freq_to_pix_freq;
    u32 hubp_per_line_delivery_pre;
    u32 hubp_per_line_delivery;
    u32 hubp_ttu_global_cntl;
    u32 hubp_surf0_ttu_cntl0;
    u32 hubp_surf0_ttu_cntl1;
    u32 hubp_viewport_start;
    u32 hubp_viewport_dim;
    u32 hubp_surface_pitch;
    u32 hubp_surface_config;
    u32 hubp_primary_addr;
    u32 hubp_primary_addr_hi;
    u32 dscl_scl_mode;
    u32 dscl_recout_start;
    u32 dscl_recout_size;
    u32 dscl_mpc_size;
    u32 dp_msa_param1;
    u32 dp_msa_param2;
    u32 dp_msa_param3;
    u32 dp_msa_param4;
    u32 dp_pixel_format;
    u32 dp_msa_colorimetry;
    u32 dp_msa_misc;
    u32 dp_vid_timing;
    u32 dp_vid_m;
    u32 dp_vid_n;
    u32 dp_vid_stream_cntl;
    u32 dp_steer_fifo;
    u32 dig_fifo_ctrl0;
    u32 cnvc_pixel_format;
    u32 cm_hdr_mult;
    u32 dsc_top_control;
    u64 orig_mc_addr;
    u32 src_width;
    u32 src_height;
    u32 dst_width;
    u32 dst_height;
    u32 refresh_mhz;
    u32 boot_pclk_khz;
    u32 boot_h_total;
    u32 boot_h_blank_end;
    u32 boot_v_blank;
    u32 boot_v_blank_end;
    u32 dto_src_clk_khz;
    bool msa_h_low;
    bool msa_misc0_high;
    bool dto_src_calibrated;
    bool dscl_static_valid;
    u8 dpp_size_reg_count;
    u32 dpp_size_regs[4];
    u32 dpp_size_saved[4];
};

/* Active Display Core pipe state (scanout buffers, flip engine, HW cursor, modeset state). */
struct dc_pipe_state {
    bool active;
    u8 pipe_idx;
    u8 dig_idx;
    u8 conn_idx;
    struct dc_timing current_mode;
    u32 src_width;
    u32 src_height;
    u32 pitch_bytes;
    bool vrr_enabled;
    bool hdr_enabled;
    bool dsc_enabled;
    struct dc_dsc_pps dsc_pps;
    struct dc_dml2_plan active_plan;

    /* Triple-buffered VRAM scanout chain + 256 KiB HW cursor buffer. */
    u32 buf_count;
    u64 scanout_vram[DC_MAX_SCANOUT_BUFS];
    u64 scanout_mc[DC_MAX_SCANOUT_BUFS];
    u64 scanout_buf_size;
    u64 cursor_vram;
    u64 cursor_mc;
    bool cursor_enabled;
    s32 cursor_x;
    s32 cursor_y;
    u16 cursor_hot_x;
    u16 cursor_hot_y;
    u32 cursor_size;

    /* Tear-free vsync flip state. */
    bool verified;
    u32 front_buf;
    s32 pending_buf;
    u64 pending_mc;
    u64 last_flip_ns;
    u64 vblank_seq;
    u64 flips_completed;

    struct dc_pipe_reg_snapshot boot_snapshot;
    struct dc_pipe_reg_snapshot suspend_snapshot;
};

struct dc_state {
    const struct dc_reg_table *regs;
    struct dc_dmub_state dmub;
    u32 connector_count;
    struct dc_connector connectors[DC_MAX_CONNECTORS];
    u32 active_pipe_count;
    struct dc_pipe_state pipes[DC_MAX_PIPES];
    u32 primary_pipe;
    bool hotplug_pending;
};

/* Atomic KMS commit request passed from `amdgpu.ddrv` into Display Core (`dc_core.c`). */
struct dc_atomic_req {
    u32 pipe_slot;
    bool test_only;
    bool allow_modeset;
    bool reset_boot;
    bool mode_changed;
    u32 mode_width;
    u32 mode_height;
    u32 mode_refresh_mhz;
    bool vrr_changed;
    bool vrr_enable;
    bool hdr_changed;
    bool hdr_enable;
    bool primary_changed;
    const u8 *primary_src;
    u32 primary_width;
    u32 primary_height;
    u32 primary_pitch;
    u32 primary_format;
    bool cursor_changed;
    const u8 *cursor_src;
    u32 cursor_size;
    s32 cursor_x;
    s32 cursor_y;
    u16 cursor_hot_x;
    u16 cursor_hot_y;
};

/* Register table lookup (`dc_regs.c`). */
const struct dc_reg_table *dc_regs_for_version(enum dc_dcn_version ver);
bool dc_reg_read(const struct amdgpu_device *adev, u8 base_idx, u32 dword_off, u32 *out_val);
bool dc_reg_write(struct amdgpu_device *adev, u8 base_idx, u32 dword_off, u32 val);

/* DMCUB (`dc_dmub.c`). */
int dc_dmub_init(struct amdgpu_device *adev, struct dc_state *dc);
void dc_dmub_fini(struct amdgpu_device *adev, struct dc_state *dc);
int dc_dmub_submit_cmd(struct amdgpu_device *adev, struct dc_state *dc, const u32 cmd_dwords[16]);

/* DML2 (`dc_dml2.c`). */
int dc_dml2_plan_mode(
    const struct amdgpu_device *adev,
    const struct dc_connector *conn,
    const struct dc_timing *timing,
    u8 bpc,
    struct dc_dml2_plan *out_plan
);
void dc_timing_cvt_rb(u32 width, u32 height, u32 refresh_mhz, struct dc_timing *out);

/* DSC 1.2a (`dc_dsc.c`). */
int dc_dsc_compute_pps(
    u16 width,
    u16 height,
    u8 bpc,
    u16 target_bpp_x16,
    u8 slice_count,
    struct dc_dsc_pps *out_pps
);
int dc_dsc_program_hw(struct amdgpu_device *adev, struct dc_state *dc, u8 pipe, const struct dc_dsc_pps *pps, bool enable);

/* DP 1.4/2.1 & HDMI 2.1 FRL link layer (`dc_link.c`). */
int dc_aux_transfer(
    struct amdgpu_device *adev,
    const struct dc_reg_table *regs,
    u8 aux_idx,
    u8 cmd,
    u32 addr,
    u8 *data,
    u8 len,
    u8 *reply_out
);
int dc_dpcd_read(struct amdgpu_device *adev, const struct dc_reg_table *regs, u8 aux_idx, u32 addr, u8 *buf, u8 len);
int dc_dpcd_write(struct amdgpu_device *adev, const struct dc_reg_table *regs, u8 aux_idx, u32 addr, const u8 *buf, u8 len);
int dc_link_probe_all(struct amdgpu_device *adev, struct dc_state *dc);
int dc_link_train_dp(
    struct amdgpu_device *adev,
    struct dc_state *dc,
    struct dc_connector *conn,
    u8 target_lanes,
    u32 target_rate_mbps
);
int dc_link_train_hdmi_frl(
    struct amdgpu_device *adev,
    struct dc_state *dc,
    struct dc_connector *conn,
    u8 target_lanes,
    u32 target_rate_mbps
);
bool dc_link_poll_hotplug(struct amdgpu_device *adev, struct dc_state *dc);
void dc_connector_push_mode(struct dc_connector *conn, const struct dc_timing *t);

/* Display Core lifecycle & Atomic KMS (`dc_core.c`). */
int dc_init(struct amdgpu_device *adev);
void dc_fini(struct amdgpu_device *adev);
int dc_suspend(struct amdgpu_device *adev);
int dc_resume(struct amdgpu_device *adev);
int dc_atomic_check_and_commit(
    struct amdgpu_device *adev,
    const struct dc_atomic_req *req,
    u64 *out_vblank_seq,
    bool *out_async
);
bool dc_poll_vblank(
    struct amdgpu_device *adev,
    u32 *out_pipe,
    u64 *out_seq,
    u64 *out_ts_ns,
    bool *out_late
);

#ifdef __cplusplus
}
#endif

#endif
