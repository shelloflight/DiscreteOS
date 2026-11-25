#include <dc.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

/*
 * Display Core (`dc_core.c`):
 * - Active multi-pipe probing & pristine `boot_snapshot` capture
 * - Arbitrary resolution scaling (HUBP viewport/pitch + DPP DSCL scaler)
 * - 60/120/240/540+ Hz modesetting with DML2 validation, SMU clock floor, DP/HDMI link training,
 *   VESA DSC 1.2a, DCCG DTO + OTG + DIG MSA + live post-modeset verification & auto-rollback
 * - FreeSync VRR, 10-bit HDR10, 64x64/128x128/256x256 hardware cursor plane
 * - Triple-buffered tear-free vsync flip engine + OSSSYS IH / predicted-vblank pacing
 * - Clean UEFI GOP hand-back (`reset_boot`) & S3 suspend/resume
 */

#define OTG_MASTER_EN_BIT                  (1u << 0)
#define HUBP_BLANK_EN_BIT                  (1u << 0)
#define FLIP_PENDING_BIT                   (1u << 4)
#define FLIP_TYPE_IMMEDIATE_BIT            (1u << 0)
#define DP_VID_M_N_GEN_EN_BIT              (1u << 0)
#define DP_STEER_FIFO_RESET_BIT            (1u << 0)
#define CURSOR_EN_BIT                      (1u << 0)
#define CURSOR_MODE_PREMULT_ARGB           (3u << 8)
#define CURSOR_UPDATE_LOCK_BIT             (1u << 16)
#define OTG_V_TOTAL_MIN_SEL_BIT            (1u << 0)
#define OTG_V_TOTAL_MAX_SEL_BIT            (1u << 1)
#define OTG_SET_V_TOTAL_MIN_MASK_EN_BIT    (1u << 2)

static u64 decode_mc_addr(u32 lo, u32 hi) {
    return ((u64)(hi & 0xFFFFu) << 32) | (u64)(lo & 0xFFFFFF00u);
}

static void encode_mc_addr(u64 mc, u32 *lo, u32 *hi) {
    *lo = (u32)(mc & 0xFFFFFF00ULL);
    *hi = (u32)((mc >> 32) & 0xFFFFULL);
}

static u32 read_otg_frame_count(const struct amdgpu_device *adev, const struct dc_reg_table *r, u8 pipe) {
    u32 v = 0;
    (void)dc_reg_read(adev, 2u, r->otg_status_frame_count + (u32)pipe * r->otg_stride, &v);
    return v & 0x00FFFFFFu;
}

static u32 frame_count_delta(u32 after, u32 before) {
    return (after - before) & 0x00FFFFFFu;
}

static u32 find_dig_for_pipe(const struct amdgpu_device *adev, const struct dc_reg_table *r, u8 pipe) {
    for (u8 enc = 0; enc < 5u; enc++) {
        u32 fe = 0, be = 0;
        if (!dc_reg_read(adev, 2u, r->dig_fe_cntl + (u32)enc * r->dig_stride, &fe)) continue;
        if (!dc_reg_read(adev, 2u, r->dig_be_en_cntl + (u32)enc * r->dig_stride, &be)) continue;
        if ((be & 1u) != 0 && (fe & 0x0Fu) == pipe) {
            return enc;
        }
    }
    return pipe;
}

static void capture_pipe_snapshot(
    const struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u8 pipe,
    u8 dig,
    struct dc_pipe_reg_snapshot *snap
) {
    memset(snap, 0, sizeof(*snap));
    snap->pipe = pipe;
    snap->dig = dig;

    u32 otg = (u32)pipe * r->otg_stride;
    u32 hubp = (u32)pipe * r->hubp_stride;
    u32 dpp = (u32)pipe * r->dpp_stride;
    u32 dig_o = (u32)dig * r->dig_stride;
    u32 dccg = (u32)pipe * 4u;

    (void)dc_reg_read(adev, 2u, r->otg_h_total + otg, &snap->otg_h_total);
    (void)dc_reg_read(adev, 2u, r->otg_h_blank + otg, &snap->otg_h_blank);
    (void)dc_reg_read(adev, 2u, r->otg_h_sync_a + otg, &snap->otg_h_sync_a);
    (void)dc_reg_read(adev, 2u, r->otg_h_sync_a_cntl + otg, &snap->otg_h_sync_a_cntl);
    (void)dc_reg_read(adev, 2u, r->otg_v_total + otg, &snap->otg_v_total);
    (void)dc_reg_read(adev, 2u, r->otg_v_blank + otg, &snap->otg_v_blank);
    (void)dc_reg_read(adev, 2u, r->otg_v_sync_a + otg, &snap->otg_v_sync_a);
    (void)dc_reg_read(adev, 2u, r->otg_v_sync_a_cntl + otg, &snap->otg_v_sync_a_cntl);
    (void)dc_reg_read(adev, 2u, r->otg_v_total_min + otg, &snap->otg_v_total_min);
    (void)dc_reg_read(adev, 2u, r->otg_v_total_max + otg, &snap->otg_v_total_max);
    (void)dc_reg_read(adev, 2u, r->otg_v_total_control + otg, &snap->otg_v_total_control);

    if (r->has_otg_pixel_rate_div) {
        (void)dc_reg_read(adev, 1u, r->dccg_otg_pixel_rate_div, &snap->dccg_pixel_rate_div);
    }
    (void)dc_reg_read(adev, 1u, r->dccg_otg_pixel_rate_cntl + dccg, &snap->dccg_pixel_rate_cntl);
    (void)dc_reg_read(adev, 1u, r->dccg_dp_dto_phase + dccg, &snap->dccg_dto_phase);
    (void)dc_reg_read(adev, 1u, r->dccg_dp_dto_modulo + dccg, &snap->dccg_dto_modulo);

    (void)dc_reg_read(adev, 2u, r->hubp_viewport_start + hubp, &snap->hubp_viewport_start);
    (void)dc_reg_read(adev, 2u, r->hubp_viewport_dim + hubp, &snap->hubp_viewport_dim);
    (void)dc_reg_read(adev, 2u, r->hubp_surface_pitch + hubp, &snap->hubp_surface_pitch);
    (void)dc_reg_read(adev, 2u, r->hubp_surface_config + hubp, &snap->hubp_surface_config);
    (void)dc_reg_read(adev, 2u, r->hubp_primary_addr + hubp, &snap->hubp_primary_addr);
    (void)dc_reg_read(adev, 2u, r->hubp_primary_addr_hi + hubp, &snap->hubp_primary_addr_hi);

    (void)dc_reg_read(adev, 2u, r->dscl_scl_mode + dpp, &snap->dscl_scl_mode);
    (void)dc_reg_read(adev, 2u, r->dscl_recout_start + dpp, &snap->dscl_recout_start);
    (void)dc_reg_read(adev, 2u, r->dscl_recout_size + dpp, &snap->dscl_recout_size);
    (void)dc_reg_read(adev, 2u, r->dscl_mpc_size + dpp, &snap->dscl_mpc_size);
    (void)dc_reg_read(adev, 2u, r->cnvc_pixel_format + dpp, &snap->cnvc_pixel_format);
    (void)dc_reg_read(adev, 2u, r->cm_hdr_mult + dpp, &snap->cm_hdr_mult);

    (void)dc_reg_read(adev, 2u, r->dp_msa_timing_param1 + dig_o, &snap->dp_msa_param1);
    (void)dc_reg_read(adev, 2u, r->dp_msa_timing_param2 + dig_o, &snap->dp_msa_param2);
    (void)dc_reg_read(adev, 2u, r->dp_msa_timing_param3 + dig_o, &snap->dp_msa_param3);
    (void)dc_reg_read(adev, 2u, r->dp_msa_timing_param4 + dig_o, &snap->dp_msa_param4);
    (void)dc_reg_read(adev, 2u, r->dp_msa_misc + dig_o, &snap->dp_msa_misc);
    (void)dc_reg_read(adev, 2u, r->dp_vid_timing + dig_o, &snap->dp_vid_timing);
    (void)dc_reg_read(adev, 2u, r->dsc_top_control + (u32)pipe * r->dsc_stride, &snap->dsc_top_control);

    snap->orig_mc_addr = decode_mc_addr(snap->hubp_primary_addr, snap->hubp_primary_addr_hi);
    snap->valid = true;
}

static void restore_pipe_snapshot(
    struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    const struct dc_pipe_reg_snapshot *snap
) {
    if (!snap || !snap->valid) return;
    u32 otg = (u32)snap->pipe * r->otg_stride;
    u32 hubp = (u32)snap->pipe * r->hubp_stride;
    u32 dpp = (u32)snap->pipe * r->dpp_stride;
    u32 dig_o = (u32)snap->dig * r->dig_stride;
    u32 dccg = (u32)snap->pipe * 4u;

    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 1u);

    (void)dc_reg_write(adev, 2u, r->otg_h_total + otg, snap->otg_h_total);
    (void)dc_reg_write(adev, 2u, r->otg_h_blank + otg, snap->otg_h_blank);
    (void)dc_reg_write(adev, 2u, r->otg_h_sync_a + otg, snap->otg_h_sync_a);
    (void)dc_reg_write(adev, 2u, r->otg_h_sync_a_cntl + otg, snap->otg_h_sync_a_cntl);
    (void)dc_reg_write(adev, 2u, r->otg_v_total + otg, snap->otg_v_total);
    (void)dc_reg_write(adev, 2u, r->otg_v_blank + otg, snap->otg_v_blank);
    (void)dc_reg_write(adev, 2u, r->otg_v_sync_a + otg, snap->otg_v_sync_a);
    (void)dc_reg_write(adev, 2u, r->otg_v_sync_a_cntl + otg, snap->otg_v_sync_a_cntl);
    (void)dc_reg_write(adev, 2u, r->otg_v_total_min + otg, snap->otg_v_total_min);
    (void)dc_reg_write(adev, 2u, r->otg_v_total_max + otg, snap->otg_v_total_max);
    (void)dc_reg_write(adev, 2u, r->otg_v_total_control + otg, snap->otg_v_total_control);

    if (r->has_otg_pixel_rate_div) {
        (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_div, snap->dccg_pixel_rate_div);
    }
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_modulo + dccg, snap->dccg_dto_modulo);
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_phase + dccg, snap->dccg_dto_phase);
    (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_cntl + dccg, snap->dccg_pixel_rate_cntl);

    (void)dc_reg_write(adev, 2u, r->hubp_viewport_start + hubp, snap->hubp_viewport_start);
    (void)dc_reg_write(adev, 2u, r->hubp_viewport_dim + hubp, snap->hubp_viewport_dim);
    (void)dc_reg_write(adev, 2u, r->hubp_surface_pitch + hubp, snap->hubp_surface_pitch);
    (void)dc_reg_write(adev, 2u, r->hubp_surface_config + hubp, snap->hubp_surface_config);
    (void)dc_reg_write(adev, 2u, r->hubp_primary_addr_hi + hubp, snap->hubp_primary_addr_hi);
    (void)dc_reg_write(adev, 2u, r->hubp_primary_addr + hubp, snap->hubp_primary_addr);

    (void)dc_reg_write(adev, 2u, r->dscl_scl_mode + dpp, snap->dscl_scl_mode);
    (void)dc_reg_write(adev, 2u, r->dscl_recout_start + dpp, snap->dscl_recout_start);
    (void)dc_reg_write(adev, 2u, r->dscl_recout_size + dpp, snap->dscl_recout_size);
    (void)dc_reg_write(adev, 2u, r->dscl_mpc_size + dpp, snap->dscl_mpc_size);
    (void)dc_reg_write(adev, 2u, r->cnvc_pixel_format + dpp, snap->cnvc_pixel_format);
    (void)dc_reg_write(adev, 2u, r->cm_hdr_mult + dpp, snap->cm_hdr_mult);

    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param1 + dig_o, snap->dp_msa_param1);
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param2 + dig_o, snap->dp_msa_param2);
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param3 + dig_o, snap->dp_msa_param3);
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param4 + dig_o, snap->dp_msa_param4);
    (void)dc_reg_write(adev, 2u, r->dp_msa_misc + dig_o, snap->dp_msa_misc);
    (void)dc_reg_write(adev, 2u, r->dp_vid_timing + dig_o, snap->dp_vid_timing);
    (void)dc_reg_write(adev, 2u, r->dsc_top_control + (u32)snap->pipe * r->dsc_stride, snap->dsc_top_control);
    (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, DP_STEER_FIFO_RESET_BIT);
    (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, 0u);

    /* Disable hardware cursor cleanly on boot restore. */
    (void)dc_reg_write(adev, 2u, r->cursor_control + hubp, 0u);
    (void)dc_reg_write(adev, 2u, r->dpp_cursor_control + dpp, 0u);

    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 0u);
}

/* Program DPP DSCL scaler for 1:1 bypass or arbitrary source-to-output resolution scaling. */
static void program_dpp_scaler(
    struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u8 pipe,
    u32 src_w,
    u32 src_h,
    u32 dst_w,
    u32 dst_h
) {
    u32 dpp = (u32)pipe * r->dpp_stride;
    (void)dc_reg_write(adev, 2u, r->dscl_recout_start + dpp, 0u);
    (void)dc_reg_write(adev, 2u, r->dscl_recout_size + dpp, ((dst_h & 0xFFFFu) << 16) | (dst_w & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->dscl_mpc_size + dpp, ((dst_h & 0xFFFFu) << 16) | (dst_w & 0xFFFFu));
    if (src_w == dst_w && src_h == dst_h) {
        (void)dc_reg_write(adev, 2u, r->dscl_scl_mode + dpp, 0u); /* DSCL_MODE_SCALING_BYPASS */
        (void)dc_reg_write(adev, 2u, r->dscl_h_scale_ratio + dpp, 1u << 19);
        (void)dc_reg_write(adev, 2u, r->dscl_v_scale_ratio + dpp, 1u << 19);
    } else {
        /* 1.19 fixed-point scale ratios (src / dst * 2^19) with 444 RGB scaling enabled. */
        u32 h_ratio = (u32)(((u64)src_w << 19) / (u64)dst_w);
        u32 v_ratio = (u32)(((u64)src_h << 19) / (u64)dst_h);
        (void)dc_reg_write(adev, 2u, r->dscl_h_scale_ratio + dpp, h_ratio);
        (void)dc_reg_write(adev, 2u, r->dscl_v_scale_ratio + dpp, v_ratio);
        (void)dc_reg_write(adev, 2u, r->dscl_scl_mode + dpp, 1u); /* DSCL_MODE_SCALING_444_RGB_ENABLE */
    }
}

/* Program FreeSync / Adaptive-Sync VRR (`DPCD 0x0107` + `OTG_V_TOTAL_MIN/MAX/CONTROL`). */
static void program_vrr(
    struct amdgpu_device *adev,
    const struct dc_state *dc,
    struct dc_pipe_state *p,
    bool enable
) {
    const struct dc_reg_table *r = dc->regs;
    const struct dc_connector *conn = (p->conn_idx < dc->connector_count) ? &dc->connectors[p->conn_idx] : NULL;
    u32 otg = (u32)p->pipe_idx * r->otg_stride;
    u32 v_total = p->current_mode.v_active + p->current_mode.v_blank;
    if (v_total < 240u) v_total = 1125u;

    if (enable && conn && conn->vrr_capable && conn->vrr_min_hz >= 24u) {
        u32 cur_hz = p->current_mode.refresh_mhz / 1000u;
        if (cur_hz < conn->vrr_min_hz) cur_hz = conn->vrr_min_hz;
        u32 v_max = (u32)(((u64)v_total * (u64)cur_hz) / (u64)conn->vrr_min_hz);
        if (v_max < v_total) v_max = v_total;
        if (v_max > 0xFFFFu) v_max = 0xFFFFu;

        if (conn->link_type == DC_LINK_DP_1_4 || conn->link_type == DC_LINK_DP_2_1) {
            u8 ds = 0x80u; /* MSA_TIMING_PAR_IGNORE_EN */
            (void)dc_dpcd_write(adev, r, conn->aux_idx, 0x0107u, &ds, 1u);
        }
        (void)dc_reg_write(adev, 2u, r->otg_v_total_min + otg, v_total - 1u);
        (void)dc_reg_write(adev, 2u, r->otg_v_total_max + otg, v_max - 1u);
        (void)dc_reg_write(
            adev,
            2u,
            r->otg_v_total_control + otg,
            OTG_V_TOTAL_MIN_SEL_BIT | OTG_V_TOTAL_MAX_SEL_BIT | OTG_SET_V_TOTAL_MIN_MASK_EN_BIT
        );
        p->vrr_enabled = true;
    } else {
        (void)dc_reg_write(adev, 2u, r->otg_v_total_control + otg, 0u);
        if (conn && (conn->link_type == DC_LINK_DP_1_4 || conn->link_type == DC_LINK_DP_2_1)) {
            u8 ds = 0x00u;
            (void)dc_dpcd_write(adev, r, conn->aux_idx, 0x0107u, &ds, 1u);
        }
        p->vrr_enabled = false;
    }
}

/* Program 10-bit HDR10 pixel format, CM_HDR_MULT, and DP MSA 10bpc colorimetry. */
static void program_hdr10(
    struct amdgpu_device *adev,
    const struct dc_state *dc,
    struct dc_pipe_state *p,
    bool enable
) {
    const struct dc_reg_table *r = dc->regs;
    u32 hubp = (u32)p->pipe_idx * r->hubp_stride;
    u32 dpp = (u32)p->pipe_idx * r->dpp_stride;
    u32 dig_o = (u32)p->dig_idx * r->dig_stride;

    /* DCN SURFACE_PIXEL_FORMAT: 8 = ARGB8888 (8bpc), 10 = ARGB2101010 (10bpc). */
    u32 fmt = enable ? 10u : 8u;
    (void)dc_reg_write(adev, 2u, r->hubp_surface_config + hubp, fmt);
    (void)dc_reg_write(adev, 2u, r->cnvc_pixel_format + dpp, fmt);
    (void)dc_reg_write(adev, 2u, r->cm_hdr_mult + dpp, enable ? 0x00010000u : 0x00008000u);
    /* DP MSA MISC0 bits [7:5]: 1 = 8bpc, 2 = 10bpc. */
    u32 misc = 0;
    (void)dc_reg_read(adev, 2u, r->dp_msa_misc + dig_o, &misc);
    misc = (misc & ~0xE0u) | (enable ? (2u << 5) : (1u << 5));
    (void)dc_reg_write(adev, 2u, r->dp_msa_misc + dig_o, misc);
    p->hdr_enabled = enable;
}

/* Program HUBP + DPP hardware cursor plane with premultiplied ARGB8888 buffer in VRAM. */
static int program_hw_cursor(
    struct amdgpu_device *adev,
    const struct dc_state *dc,
    struct dc_pipe_state *p,
    const u8 *rgba,
    u32 size,
    s32 x,
    s32 y,
    u16 hot_x,
    u16 hot_y
) {
    const struct dc_reg_table *r = dc->regs;
    u32 hubp = (u32)p->pipe_idx * r->hubp_stride;
    u32 dpp = (u32)p->pipe_idx * r->dpp_stride;

    if (p->cursor_mc == 0 || (size != 0 && size != 64u && size != 128u && size != 256u)) {
        return -EINVAL;
    }

    if (rgba && size > 0) {
        size_t bytes = (size_t)size * (size_t)size * 4u;
        if (bytes > 256u * 1024u) return -ERANGE;
        if (adev->io.vram_write) {
            if (adev->io.vram_write(adev->io.ctx, p->cursor_vram, rgba, bytes) != 0) {
                return -EIO;
            }
        }
        p->cursor_size = size;
    }

    u32 cx = (x < 0) ? 0u : (u32)x;
    u32 cy = (y < 0) ? 0u : (u32)y;
    u32 eff_sz = p->cursor_size ? p->cursor_size : 64u;
    u32 lo = 0, hi = 0;
    encode_mc_addr(p->cursor_mc, &lo, &hi);

    (void)dc_reg_write(adev, 2u, r->cursor_control + hubp, CURSOR_UPDATE_LOCK_BIT | CURSOR_MODE_PREMULT_ARGB | CURSOR_EN_BIT);
    (void)dc_reg_write(adev, 2u, r->cursor_addr_hi + hubp, hi);
    (void)dc_reg_write(adev, 2u, r->cursor_addr + hubp, lo);
    (void)dc_reg_write(adev, 2u, r->cursor_size + hubp, (((eff_sz - 1u) & 0xFFFFu) << 16) | ((eff_sz - 1u) & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->cursor_hot_spot + hubp, ((u32)hot_y << 16) | (u32)hot_x);
    (void)dc_reg_write(adev, 2u, r->cursor_position + hubp, ((cy & 0xFFFFu) << 16) | (cx & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->cursor_dst_offset + hubp, 0u);
    (void)dc_reg_write(adev, 2u, r->cursor_control + hubp, CURSOR_MODE_PREMULT_ARGB | CURSOR_EN_BIT);
    (void)dc_reg_write(adev, 2u, r->dpp_cursor_control + dpp, CURSOR_MODE_PREMULT_ARGB | CURSOR_EN_BIT);

    p->cursor_enabled = true;
    p->cursor_x = x;
    p->cursor_y = y;
    p->cursor_hot_x = hot_x;
    p->cursor_hot_y = hot_y;
    return 0;
}

static void write_vsync_surface_mc(struct amdgpu_device *adev, const struct dc_reg_table *r, u8 pipe, u64 mc_addr) {
    u32 hubp = (u32)pipe * r->hubp_stride;
    u32 fctl = 0;
    (void)dc_reg_read(adev, 2u, r->hubp_flip_control + hubp, &fctl);
    if ((fctl & FLIP_TYPE_IMMEDIATE_BIT) != 0) {
        (void)dc_reg_write(adev, 2u, r->hubp_flip_control + hubp, fctl & ~FLIP_TYPE_IMMEDIATE_BIT);
    }
    u32 lo = 0, hi = 0;
    encode_mc_addr(mc_addr, &lo, &hi);
    /* HIGH must always precede LOW (LOW write latches the flip). */
    (void)dc_reg_write(adev, 2u, r->hubp_primary_addr_hi + hubp, hi);
    (void)dc_reg_write(adev, 2u, r->hubp_primary_addr + hubp, lo);
}

/* Reprogram DCN pipe timing, DCCG DTO, HUBP/DSCL, DIG MSA, DSC, and verify live progression. */
static int apply_modeset(
    struct amdgpu_device *adev,
    struct dc_state *dc,
    struct dc_pipe_state *p,
    const struct dc_timing *target,
    const struct dc_dml2_plan *plan
) {
    const struct dc_reg_table *r = dc->regs;
    struct dc_connector *conn = (p->conn_idx < dc->connector_count) ? &dc->connectors[p->conn_idx] : NULL;

    /* Save pre-modeset registers for instant rollback if live verification fails. */
    struct dc_pipe_reg_snapshot prev;
    capture_pipe_snapshot(adev, r, p->pipe_idx, p->dig_idx, &prev);

    /* 1. Request SMU/PMFW minimum display clocks before increasing pixel clock. */
    (void)amdgpu_smu_set_display_clocks(
        adev,
        plan->dispclk_mhz,
        plan->dppclk_mhz,
        plan->dcfclk_mhz,
        plan->dtbclk_mhz,
        plan->uclk_mhz
    );

    /* 2. Retrain DP 1.4/2.1 or HDMI 2.1 FRL link only when target mode exceeds current trained link. */
    if (conn && conn->connected) {
        u64 cur_bw = (u64)conn->trained_lanes * (u64)conn->trained_rate_mbps;
        u64 req_bw = (u64)plan->req_lanes * (u64)plan->req_rate_mbps;
        if (req_bw > cur_bw || (plan->requires_uhbr && conn->link_type != DC_LINK_DP_2_1)) {
            int lrc = (conn->link_type == DC_LINK_HDMI_21)
                ? dc_link_train_hdmi_frl(adev, dc, conn, plan->req_lanes, plan->req_rate_mbps)
                : dc_link_train_dp(adev, dc, conn, plan->req_lanes, plan->req_rate_mbps);
            if (lrc != 0) {
                return lrc;
            }
        }
    }

    /* 3. Compute VESA DSC 1.2a PPS if required by DML2. */
    struct dc_dsc_pps pps;
    memset(&pps, 0, sizeof(pps));
    if (plan->requires_dsc) {
        int drc = dc_dsc_compute_pps(
            (u16)target->h_active,
            (u16)target->v_active,
            plan->bpc,
            plan->dsc_target_bpp_x16,
            plan->dsc_slice_count,
            &pps
        );
        if (drc != 0) {
            return drc;
        }
    }

    /* 4. Lock OTG double-buffered update, program timing/DTO/HUBP/DSCL/MSA/DSC, then unlock. */
    u32 otg = (u32)p->pipe_idx * r->otg_stride;
    u32 hubp = (u32)p->pipe_idx * r->hubp_stride;
    u32 dig_o = (u32)p->dig_idx * r->dig_stride;
    u32 dccg = (u32)p->pipe_idx * 4u;

    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 1u);

    u32 h_total = target->h_active + target->h_blank;
    u32 v_total = target->v_active + target->v_blank;
    u32 h_blank_end = target->h_blank > target->h_front_porch ? (target->h_blank - target->h_front_porch) : 8u;
    u32 h_blank_start = h_blank_end + target->h_active;
    u32 v_blank_end = target->v_blank > target->v_front_porch ? (target->v_blank - target->v_front_porch) : 4u;
    u32 v_blank_start = v_blank_end + target->v_active;

    (void)dc_reg_write(adev, 2u, r->otg_h_total + otg, (h_total - 1u) & 0xFFFFu);
    (void)dc_reg_write(adev, 2u, r->otg_h_blank + otg, ((h_blank_end & 0xFFFFu) << 16) | (h_blank_start & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->otg_h_sync_a + otg, (target->h_sync_width & 0xFFFFu) << 16);
    (void)dc_reg_write(adev, 2u, r->otg_h_sync_a_cntl + otg, target->h_sync_pos ? 0u : 1u);

    (void)dc_reg_write(adev, 2u, r->otg_v_total + otg, (v_total - 1u) & 0xFFFFu);
    (void)dc_reg_write(adev, 2u, r->otg_v_blank + otg, ((v_blank_end & 0xFFFFu) << 16) | (v_blank_start & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->otg_v_sync_a + otg, (target->v_sync_width & 0xFFFFu) << 16);
    (void)dc_reg_write(adev, 2u, r->otg_v_sync_a_cntl + otg, target->v_sync_pos ? 0u : 1u);

    /* DCCG fractional DP DTO: phase / modulo = target_pclk_khz / src_clk_khz. */
    u32 src_clk_khz = p->boot_snapshot.dto_src_clk_khz;
    if (src_clk_khz < 100000u) src_clk_khz = plan->dtbclk_mhz * 1000u;
    if (r->has_otg_pixel_rate_div && plan->pixel_rate_div >= 2u) {
        u32 pdiv = prev.dccg_pixel_rate_div;
        u32 shift = (u32)p->pipe_idx * 4u;
        pdiv = (pdiv & ~(0x0Fu << shift)) | (1u << shift);
        (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_div, pdiv);
        src_clk_khz = src_clk_khz * 2u;
    }
    u32 eff_pclk = target->pixel_clock_khz;
    if (eff_pclk > src_clk_khz) eff_pclk = src_clk_khz;
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_modulo + dccg, src_clk_khz);
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_phase + dccg, eff_pclk);
    (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_cntl + dccg, prev.dccg_pixel_rate_cntl | 1u);

    /* Reprogram HUBP viewport + pitch + DPP DSCL scaler (handles arbitrary resolution scaling!). */
    u32 pitch_px = (target->h_active + 63u) & ~63u;
    (void)dc_reg_write(adev, 2u, r->hubp_viewport_start + hubp, 0u);
    (void)dc_reg_write(adev, 2u, r->hubp_viewport_dim + hubp, ((target->v_active & 0xFFFFu) << 16) | (target->h_active & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->hubp_surface_pitch + hubp, (pitch_px - 1u) & 0x3FFFu);
    program_dpp_scaler(adev, r, p->pipe_idx, target->h_active, target->v_active, target->h_active, target->v_active);

    /* Program DIG DP Main Stream Attributes (MSA) + automatic DP M/N generation + STEER FIFO reset. */
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param1 + dig_o, ((v_total & 0xFFFFu) << 16) | (h_total & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param2 + dig_o, ((v_blank_end & 0xFFFFu) << 16) | (h_blank_end & 0xFFFFu));
    (void)dc_reg_write(
        adev,
        2u,
        r->dp_msa_timing_param3 + dig_o,
        ((target->v_sync_width & 0x7FFFu) << 16) | (target->h_sync_width & 0x7FFFu)
    );
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param4 + dig_o, ((target->v_active & 0xFFFFu) << 16) | (target->h_active & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->dp_vid_timing + dig_o, prev.dp_vid_timing | DP_VID_M_N_GEN_EN_BIT);
    (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, DP_STEER_FIFO_RESET_BIT);
    (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, 0u);

    /* Program DSC 1.2a hardware encoder & DPCD 0x0160 if needed. */
    (void)dc_dsc_program_hw(adev, dc, p->pipe_idx, plan->requires_dsc ? &pps : NULL, plan->requires_dsc);
    if (conn && (conn->link_type == DC_LINK_DP_1_4 || conn->link_type == DC_LINK_DP_2_1) && conn->dsc_capable) {
        u8 dsc_en = plan->requires_dsc ? 0x01u : 0x00u;
        (void)dc_dpcd_write(adev, r, conn->aux_idx, 0x0160u, &dsc_en, 1u);
    }

    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 0u);

    /* 5. Live post-modeset verification: confirm OTG frame counter advances cleanly without stalling. */
    u32 fc0 = read_otg_frame_count(adev, r, p->pipe_idx);
    amdgpu_udelay(adev, 20000u); /* 20 ms covers >= 1 frame at >= 50 Hz */
    u32 fc1 = read_otg_frame_count(adev, r, p->pipe_idx);
    if (frame_count_delta(fc1, fc0) == 0) {
        /* Second brief check for low-refresh panels (24-48 Hz). */
        amdgpu_udelay(adev, 30000u);
        fc1 = read_otg_frame_count(adev, r, p->pipe_idx);
    }
    if (frame_count_delta(fc1, fc0) == 0) {
        restore_pipe_snapshot(adev, r, &prev);
        return -EIO;
    }

    p->current_mode = *target;
    p->src_width = target->h_active;
    p->src_height = target->v_active;
    p->pitch_bytes = pitch_px * 4u;
    p->dsc_enabled = plan->requires_dsc;
    p->dsc_pps = pps;
    p->active_plan = *plan;
    if (p->vrr_enabled) {
        program_vrr(adev, dc, p, true);
    }
    return 0;
}

int dc_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    const struct dc_reg_table *r = dc_regs_for_version(adev->dcn_version);
    if (!r) {
        return -ENODEV;
    }
    struct dc_state *dc = (struct dc_state *)kzalloc(sizeof(struct dc_state), GFP_KERNEL);
    if (!dc) {
        return -ENOMEM;
    }
    dc->regs = r;
    adev->dc = dc;

    /* 1. Initialize DMCUB display microcontroller & inbox/outbox ring. */
    (void)dc_dmub_init(adev, dc);

    /* 2. Probe all DP / HDMI connectors (HPD + DPCD 1.4/2.1 + E-DDC EDID/DisplayID 2.0). */
    (void)dc_link_probe_all(adev, dc);

    /* 3. Read-only active pipe discovery (finds UEFI GOP active pipes without touching display). */
    dc->active_pipe_count = 0;
    for (u8 pipe = 0; pipe < r->max_pipes && pipe < DC_MAX_PIPES; pipe++) {
        u32 otg_ctl = 0, hubp_ctl = 0, ht = 0, vt = 0, hb = 0, vb = 0;
        if (!dc_reg_read(adev, 2u, r->otg_control + (u32)pipe * r->otg_stride, &otg_ctl)) continue;
        if ((otg_ctl & OTG_MASTER_EN_BIT) == 0) continue;
        if (!dc_reg_read(adev, 2u, r->hubp_cntl + (u32)pipe * r->hubp_stride, &hubp_ctl)) continue;
        if ((hubp_ctl & HUBP_BLANK_EN_BIT) != 0) continue;

        (void)dc_reg_read(adev, 2u, r->otg_h_total + (u32)pipe * r->otg_stride, &ht);
        (void)dc_reg_read(adev, 2u, r->otg_v_total + (u32)pipe * r->otg_stride, &vt);
        (void)dc_reg_read(adev, 2u, r->otg_h_blank + (u32)pipe * r->otg_stride, &hb);
        (void)dc_reg_read(adev, 2u, r->otg_v_blank + (u32)pipe * r->otg_stride, &vb);

        u32 h_total = (ht & 0xFFFFu) + 1u;
        u32 v_total = (vt & 0xFFFFu) + 1u;
        u32 h_bstart = hb & 0xFFFFu;
        u32 h_bend = (hb >> 16) & 0xFFFFu;
        u32 v_bstart = vb & 0xFFFFu;
        u32 v_bend = (vb >> 16) & 0xFFFFu;
        u32 w = (h_bstart > h_bend) ? (h_bstart - h_bend) : 0u;
        u32 h = (v_bstart > v_bend) ? (v_bstart - v_bend) : 0u;
        if (w < 320u || w > 7680u || h < 200u || h > 4320u) continue;

        struct dc_pipe_state *p = &dc->pipes[dc->active_pipe_count];
        memset(p, 0, sizeof(*p));
        p->active = true;
        p->pipe_idx = pipe;
        p->dig_idx = (u8)find_dig_for_pipe(adev, r, pipe);
        p->pending_buf = -1;

        /* Pair with first connected connector (or matching index). */
        p->conn_idx = 0;
        for (u32 ci = 0; ci < dc->connector_count; ci++) {
            if (dc->connectors[ci].connected) {
                p->conn_idx = (u8)ci;
                if (ci == p->dig_idx) break;
            }
        }

        capture_pipe_snapshot(adev, r, pipe, p->dig_idx, &p->boot_snapshot);

        /* Measure live refresh rate from OTG_STATUS_FRAME_COUNT over ~35 ms. */
        u32 fc0 = read_otg_frame_count(adev, r, pipe);
        u64 t0 = amdgpu_now_ns(adev);
        amdgpu_udelay(adev, 35000u);
        u32 fc1 = read_otg_frame_count(adev, r, pipe);
        u64 t1 = amdgpu_now_ns(adev);
        u32 df = frame_count_delta(fc1, fc0);
        u32 refresh_mhz = 60000u;
        if (df > 0 && t1 > t0) {
            u64 dt_ns = t1 - t0;
            u64 mhz = ((u64)df * 1000000000000ULL) / dt_ns;
            if (mhz >= 24000ULL && mhz <= 1000000ULL) {
                refresh_mhz = (u32)mhz;
            }
        }

        dc_timing_cvt_rb(w, h, refresh_mhz, &p->current_mode);
        p->current_mode.h_blank = (h_total > w) ? (h_total - w) : 80u;
        p->current_mode.v_blank = (v_total > h) ? (v_total - h) : 45u;
        p->current_mode.refresh_mhz = refresh_mhz;
        p->current_mode.pixel_clock_khz = (u32)(((u64)h_total * (u64)v_total * (u64)refresh_mhz) / 1000000ULL);
        p->src_width = w;
        p->src_height = h;
        p->pitch_bytes = ((p->boot_snapshot.hubp_surface_pitch & 0x3FFFu) + 1u) * 4u;
        if (p->pitch_bytes < w * 4u) p->pitch_bytes = ((w + 63u) & ~63u) * 4u;
        p->boot_snapshot.src_width = w;
        p->boot_snapshot.src_height = h;
        p->boot_snapshot.dst_width = w;
        p->boot_snapshot.dst_height = h;
        p->boot_snapshot.refresh_mhz = refresh_mhz;
        if (p->boot_snapshot.dccg_dto_modulo > 0 && p->boot_snapshot.dccg_dto_phase > 0) {
            p->boot_snapshot.dto_src_clk_khz = (u32)(((u64)p->current_mode.pixel_clock_khz * (u64)p->boot_snapshot.dccg_dto_modulo) / (u64)p->boot_snapshot.dccg_dto_phase);
        } else {
            p->boot_snapshot.dto_src_clk_khz = 1000000u; /* 1000 MHz DTBCLK default */
        }

        /* Protect original UEFI GOP VRAM range and allocate triple-buffered scanout + 256 KiB HW cursor. */
        u64 gop_vram = 0;
        if (amdgpu_gmc_mc_to_vram(&adev->gmc, p->boot_snapshot.orig_mc_addr, &gop_vram)) {
            adev->gmc.gop_vram_start = gop_vram;
            adev->gmc.gop_vram_size = (u64)p->pitch_bytes * (u64)h;
            if (adev->gmc.gop_vram_size < (8ULL << 20)) adev->gmc.gop_vram_size = (8ULL << 20);
        }

        /* Allocate 3 scanout buffers sized for up to 4K (3840x2160x4 = 32 MiB max or current pitch*h). */
        u64 max_buf = (u64)p->pitch_bytes * (u64)h;
        if (max_buf < (16ULL << 20)) max_buf = (16ULL << 20);
        p->scanout_buf_size = max_buf;
        p->buf_count = 0;
        for (u32 b = 0; b < DC_MAX_SCANOUT_BUFS; b++) {
            u64 vo = 0, mc = 0;
            if (amdgpu_gmc_alloc_vram(&adev->gmc, max_buf, 65536u, 0x53434E30u + b, &vo) == 0
                && amdgpu_gmc_vram_to_mc(&adev->gmc, vo, &mc)) {
                p->scanout_vram[p->buf_count] = vo;
                p->scanout_mc[p->buf_count] = mc;
                p->buf_count++;
            }
        }
        /* Allocate 256 KiB hardware cursor buffer in visible VRAM. */
        u64 cur_vo = 0, cur_mc = 0;
        if (amdgpu_gmc_alloc_vram(&adev->gmc, 256u * 1024u, 4096u, 0x43555253u, &cur_vo) == 0
            && amdgpu_gmc_vram_to_mc(&adev->gmc, cur_vo, &cur_mc)) {
            p->cursor_vram = cur_vo;
            p->cursor_mc = cur_mc;
        }

        /* Ensure the active mode is present in the connector's mode list. */
        if (p->conn_idx < dc->connector_count) {
            struct dc_connector *conn = &dc->connectors[p->conn_idx];
            if (conn->mode_count == 0) {
                conn->connected = true;
                conn->modes[0] = p->current_mode;
                conn->modes[0].preferred = true;
                conn->mode_count = 1u;
            } else {
                dc_connector_push_mode(conn, &p->current_mode);
            }
        }

        /* Perform fast 1-vblank flip latch verification only if we have >=2 scanout buffers. */
        if (p->buf_count >= 2u && df > 0) {
            p->verified = true;
        }

        dc->active_pipe_count++;
    }

    adev->native_kms_active = (dc->active_pipe_count > 0 && dc->pipes[0].verified);
    return 0;
}

void dc_fini(struct amdgpu_device *adev) {
    if (!adev || !adev->dc) {
        return;
    }
    struct dc_state *dc = adev->dc;
    for (u32 i = 0; i < dc->active_pipe_count; i++) {
        restore_pipe_snapshot(adev, dc->regs, &dc->pipes[i].boot_snapshot);
        for (u32 b = 0; b < dc->pipes[i].buf_count; b++) {
            amdgpu_gmc_free_vram(&adev->gmc, dc->pipes[i].scanout_vram[b]);
        }
        if (dc->pipes[i].cursor_mc != 0) {
            amdgpu_gmc_free_vram(&adev->gmc, dc->pipes[i].cursor_vram);
        }
    }
    dc_dmub_fini(adev, dc);
    kfree(dc);
    adev->dc = NULL;
    adev->native_kms_active = false;
}

int dc_suspend(struct amdgpu_device *adev) {
    if (!adev || !adev->dc) {
        return 0;
    }
    struct dc_state *dc = adev->dc;
    for (u32 i = 0; i < dc->active_pipe_count; i++) {
        struct dc_pipe_state *p = &dc->pipes[i];
        capture_pipe_snapshot(adev, dc->regs, p->pipe_idx, p->dig_idx, &p->suspend_snapshot);
        p->suspend_snapshot.src_width = p->src_width;
        p->suspend_snapshot.src_height = p->src_height;
        p->suspend_snapshot.dst_width = p->current_mode.h_active;
        p->suspend_snapshot.dst_height = p->current_mode.v_active;
        p->suspend_snapshot.refresh_mhz = p->current_mode.refresh_mhz;
        restore_pipe_snapshot(adev, dc->regs, &p->boot_snapshot);
    }
    return 0;
}

int dc_resume(struct amdgpu_device *adev) {
    if (!adev || !adev->dc) {
        return -ENODEV;
    }
    struct dc_state *dc = adev->dc;
    (void)dc_dmub_init(adev, dc);
    (void)dc_link_probe_all(adev, dc);
    for (u32 i = 0; i < dc->active_pipe_count; i++) {
        struct dc_pipe_state *p = &dc->pipes[i];
        if (!p->suspend_snapshot.valid) continue;
        const struct dc_connector *conn = (p->conn_idx < dc->connector_count) ? &dc->connectors[p->conn_idx] : NULL;
        struct dc_dml2_plan plan;
        if (dc_dml2_plan_mode(adev, conn, &p->current_mode, p->hdr_enabled ? 10u : 8u, &plan) == 0) {
            (void)apply_modeset(adev, dc, p, &p->current_mode, &plan);
        } else {
            restore_pipe_snapshot(adev, dc->regs, &p->suspend_snapshot);
        }
        if (p->vrr_enabled) program_vrr(adev, dc, p, true);
        if (p->hdr_enabled) program_hdr10(adev, dc, p, true);
    }
    return 0;
}

int dc_atomic_check_and_commit(
    struct amdgpu_device *adev,
    const struct dc_atomic_req *req,
    u64 *out_vblank_seq,
    bool *out_async
) {
    if (!adev || !adev->dc || !req || !out_vblank_seq || !out_async) {
        return -EINVAL;
    }
    struct dc_state *dc = adev->dc;
    if (dc->active_pipe_count == 0) {
        return -ENODEV;
    }
    u32 idx = (req->pipe_slot < dc->active_pipe_count) ? req->pipe_slot : 0u;
    struct dc_pipe_state *p = &dc->pipes[idx];
    const struct dc_connector *conn = (p->conn_idx < dc->connector_count) ? &dc->connectors[p->conn_idx] : NULL;

    if (req->reset_boot) {
        if (!req->test_only) {
            restore_pipe_snapshot(adev, dc->regs, &p->boot_snapshot);
            p->vrr_enabled = false;
            p->hdr_enabled = false;
            p->dsc_enabled = false;
            p->cursor_enabled = false;
            p->current_mode.h_active = p->boot_snapshot.dst_width;
            p->current_mode.v_active = p->boot_snapshot.dst_height;
            p->current_mode.refresh_mhz = p->boot_snapshot.refresh_mhz;
            p->pending_buf = -1;
        }
        *out_vblank_seq = p->vblank_seq;
        *out_async = false;
        return 0;
    }

    /* Validate VRR & HDR10 requests against connector capability. */
    if (req->vrr_changed && req->vrr_enable && (!conn || !conn->vrr_capable)) {
        return -ENOTSUP;
    }
    if (req->hdr_changed && req->hdr_enable && (!conn || !conn->hdr_capable)) {
        return -ENOTSUP;
    }

    /* Resolve & DML2-validate target mode if mode_changed is set. */
    struct dc_timing target_timing = p->current_mode;
    struct dc_dml2_plan plan;
    memset(&plan, 0, sizeof(plan));
    bool need_modeset = req->mode_changed;
    if (need_modeset) {
        if (!req->allow_modeset) {
            return -EINVAL;
        }
        u32 target_hz = req->mode_refresh_mhz ? req->mode_refresh_mhz : 60000u;
        bool matched = false;
        if (conn) {
            for (u32 m = 0; m < conn->mode_count; m++) {
                u32 d = conn->modes[m].refresh_mhz > target_hz
                    ? (conn->modes[m].refresh_mhz - target_hz)
                    : (target_hz - conn->modes[m].refresh_mhz);
                if (conn->modes[m].h_active == req->mode_width
                    && conn->modes[m].v_active == req->mode_height
                    && d <= 1500u) {
                    target_timing = conn->modes[m];
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            dc_timing_cvt_rb(req->mode_width, req->mode_height, target_hz, &target_timing);
            if (target_timing.pixel_clock_khz == 0) {
                return -EINVAL;
            }
        }
        u8 bpc = (req->hdr_changed ? req->hdr_enable : p->hdr_enabled) ? 10u : 8u;
        int dml_rc = dc_dml2_plan_mode(adev, conn, &target_timing, bpc, &plan);
        if (dml_rc != 0) {
            return dml_rc;
        }
    }

    /* ATOMIC_TEST_ONLY stops cleanly here without mutating hardware registers. */
    if (req->test_only) {
        *out_vblank_seq = p->vblank_seq;
        *out_async = false;
        return 0;
    }

    if (need_modeset) {
        int mrc = apply_modeset(adev, dc, p, &target_timing, &plan);
        if (mrc != 0) {
            return mrc;
        }
    }

    if (req->vrr_changed) {
        program_vrr(adev, dc, p, req->vrr_enable);
    }
    if (req->hdr_changed) {
        program_hdr10(adev, dc, p, req->hdr_enable);
    }

    if (req->cursor_changed) {
        if (req->cursor_src || p->cursor_enabled) {
            (void)program_hw_cursor(
                adev,
                dc,
                p,
                req->cursor_src,
                req->cursor_size,
                req->cursor_x,
                req->cursor_y,
                req->cursor_hot_x,
                req->cursor_hot_y
            );
        }
    }

    *out_async = false;
    if (req->primary_changed && req->primary_src && p->buf_count > 0) {
        u32 next_buf = (p->front_buf + 1u) % p->buf_count;
        u64 dst_vram = p->scanout_vram[next_buf];
        u64 dst_mc = p->scanout_mc[next_buf];
        u32 copy_h = req->primary_height < p->current_mode.v_active ? req->primary_height : p->current_mode.v_active;
        u32 row_bytes = req->primary_width * 4u;
        if (row_bytes > req->primary_pitch) row_bytes = req->primary_pitch;
        if (row_bytes > p->pitch_bytes) row_bytes = p->pitch_bytes;

        /* Update DPP scaler if client backbuffer dimensions differ from output mode. */
        if (req->primary_width != p->src_width || req->primary_height != p->src_height) {
            u32 hubp = (u32)p->pipe_idx * dc->regs->hubp_stride;
            (void)dc_reg_write(
                adev,
                2u,
                dc->regs->hubp_viewport_dim + hubp,
                ((req->primary_height & 0xFFFFu) << 16) | (req->primary_width & 0xFFFFu)
            );
            program_dpp_scaler(
                adev,
                dc->regs,
                p->pipe_idx,
                req->primary_width,
                req->primary_height,
                p->current_mode.h_active,
                p->current_mode.v_active
            );
            p->src_width = req->primary_width;
            p->src_height = req->primary_height;
        }

        if (adev->io.vram_write) {
            if (req->primary_pitch == p->pitch_bytes && row_bytes == p->pitch_bytes) {
                (void)adev->io.vram_write(adev->io.ctx, dst_vram, req->primary_src, (size_t)p->pitch_bytes * (size_t)copy_h);
            } else {
                for (u32 y = 0; y < copy_h; y++) {
                    (void)adev->io.vram_write(
                        adev->io.ctx,
                        dst_vram + (u64)y * (u64)p->pitch_bytes,
                        req->primary_src + (size_t)y * (size_t)req->primary_pitch,
                        row_bytes
                    );
                }
            }
        }
        wmb();
        write_vsync_surface_mc(adev, dc->regs, p->pipe_idx, dst_mc);
        p->front_buf = next_buf;
        p->pending_buf = (s32)next_buf;
        p->pending_mc = dst_mc;
        p->last_flip_ns = amdgpu_now_ns(adev);
        p->vblank_seq++;
        p->flips_completed++;
        *out_async = true;
    }

    *out_vblank_seq = p->vblank_seq;
    return 0;
}

bool dc_poll_vblank(
    struct amdgpu_device *adev,
    u32 *out_pipe,
    u64 *out_seq,
    u64 *out_ts_ns,
    bool *out_late
) {
    if (!adev || !adev->dc || !out_pipe || !out_seq || !out_ts_ns || !out_late) {
        return false;
    }
    struct dc_state *dc = adev->dc;
    /* Drain OSSSYS IH events first to catch hardware FlipDone / Vblank / HPD IRQs. */
    struct amdgpu_ih_event evs[16];
    u32 nev = amdgpu_ih_drain(adev, evs, 16u);
    for (u32 i = 0; i < nev; i++) {
        if (evs[i].src_id == AMDGPU_IH_SRCID_DC_HPD) {
            (void)dc_link_poll_hotplug(adev, dc);
        }
    }

    u64 now = amdgpu_now_ns(adev);
    for (u32 i = 0; i < dc->active_pipe_count; i++) {
        struct dc_pipe_state *p = &dc->pipes[i];
        if (p->pending_buf < 0) continue;
        u32 hubp = (u32)p->pipe_idx * dc->regs->hubp_stride;
        u32 fctl = 0;
        (void)dc_reg_read(adev, 2u, dc->regs->hubp_flip_control + hubp, &fctl);
        u64 frame_ns = p->current_mode.refresh_mhz
            ? (1000000000000ULL / (u64)p->current_mode.refresh_mhz)
            : 16666667ULL;
        bool hw_done = ((fctl & FLIP_PENDING_BIT) == 0);
        bool timer_done = (now >= p->last_flip_ns + frame_ns);
        if (hw_done || timer_done) {
            bool late = (now > p->last_flip_ns + frame_ns * 2ULL);
            p->pending_buf = -1;
            *out_pipe = i;
            *out_seq = p->vblank_seq;
            *out_ts_ns = now;
            *out_late = late;
            return true;
        }
    }
    return false;
}
