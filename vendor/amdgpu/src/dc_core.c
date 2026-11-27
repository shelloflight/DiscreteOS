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

#define OTG_MASTER_EN_MASK                 ((1u << 0) | (1u << 16))
#define HUBP_BLANK_EN_BIT                  (1u << 0)
#define HUBP_VREADY_AT_OR_AFTER_VSYNC_BIT  (1u << 8)
#define HUBP_UNDERFLOW_CLEAR_BIT           (1u << 31)
#define OPTC_UNDERFLOW_CLEAR_BIT           (1u << 12)
#define DENTIST_DISPCLK_CHG_DONE_BIT       (1u << 19)
#define DENTIST_DPPCLK_CHG_DONE_BIT        (1u << 20)
/* Navi 48 / DCN 4.0.1 CLK01 DFS PLL & slices (`dcn401_clk_mgr.c`, byte offsets inside BAR5). */
#define DCN401_CLK0_PLL_REQ_BYTE           (0x16E37ULL * 4ULL)
#define DCN401_CLK0_DISP_DFS_BYTE          (0x16E69ULL * 4ULL)
#define DCN401_CLK0_DPP_DFS_BYTE           (0x16E6CULL * 4ULL)
#define DCN401_CLK0_DCF_DFS_BYTE           (0x16E72ULL * 4ULL)
#define DCN401_CLK0_DTB_DFS_BYTE           (0x16E75ULL * 4ULL)
#define FLIP_TYPE_IMMEDIATE_BIT            (1u << 1)
#define FLIP_PENDING_BIT                   (1u << 8)
#define DP_DTO_ENABLE_BIT                  (1u << 4)
#define PIPE_DTO_SRC_SEL_BIT               (1u << 12)
#define DP_VID_M_N_GEN_EN_BIT              (1u << 8)  /* dcn_4_1_0_sh_mask.h: DP_VID_M_N_GEN_EN__SHIFT = 0x8 */
#define DP_VID_STREAM_ENABLE_BIT           (1u << 0)
#define DP_VID_STREAM_DIS_DEFER_MASK       (0x3u << 8)
#define DP_VID_STREAM_STATUS_BIT           (1u << 16)
#define DP_STEER_FIFO_ENABLE_BIT_401       (1u << 0)  /* dcn_4_1_0_sh_mask.h: bit 0 = ENABLE, bit 1 = RESET */
#define DP_STEER_FIFO_RESET_BIT_401        (1u << 1)
#define DP_STEER_FIFO_RESET_BIT_3X         (1u << 0)  /* DCN 3.0/3.1.5/3.2: bit 0 = RESET */
#define DIG_FIFO_ENABLE_BIT                (1u << 0)
#define DIG_FIFO_RESET_BIT                 (1u << 1)
#define DIG_FIFO_READ_START_LEVEL_MASK     (0x1Fu << 2)
#define DIG_FIFO_READ_START_LEVEL_7        (0x7u << 2)
#define DIG_FIFO_RESET_DONE_BIT            (1u << 20)
#define CURSOR_EN_BIT                      (1u << 0)
#define CURSOR_MODE_ARGB_UNPREMUL          3u
#define OTG_V_TOTAL_MIN_SEL_BIT            (1u << 0)
#define OTG_V_TOTAL_MAX_SEL_BIT            (1u << 1)
#define OTG_SET_V_TOTAL_MIN_MASK_EN_BIT    (1u << 3)
#define OTG_SET_V_TOTAL_MIN_MASK_FLIP      ((1u << 1) << 16)

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

/* Lightweight freestanding log builder for bare-metal diagnostics (`log amdgpu`). */
struct dc_log_buf {
    char data[256];
    size_t len;
};

static void dlog_str(struct dc_log_buf *b, const char *s) {
    if (!b || !s) return;
    while (*s && b->len + 1u < sizeof(b->data)) {
        b->data[b->len++] = *s++;
    }
    b->data[b->len] = '\0';
}

static void dlog_u32(struct dc_log_buf *b, u32 v) {
    char tmp[12];
    size_t n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0 && n < sizeof(tmp)) {
            tmp[n++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
    }
    while (n > 0 && b->len + 1u < sizeof(b->data)) {
        b->data[b->len++] = tmp[--n];
    }
    b->data[b->len] = '\0';
}

static void dlog_hex(struct dc_log_buf *b, u32 v) {
    static const char hex[] = "0123456789abcdef";
    dlog_str(b, "0x");
    bool started = false;
    for (int sh = 28; sh >= 0; sh -= 4) {
        u32 nib = (v >> (u32)sh) & 0xFu;
        if (nib != 0 || started || sh == 0) {
            started = true;
            if (b->len + 1u < sizeof(b->data)) {
                b->data[b->len++] = hex[nib];
            }
        }
    }
    b->data[b->len] = '\0';
}

static void dlog_emit(const struct amdgpu_device *adev, const struct dc_log_buf *b) {
    if (adev && adev->io.log && b && b->len > 0) {
        adev->io.log(adev->io.ctx, b->data);
    }
}

/* Measure live OTG refresh rate in mHz over ~15-55 ms using OTG_STATUS_FRAME_COUNT. */
static u32 measure_otg_refresh_mhz(
    const struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u8 pipe,
    u32 *out_total_df
) {
    u32 fc0 = read_otg_frame_count(adev, r, pipe);
    u32 fc_start = fc0;
    u64 t_start = amdgpu_now_ns(adev);
    for (u32 step = 0; step < 25u; step++) {
        amdgpu_udelay(adev, 1000u);
        u32 cur = read_otg_frame_count(adev, r, pipe);
        if (cur != fc0) {
            fc_start = cur;
            t_start = amdgpu_now_ns(adev);
            break;
        }
    }
    u32 fc_last = fc_start;
    u64 t_last = t_start;
    for (u32 step = 0; step < 50u; step++) {
        amdgpu_udelay(adev, 1000u);
        u32 cur = read_otg_frame_count(adev, r, pipe);
        if (cur != fc_last) {
            fc_last = cur;
            t_last = amdgpu_now_ns(adev);
            if (frame_count_delta(fc_last, fc_start) >= 3u && (t_last - t_start) >= 12000000ULL) {
                break;
            }
        }
    }
    u32 df = frame_count_delta(fc_last, fc_start);
    if (out_total_df) {
        *out_total_df = frame_count_delta(fc_last, fc0);
    }
    if (df > 0 && t_last > t_start) {
        u64 dt_ns = t_last - t_start;
        u64 mhz = ((u64)df * 1000000000000ULL) / dt_ns;
        if (mhz >= 20000ULL && mhz <= 1000000ULL) {
            return (u32)mhz;
        }
    }
    return 0u;
}

/* Locate the live DIG stream encoder driving `pipe`.
 * On DCN 3.2/4.0.1 DIG_FE (stream encoder) and DIG_BE (link encoder) are decoupled, so matching
 * live DP_MSA_TIMING_PARAM4/PARAM1 against the active OTG geometry finds the exact stream encoder
 * even when physical port index != stream encoder index. */
static u32 find_dig_for_pipe(
    const struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u8 pipe,
    u32 w,
    u32 h,
    u32 h_total,
    u32 v_total
) {
    for (u8 enc = 0; enc < 5u; enc++) {
        u32 p4 = 0, p1 = 0;
        if (!dc_reg_read(adev, 2u, r->dp_msa_timing_param4 + (u32)enc * r->dig_stride, &p4)) continue;
        if (p4 == 0 || p4 == 0xFFFFFFFFu) continue;
        bool h_low = ((p4 & 0xFFFFu) == w && ((p4 >> 16) & 0xFFFFu) == h);
        bool h_high = (((p4 >> 16) & 0xFFFFu) == w && (p4 & 0xFFFFu) == h);
        if (!h_low && !h_high) continue;
        (void)dc_reg_read(adev, 2u, r->dp_msa_timing_param1 + (u32)enc * r->dig_stride, &p1);
        if (p1 != 0 && p1 != 0xFFFFFFFFu) {
            bool p1_ok = h_low
                ? ((p1 & 0xFFFFu) == h_total && ((p1 >> 16) & 0xFFFFu) == v_total)
                : (((p1 >> 16) & 0xFFFFu) == h_total && (p1 & 0xFFFFu) == v_total);
            if (!p1_ok) continue;
        }
        return enc;
    }
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

/* Read-only probe of DPP geometry registers (`DSCL_RECOUT_SIZE`, `DSCL_MPC_SIZE`) holding
 * `(height << 16) | width`, used when static DSCL offsets do not match live hardware. */
static void probe_dpp_size_regs(
    const struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u8 pipe,
    u32 w,
    u32 h,
    struct dc_pipe_reg_snapshot *snap
) {
    snap->dpp_size_reg_count = 0;
    if (w < 320u || h < 200u || w > 0x3FFFu || h > 0x3FFFu) return;
    u32 target = (w & 0x3FFFu) | ((h & 0x3FFFu) << 16);
    u32 dpp = (u32)pipe * r->dpp_stride;
    u32 start = r->cnvc_pixel_format + dpp + 1u;
    u32 end = r->cm_hdr_mult + dpp;
    if (end <= start || (end - start) > 512u) return;
    u8 found = 0;
    for (u32 off = start; off < end; off++) {
        u32 v = 0;
        if (dc_reg_read(adev, 2u, off, &v) && v == target) {
            if (found >= 4u) {
                snap->dpp_size_reg_count = 0;
                return;
            }
            snap->dpp_size_regs[found] = off;
            snap->dpp_size_saved[found] = v;
            found++;
        }
    }
    snap->dpp_size_reg_count = found;
}

/* Blank DP video stream cleanly before modifying OTG timing/clocks or resetting FIFOs
 * (matches `enc1_stream_encoder_dp_blank` + `enc35_disable_fifo`). */
static void dp_stream_blank(struct amdgpu_device *adev, const struct dc_reg_table *r, u32 dig_o) {
    if (r->dp_vid_stream_cntl != 0) {
        u32 cntl = 0;
        if (dc_reg_read(adev, 2u, r->dp_vid_stream_cntl + dig_o, &cntl) && cntl != 0xFFFFFFFFu) {
            if ((cntl & DP_VID_STREAM_ENABLE_BIT) != 0) {
                (void)dc_reg_write(adev, 2u, r->dp_vid_stream_cntl + dig_o, cntl & ~DP_VID_STREAM_ENABLE_BIT);
                for (u32 i = 0; i < 500u; i++) {
                    u32 st = 0;
                    if (!dc_reg_read(adev, 2u, r->dp_vid_stream_cntl + dig_o, &st)) break;
                    if ((st & DP_VID_STREAM_STATUS_BIT) == 0) break;
                    amdgpu_udelay(adev, 100u);
                }
            }
        }
    }
    if (r->has_dig_fifo_ctrl && r->dig_fifo_ctrl0 != 0) {
        u32 df = 0;
        if (dc_reg_read(adev, 2u, r->dig_fifo_ctrl0 + dig_o, &df) && df != 0xFFFFFFFFu) {
            (void)dc_reg_write(adev, 2u, r->dig_fifo_ctrl0 + dig_o, df & ~DIG_FIFO_ENABLE_BIT);
        }
    }
}

/* Reset & re-enable DP_STEER_FIFO, DIG_FIFO_CTRL0 (DCN 4.0.1), and DP_VID_STREAM_CNTL after
 * OTG latches the new timing/pixel clock (`enc401_stream_encoder_dp_unblank`). */
static void dp_stream_resync_and_unblank(
    struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u32 dig_o,
    u32 saved_steer,
    u32 saved_vid_stream,
    u32 saved_dig_fifo
) {
    if (r->has_dig_fifo_ctrl) {
        /* DCN 4.0.1 (`dcn_4_1_0_sh_mask.h`): DP_STEER_FIFO bit 0 = ENABLE, bit 1 = RESET! */
        u32 steer_base = saved_steer & ~DP_STEER_FIFO_RESET_BIT_401;
        (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, steer_base | DP_STEER_FIFO_RESET_BIT_401);
        amdgpu_udelay(adev, 10u);
        (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, steer_base);
        (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, steer_base | DP_STEER_FIFO_ENABLE_BIT_401);

        if (r->dp_vid_stream_cntl != 0) {
            u32 vs = (saved_vid_stream & ~DP_VID_STREAM_DIS_DEFER_MASK)
                | DP_VID_STREAM_ENABLE_BIT
                | (2u << 8);
            (void)dc_reg_write(adev, 2u, r->dp_vid_stream_cntl + dig_o, vs);
            amdgpu_udelay(adev, 200u);
        }

        /* DCN 4.0.1 DIG resync FIFO (`DIG_FIFO_CTRL0`, 0x209B): ensure ENABLE=0 during reset,
         * set start level = 7, pulse RESET (bit 1), wait for RESET_DONE (bit 20), then set ENABLE=1. */
        if (r->dig_fifo_ctrl0 != 0) {
            u32 df = (saved_dig_fifo & ~(DIG_FIFO_ENABLE_BIT | DIG_FIFO_READ_START_LEVEL_MASK | DIG_FIFO_RESET_BIT))
                | DIG_FIFO_READ_START_LEVEL_7;
            (void)dc_reg_write(adev, 2u, r->dig_fifo_ctrl0 + dig_o, df);
            (void)dc_reg_write(adev, 2u, r->dig_fifo_ctrl0 + dig_o, df | DIG_FIFO_RESET_BIT);
            for (u32 i = 0; i < 500u; i++) {
                u32 st = 0;
                if (!dc_reg_read(adev, 2u, r->dig_fifo_ctrl0 + dig_o, &st)) break;
                if ((st & DIG_FIFO_RESET_DONE_BIT) != 0) break;
                amdgpu_udelay(adev, 10u);
            }
            (void)dc_reg_write(adev, 2u, r->dig_fifo_ctrl0 + dig_o, df);
            for (u32 i = 0; i < 500u; i++) {
                u32 st = 0;
                if (!dc_reg_read(adev, 2u, r->dig_fifo_ctrl0 + dig_o, &st)) break;
                if ((st & DIG_FIFO_RESET_DONE_BIT) == 0) break;
                amdgpu_udelay(adev, 10u);
            }
            (void)dc_reg_write(adev, 2u, r->dig_fifo_ctrl0 + dig_o, df | DIG_FIFO_ENABLE_BIT);
            amdgpu_udelay(adev, 100u);
        }

        if (r->dp_vid_stream_cntl != 0) {
            u32 vs = (saved_vid_stream & ~DP_VID_STREAM_DIS_DEFER_MASK)
                | DP_VID_STREAM_ENABLE_BIT
                | (2u << 8);
            (void)dc_reg_write(adev, 2u, r->dp_vid_stream_cntl + dig_o, vs);
        }
    } else {
        /* DCN 3.0 / 3.1.5 / 3.2: DP_STEER_FIFO bit 0 = RESET. */
        (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, saved_steer | DP_STEER_FIFO_RESET_BIT_3X);
        amdgpu_udelay(adev, 10u);
        (void)dc_reg_write(adev, 2u, r->dp_steer_fifo + dig_o, saved_steer & ~DP_STEER_FIFO_RESET_BIT_3X);
        if (r->dp_vid_stream_cntl != 0) {
            (void)dc_reg_write(adev, 2u, r->dp_vid_stream_cntl + dig_o, saved_vid_stream | DP_VID_STREAM_ENABLE_BIT);
        }
    }
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
    (void)dc_reg_read(adev, 2u, r->otg_double_buffer_control + otg, &snap->otg_double_buffer_control);
    if (r->otg_vstartup_param != 0) {
        (void)dc_reg_read(adev, 2u, r->otg_vstartup_param + otg, &snap->otg_vstartup_param);
    }
    if (r->vtg_control != 0) {
        (void)dc_reg_read(adev, 2u, r->vtg_control + (u32)pipe, &snap->vtg_control);
    }

    if (r->dccg_dentist_dispclk_cntl != 0) {
        (void)dc_reg_read(adev, 1u, r->dccg_dentist_dispclk_cntl, &snap->dccg_dentist_dispclk_cntl);
    }
    if (r->has_otg_pixel_rate_div) {
        (void)dc_reg_read(adev, 1u, r->dccg_otg_pixel_rate_div, &snap->dccg_pixel_rate_div);
    }
    (void)dc_reg_read(adev, 1u, r->dccg_otg_pixel_rate_cntl + dccg, &snap->dccg_pixel_rate_cntl);
    (void)dc_reg_read(adev, 1u, r->dccg_dp_dto_phase + dccg, &snap->dccg_dto_phase);
    (void)dc_reg_read(adev, 1u, r->dccg_dp_dto_modulo + dccg, &snap->dccg_dto_modulo);
    if (r->dccg_dppclk_dto_param != 0) {
        (void)dc_reg_read(adev, 1u, r->dccg_dppclk_dto_param + (u32)pipe, &snap->dccg_dppclk_dto_param);
    }
    if (r->dccg_dppclk_ctrl != 0) {
        (void)dc_reg_read(adev, 1u, r->dccg_dppclk_ctrl, &snap->dccg_dppclk_ctrl);
    }

    (void)dc_reg_read(adev, 2u, r->hubp_cntl + hubp, &snap->hubp_cntl);
    if (r->hubp_blank_offset_0 != 0) {
        (void)dc_reg_read(adev, 2u, r->hubp_blank_offset_0 + hubp, &snap->hubp_blank_offset_0);
        (void)dc_reg_read(adev, 2u, r->hubp_blank_offset_1 + hubp, &snap->hubp_blank_offset_1);
        (void)dc_reg_read(adev, 2u, r->hubp_dst_dimensions + hubp, &snap->hubp_dst_dimensions);
        (void)dc_reg_read(adev, 2u, r->hubp_ref_freq_to_pix_freq + hubp, &snap->hubp_ref_freq_to_pix_freq);
        (void)dc_reg_read(adev, 2u, r->hubp_per_line_delivery_pre + hubp, &snap->hubp_per_line_delivery_pre);
        (void)dc_reg_read(adev, 2u, r->hubp_per_line_delivery + hubp, &snap->hubp_per_line_delivery);
        (void)dc_reg_read(adev, 2u, r->hubp_ttu_global_cntl + hubp, &snap->hubp_ttu_global_cntl);
        (void)dc_reg_read(adev, 2u, r->hubp_surf0_ttu_cntl0 + hubp, &snap->hubp_surf0_ttu_cntl0);
        (void)dc_reg_read(adev, 2u, r->hubp_surf0_ttu_cntl1 + hubp, &snap->hubp_surf0_ttu_cntl1);
    }
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
    (void)dc_reg_read(adev, 2u, r->dp_pixel_format + dig_o, &snap->dp_pixel_format);
    (void)dc_reg_read(adev, 2u, r->dp_msa_colorimetry + dig_o, &snap->dp_msa_colorimetry);
    (void)dc_reg_read(adev, 2u, r->dp_msa_misc + dig_o, &snap->dp_msa_misc);
    (void)dc_reg_read(adev, 2u, r->dp_vid_timing + dig_o, &snap->dp_vid_timing);
    (void)dc_reg_read(adev, 2u, r->dp_vid_m + dig_o, &snap->dp_vid_m);
    (void)dc_reg_read(adev, 2u, r->dp_vid_n + dig_o, &snap->dp_vid_n);
    if (r->dp_vid_stream_cntl != 0) {
        (void)dc_reg_read(adev, 2u, r->dp_vid_stream_cntl + dig_o, &snap->dp_vid_stream_cntl);
    }
    (void)dc_reg_read(adev, 2u, r->dp_steer_fifo + dig_o, &snap->dp_steer_fifo);
    if (r->dig_fifo_ctrl0 != 0) {
        (void)dc_reg_read(adev, 2u, r->dig_fifo_ctrl0 + dig_o, &snap->dig_fifo_ctrl0);
    }
    (void)dc_reg_read(adev, 2u, r->dsc_top_control + (u32)pipe * r->dsc_stride, &snap->dsc_top_control);

    u32 e_lo = snap->hubp_primary_addr, e_hi = snap->hubp_primary_addr_hi;
    (void)dc_reg_read(adev, 2u, r->hubp_earliest_inuse + hubp, &e_lo);
    (void)dc_reg_read(adev, 2u, r->hubp_earliest_inuse_hi + hubp, &e_hi);
    u64 earliest_mc = decode_mc_addr(e_lo, e_hi);
    u64 primary_mc = decode_mc_addr(snap->hubp_primary_addr, snap->hubp_primary_addr_hi);
    snap->orig_mc_addr = (earliest_mc != 0) ? earliest_mc : primary_mc;
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

    dp_stream_blank(adev, r, dig_o);
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
    (void)dc_reg_write(adev, 2u, r->otg_double_buffer_control + otg, snap->otg_double_buffer_control);
    if (r->otg_vstartup_param != 0) {
        (void)dc_reg_write(adev, 2u, r->otg_vstartup_param + otg, snap->otg_vstartup_param);
    }
    if (r->vtg_control != 0) {
        (void)dc_reg_write(adev, 2u, r->vtg_control + (u32)snap->pipe, snap->vtg_control);
    }

    if (r->dccg_dentist_dispclk_cntl != 0 && snap->dccg_dentist_dispclk_cntl != 0
        && snap->dccg_dentist_dispclk_cntl != 0xFFFFFFFFu) {
        (void)dc_reg_write(adev, 1u, r->dccg_dentist_dispclk_cntl, snap->dccg_dentist_dispclk_cntl);
    }
    if (r->has_otg_pixel_rate_div) {
        (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_div, snap->dccg_pixel_rate_div);
    }
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_modulo + dccg, snap->dccg_dto_modulo);
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_phase + dccg, snap->dccg_dto_phase);
    (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_cntl + dccg, snap->dccg_pixel_rate_cntl);
    if (r->dccg_dppclk_dto_param != 0) {
        (void)dc_reg_write(adev, 1u, r->dccg_dppclk_dto_param + (u32)snap->pipe, snap->dccg_dppclk_dto_param);
    }
    if (r->dccg_dppclk_ctrl != 0) {
        (void)dc_reg_write(adev, 1u, r->dccg_dppclk_ctrl, snap->dccg_dppclk_ctrl);
    }

    if (r->hubp_blank_offset_0 != 0 && snap->hubp_blank_offset_0 != 0 && snap->hubp_blank_offset_0 != 0xFFFFFFFFu) {
        (void)dc_reg_write(adev, 2u, r->hubp_blank_offset_0 + hubp, snap->hubp_blank_offset_0);
        (void)dc_reg_write(adev, 2u, r->hubp_blank_offset_1 + hubp, snap->hubp_blank_offset_1);
        (void)dc_reg_write(adev, 2u, r->hubp_dst_dimensions + hubp, snap->hubp_dst_dimensions);
        (void)dc_reg_write(adev, 2u, r->hubp_ref_freq_to_pix_freq + hubp, snap->hubp_ref_freq_to_pix_freq);
        (void)dc_reg_write(adev, 2u, r->hubp_per_line_delivery_pre + hubp, snap->hubp_per_line_delivery_pre);
        (void)dc_reg_write(adev, 2u, r->hubp_per_line_delivery + hubp, snap->hubp_per_line_delivery);
        (void)dc_reg_write(adev, 2u, r->hubp_ttu_global_cntl + hubp, snap->hubp_ttu_global_cntl);
        (void)dc_reg_write(adev, 2u, r->hubp_surf0_ttu_cntl0 + hubp, snap->hubp_surf0_ttu_cntl0);
        (void)dc_reg_write(adev, 2u, r->hubp_surf0_ttu_cntl1 + hubp, snap->hubp_surf0_ttu_cntl1);
    }
    if (snap->hubp_cntl != 0 && snap->hubp_cntl != 0xFFFFFFFFu) {
        (void)dc_reg_write(adev, 2u, r->hubp_cntl + hubp, snap->hubp_cntl | HUBP_UNDERFLOW_CLEAR_BIT);
    }
    (void)dc_reg_write(adev, 2u, r->hubp_viewport_start + hubp, snap->hubp_viewport_start);
    (void)dc_reg_write(adev, 2u, r->hubp_viewport_dim + hubp, snap->hubp_viewport_dim);
    (void)dc_reg_write(adev, 2u, r->hubp_surface_pitch + hubp, snap->hubp_surface_pitch);
    (void)dc_reg_write(adev, 2u, r->hubp_surface_config + hubp, snap->hubp_surface_config);
    (void)dc_reg_write(adev, 2u, r->hubp_primary_addr_hi + hubp, snap->hubp_primary_addr_hi);
    (void)dc_reg_write(adev, 2u, r->hubp_primary_addr + hubp, snap->hubp_primary_addr);

    if (snap->dscl_static_valid) {
        (void)dc_reg_write(adev, 2u, r->dscl_scl_mode + dpp, snap->dscl_scl_mode);
        (void)dc_reg_write(adev, 2u, r->dscl_recout_start + dpp, snap->dscl_recout_start);
        (void)dc_reg_write(adev, 2u, r->dscl_recout_size + dpp, snap->dscl_recout_size);
        (void)dc_reg_write(adev, 2u, r->dscl_mpc_size + dpp, snap->dscl_mpc_size);
    } else {
        for (u8 i = 0; i < snap->dpp_size_reg_count && i < 4u; i++) {
            (void)dc_reg_write(adev, 2u, snap->dpp_size_regs[i], snap->dpp_size_saved[i]);
        }
    }
    (void)dc_reg_write(adev, 2u, r->cnvc_pixel_format + dpp, snap->cnvc_pixel_format);
    (void)dc_reg_write(adev, 2u, r->cm_hdr_mult + dpp, snap->cm_hdr_mult);

    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param1 + dig_o, snap->dp_msa_param1);
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param2 + dig_o, snap->dp_msa_param2);
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param3 + dig_o, snap->dp_msa_param3);
    (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param4 + dig_o, snap->dp_msa_param4);
    (void)dc_reg_write(adev, 2u, r->dp_pixel_format + dig_o, snap->dp_pixel_format);
    (void)dc_reg_write(adev, 2u, r->dp_msa_colorimetry + dig_o, snap->dp_msa_colorimetry);
    (void)dc_reg_write(adev, 2u, r->dp_msa_misc + dig_o, snap->dp_msa_misc);
    (void)dc_reg_write(adev, 2u, r->dp_vid_timing + dig_o, snap->dp_vid_timing);
    (void)dc_reg_write(adev, 2u, r->dp_vid_n + dig_o, snap->dp_vid_n);
    (void)dc_reg_write(adev, 2u, r->dp_vid_m + dig_o, snap->dp_vid_m);
    (void)dc_reg_write(adev, 2u, r->dsc_top_control + (u32)snap->pipe * r->dsc_stride, snap->dsc_top_control);

    /* Disable hardware cursor cleanly on boot restore. */
    (void)dc_reg_write(adev, 2u, r->cursor_control + hubp, 0u);
    (void)dc_reg_write(adev, 2u, r->dpp_cursor_control + dpp, 0u);

    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 0u);
    dp_stream_resync_and_unblank(
        adev,
        r,
        dig_o,
        snap->dp_steer_fifo,
        snap->dp_vid_stream_cntl,
        snap->dig_fifo_ctrl0
    );
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
        u32 dbuf = 0;
        (void)dc_reg_read(adev, 2u, r->otg_double_buffer_control + otg, &dbuf);
        dbuf = (dbuf & ~(0x3u << 24)) | (2u << 24);
        (void)dc_reg_write(adev, 2u, r->otg_double_buffer_control + otg, dbuf);
        (void)dc_reg_write(
            adev,
            2u,
            r->otg_v_total_control + otg,
            OTG_V_TOTAL_MIN_SEL_BIT
                | OTG_V_TOTAL_MAX_SEL_BIT
                | OTG_SET_V_TOTAL_MIN_MASK_EN_BIT
                | OTG_SET_V_TOTAL_MIN_MASK_FLIP
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
    u32 surf_cfg = 0;
    (void)dc_reg_read(adev, 2u, r->hubp_surface_config + hubp, &surf_cfg);
    (void)dc_reg_write(adev, 2u, r->hubp_surface_config + hubp, (surf_cfg & ~0x7Fu) | fmt);
    (void)dc_reg_write(adev, 2u, r->cnvc_pixel_format + dpp, fmt);
    (void)dc_reg_write(adev, 2u, r->cm_hdr_mult + dpp, enable ? 0x00010000u : 0x00008000u);
    u32 dp_fmt = 0;
    (void)dc_reg_read(adev, 2u, r->dp_pixel_format + dig_o, &dp_fmt);
    u32 depth_code = enable ? 2u : 1u;
    (void)dc_reg_write(adev, 2u, r->dp_pixel_format + dig_o, (dp_fmt & ~(0x7u << 8)) | (depth_code << 8));
    u32 col = 0;
    (void)dc_reg_read(adev, 2u, r->dp_msa_colorimetry + dig_o, &col);
    u32 misc0 = (depth_code << 5) | 1u;
    u32 new_col = p->boot_snapshot.msa_misc0_high
        ? ((col & 0x00FFFFFFu) | (misc0 << 24))
        : ((col & 0xFFFFFF00u) | (misc0 & 0xFFu));
    (void)dc_reg_write(adev, 2u, r->dp_msa_colorimetry + dig_o, new_col);
    /* MSA_MISC1 bit 6 = use VSC SDP for BT.2020/HDR colorimetry (dcn401_dio_stream_encoder.c). */
    u32 misc1 = 0;
    (void)dc_reg_read(adev, 2u, r->dp_msa_misc + dig_o, &misc1);
    if (enable) {
        misc1 |= (1u << 6);
    } else {
        misc1 &= ~(1u << 6);
    }
    (void)dc_reg_write(adev, 2u, r->dp_msa_misc + dig_o, misc1);
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
    u32 hx = (x < 0) ? ((u32)hot_x + (u32)(-x)) : (u32)hot_x;
    u32 hy = (y < 0) ? ((u32)hot_y + (u32)(-y)) : (u32)hot_y;
    if (hx >= eff_sz) hx = eff_sz - 1u;
    if (hy >= eff_sz) hy = eff_sz - 1u;
    u32 pitch_code = (eff_sz == 256u) ? 2u : ((eff_sz == 128u) ? 1u : 0u);
    u32 lines_per_chunk = (eff_sz == 256u) ? 1u : ((eff_sz == 128u) ? 2u : 3u);
    u32 lo = 0, hi = 0;
    encode_mc_addr(p->cursor_mc, &lo, &hi);

    /* Program HUBP cursor address (HIGH then LOW), size, hotspot, settings, and control (dcn10_hubp.c). */
    (void)dc_reg_write(adev, 2u, r->cursor_addr_hi + hubp, hi);
    (void)dc_reg_write(adev, 2u, r->cursor_addr + hubp, lo);
    (void)dc_reg_write(adev, 2u, r->cursor_size + hubp, (((eff_sz - 1u) & 0xFFFFu) << 16) | ((eff_sz - 1u) & 0xFFFFu));
    (void)dc_reg_write(adev, 2u, r->cursor_hot_spot + hubp, ((hx & 0x3FFFu) << 16) | (hy & 0x3FFFu));
    (void)dc_reg_write(adev, 2u, r->hubp_cursor_settings + hubp, 3u << 8);
    (void)dc_reg_write(adev, 2u, r->cursor_dst_offset + hubp, 0u);
    /* CURSOR_POSITION: X at bits [29:15], Y at bits [14:0] (dcn_4_1_0_sh_mask.h). */
    (void)dc_reg_write(adev, 2u, r->cursor_position + hubp, ((cx & 0x7FFFu) << 15) | (cy & 0x7FFFu));
    u32 hubp_cur_ctl = CURSOR_EN_BIT
        | (CURSOR_MODE_ARGB_UNPREMUL << 8)
        | (pitch_code << 16)
        | (lines_per_chunk << 24);
    (void)dc_reg_write(adev, 2u, r->cursor_control + hubp, hubp_cur_ctl);
    /* DPP CM_CUR/CNVC_CUR: CUR0_ENABLE=1 (bit 0), CUR0_MODE (bits 6:4). */
    (void)dc_reg_write(adev, 2u, r->dpp_cursor_control + dpp, CURSOR_EN_BIT | ((CURSOR_MODE_ARGB_UNPREMUL & 0x7u) << 4));

    p->cursor_enabled = true;
    p->cursor_x = x;
    p->cursor_y = y;
    p->cursor_hot_x = hot_x;
    p->cursor_hot_y = hot_y;
    return 0;
}

static void invalidate_scanout_buffers(struct dc_pipe_state *p) {
    if (!p) return;
    for (u32 b = 0; b < DC_MAX_SCANOUT_BUFS; b++) {
        p->buf_valid[b] = false;
        p->buf_dirty_any[b] = false;
        p->buf_dirty_x0[b] = 0u;
        p->buf_dirty_y0[b] = 0u;
        p->buf_dirty_x1[b] = 0u;
        p->buf_dirty_y1[b] = 0u;
    }
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

/* Program DCCG DP pixel-rate DTO (`dccg401_set_dp_dto` in dcn401_dccg.c):
 *   dto_int    = pclk_hz / refclk_hz   (4-bit field DPDTO{0..3}_INT in OTG_PIXEL_RATE_DIV, 0..15)
 *   dto_phase  = pclk_hz - dto_int * refclk_hz
 *   dto_modulo = refclk_hz
 * and enable BOTH `DP_DTO_ENABLE` (bit 4) and `PIPE_DTO_SRC_SEL` (bit 12) in `OTG_PIXEL_RATE_CNTL`. */
static void program_dp_dto(
    struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u8 pipe,
    u32 prev_pdiv,
    u32 prev_cntl,
    u32 pclk_khz,
    u32 refclk_khz,
    u32 *out_dto_int,
    u32 *out_dto_phase
) {
    u32 dccg = (u32)pipe * 4u;
    u32 refclk = refclk_khz >= 50000u ? refclk_khz : 100000u;
    u32 dto_int = pclk_khz / refclk;
    u32 rem_khz = pclk_khz - dto_int * refclk;
    if (dto_int > 15u) {
        dto_int = 15u;
        rem_khz = refclk - 1u;
    }
    /* Match AMD dcn401_dccg.c Hz units (fits cleanly in u32 up to 4.29 GHz). */
    u32 dto_modulo_hz = refclk * 1000u;
    u32 dto_phase_hz = rem_khz * 1000u;
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_phase + dccg, dto_phase_hz);
    (void)dc_reg_write(adev, 1u, r->dccg_dp_dto_modulo + dccg, dto_modulo_hz);
    if (r->has_otg_pixel_rate_div) {
        /* DPDTO{0..3}_INT are 4-bit fields at shifts 1, 6, 11, 16 (`dcn_4_1_0_sh_mask.h`). */
        u32 shift = 1u + (u32)(pipe & 3u) * 5u;
        u32 pdiv = (prev_pdiv & ~(0xFu << shift)) | ((dto_int & 0xFu) << shift);
        (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_div, pdiv);
    }
    u32 cntl_bits = DP_DTO_ENABLE_BIT | (r->has_otg_pixel_rate_div ? PIPE_DTO_SRC_SEL_BIT : 0u);
    (void)dc_reg_write(adev, 1u, r->dccg_otg_pixel_rate_cntl + dccg, prev_cntl | cntl_bits);
    if (out_dto_int) *out_dto_int = dto_int;
    if (out_dto_phase) *out_dto_phase = rem_khz;
}

/* AMD DENTIST DID <-> divider*4 conversions (`dcn10_dentist_get_divider_from_did` / `dentist_get_did_from_divider`). */
static u32 dentist_did_to_div_x4(u32 did) {
    did &= 0x7Fu;
    if (did < 8u) return 0u;
    if (did < 64u) return did;
    if (did < 96u) return 64u + (did - 64u) * 2u;
    return 128u + (did - 96u) * 4u;
}

static u32 dentist_div_x4_to_did(u32 div_x4) {
    u32 did;
    if (div_x4 <= 8u) did = 8u;
    else if (div_x4 <= 64u) did = div_x4;
    else if (div_x4 <= 128u) did = 64u + (div_x4 - 64u) / 2u;
    else did = 96u + (div_x4 - 128u) / 4u;
    if (did > 127u) did = 127u;
    return did;
}

static u32 dcn401_read_vco_khz(const struct amdgpu_device *adev) {
    if (!adev || adev->dcn_version != DC_DCN_4_0_1) return 4500000u;
    u32 pll = amdgpu_rreg32(adev, DCN401_CLK0_PLL_REQ_BYTE);
    if (pll != 0 && pll != 0xFFFFFFFFu) {
        u32 fb_int = pll & 0x1FFu;
        u32 fb_frac = (pll >> 16) & 0xFFFFu;
        u64 vco = (u64)fb_int * 100000ULL + (((u64)fb_frac * 100000ULL) >> 16);
        if (vco >= 2000000ULL && vco <= 8000000ULL) {
            return (u32)vco;
        }
    }
    return 4500000u;
}

static u32 dcn401_dfs_did_to_khz(u32 vco_khz, u32 dfs_reg) {
    if (dfs_reg == 0 || dfs_reg == 0xFFFFFFFFu) return 0u;
    u32 div_x4 = dentist_did_to_div_x4(dfs_reg & 0x7Fu);
    if (div_x4 == 0) return 0u;
    return (u32)((4ULL * (u64)vco_khz) / (u64)div_x4);
}

/* Raise DISPCLK/DPPCLK directly via DENTIST_DISPCLK_CNTL (`dcn401_update_clocks_update_dentist`)
 * whenever SMU PMFW is unavailable and current DISPCLK/DPPCLK sits below the target mode pixel clock. */
static void program_dentist_clocks(
    struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    u32 req_dispclk_mhz,
    u32 req_dppclk_mhz
) {
    if (!adev || !r || r->dccg_dentist_dispclk_cntl == 0 || adev->smu.pmfw_alive) {
        return;
    }
    u32 dent = 0;
    if (!dc_reg_read(adev, 1u, r->dccg_dentist_dispclk_cntl, &dent) || dent == 0 || dent == 0xFFFFFFFFu) {
        return;
    }
    u32 vco_khz = dcn401_read_vco_khz(adev);
    u32 cur_disp_did = dent & 0x7Fu;
    if (req_dispclk_mhz >= 100u && cur_disp_did >= 8u && cur_disp_did <= 127u) {
        u32 target_khz = req_dispclk_mhz * 1000u;
        u32 div_x4 = (u32)((4ULL * (u64)vco_khz) / (u64)target_khz);
        u32 new_did = dentist_div_x4_to_did(div_x4);
        if (new_did < 12u) new_did = 12u; /* safety ceiling: <= 1500 MHz at 4.5 GHz VCO */
        if (new_did < cur_disp_did) {
            dent = (dent & ~0x7Fu) | (new_did & 0x7Fu);
            (void)dc_reg_write(adev, 1u, r->dccg_dentist_dispclk_cntl, dent);
            for (u32 i = 0; i < 400u; i++) {
                u32 st = 0;
                if (!dc_reg_read(adev, 1u, r->dccg_dentist_dispclk_cntl, &st)) break;
                if ((st & DENTIST_DISPCLK_CHG_DONE_BIT) != 0) break;
                amdgpu_udelay(adev, 50u);
            }
        }
    }
    (void)dc_reg_read(adev, 1u, r->dccg_dentist_dispclk_cntl, &dent);
    u32 cur_dpp_did = (dent >> 24) & 0x7Fu;
    if (req_dppclk_mhz >= 100u && cur_dpp_did >= 8u && cur_dpp_did <= 127u) {
        u32 target_khz = req_dppclk_mhz * 1000u;
        u32 div_x4 = (u32)((4ULL * (u64)vco_khz) / (u64)target_khz);
        u32 new_did = dentist_div_x4_to_did(div_x4);
        if (new_did < 12u) new_did = 12u;
        if (new_did < cur_dpp_did) {
            dent = (dent & ~(0x7Fu << 24)) | ((new_did & 0x7Fu) << 24);
            (void)dc_reg_write(adev, 1u, r->dccg_dentist_dispclk_cntl, dent);
            for (u32 i = 0; i < 400u; i++) {
                u32 st = 0;
                if (!dc_reg_read(adev, 1u, r->dccg_dentist_dispclk_cntl, &st)) break;
                if ((st & DENTIST_DPPCLK_CHG_DONE_BIT) != 0) break;
                amdgpu_udelay(adev, 50u);
            }
        }
    }
}

static u32 scale_dlg_field(u32 boot_val, u64 num, u64 den, u32 mask) {
    if (boot_val == 0 || num == 0 || den == 0) return boot_val & mask;
    u64 v = ((u64)boot_val * num + (den / 2ULL)) / den;
    if (v == 0) v = 1ULL;
    if (v > (u64)mask) v = (u64)mask;
    return (u32)v;
}

/* Reprogram DCN 4.0.1 HUBP DLG & TTU deadline timers proportionally from UEFI's calibrated boot
 * snapshot (`hubp401_program_deadline` / `hubp401_setup_interdependent`) so high-refresh modes
 * (e.g. 60 -> 240 Hz with 4x shorter scanlines and different v_blank_end) never underflow HUBP. */
static void program_hubp_dlg_ttu(
    struct amdgpu_device *adev,
    const struct dc_reg_table *r,
    const struct dc_pipe_state *p,
    const struct dc_timing *target,
    u32 h_total,
    u32 h_blank_end,
    u32 v_blank_end,
    u32 vstartup
) {
    const struct dc_pipe_reg_snapshot *bs = &p->boot_snapshot;
    if (!r || r->hubp_blank_offset_0 == 0 || bs->boot_pclk_khz == 0 || target->pixel_clock_khz == 0) {
        return;
    }
    if (bs->hubp_blank_offset_0 == 0 || bs->hubp_blank_offset_0 == 0xFFFFFFFFu) {
        return;
    }
    u32 hubp = (u32)p->pipe_idx * r->hubp_stride;
    u64 p_boot = (u64)bs->boot_pclk_khz;
    u64 p_new = (u64)target->pixel_clock_khz;
    u64 ht_boot = bs->boot_h_total ? (u64)bs->boot_h_total : (u64)h_total;
    u64 hbe_boot = bs->boot_h_blank_end ? (u64)bs->boot_h_blank_end : (u64)h_blank_end;
    u64 ha_boot = bs->dst_width ? (u64)bs->dst_width : (u64)target->h_active;
    u64 vb_boot = bs->boot_v_blank ? (u64)bs->boot_v_blank : (u64)target->v_blank;

    /* BLANK_OFFSET_0: [12:0] REFCYC_H_BLANK_END, [30:16] DLG_V_BLANK_END */
    u32 hbe_ref = scale_dlg_field(bs->hubp_blank_offset_0 & 0x1FFFu, (u64)h_blank_end * p_boot, hbe_boot * p_new, 0x1FFFu);
    u32 bo0 = (bs->hubp_blank_offset_0 & ~(0x1FFFu | (0x7FFFu << 16)))
        | hbe_ref
        | ((v_blank_end & 0x7FFFu) << 16);
    (void)dc_reg_write(adev, 2u, r->hubp_blank_offset_0 + hubp, bo0);

    /* DST_DIMENSIONS: [20:0] REFCYC_PER_HTOTAL */
    if (bs->hubp_dst_dimensions != 0 && bs->hubp_dst_dimensions != 0xFFFFFFFFu) {
        u32 rph = scale_dlg_field(bs->hubp_dst_dimensions & 0x1FFFFFu, (u64)h_total * p_boot, ht_boot * p_new, 0x1FFFFFu);
        (void)dc_reg_write(adev, 2u, r->hubp_dst_dimensions + hubp, (bs->hubp_dst_dimensions & ~0x1FFFFFu) | rph);
    }

    /* REF_FREQ_TO_PIX_FREQ: [20:0] */
    if (bs->hubp_ref_freq_to_pix_freq != 0 && bs->hubp_ref_freq_to_pix_freq != 0xFFFFFFFFu) {
        u32 r2p = scale_dlg_field(bs->hubp_ref_freq_to_pix_freq & 0x1FFFFFu, p_boot, p_new, 0x1FFFFFu);
        (void)dc_reg_write(adev, 2u, r->hubp_ref_freq_to_pix_freq + hubp, (bs->hubp_ref_freq_to_pix_freq & ~0x1FFFFFu) | r2p);
    }

    /* PER_LINE_DELIVERY & PER_LINE_DELIVERY_PRE: [12:0] L, [28:16] C */
    if (bs->hubp_per_line_delivery != 0 && bs->hubp_per_line_delivery != 0xFFFFFFFFu) {
        u32 l_val = scale_dlg_field(bs->hubp_per_line_delivery & 0x1FFFu, (u64)target->h_active * p_boot, ha_boot * p_new, 0x1FFFu);
        u32 c_val = scale_dlg_field((bs->hubp_per_line_delivery >> 16) & 0x1FFFu, (u64)target->h_active * p_boot, ha_boot * p_new, 0x1FFFu);
        u32 pld = (bs->hubp_per_line_delivery & ~(0x1FFFu | (0x1FFFu << 16))) | l_val | (c_val << 16);
        (void)dc_reg_write(adev, 2u, r->hubp_per_line_delivery + hubp, pld);
    }
    if (bs->hubp_per_line_delivery_pre != 0 && bs->hubp_per_line_delivery_pre != 0xFFFFFFFFu) {
        u32 l_val = scale_dlg_field(bs->hubp_per_line_delivery_pre & 0x1FFFu, (u64)target->h_active * p_boot, ha_boot * p_new, 0x1FFFu);
        u32 c_val = scale_dlg_field((bs->hubp_per_line_delivery_pre >> 16) & 0x1FFFu, (u64)target->h_active * p_boot, ha_boot * p_new, 0x1FFFu);
        u32 pldp = (bs->hubp_per_line_delivery_pre & ~(0x1FFFu | (0x1FFFu << 16))) | l_val | (c_val << 16);
        (void)dc_reg_write(adev, 2u, r->hubp_per_line_delivery_pre + hubp, pldp);
    }

    /* DCN_SURF0_TTU_CNTL0 / CNTL1: [22:0] REFCYC_PER_REQ_DELIVERY(_PRE) */
    if (bs->hubp_surf0_ttu_cntl0 != 0 && bs->hubp_surf0_ttu_cntl0 != 0xFFFFFFFFu) {
        u32 rpr = scale_dlg_field(bs->hubp_surf0_ttu_cntl0 & 0x7FFFFFu, p_boot, p_new, 0x7FFFFFu);
        (void)dc_reg_write(adev, 2u, r->hubp_surf0_ttu_cntl0 + hubp, (bs->hubp_surf0_ttu_cntl0 & ~0x7FFFFFu) | rpr);
    }
    if (bs->hubp_surf0_ttu_cntl1 != 0 && bs->hubp_surf0_ttu_cntl1 != 0xFFFFFFFFu) {
        u32 rprp = scale_dlg_field(bs->hubp_surf0_ttu_cntl1 & 0x7FFFFFu, p_boot, p_new, 0x7FFFFFu);
        (void)dc_reg_write(adev, 2u, r->hubp_surf0_ttu_cntl1 + hubp, (bs->hubp_surf0_ttu_cntl1 & ~0x7FFFFFu) | rprp);
    }

    /* DCN_GLOBAL_TTU_CNTL: [23:0] MIN_TTU_VBLANK */
    if (bs->hubp_ttu_global_cntl != 0 && bs->hubp_ttu_global_cntl != 0xFFFFFFFFu) {
        u32 mtv = scale_dlg_field(
            bs->hubp_ttu_global_cntl & 0xFFFFFFu,
            (u64)target->v_blank * (u64)h_total * p_boot,
            vb_boot * ht_boot * p_new,
            0xFFFFFFu
        );
        (void)dc_reg_write(adev, 2u, r->hubp_ttu_global_cntl + hubp, (bs->hubp_ttu_global_cntl & ~0xFFFFFFu) | mtv);
    }

    /* Update HUBP_VREADY_AT_OR_AFTER_VSYNC coherently with vstartup vs v_blank_end (`hubp401_vready_at_or_After_vsync`). */
    if (bs->hubp_cntl != 0 && bs->hubp_cntl != 0xFFFFFFFFu) {
        u32 hctl = bs->hubp_cntl & ~HUBP_UNDERFLOW_CLEAR_BIT;
        if (vstartup <= v_blank_end) {
            hctl |= HUBP_VREADY_AT_OR_AFTER_VSYNC_BIT;
        } else {
            hctl &= ~HUBP_VREADY_AT_OR_AFTER_VSYNC_BIT;
        }
        (void)dc_reg_write(adev, 2u, r->hubp_cntl + hubp, hctl);
    }
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
    prev.msa_h_low = p->boot_snapshot.msa_h_low;
    prev.msa_misc0_high = p->boot_snapshot.msa_misc0_high;
    prev.dscl_static_valid = p->boot_snapshot.dscl_static_valid;
    prev.dpp_size_reg_count = p->boot_snapshot.dpp_size_reg_count;
    for (u8 i = 0; i < prev.dpp_size_reg_count && i < 4u; i++) {
        prev.dpp_size_regs[i] = p->boot_snapshot.dpp_size_regs[i];
        (void)dc_reg_read(adev, 2u, prev.dpp_size_regs[i], &prev.dpp_size_saved[i]);
    }

    /* 1. Record / request minimum display clocks (SMU v14.0.2 & DENTIST fallback). */
    (void)amdgpu_smu_set_display_clocks(
        adev,
        plan->dispclk_mhz,
        plan->dppclk_mhz,
        plan->dcfclk_mhz,
        plan->dtbclk_mhz,
        plan->uclk_mhz
    );
    program_dentist_clocks(adev, r, plan->dispclk_mhz, plan->dppclk_mhz);

    /* 2. Retrain DP 1.4/2.1 or HDMI 2.1 FRL link only when target mode exceeds current trained link.
     * Never touch sink DPCD 0x0100/0x0102 when UEFI owns DMCUB (no GPU PHY transmitter control). */
    if (conn && conn->connected) {
        u64 cur_bw = (u64)conn->trained_lanes * (u64)conn->trained_rate_mbps;
        u64 req_bw = (u64)plan->req_lanes * (u64)plan->req_rate_mbps;
        if (req_bw > cur_bw || (plan->requires_uhbr && conn->link_type != DC_LINK_DP_2_1)) {
            if (!dc->dmub.ring_owned) {
                struct dc_log_buf lb = { { 0 }, 0 };
                dlog_str(&lb, "amdgpu: dc: modeset refused: link retrain needs ");
                dlog_u32(&lb, plan->req_lanes);
                dlog_str(&lb, "x");
                dlog_u32(&lb, plan->req_rate_mbps);
                dlog_str(&lb, "Mbps > trained ");
                dlog_u32(&lb, conn->trained_lanes);
                dlog_str(&lb, "x");
                dlog_u32(&lb, conn->trained_rate_mbps);
                dlog_str(&lb, "Mbps (UEFI DMUB owns PHY)");
                dlog_emit(adev, &lb);
                return -ENOTSUP;
            }
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

    dp_stream_blank(adev, r, dig_o);
    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 1u);

    u32 h_total = target->h_active + target->h_blank;
    u32 v_total = target->v_active + target->v_blank;
    u32 h_blank_end = target->h_blank > target->h_front_porch ? (target->h_blank - target->h_front_porch) : 8u;
    u32 h_blank_start = h_blank_end + target->h_active;
    u32 v_blank_end = target->v_blank > target->v_front_porch ? (target->v_blank - target->v_front_porch) : 4u;
    u32 v_blank_start = v_blank_end + target->v_active;

    (void)dc_reg_write(adev, 2u, r->otg_h_total + otg, (h_total - 1u) & 0x7FFFu);
    (void)dc_reg_write(adev, 2u, r->otg_h_blank + otg, ((h_blank_end & 0x7FFFu) << 16) | (h_blank_start & 0x7FFFu));
    (void)dc_reg_write(adev, 2u, r->otg_h_sync_a + otg, (target->h_sync_width & 0x7FFFu) << 16);
    (void)dc_reg_write(adev, 2u, r->otg_h_sync_a_cntl + otg, target->h_sync_pos ? 0u : 1u);

    (void)dc_reg_write(adev, 2u, r->otg_v_total + otg, (v_total - 1u) & 0x7FFFu);
    (void)dc_reg_write(adev, 2u, r->otg_v_blank + otg, ((v_blank_end & 0x7FFFu) << 16) | (v_blank_start & 0x7FFFu));
    (void)dc_reg_write(adev, 2u, r->otg_v_sync_a + otg, (target->v_sync_width & 0x7FFFu) << 16);
    (void)dc_reg_write(adev, 2u, r->otg_v_sync_a_cntl + otg, target->v_sync_pos ? 0u : 1u);
    /* Ensure stale VRR/DRR vertical limits cannot clamp the newly programmed v_total. */
    if (!p->vrr_enabled) {
        (void)dc_reg_write(adev, 2u, r->otg_v_total_control + otg, 0u);
        (void)dc_reg_write(adev, 2u, r->otg_v_total_min + otg, (v_total - 1u) & 0x7FFFu);
        (void)dc_reg_write(adev, 2u, r->otg_v_total_max + otg, (v_total - 1u) & 0x7FFFu);
    }

    /* Synchronize VTG0_VCOUNT_INIT / VTG0_FP2, OTG_VSTARTUP_PARAM, and HUBP DLG/TTU deadlines
     * with the new timing (`optc1_set_vtg_params` + `hubp401_program_deadline`). */
    u32 vstartup = p->boot_snapshot.otg_vstartup_param & 0x3FFu;
    if (vstartup < 14u) vstartup = 14u;
    if (p->boot_snapshot.boot_v_blank_end > 0 && v_blank_end > p->boot_snapshot.boot_v_blank_end) {
        u32 scaled = (vstartup * v_blank_end) / p->boot_snapshot.boot_v_blank_end;
        if (scaled > vstartup) vstartup = scaled;
    }
    if (v_blank_end >= 14u && vstartup > v_blank_end) {
        vstartup = v_blank_end;
    } else if (target->v_blank > 2u && vstartup >= target->v_blank) {
        vstartup = target->v_blank - 1u;
    }
    if (r->vtg_control != 0 || r->otg_vstartup_param != 0) {
        if (r->otg_vstartup_param != 0) {
            (void)dc_reg_write(adev, 2u, r->otg_vstartup_param + otg, vstartup & 0x3FFu);
        }
        if (r->vtg_control != 0) {
            u32 v_fp2 = (vstartup > (v_blank_end + 1u)) ? (vstartup - (v_blank_end + 1u)) : 0u;
            u32 vtg_val = (1u << 31) | ((v_blank_start & 0x7FFFu) << 16) | (v_fp2 & 0x7FFFu);
            (void)dc_reg_write(adev, 2u, r->vtg_control + (u32)p->pipe_idx, vtg_val);
        }
    }
    program_hubp_dlg_ttu(adev, r, p, target, h_total, h_blank_end, v_blank_end, vstartup);

    /* Unthrottle per-pipe DCCG DPPCLK DTO to 100% of global DPPCLK (`dccg401_update_dpp_dto`)
     * so high-refresh modes (e.g. 240 Hz / 580 MHz) never underflow on UEFI's 60 Hz DPPCLK divider. */
    if (r->dccg_dppclk_dto_param != 0) {
        (void)dc_reg_write(adev, 1u, r->dccg_dppclk_dto_param + (u32)p->pipe_idx, (0xFFu << 16) | 0xFFu);
    }
    if (r->dccg_dppclk_ctrl != 0) {
        u32 dpp_en = 1u << ((u32)(p->pipe_idx & 3u) * 3u);
        (void)dc_reg_write(adev, 1u, r->dccg_dppclk_ctrl, prev.dccg_dppclk_ctrl | dpp_en);
    }

    u32 refclk = p->boot_snapshot.dto_src_clk_khz;
    if (refclk < 50000u) refclk = r->has_otg_pixel_rate_div ? 100000u : 1000000u;
    u32 dto_int = 0u, dto_phase = 0u;
    program_dp_dto(
        adev,
        r,
        p->pipe_idx,
        prev.dccg_pixel_rate_div,
        prev.dccg_pixel_rate_cntl,
        target->pixel_clock_khz,
        refclk,
        &dto_int,
        &dto_phase
    );

    /* Only reprogram HUBP viewport/pitch + DPP geometry when output resolution actually changes;
     * preserve firmware's live HUBP/DPP pipeline for same-resolution refresh-rate switches (e.g. 60 -> 240 Hz). */
    bool res_changed = (target->h_active != p->src_width || target->v_active != p->src_height);
    u32 pitch_px = p->pitch_bytes / 4u;
    if (res_changed) {
        pitch_px = (target->h_active + 63u) & ~63u;
        u32 dim = ((target->v_active & 0x3FFFu) << 16) | (target->h_active & 0x3FFFu);
        (void)dc_reg_write(adev, 2u, r->hubp_viewport_start + hubp, 0u);
        (void)dc_reg_write(adev, 2u, r->hubp_viewport_dim + hubp, dim);
        (void)dc_reg_write(adev, 2u, r->hubp_surface_pitch + hubp, (pitch_px - 1u) & 0x3FFFu);
        if (p->boot_snapshot.dscl_static_valid) {
            program_dpp_scaler(adev, r, p->pipe_idx, target->h_active, target->v_active, target->h_active, target->v_active);
        } else {
            for (u8 i = 0; i < p->boot_snapshot.dpp_size_reg_count && i < 4u; i++) {
                (void)dc_reg_write(adev, 2u, p->boot_snapshot.dpp_size_regs[i], dim);
            }
        }
    }

    /* Program DIG DP Main Stream Attributes (MSA) matching the live silicon layout detected at boot
     * (`msa_h_low = true` = AMD DCN standard: H in [15:0], V in [31:16]; else H in [31:16], V in [15:0]). */
    if (p->boot_snapshot.msa_h_low) {
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param1 + dig_o, ((v_total & 0xFFFFu) << 16) | (h_total & 0xFFFFu));
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param2 + dig_o, ((v_blank_end & 0xFFFFu) << 16) | (h_blank_end & 0xFFFFu));
        u32 msa3 = (target->h_sync_width & 0x7FFFu)
            | ((target->h_sync_pos ? 0u : 1u) << 15)
            | ((target->v_sync_width & 0x7FFFu) << 16)
            | ((target->v_sync_pos ? 0u : 1u) << 31);
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param3 + dig_o, msa3);
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param4 + dig_o, ((target->v_active & 0xFFFFu) << 16) | (target->h_active & 0xFFFFu));
    } else {
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param1 + dig_o, ((h_total & 0xFFFFu) << 16) | (v_total & 0xFFFFu));
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param2 + dig_o, ((h_blank_end & 0xFFFFu) << 16) | (v_blank_end & 0xFFFFu));
        u32 msa3 = (target->v_sync_width & 0x7FFFu)
            | ((target->v_sync_pos ? 0u : 1u) << 15)
            | ((target->h_sync_width & 0x7FFFu) << 16)
            | ((target->h_sync_pos ? 0u : 1u) << 31);
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param3 + dig_o, msa3);
        (void)dc_reg_write(adev, 2u, r->dp_msa_timing_param4 + dig_o, ((target->h_active & 0xFFFFu) << 16) | (target->v_active & 0xFFFFu));
    }

    /* Preserve firmware's working DP_PIXEL_FORMAT & DP_MSA_COLORIMETRY for normal 8-bpc SDR modes;
     * only touch component depth / DSC / MISC0 bits when bpc or DSC actually changes.
     * (`dcn_4_1_0_sh_mask.h`: PIXEL_ENCODING_TYPE = bit 0, UNCOMPRESSED_COMPONENT_DEPTH = [10:8],
     *  DP_MSA_MISC0 = [31:24]). */
    if (plan->bpc != 8u || plan->requires_dsc || p->hdr_enabled || p->dsc_enabled) {
        u32 depth_code = (plan->bpc >= 10u) ? 2u : 1u; /* 1 = 8bpc, 2 = 10bpc */
        u32 dp_fmt = (prev.dp_pixel_format & ~((0x7u << 8) | 1u))
            | (depth_code << 8)
            | (plan->requires_dsc ? 1u : 0u);
        (void)dc_reg_write(adev, 2u, r->dp_pixel_format + dig_o, dp_fmt);
        u32 misc0 = (depth_code << 5) | 1u; /* synchronous clock + bpc */
        u32 new_col = p->boot_snapshot.msa_misc0_high
            ? ((prev.dp_msa_colorimetry & 0x00FFFFFFu) | (misc0 << 24))
            : ((prev.dp_msa_colorimetry & 0xFFFFFF00u) | (misc0 & 0xFFu));
        (void)dc_reg_write(adev, 2u, r->dp_msa_colorimetry + dig_o, new_col);
    }

    /* Seed initial DP_VID_N / DP_VID_M for the new pixel clock (matching dcn401_dio_stream_encoder.c),
     * then re-enable automatic hardware M/N tracking (`DP_VID_M_N_GEN_EN = 1`). */
    {
        u32 rate_mbps = (conn && conn->trained_rate_mbps > 0) ? conn->trained_rate_mbps : DC_DP_RATE_HBR2_MBPS;
        u64 f_ls_khz = (rate_mbps >= DC_DP_RATE_UHBR10_MBPS)
            ? (((u64)rate_mbps * 1000ULL) / 32ULL)
            : ((u64)rate_mbps * 100ULL);
        u32 n_vid = 0x8000u;
        u32 m_vid = f_ls_khz
            ? (u32)(((u64)target->pixel_clock_khz * (u64)n_vid + (f_ls_khz / 2ULL)) / f_ls_khz)
            : 0x2000u;
        (void)dc_reg_write(adev, 2u, r->dp_vid_timing + dig_o, prev.dp_vid_timing & ~DP_VID_M_N_GEN_EN_BIT);
        (void)dc_reg_write(adev, 2u, r->dp_vid_n + dig_o, n_vid);
        (void)dc_reg_write(adev, 2u, r->dp_vid_m + dig_o, m_vid);
        (void)dc_reg_write(adev, 2u, r->dp_vid_timing + dig_o, prev.dp_vid_timing | DP_VID_M_N_GEN_EN_BIT);
    }

    /* Program DSC 1.2a hardware encoder & DPCD 0x0160 only when enabling or disabling DSC. */
    if (plan->requires_dsc || p->dsc_enabled) {
        (void)dc_dsc_program_hw(adev, dc, p->pipe_idx, plan->requires_dsc ? &pps : NULL, plan->requires_dsc);
        if (conn && (conn->link_type == DC_LINK_DP_1_4 || conn->link_type == DC_LINK_DP_2_1) && conn->dsc_capable) {
            u8 dsc_en = plan->requires_dsc ? 0x01u : 0x00u;
            (void)dc_dpcd_write(adev, r, conn->aux_idx, 0x0160u, &dsc_en, 1u);
        }
    }

    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 0u);

    /* Wait for OTG to latch the unlocked timing on the next frame boundary (max ~25 ms) before
     * resetting DP_STEER_FIFO & DIG_FIFO_CTRL0 so the FIFOs sync cleanly to the NEW timing! */
    {
        u32 fc_pre = read_otg_frame_count(adev, r, p->pipe_idx);
        for (u32 wstep = 0; wstep < 25u; wstep++) {
            amdgpu_udelay(adev, 1000u);
            if (read_otg_frame_count(adev, r, p->pipe_idx) != fc_pre) break;
        }
    }

    /* Reset & re-enable DP_STEER_FIFO, DIG_FIFO_CTRL0 (DCN 4.0.1), and DP_VID_STREAM_CNTL. */
    dp_stream_resync_and_unblank(
        adev,
        r,
        dig_o,
        prev.dp_steer_fifo,
        prev.dp_vid_stream_cntl,
        prev.dig_fifo_ctrl0
    );

    /* 5. Live post-modeset verification & one-shot DTBCLK self-calibration when boot DTO was disabled. */
    u32 total_df = 0;
    u32 measured_mhz = measure_otg_refresh_mhz(adev, r, p->pipe_idx, &total_df);
    if (total_df == 0) {
        restore_pipe_snapshot(adev, r, &prev);
        struct dc_log_buf lb = { { 0 }, 0 };
        dlog_str(&lb, "amdgpu: dc: modeset rollback (OTG stalled) target=");
        dlog_u32(&lb, target->h_active);
        dlog_str(&lb, "x");
        dlog_u32(&lb, target->v_active);
        dlog_str(&lb, "@");
        dlog_u32(&lb, target->refresh_mhz / 1000u);
        dlog_str(&lb, "Hz pclk=");
        dlog_u32(&lb, target->pixel_clock_khz);
        dlog_str(&lb, "kHz ref=");
        dlog_u32(&lb, refclk);
        dlog_emit(adev, &lb);
        return -EIO;
    }

    if (!p->boot_snapshot.dto_src_calibrated && measured_mhz >= 20000u && target->refresh_mhz >= 20000u) {
        u32 diff = measured_mhz > target->refresh_mhz
            ? (measured_mhz - target->refresh_mhz)
            : (target->refresh_mhz - measured_mhz);
        if (diff > (target->refresh_mhz / 25u)) {
            u64 real_ref = ((u64)refclk * (u64)measured_mhz) / (u64)target->refresh_mhz;
            if (real_ref >= 100000ULL && real_ref <= 3000000ULL) {
                refclk = (u32)real_ref;
                p->boot_snapshot.dto_src_clk_khz = refclk;
                p->boot_snapshot.dto_src_calibrated = true;
                dp_stream_blank(adev, r, dig_o);
    (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 1u);
                program_dp_dto(
                    adev,
                    r,
                    p->pipe_idx,
                    prev.dccg_pixel_rate_div,
                    prev.dccg_pixel_rate_cntl,
                    target->pixel_clock_khz,
                    refclk,
                    &dto_int,
                    &dto_phase
                );
                (void)dc_reg_write(adev, 2u, r->otg_master_update_lock + otg, 0u);
                dp_stream_resync_and_unblank(
                    adev,
                    r,
                    dig_o,
                    prev.dp_steer_fifo,
                    prev.dp_vid_stream_cntl,
                    prev.dig_fifo_ctrl0
                );
                u32 cal_df = 0;
                u32 cal_mhz = measure_otg_refresh_mhz(adev, r, p->pipe_idx, &cal_df);
                if (cal_df == 0) {
                    restore_pipe_snapshot(adev, r, &prev);
                    return -EIO;
                }
                if (cal_mhz > 0) measured_mhz = cal_mhz;
            }
        } else {
            p->boot_snapshot.dto_src_calibrated = true;
        }
    }

    {
        struct dc_log_buf lb = { { 0 }, 0 };
        dlog_str(&lb, "amdgpu: dc: modeset OK pipe=");
        dlog_u32(&lb, p->pipe_idx);
        dlog_str(&lb, " dig=");
        dlog_u32(&lb, p->dig_idx);
        dlog_str(&lb, " ");
        dlog_u32(&lb, target->h_active);
        dlog_str(&lb, "x");
        dlog_u32(&lb, target->v_active);
        dlog_str(&lb, "@");
        dlog_u32(&lb, target->refresh_mhz / 1000u);
        dlog_str(&lb, "Hz (meas=");
        dlog_u32(&lb, measured_mhz / 1000u);
        dlog_str(&lb, "Hz pclk=");
        dlog_u32(&lb, target->pixel_clock_khz);
        dlog_str(&lb, "kHz dto=");
        dlog_u32(&lb, dto_int);
        dlog_str(&lb, "+");
        dlog_u32(&lb, dto_phase);
        dlog_str(&lb, "/");
        dlog_u32(&lb, refclk);
        dlog_str(&lb, " smu=");
        dlog_u32(&lb, adev->smu.pmfw_alive ? 1u : 0u);
        dlog_str(&lb, ")");
        dlog_emit(adev, &lb);
    }
    /* Clear any transient HUBP/OPTC underflow flags latched during the mode transition,
     * then wait one steady-state frame before sampling diagnostic status. */
    {
        u32 hctl = 0;
        if (dc_reg_read(adev, 2u, r->hubp_cntl + hubp, &hctl) && hctl != 0xFFFFFFFFu) {
            (void)dc_reg_write(adev, 2u, r->hubp_cntl + hubp, hctl | HUBP_UNDERFLOW_CLEAR_BIT);
            (void)dc_reg_write(adev, 2u, r->hubp_cntl + hubp, hctl & ~HUBP_UNDERFLOW_CLEAR_BIT);
        }
        if (r->optc_input_global_ctrl != 0) {
            u32 og = 0;
            u32 og_off = r->optc_input_global_ctrl + (u32)p->pipe_idx * r->optc_input_stride;
            if (dc_reg_read(adev, 2u, og_off, &og) && og != 0xFFFFFFFFu) {
                (void)dc_reg_write(adev, 2u, og_off, og | OPTC_UNDERFLOW_CLEAR_BIT);
                (void)dc_reg_write(adev, 2u, og_off, og & ~OPTC_UNDERFLOW_CLEAR_BIT);
            }
        }
        u32 fc_clr = read_otg_frame_count(adev, r, p->pipe_idx);
        for (u32 wstep = 0; wstep < 25u; wstep++) {
            amdgpu_udelay(adev, 1000u);
            if (read_otg_frame_count(adev, r, p->pipe_idx) != fc_clr) break;
        }
    }

    {
        u32 st_df = 0, st_sf = 0, st_vs = 0, st_vtg = 0, st_dpp = 0;
        if (r->dig_fifo_ctrl0 != 0) (void)dc_reg_read(adev, 2u, r->dig_fifo_ctrl0 + dig_o, &st_df);
        (void)dc_reg_read(adev, 2u, r->dp_steer_fifo + dig_o, &st_sf);
        if (r->dp_vid_stream_cntl != 0) (void)dc_reg_read(adev, 2u, r->dp_vid_stream_cntl + dig_o, &st_vs);
        if (r->vtg_control != 0) (void)dc_reg_read(adev, 2u, r->vtg_control + (u32)p->pipe_idx, &st_vtg);
        if (r->dccg_dppclk_dto_param != 0) (void)dc_reg_read(adev, 1u, r->dccg_dppclk_dto_param + (u32)p->pipe_idx, &st_dpp);
        struct dc_log_buf lb = { { 0 }, 0 };
        dlog_str(&lb, "amdgpu: dc: post df=");
        dlog_hex(&lb, st_df);
        dlog_str(&lb, " sf=");
        dlog_hex(&lb, st_sf);
        dlog_str(&lb, " vs=");
        dlog_hex(&lb, st_vs);
        dlog_str(&lb, " vtg=");
        dlog_hex(&lb, st_vtg);
        dlog_str(&lb, " dpp=");
        dlog_hex(&lb, st_dpp);
        dlog_emit(adev, &lb);
    }
    {
        u32 st_hubp = 0, st_optc = 0, st_bo0 = 0, st_r2p = 0, st_dent = 0;
        (void)dc_reg_read(adev, 2u, r->hubp_cntl + hubp, &st_hubp);
        if (r->optc_input_global_ctrl != 0) {
            (void)dc_reg_read(adev, 2u, r->optc_input_global_ctrl + (u32)p->pipe_idx * r->optc_input_stride, &st_optc);
        }
        if (r->hubp_blank_offset_0 != 0) {
            (void)dc_reg_read(adev, 2u, r->hubp_blank_offset_0 + hubp, &st_bo0);
            (void)dc_reg_read(adev, 2u, r->hubp_ref_freq_to_pix_freq + hubp, &st_r2p);
        }
        if (r->dccg_dentist_dispclk_cntl != 0) {
            (void)dc_reg_read(adev, 1u, r->dccg_dentist_dispclk_cntl, &st_dent);
        }
        u32 vco_khz = dcn401_read_vco_khz(adev);
        u32 disp_mhz = dcn401_dfs_did_to_khz(vco_khz, amdgpu_rreg32(adev, DCN401_CLK0_DISP_DFS_BYTE)) / 1000u;
        u32 dpp_mhz = dcn401_dfs_did_to_khz(vco_khz, amdgpu_rreg32(adev, DCN401_CLK0_DPP_DFS_BYTE)) / 1000u;
        struct dc_log_buf lb = { { 0 }, 0 };
        dlog_str(&lb, "amdgpu: dc: post2 hubp=");
        dlog_hex(&lb, st_hubp);
        dlog_str(&lb, " optc=");
        dlog_hex(&lb, st_optc);
        dlog_str(&lb, " bo0=");
        dlog_hex(&lb, st_bo0);
        dlog_str(&lb, " r2p=");
        dlog_hex(&lb, st_r2p);
        dlog_str(&lb, " dent=");
        dlog_hex(&lb, st_dent);
        dlog_str(&lb, " clk=");
        dlog_u32(&lb, disp_mhz);
        dlog_str(&lb, "/");
        dlog_u32(&lb, dpp_mhz);
        dlog_emit(adev, &lb);
    }

    p->current_mode = *target;
    p->src_width = target->h_active;
    p->src_height = target->v_active;
    p->pitch_bytes = pitch_px * 4u;
    p->dsc_enabled = plan->requires_dsc;
    p->dsc_pps = pps;
    p->active_plan = *plan;
    invalidate_scanout_buffers(p);
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
        if (otg_ctl == 0xFFFFFFFFu || (otg_ctl & OTG_MASTER_EN_MASK) == 0) continue;
        if (!dc_reg_read(adev, 2u, r->hubp_cntl + (u32)pipe * r->hubp_stride, &hubp_ctl)) continue;
        if (hubp_ctl == 0xFFFFFFFFu || (hubp_ctl & HUBP_BLANK_EN_BIT) != 0) continue;

        (void)dc_reg_read(adev, 2u, r->otg_h_total + (u32)pipe * r->otg_stride, &ht);
        (void)dc_reg_read(adev, 2u, r->otg_v_total + (u32)pipe * r->otg_stride, &vt);
        (void)dc_reg_read(adev, 2u, r->otg_h_blank + (u32)pipe * r->otg_stride, &hb);
        (void)dc_reg_read(adev, 2u, r->otg_v_blank + (u32)pipe * r->otg_stride, &vb);

        u32 h_total = (ht & 0x7FFFu) + 1u;
        u32 v_total = (vt & 0x7FFFu) + 1u;
        u32 h_bstart = hb & 0x7FFFu;
        u32 h_bend = (hb >> 16) & 0x7FFFu;
        u32 v_bstart = vb & 0x7FFFu;
        u32 v_bend = (vb >> 16) & 0x7FFFu;
        u32 w = (h_bstart > h_bend) ? (h_bstart - h_bend) : 0u;
        u32 h = (v_bstart > v_bend) ? (v_bstart - v_bend) : 0u;
        if (w < 320u || w > 7680u || h < 200u || h > 4320u) continue;

        struct dc_pipe_state *p = &dc->pipes[dc->active_pipe_count];
        memset(p, 0, sizeof(*p));
        p->active = true;
        p->pipe_idx = pipe;
        p->dig_idx = (u8)find_dig_for_pipe(adev, r, pipe, w, h, h_total, v_total);
        p->pending_buf = -1;

        /* Pair with connected connector: prefer exact DIG match with EDID, then any EDID sink, then any connected sink. */
        p->conn_idx = 0;
        bool paired = false;
        for (u32 ci = 0; ci < dc->connector_count; ci++) {
            if (dc->connectors[ci].connected && dc->connectors[ci].edid_blocks > 0 && ci == p->dig_idx) {
                p->conn_idx = (u8)ci;
                paired = true;
                break;
            }
        }
        if (!paired) {
            for (u32 ci = 0; ci < dc->connector_count; ci++) {
                if (dc->connectors[ci].connected && dc->connectors[ci].edid_blocks > 0) {
                    p->conn_idx = (u8)ci;
                    paired = true;
                    break;
                }
            }
        }
        if (!paired) {
            for (u32 ci = 0; ci < dc->connector_count; ci++) {
                if (dc->connectors[ci].connected) {
                    p->conn_idx = (u8)ci;
                    if (ci == p->dig_idx) break;
                }
            }
        }

        capture_pipe_snapshot(adev, r, pipe, p->dig_idx, &p->boot_snapshot);

        /* Auto-detect live DP MSA H/V bit layout & MISC0 byte position from UEFI's working registers.
         * Official DCN 4.0.1 (`dcn_4_1_0_sh_mask.h`) puts H in [31:16], V in [15:0] (`msa_h_low = false`),
         * and DP_MSA_MISC0 in [31:24] (`msa_misc0_high = true`). */
        {
            u32 p4 = p->boot_snapshot.dp_msa_param4;
            if (((p4 >> 16) & 0xFFFFu) == w && (p4 & 0xFFFFu) == h) {
                p->boot_snapshot.msa_h_low = false;
            } else if ((p4 & 0xFFFFu) == w && ((p4 >> 16) & 0xFFFFu) == h) {
                p->boot_snapshot.msa_h_low = true;
            } else {
                p->boot_snapshot.msa_h_low = false;
            }
            u32 col = p->boot_snapshot.dp_msa_colorimetry;
            if (((col >> 24) & 0xFFu) != 0) {
                p->boot_snapshot.msa_misc0_high = true;
            } else if ((col & 0xFFu) != 0) {
                p->boot_snapshot.msa_misc0_high = false;
            } else {
                p->boot_snapshot.msa_misc0_high = true;
            }

            u32 dim_wh = ((h & 0x3FFFu) << 16) | (w & 0x3FFFu);
            p->boot_snapshot.dscl_static_valid =
                (p->boot_snapshot.dscl_recout_size == dim_wh || p->boot_snapshot.dscl_mpc_size == dim_wh);
            if (!p->boot_snapshot.dscl_static_valid) {
                probe_dpp_size_regs(adev, r, pipe, w, h, &p->boot_snapshot);
            }
        }

        /* Measure live refresh rate from OTG_STATUS_FRAME_COUNT (bounded to ~55 ms, exits early at high Hz). */
        u32 total_df = 0;
        u32 measured_mhz = measure_otg_refresh_mhz(adev, r, pipe, &total_df);
        u32 refresh_mhz = measured_mhz ? measured_mhz : 60000u;

        dc_timing_cvt_rb(w, h, refresh_mhz, &p->current_mode);
        p->current_mode.h_blank = (h_total > w) ? (h_total - w) : 80u;
        p->current_mode.v_blank = (v_total > h) ? (v_total - h) : 45u;
        p->current_mode.refresh_mhz = refresh_mhz;
        p->current_mode.pixel_clock_khz = (u32)(((u64)h_total * (u64)v_total * (u64)refresh_mhz) / 1000000ULL);
        /* Snap boot pixel clock to exact matching EDID DTD (same H/V active & totals, within +-2 Hz)
         * to eliminate frame-counter measurement jitter in DCCG DTO reference clock derivation. */
        if (p->conn_idx < dc->connector_count) {
            const struct dc_connector *c = &dc->connectors[p->conn_idx];
            for (u32 m = 0; m < c->mode_count; m++) {
                const struct dc_timing *t = &c->modes[m];
                u32 d = t->refresh_mhz > refresh_mhz ? (t->refresh_mhz - refresh_mhz) : (refresh_mhz - t->refresh_mhz);
                if (t->h_active == w && t->v_active == h
                    && (t->h_active + t->h_blank) == h_total
                    && (t->v_active + t->v_blank) == v_total
                    && d <= 2000u && t->pixel_clock_khz > 0) {
                    p->current_mode.pixel_clock_khz = t->pixel_clock_khz;
                    p->current_mode.refresh_mhz = t->refresh_mhz;
                    refresh_mhz = t->refresh_mhz;
                    break;
                }
            }
        }
        p->src_width = w;
        p->src_height = h;
        p->pitch_bytes = ((p->boot_snapshot.hubp_surface_pitch & 0x3FFFu) + 1u) * 4u;
        if (p->pitch_bytes < w * 4u) p->pitch_bytes = ((w + 63u) & ~63u) * 4u;
        p->boot_snapshot.src_width = w;
        p->boot_snapshot.src_height = h;
        p->boot_snapshot.dst_width = w;
        p->boot_snapshot.dst_height = h;
        p->boot_snapshot.refresh_mhz = refresh_mhz;
        p->boot_snapshot.boot_pclk_khz = p->current_mode.pixel_clock_khz;
        p->boot_snapshot.boot_h_total = h_total;
        p->boot_snapshot.boot_h_blank_end = h_bend;
        p->boot_snapshot.boot_v_blank = (v_total > h) ? (v_total - h) : 45u;
        p->boot_snapshot.boot_v_blank_end = v_bend;
        u32 dto_src = r->has_otg_pixel_rate_div ? 100000u : 1000000u; /* 100 MHz REFCLK on DCN 4.0.1/3.2 */
        bool boot_dto_en = ((p->boot_snapshot.dccg_pixel_rate_cntl & DP_DTO_ENABLE_BIT) != 0);
        if (boot_dto_en && p->boot_snapshot.dccg_dto_modulo > 0) {
            u32 old_int = r->has_otg_pixel_rate_div
                ? ((p->boot_snapshot.dccg_pixel_rate_div >> (1u + (u32)(pipe & 3u) * 5u)) & 0xFu)
                : 0u;
            u64 den = (u64)old_int * (u64)p->boot_snapshot.dccg_dto_modulo + (u64)p->boot_snapshot.dccg_dto_phase;
            if (den > 0 && p->current_mode.pixel_clock_khz > 0) {
                u64 derived = ((u64)p->current_mode.pixel_clock_khz * (u64)p->boot_snapshot.dccg_dto_modulo) / den;
                if (derived >= 50000ULL && derived <= 3000000ULL) {
                    dto_src = (u32)derived;
                    p->boot_snapshot.dto_src_calibrated = true;
                }
            }
        }
        p->boot_snapshot.dto_src_clk_khz = dto_src;

        {
            const struct dc_connector *c = (p->conn_idx < dc->connector_count) ? &dc->connectors[p->conn_idx] : NULL;
            struct dc_log_buf lb = { { 0 }, 0 };
            dlog_str(&lb, "amdgpu: dc: pipe");
            dlog_u32(&lb, pipe);
            dlog_str(&lb, " dig=");
            dlog_u32(&lb, p->dig_idx);
            dlog_str(&lb, " msa_h_low=");
            dlog_u32(&lb, p->boot_snapshot.msa_h_low ? 1u : 0u);
            dlog_str(&lb, " ");
            dlog_u32(&lb, w);
            dlog_str(&lb, "x");
            dlog_u32(&lb, h);
            dlog_str(&lb, "@");
            dlog_u32(&lb, refresh_mhz / 1000u);
            dlog_str(&lb, "Hz dto_en=");
            dlog_u32(&lb, boot_dto_en ? 1u : 0u);
            dlog_str(&lb, " src=");
            dlog_u32(&lb, dto_src);
            dlog_str(&lb, "kHz p4=");
            dlog_hex(&lb, p->boot_snapshot.dp_msa_param4);
            dlog_str(&lb, " col=");
            dlog_hex(&lb, p->boot_snapshot.dp_msa_colorimetry);
            if (c && c->connected) {
                dlog_str(&lb, " link=");
                dlog_u32(&lb, c->trained_lanes);
                dlog_str(&lb, "x");
                dlog_u32(&lb, c->trained_rate_mbps);
                dlog_str(&lb, "Mbps modes=");
                dlog_u32(&lb, c->mode_count);
            }
            dlog_emit(adev, &lb);
        }
        {
            struct dc_log_buf lb = { { 0 }, 0 };
            dlog_str(&lb, "amdgpu: dc: boot ctl=");
            dlog_hex(&lb, p->boot_snapshot.dccg_pixel_rate_cntl);
            dlog_str(&lb, " div=");
            dlog_hex(&lb, p->boot_snapshot.dccg_pixel_rate_div);
            dlog_str(&lb, " ph=");
            dlog_u32(&lb, p->boot_snapshot.dccg_dto_phase);
            dlog_str(&lb, " mod=");
            dlog_u32(&lb, p->boot_snapshot.dccg_dto_modulo);
            dlog_str(&lb, " steer=");
            dlog_hex(&lb, p->boot_snapshot.dp_steer_fifo);
            dlog_str(&lb, " vs=");
            dlog_hex(&lb, p->boot_snapshot.dp_vid_stream_cntl);
            dlog_str(&lb, " df=");
            dlog_hex(&lb, p->boot_snapshot.dig_fifo_ctrl0);
            dlog_str(&lb, " vtg=");
            dlog_hex(&lb, p->boot_snapshot.vtg_control);
            dlog_str(&lb, " vsu=");
            dlog_hex(&lb, p->boot_snapshot.otg_vstartup_param);
            dlog_str(&lb, " dpp=");
            dlog_hex(&lb, p->boot_snapshot.dccg_dppclk_dto_param);
            dlog_emit(adev, &lb);
        }
        if (adev->dcn_version == DC_DCN_4_0_1) {
            u32 vco_khz = dcn401_read_vco_khz(adev);
            u32 disp_mhz = dcn401_dfs_did_to_khz(vco_khz, amdgpu_rreg32(adev, DCN401_CLK0_DISP_DFS_BYTE)) / 1000u;
            u32 dpp_mhz = dcn401_dfs_did_to_khz(vco_khz, amdgpu_rreg32(adev, DCN401_CLK0_DPP_DFS_BYTE)) / 1000u;
            u32 dcf_mhz = dcn401_dfs_did_to_khz(vco_khz, amdgpu_rreg32(adev, DCN401_CLK0_DCF_DFS_BYTE)) / 1000u;
            u32 dtb_mhz = dcn401_dfs_did_to_khz(vco_khz, amdgpu_rreg32(adev, DCN401_CLK0_DTB_DFS_BYTE)) / 1000u;
            u32 optc_g = 0;
            if (r->optc_input_global_ctrl != 0) {
                (void)dc_reg_read(adev, 2u, r->optc_input_global_ctrl + (u32)pipe * r->optc_input_stride, &optc_g);
            }
            struct dc_log_buf lb = { { 0 }, 0 };
            dlog_str(&lb, "amdgpu: dc: clk vco=");
            dlog_u32(&lb, vco_khz / 1000u);
            dlog_str(&lb, " disp=");
            dlog_u32(&lb, disp_mhz);
            dlog_str(&lb, " dpp=");
            dlog_u32(&lb, dpp_mhz);
            dlog_str(&lb, " dcf=");
            dlog_u32(&lb, dcf_mhz);
            dlog_str(&lb, " dtb=");
            dlog_u32(&lb, dtb_mhz);
            dlog_str(&lb, " dent=");
            dlog_hex(&lb, p->boot_snapshot.dccg_dentist_dispclk_cntl);
            dlog_emit(adev, &lb);

            struct dc_log_buf lb2 = { { 0 }, 0 };
            dlog_str(&lb2, "amdgpu: dc: hubp cntl=");
            dlog_hex(&lb2, p->boot_snapshot.hubp_cntl);
            dlog_str(&lb2, " optc=");
            dlog_hex(&lb2, optc_g);
            dlog_str(&lb2, " bo0=");
            dlog_hex(&lb2, p->boot_snapshot.hubp_blank_offset_0);
            dlog_str(&lb2, " r2p=");
            dlog_hex(&lb2, p->boot_snapshot.hubp_ref_freq_to_pix_freq);
            dlog_str(&lb2, " vsu=");
            dlog_hex(&lb2, p->boot_snapshot.otg_vstartup_param);
            dlog_emit(adev, &lb2);
        }

        /* Protect original UEFI GOP VRAM range and allocate triple-buffered scanout + 256 KiB HW cursor. */
        u64 gop_vram = 0;
        if (amdgpu_gmc_mc_to_vram(&adev->gmc, p->boot_snapshot.orig_mc_addr, &gop_vram)) {
            adev->gmc.gop_vram_start = gop_vram;
            adev->gmc.gop_vram_size = (u64)p->pitch_bytes * (u64)h;
            if (adev->gmc.gop_vram_size < (8ULL << 20)) adev->gmc.gop_vram_size = (8ULL << 20);
        }

        /* Allocate 3 scanout buffers: 32 MiB each on large ReBAR GPUs (supports up to 4K modesets), else 16 MiB. */
        u64 max_buf = (u64)p->pitch_bytes * (u64)h;
        u64 min_buf = (adev->gmc.visible_vram_size >= (256ULL << 20)) ? (32ULL << 20) : (16ULL << 20);
        if (max_buf < min_buf) max_buf = min_buf;
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

        /* Verified once >=2 scanout buffers are allocated and OTG frame counter is advancing. */
        if (p->buf_count >= 2u && total_df > 0) {
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
        invalidate_scanout_buffers(p);
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
            invalidate_scanout_buffers(p);
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
        if (conn && conn->connected && !dc->dmub.ring_owned) {
            u64 cur_bw = (u64)conn->trained_lanes * (u64)conn->trained_rate_mbps;
            u64 req_bw = (u64)plan.req_lanes * (u64)plan.req_rate_mbps;
            if (req_bw > cur_bw || (plan.requires_uhbr && conn->link_type != DC_LINK_DP_2_1)) {
                return -ENOTSUP;
            }
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
        if (p->pitch_bytes > 0 && (u64)copy_h * (u64)p->pitch_bytes > p->scanout_buf_size) {
            copy_h = (u32)(p->scanout_buf_size / (u64)p->pitch_bytes);
        }
        u32 row_bytes = req->primary_width * 4u;
        if (row_bytes > req->primary_pitch) row_bytes = req->primary_pitch;
        if (row_bytes > p->pitch_bytes) row_bytes = p->pitch_bytes;
        u32 copy_w = row_bytes / 4u;

        /* Update DPP scaler if client backbuffer dimensions differ from output mode. */
        if (req->primary_width != p->src_width || req->primary_height != p->src_height) {
            u32 hubp = (u32)p->pipe_idx * dc->regs->hubp_stride;
            (void)dc_reg_write(
                adev,
                2u,
                dc->regs->hubp_viewport_dim + hubp,
                ((req->primary_height & 0x3FFFu) << 16) | (req->primary_width & 0x3FFFu)
            );
            if (p->boot_snapshot.dscl_static_valid) {
                program_dpp_scaler(
                    adev,
                    dc->regs,
                    p->pipe_idx,
                    req->primary_width,
                    req->primary_height,
                    p->current_mode.h_active,
                    p->current_mode.v_active
                );
            } else {
                u32 dim = ((p->current_mode.v_active & 0x3FFFu) << 16) | (p->current_mode.h_active & 0x3FFFu);
                for (u8 i = 0; i < p->boot_snapshot.dpp_size_reg_count && i < 4u; i++) {
                    (void)dc_reg_write(adev, 2u, p->boot_snapshot.dpp_size_regs[i], dim);
                }
            }
            p->src_width = req->primary_width;
            p->src_height = req->primary_height;
            invalidate_scanout_buffers(p);
        }

        /* Compute incoming damage bounding box and propagate it into every scanout buffer's
         * dirty union so triple-buffered scanout copies only changed pixels per flip. */
        bool have_in = false;
        u32 in_x0 = 0u, in_y0 = 0u, in_x1 = copy_w, in_y1 = copy_h;
        if (copy_w > 0 && copy_h > 0) {
            if (req->damage_count == 0) {
                have_in = true;
            } else {
                u32 cnt = req->damage_count < DC_MAX_DAMAGE_RECTS ? req->damage_count : DC_MAX_DAMAGE_RECTS;
                in_x0 = copy_w;
                in_y0 = copy_h;
                in_x1 = 0u;
                in_y1 = 0u;
                for (u32 i = 0; i < cnt; i++) {
                    u32 rx0 = req->damage[i].x;
                    u32 ry0 = req->damage[i].y;
                    u32 rw = req->damage[i].w;
                    u32 rh = req->damage[i].h;
                    if (rw == 0 || rh == 0 || rx0 >= copy_w || ry0 >= copy_h) continue;
                    u32 rx1 = (rw > copy_w - rx0) ? copy_w : (rx0 + rw);
                    u32 ry1 = (rh > copy_h - ry0) ? copy_h : (ry0 + rh);
                    if (rx0 < in_x0) in_x0 = rx0;
                    if (ry0 < in_y0) in_y0 = ry0;
                    if (rx1 > in_x1) in_x1 = rx1;
                    if (ry1 > in_y1) in_y1 = ry1;
                    have_in = true;
                }
            }
        }
        if (have_in) {
            for (u32 b = 0; b < p->buf_count && b < DC_MAX_SCANOUT_BUFS; b++) {
                if (!p->buf_valid[b]) continue;
                if (!p->buf_dirty_any[b]) {
                    p->buf_dirty_any[b] = true;
                    p->buf_dirty_x0[b] = in_x0;
                    p->buf_dirty_y0[b] = in_y0;
                    p->buf_dirty_x1[b] = in_x1;
                    p->buf_dirty_y1[b] = in_y1;
                } else {
                    if (in_x0 < p->buf_dirty_x0[b]) p->buf_dirty_x0[b] = in_x0;
                    if (in_y0 < p->buf_dirty_y0[b]) p->buf_dirty_y0[b] = in_y0;
                    if (in_x1 > p->buf_dirty_x1[b]) p->buf_dirty_x1[b] = in_x1;
                    if (in_y1 > p->buf_dirty_y1[b]) p->buf_dirty_y1[b] = in_y1;
                }
            }
        }

        if (adev->io.vram_write && copy_w > 0 && copy_h > 0) {
            bool do_full = !p->buf_valid[next_buf];
            u32 ux0 = 0u, uy0 = 0u, ux1 = copy_w, uy1 = copy_h;
            if (!do_full && p->buf_dirty_any[next_buf]) {
                ux0 = p->buf_dirty_x0[next_buf];
                uy0 = p->buf_dirty_y0[next_buf];
                ux1 = p->buf_dirty_x1[next_buf];
                uy1 = p->buf_dirty_y1[next_buf];
                if (ux1 > copy_w) ux1 = copy_w;
                if (uy1 > copy_h) uy1 = copy_h;
                u64 dirty_px = (ux1 > ux0 && uy1 > uy0) ? (u64)(ux1 - ux0) * (u64)(uy1 - uy0) : 0ULL;
                u64 full_px = (u64)copy_w * (u64)copy_h;
                if (dirty_px * 100ULL >= full_px * 65ULL) {
                    do_full = true;
                }
            } else if (!do_full) {
                ux0 = ux1 = 0u;
                uy0 = uy1 = 0u;
            }

            if (do_full) {
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
                p->buf_valid[next_buf] = true;
                p->buf_dirty_any[next_buf] = false;
            } else if (ux1 > ux0 && uy1 > uy0) {
                u32 span_bytes = (ux1 - ux0) * 4u;
                if (ux0 == 0u && span_bytes == p->pitch_bytes && req->primary_pitch == p->pitch_bytes) {
                    (void)adev->io.vram_write(
                        adev->io.ctx,
                        dst_vram + (u64)uy0 * (u64)p->pitch_bytes,
                        req->primary_src + (size_t)uy0 * (size_t)req->primary_pitch,
                        (size_t)(uy1 - uy0) * (size_t)p->pitch_bytes
                    );
                } else {
                    u32 x_off = ux0 * 4u;
                    for (u32 y = uy0; y < uy1; y++) {
                        (void)adev->io.vram_write(
                            adev->io.ctx,
                            dst_vram + (u64)y * (u64)p->pitch_bytes + (u64)x_off,
                            req->primary_src + (size_t)y * (size_t)req->primary_pitch + (size_t)x_off,
                            span_bytes
                        );
                    }
                }
                p->buf_dirty_any[next_buf] = false;
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

bool dc_has_pending_flip(const struct amdgpu_device *adev) {
    if (!adev || !adev->dc) {
        return false;
    }
    const struct dc_state *dc = adev->dc;
    for (u32 i = 0; i < dc->active_pipe_count; i++) {
        if (dc->pipes[i].pending_buf >= 0) {
            return true;
        }
    }
    return false;
}

u32 dc_current_refresh_mhz(const struct amdgpu_device *adev) {
    if (!adev || !adev->dc || adev->dc->active_pipe_count == 0) {
        return 60000u;
    }
    u32 max_hz = 60000u;
    for (u32 i = 0; i < adev->dc->active_pipe_count; i++) {
        u32 hz = adev->dc->pipes[i].current_mode.refresh_mhz;
        if (hz > max_hz) {
            max_hz = hz;
        }
    }
    return max_hz;
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
        u32 fctl = 0, e_lo = 0, e_hi = 0;
        (void)dc_reg_read(adev, 2u, dc->regs->hubp_flip_control + hubp, &fctl);
        (void)dc_reg_read(adev, 2u, dc->regs->hubp_earliest_inuse + hubp, &e_lo);
        (void)dc_reg_read(adev, 2u, dc->regs->hubp_earliest_inuse_hi + hubp, &e_hi);
        u64 earliest = decode_mc_addr(e_lo, e_hi);
        u64 frame_ns = p->current_mode.refresh_mhz
            ? (1000000000000ULL / (u64)p->current_mode.refresh_mhz)
            : 16666667ULL;
        bool hw_done = ((fctl & FLIP_PENDING_BIT) == 0) && (earliest == 0 || earliest == p->pending_mc);
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
