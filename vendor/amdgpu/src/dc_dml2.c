#include <dc.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>

/*
 * Display Mode Library 2 (`dc_dml2.c`): deterministic fixed-point/integer mode validation,
 * clock/watermark calculation, MPC pipe-split selection, and DP 1.4/2.1 + HDMI 2.1 FRL + DSC 1.2a
 * link bandwidth planner for DCN 3.0 / 3.1.5 / 3.2 / 4.0.1.
 */

struct dcn_clock_limits {
    u32 max_dispclk_mhz;
    u32 max_dppclk_mhz;
    u32 max_dcfclk_mhz;
    u32 max_dtbclk_mhz;
    u32 max_uclk_mhz;
    u32 det_total_kb;
    u32 single_pipe_max_pclk_khz;
};

static struct dcn_clock_limits dcn_limits_for(enum dc_dcn_version ver) {
    struct dcn_clock_limits l;
    switch (ver) {
        case DC_DCN_4_0_1: /* RDNA 4 / Navi 48 RX 9070 */
            l.max_dispclk_mhz = 2170u;
            l.max_dppclk_mhz  = 2170u;
            l.max_dcfclk_mhz  = 1800u;
            l.max_dtbclk_mhz  = 1564u;
            l.max_uclk_mhz    = 1250u;
            l.det_total_kb    = 1152u;
            l.single_pipe_max_pclk_khz = 1600000u; /* >1.6 GHz uses 2:1 ODM/MPC combine */
            break;
        case DC_DCN_3_2: /* RDNA 3 / Navi 31/32/33 */
            l.max_dispclk_mhz = 2170u;
            l.max_dppclk_mhz  = 2170u;
            l.max_dcfclk_mhz  = 1564u;
            l.max_dtbclk_mhz  = 1564u;
            l.max_uclk_mhz    = 1250u;
            l.det_total_kb    = 1152u;
            l.single_pipe_max_pclk_khz = 1500000u;
            break;
        case DC_DCN_3_1_5: /* Ryzen 7000/9000 APU */
            l.max_dispclk_mhz = 1372u;
            l.max_dppclk_mhz  = 1372u;
            l.max_dcfclk_mhz  = 1200u;
            l.max_dtbclk_mhz  = 1200u;
            l.max_uclk_mhz    = 800u;
            l.det_total_kb    = 384u;
            l.single_pipe_max_pclk_khz = 1200000u;
            break;
        default: /* DCN 3.0 / RDNA 2 */
            l.max_dispclk_mhz = 1600u;
            l.max_dppclk_mhz  = 1600u;
            l.max_dcfclk_mhz  = 1200u;
            l.max_dtbclk_mhz  = 1200u;
            l.max_uclk_mhz    = 1000u;
            l.det_total_kb    = 384u;
            l.single_pipe_max_pclk_khz = 1200000u;
            break;
    }
    return l;
}

/* Effective payload bandwidth in kbps for a DP 1.4 (8b/10b), DP 2.1 (128b/132b), or HDMI 2.1 FRL link. */
static u64 effective_link_payload_kbps(enum dc_link_type type, u8 lanes, u32 rate_mbps) {
    u64 wire_kbps = (u64)lanes * (u64)rate_mbps * 1000ULL;
    if (type == DC_LINK_DP_2_1 || rate_mbps >= DC_DP_RATE_UHBR10_MBPS) {
        /* 128b/132b encoding (~96.71% payload efficiency including FEC/framing overhead). */
        return (wire_kbps * 965ULL) / 1000ULL;
    }
    if (type == DC_LINK_HDMI_21) {
        /* HDMI 2.1 FRL uses 16b/18b (~88.8% raw, ~85% usable video payload). */
        return (wire_kbps * 850ULL) / 1000ULL;
    }
    /* DP 1.4 8b/10b encoding (80% raw, ~77.5% usable with FEC when DSC is active). */
    return (wire_kbps * 800ULL) / 1000ULL;
}

void dc_timing_cvt_rb(u32 width, u32 height, u32 refresh_mhz, struct dc_timing *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (width < 320u || width > 7680u || height < 200u || height > 4320u
        || refresh_mhz < 24000u || refresh_mhz > 1000000u) {
        return;
    }
    const u32 h_blank = 80u;
    const u32 h_fp = 8u;
    const u32 h_sync = 32u;
    const u32 v_sync = 8u;
    const u32 v_bp = 6u;
    const u64 min_vbi_us = 460ULL;

    u64 rf = (u64)refresh_mhz;
    u64 denom = 1000000000ULL > (min_vbi_us * rf) ? (1000000000ULL - min_vbi_us * rf) : 0ULL;
    u32 v_blank = 0;
    if (denom > 100000000ULL) {
        u64 num = min_vbi_us * (u64)height * rf;
        u64 vbi = (num + denom - 1ULL) / denom;
        v_blank = (u32)(vbi > (v_sync + v_bp + 1u) ? vbi : (v_sync + v_bp + 1u));
    } else {
        v_blank = (height / 8u) > (v_sync + v_bp + 1u) ? (height / 8u) : (v_sync + v_bp + 1u);
    }
    if (v_blank > 2048u) v_blank = 2048u;
    u32 v_fp = v_blank > (v_sync + v_bp) ? (v_blank - v_sync - v_bp) : 1u;
    u32 h_total = width + h_blank;
    u32 v_total = height + v_blank;
    u64 pclk_khz = ((u64)h_total * (u64)v_total * rf + 500000ULL) / 1000000ULL;
    if (pclk_khz == 0 || pclk_khz > 0xFFFFFFFFULL) {
        return;
    }
    u64 actual_mhz = (pclk_khz * 1000000ULL) / ((u64)h_total * (u64)v_total);
    out->pixel_clock_khz = (u32)pclk_khz;
    out->h_active = width;
    out->h_blank = h_blank;
    out->h_front_porch = h_fp;
    out->h_sync_width = h_sync;
    out->v_active = height;
    out->v_blank = v_blank;
    out->v_front_porch = v_fp;
    out->v_sync_width = v_sync;
    out->h_sync_pos = true;
    out->v_sync_pos = false;
    out->refresh_mhz = (u32)actual_mhz;
}

int dc_dml2_plan_mode(
    const struct amdgpu_device *adev,
    const struct dc_connector *conn,
    const struct dc_timing *timing,
    u8 bpc,
    struct dc_dml2_plan *out_plan
) {
    if (!adev || !timing || !out_plan) {
        return -EINVAL;
    }
    memset(out_plan, 0, sizeof(*out_plan));
    if (timing->h_active < 320u || timing->h_active > 7680u
        || timing->v_active < 200u || timing->v_active > 4320u
        || timing->pixel_clock_khz == 0) {
        return -EINVAL;
    }
    if (bpc != 8u && bpc != 10u) {
        bpc = 8u;
    }

    struct dcn_clock_limits lim = dcn_limits_for(adev->dcn_version);
    u64 pclk_khz = (u64)timing->pixel_clock_khz;
    u64 raw_bw_kbps = pclk_khz * (u64)(3u * bpc);

    /* Pipe-split (2:1 ODM/MPC combine) if pixel clock exceeds single-pipe ceiling. */
    bool pipe_split = (pclk_khz > (u64)lim.single_pipe_max_pclk_khz);
    u32 pipes = pipe_split ? 2u : 1u;
    u32 eff_pclk_mhz = (u32)DIV_ROUND_UP(pclk_khz / pipes, 1000ULL);
    u32 dispclk_mhz = eff_pclk_mhz + (eff_pclk_mhz / 20u) + 50u; /* +5% margin */
    if (dispclk_mhz < 300u) dispclk_mhz = 300u;
    if (dispclk_mhz > lim.max_dispclk_mhz) {
        if (!pipe_split && (eff_pclk_mhz / 2u + 50u) <= lim.max_dispclk_mhz) {
            pipe_split = true;
            pipes = 2u;
            eff_pclk_mhz = (u32)DIV_ROUND_UP(pclk_khz / 2ULL, 1000ULL);
            dispclk_mhz = eff_pclk_mhz + (eff_pclk_mhz / 20u) + 50u;
        } else {
            return -ERANGE;
        }
    }
    u32 dppclk_mhz = dispclk_mhz;
    /* Memory bandwidth demand: width*height*4B*refresh -> DCFCLK @ 64B/cycle with 1.4x urgent headroom. */
    u64 mem_bps = pclk_khz * 1000ULL * 4ULL;
    u32 dcfclk_mhz = (u32)DIV_ROUND_UP((mem_bps * 14ULL) / 10ULL, 64ULL * 1000000ULL);
    if (dcfclk_mhz < 300u) dcfclk_mhz = 300u;
    if (dcfclk_mhz > lim.max_dcfclk_mhz) {
        return -ERANGE;
    }

    /* Choose minimum link rate/lanes & DSC 1.2a BPP that fits connector capabilities. */
    enum dc_link_type ltype = conn ? conn->link_type : DC_LINK_DP_1_4;
    u8 max_lanes = (conn && conn->max_lanes > 0) ? conn->max_lanes : 4u;
    u32 max_rate = (conn && conn->max_rate_mbps > 0) ? conn->max_rate_mbps : DC_DP_RATE_HBR3_MBPS;
    bool dsc_ok = conn ? conn->dsc_capable : true;

    u8 chosen_lanes = max_lanes;
    u32 chosen_rate = max_rate;
    bool use_dsc = false;
    u16 target_bpp_x16 = (u16)(3u * bpc * 16u);
    u8 slice_cnt = 1u;

    if (ltype == DC_LINK_HDMI_21) {
        static const struct { u8 lanes; u32 rate; } frl_modes[] = {
            { 3, DC_HDMI_FRL_3G_MBPS },
            { 3, DC_HDMI_FRL_6G_MBPS },
            { 4, DC_HDMI_FRL_6G_MBPS },
            { 4, DC_HDMI_FRL_8G_MBPS },
            { 4, DC_HDMI_FRL_10G_MBPS },
            { 4, DC_HDMI_FRL_12G_MBPS },
        };
        bool found = false;
        for (u32 i = 0; i < ARRAY_SIZE(frl_modes); i++) {
            if (frl_modes[i].lanes > max_lanes || frl_modes[i].rate > max_rate) continue;
            if (effective_link_payload_kbps(DC_LINK_HDMI_21, frl_modes[i].lanes, frl_modes[i].rate) >= raw_bw_kbps) {
                chosen_lanes = frl_modes[i].lanes;
                chosen_rate = frl_modes[i].rate;
                found = true;
                break;
            }
        }
        if (!found) {
            u64 cap = effective_link_payload_kbps(DC_LINK_HDMI_21, max_lanes, max_rate);
            if (!dsc_ok || raw_bw_kbps > cap * 3ULL) {
                return -ERANGE;
            }
            use_dsc = true;
            chosen_lanes = max_lanes;
            chosen_rate = max_rate;
        }
    } else {
        /* DisplayPort 1.4 / 2.1 (pick lowest link rate that carries uncompressed stream, else enable DSC 1.2a). */
        static const u32 dp_rates[] = {
            DC_DP_RATE_RBR_MBPS,
            DC_DP_RATE_HBR_MBPS,
            DC_DP_RATE_HBR2_MBPS,
            DC_DP_RATE_HBR3_MBPS,
            DC_DP_RATE_UHBR10_MBPS,
            DC_DP_RATE_UHBR13_5_MBPS,
            DC_DP_RATE_UHBR20_MBPS,
        };
        bool found = false;
        for (u32 i = 0; i < ARRAY_SIZE(dp_rates); i++) {
            u32 r = dp_rates[i];
            if (r > max_rate) break;
            if (r >= DC_DP_RATE_UHBR10_MBPS && conn && !conn->dp_uhbr_capable) break;
            enum dc_link_type lt = (r >= DC_DP_RATE_UHBR10_MBPS) ? DC_LINK_DP_2_1 : DC_LINK_DP_1_4;
            if (effective_link_payload_kbps(lt, max_lanes, r) >= raw_bw_kbps) {
                chosen_lanes = max_lanes;
                chosen_rate = r;
                found = true;
                break;
            }
        }
        if (!found) {
            enum dc_link_type lt = (max_rate >= DC_DP_RATE_UHBR10_MBPS) ? DC_LINK_DP_2_1 : DC_LINK_DP_1_4;
            /* With FEC enabled for DSC, usable payload is ~97.6% of normal payload. */
            u64 cap_dsc = (effective_link_payload_kbps(lt, max_lanes, max_rate) * 976ULL) / 1000ULL;
            /* VESA DSC 1.2a supports down to 8.0 bpp (3:1 for 8bpc, 3.75:1 for 10bpc). */
            u64 min_dsc_bw = pclk_khz * 8ULL;
            if (!dsc_ok || min_dsc_bw > cap_dsc) {
                return -ERANGE;
            }
            use_dsc = true;
            chosen_lanes = max_lanes;
            chosen_rate = max_rate;
            u64 max_bpp_x16 = (cap_dsc * 16ULL) / pclk_khz;
            if (max_bpp_x16 > (u64)(bpc == 10u ? 240u : 192u)) {
                max_bpp_x16 = (u64)(bpc == 10u ? 240u : 192u);
            }
            if (max_bpp_x16 < 128u) max_bpp_x16 = 128u; /* 8.0 bpp minimum */
            target_bpp_x16 = (u16)max_bpp_x16;
            slice_cnt = (timing->h_active >= 3840u) ? 4u : ((timing->h_active >= 2560u) ? 2u : 1u);
        }
    }

    if (use_dsc && slice_cnt == 1u && timing->h_active >= 2560u) {
        slice_cnt = (timing->h_active >= 3840u) ? 4u : 2u;
    }

    u32 dtbclk_mhz = (u32)DIV_ROUND_UP(pclk_khz, 1000ULL);
    if (dtbclk_mhz < 600u) dtbclk_mhz = 600u;
    if (dtbclk_mhz > lim.max_dtbclk_mhz) dtbclk_mhz = lim.max_dtbclk_mhz;

    u32 uclk_mhz = (dcfclk_mhz > 800u || timing->refresh_mhz >= 200000u) ? lim.max_uclk_mhz : (lim.max_uclk_mhz / 2u);

    out_plan->supported = true;
    out_plan->requires_dsc = use_dsc;
    out_plan->requires_pipe_split = pipe_split;
    out_plan->requires_uhbr = (chosen_rate >= DC_DP_RATE_UHBR10_MBPS);
    out_plan->bpc = bpc;
    out_plan->dsc_target_bpp_x16 = target_bpp_x16;
    out_plan->dsc_slice_count = slice_cnt;
    out_plan->dispclk_mhz = dispclk_mhz;
    out_plan->dppclk_mhz = dppclk_mhz;
    out_plan->dcfclk_mhz = dcfclk_mhz;
    out_plan->dtbclk_mhz = dtbclk_mhz;
    out_plan->uclk_mhz = uclk_mhz;
    out_plan->det_buffer_kb = lim.det_total_kb / (pipes * 2u);
    out_plan->urgent_watermark_ns = (adev->is_apu) ? 14000u : 6000u;
    out_plan->stutter_watermark_ns = (adev->is_apu) ? 45000u : 18000u;
    out_plan->raw_bandwidth_kbps = raw_bw_kbps;
    out_plan->effective_link_kbps = effective_link_payload_kbps(
        out_plan->requires_uhbr ? DC_LINK_DP_2_1 : ltype,
        chosen_lanes,
        chosen_rate
    );
    out_plan->req_lanes = chosen_lanes;
    out_plan->req_rate_mbps = chosen_rate;
    out_plan->pixel_rate_div = (pclk_khz > (u64)dtbclk_mhz * 1000ULL) ? 2u : 1u;
    return 0;
}
