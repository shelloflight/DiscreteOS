#include <dc.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>

/*
 * VESA Display Stream Compression (DSC) 1.2a Picture Parameter Set (PPS) generator
 * and DCN DSCC hardware encoder programmer.
 */

static const u8 DSC_RC_BUF_THRESH[14] = {
    14u, 28u, 42u, 56u, 70u, 84u, 98u, 105u, 112u, 119u, 121u, 123u, 125u, 126u
};

/* Standard VESA DSC 1.2a 8-bpc 8-bpp RC range parameters (min_qp, max_qp, bpg_offset). */
static const struct { u8 min_qp; u8 max_qp; s8 offset; } DSC_RC_RANGE_8BPC[15] = {
    { 0, 4,  2 }, { 0, 4,  0 }, { 1, 5,  0 }, { 1, 6, -2 }, { 3, 7, -4 },
    { 3, 7, -6 }, { 3, 7, -8 }, { 3, 8, -8 }, { 3, 9, -8 }, { 3, 10, -10 },
    { 5, 11, -10 }, { 5, 12, -12 }, { 5, 13, -12 }, { 7, 13, -12 }, { 13, 15, -12 },
};

static void put_be16(u8 *p, u16 v) {
    p[0] = (u8)((v >> 8) & 0xFFu);
    p[1] = (u8)(v & 0xFFu);
}

int dc_dsc_compute_pps(
    u16 width,
    u16 height,
    u8 bpc,
    u16 target_bpp_x16,
    u8 slice_count,
    struct dc_dsc_pps *out_pps
) {
    if (!out_pps || width < 320u || height < 200u || (bpc != 8u && bpc != 10u)) {
        return -EINVAL;
    }
    if (target_bpp_x16 < 128u || target_bpp_x16 > 384u) {
        return -ERANGE;
    }
    if (slice_count != 1u && slice_count != 2u && slice_count != 4u && slice_count != 8u) {
        slice_count = 2u;
    }
    while (slice_count > 1u && (width % slice_count) != 0) {
        slice_count /= 2u;
    }

    memset(out_pps, 0, sizeof(*out_pps));
    u16 slice_w = width / (u16)slice_count;
    u16 slice_h = 108u;
    if ((height % 108u) != 0) {
        if ((height % 72u) == 0) slice_h = 72u;
        else if ((height % 60u) == 0) slice_h = 60u;
        else if ((height % 32u) == 0) slice_h = 32u;
        else if ((height % 16u) == 0) slice_h = 16u;
        else slice_h = height;
    }

    u16 chunk_size = (u16)DIV_ROUND_UP((u32)slice_w * (u32)target_bpp_x16, 128u);
    u16 rc_model_size = 8192u;
    u16 initial_xmit_delay = 512u;
    u16 initial_offset = (target_bpp_x16 >= 192u) ? 2048u : 6144u;
    u16 initial_dec_delay = (u16)(526u + ((slice_w > 1920u) ? 96u : 0u));
    u8 initial_scale_val = (u8)((8u * rc_model_size) / (rc_model_size - initial_offset));
    u8 first_line_bpg = (slice_h >= 8u) ? 12u : 15u;

    u32 groups_per_line = DIV_ROUND_UP((u32)slice_w, 3u);
    u32 groups_total = groups_per_line * (u32)slice_h;
    u32 num_extra_mux_bits = 3u * (u32)(3u * bpc + 4u) - 2u;
    while (num_extra_mux_bits > 0 && ((num_extra_mux_bits % 48u) != 0)) {
        num_extra_mux_bits--;
    }
    u16 final_offset = (u16)(rc_model_size - (((u32)initial_xmit_delay * (u32)target_bpp_x16 + 8u) >> 4) + num_extra_mux_bits);
    u16 nfl_bpg_offset = (u16)DIV_ROUND_UP((u32)first_line_bpg << 11, (u32)(slice_h > 1u ? (slice_h - 1u) : 1u));
    u16 slice_bpg_offset = (u16)DIV_ROUND_UP((u32)(rc_model_size - initial_offset + num_extra_mux_bits) << 11, groups_total > 0 ? groups_total : 1u);
    u16 scale_dec_interval = (u16)((initial_scale_val > 8u) ? (groups_per_line / (u32)(initial_scale_val - 8u)) : 4095u);
    if (scale_dec_interval == 0) scale_dec_interval = 1u;
    u32 final_scale = (8u * (u32)rc_model_size) / (rc_model_size > final_offset ? (u32)(rc_model_size - final_offset) : 1u);
    u16 scale_inc_interval = 1024u;
    if (final_scale > 9u) {
        u32 denom = (final_scale - 9u) * (u32)(nfl_bpg_offset + slice_bpg_offset);
        if (denom > 0) {
            u32 inc = ((u32)final_offset << 11) / denom;
            scale_inc_interval = (u16)(inc > 65535u ? 65535u : (inc == 0 ? 1u : inc));
        }
    }

    /* Assemble 128-byte VESA DSC 1.2a PPS table (big-endian per VESA DSC 1.2a Table 4-1). */
    u8 *p = out_pps->raw;
    p[0] = 0x12u; /* DSC v1.2 */
    p[1] = 0x00u; /* PPS identifier */
    p[2] = 0x00u;
    p[3] = (u8)(((bpc & 0x0Fu) << 4) | 9u); /* bpc | linebuf_depth=9 */
    p[4] = (u8)((1u << 5) | (1u << 4) | ((target_bpp_x16 >> 8) & 0x03u)); /* block_pred_en | convert_rgb | bpp[9:8] */
    p[5] = (u8)(target_bpp_x16 & 0xFFu);
    put_be16(&p[6], height);
    put_be16(&p[8], width);
    put_be16(&p[10], slice_h);
    put_be16(&p[12], slice_w);
    put_be16(&p[14], chunk_size);
    put_be16(&p[16], initial_xmit_delay);
    put_be16(&p[18], initial_dec_delay);
    p[20] = 0;
    p[21] = initial_scale_val;
    put_be16(&p[22], scale_inc_interval);
    put_be16(&p[24], scale_dec_interval);
    p[26] = 0;
    p[27] = first_line_bpg;
    put_be16(&p[28], nfl_bpg_offset);
    put_be16(&p[30], slice_bpg_offset);
    put_be16(&p[32], initial_offset);
    put_be16(&p[34], final_offset);
    p[36] = (bpc == 10u) ? 7u : 3u;  /* flatness_min_qp */
    p[37] = (bpc == 10u) ? 16u : 12u; /* flatness_max_qp */
    put_be16(&p[38], rc_model_size);
    p[40] = 6u; /* rc_edge_factor */
    p[41] = (bpc == 10u) ? 15u : 11u; /* rc_quant_incr_limit0 */
    p[42] = (bpc == 10u) ? 15u : 11u; /* rc_quant_incr_limit1 */
    p[43] = 0x33u; /* rc_tgt_offset_hi=3 | rc_tgt_offset_lo=3 */
    memcpy(&p[44], DSC_RC_BUF_THRESH, 14u);
    u8 qp_bias = (bpc == 10u) ? 4u : 0u;
    for (u32 i = 0; i < 15u; i++) {
        u16 min_q = (u16)(DSC_RC_RANGE_8BPC[i].min_qp + qp_bias) & 0x1Fu;
        u16 max_q = (u16)(DSC_RC_RANGE_8BPC[i].max_qp + qp_bias) & 0x1Fu;
        u16 off6 = (u16)((u8)DSC_RC_RANGE_8BPC[i].offset & 0x3Fu);
        u16 word = (u16)((min_q << 11) | (max_q << 6) | off6);
        put_be16(&p[58u + i * 2u], word);
    }

    out_pps->valid = true;
    out_pps->bpc = bpc;
    out_pps->bpp_x16 = target_bpp_x16;
    out_pps->pic_width = width;
    out_pps->pic_height = height;
    out_pps->slice_width = slice_w;
    out_pps->slice_height = slice_h;
    out_pps->slice_count = slice_count;
    return 0;
}

int dc_dsc_program_hw(struct amdgpu_device *adev, struct dc_state *dc, u8 pipe, const struct dc_dsc_pps *pps, bool enable) {
    if (!adev || !dc || !dc->regs || pipe >= dc->regs->max_pipes) {
        return -EINVAL;
    }
    const struct dc_reg_table *r = dc->regs;
    u32 dsc_off = (u32)pipe * r->dsc_stride;

    if (!enable) {
        (void)dc_reg_write(adev, 2u, r->dsc_top_control + dsc_off, 0u);
        if (r->optc_dsc_forward_config != 0) {
            (void)dc_reg_write(adev, 2u, r->optc_dsc_forward_config + (u32)pipe, 0u);
        }
        return 0;
    }
    if (!pps || !pps->valid) {
        return -EINVAL;
    }
    /* Program 23 DCN DSCC_PPS_CONFIG0..22 dwords from the 128-byte VESA DSC 1.2a PPS table. */
    for (u32 i = 0; i < 23u; i++) {
        size_t bo = (size_t)i * 4u;
        u32 dw = (u32)pps->raw[bo + 0u]
            | ((u32)pps->raw[bo + 1u] << 8)
            | ((u32)pps->raw[bo + 2u] << 16)
            | ((u32)pps->raw[bo + 3u] << 24);
        (void)dc_reg_write(adev, 2u, r->dscc_pps_config0 + dsc_off + i, dw);
    }
    /* Enable DSC_TOP_CONTROL (clock + encoder enable) and OPTC forwarding. */
    (void)dc_reg_write(adev, 2u, r->dsc_top_control + dsc_off, 0x00000101u);
    if (r->optc_dsc_forward_config != 0) {
        (void)dc_reg_write(adev, 2u, r->optc_dsc_forward_config + (u32)pipe, (u32)(pipe + 1u));
    }
    return 0;
}
