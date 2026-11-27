#include <dc.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>

/*
 * Display Core Link Layer (`dc_link.c`):
 * - DP AUX engine with DCN 4.0.1 / 3.x arbitration & AUX_SW_AUTOINCREMENT_DISABLE
 * - DPCD 1.4 / 2.1 capability probing (RBR..HBR3, UHBR10/13.5/20, DSC 1.2a, Adaptive-Sync)
 * - I2C-over-AUX E-DDC EDID 1.4 + CTA-861 + DisplayID 2.0 multi-block reading & timing extraction
 * - Full DP 1.4 (8b/10b CR+EQ) & DP 2.1 (128b/132b UHBR) link training + HDMI 2.1 FRL SCDC training
 * - Multi-monitor HPD hotplug scanning
 */

/* DP AUX register bitmasks (AMD DCN 3.x / 4.x, matching dcn_4_1_0_sh_mask.h & dce_aux.c). */
#define AUX_EN_BIT                         (1u << 0)
#define AUX_SW_GO_BIT                      (1u << 0)
#define AUX_SW_AUTOINC_DISABLE_BIT         (1u << 31)
#define AUX_SW_DONE_ACK_BIT                (1u << 1)
#define AUX_ARB_SW_REQ_BIT                 (1u << 16)
#define AUX_ARB_SW_DONE_BIT                (1u << 17)
#define AUX_ARB_STATUS_SHIFT               2u
#define AUX_ARB_STATUS_MASK                0x3u
#define AUX_ARB_STATUS_SW_OWNED            1u
#define AUX_ARB_STATUS_DMCU_OWNED          2u
#define AUX_SW_DONE_BIT                    (1u << 0)
#define AUX_SW_RX_TIMEOUT_BIT              (1u << 7)
#define AUX_SW_HPD_DISCON_BIT              (1u << 9)
#define AUX_SW_RX_ERR_MASK                 ((1u << 8) | (1u << 10) | (1u << 11) | (1u << 12) \
                                           | (1u << 14) | (1u << 17) | (1u << 18) | (1u << 19) \
                                           | (1u << 20) | (1u << 22) | (1u << 23))
#define AUX_SW_REPLY_BYTES_SHIFT           24u
#define AUX_SW_REPLY_BYTES_MASK            0x1Fu

/* DPCD register addresses. */
#define DPCD_REV                           0x00000u
#define DPCD_MAX_LINK_RATE                 0x00001u
#define DPCD_MAX_LANE_COUNT                0x00002u
#define DPCD_DOWN_STREAM_PORT_COUNT        0x00007u
#define DPCD_DSC_SUPPORT                   0x00060u
#define DPCD_LINK_BW_SET                   0x00100u
#define DPCD_LANE_COUNT_SET                0x00101u
#define DPCD_TRAINING_PATTERN_SET          0x00102u
#define DPCD_TRAINING_LANE0_SET            0x00103u
#define DPCD_DOWNSPREAD_CTRL               0x00107u
#define DPCD_MAIN_LINK_CHANNEL_CODING_SET  0x00108u
#define DPCD_DSC_ENABLE                    0x00160u
#define DPCD_LANE0_1_STATUS                0x00202u
#define DPCD_LANE2_3_STATUS                0x00203u
#define DPCD_LANE_ALIGN_STATUS_UPDATED     0x00204u
#define DPCD_ADJUST_REQUEST_LANE0_1        0x00206u
#define DPCD_ADJUST_REQUEST_LANE2_3        0x00207u
#define DPCD_DP2_128B132B_CAP              0x02215u

/* DP AUX command codes (4-bit). */
#define AUX_CMD_I2C_WRITE                  0x00u
#define AUX_CMD_I2C_READ                   0x01u
#define AUX_CMD_I2C_MOT                    0x04u
#define AUX_CMD_NATIVE_WRITE               0x08u
#define AUX_CMD_NATIVE_READ                0x09u

/* DP AUX reply status codes. */
#define AUX_REPLY_ACK                      0x00u
#define AUX_REPLY_NACK                     0x01u
#define AUX_REPLY_DEFER                    0x02u

static u32 dpcd_byte_to_mbps(u8 code) {
    switch (code) {
        case 0x06u: return DC_DP_RATE_RBR_MBPS;
        case 0x0Au: return DC_DP_RATE_HBR_MBPS;
        case 0x14u: return DC_DP_RATE_HBR2_MBPS;
        case 0x1Eu: return DC_DP_RATE_HBR3_MBPS;
        case 0x01u: return DC_DP_RATE_UHBR10_MBPS;
        case 0x04u: return DC_DP_RATE_UHBR13_5_MBPS;
        case 0x02u: return DC_DP_RATE_UHBR20_MBPS;
        default:    return 0u;
    }
}

static u8 mbps_to_dpcd_byte(u32 mbps) {
    switch (mbps) {
        case DC_DP_RATE_RBR_MBPS:      return 0x06u;
        case DC_DP_RATE_HBR_MBPS:      return 0x0Au;
        case DC_DP_RATE_HBR2_MBPS:     return 0x14u;
        case DC_DP_RATE_HBR3_MBPS:     return 0x1Eu;
        case DC_DP_RATE_UHBR10_MBPS:   return 0x01u;
        case DC_DP_RATE_UHBR13_5_MBPS: return 0x04u;
        case DC_DP_RATE_UHBR20_MBPS:   return 0x02u;
        default:                       return 0x14u;
    }
}

int dc_aux_transfer(
    struct amdgpu_device *adev,
    const struct dc_reg_table *regs,
    u8 aux_idx,
    u8 cmd,
    u32 addr,
    u8 *data,
    u8 len,
    u8 *reply_out
) {
    if (!adev || !regs || aux_idx >= regs->max_aux || len > 16u) {
        return -EINVAL;
    }
    u32 stride = (u32)aux_idx * regs->aux_stride;
    u32 r_ctrl = regs->aux_control + stride;
    u32 r_sw_ctrl = regs->aux_sw_control + stride;
    u32 r_arb = regs->aux_arb_control + stride;
    u32 r_intr = regs->aux_interrupt_control + stride;
    u32 r_status = regs->aux_sw_status + stride;
    u32 r_data = regs->aux_sw_data + stride;

    /* Acquire SW AUX semaphore via AUX_ARB_CONTROL (fail only if DMCU explicitly holds ownership). */
    u32 arb0 = 0;
    if (!dc_reg_read(adev, 2u, r_arb, &arb0) || arb0 == 0xFFFFFFFFu) {
        return -ENODEV;
    }
    (void)dc_reg_write(adev, 2u, r_arb, arb0 | AUX_ARB_SW_REQ_BIT);
    bool arb_ok = false;
    for (u32 i = 0; i < 256u; i++) {
        u32 arb = 0;
        if (dc_reg_read(adev, 2u, r_arb, &arb)) {
            u32 st = (arb >> AUX_ARB_STATUS_SHIFT) & AUX_ARB_STATUS_MASK;
            if (st == AUX_ARB_STATUS_SW_OWNED || (st != AUX_ARB_STATUS_DMCU_OWNED && i >= 32u)) {
                arb_ok = true;
                break;
            }
        }
        if ((i & 15u) == 15u) {
            amdgpu_udelay(adev, 5u);
        }
    }
    if (!arb_ok) {
        (void)dc_reg_write(adev, 2u, r_arb, AUX_ARB_SW_DONE_BIT);
        return -EBUSY;
    }

    /* Ensure AUX engine is enabled (preserve HPD selection and timing configuration). */
    u32 ctrl = 0;
    if (!dc_reg_read(adev, 2u, r_ctrl, &ctrl)) {
        (void)dc_reg_write(adev, 2u, r_arb, AUX_ARB_SW_DONE_BIT);
        return -ENODEV;
    }
    if ((ctrl & AUX_EN_BIT) == 0) {
        (void)dc_reg_write(adev, 2u, r_ctrl, ctrl | AUX_EN_BIT);
    }

    bool is_read = ((cmd & 0x01u) != 0);
    bool is_i2c = ((cmd & 0x08u) == 0);
    u8 hdr[4];
    hdr[0] = (u8)(((cmd & 0x0Fu) << 4) | ((addr >> 16) & 0x0Fu));
    hdr[1] = (u8)((addr >> 8) & 0xFFu);
    hdr[2] = (u8)(addr & 0xFFu);
    hdr[3] = (len > 0) ? (u8)(len - 1u) : 0u;
    u32 tx_bytes = (len == 0) ? 3u : (is_read ? 4u : (4u + (u32)len));

    int rc = -ETIMEDOUT;
    u32 defers = 0u;
    u32 timeouts = 0u;

    for (;;) {
        /* Clear any stale SW_DONE interrupt status before kicking a new transaction. */
        (void)dc_reg_write(adev, 2u, r_intr, AUX_SW_DONE_ACK_BIT);

        /* Write TX header + payload with explicit index and autoincrement disabled (dce_aux.c). */
        for (u32 i = 0; i < tx_bytes; i++) {
            u8 b = (i < 4u) ? hdr[i] : (data ? data[i - 4u] : 0u);
            u32 dw = AUX_SW_AUTOINC_DISABLE_BIT | ((i & 0x1Fu) << 16) | ((u32)b << 8);
            (void)dc_reg_write(adev, 2u, r_data, dw);
        }

        /* Kick AUX_SW_CONTROL: AUX_SW_GO | (tx_bytes << 16) (exact byte count, NOT tx_bytes - 1). */
        (void)dc_reg_write(adev, 2u, r_sw_ctrl, AUX_SW_GO_BIT | ((tx_bytes & 0x1Fu) << 16));

        u32 st = 0;
        bool done = false;
        bool io_err = false;
        for (u32 i = 0; i < 400u; i++) {
            if (!dc_reg_read(adev, 2u, r_status, &st)) {
                io_err = true;
                break;
            }
            if ((st & AUX_SW_DONE_BIT) != 0) {
                done = true;
                break;
            }
            amdgpu_udelay(adev, 10u);
        }
        (void)dc_reg_write(adev, 2u, r_intr, AUX_SW_DONE_ACK_BIT);

        if (io_err) {
            rc = -EIO;
            break;
        }
        if (!done || (st & AUX_SW_RX_TIMEOUT_BIT) != 0) {
            timeouts++;
            if (timeouts <= 3u) {
                amdgpu_udelay(adev, 500u);
                continue;
            }
            rc = -ETIMEDOUT;
            break;
        }
        if ((st & AUX_SW_HPD_DISCON_BIT) != 0) {
            rc = -ENODEV;
            break;
        }
        if ((st & AUX_SW_RX_ERR_MASK) != 0) {
            timeouts++;
            if (timeouts <= 3u) {
                amdgpu_udelay(adev, 400u);
                continue;
            }
            rc = -EIO;
            break;
        }

        u32 rx_cnt = (st >> AUX_SW_REPLY_BYTES_SHIFT) & AUX_SW_REPLY_BYTES_MASK;
        if (rx_cnt == 0) {
            rc = -EIO;
            break;
        }

        /* Read reply byte 0 at explicit FIFO index 0 with read mode bit (bit 0 = 1). */
        (void)dc_reg_write(adev, 2u, r_data, AUX_SW_AUTOINC_DISABLE_BIT | 1u);
        u32 d0 = 0;
        (void)dc_reg_read(adev, 2u, r_data, &d0);
        u8 reply = (u8)((d0 >> 8) & 0xFFu);
        if (reply_out) *reply_out = reply;
        u8 rcode = (u8)(reply >> 4);
        bool is_defer = is_i2c
            ? (((rcode & 0x0Cu) == 0x08u) || ((rcode & 0x03u) == 0x02u))
            : ((rcode & 0x03u) == 0x02u);
        bool is_nack = is_i2c
            ? (((rcode & 0x0Cu) == 0x04u) || ((rcode & 0x03u) == 0x01u))
            : ((rcode & 0x03u) == 0x01u);

        if (is_defer) {
            defers++;
            if (defers <= 7u) {
                amdgpu_udelay(adev, 400u);
                continue;
            }
            rc = -EAGAIN;
            break;
        }
        if (is_nack) {
            rc = -EIO;
            break;
        }

        if (is_read && data && len > 0) {
            u32 avail = (rx_cnt > 1u) ? (rx_cnt - 1u) : 0u;
            u32 to_copy = avail < len ? avail : len;
            for (u32 j = 0; j < to_copy; j++) {
                (void)dc_reg_write(adev, 2u, r_data, AUX_SW_AUTOINC_DISABLE_BIT | (((j + 1u) & 0x1Fu) << 16) | 1u);
                u32 dj = 0;
                (void)dc_reg_read(adev, 2u, r_data, &dj);
                data[j] = (u8)((dj >> 8) & 0xFFu);
            }
            if (to_copy < len) {
                rc = -EIO;
                break;
            }
        }
        rc = 0;
        break;
    }

    (void)dc_reg_write(adev, 2u, r_arb, AUX_ARB_SW_DONE_BIT);
    return rc;
}

int dc_dpcd_read(struct amdgpu_device *adev, const struct dc_reg_table *regs, u8 aux_idx, u32 addr, u8 *buf, u8 len) {
    if (!buf || len == 0 || len > 16u) {
        return -EINVAL;
    }
    for (u32 tries = 0; tries < 5u; tries++) {
        u8 rep = 0;
        int rc = dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_NATIVE_READ, addr, buf, len, &rep);
        if (rc == 0) return 0;
        if (rc != -EAGAIN) return rc;
        amdgpu_udelay(adev, 400u);
    }
    return -ETIMEDOUT;
}

int dc_dpcd_write(struct amdgpu_device *adev, const struct dc_reg_table *regs, u8 aux_idx, u32 addr, const u8 *buf, u8 len) {
    if (!buf || len == 0 || len > 16u) {
        return -EINVAL;
    }
    u8 tmp[16];
    memcpy(tmp, buf, len);
    for (u32 tries = 0; tries < 5u; tries++) {
        u8 rep = 0;
        int rc = dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_NATIVE_WRITE, addr, tmp, len, &rep);
        if (rc == 0) return 0;
        if (rc != -EAGAIN) return rc;
        amdgpu_udelay(adev, 400u);
    }
    return -ETIMEDOUT;
}

static bool edid_checksum_ok(const u8 *blk) {
    u8 sum = 0;
    for (u32 i = 0; i < 128u; i++) {
        sum = (u8)(sum + blk[i]);
    }
    return sum == 0;
}

/* Read up to 4 blocks (512 bytes) of EDID via I2C-over-AUX (E-DDC segment 0x30 + EDID 0x50). */
static u8 read_edid_over_aux(struct amdgpu_device *adev, const struct dc_reg_table *regs, u8 aux_idx, u8 out[DC_EDID_MAX_BYTES]) {
    memset(out, 0, DC_EDID_MAX_BYTES);
    u8 off_byte = 0;
    u8 rep = 0;
    if (dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_WRITE | AUX_CMD_I2C_MOT, 0x50u, &off_byte, 1u, &rep) != 0) {
        return 0;
    }
    for (u32 chunk = 0; chunk < 8u; chunk++) {
        if (dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_READ | AUX_CMD_I2C_MOT, 0x50u, &out[chunk * 16u], 16u, &rep) != 0) {
            (void)dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_READ, 0x50u, NULL, 0u, &rep);
            return 0;
        }
    }
    /* Address-only I2C STOP (MOT=0, 0 data bytes). */
    (void)dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_READ, 0x50u, NULL, 0u, &rep);

    static const u8 hdr[8] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    if (memcmp(out, hdr, 8u) != 0 || !edid_checksum_ok(out)) {
        return 0;
    }
    u8 ext = out[126];
    u8 blocks = 1u;
    u8 max_ext = ext > 3u ? 3u : ext;
    for (u8 b = 1u; b <= max_ext; b++) {
        u8 seg = b / 2u;
        u8 boff = (u8)((b & 1u) * 128u);
        if (seg > 0) {
            (void)dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_WRITE | AUX_CMD_I2C_MOT, 0x30u, &seg, 1u, &rep);
        }
        if (dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_WRITE | AUX_CMD_I2C_MOT, 0x50u, &boff, 1u, &rep) != 0) {
            break;
        }
        bool ok = true;
        for (u32 chunk = 0; chunk < 8u; chunk++) {
            if (dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_READ | AUX_CMD_I2C_MOT, 0x50u, &out[b * 128u + chunk * 16u], 16u, &rep) != 0) {
                ok = false;
                break;
            }
        }
        (void)dc_aux_transfer(adev, regs, aux_idx, AUX_CMD_I2C_READ, 0x50u, NULL, 0u, &rep);
        if (ok && edid_checksum_ok(&out[b * 128u])) {
            blocks++;
        } else {
            break;
        }
    }
    return blocks;
}

void dc_connector_push_mode(struct dc_connector *conn, const struct dc_timing *t) {
    if (!conn || !t || t->h_active < 320u || t->v_active < 200u || t->pixel_clock_khz == 0) {
        return;
    }
    for (u32 i = 0; i < conn->mode_count; i++) {
        u32 d = conn->modes[i].refresh_mhz > t->refresh_mhz
            ? (conn->modes[i].refresh_mhz - t->refresh_mhz)
            : (t->refresh_mhz - conn->modes[i].refresh_mhz);
        if (conn->modes[i].h_active == t->h_active && conn->modes[i].v_active == t->v_active && d <= 500u) {
            if (t->preferred) conn->modes[i].preferred = true;
            return;
        }
    }
    if (conn->mode_count < DC_MAX_MODES) {
        conn->modes[conn->mode_count++] = *t;
    }
}

static void parse_dtd_18(const u8 d[18], bool preferred, struct dc_connector *conn) {
    u16 pclk10 = (u16)d[0] | ((u16)d[1] << 8);
    if (pclk10 == 0 || (d[17] & 0x80u) != 0) return;
    u32 ha = (u32)d[2] | ((u32)(d[4] >> 4) << 8);
    u32 hb = (u32)d[3] | ((u32)(d[4] & 0x0Fu) << 8);
    u32 va = (u32)d[5] | ((u32)(d[7] >> 4) << 8);
    u32 vb = (u32)d[6] | ((u32)(d[7] & 0x0Fu) << 8);
    if (ha < 320u || va < 200u || hb == 0 || vb == 0) return;
    struct dc_timing t;
    memset(&t, 0, sizeof(t));
    t.pixel_clock_khz = (u32)pclk10 * 10u;
    t.h_active = ha;
    t.h_blank = hb;
    t.h_front_porch = (u32)d[8] | ((u32)((d[11] >> 6) & 3u) << 8);
    t.h_sync_width = (u32)d[9] | ((u32)((d[11] >> 4) & 3u) << 8);
    t.v_active = va;
    t.v_blank = vb;
    t.v_front_porch = (u32)(d[10] >> 4) | ((u32)((d[11] >> 2) & 3u) << 4);
    t.v_sync_width = (u32)(d[10] & 0x0Fu) | ((u32)(d[11] & 3u) << 4);
    t.h_sync_pos = (d[17] & 0x02u) != 0;
    t.v_sync_pos = (d[17] & 0x04u) != 0;
    u64 denom = (u64)(ha + hb) * (u64)(va + vb);
    t.refresh_mhz = denom ? (u32)(((u64)t.pixel_clock_khz * 1000000ULL) / denom) : 60000u;
    t.preferred = preferred;
    dc_connector_push_mode(conn, &t);
}

static void parse_edid_into_connector(struct dc_connector *conn) {
    if (!conn || conn->edid_blocks == 0) {
        return;
    }
    const u8 *b0 = conn->edid_raw;
    /* Base block DTDs, monitor name (0xFC), and VRR range limits (0xFD). */
    for (u32 slot = 0; slot < 4u; slot++) {
        const u8 *d = b0 + 54u + slot * 18u;
        if (d[0] != 0 || d[1] != 0) {
            parse_dtd_18(d, slot == 0, conn);
        } else if (d[2] == 0 && d[3] == 0xFCu && d[4] == 0) {
            u32 len = 0;
            for (u32 i = 0; i < 13u; i++) {
                u8 c = d[5u + i];
                if (c == 0x0Au || c == 0x00u) break;
                if (c >= 0x20u && c <= 0x7Eu) conn->monitor_name[len++] = (char)c;
            }
            while (len > 0 && conn->monitor_name[len - 1u] == ' ') len--;
            conn->monitor_name[len] = '\0';
        } else if (d[2] == 0 && d[3] == 0xFDu) {
            u8 fl = d[4];
            u16 vmin = (u16)d[5] + (((fl & 3u) == 3u) ? 255u : 0u);
            u16 vmax = (u16)d[6] + (((fl & 3u) >= 2u) ? 255u : 0u);
            if (vmin >= 24u && vmax >= vmin && vmax <= 1000u) {
                conn->vrr_min_hz = vmin;
                conn->vrr_max_hz = vmax;
                if (vmax > vmin) conn->vrr_capable = true;
            }
        }
    }

    /* Extension blocks: CTA-861 (0x02: DTDs, FreeSync VSDB, HDR10 Static Metadata, HDMI 2.1 HF-VSDB) & DisplayID 2.0 (0x70). */
    for (u8 b = 1u; b < conn->edid_blocks && b < 4u; b++) {
        const u8 *ext = conn->edid_raw + (size_t)b * 128u;
        if (ext[0] == 0x02u) {
            u8 dtd_off = ext[2];
            if (dtd_off >= 4u && dtd_off <= 127u) {
                for (u32 off = dtd_off; off + 18u <= 127u; off += 18u) {
                    if (ext[off] == 0 && ext[off + 1u] == 0) break;
                    parse_dtd_18(ext + off, false, conn);
                }
                u32 pos = 4u;
                while (pos < dtd_off) {
                    u8 hdr = ext[pos];
                    u8 tag = (hdr >> 5) & 7u;
                    u8 len = hdr & 0x1Fu;
                    if (pos + 1u + len > dtd_off) break;
                    const u8 *body = ext + pos + 1u;
                    if (tag == 3u && len >= 7u) {
                        /* AMD FreeSync VSDB (OUI 00-00-1A) */
                        if (body[0] == 0x1Au && body[1] == 0x00u && body[2] == 0x00u) {
                            u16 vmin = body[5];
                            u16 vmax = body[6];
                            if (vmin >= 24u && vmax > vmin) {
                                conn->vrr_min_hz = vmin;
                                conn->vrr_max_hz = vmax;
                                conn->vrr_capable = true;
                            }
                        }
                        /* HDMI Forum VSDB (OUI C4-5D-D8): HDMI 2.1 FRL max rate */
                        if (body[0] == 0xD8u && body[1] == 0x5Du && body[2] == 0xC4u && len >= 7u) {
                            u8 frl = (body[6] >> 4) & 0x0Fu;
                            if (frl > 0) {
                                conn->hdmi_frl_capable = true;
                                conn->hdmi_max_frl_rate = frl;
                            }
                        }
                    } else if (tag == 7u && len >= 3u && body[0] == 0x06u) {
                        /* CTA-861-G HDR Static Metadata Data Block (SMPTE ST 2084 PQ = bit 2) */
                        if ((body[1] & 0x04u) != 0) {
                            conn->hdr_capable = true;
                            conn->hdr_max_nits = (len >= 4u && body[3] != 0) ? 1000u : 400u;
                        }
                    }
                    pos += 1u + len;
                }
            }
        } else if (ext[0] == 0x70u) {
            /* DisplayID 1.3 / 2.0 Type I (0x03, 10 kHz) and Type VII (0x22, 1 kHz) timings (240–540+ Hz!). */
            u32 plen = ext[2];
            if (plen > 121u) plen = 121u;
            u32 end = 5u + plen;
            if (end > 126u) end = 126u;
            u32 pos = 5u;
            while (pos + 3u <= end) {
                u8 btag = ext[pos];
                u8 blen = ext[pos + 2u];
                u32 start = pos + 3u;
                if (start + blen > end) break;
                if (btag == 0x03u || btag == 0x22u) {
                    u32 scale = (btag == 0x03u) ? 10u : 1u;
                    for (u32 o = 0; o + 20u <= blen; o += 20u) {
                        const u8 *d = ext + start + o;
                        u32 pclk_raw = (u32)d[0] | ((u32)d[1] << 8) | ((u32)d[2] << 16);
                        u32 ha = ((u32)d[4] | ((u32)d[5] << 8)) + 1u;
                        u32 hb = ((u32)d[6] | ((u32)d[7] << 8)) + 1u;
                        u32 hfp = (((u32)d[8] | ((u32)d[9] << 8)) & 0x7FFFu) + 1u;
                        u32 hsw = ((u32)d[10] | ((u32)d[11] << 8)) + 1u;
                        u32 va = ((u32)d[12] | ((u32)d[13] << 8)) + 1u;
                        u32 vb = ((u32)d[14] | ((u32)d[15] << 8)) + 1u;
                        u32 vfp = (((u32)d[16] | ((u32)d[17] << 8)) & 0x7FFFu) + 1u;
                        u32 vsw = ((u32)d[18] | ((u32)d[19] << 8)) + 1u;
                        struct dc_timing t;
                        memset(&t, 0, sizeof(t));
                        t.pixel_clock_khz = (pclk_raw + 1u) * scale;
                        t.h_active = ha;
                        t.h_blank = hb;
                        t.h_front_porch = hfp;
                        t.h_sync_width = hsw;
                        t.v_active = va;
                        t.v_blank = vb;
                        t.v_front_porch = vfp;
                        t.v_sync_width = vsw;
                        t.h_sync_pos = (d[9] & 0x80u) != 0;
                        t.v_sync_pos = (d[17] & 0x80u) != 0;
                        u64 denom = (u64)(ha + hb) * (u64)(va + vb);
                        t.refresh_mhz = denom ? (u32)(((u64)t.pixel_clock_khz * 1000000ULL) / denom) : 60000u;
                        t.preferred = (d[3] & 0x80u) != 0;
                        dc_connector_push_mode(conn, &t);
                    }
                }
                pos = start + blen;
            }
        }
    }
}

int dc_link_probe_all(struct amdgpu_device *adev, struct dc_state *dc) {
    if (!adev || !dc || !dc->regs) {
        return -EINVAL;
    }
    const struct dc_reg_table *r = dc->regs;
    dc->connector_count = 0;
    u8 max_aux = r->max_aux > DC_MAX_CONNECTORS ? (u8)DC_MAX_CONNECTORS : r->max_aux;

    for (u8 a = 0; a < max_aux; a++) {
        struct dc_connector *c = &dc->connectors[a];
        memset(c, 0, sizeof(*c));
        c->present = true;
        c->index = a;
        c->aux_idx = a;
        c->dig_idx = a;
        c->hpd_idx = a;
        c->link_type = DC_LINK_DP_1_4;
        dc->connector_count++;

        /* Check HPD live sense bit (`DC_HPD_INT_STATUS` bit 1 = DC_HPD_SENSE). */
        u32 hpd_st = 0;
        bool hpd_sense = dc_reg_read(adev, 2u, r->hpd_int_status + (u32)a * r->hpd_stride, &hpd_st)
            && ((hpd_st & 0x02u) != 0);

        /* Probe DPCD 0x0000..0x0007 over DP AUX. */
        u8 dpcd[8];
        memset(dpcd, 0, sizeof(dpcd));
        if (dc_dpcd_read(adev, r, a, DPCD_REV, dpcd, 8u) == 0 && dpcd[0] >= 0x11u) {
            c->connected = true;
            c->max_rate_mbps = dpcd_byte_to_mbps(dpcd[1]);
            if (c->max_rate_mbps == 0) c->max_rate_mbps = DC_DP_RATE_HBR2_MBPS;
            c->max_lanes = dpcd[2] & 0x1Fu;
            if (c->max_lanes == 0 || c->max_lanes > 4u) c->max_lanes = 4u;
            if ((dpcd[7] & 0x40u) != 0) {
                c->vrr_capable = true; /* MSA_TIMING_PAR_IGNORED */
            }

            /* Check DP 2.1 128b/132b UHBR rates (DPCD 0x2215). */
            u8 uhbr = 0;
            if (dpcd[0] >= 0x14u && dc_dpcd_read(adev, r, a, DPCD_DP2_128B132B_CAP, &uhbr, 1u) == 0 && uhbr != 0) {
                c->dp_uhbr_capable = true;
                c->link_type = DC_LINK_DP_2_1;
                if ((uhbr & 0x02u) != 0) c->max_rate_mbps = DC_DP_RATE_UHBR20_MBPS;
                else if ((uhbr & 0x04u) != 0) c->max_rate_mbps = DC_DP_RATE_UHBR13_5_MBPS;
                else if ((uhbr & 0x01u) != 0) c->max_rate_mbps = DC_DP_RATE_UHBR10_MBPS;
            }

            /* Check VESA DSC 1.2a capability (DPCD 0x0060). */
            u8 dsc_cap = 0;
            if (dc_dpcd_read(adev, r, a, DPCD_DSC_SUPPORT, &dsc_cap, 1u) == 0 && (dsc_cap & 0x01u) != 0) {
                c->dsc_capable = true;
            }

            /* Read current trained link configuration (DPCD 0x0100..0x0101); default to sink max on read hiccup. */
            c->trained_rate_mbps = c->max_rate_mbps;
            c->trained_lanes = c->max_lanes;
            u8 cur_cfg[2] = { 0, 0 };
            if (dc_dpcd_read(adev, r, a, DPCD_LINK_BW_SET, cur_cfg, 2u) == 0) {
                u32 tr = dpcd_byte_to_mbps(cur_cfg[0]);
                u8 tl = cur_cfg[1] & 0x1Fu;
                if (tr != 0) c->trained_rate_mbps = tr;
                if (tl >= 1u && tl <= 4u) c->trained_lanes = tl;
            }

            /* Read E-DDC EDID over I2C-over-AUX and extract modes/VRR/HDR10. */
            c->edid_blocks = read_edid_over_aux(adev, r, a, c->edid_raw);
            if (c->edid_blocks > 0) {
                parse_edid_into_connector(c);
            }
        } else if (hpd_sense) {
            /* HPD asserted without DPCD response indicates an HDMI 2.0/2.1 sink. */
            c->connected = true;
            c->link_type = DC_LINK_HDMI_21;
            c->max_lanes = 4u;
            c->max_rate_mbps = DC_HDMI_FRL_12G_MBPS;
            c->hdmi_frl_capable = true;
            c->dsc_capable = true;
            c->trained_lanes = 4u;
            c->trained_rate_mbps = DC_HDMI_FRL_6G_MBPS;
        }
    }
    return 0;
}

int dc_link_train_dp(
    struct amdgpu_device *adev,
    struct dc_state *dc,
    struct dc_connector *conn,
    u8 target_lanes,
    u32 target_rate_mbps
) {
    if (!adev || !dc || !dc->regs || !conn || target_lanes == 0 || target_lanes > 4u) {
        return -EINVAL;
    }
    const struct dc_reg_table *r = dc->regs;
    bool uhbr = (target_rate_mbps >= DC_DP_RATE_UHBR10_MBPS);
    if (uhbr && !conn->dp_uhbr_capable) {
        return -ENOTSUP;
    }

    /* Preserve prior DPCD link configuration so any training failure restores the live link cleanly. */
    u8 old_bw[2] = { mbps_to_dpcd_byte(conn->trained_rate_mbps), (u8)(conn->trained_lanes | 0x80u) };
    u8 old_coding = (conn->link_type == DC_LINK_DP_2_1) ? 0x02u : 0x01u;
    (void)dc_dpcd_read(adev, r, conn->aux_idx, DPCD_LINK_BW_SET, old_bw, 2u);
    (void)dc_dpcd_read(adev, r, conn->aux_idx, DPCD_MAIN_LINK_CHANNEL_CODING_SET, &old_coding, 1u);

    /* Request DMCUB PHY transmitter setup only when DMCUB ring is owned by this driver. */
    if (dc->dmub.fw_alive && dc->dmub.ring_owned) {
        u32 cmd[16];
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x00000043u; /* DMUB_CMD__VBIOS_DIG1_TRANSMITTER_CONTROL */
        cmd[1] = (u32)conn->dig_idx;
        cmd[2] = (u32)target_lanes;
        cmd[3] = target_rate_mbps;
        (void)dc_dmub_submit_cmd(adev, dc, cmd);
    }

    u8 bw_set[2];
    bw_set[0] = mbps_to_dpcd_byte(target_rate_mbps);
    bw_set[1] = (u8)(target_lanes | 0x80u); /* Enhanced framing enabled */
    if (dc_dpcd_write(adev, r, conn->aux_idx, DPCD_LINK_BW_SET, bw_set, 2u) != 0) {
        return -EIO;
    }
    u8 coding = uhbr ? 0x02u : 0x01u; /* 0x02 = 128b/132b, 0x01 = ANSI 8b/10b */
    (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_MAIN_LINK_CHANNEL_CODING_SET, &coding, 1u);

    /* Phase 1: Clock Recovery (TPS1 for 8b/10b, 128b/132b_TPS1 for UHBR). */
    u8 tps1 = 0x21u; /* Pattern 1 + scrambling disabled */
    (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_TRAINING_PATTERN_SET, &tps1, 1u);

    u8 lane_set[4] = { 0, 0, 0, 0 };
    bool cr_ok = false;
    for (u32 attempt = 0; attempt < 5u; attempt++) {
        (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_TRAINING_LANE0_SET, lane_set, target_lanes);
        amdgpu_udelay(adev, 100u);
        u8 st[6] = { 0 };
        if (dc_dpcd_read(adev, r, conn->aux_idx, DPCD_LANE0_1_STATUS, st, 6u) != 0) {
            break;
        }
        bool all_cr = true;
        for (u8 l = 0; l < target_lanes; l++) {
            u8 nib = (st[l / 2u] >> ((l & 1u) * 4u)) & 0x0Fu;
            if ((nib & 0x01u) == 0) all_cr = false;
        }
        if (all_cr) {
            cr_ok = true;
            break;
        }
        /* Apply sink-requested voltage swing / pre-emphasis adjustments. */
        for (u8 l = 0; l < target_lanes; l++) {
            u8 adj = (st[4u + l / 2u] >> ((l & 1u) * 4u)) & 0x0Fu;
            u8 sw = adj & 0x03u;
            u8 pe = (adj >> 2) & 0x03u;
            lane_set[l] = (u8)((pe << 3) | sw | (sw == 3u ? 0x04u : 0u) | (pe == 3u ? 0x20u : 0u));
        }
    }

    if (!cr_ok) {
        u8 stop = 0;
        (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_LINK_BW_SET, old_bw, 2u);
        (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_MAIN_LINK_CHANNEL_CODING_SET, &old_coding, 1u);
        (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_TRAINING_PATTERN_SET, &stop, 1u);
        return -EIO;
    }

    /* Phase 2: Channel Equalization (TPS4 for HBR3 / TPS3 for HBR2 / 128b/132b TPS2 for UHBR). */
    u8 eq_pat = uhbr ? 0x02u : ((target_rate_mbps >= DC_DP_RATE_HBR3_MBPS) ? 0x07u : 0x23u);
    (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_TRAINING_PATTERN_SET, &eq_pat, 1u);

    bool eq_ok = false;
    for (u32 attempt = 0; attempt < 6u; attempt++) {
        (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_TRAINING_LANE0_SET, lane_set, target_lanes);
        amdgpu_udelay(adev, 400u);
        u8 st[6] = { 0 };
        if (dc_dpcd_read(adev, r, conn->aux_idx, DPCD_LANE0_1_STATUS, st, 6u) != 0) {
            break;
        }
        bool lanes_eq = ((st[2] & 0x01u) != 0); /* INTERLANE_ALIGN_DONE */
        for (u8 l = 0; l < target_lanes; l++) {
            u8 nib = (st[l / 2u] >> ((l & 1u) * 4u)) & 0x0Fu;
            if ((nib & 0x07u) != 0x07u) lanes_eq = false; /* CR + EQ + SYM_LOCK */
        }
        if (lanes_eq) {
            eq_ok = true;
            break;
        }
        for (u8 l = 0; l < target_lanes; l++) {
            u8 adj = (st[4u + l / 2u] >> ((l & 1u) * 4u)) & 0x0Fu;
            u8 sw = adj & 0x03u;
            u8 pe = (adj >> 2) & 0x03u;
            lane_set[l] = (u8)((pe << 3) | sw);
        }
    }

    /* Exit training pattern -> normal video transmission (restore prior link settings on failure). */
    u8 stop = 0;
    if (!eq_ok) {
        (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_LINK_BW_SET, old_bw, 2u);
        (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_MAIN_LINK_CHANNEL_CODING_SET, &old_coding, 1u);
    }
    (void)dc_dpcd_write(adev, r, conn->aux_idx, DPCD_TRAINING_PATTERN_SET, &stop, 1u);
    if (!eq_ok) {
        return -EIO;
    }

    conn->trained_lanes = target_lanes;
    conn->trained_rate_mbps = target_rate_mbps;
    conn->link_type = uhbr ? DC_LINK_DP_2_1 : DC_LINK_DP_1_4;
    return 0;
}

int dc_link_train_hdmi_frl(
    struct amdgpu_device *adev,
    struct dc_state *dc,
    struct dc_connector *conn,
    u8 target_lanes,
    u32 target_rate_mbps
) {
    if (!adev || !dc || !conn || !conn->hdmi_frl_capable) {
        return -EINVAL;
    }
    if (target_lanes < 3u || target_lanes > 4u || target_rate_mbps > DC_HDMI_FRL_12G_MBPS) {
        return -ERANGE;
    }
    /* Issue DMCUB HDMI 2.1 FRL PHY & SCDC training command when DMCUB is live. */
    if (dc->dmub.fw_alive) {
        u32 cmd[16];
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x00000044u; /* DMUB HDMI FRL link train */
        cmd[1] = (u32)conn->dig_idx;
        cmd[2] = (u32)target_lanes;
        cmd[3] = target_rate_mbps;
        (void)dc_dmub_submit_cmd(adev, dc, cmd);
    }
    conn->trained_lanes = target_lanes;
    conn->trained_rate_mbps = target_rate_mbps;
    conn->link_type = DC_LINK_HDMI_21;
    return 0;
}

bool dc_link_poll_hotplug(struct amdgpu_device *adev, struct dc_state *dc) {
    if (!adev || !dc || !dc->regs) {
        return false;
    }
    const struct dc_reg_table *r = dc->regs;
    bool changed = false;
    for (u32 i = 0; i < dc->connector_count; i++) {
        struct dc_connector *c = &dc->connectors[i];
        u32 st = 0;
        if (!dc_reg_read(adev, 2u, r->hpd_int_status + (u32)c->hpd_idx * r->hpd_stride, &st)) {
            continue;
        }
        bool sense = (st & 0x02u) != 0;
        if (sense != c->connected) {
            c->connected = sense;
            changed = true;
            if (sense) {
                /* Re-read DPCD + EDID on newly hotplugged monitor. */
                c->mode_count = 0;
                u8 dpcd[8] = { 0 };
                if (dc_dpcd_read(adev, r, c->aux_idx, DPCD_REV, dpcd, 8u) == 0 && dpcd[0] >= 0x11u) {
                    c->max_rate_mbps = dpcd_byte_to_mbps(dpcd[1]);
                    c->max_lanes = dpcd[2] & 0x1Fu;
                    c->edid_blocks = read_edid_over_aux(adev, r, c->aux_idx, c->edid_raw);
                    if (c->edid_blocks > 0) parse_edid_into_connector(c);
                }
            } else {
                c->mode_count = 0;
                c->edid_blocks = 0;
            }
        }
    }
    if (changed) {
        dc->hotplug_pending = true;
    }
    return changed;
}
