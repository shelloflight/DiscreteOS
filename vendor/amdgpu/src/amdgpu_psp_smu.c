#include <amdgpu_hw.h>
#include <linux/errno.h>
#include <linux/string.h>

/* Verified MP0 (PSP) & MP1 (SMU) C2PMSG dword offsets from upstream mp_13_0_0_offset.h & mp_14_0_2_offset.h. */
static bool psp_c2pmsg_off(const struct amdgpu_device *adev, u32 msg_idx, u64 *out_byte) {
    u32 dword_off = 0;
    u8 seg = 0;
    if (adev->family == AMDGPU_FAMILY_RDNA4) {
        /* MP0 v14.0.x (BASE_IDX 0) */
        if (msg_idx == 35u) dword_off = 0x0063u;
        else if (msg_idx == 36u) dword_off = 0x0064u;
        else if (msg_idx == 64u) dword_off = 0x0080u;
        else if (msg_idx == 69u) dword_off = 0x0085u;
        else if (msg_idx == 70u) dword_off = 0x0086u;
        else if (msg_idx == 71u) dword_off = 0x0087u;
        else if (msg_idx == 81u) dword_off = 0x0091u;
        else return false;
    } else {
        /* MP0 v11 / v13 (BASE_IDX 0) */
        if (msg_idx == 35u) dword_off = 0x0063u;
        else if (msg_idx == 36u) dword_off = 0x0064u;
        else if (msg_idx == 64u) dword_off = 0x0080u;
        else if (msg_idx == 69u) dword_off = 0x0085u;
        else if (msg_idx == 70u) dword_off = 0x0086u;
        else if (msg_idx == 71u) dword_off = 0x0087u;
        else if (msg_idx == 81u) dword_off = 0x0091u;
        else return false;
    }
    return amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MP0, 0, seg, dword_off, out_byte);
}

/* Official DCN 4.0.1 / SMU v14.0.2 DAL mailbox commands (`dalsmc.h` & `dcn401_smu14_driver_if.h`). */
#define DALSMC_MSG_TestMessage          0x01u
#define DALSMC_MSG_GetSmuVersion        0x02u
#define DALSMC_MSG_SetHardMinByFreq     0x09u
#define DALSMC_MSG_ReturnHardMinStatus  0x15u

#define DALSMC_PPCLK_UCLK               2u
#define DALSMC_PPCLK_DISPCLK            6u
#define DALSMC_PPCLK_DPPCLK             7u
#define DALSMC_PPCLK_DCFCLK             9u

static void smu_log_hex_pair(
    const struct amdgpu_device *adev,
    const char *prefix,
    u32 a,
    const char *mid,
    u32 b,
    const char *mid2,
    u32 c
) {
    if (!adev || !adev->io.log) return;
    static const char hx[] = "0123456789abcdef";
    char buf[160];
    size_t n = 0;
    const char *parts[3] = { prefix, mid, mid2 };
    u32 vals[3] = { a, b, c };
    for (u32 p = 0; p < 3u; p++) {
        const char *s = parts[p];
        if (!s) continue;
        while (*s && n + 1u < sizeof(buf)) buf[n++] = *s++;
        if (n + 2u < sizeof(buf)) { buf[n++] = '0'; buf[n++] = 'x'; }
        bool started = false;
        for (int sh = 28; sh >= 0; sh -= 4) {
            u32 nib = (vals[p] >> (u32)sh) & 0xFu;
            if (nib != 0 || started || sh == 0) {
                started = true;
                if (n + 1u < sizeof(buf)) buf[n++] = hx[nib];
            }
        }
    }
    buf[n] = '\0';
    adev->io.log(adev->io.ctx, buf);
}

static bool smu_rdna4_mailbox_off(
    const struct amdgpu_device *adev,
    bool main_mbox,
    u32 msg_idx,
    u64 *out_byte
) {
    /* MP1 v14.0.2/14.0.3 (`mp_14_0_2_offset.h`, BASE_IDX 1):
     * - DAL mailbox (`dcn401_clk_mgr_smu_msg.c`): C2PMSG_74 (0x8A), C2PMSG_51 (0x73), C2PMSG_52 (0x74)
     * - Main PMFW mailbox (`smu_v14_0_2_ppt.c`):  C2PMSG_66 (0x82), C2PMSG_82 (0x92), C2PMSG_90 (0x9A) */
    u32 dword_off = 0, abs_dw = 0;
    if (!main_mbox) {
        if (msg_idx == 66u) { dword_off = 0x008Au; abs_dw = 0x1628Au; }
        else if (msg_idx == 82u) { dword_off = 0x0073u; abs_dw = 0x16273u; }
        else if (msg_idx == 90u) { dword_off = 0x0074u; abs_dw = 0x16274u; }
        else return false;
    } else {
        if (msg_idx == 66u) { dword_off = 0x0082u; abs_dw = 0x16282u; }
        else if (msg_idx == 82u) { dword_off = 0x0092u; abs_dw = 0x16292u; }
        else if (msg_idx == 90u) { dword_off = 0x009Au; abs_dw = 0x1629Au; }
        else return false;
    }
    u64 disc_off = 0;
    if (amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MP1, 0, 1u, dword_off, &disc_off)) {
        *out_byte = disc_off;
        return true;
    }
    *out_byte = (u64)abs_dw * 4ULL;
    return true;
}

static bool smu_c2pmsg_off(const struct amdgpu_device *adev, u32 msg_idx, u64 *out_byte) {
    u32 dword_off = 0;
    u8 seg = 0;
    if (adev->family == AMDGPU_FAMILY_RDNA4) {
        return smu_rdna4_mailbox_off(adev, adev->smu.use_main_mailbox, msg_idx, out_byte);
    }
    /* Verified from mp_13_0_0_offset.h: C2PMSG_66=0x282, C2PMSG_82=0x292, C2PMSG_90=0x29a (BASE_IDX 0) */
    if (msg_idx == 66u) dword_off = 0x0282u;
    else if (msg_idx == 82u) dword_off = 0x0292u;
    else if (msg_idx == 90u) dword_off = 0x029Au;
    else return false;
    return amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MP1, 0, seg, dword_off, out_byte);
}

int amdgpu_psp_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    memset(&adev->psp, 0, sizeof(adev->psp));
    u64 c2p35 = 0;
    if (!psp_c2pmsg_off(adev, 35u, &c2p35)) {
        return -ENODEV;
    }

    /* Check if VBIOS/firmware already booted PSP Secure OS (SOS) & Trusted Memory Region (TMR). */
    u32 status = amdgpu_rreg32(adev, c2p35);
    adev->psp.sos_alive = ((status & 0x80000000u) != 0) || (status != 0 && status != 0xFFFFFFFFu);

    if (adev->ucodes[AMDGPU_UCODE_PSP_SOS].loaded) {
        adev->psp.fw_version = adev->ucodes[AMDGPU_UCODE_PSP_SOS].ucode_version;
    }

    /* Allocate IOMMU-pinned coherent PSP command/response buffer (4 KiB). */
    if (adev->io.dma_alloc) {
        if (adev->io.dma_alloc(adev->io.ctx, 4096u, &adev->psp.cmd_buf) == 0) {
            adev->psp.tmr_ready = adev->psp.sos_alive;
        }
    }

    adev->psp.initialized = true;
    return 0;
}

int amdgpu_psp_load_ip_fw(struct amdgpu_device *adev, u32 psp_fw_type, u64 dma_addr, u32 size_bytes) {
    if (!adev || !adev->psp.initialized || dma_addr == 0 || size_bytes == 0) {
        return -EINVAL;
    }
    if (!adev->psp.sos_alive || !adev->psp.cmd_buf.cpu_addr) {
        return -ENODEV;
    }
    /* Populate psp_gfx_cmd_resp in coherent IOMMU DMA memory. */
    u32 *cmd = (u32 *)adev->psp.cmd_buf.cpu_addr;
    memset(cmd, 0, 256u);
    cmd[0] = 0;                     /* buf_size / reserved */
    cmd[1] = PSP_CMD_LOAD_IP_FW;    /* cmd_id */
    cmd[2] = (u32)(dma_addr & 0xFFFFFFFFULL);
    cmd[3] = (u32)((dma_addr >> 32) & 0xFFFFFFFFULL);
    cmd[4] = size_bytes;
    cmd[5] = psp_fw_type;

    u64 c2p64 = 0, c2p69 = 0, c2p70 = 0;
    if (psp_c2pmsg_off(adev, 64u, &c2p64)
        && psp_c2pmsg_off(adev, 69u, &c2p69)
        && psp_c2pmsg_off(adev, 70u, &c2p70)) {
        amdgpu_wreg32(adev, c2p69, (u32)(adev->psp.cmd_buf.dma_addr & 0xFFFFFFFFULL));
        amdgpu_wreg32(adev, c2p70, (u32)((adev->psp.cmd_buf.dma_addr >> 32) & 0xFFFFFFFFULL));
        amdgpu_wreg32(adev, c2p64, 0x00010000u); /* ring submit */
        for (u32 i = 0; i < 200u; i++) {
            u32 r = amdgpu_rreg32(adev, c2p64);
            if ((r & 0x80000000u) != 0) {
                adev->psp.loaded_fw_mask |= (1u << (psp_fw_type & 31u));
                return 0;
            }
            amdgpu_udelay(adev, 50u);
        }
    }
    return -ETIMEDOUT;
}

void amdgpu_psp_fini(struct amdgpu_device *adev) {
    if (!adev) {
        return;
    }
    if (adev->io.dma_free && adev->psp.cmd_buf.cpu_addr) {
        adev->io.dma_free(adev->io.ctx, &adev->psp.cmd_buf);
    }
    adev->psp.initialized = false;
}

static int smu_send_regs(
    struct amdgpu_device *adev,
    u64 reg_msg,
    u64 reg_param,
    u64 reg_resp,
    u32 msg,
    u32 param,
    u32 *resp_out
) {
    /* Wait briefly for any in-flight SMU transaction to settle.
     * On cold UEFI boot, DAL_RESP_REG (C2PMSG_52) is 0x00000000 until the first DAL message is sent
     * (matching `dcn401_smu_send_msg_with_param` in dcn401_clk_mgr_smu_msg.c: never abort on 0!). */
    u32 cur = amdgpu_rreg32(adev, reg_resp);
    if (cur == 0xFFFFFFFFu) {
        return -ENODEV;
    }
    for (u32 i = 0; i < 40u && cur == 0; i++) {
        amdgpu_udelay(adev, 25u);
        cur = amdgpu_rreg32(adev, reg_resp);
    }

    amdgpu_wreg32(adev, reg_resp, 0u);
    amdgpu_wreg32(adev, reg_param, param);
    amdgpu_wreg32(adev, reg_msg, msg);

    for (u32 i = 0; i < 2000u; i++) {
        u32 r = amdgpu_rreg32(adev, reg_resp);
        if (r != 0) {
            if (r == PPSMC_Result_OK) {
                if (resp_out) {
                    *resp_out = amdgpu_rreg32(adev, reg_param);
                }
                return 0;
            }
            return -EIO;
        }
        amdgpu_udelay(adev, 25u);
    }
    return -ETIMEDOUT;
}

int amdgpu_smu_send_msg(struct amdgpu_device *adev, u32 msg, u32 param, u32 *resp_out) {
    if (!adev) {
        return -EINVAL;
    }
    u64 reg_msg = 0, reg_param = 0, reg_resp = 0;
    if (!smu_c2pmsg_off(adev, 66u, &reg_msg)
        || !smu_c2pmsg_off(adev, 82u, &reg_param)
        || !smu_c2pmsg_off(adev, 90u, &reg_resp)) {
        return -ENODEV;
    }
    return smu_send_regs(adev, reg_msg, reg_param, reg_resp, msg, param, resp_out);
}

int amdgpu_smu_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    memset(&adev->smu, 0, sizeof(adev->smu));
    u64 reg_msg = 0, reg_param = 0, reg_resp = 0;
    u32 ver = 0;

    if (adev->family == AMDGPU_FAMILY_RDNA4) {
        /* 1. Try dedicated Display/DAL SMU mailbox first (`C2PMSG_74/51/52`). */
        if (smu_rdna4_mailbox_off(adev, false, 66u, &reg_msg)
            && smu_rdna4_mailbox_off(adev, false, 82u, &reg_param)
            && smu_rdna4_mailbox_off(adev, false, 90u, &reg_resp)) {
            if (smu_send_regs(adev, reg_msg, reg_param, reg_resp, DALSMC_MSG_GetSmuVersion, 0u, &ver) == 0
                || smu_send_regs(adev, reg_msg, reg_param, reg_resp, DALSMC_MSG_TestMessage, 0x11u, &ver) == 0) {
                adev->smu.pmfw_alive = true;
                adev->smu.use_main_mailbox = false;
                if (ver != 0) adev->smu.smu_version = ver;
            }
        }
        /* 2. Fallback to main PMFW SMU mailbox (`C2PMSG_66/82/90`) if DAL mailbox was silent. */
        u32 r90 = 0;
        u64 m_msg = 0, m_par = 0, m_rsp = 0;
        if (smu_rdna4_mailbox_off(adev, true, 66u, &m_msg)
            && smu_rdna4_mailbox_off(adev, true, 82u, &m_par)
            && smu_rdna4_mailbox_off(adev, true, 90u, &m_rsp)) {
            r90 = amdgpu_rreg32(adev, m_rsp);
            if (!adev->smu.pmfw_alive) {
                if (smu_send_regs(adev, m_msg, m_par, m_rsp, PPSMC_MSG_GetSmuVersion, 0u, &ver) == 0
                    || smu_send_regs(adev, m_msg, m_par, m_rsp, PPSMC_MSG_TestMessage, 0x11u, &ver) == 0) {
                    adev->smu.pmfw_alive = true;
                    adev->smu.use_main_mailbox = true;
                    if (ver != 0) adev->smu.smu_version = ver;
                    reg_msg = m_msg;
                    reg_resp = m_rsp;
                }
                r90 = amdgpu_rreg32(adev, m_rsp);
            }
        }
        u32 r_after = reg_resp ? amdgpu_rreg32(adev, reg_resp) : 0u;
        smu_log_hex_pair(adev, "amdgpu: smu: msg=", (u32)reg_msg, " resp=", r_after, " ver=", adev->smu.smu_version);
        u64 mp1b1 = 0;
        (void)amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MP1, 0, 1u, 0u, &mp1b1);
        smu_log_hex_pair(adev, "amdgpu: smu: bar5=", (u32)adev->mmio_len, " mp1b1=", (u32)mp1b1, " r90=", r90);
    } else if (smu_c2pmsg_off(adev, 66u, &reg_msg)
        && smu_c2pmsg_off(adev, 82u, &reg_param)
        && smu_c2pmsg_off(adev, 90u, &reg_resp)) {
        if (smu_send_regs(adev, reg_msg, reg_param, reg_resp, PPSMC_MSG_GetSmuVersion, 0u, &ver) == 0
            || smu_send_regs(adev, reg_msg, reg_param, reg_resp, PPSMC_MSG_TestMessage, 0x11u, &ver) == 0) {
            adev->smu.pmfw_alive = true;
            if (ver != 0) adev->smu.smu_version = ver;
        }
    }
    if (adev->smu.smu_version == 0 && adev->ucodes[AMDGPU_UCODE_SMU].loaded) {
        adev->smu.smu_version = adev->ucodes[AMDGPU_UCODE_SMU].ucode_version;
    }
    adev->smu.initialized = true;
    return 0;
}

int amdgpu_smu_set_display_clocks(
    struct amdgpu_device *adev,
    u32 dispclk_mhz,
    u32 dppclk_mhz,
    u32 dcfclk_mhz,
    u32 dtbclk_mhz,
    u32 uclk_mhz
) {
    if (!adev || !adev->smu.initialized) {
        return -EINVAL;
    }
    adev->smu.min_dispclk_mhz = dispclk_mhz;
    adev->smu.min_dppclk_mhz = dppclk_mhz;
    adev->smu.min_dcfclk_mhz = dcfclk_mhz;
    adev->smu.min_dtbclk_mhz = dtbclk_mhz;
    adev->smu.min_uclk_mhz = uclk_mhz;

    if (!adev->smu.pmfw_alive) {
        return 0;
    }
    if (adev->family == AMDGPU_FAMILY_RDNA4) {
        struct { u32 ppclk; u32 mhz; } reqs[4] = {
            { DALSMC_PPCLK_DISPCLK, dispclk_mhz },
            { DALSMC_PPCLK_DPPCLK,  dppclk_mhz },
            { DALSMC_PPCLK_DCFCLK,  dcfclk_mhz },
            { DALSMC_PPCLK_UCLK,    uclk_mhz },
        };
        u32 got[4] = { 0, 0, 0, 0 };
        u32 set_msg = adev->smu.use_main_mailbox ? PPSMC_MSG_SetHardMinByFreq : DALSMC_MSG_SetHardMinByFreq;
        for (u32 i = 0; i < 4u; i++) {
            if (reqs[i].mhz == 0) continue;
            u32 param = ((reqs[i].ppclk & 0xFFu) << 16) | (reqs[i].mhz & 0xFFFFu);
            u32 actual = 0;
            if (amdgpu_smu_send_msg(adev, set_msg, param, &actual) == 0) {
                got[i] = actual;
                if (!adev->smu.use_main_mailbox) {
                    u32 mask = 1u << reqs[i].ppclk;
                    for (u32 poll = 0; poll < 60u; poll++) {
                        u32 st = 0;
                        if (amdgpu_smu_send_msg(adev, DALSMC_MSG_ReturnHardMinStatus, 0u, &st) == 0
                            && (st & mask) != 0) {
                            break;
                        }
                        amdgpu_udelay(adev, 500u);
                    }
                }
            }
        }
        smu_log_hex_pair(adev, "amdgpu: smu: clks disp=", got[0], " dpp=", got[1], " dcf=", got[2]);
        return 0;
    }
    /* Encode (clk_id << 16) | freq_mhz per upstream smu_v13_0 SetHardMinByFreq. */
    struct { u32 clk; u32 mhz; } reqs[4] = {
        { AMDGPU_SMU_CLK_DISPCLK, dispclk_mhz },
        { AMDGPU_SMU_CLK_DPPCLK,  dppclk_mhz },
        { AMDGPU_SMU_CLK_DCEFCLK, dcfclk_mhz },
        { AMDGPU_SMU_CLK_UCLK,    uclk_mhz },
    };
    for (u32 i = 0; i < 4u; i++) {
        if (reqs[i].mhz > 0) {
            u32 param = ((reqs[i].clk & 0xFFFFu) << 16) | (reqs[i].mhz & 0xFFFFu);
            (void)amdgpu_smu_send_msg(adev, PPSMC_MSG_SetHardMinByFreq, param, NULL);
        }
    }
    return 0;
}

int amdgpu_smu_suspend(struct amdgpu_device *adev) {
    if (!adev || !adev->smu.initialized) {
        return 0;
    }
    if (adev->smu.pmfw_alive && adev->family != AMDGPU_FAMILY_RDNA4) {
        (void)amdgpu_smu_send_msg(adev, PPSMC_MSG_PrepareMp1ForUnload, 0, NULL);
    }
    return 0;
}

int amdgpu_smu_resume(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    int rc = amdgpu_smu_init(adev);
    if (rc == 0 && adev->smu.min_dispclk_mhz > 0) {
        (void)amdgpu_smu_set_display_clocks(
            adev,
            adev->smu.min_dispclk_mhz,
            adev->smu.min_dppclk_mhz,
            adev->smu.min_dcfclk_mhz,
            adev->smu.min_dtbclk_mhz,
            adev->smu.min_uclk_mhz
        );
    }
    return rc;
}
