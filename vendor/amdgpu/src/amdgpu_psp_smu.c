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

static bool smu_c2pmsg_off(const struct amdgpu_device *adev, u32 msg_idx, u64 *out_byte) {
    u32 dword_off = 0;
    u8 seg = 0;
    if (adev->family == AMDGPU_FAMILY_RDNA4) {
        /* Verified from mp_14_0_2_offset.h: C2PMSG_66=0x82, C2PMSG_82=0x92, C2PMSG_90=0x9a (BASE_IDX 0) */
        if (msg_idx == 66u) dword_off = 0x0082u;
        else if (msg_idx == 82u) dword_off = 0x0092u;
        else if (msg_idx == 90u) dword_off = 0x009Au;
        else return false;
    } else {
        /* Verified from mp_13_0_0_offset.h: C2PMSG_66=0x282, C2PMSG_82=0x292, C2PMSG_90=0x29a (BASE_IDX 0) */
        if (msg_idx == 66u) dword_off = 0x0282u;
        else if (msg_idx == 82u) dword_off = 0x0292u;
        else if (msg_idx == 90u) dword_off = 0x029Au;
        else return false;
    }
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

    /* Wait for any prior SMU mailbox transaction to settle. */
    u32 cur = 0;
    for (u32 i = 0; i < 200u; i++) {
        cur = amdgpu_rreg32(adev, reg_resp);
        if (cur != 0) {
            break;
        }
        amdgpu_udelay(adev, 25u);
    }
    if (cur == 0 || cur == 0xFFFFFFFFu) {
        return -ETIMEDOUT;
    }

    amdgpu_wreg32(adev, reg_resp, 0u);
    amdgpu_wreg32(adev, reg_param, param);
    amdgpu_wreg32(adev, reg_msg, msg);

    for (u32 i = 0; i < 400u; i++) {
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

int amdgpu_smu_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    memset(&adev->smu, 0, sizeof(adev->smu));
    u32 test_resp = 0;
    if (amdgpu_smu_send_msg(adev, PPSMC_MSG_TestMessage, 0x11u, &test_resp) == 0) {
        adev->smu.pmfw_alive = true;
        u32 ver = 0;
        if (amdgpu_smu_send_msg(adev, PPSMC_MSG_GetSmuVersion, 0, &ver) == 0 && ver != 0) {
            adev->smu.smu_version = ver;
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
    /* Encode (clk_id << 16) | freq_mhz per upstream smu_v13_0 / smu_v14_0 SetHardMinByFreq. */
    struct { u32 clk; u32 mhz; } reqs[5] = {
        { AMDGPU_SMU_CLK_DISPCLK, dispclk_mhz },
        { AMDGPU_SMU_CLK_DPPCLK,  dppclk_mhz },
        { AMDGPU_SMU_CLK_DCEFCLK, dcfclk_mhz },
        { AMDGPU_SMU_CLK_DTBCLK,  dtbclk_mhz },
        { AMDGPU_SMU_CLK_UCLK,    uclk_mhz },
    };
    for (u32 i = 0; i < 5u; i++) {
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
    if (adev->smu.pmfw_alive) {
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
