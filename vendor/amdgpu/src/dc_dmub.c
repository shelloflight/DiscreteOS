#include <dc.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/string.h>

/* DMCUB GPINT commands (upstream dmub_cmd.h). */
#define DMUB_GPINT__GET_FW_VERSION         1u
#define DMUB_GPINT__GET_MAC_VERSION        2u
#define DMUB_CNTL_ENABLE_BIT               (1u << 0)
#define DMUB_CNTL_SOFT_RESET_BIT           (1u << 1)
#define DMUB_SCRATCH0_FW_BOOT_COMPLETE     (1u << 0)

static bool dmub_gpint_exec(struct amdgpu_device *adev, const struct dc_reg_table *r, u32 cmd, u32 *out_val) {
    if (!dc_reg_write(adev, 2u, r->dmcub_gpint_datain1, (cmd & 0xFFFFu) << 16)) {
        return false;
    }
    for (u32 i = 0; i < 200u; i++) {
        u32 cur = 0;
        if (!dc_reg_read(adev, 2u, r->dmcub_gpint_datain1, &cur)) {
            return false;
        }
        if (cur == 0) {
            u32 res = 0;
            if (dc_reg_read(adev, 2u, r->dmcub_gpint_dataout, &res)) {
                if (out_val) *out_val = res;
                return true;
            }
            return false;
        }
        amdgpu_udelay(adev, 25u);
    }
    return false;
}

int dc_dmub_init(struct amdgpu_device *adev, struct dc_state *dc) {
    if (!adev || !dc || !dc->regs) {
        return -EINVAL;
    }
    memset(&dc->dmub, 0, sizeof(dc->dmub));
    const struct dc_reg_table *r = dc->regs;

    u32 cntl = 0, scratch0 = 0;
    (void)dc_reg_read(adev, 2u, r->dmcub_cntl, &cntl);
    (void)dc_reg_read(adev, 2u, r->dmcub_scratch0, &scratch0);

    bool already_running = ((cntl & DMUB_CNTL_ENABLE_BIT) != 0)
        && ((cntl & DMUB_CNTL_SOFT_RESET_BIT) == 0)
        && ((scratch0 & DMUB_SCRATCH0_FW_BOOT_COMPLETE) != 0);

    /* Allocate 8 KiB coherent IOMMU DMA ring for Inbox1 (4 KiB) + Outbox1 (4 KiB). */
    if (adev->io.dma_alloc) {
        (void)adev->io.dma_alloc(adev->io.ctx, 8192u, &dc->dmub.ring_dma);
    }

    if (already_running) {
        dc->dmub.fw_alive = true;
        u32 ver = 0;
        if (dmub_gpint_exec(adev, r, DMUB_GPINT__GET_FW_VERSION, &ver) && ver != 0) {
            dc->dmub.fw_version = ver;
        }
        u32 wptr = 0;
        if (dc_reg_read(adev, 2u, r->dmcub_inbox1_wptr, &wptr)) {
            dc->dmub.inbox1_wptr = wptr & 0x0FFFu;
        }
    } else if (adev->ucodes[AMDGPU_UCODE_DMCUB].loaded && dc->dmub.ring_dma.cpu_addr) {
        /* Cold boot / post-S3 DMCUB load: authenticate via PSP when available, else configure inbox ring. */
        const struct amdgpu_ucode_info *uc = &adev->ucodes[AMDGPU_UCODE_DMCUB];
        if (adev->psp.sos_alive && uc->payload_size > 0 && uc->payload_size <= 512u * 1024u) {
            struct dosdrm_dma_buf fw_dma;
            memset(&fw_dma, 0, sizeof(fw_dma));
            if (adev->io.dma_alloc && adev->io.dma_alloc(adev->io.ctx, uc->payload_size, &fw_dma) == 0) {
                memcpy(fw_dma.cpu_addr, uc->raw_data + uc->payload_offset, uc->payload_size);
                dma_wmb();
                (void)amdgpu_psp_load_ip_fw(adev, PSP_GFX_FW_TYPE_DMUB, fw_dma.dma_addr, uc->payload_size);
                if (adev->io.dma_free) {
                    adev->io.dma_free(adev->io.ctx, &fw_dma);
                }
            }
        }
        (void)dc_reg_write(adev, 2u, r->dmcub_inbox1_base, (u32)(dc->dmub.ring_dma.dma_addr & 0xFFFFFFFFULL));
        (void)dc_reg_write(adev, 2u, r->dmcub_inbox1_size, 4096u);
        (void)dc_reg_write(adev, 2u, r->dmcub_inbox1_rptr, 0u);
        (void)dc_reg_write(adev, 2u, r->dmcub_inbox1_wptr, 0u);
        (void)dc_reg_write(adev, 2u, r->dmcub_outbox1_base, (u32)((dc->dmub.ring_dma.dma_addr + 4096ULL) & 0xFFFFFFFFULL));
        (void)dc_reg_write(adev, 2u, r->dmcub_outbox1_size, 4096u);
        (void)dc_reg_write(adev, 2u, r->dmcub_outbox1_rptr, 0u);
        (void)dc_reg_write(adev, 2u, r->dmcub_outbox1_wptr, 0u);
        (void)dc_reg_write(adev, 2u, r->dmcub_cntl, DMUB_CNTL_ENABLE_BIT);
        dc->dmub.fw_version = uc->ucode_version;
        /* Poll scratch0 briefly for boot completion. */
        for (u32 i = 0; i < 40u; i++) {
            (void)dc_reg_read(adev, 2u, r->dmcub_scratch0, &scratch0);
            if ((scratch0 & DMUB_SCRATCH0_FW_BOOT_COMPLETE) != 0) {
                dc->dmub.fw_alive = true;
                break;
            }
            amdgpu_udelay(adev, 100u);
        }
    }

    if (dc->dmub.fw_version == 0 && adev->ucodes[AMDGPU_UCODE_DMCUB].loaded) {
        dc->dmub.fw_version = adev->ucodes[AMDGPU_UCODE_DMCUB].ucode_version;
    }
    dc->dmub.initialized = true;
    return 0;
}

void dc_dmub_fini(struct amdgpu_device *adev, struct dc_state *dc) {
    if (!adev || !dc) {
        return;
    }
    if (adev->io.dma_free && dc->dmub.ring_dma.cpu_addr) {
        adev->io.dma_free(adev->io.ctx, &dc->dmub.ring_dma);
    }
    dc->dmub.initialized = false;
    dc->dmub.fw_alive = false;
}

int dc_dmub_submit_cmd(struct amdgpu_device *adev, struct dc_state *dc, const u32 cmd_dwords[16]) {
    if (!adev || !dc || !dc->regs || !cmd_dwords || !dc->dmub.initialized) {
        return -EINVAL;
    }
    if (!dc->dmub.fw_alive || !dc->dmub.ring_dma.cpu_addr) {
        return -ENODEV;
    }
    /* Each DMUB command packet is 64 bytes (16 dwords) in a 4 KiB circular ring. */
    u32 wptr = dc->dmub.inbox1_wptr & 0x0FC0u;
    volatile u32 *slot = (volatile u32 *)((u8 *)dc->dmub.ring_dma.cpu_addr + wptr);
    for (u32 i = 0; i < 16u; i++) {
        slot[i] = cmd_dwords[i];
    }
    dma_wmb();
    u32 next_wptr = (wptr + 64u) & 0x0FFFu;
    dc->dmub.inbox1_wptr = next_wptr;
    dc->dmub.cmds_submitted++;
    if (!dc_reg_write(adev, 2u, dc->regs->dmcub_inbox1_wptr, next_wptr)) {
        return -EIO;
    }
    /* Wait briefly for DMCUB rptr to advance. */
    for (u32 i = 0; i < 100u; i++) {
        u32 rptr = 0;
        if (dc_reg_read(adev, 2u, dc->regs->dmcub_inbox1_rptr, &rptr) && (rptr & 0x0FFFu) == next_wptr) {
            return 0;
        }
        amdgpu_udelay(adev, 20u);
    }
    return 0;
}
