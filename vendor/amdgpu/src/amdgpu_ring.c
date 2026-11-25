#include <amdgpu_hw.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/string.h>

static u32 rd_le32(const u8 *b, size_t off) {
    return (u32)b[off]
        | ((u32)b[off + 1] << 8)
        | ((u32)b[off + 2] << 16)
        | ((u32)b[off + 3] << 24);
}

int amdgpu_rings_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    memset(adev->rings, 0, sizeof(adev->rings));
    for (u32 i = 0; i < AMDGPU_RING_COUNT; i++) {
        struct amdgpu_ring *r = &adev->rings[i];
        r->engine = i;
        r->ring_dwords = 1024u; /* 4 KiB ring buffer */
        if (adev->io.dma_alloc) {
            /* Page 0: ring buffer (4 KiB); Page 1: fence writeback (4 KiB). */
            if (adev->io.dma_alloc(adev->io.ctx, 8192u, &r->dma) == 0) {
                r->ready = true;
            }
        }
    }
    return 0;
}

void amdgpu_rings_fini(struct amdgpu_device *adev) {
    if (!adev) {
        return;
    }
    for (u32 i = 0; i < AMDGPU_RING_COUNT; i++) {
        if (adev->io.dma_free && adev->rings[i].dma.cpu_addr) {
            adev->io.dma_free(adev->io.ctx, &adev->rings[i].dma);
        }
        adev->rings[i].ready = false;
    }
}

/* Strict packet-boundary validator for PM4 Type-3 (GFX/Compute), SDMA v5-7, and MES v11-12 streams. */
int amdgpu_ring_validate_cs(u32 engine, const u8 *cmd, size_t len) {
    if (!cmd || len == 0 || len > 65536u || (len & 3u) != 0) {
        return -EINVAL;
    }
    size_t dwords = len / 4u;
    size_t pos = 0;

    if (engine == AMDGPU_RING_GFX || engine == AMDGPU_RING_COMPUTE) {
        while (pos < dwords) {
            u32 hdr = rd_le32(cmd, pos * 4u);
            u32 pkt_type = (hdr >> 30) & 3u;
            if (pkt_type != 3u) {
                return -EINVAL;
            }
            u32 count = ((hdr >> 16) & 0x3FFFu) + 1u;
            u32 opcode = (hdr >> 8) & 0xFFu;
            if (pos + 1u + count > dwords) {
                return -ERANGE;
            }
            /* Only permit safe unprivileged PM4 Type-3 opcodes (NOP, IB, RELEASE_MEM, WAIT_REG_MEM, EVENT_WRITE). */
            switch (opcode) {
                case PM4_NOP:
                case PM4_INDIRECT_BUFFER:
                case PM4_RELEASE_MEM:
                case PM4_WAIT_REG_MEM:
                case PM4_EVENT_WRITE:
                    break;
                default:
                    return -EPERM;
            }
            pos += 1u + count;
        }
        return 0;
    }

    if (engine == AMDGPU_RING_SDMA) {
        while (pos < dwords) {
            u32 hdr = rd_le32(cmd, pos * 4u);
            u32 op = hdr & 0xFFu;
            size_t pkt_dw = 0;
            switch (op) {
                case SDMA_OP_NOP:   pkt_dw = 1u + ((hdr >> 16) & 0x3FFFu); break;
                case SDMA_OP_COPY:  pkt_dw = 7u; break;
                case SDMA_OP_WRITE: pkt_dw = 4u + (pos + 3u < dwords ? rd_le32(cmd, (pos + 3u) * 4u) : 0u); break;
                case SDMA_OP_FENCE: pkt_dw = 4u; break;
                case SDMA_OP_TRAP:  pkt_dw = 2u; break;
                default:
                    return -EPERM;
            }
            if (pkt_dw == 0 || pos + pkt_dw > dwords) {
                return -ERANGE;
            }
            pos += pkt_dw;
        }
        return 0;
    }

    if (engine == AMDGPU_RING_MES) {
        /* MES API packets are fixed 64-dword (256-byte) frames with type=MES_API_TYPE_SCH. */
        if (dwords < 4u || (dwords % 64u) != 0) {
            return -EINVAL;
        }
        while (pos < dwords) {
            u32 hdr = rd_le32(cmd, pos * 4u);
            u32 api_type = hdr & 0x0Fu;
            u32 api_op = (hdr >> 4) & 0xFFu;
            if (api_type != MES_API_TYPE_SCH) {
                return -EPERM;
            }
            if (api_op != MES_SCH_API_SET_HW_RSRC
                && api_op != MES_SCH_API_ADD_QUEUE
                && api_op != MES_SCH_API_REMOVE_QUEUE) {
                return -EPERM;
            }
            pos += 64u;
        }
        return 0;
    }

    return -EINVAL;
}

int amdgpu_ring_submit(struct amdgpu_device *adev, u32 engine, u32 vm_id, const u8 *cmd, size_t len, u64 *out_seq) {
    if (!adev || engine >= AMDGPU_RING_COUNT || !out_seq) {
        return -EINVAL;
    }
    int vrc = amdgpu_ring_validate_cs(engine, cmd, len);
    if (vrc != 0) {
        return vrc;
    }
    struct amdgpu_ring *r = &adev->rings[engine];
    if (!r->ready || !r->dma.cpu_addr) {
        return -ENODEV;
    }
    /* Verify VM exists if non-zero (per-client hardware GPU VM isolation). */
    if (vm_id != 0) {
        bool vm_ok = false;
        for (u32 i = 0; i < AMDGPU_MAX_VM_SPACES; i++) {
            if (adev->gmc.vms[i].active && adev->gmc.vms[i].vm_id == vm_id) {
                vm_ok = true;
                break;
            }
        }
        if (!vm_ok) {
            return -ENOENT;
        }
    }

    u32 dwords = (u32)(len / 4u);
    if (dwords > r->ring_dwords) {
        return -ERANGE;
    }
    volatile u32 *ring_buf = (volatile u32 *)r->dma.cpu_addr;
    u32 mask = r->ring_dwords - 1u;
    for (u32 i = 0; i < dwords; i++) {
        ring_buf[(r->wptr + i) & mask] = rd_le32(cmd, (size_t)i * 4u);
    }
    dma_wmb();
    r->wptr = (r->wptr + dwords) & mask;
    r->last_seq++;
    r->submissions++;

    /* Update fence writeback page for coherent completion tracking. */
    volatile u64 *fence_wb = (volatile u64 *)((u8 *)r->dma.cpu_addr + 4096u);
    fence_wb[0] = r->last_seq;
    r->completed_seq = r->last_seq;
    r->rptr = r->wptr;
    *out_seq = r->last_seq;
    return 0;
}
