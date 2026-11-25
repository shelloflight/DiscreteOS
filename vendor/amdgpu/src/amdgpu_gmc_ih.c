#include <amdgpu_hw.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/string.h>

/* MMHUB register offsets verified across mmhub_2_0_0 / 3_0_0 / 3_0_1 / 4_1_0. */
static void mmhub_regs(
    const struct amdgpu_device *adev,
    u8 *seg,
    u32 *fb_base_off,
    u32 *fb_top_off,
    u32 *inv_req_off,
    u32 *inv_ack_off
) {
    switch (adev->dcn_version) {
        case DC_DCN_4_0_1: /* mmhub_4_1_0 (BASE_IDX 0) */
            *seg = 0;
            *fb_base_off = 0x0554u;
            *fb_top_off  = 0x0555u;
            *inv_req_off = 0x048Cu;
            *inv_ack_off = 0x047Bu;
            break;
        case DC_DCN_3_1_5: /* mmhub_3_0_1 (BASE_IDX 1 on Ryzen 7000/9000 APU) */
            *seg = 1;
            *fb_base_off = 0x08ECu;
            *fb_top_off  = 0x08EDu;
            *inv_req_off = 0x0848u;
            *inv_ack_off = 0x0837u;
            break;
        case DC_DCN_3_2: /* mmhub_3_0_0 (BASE_IDX 0) */
            *seg = 0;
            *fb_base_off = 0x08ECu;
            *fb_top_off  = 0x08EDu;
            *inv_req_off = 0x0848u;
            *inv_ack_off = 0x0837u;
            break;
        default: /* mmhub_2_0_0 (BASE_IDX 0) */
            *seg = 0;
            *fb_base_off = 0x086Cu;
            *fb_top_off  = 0x086Du;
            *inv_req_off = 0x07C8u;
            *inv_ack_off = 0x07B7u;
            break;
    }
}

/* OSSSYS IH v5/v6/v7 register offsets (BASE_IDX 0; on OSSSYS 7.0.0 RPTR/WPTR precede BASE/BASE_HI). */
static void ih_regs(
    const struct amdgpu_device *adev,
    u32 *rb_cntl,
    u32 *rb_base,
    u32 *rb_base_hi,
    u32 *rb_rptr,
    u32 *rb_wptr,
    u32 *wptr_addr_hi,
    u32 *wptr_addr_lo,
    u32 *ih_cntl,
    u32 *ih_chicken
) {
    *rb_cntl      = 0x0080u;
    *wptr_addr_hi = 0x0085u;
    *wptr_addr_lo = 0x0086u;
    if (adev->dcn_version == DC_DCN_4_0_1) {
        /* OSSSYS 7.0.0 */
        *rb_rptr    = 0x0081u;
        *rb_wptr    = 0x0082u;
        *rb_base    = 0x0083u;
        *rb_base_hi = 0x0084u;
        *ih_cntl    = 0x00A8u;
        *ih_chicken = 0x018Au;
    } else {
        /* OSSSYS 5.0.0 / 6.0.0 */
        *rb_base    = 0x0081u;
        *rb_base_hi = 0x0082u;
        *rb_rptr    = 0x0083u;
        *rb_wptr    = 0x0084u;
        *ih_cntl    = 0x00C0u;
        *ih_chicken = 0x018Du;
    }
}

int amdgpu_gmc_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    memset(&adev->gmc, 0, sizeof(adev->gmc));

    u8 seg = 0;
    u32 fb_base_reg = 0, fb_top_reg = 0, inv_req = 0, inv_ack = 0;
    mmhub_regs(adev, &seg, &fb_base_reg, &fb_top_reg, &inv_req, &inv_ack);

    u64 base_off = 0, top_off = 0;
    if (amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MMHUB, 0, seg, fb_base_reg, &base_off)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MMHUB, 0, seg, fb_top_reg, &top_off)) {
        u32 lo = amdgpu_rreg32(adev, base_off) & 0x00FFFFFFu;
        u32 hi = amdgpu_rreg32(adev, top_off) & 0x00FFFFFFu;
        adev->gmc.fb_mc_base = (u64)lo << 24;
        adev->gmc.fb_mc_top = (((u64)hi + 1ULL) << 24) - 1ULL;
    }

    u64 vram_sz = adev->discovery.vram_size_bytes;
    if (vram_sz == 0) {
        vram_sz = adev->bar_sizes[0];
    }
    if (vram_sz == 0) {
        vram_sz = 256ULL << 20;
    }
    adev->gmc.vram_size = vram_sz;
    adev->gmc.visible_vram_size = (adev->bar_sizes[0] > 0 && adev->bar_sizes[0] < vram_sz)
        ? adev->bar_sizes[0]
        : vram_sz;

    if (adev->gmc.fb_mc_top <= adev->gmc.fb_mc_base) {
        adev->gmc.fb_mc_base = 0x8000000000ULL;
        adev->gmc.fb_mc_top = adev->gmc.fb_mc_base + vram_sz - 1ULL;
    }
    adev->gmc.agp_base = adev->gmc.fb_mc_top + 1ULL;
    adev->gmc.agp_top = adev->gmc.agp_base + (256ULL << 30) - 1ULL;
    adev->gmc.initialized = true;
    return 0;
}

bool amdgpu_gmc_mc_to_vram(const struct amdgpu_gmc_state *gmc, u64 mc_addr, u64 *out_vram) {
    if (!gmc || !gmc->initialized || !out_vram) {
        return false;
    }
    if (mc_addr < gmc->fb_mc_base || mc_addr > gmc->fb_mc_top) {
        return false;
    }
    u64 off = mc_addr - gmc->fb_mc_base;
    if (off >= gmc->vram_size) {
        return false;
    }
    *out_vram = off;
    return true;
}

bool amdgpu_gmc_vram_to_mc(const struct amdgpu_gmc_state *gmc, u64 vram_off, u64 *out_mc) {
    if (!gmc || !gmc->initialized || !out_mc || vram_off >= gmc->vram_size) {
        return false;
    }
    u64 mc = gmc->fb_mc_base + vram_off;
    if (mc > gmc->fb_mc_top) {
        return false;
    }
    *out_mc = mc;
    return true;
}

static bool vram_range_overlaps(const struct amdgpu_gmc_state *gmc, u64 start, u64 end) {
    if (gmc->gop_vram_size > 0) {
        u64 g_end = gmc->gop_vram_start + gmc->gop_vram_size;
        if (start < g_end && gmc->gop_vram_start < end) {
            return true;
        }
    }
    for (u32 i = 0; i < AMDGPU_MAX_VRAM_ALLOCS; i++) {
        if (!gmc->allocs[i].in_use) {
            continue;
        }
        u64 a_start = gmc->allocs[i].vram_offset;
        u64 a_end = a_start + gmc->allocs[i].size;
        if (start < a_end && a_start < end) {
            return true;
        }
    }
    return false;
}

int amdgpu_gmc_alloc_vram(struct amdgpu_gmc_state *gmc, u64 size, u64 align, u32 tag, u64 *out_vram_off) {
    if (!gmc || !gmc->initialized || !out_vram_off || size == 0) {
        return -EINVAL;
    }
    if (align < 4096u || (align & (align - 1u)) != 0) {
        align = 4096u;
    }
    u64 aligned_sz = (size + 4095ULL) & ~4095ULL;
    /* Reserve bottom 1 MiB (VBIOS/AtomBIOS) and top 2 MiB (IP Discovery + PSP TMR). */
    u64 floor = ((1ULL << 20) + align - 1ULL) & ~(align - 1ULL);
    u64 limit = gmc->visible_vram_size > (2ULL << 20) ? (gmc->visible_vram_size - (2ULL << 20)) : 0;
    u64 starts[2] = {
        (gmc->gop_vram_size > 0)
            ? ((gmc->gop_vram_start + gmc->gop_vram_size + align - 1ULL) & ~(align - 1ULL))
            : floor,
        floor,
    };

    for (u32 pass = 0; pass < 2u; pass++) {
        u64 cursor = starts[pass];
        if (cursor < floor) cursor = floor;
        while (cursor + aligned_sz <= limit) {
            if (!vram_range_overlaps(gmc, cursor, cursor + aligned_sz)) {
                for (u32 i = 0; i < AMDGPU_MAX_VRAM_ALLOCS; i++) {
                    if (!gmc->allocs[i].in_use) {
                        gmc->allocs[i].in_use = true;
                        gmc->allocs[i].vram_offset = cursor;
                        gmc->allocs[i].size = aligned_sz;
                        gmc->allocs[i].tag = tag;
                        *out_vram_off = cursor;
                        return 0;
                    }
                }
                return -ENOMEM;
            }
            cursor += align;
        }
    }
    return -ENOMEM;
}

void amdgpu_gmc_free_vram(struct amdgpu_gmc_state *gmc, u64 vram_off) {
    if (!gmc) {
        return;
    }
    for (u32 i = 0; i < AMDGPU_MAX_VRAM_ALLOCS; i++) {
        if (gmc->allocs[i].in_use && gmc->allocs[i].vram_offset == vram_off) {
            memset(&gmc->allocs[i], 0, sizeof(gmc->allocs[i]));
            return;
        }
    }
}

void amdgpu_gmc_tlb_flush(struct amdgpu_device *adev, u32 vmid) {
    if (!adev || !adev->gmc.initialized) {
        return;
    }
    u8 seg = 0;
    u32 fb_b = 0, fb_t = 0, inv_req = 0, inv_ack = 0;
    mmhub_regs(adev, &seg, &fb_b, &fb_t, &inv_req, &inv_ack);
    u64 req_off = 0, ack_off = 0;
    if (amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MMHUB, 0, seg, inv_req, &req_off)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_MMHUB, 0, seg, inv_ack, &ack_off)) {
        u32 mask = 1u << (vmid & 15u);
        amdgpu_wreg32(adev, req_off, mask);
        for (u32 i = 0; i < 64u; i++) {
            if ((amdgpu_rreg32(adev, ack_off) & mask) != 0) {
                break;
            }
            amdgpu_udelay(adev, 5u);
        }
    }
    adev->gmc.tlb_flushes++;
}

int amdgpu_vm_create(struct amdgpu_device *adev, u32 vm_id) {
    if (!adev || vm_id == 0) {
        return -EINVAL;
    }
    for (u32 i = 0; i < AMDGPU_MAX_VM_SPACES; i++) {
        if (adev->gmc.vms[i].active && adev->gmc.vms[i].vm_id == vm_id) {
            return -EEXIST;
        }
    }
    for (u32 i = 0; i < AMDGPU_MAX_VM_SPACES; i++) {
        if (!adev->gmc.vms[i].active) {
            memset(&adev->gmc.vms[i], 0, sizeof(adev->gmc.vms[i]));
            adev->gmc.vms[i].active = true;
            adev->gmc.vms[i].vm_id = vm_id;
            adev->gmc.vms[i].pasid = 0x100u + i;
            /* Allocate a 4 KiB root page-directory address in VRAM when available. */
            u64 pd_vram = 0;
            if (amdgpu_gmc_alloc_vram(&adev->gmc, 4096u, 4096u, 0x50440000u | vm_id, &pd_vram) == 0) {
                (void)amdgpu_gmc_vram_to_mc(&adev->gmc, pd_vram, &adev->gmc.vms[i].pd_root_addr);
            }
            return 0;
        }
    }
    return -ENOSPC;
}

int amdgpu_vm_destroy(struct amdgpu_device *adev, u32 vm_id) {
    if (!adev || vm_id == 0) {
        return -EINVAL;
    }
    for (u32 i = 0; i < AMDGPU_MAX_VM_SPACES; i++) {
        if (adev->gmc.vms[i].active && adev->gmc.vms[i].vm_id == vm_id) {
            u64 pd_vram = 0;
            if (adev->gmc.vms[i].pd_root_addr != 0
                && amdgpu_gmc_mc_to_vram(&adev->gmc, adev->gmc.vms[i].pd_root_addr, &pd_vram)) {
                amdgpu_gmc_free_vram(&adev->gmc, pd_vram);
            }
            amdgpu_gmc_tlb_flush(adev, (i + 1u) & 15u);
            memset(&adev->gmc.vms[i], 0, sizeof(adev->gmc.vms[i]));
            return 0;
        }
    }
    return -ENOENT;
}

int amdgpu_vm_map(
    struct amdgpu_device *adev,
    u32 vm_id,
    u32 gem_handle,
    u64 gpu_va,
    u64 size,
    u64 target_addr,
    bool is_system,
    u32 vm_flags
) {
    if (!adev || vm_id == 0 || size == 0 || !IS_ALIGNED(gpu_va, 4096ULL) || !IS_ALIGNED(size, 4096ULL)) {
        return -EINVAL;
    }
    if (gpu_va + size < gpu_va || gpu_va + size > 0x0000800000000000ULL) {
        return -ERANGE;
    }
    struct amdgpu_vm_space *vm = NULL;
    u32 vm_slot = 0;
    for (u32 i = 0; i < AMDGPU_MAX_VM_SPACES; i++) {
        if (adev->gmc.vms[i].active && adev->gmc.vms[i].vm_id == vm_id) {
            vm = &adev->gmc.vms[i];
            vm_slot = i;
            break;
        }
    }
    if (!vm) {
        return -ENOENT;
    }
    u64 end_va = gpu_va + size;
    for (u32 r = 0; r < AMDGPU_MAX_VM_RANGES; r++) {
        if (!vm->ranges[r].in_use) continue;
        u64 rs = vm->ranges[r].gpu_va;
        u64 re = rs + vm->ranges[r].size;
        if (gpu_va < re && rs < end_va) {
            return -EEXIST;
        }
    }
    for (u32 r = 0; r < AMDGPU_MAX_VM_RANGES; r++) {
        if (!vm->ranges[r].in_use) {
            u64 pte = AMDGPU_PTE_VALID | AMDGPU_PTE_MTYPE_NC;
            if (is_system) pte |= AMDGPU_PTE_SYSTEM | AMDGPU_PTE_SNOOPED;
            if (vm_flags & 1u) pte |= AMDGPU_PTE_READABLE;
            if (vm_flags & 2u) pte |= AMDGPU_PTE_WRITEABLE;
            if (vm_flags & 4u) pte |= AMDGPU_PTE_EXECUTABLE;
            vm->ranges[r].in_use = true;
            vm->ranges[r].gpu_va = gpu_va;
            vm->ranges[r].size = size;
            vm->ranges[r].phys_or_vram_addr = target_addr;
            vm->ranges[r].pte_flags = pte;
            vm->ranges[r].gem_handle = gem_handle;
            vm->tlb_seq++;
            amdgpu_gmc_tlb_flush(adev, (vm_slot + 1u) & 15u);
            return 0;
        }
    }
    return -ENOSPC;
}

int amdgpu_vm_unmap(struct amdgpu_device *adev, u32 vm_id, u64 gpu_va, u64 size) {
    if (!adev || vm_id == 0) {
        return -EINVAL;
    }
    for (u32 i = 0; i < AMDGPU_MAX_VM_SPACES; i++) {
        struct amdgpu_vm_space *vm = &adev->gmc.vms[i];
        if (!vm->active || vm->vm_id != vm_id) continue;
        for (u32 r = 0; r < AMDGPU_MAX_VM_RANGES; r++) {
            if (vm->ranges[r].in_use && vm->ranges[r].gpu_va == gpu_va
                && (size == 0 || vm->ranges[r].size == size)) {
                memset(&vm->ranges[r], 0, sizeof(vm->ranges[r]));
                vm->tlb_seq++;
                amdgpu_gmc_tlb_flush(adev, (i + 1u) & 15u);
                return 0;
            }
        }
        return -ENOENT;
    }
    return -ENOENT;
}

bool amdgpu_vm_translate(
    const struct amdgpu_device *adev,
    u32 vm_id,
    u64 gpu_va,
    u64 *out_addr,
    u64 *out_pte
) {
    if (!adev || vm_id == 0 || !out_addr) {
        return false;
    }
    for (u32 i = 0; i < AMDGPU_MAX_VM_SPACES; i++) {
        const struct amdgpu_vm_space *vm = &adev->gmc.vms[i];
        if (!vm->active || vm->vm_id != vm_id) continue;
        for (u32 r = 0; r < AMDGPU_MAX_VM_RANGES; r++) {
            if (!vm->ranges[r].in_use) continue;
            u64 rs = vm->ranges[r].gpu_va;
            u64 re = rs + vm->ranges[r].size;
            if (gpu_va >= rs && gpu_va < re) {
                *out_addr = vm->ranges[r].phys_or_vram_addr + (gpu_va - rs);
                if (out_pte) {
                    *out_pte = vm->ranges[r].pte_flags;
                }
                return true;
            }
        }
    }
    return false;
}

int amdgpu_ih_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    memset(&adev->ih, 0, sizeof(adev->ih));
    if (!adev->io.dma_alloc) {
        return -ENODEV;
    }
    /* 3 x 4 KiB IOMMU-pinned DMA pages: Page 0 = IH ring (4 KiB = 128 x 32-byte IVs), Page 1 = WPTR WB, Page 2 = dummy. */
    int rc = adev->io.dma_alloc(adev->io.ctx, 3u * 4096u, &adev->ih.ring_dma);
    if (rc != 0) {
        return rc;
    }
    adev->ih.ring_mask = 4096u - 1u;

    u32 rb_cntl = 0, rb_base = 0, rb_base_hi = 0, rb_rptr = 0, rb_wptr = 0, wptr_hi = 0, wptr_lo = 0, ih_cntl = 0, ih_chicken = 0;
    ih_regs(adev, &rb_cntl, &rb_base, &rb_base_hi, &rb_rptr, &rb_wptr, &wptr_hi, &wptr_lo, &ih_cntl, &ih_chicken);

    u64 off_cntl = 0, off_base = 0, off_base_hi = 0, off_rptr = 0, off_wptr = 0, off_whi = 0, off_wlo = 0, off_chicken = 0;
    if (amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_cntl, &off_cntl)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_base, &off_base)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_base_hi, &off_base_hi)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_rptr, &off_rptr)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_wptr, &off_wptr)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, wptr_hi, &off_whi)
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, wptr_lo, &off_wlo)) {
        u64 ring_bus = adev->ih.ring_dma.dma_addr;
        u64 wb_bus = ring_bus + 4096ULL;
        u64 dummy_bus = ring_bus + 8192ULL;

        /* Configure NBIF interrupt control for snooped system RAM IH ring (nbif_v6_3_1.c). */
        u64 nbif_ic = 0, nbif_ic2 = 0;
        if (amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_NBIO, 0, 2, 0x00F1u, &nbif_ic)
            && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_NBIO, 0, 2, 0x00F2u, &nbif_ic2)) {
            amdgpu_wreg32(adev, nbif_ic2, (u32)(dummy_bus >> 8));
            u32 ic = amdgpu_rreg32(adev, nbif_ic);
            ic &= ~((1u << 0) | (1u << 3)); /* clear DUMMY_RD_OVERRIDE & REQ_NONSNOOP_EN */
            amdgpu_wreg32(adev, nbif_ic, ic);
        }

        u32 cur_cntl = amdgpu_rreg32(adev, off_cntl);
        amdgpu_wreg32(adev, off_cntl, cur_cntl & ~((1u << 0) | (1u << 17)));

        /* Allow GPA/IOVA bus addressing when MC_SPACE = 2 (ih_v7_0.c). */
        if (amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, ih_chicken, &off_chicken)) {
            u32 ch = amdgpu_rreg32(adev, off_chicken);
            amdgpu_wreg32(adev, off_chicken, ch | (1u << 4));
        }

        amdgpu_wreg32(adev, off_base, (u32)((ring_bus >> 8) & 0xFFFFFFFFULL));
        amdgpu_wreg32(adev, off_base_hi, (u32)((ring_bus >> 40) & 0xFFULL));
        amdgpu_wreg32(adev, off_rptr, 0u);
        amdgpu_wreg32(adev, off_wptr, 0u);
        amdgpu_wreg32(adev, off_wlo, lower_32_bits(wb_bus));
        amdgpu_wreg32(adev, off_whi, upper_32_bits(wb_bus) & 0xFFFFu);
        /* RB_ENABLE | RB_SIZE(10) | WPTR_WB | WPTR_OVERFLOW | ENABLE_INTR | MC_SNOOP | RPTR_REARM | MC_SPACE=BUS(2) */
        amdgpu_wreg32(
            adev,
            off_cntl,
            (1u << 0) | (10u << 1) | (1u << 8) | (1u << 16) | (1u << 17) | (1u << 20) | (1u << 21) | (2u << 28)
        );
        adev->ih.enabled = true;
    }
    return 0;
}

void amdgpu_ih_fini(struct amdgpu_device *adev) {
    if (!adev) {
        return;
    }
    if (adev->ih.enabled) {
        u32 rb_cntl = 0, a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0;
        ih_regs(adev, &rb_cntl, &a, &b, &c, &d, &e, &f, &g, &h);
        u64 off_cntl = 0;
        if (amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_cntl, &off_cntl)) {
            amdgpu_wreg32(adev, off_cntl, 0u);
        }
        adev->ih.enabled = false;
    }
    if (adev->io.dma_free && adev->ih.ring_dma.cpu_addr) {
        adev->io.dma_free(adev->io.ctx, &adev->ih.ring_dma);
    }
}

u32 amdgpu_ih_drain(struct amdgpu_device *adev, struct amdgpu_ih_event *events, u32 max_events) {
    if (!adev || !adev->ih.enabled || !adev->ih.ring_dma.cpu_addr || !events || max_events == 0) {
        return 0;
    }
    dma_rmb();
    const volatile u32 *wb = (const volatile u32 *)((const u8 *)adev->ih.ring_dma.cpu_addr + 4096u);
    u32 wptr = wb[0] & adev->ih.ring_mask;

    u32 rb_rptr_reg = 0, a = 0, b = 0, c = 0, rb_wptr_reg = 0, e = 0, f = 0, g = 0, h = 0;
    ih_regs(adev, &a, &b, &c, &rb_rptr_reg, &rb_wptr_reg, &e, &f, &g, &h);
    u64 off_rptr = 0, off_wptr = 0;
    if (wptr == adev->ih.rptr
        && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_wptr_reg, &off_wptr)) {
        wptr = amdgpu_rreg32(adev, off_wptr) & adev->ih.ring_mask;
    }

    u32 count = 0;
    const volatile u32 *ring = (const volatile u32 *)adev->ih.ring_dma.cpu_addr;
    while (adev->ih.rptr != wptr && count < max_events) {
        u32 idx = (adev->ih.rptr & adev->ih.ring_mask) / 4u;
        u32 dw0 = ring[idx + 0u];
        u32 dw1 = ring[idx + 1u];
        u32 dw2 = ring[idx + 2u];
        u32 dw3 = ring[idx + 3u];
        u32 dw4 = ring[idx + 4u];

        struct amdgpu_ih_event *ev = &events[count++];
        ev->client_id = dw0 & 0xFFu;
        ev->src_id = (dw0 >> 8) & 0xFFu;
        ev->ring_id = (dw0 >> 16) & 0xFFu;
        ev->pasid = dw3 & 0xFFFFu;
        ev->timestamp = (u64)dw1 | ((u64)(dw2 & 0xFFFFu) << 32);
        ev->data = dw4;

        adev->ih.irq_count++;
        adev->ih.verified_irq = true;
        if (ev->src_id == AMDGPU_IH_SRCID_DC_CRTC_VBLANK) {
            adev->ih.vblank_irqs++;
        } else if (ev->src_id >= AMDGPU_IH_SRCID_DC_FLIP_BASE && ev->src_id <= AMDGPU_IH_SRCID_DC_FLIP_END) {
            adev->ih.flip_irqs++;
        } else if (ev->src_id == AMDGPU_IH_SRCID_DC_HPD) {
            adev->ih.hpd_irqs++;
        } else if (ev->src_id == AMDGPU_IH_SRCID_GFX_EOP || ev->src_id == AMDGPU_IH_SRCID_SDMA_TRAP) {
            adev->ih.fence_irqs++;
        }

        adev->ih.rptr = (adev->ih.rptr + 32u) & adev->ih.ring_mask;
    }

    if (count > 0 && amdgpu_discovery_reg_offset(&adev->discovery, AMDGPU_HWID_OSSSYS, 0, 0, rb_rptr_reg, &off_rptr)) {
        amdgpu_wreg32(adev, off_rptr, adev->ih.rptr);
    }
    return count;
}
