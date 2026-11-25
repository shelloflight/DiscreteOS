#ifndef _AMDGPU_GMC_IH_H
#define _AMDGPU_GMC_IH_H

#include <linux/types.h>
#include <linux/dma-mapping.h>

/* AMDGPU 4-level GPU Virtual Memory PTE flags (RDNA 2/3/4 GMC v10/v11/v12). */
#define AMDGPU_PTE_VALID                   (1ULL << 0)
#define AMDGPU_PTE_SYSTEM                  (1ULL << 1)
#define AMDGPU_PTE_SNOOPED                 (1ULL << 2)
#define AMDGPU_PTE_EXECUTABLE              (1ULL << 4)
#define AMDGPU_PTE_READABLE                (1ULL << 5)
#define AMDGPU_PTE_WRITEABLE               (1ULL << 6)
#define AMDGPU_PTE_MTYPE_NC                (0ULL << 59)
#define AMDGPU_PTE_MTYPE_RW                (1ULL << 59)
#define AMDGPU_PTE_MTYPE_CC                (2ULL << 59)
#define AMDGPU_PTE_MTYPE_UC                (3ULL << 59)

#define AMDGPU_MAX_VM_SPACES               8u
#define AMDGPU_MAX_VM_RANGES               32u
#define AMDGPU_MAX_VRAM_ALLOCS             32u

/* OSSSYS Interrupt Handler (IH) source IDs (DCN & GFX/SDMA). */
#define AMDGPU_IH_SRCID_DC_CRTC_VBLANK     0x01u
#define AMDGPU_IH_SRCID_DC_VLINE0          0x02u
#define AMDGPU_IH_SRCID_DC_HPD             0x2Au
#define AMDGPU_IH_SRCID_DC_FLIP_BASE       0x5Fu
#define AMDGPU_IH_SRCID_DC_FLIP_END        0x66u
#define AMDGPU_IH_SRCID_GFX_EOP            0xB5u
#define AMDGPU_IH_SRCID_SDMA_TRAP          0xE0u

/* Ring engine identifiers. */
#define AMDGPU_RING_GFX                    0u
#define AMDGPU_RING_COMPUTE                1u
#define AMDGPU_RING_SDMA                   2u
#define AMDGPU_RING_MES                    3u
#define AMDGPU_RING_COUNT                  4u

/* PM4 Type-3 packet opcodes (RDNA 2/3/4). */
#define PM4_TYPE3_HEADER(op, cnt)          ((3u << 30) | (((cnt) & 0x3FFFu) << 16) | (((op) & 0xFFu) << 8))
#define PM4_NOP                            0x10u
#define PM4_INDIRECT_BUFFER                0x3Fu
#define PM4_RELEASE_MEM                    0x49u
#define PM4_WAIT_REG_MEM                   0x3Cu
#define PM4_EVENT_WRITE                    0x46u

/* SDMA v5/v6/v7 packet opcodes. */
#define SDMA_OP_NOP                        0x00u
#define SDMA_OP_COPY                       0x01u
#define SDMA_OP_WRITE                      0x02u
#define SDMA_OP_FENCE                      0x05u
#define SDMA_OP_TRAP                       0x06u

/* MES v11/v12 API packet opcodes. */
#define MES_API_TYPE_SCH                   1u
#define MES_SCH_API_SET_HW_RSRC            0u
#define MES_SCH_API_ADD_QUEUE              2u
#define MES_SCH_API_REMOVE_QUEUE           3u

struct amdgpu_vm_range {
    bool in_use;
    u64 gpu_va;
    u64 size;
    u64 phys_or_vram_addr;
    u64 pte_flags;
    u32 gem_handle;
};

struct amdgpu_vm_space {
    bool active;
    u32 vm_id;
    u32 pasid;
    u64 pd_root_addr;
    u64 tlb_seq;
    struct amdgpu_vm_range ranges[AMDGPU_MAX_VM_RANGES];
};

struct amdgpu_vram_block {
    bool in_use;
    u64 vram_offset;
    u64 size;
    u32 tag;
};

struct amdgpu_gmc_state {
    bool initialized;
    u64 fb_mc_base;
    u64 fb_mc_top;
    u64 agp_base;
    u64 agp_top;
    u64 vram_size;
    u64 visible_vram_size;
    u64 gop_vram_start;
    u64 gop_vram_size;
    u64 tlb_flushes;
    struct amdgpu_vram_block allocs[AMDGPU_MAX_VRAM_ALLOCS];
    struct amdgpu_vm_space vms[AMDGPU_MAX_VM_SPACES];
};

struct amdgpu_ih_event {
    u32 src_id;
    u32 client_id;
    u32 ring_id;
    u32 pasid;
    u64 timestamp;
    u32 data;
};

struct amdgpu_ih_state {
    bool enabled;
    bool verified_irq;
    u32 rptr;
    u32 ring_mask;
    u64 irq_count;
    u64 vblank_irqs;
    u64 flip_irqs;
    u64 hpd_irqs;
    u64 fence_irqs;
    struct dosdrm_dma_buf ring_dma; /* Page 0: 4 KiB IH ring, Page 1: WPTR WB, Page 2: dummy */
};

struct amdgpu_ring {
    bool ready;
    u32 engine;
    u32 wptr;
    u32 rptr;
    u32 ring_dwords;
    u64 last_seq;
    u64 completed_seq;
    u64 submissions;
    struct dosdrm_dma_buf dma; /* Page 0: ring, Page 1: fence WB */
};

struct amdgpu_device;

/* GMC / MMHUB initialization, MC<->VRAM translation, VRAM allocator, and per-client GPU VM. */
int amdgpu_gmc_init(struct amdgpu_device *adev);
bool amdgpu_gmc_mc_to_vram(const struct amdgpu_gmc_state *gmc, u64 mc_addr, u64 *out_vram);
bool amdgpu_gmc_vram_to_mc(const struct amdgpu_gmc_state *gmc, u64 vram_off, u64 *out_mc);
int amdgpu_gmc_alloc_vram(struct amdgpu_gmc_state *gmc, u64 size, u64 align, u32 tag, u64 *out_vram_off);
void amdgpu_gmc_free_vram(struct amdgpu_gmc_state *gmc, u64 vram_off);

int amdgpu_vm_create(struct amdgpu_device *adev, u32 vm_id);
int amdgpu_vm_destroy(struct amdgpu_device *adev, u32 vm_id);
int amdgpu_vm_map(
    struct amdgpu_device *adev,
    u32 vm_id,
    u32 gem_handle,
    u64 gpu_va,
    u64 size,
    u64 target_addr,
    bool is_system,
    u32 vm_flags
);
int amdgpu_vm_unmap(struct amdgpu_device *adev, u32 vm_id, u64 gpu_va, u64 size);
bool amdgpu_vm_translate(
    const struct amdgpu_device *adev,
    u32 vm_id,
    u64 gpu_va,
    u64 *out_addr,
    u64 *out_pte
);
void amdgpu_gmc_tlb_flush(struct amdgpu_device *adev, u32 vmid);

/* OSSSYS IH ring controller. */
int amdgpu_ih_init(struct amdgpu_device *adev);
void amdgpu_ih_fini(struct amdgpu_device *adev);
u32 amdgpu_ih_drain(struct amdgpu_device *adev, struct amdgpu_ih_event *events, u32 max_events);

/* GFX / SDMA / MES rings & strict command-stream validation. */
int amdgpu_rings_init(struct amdgpu_device *adev);
void amdgpu_rings_fini(struct amdgpu_device *adev);
int amdgpu_ring_validate_cs(u32 engine, const u8 *cmd, size_t len);
int amdgpu_ring_submit(struct amdgpu_device *adev, u32 engine, u32 vm_id, const u8 *cmd, size_t len, u64 *out_seq);

#endif
