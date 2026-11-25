#ifndef _AMDGPU_HW_H
#define _AMDGPU_HW_H

#include <linux/types.h>
#include <amdgpu_ucode.h>
#include <amdgpu_discovery.h>
#include <amdgpu_atom.h>
#include <amdgpu_psp_smu.h>
#include <amdgpu_gmc_ih.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AMDGPU_PCI_VENDOR_AMD              0x1002u

enum amdgpu_family {
    AMDGPU_FAMILY_UNKNOWN = 0,
    AMDGPU_FAMILY_RDNA2   = 2, /* Navi 21/22/23/24 (DCN 3.0) */
    AMDGPU_FAMILY_RDNA2_APU = 3, /* Ryzen 7000/9000 Raphael/Granite Ridge iGPU (DCN 3.1.5) */
    AMDGPU_FAMILY_RDNA3   = 4, /* Navi 31/32/33 (DCN 3.2 / 3.2.1) */
    AMDGPU_FAMILY_RDNA4   = 5, /* Navi 48 RX 9070 / Navi 44 (DCN 4.0.1) */
};

enum dc_dcn_version {
    DC_DCN_NONE = 0,
    DC_DCN_3_0  = 300,
    DC_DCN_3_1_5 = 315,
    DC_DCN_3_2  = 320,
    DC_DCN_4_0_1 = 401,
};

struct amdgpu_asic_id {
    u16 device_id;
    enum amdgpu_family family;
    enum dc_dcn_version dcn_hint;
    u8 gfx_major;
    u8 sdma_major;
    bool is_apu;
    const char *marketing_name;
};

/* Abstract I/O hooks: implemented over Ring-3 BAR5/BAR0/DMA on hardware, or over a simulator in tests. */
struct amdgpu_io_ops {
    void *ctx;
    u32 (*mmio_r32)(void *ctx, u64 byte_off);
    void (*mmio_w32)(void *ctx, u64 byte_off, u32 val);
    int (*vram_read)(void *ctx, u64 vram_off, void *dst, size_t len);
    int (*vram_write)(void *ctx, u64 vram_off, const void *src, size_t len);
    int (*dma_alloc)(void *ctx, u64 size, struct dosdrm_dma_buf *out);
    void (*dma_free)(void *ctx, struct dosdrm_dma_buf *buf);
    int (*load_fw)(void *ctx, const char *name, const u8 **out_data, size_t *out_size, const void **out_handle);
    void (*release_fw)(void *ctx, const void *handle);
    u64 (*clock_ns)(void *ctx);
    void (*udelay)(void *ctx, u32 us);
    void (*log)(void *ctx, const char *msg);
};

struct dc_state;

struct amdgpu_device {
    u32 dev_handle;
    u16 vendor_id;
    u16 device_id;
    u8 revision_id;
    enum amdgpu_family family;
    enum dc_dcn_version dcn_version;
    bool is_apu;
    const char *asic_name;
    u64 bar_sizes[6];

    /* Mapped Ring-3 MMIO (BAR5) and WC scanout VRAM window (BAR0) when running on real hardware. */
    u32 mmio_vmo;
    u64 mmio_addr;
    u64 mmio_len;
    u32 vram_vmo;
    u64 vram_addr;
    u64 vram_len;
    u64 vram_win_base;

    struct amdgpu_io_ops io;
    struct amdgpu_discovery_info discovery;
    struct amdgpu_atom_info atom;
    struct amdgpu_ucode_info ucodes[AMDGPU_UCODE_MAX];
    u32 ucode_loaded_count;
    struct amdgpu_psp_state psp;
    struct amdgpu_smu_state smu;
    struct amdgpu_gmc_state gmc;
    struct amdgpu_ih_state ih;
    struct amdgpu_ring rings[AMDGPU_RING_COUNT];
    struct dc_state *dc;

    bool suspended;
    bool native_kms_active;
};

/* Identify AMD PCI device ID (`1002:device_id`). */
struct amdgpu_asic_id amdgpu_identify_asic(u16 device_id);

/* Inline MMIO helpers through `adev->io`. */
static inline u32 amdgpu_rreg32(const struct amdgpu_device *adev, u64 byte_off) {
    if (!adev || !adev->io.mmio_r32) {
        return 0;
    }
    return adev->io.mmio_r32(adev->io.ctx, byte_off);
}

static inline void amdgpu_wreg32(struct amdgpu_device *adev, u64 byte_off, u32 val) {
    if (adev && adev->io.mmio_w32) {
        adev->io.mmio_w32(adev->io.ctx, byte_off, val);
    }
}

static inline u64 amdgpu_now_ns(const struct amdgpu_device *adev) {
    return (adev && adev->io.clock_ns) ? adev->io.clock_ns(adev->io.ctx) : 0ULL;
}

static inline void amdgpu_udelay(const struct amdgpu_device *adev, u32 us) {
    if (adev && adev->io.udelay) {
        adev->io.udelay(adev->io.ctx, us);
    }
}

/* Full device lifecycle (works on real hardware over dosdrm_c or custom `io_ops` in tests). */
int amdgpu_device_init_with_ops(
    struct amdgpu_device *adev,
    u16 vendor_id,
    u16 device_id,
    u8 revision_id,
    const u64 bar_sizes[6],
    const struct amdgpu_io_ops *ops
);
int amdgpu_device_init_hardware(struct amdgpu_device *adev, u32 dev_handle);
int amdgpu_device_suspend(struct amdgpu_device *adev);
int amdgpu_device_resume(struct amdgpu_device *adev);
void amdgpu_device_fini(struct amdgpu_device *adev);

/* Hardware-mapped WC VRAM read/write helper (maps exact window on demand). */
int amdgpu_hw_ensure_vram_window(struct amdgpu_device *adev, u64 vram_base, u64 len);

#ifdef __cplusplus
}
#endif

#endif
