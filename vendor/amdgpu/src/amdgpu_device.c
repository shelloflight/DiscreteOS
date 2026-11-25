#include <dc.h>
#include <dosdrm/shim.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/string.h>

/*
 * Top-level AMD RDNA / AMDGPU device orchestrator (`amdgpu_device.c`):
 * - PCI ASIC classification covering RDNA 4 (Navi 48 RX 9070 / Navi 44), Ryzen 7000/9000 APU
 *   (Raphael / Granite Ridge DCN 3.1.5), RDNA 3 (Navi 31/32/33), and RDNA 2 (Navi 21/22/23/24)
 * - Ring-3 `dosdrm_c` hardware I/O callbacks (BAR5 MMIO up to 16 MiB, dynamic WC BAR0 VRAM window,
 *   IOMMU coherent DMA, read-only `sys:/firmware/amdgpu/` loading)
 * - Full initialization, S3 suspend/resume, and teardown pipeline
 */

struct amdgpu_asic_id amdgpu_identify_asic(u16 device_id) {
    struct amdgpu_asic_id id;
    memset(&id, 0, sizeof(id));
    id.device_id = device_id;

    switch (device_id) {
        /* RDNA 4 — Navi 48 (Radeon RX 9070 / RX 9070 XT, GFX12.0.1, DCN 4.0.1, SDMA 7.0.1) */
        case 0x7550u:
            id.family = AMDGPU_FAMILY_RDNA4;
            id.dcn_hint = DC_DCN_4_0_1;
            id.gfx_major = 12; id.sdma_major = 7; id.is_apu = false;
            id.marketing_name = "AMD Radeon RX 9070 (Navi 48)";
            return id;
        case 0x7551u:
            id.family = AMDGPU_FAMILY_RDNA4;
            id.dcn_hint = DC_DCN_4_0_1;
            id.gfx_major = 12; id.sdma_major = 7; id.is_apu = false;
            id.marketing_name = "AMD Radeon Navi 48";
            return id;
        /* RDNA 4 — Navi 44 (Radeon RX 9060 series, GFX12.0.0, DCN 4.0.1) */
        case 0x7590u:
        case 0x7591u:
            id.family = AMDGPU_FAMILY_RDNA4;
            id.dcn_hint = DC_DCN_4_0_1;
            id.gfx_major = 12; id.sdma_major = 7; id.is_apu = false;
            id.marketing_name = "AMD Radeon RX 9060 (Navi 44)";
            return id;
        /* Ryzen 7000/9000 iGPU — Raphael / Granite Ridge (GFX10.3.6, DCN 3.1.5, SDMA 5.2.6) */
        case 0x164Eu:
        case 0x13C0u:
            id.family = AMDGPU_FAMILY_RDNA2_APU;
            id.dcn_hint = DC_DCN_3_1_5;
            id.gfx_major = 10; id.sdma_major = 5; id.is_apu = true;
            id.marketing_name = "AMD Ryzen Graphics (DCN 3.1.5)";
            return id;
        /* RDNA 3 — Navi 31/32/33 (RX 7900 / 7800 / 7700 / 7600, GFX11, DCN 3.2) */
        case 0x744Cu:
        case 0x747Eu:
        case 0x7480u:
        case 0x7483u:
            id.family = AMDGPU_FAMILY_RDNA3;
            id.dcn_hint = DC_DCN_3_2;
            id.gfx_major = 11; id.sdma_major = 6; id.is_apu = false;
            id.marketing_name = "AMD Radeon RX 7000 (RDNA 3)";
            return id;
        /* RDNA 2 — Navi 21/22/23/24 (RX 6000, GFX10.3, DCN 3.0) */
        case 0x73BFu:
        case 0x73DFu:
        case 0x73FFu:
        case 0x743Fu:
            id.family = AMDGPU_FAMILY_RDNA2;
            id.dcn_hint = DC_DCN_3_0;
            id.gfx_major = 10; id.sdma_major = 5; id.is_apu = false;
            id.marketing_name = "AMD Radeon RX 6000 (RDNA 2)";
            return id;
        default:
            break;
    }

    if (device_id >= 0x7550u && device_id <= 0x75FFu) {
        id.family = AMDGPU_FAMILY_RDNA4;
        id.dcn_hint = DC_DCN_4_0_1;
        id.gfx_major = 12; id.sdma_major = 7;
        id.marketing_name = "AMD Radeon RDNA 4";
    } else if (device_id >= 0x7440u && device_id <= 0x749Fu) {
        id.family = AMDGPU_FAMILY_RDNA3;
        id.dcn_hint = DC_DCN_3_2;
        id.gfx_major = 11; id.sdma_major = 6;
        id.marketing_name = "AMD Radeon RDNA 3";
    } else if (device_id >= 0x73A0u && device_id <= 0x73FFu) {
        id.family = AMDGPU_FAMILY_RDNA2;
        id.dcn_hint = DC_DCN_3_0;
        id.gfx_major = 10; id.sdma_major = 5;
        id.marketing_name = "AMD Radeon RDNA 2";
    } else {
        id.family = AMDGPU_FAMILY_UNKNOWN;
        id.dcn_hint = DC_DCN_NONE;
        id.marketing_name = "AMD Radeon GPU";
    }
    return id;
}

/* ---- Ring-3 hardware `dosdrm_c` I/O callbacks ---- */

static u32 hw_mmio_r32(void *ctx, u64 byte_off) {
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    if (!adev || adev->mmio_addr == 0 || byte_off + 4ULL > adev->mmio_len || (byte_off & 3ULL) != 0) {
        return 0u;
    }
    return readl((const volatile void __iomem *)(uintptr_t)(adev->mmio_addr + byte_off));
}

static void hw_mmio_w32(void *ctx, u64 byte_off, u32 val) {
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    if (!adev || adev->mmio_addr == 0 || byte_off + 4ULL > adev->mmio_len || (byte_off & 3ULL) != 0) {
        return;
    }
    writel(val, (volatile void __iomem *)(uintptr_t)(adev->mmio_addr + byte_off));
}

int amdgpu_hw_ensure_vram_window(struct amdgpu_device *adev, u64 vram_base, u64 len) {
    if (!adev || len == 0 || adev->bar_sizes[0] == 0) {
        return -EINVAL;
    }
    if (adev->vram_addr != 0
        && vram_base >= adev->vram_win_base
        && vram_base + len <= adev->vram_win_base + adev->vram_len) {
        return 0;
    }
    if (adev->vram_addr != 0) {
        dosdrm_unmap_bar(adev->vram_vmo, adev->vram_addr, adev->vram_len);
        adev->vram_vmo = 0;
        adev->vram_addr = 0;
        adev->vram_len = 0;
        adev->vram_win_base = 0;
    }
    u64 aligned_base = vram_base & ~4095ULL;
    u64 end = (vram_base + len + 4095ULL) & ~4095ULL;
    u64 map_len = end - aligned_base;
    u64 min_win = (adev->bar_sizes[0] >= (256ULL << 20)) ? (128ULL << 20) : (64ULL << 20);
    if (map_len < min_win) {
        map_len = min_win;
    }
    if (aligned_base + map_len > adev->bar_sizes[0]) {
        if (aligned_base >= adev->bar_sizes[0]) {
            return -ERANGE;
        }
        map_len = adev->bar_sizes[0] - aligned_base;
    }
    u32 vmo = 0;
    u64 addr = 0;
    u64 got_len = 0;
    int rc = dosdrm_map_bar(adev->dev_handle, 0u, aligned_base, map_len, &vmo, &addr, &got_len);
    if (rc != 0) {
        return rc;
    }
    adev->vram_vmo = vmo;
    adev->vram_addr = addr;
    adev->vram_len = got_len;
    adev->vram_win_base = aligned_base;
    return 0;
}

static int hw_vram_read(void *ctx, u64 vram_off, void *dst, size_t len) {
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    if (!adev || !dst || len == 0) return -EINVAL;
    int rc = amdgpu_hw_ensure_vram_window(adev, vram_off, (u64)len);
    if (rc != 0) return rc;
    u64 rel = vram_off - adev->vram_win_base;
    memcpy(dst, (const void *)(uintptr_t)(adev->vram_addr + rel), len);
    return 0;
}

static int hw_vram_write(void *ctx, u64 vram_off, const void *src, size_t len) {
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    if (!adev || !src || len == 0) return -EINVAL;
    int rc = amdgpu_hw_ensure_vram_window(adev, vram_off, (u64)len);
    if (rc != 0) return rc;
    u64 rel = vram_off - adev->vram_win_base;
    /* Write-combining 32-bit streaming store for aligned lengths to maximize PCIe WC burst throughput. */
    if (((rel | (u64)(uintptr_t)src | (u64)len) & 3ULL) == 0) {
        volatile u32 *d = (volatile u32 *)(uintptr_t)(adev->vram_addr + rel);
        const u32 *s = (const u32 *)src;
        size_t n = len / 4u;
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        memcpy((void *)(uintptr_t)(adev->vram_addr + rel), src, len);
    }
    wmb();
    return 0;
}

static int hw_dma_alloc(void *ctx, u64 size, struct dosdrm_dma_buf *out) {
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    return dosdrm_dma_alloc_coherent(adev ? adev->dev_handle : 0u, size, out);
}

static void hw_dma_free(void *ctx, struct dosdrm_dma_buf *buf) {
    (void)ctx;
    dosdrm_dma_free_coherent(buf);
}

static int hw_load_fw(void *ctx, const char *name, const u8 **out_data, size_t *out_size, const void **out_handle) {
    (void)ctx;
    const struct firmware *fw = NULL;
    int rc = request_firmware(&fw, name, NULL);
    if (rc != 0 || !fw) {
        return rc ? rc : -ENOENT;
    }
    *out_data = fw->data;
    *out_size = fw->size;
    *out_handle = fw;
    return 0;
}

static void hw_release_fw(void *ctx, const void *handle) {
    (void)ctx;
    release_firmware((const struct firmware *)handle);
}

static u64 hw_clock_ns(void *ctx) {
    (void)ctx;
    return ktime_get_ns();
}

static void hw_udelay(void *ctx, u32 us) {
    (void)ctx;
    dosdrm_udelay(us);
}

static void hw_log(void *ctx, const char *msg) {
    (void)ctx;
    dosdrm_log_cstr(msg);
}

/* ---- Core lifecycle ---- */

int amdgpu_device_init_with_ops(
    struct amdgpu_device *adev,
    u16 vendor_id,
    u16 device_id,
    u8 revision_id,
    const u64 bar_sizes[6],
    const struct amdgpu_io_ops *ops
) {
    if (!adev || !ops || vendor_id != AMDGPU_PCI_VENDOR_AMD) {
        return -EINVAL;
    }
    u32 saved_dev = adev->dev_handle;
    u32 saved_mvmo = adev->mmio_vmo;
    u64 saved_maddr = adev->mmio_addr;
    u64 saved_mlen = adev->mmio_len;
    memset(adev, 0, sizeof(*adev));
    adev->dev_handle = saved_dev;
    adev->mmio_vmo = saved_mvmo;
    adev->mmio_addr = saved_maddr;
    adev->mmio_len = saved_mlen;

    adev->vendor_id = vendor_id;
    adev->device_id = device_id;
    adev->revision_id = revision_id;
    if (bar_sizes) {
        memcpy(adev->bar_sizes, bar_sizes, sizeof(adev->bar_sizes));
    }
    adev->io = *ops;

    struct amdgpu_asic_id id = amdgpu_identify_asic(device_id);
    adev->family = id.family;
    adev->dcn_version = id.dcn_hint;
    adev->is_apu = id.is_apu;
    adev->asic_name = id.marketing_name;

    /* 1. Load & validate official AMD firmware blobs from sys:/firmware/amdgpu/. */
    (void)amdgpu_ucode_load_all(adev);

    /* 2. Parse IP Discovery from VRAM top (direct BAR0 first, indirect MM_INDEX fallback). */
    int disc_rc = amdgpu_discovery_init(adev);
    if (disc_rc != 0) {
        /* Still keep GEM/VM/syncobj ready even if hardware discovery isn't present. */
        return disc_rc;
    }

    /* 3. Parse AtomBIOS ROM data/command tables from VRAM offset 0 when present. */
    (void)amdgpu_atom_init(adev);

    /* 4. Initialize PSP & SMU (PMFW) firmware interfaces. */
    (void)amdgpu_psp_init(adev);
    (void)amdgpu_smu_init(adev);

    /* 5. Initialize GMC / MMHUB GPU VM, OSSSYS IH interrupt ring, and GFX/SDMA/MES rings. */
    (void)amdgpu_gmc_init(adev);
    (void)amdgpu_ih_init(adev);
    (void)amdgpu_rings_init(adev);

    /* 6. Initialize Display Core (`dc` / `dmub` / `dml2` / `dc_link` / Atomic KMS pipes). */
    (void)dc_init(adev);
    return 0;
}

int amdgpu_device_init_hardware(struct amdgpu_device *adev, u32 dev_handle) {
    if (!adev || dev_handle == 0) {
        return -EINVAL;
    }
    memset(adev, 0, sizeof(*adev));
    adev->dev_handle = dev_handle;

    u16 vendor = 0, device = 0;
    u8 rev = 0;
    u64 bars[6];
    memset(bars, 0, sizeof(bars));
    int rc = dosdrm_pci_get_info(dev_handle, &vendor, &device, &rev, bars);
    if (rc != 0) {
        return rc;
    }

    /* Map MMIO BAR 5 (up to 16 MiB — required for RDNA 3/4 DCN + MMHUB + OSSSYS + MP0/MP1). */
    u64 mmio_sz = bars[5];
    if (mmio_sz > (16ULL << 20)) {
        mmio_sz = (16ULL << 20);
    }
    if (mmio_sz > 0) {
        rc = dosdrm_map_bar(dev_handle, 5u, 0, mmio_sz, &adev->mmio_vmo, &adev->mmio_addr, &adev->mmio_len);
        if (rc != 0) {
            return rc;
        }
    }

    struct amdgpu_io_ops ops;
    memset(&ops, 0, sizeof(ops));
    ops.ctx = adev;
    ops.mmio_r32 = hw_mmio_r32;
    ops.mmio_w32 = hw_mmio_w32;
    ops.vram_read = hw_vram_read;
    ops.vram_write = hw_vram_write;
    ops.dma_alloc = hw_dma_alloc;
    ops.dma_free = hw_dma_free;
    ops.load_fw = hw_load_fw;
    ops.release_fw = hw_release_fw;
    ops.clock_ns = hw_clock_ns;
    ops.udelay = hw_udelay;
    ops.log = hw_log;

    return amdgpu_device_init_with_ops(adev, vendor, device, rev, bars, &ops);
}

int amdgpu_device_suspend(struct amdgpu_device *adev) {
    if (!adev || adev->suspended) {
        return 0;
    }
    (void)dc_suspend(adev);
    amdgpu_ih_fini(adev);
    amdgpu_rings_fini(adev);
    (void)amdgpu_smu_suspend(adev);
    adev->suspended = true;
    return 0;
}

int amdgpu_device_resume(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    if (!adev->suspended) {
        return 0;
    }
    (void)amdgpu_psp_init(adev);
    (void)amdgpu_smu_resume(adev);
    (void)amdgpu_ih_init(adev);
    (void)amdgpu_rings_init(adev);
    (void)dc_resume(adev);
    adev->suspended = false;
    return 0;
}

void amdgpu_device_fini(struct amdgpu_device *adev) {
    if (!adev) {
        return;
    }
    dc_fini(adev);
    amdgpu_rings_fini(adev);
    amdgpu_ih_fini(adev);
    amdgpu_psp_fini(adev);
    amdgpu_ucode_release_all(adev);
    if (adev->vram_addr != 0) {
        dosdrm_unmap_bar(adev->vram_vmo, adev->vram_addr, adev->vram_len);
        adev->vram_vmo = 0;
        adev->vram_addr = 0;
        adev->vram_len = 0;
    }
    if (adev->mmio_addr != 0) {
        dosdrm_unmap_bar(adev->mmio_vmo, adev->mmio_addr, adev->mmio_len);
        adev->mmio_vmo = 0;
        adev->mmio_addr = 0;
        adev->mmio_len = 0;
    }
}
