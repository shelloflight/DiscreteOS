#include <dosdrm/shim.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_mode.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/slab.h>

#define DOSDRM_ALLOC_MAGIC 0x4444524Du /* "DDRM" */

struct dosdrm_alloc_hdr {
    uint32_t magic;
    uint32_t reserved;
    size_t total_bytes;
};

static size_t cstr_len(const char *s, size_t max_len) {
    size_t n = 0;
    if (!s) {
        return 0;
    }
    while (n < max_len && s[n] != '\0') {
        n++;
    }
    return n;
}

static void mem_zero(void *dst, size_t n) {
    uint8_t *p = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++) {
        p[i] = 0;
    }
}

uint32_t dosdrm_shim_version(void) {
    return DOSDRM_SHIM_ABI_VERSION;
}

void dosdrm_log_cstr(const char *msg) {
    size_t len = cstr_len(msg, 256);
    if (len > 0) {
        dosdrm_host_log(msg, len);
    }
}

void dosdrm_udelay(uint32_t us) {
    dosdrm_host_udelay(us);
}

void *dosdrm_kzalloc(size_t size) {
    if (size == 0) {
        size = 8;
    }
    if (size > ((size_t)1 << 28)) {
        return NULL;
    }
    size_t total = sizeof(struct dosdrm_alloc_hdr) + ALIGN(size, 16u);
    struct dosdrm_alloc_hdr *hdr = (struct dosdrm_alloc_hdr *)dosdrm_host_alloc(total);
    if (!hdr) {
        return NULL;
    }
    mem_zero(hdr, total);
    hdr->magic = DOSDRM_ALLOC_MAGIC;
    hdr->reserved = 0;
    hdr->total_bytes = total;
    return (void *)(hdr + 1);
}

void dosdrm_kfree(void *ptr) {
    if (!ptr) {
        return;
    }
    struct dosdrm_alloc_hdr *hdr = ((struct dosdrm_alloc_hdr *)ptr) - 1;
    if (hdr->magic != DOSDRM_ALLOC_MAGIC) {
        return;
    }
    size_t total = hdr->total_bytes;
    hdr->magic = 0;
    dosdrm_host_free(hdr, total);
}

int dosdrm_pci_read_config(uint32_t dev_handle, uint16_t where, uint8_t width, void *out) {
    uint32_t val = 0;
    if (!out) {
        return -EINVAL;
    }
    int rc = dosdrm_host_pci_cfg_read(dev_handle, where, width, &val);
    if (rc != 0) {
        return rc;
    }
    if (width == 1) {
        *(uint8_t *)out = (uint8_t)val;
    } else if (width == 2) {
        *(uint16_t *)out = (uint16_t)val;
    } else if (width == 4) {
        *(uint32_t *)out = val;
    } else {
        return -EINVAL;
    }
    return 0;
}

int dosdrm_pci_write_config(uint32_t dev_handle, uint16_t where, uint8_t width, uint32_t val) {
    return dosdrm_host_pci_cfg_write(dev_handle, where, width, val);
}

int dosdrm_request_firmware(const struct firmware **fw_out, const char *name) {
    if (!fw_out || !name) {
        return -EINVAL;
    }
    *fw_out = NULL;
    size_t nlen = cstr_len(name, 255);
    if (nlen == 0) {
        return -EINVAL;
    }
    struct firmware *fw = (struct firmware *)kzalloc(sizeof(struct firmware), GFP_KERNEL);
    if (!fw) {
        return -ENOMEM;
    }
    uint32_t vmo = 0;
    uint64_t addr = 0;
    uint64_t map_len = 0;
    size_t size = 0;
    int rc = dosdrm_host_load_firmware(name, nlen, &vmo, &addr, &map_len, &size);
    if (rc != 0) {
        kfree(fw);
        return rc;
    }
    fw->size = size;
    fw->data = (const u8 *)(uintptr_t)addr;
    fw->_vmo_handle = vmo;
    fw->_map_addr = addr;
    fw->_map_len = map_len;
    *fw_out = fw;
    return 0;
}

void dosdrm_release_firmware(const struct firmware *fw) {
    if (!fw) {
        return;
    }
    if (fw->_vmo_handle != 0 || fw->_map_addr != 0) {
        dosdrm_host_unload_firmware(fw->_vmo_handle, fw->_map_addr, fw->_map_len);
    }
    kfree(fw);
}

uint32_t dosdrm_fourcc_bpp(uint32_t fourcc) {
    switch (fourcc) {
        case DRM_FORMAT_XRGB8888:
        case DRM_FORMAT_ARGB8888:
        case DRM_FORMAT_XBGR8888:
        case DRM_FORMAT_ABGR8888:
        case DRM_FORMAT_XRGB2101010:
        case DRM_FORMAT_ARGB2101010:
            return 32u;
        default:
            return 0u;
    }
}

int dosdrm_mode_validate(const void *mode_info, uint32_t max_dim) {
    const struct drm_mode_modeinfo *m = (const struct drm_mode_modeinfo *)mode_info;
    if (!m || max_dim == 0) {
        return -EINVAL;
    }
    if (m->hdisplay < 320 || m->vdisplay < 200 || m->hdisplay > max_dim || m->vdisplay > max_dim) {
        return -ERANGE;
    }
    if (m->htotal <= m->hdisplay || m->vtotal <= m->vdisplay || m->clock == 0) {
        return -EINVAL;
    }
    return 0;
}

int dosdrm_vendor_self_test(void) {
    if (dosdrm_shim_version() != DOSDRM_SHIM_ABI_VERSION) {
        return -EINVAL;
    }
    if (dosdrm_fourcc_bpp(DRM_FORMAT_XRGB8888) != 32u || dosdrm_fourcc_bpp(DRM_FORMAT_ARGB2101010) != 32u) {
        return -EINVAL;
    }
    uint32_t *buf = (uint32_t *)kzalloc(64, GFP_KERNEL);
    if (!buf) {
        return -ENOMEM;
    }
    for (uint32_t i = 0; i < 16; i++) {
        if (buf[i] != 0) {
            kfree(buf);
            return -EFAULT;
        }
        buf[i] = 0xA500u + i;
    }
    kfree(buf);

    uint32_t cxx = dosdrm_cxx_probe(0x240u);
    if (cxx != (0x240u ^ 0x4B4D5331u)) {
        return -EIO;
    }
    return 0;
}
