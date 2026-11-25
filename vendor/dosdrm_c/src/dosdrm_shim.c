#include <dosdrm/shim.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_mode.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/slab.h>
#include <linux/string.h>

#define DOSDRM_ALLOC_MAGIC 0x4444524Du /* "DDRM" */

struct dosdrm_alloc_hdr {
    uint32_t magic;
    uint32_t reserved;
    size_t total_bytes;
};

void *dosdrm_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

void *dosdrm_memmove(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (d == s || n == 0) {
        return dst;
    }
    if (d < s) {
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }
    return dst;
}

void *dosdrm_memset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    uint8_t v = (uint8_t)c;
    for (size_t i = 0; i < n; i++) {
        d[i] = v;
    }
    return dst;
}

int dosdrm_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++) {
        if (pa[i] != pb[i]) {
            return (int)pa[i] - (int)pb[i];
        }
    }
    return 0;
}

size_t dosdrm_strlen(const char *s) {
    size_t n = 0;
    if (!s) {
        return 0;
    }
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

size_t dosdrm_strnlen(const char *s, size_t max_len) {
    size_t n = 0;
    if (!s) {
        return 0;
    }
    while (n < max_len && s[n] != '\0') {
        n++;
    }
    return n;
}

int dosdrm_strcmp(const char *a, const char *b) {
    if (!a || !b) {
        return (a == b) ? 0 : (a ? 1 : -1);
    }
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

int dosdrm_strncmp(const char *a, const char *b, size_t n) {
    if (!a || !b) {
        return (a == b) ? 0 : (a ? 1 : -1);
    }
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i] || a[i] == '\0') {
            return (int)(uint8_t)a[i] - (int)(uint8_t)b[i];
        }
    }
    return 0;
}

uint32_t dosdrm_shim_version(void) {
    return DOSDRM_SHIM_ABI_VERSION;
}

void dosdrm_log_cstr(const char *msg) {
    size_t len = dosdrm_strnlen(msg, 256);
    if (len > 0) {
        dosdrm_host_log(msg, len);
    }
}

void dosdrm_udelay(uint32_t us) {
    dosdrm_host_udelay(us);
}

uint64_t dosdrm_clock_ns(void) {
    return dosdrm_host_clock_ns();
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
    dosdrm_memset(hdr, 0, total);
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

int dosdrm_pci_get_info(
    uint32_t dev_handle,
    uint16_t *out_vendor,
    uint16_t *out_device,
    uint8_t *out_rev,
    uint64_t *out_bar_sizes
) {
    return dosdrm_host_pci_info(dev_handle, out_vendor, out_device, out_rev, out_bar_sizes);
}

int dosdrm_map_bar(
    uint32_t dev_handle,
    uint8_t bar,
    uint64_t off,
    uint64_t len,
    uint32_t *out_vmo,
    uint64_t *out_addr,
    uint64_t *out_len
) {
    return dosdrm_host_map_bar(dev_handle, bar, off, len, out_vmo, out_addr, out_len);
}

void dosdrm_unmap_bar(uint32_t vmo, uint64_t addr, uint64_t len) {
    dosdrm_host_unmap_bar(vmo, addr, len);
}

int dosdrm_dma_alloc(
    uint32_t dev_handle,
    uint64_t size,
    uint64_t *out_cpu_addr,
    uint64_t *out_dma_addr,
    uint32_t *out_vmo,
    uint32_t *out_pin,
    uint64_t *out_map_len
) {
    return dosdrm_host_dma_alloc(dev_handle, size, out_cpu_addr, out_dma_addr, out_vmo, out_pin, out_map_len);
}

void dosdrm_dma_free(uint64_t cpu_addr, uint64_t map_len, uint32_t vmo, uint32_t pin) {
    dosdrm_host_dma_free(cpu_addr, map_len, vmo, pin);
}

int dosdrm_request_firmware(const struct firmware **fw_out, const char *name) {
    if (!fw_out || !name) {
        return -EINVAL;
    }
    *fw_out = NULL;
    size_t nlen = dosdrm_strnlen(name, 255);
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
