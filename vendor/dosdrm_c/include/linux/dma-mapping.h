#ifndef _LINUX_DMA_MAPPING_H
#define _LINUX_DMA_MAPPING_H

#include <linux/types.h>
#include <dosdrm/shim.h>

struct dosdrm_dma_buf {
    void *cpu_addr;
    dma_addr_t dma_addr;
    u64 size;
    u64 map_len;
    u32 vmo;
    u32 pin;
};

static inline int dosdrm_dma_alloc_coherent(uint32_t dev_handle, u64 size, struct dosdrm_dma_buf *out) {
    if (!out || size == 0) {
        return -22;
    }
    uint64_t cpu_va = 0;
    uint64_t dma_pa = 0;
    uint32_t vmo = 0;
    uint32_t pin = 0;
    uint64_t map_len = 0;
    int rc = dosdrm_dma_alloc(dev_handle, size, &cpu_va, &dma_pa, &vmo, &pin, &map_len);
    if (rc != 0) {
        out->cpu_addr = NULL;
        out->dma_addr = 0;
        out->size = 0;
        out->map_len = 0;
        out->vmo = 0;
        out->pin = 0;
        return rc;
    }
    out->cpu_addr = (void *)(uintptr_t)cpu_va;
    out->dma_addr = dma_pa;
    out->size = size;
    out->map_len = map_len;
    out->vmo = vmo;
    out->pin = pin;
    return 0;
}

static inline void dosdrm_dma_free_coherent(struct dosdrm_dma_buf *buf) {
    if (!buf || (!buf->cpu_addr && buf->vmo == 0 && buf->pin == 0)) {
        return;
    }
    dosdrm_dma_free((uint64_t)(uintptr_t)buf->cpu_addr, buf->map_len, buf->vmo, buf->pin);
    buf->cpu_addr = NULL;
    buf->dma_addr = 0;
    buf->size = 0;
    buf->map_len = 0;
    buf->vmo = 0;
    buf->pin = 0;
}

#endif
