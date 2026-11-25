#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <linux/types.h>
#include <dosdrm/shim.h>

static inline void *kzalloc(size_t size, gfp_t flags) {
    (void)flags;
    return dosdrm_kzalloc(size);
}

static inline void *kmalloc(size_t size, gfp_t flags) {
    (void)flags;
    return dosdrm_kzalloc(size);
}

static inline void *kcalloc(size_t n, size_t size, gfp_t flags) {
    (void)flags;
    if (size != 0 && n > ((size_t)-1) / size) {
        return NULL;
    }
    return dosdrm_kzalloc(n * size);
}

static inline void kfree(const void *ptr) {
    dosdrm_kfree((void *)ptr);
}

#endif
