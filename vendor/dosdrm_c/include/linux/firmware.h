#ifndef _LINUX_FIRMWARE_H
#define _LINUX_FIRMWARE_H

#include <linux/types.h>
#include <dosdrm/shim.h>

struct firmware {
    size_t size;
    const u8 *data;
    uint32_t _vmo_handle;
    uint64_t _map_addr;
    uint64_t _map_len;
};

static inline int request_firmware(const struct firmware **fw, const char *name, void *device) {
    (void)device;
    return dosdrm_request_firmware(fw, name);
}

static inline void release_firmware(const struct firmware *fw) {
    dosdrm_release_firmware(fw);
}

#endif
