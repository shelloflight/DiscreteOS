#ifndef _DOSDRM_SHIM_H
#define _DOSDRM_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DOSDRM_SHIM_ABI_VERSION 0x00010002u

struct firmware;

/* Host callbacks implemented in Rust (`dosdrm::shim`) over Ring-3 libd syscalls. */
void dosdrm_host_log(const char *msg, size_t len);
void dosdrm_host_udelay(uint32_t us);
uint64_t dosdrm_host_clock_ns(void);
void *dosdrm_host_alloc(size_t size);
void dosdrm_host_free(void *ptr, size_t size);
int dosdrm_host_pci_cfg_read(uint32_t dev_handle, uint16_t offset, uint8_t width, uint32_t *out_val);
int dosdrm_host_pci_cfg_write(uint32_t dev_handle, uint16_t offset, uint8_t width, uint32_t val);
int dosdrm_host_pci_info(
    uint32_t dev_handle,
    uint16_t *out_vendor,
    uint16_t *out_device,
    uint8_t *out_rev,
    uint64_t *out_bar_sizes
);
int dosdrm_host_map_bar(
    uint32_t dev_handle,
    uint8_t bar,
    uint64_t off,
    uint64_t len,
    uint32_t *out_vmo,
    uint64_t *out_addr,
    uint64_t *out_len
);
void dosdrm_host_unmap_bar(uint32_t vmo, uint64_t addr, uint64_t len);
int dosdrm_host_dma_alloc(
    uint32_t dev_handle,
    uint64_t size,
    uint64_t *out_cpu_addr,
    uint64_t *out_dma_addr,
    uint32_t *out_vmo,
    uint32_t *out_pin,
    uint64_t *out_map_len
);
void dosdrm_host_dma_free(uint64_t cpu_addr, uint64_t map_len, uint32_t vmo, uint32_t pin);
int dosdrm_host_load_firmware(
    const char *name,
    size_t name_len,
    uint32_t *out_vmo,
    uint64_t *out_addr,
    uint64_t *out_map_len,
    size_t *out_size
);
void dosdrm_host_unload_firmware(uint32_t vmo, uint64_t addr, uint64_t map_len);

/* C17 shim entry points used by vendored C/C++ GPU drivers. */
uint32_t dosdrm_shim_version(void);
void dosdrm_log_cstr(const char *msg);
void dosdrm_udelay(uint32_t us);
uint64_t dosdrm_clock_ns(void);
void *dosdrm_kzalloc(size_t size);
void dosdrm_kfree(void *ptr);
int dosdrm_pci_read_config(uint32_t dev_handle, uint16_t where, uint8_t width, void *out);
int dosdrm_pci_write_config(uint32_t dev_handle, uint16_t where, uint8_t width, uint32_t val);
int dosdrm_pci_get_info(
    uint32_t dev_handle,
    uint16_t *out_vendor,
    uint16_t *out_device,
    uint8_t *out_rev,
    uint64_t *out_bar_sizes
);
int dosdrm_map_bar(
    uint32_t dev_handle,
    uint8_t bar,
    uint64_t off,
    uint64_t len,
    uint32_t *out_vmo,
    uint64_t *out_addr,
    uint64_t *out_len
);
void dosdrm_unmap_bar(uint32_t vmo, uint64_t addr, uint64_t len);
int dosdrm_dma_alloc(
    uint32_t dev_handle,
    uint64_t size,
    uint64_t *out_cpu_addr,
    uint64_t *out_dma_addr,
    uint32_t *out_vmo,
    uint32_t *out_pin,
    uint64_t *out_map_len
);
void dosdrm_dma_free(uint64_t cpu_addr, uint64_t map_len, uint32_t vmo, uint32_t pin);
int dosdrm_request_firmware(const struct firmware **fw_out, const char *name);
void dosdrm_release_firmware(const struct firmware *fw);
uint32_t dosdrm_fourcc_bpp(uint32_t fourcc);
int dosdrm_mode_validate(const void *mode_info, uint32_t max_dim);

/* Freestanding C++20 runtime probe (`dosdrm_cxx_abi.cpp`). */
uint32_t dosdrm_cxx_probe(uint32_t seed);

/* Combined C17 + C++20 vendor link & allocator self-test run by `.ddrv` drivers at startup. */
int dosdrm_vendor_self_test(void);

#ifdef __cplusplus
}
#endif

#endif
