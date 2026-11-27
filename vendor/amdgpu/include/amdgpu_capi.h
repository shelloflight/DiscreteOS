#ifndef _AMDGPU_CAPI_H
#define _AMDGPU_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct amdgpu_capi_mode {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_mhz;
    uint32_t pixel_clock_khz;
    uint16_t htotal;
    uint16_t vtotal;
    uint32_t flags;
};

struct amdgpu_capi_info {
    uint8_t native_kms;
    uint8_t active_pipes;
    uint8_t connector_kind; /* matches dosdrm::kms::ConnectorKind */
    uint8_t dp_lanes;
    uint8_t edid_blocks;
    uint8_t vrr_capable;
    uint8_t vrr_enabled;
    uint8_t hdr_capable;
    uint8_t hdr_enabled;
    uint8_t dsc_capable;
    uint8_t dsc_enabled;
    uint8_t hw_cursor;
    uint8_t psp_alive;
    uint8_t smu_alive;
    uint8_t dmub_alive;
    uint8_t ih_enabled;
    uint16_t vrr_min_hz;
    uint16_t vrr_max_hz;
    uint32_t dcn_version;
    uint32_t fw_loaded_count;
    uint32_t width;
    uint32_t height;
    uint32_t pitch_bytes;
    uint32_t refresh_mhz;
    uint16_t htotal;
    uint16_t vtotal;
    uint32_t dp_rate_mbps;
    uint64_t vblank_seq;
    uint64_t vram_bytes;
    char monitor_name[24];
    char asic_name[40];
};

struct amdgpu_capi_damage_rect {
    uint32_t x;
    uint32_t y;
    uint32_t w;
    uint32_t h;
};

struct amdgpu_capi_commit {
    uint32_t pipe_slot;
    uint8_t test_only;
    uint8_t allow_modeset;
    uint8_t reset_boot;
    uint8_t mode_changed;
    uint32_t mode_width;
    uint32_t mode_height;
    uint32_t mode_refresh_mhz;
    uint8_t vrr_changed;
    uint8_t vrr_enable;
    uint8_t hdr_changed;
    uint8_t hdr_enable;
    uint8_t primary_changed;
    uint8_t cursor_changed;
    uint16_t cursor_hot_x;
    uint16_t cursor_hot_y;
    const uint8_t *primary_src;
    uint32_t primary_width;
    uint32_t primary_height;
    uint32_t primary_pitch;
    uint32_t primary_format;
    const uint8_t *cursor_src;
    uint32_t cursor_size;
    int32_t cursor_x;
    int32_t cursor_y;
    uint32_t damage_count;
    struct amdgpu_capi_damage_rect damage[16];
};

void *amdgpu_capi_open(uint32_t dev_handle);
void amdgpu_capi_close(void *ctx);
int amdgpu_capi_suspend(void *ctx);
int amdgpu_capi_resume(void *ctx);

uint32_t amdgpu_capi_get_info(
    void *ctx,
    uint32_t pipe_slot,
    struct amdgpu_capi_info *out_info,
    struct amdgpu_capi_mode *out_modes,
    uint32_t max_modes
);

int amdgpu_capi_atomic_commit(
    void *ctx,
    const struct amdgpu_capi_commit *req,
    uint64_t *out_vblank_seq,
    uint8_t *out_async
);

int amdgpu_capi_poll_vblank(
    void *ctx,
    uint32_t *out_pipe,
    uint64_t *out_seq,
    uint64_t *out_ts_ns,
    uint8_t *out_late
);

int amdgpu_capi_poll_hotplug(void *ctx);
int amdgpu_capi_has_pending_flip(void *ctx);
uint32_t amdgpu_capi_refresh_mhz(void *ctx);
int amdgpu_capi_vm_create(void *ctx, uint32_t vm_id);
int amdgpu_capi_vm_destroy(void *ctx, uint32_t vm_id);
int amdgpu_capi_vm_map(
    void *ctx,
    uint32_t vm_id,
    uint32_t gem_handle,
    uint64_t gpu_va,
    uint64_t size,
    uint64_t target_addr,
    uint8_t is_system,
    uint32_t vm_flags
);
int amdgpu_capi_vm_unmap(void *ctx, uint32_t vm_id, uint64_t gpu_va, uint64_t size);
int amdgpu_capi_ring_submit(
    void *ctx,
    uint32_t engine,
    uint32_t vm_id,
    const uint8_t *cmd,
    size_t len,
    uint64_t *out_seq
);
uint64_t amdgpu_capi_irqs(void *ctx);
uint64_t amdgpu_capi_frames(void *ctx);

#ifdef __cplusplus
}
#endif

#endif
