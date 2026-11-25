#include <amdgpu_capi.h>
#include <dc.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>

static void copy_str(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    memset(dst, 0, cap);
    if (!src) return;
    size_t n = strnlen(src, cap - 1u);
    memcpy(dst, src, n);
}

void *amdgpu_capi_open(uint32_t dev_handle) {
    struct amdgpu_device *adev = (struct amdgpu_device *)kzalloc(sizeof(struct amdgpu_device), GFP_KERNEL);
    if (!adev) {
        return NULL;
    }
    /* Initialize hardware; even if IP Discovery is absent, keep context alive for GEM/VM/syncobj. */
    (void)amdgpu_device_init_hardware(adev, dev_handle);
    return adev;
}

void amdgpu_capi_close(void *ctx) {
    if (!ctx) return;
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    amdgpu_device_fini(adev);
    kfree(adev);
}

int amdgpu_capi_suspend(void *ctx) {
    return ctx ? amdgpu_device_suspend((struct amdgpu_device *)ctx) : -EINVAL;
}

int amdgpu_capi_resume(void *ctx) {
    return ctx ? amdgpu_device_resume((struct amdgpu_device *)ctx) : -EINVAL;
}

uint32_t amdgpu_capi_get_info(
    void *ctx,
    uint32_t pipe_slot,
    struct amdgpu_capi_info *out_info,
    struct amdgpu_capi_mode *out_modes,
    uint32_t max_modes
) {
    if (!ctx || !out_info) return 0u;
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    memset(out_info, 0, sizeof(*out_info));

    out_info->native_kms = adev->native_kms_active ? 1u : 0u;
    out_info->dcn_version = (uint32_t)adev->dcn_version;
    out_info->fw_loaded_count = adev->ucode_loaded_count;
    out_info->psp_alive = adev->psp.sos_alive ? 1u : 0u;
    out_info->smu_alive = adev->smu.pmfw_alive ? 1u : 0u;
    out_info->ih_enabled = adev->ih.enabled ? 1u : 0u;
    out_info->vram_bytes = adev->gmc.vram_size ? adev->gmc.vram_size : adev->bar_sizes[0];
    copy_str(out_info->asic_name, sizeof(out_info->asic_name), adev->asic_name);

    if (!adev->dc) {
        out_info->connector_kind = 3u; /* DisplayPort default */
        return 0u;
    }
    struct dc_state *dc = adev->dc;
    out_info->active_pipes = (uint8_t)dc->active_pipe_count;
    out_info->dmub_alive = dc->dmub.fw_alive ? 1u : 0u;

    if (dc->active_pipe_count == 0) {
        out_info->connector_kind = 3u;
        return 0u;
    }
    uint32_t idx = (pipe_slot < dc->active_pipe_count) ? pipe_slot : 0u;
    const struct dc_pipe_state *p = &dc->pipes[idx];
    const struct dc_connector *c = (p->conn_idx < dc->connector_count) ? &dc->connectors[p->conn_idx] : NULL;

    out_info->width = p->current_mode.h_active;
    out_info->height = p->current_mode.v_active;
    out_info->pitch_bytes = p->pitch_bytes;
    out_info->refresh_mhz = p->current_mode.refresh_mhz;
    out_info->htotal = (uint16_t)(p->current_mode.h_active + p->current_mode.h_blank);
    out_info->vtotal = (uint16_t)(p->current_mode.v_active + p->current_mode.v_blank);
    out_info->vblank_seq = p->vblank_seq;
    out_info->vrr_enabled = p->vrr_enabled ? 1u : 0u;
    out_info->hdr_enabled = p->hdr_enabled ? 1u : 0u;
    out_info->dsc_enabled = p->dsc_enabled ? 1u : 0u;
    out_info->hw_cursor = (p->cursor_mc != 0) ? 1u : 0u;

    uint32_t mode_cnt = 0;
    if (c) {
        out_info->connector_kind = (c->link_type == DC_LINK_HDMI_21) ? 4u : ((c->link_type == DC_LINK_EDP) ? 5u : 3u);
        out_info->dp_lanes = c->trained_lanes ? c->trained_lanes : c->max_lanes;
        out_info->dp_rate_mbps = c->trained_rate_mbps ? c->trained_rate_mbps : c->max_rate_mbps;
        out_info->edid_blocks = c->edid_blocks;
        out_info->vrr_capable = c->vrr_capable ? 1u : 0u;
        out_info->vrr_min_hz = c->vrr_min_hz;
        out_info->vrr_max_hz = c->vrr_max_hz;
        out_info->hdr_capable = c->hdr_capable ? 1u : 0u;
        out_info->dsc_capable = c->dsc_capable ? 1u : 0u;
        copy_str(out_info->monitor_name, sizeof(out_info->monitor_name), c->monitor_name);

        if (out_modes && max_modes > 0) {
            uint32_t n = c->mode_count < max_modes ? c->mode_count : max_modes;
            for (uint32_t i = 0; i < n; i++) {
                const struct dc_timing *t = &c->modes[i];
                out_modes[i].width = t->h_active;
                out_modes[i].height = t->v_active;
                out_modes[i].refresh_mhz = t->refresh_mhz;
                out_modes[i].pixel_clock_khz = t->pixel_clock_khz;
                out_modes[i].htotal = (uint16_t)(t->h_active + t->h_blank);
                out_modes[i].vtotal = (uint16_t)(t->v_active + t->v_blank);
                uint32_t fl = t->preferred ? 1u : 0u;
                uint32_t diff = t->refresh_mhz > p->current_mode.refresh_mhz
                    ? (t->refresh_mhz - p->current_mode.refresh_mhz)
                    : (p->current_mode.refresh_mhz - t->refresh_mhz);
                if (t->h_active == p->current_mode.h_active
                    && t->v_active == p->current_mode.v_active
                    && diff <= 1500u) {
                    fl |= 2u; /* MODE_FLAG_CURRENT */
                }
                out_modes[i].flags = fl;
                mode_cnt++;
            }
        }
    } else {
        out_info->connector_kind = 3u;
    }
    return mode_cnt;
}

int amdgpu_capi_atomic_commit(
    void *ctx,
    const struct amdgpu_capi_commit *req,
    uint64_t *out_vblank_seq,
    uint8_t *out_async
) {
    if (!ctx || !req || !out_vblank_seq || !out_async) return -EINVAL;
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    struct dc_atomic_req dc_req;
    memset(&dc_req, 0, sizeof(dc_req));
    dc_req.pipe_slot = req->pipe_slot;
    dc_req.test_only = req->test_only != 0;
    dc_req.allow_modeset = req->allow_modeset != 0;
    dc_req.reset_boot = req->reset_boot != 0;
    dc_req.mode_changed = req->mode_changed != 0;
    dc_req.mode_width = req->mode_width;
    dc_req.mode_height = req->mode_height;
    dc_req.mode_refresh_mhz = req->mode_refresh_mhz;
    dc_req.vrr_changed = req->vrr_changed != 0;
    dc_req.vrr_enable = req->vrr_enable != 0;
    dc_req.hdr_changed = req->hdr_changed != 0;
    dc_req.hdr_enable = req->hdr_enable != 0;
    dc_req.primary_changed = req->primary_changed != 0;
    dc_req.primary_src = req->primary_src;
    dc_req.primary_width = req->primary_width;
    dc_req.primary_height = req->primary_height;
    dc_req.primary_pitch = req->primary_pitch;
    dc_req.primary_format = req->primary_format;
    dc_req.cursor_changed = req->cursor_changed != 0;
    dc_req.cursor_src = req->cursor_src;
    dc_req.cursor_size = req->cursor_size;
    dc_req.cursor_x = req->cursor_x;
    dc_req.cursor_y = req->cursor_y;
    dc_req.cursor_hot_x = req->cursor_hot_x;
    dc_req.cursor_hot_y = req->cursor_hot_y;

    bool is_async = false;
    int rc = dc_atomic_check_and_commit(adev, &dc_req, out_vblank_seq, &is_async);
    *out_async = is_async ? 1u : 0u;
    return rc;
}

int amdgpu_capi_poll_vblank(
    void *ctx,
    uint32_t *out_pipe,
    uint64_t *out_seq,
    uint64_t *out_ts_ns,
    uint8_t *out_late
) {
    if (!ctx || !out_pipe || !out_seq || !out_ts_ns || !out_late) return 0;
    bool late = false;
    bool got = dc_poll_vblank((struct amdgpu_device *)ctx, out_pipe, out_seq, out_ts_ns, &late);
    *out_late = late ? 1u : 0u;
    return got ? 1 : 0;
}

int amdgpu_capi_poll_hotplug(void *ctx) {
    if (!ctx) return 0;
    struct amdgpu_device *adev = (struct amdgpu_device *)ctx;
    if (!adev->dc) return 0;
    bool ch = dc_link_poll_hotplug(adev, adev->dc);
    if (adev->dc->hotplug_pending) {
        adev->dc->hotplug_pending = false;
        return 1;
    }
    return ch ? 1 : 0;
}

int amdgpu_capi_vm_create(void *ctx, uint32_t vm_id) {
    return ctx ? amdgpu_vm_create((struct amdgpu_device *)ctx, vm_id) : -EINVAL;
}

int amdgpu_capi_vm_destroy(void *ctx, uint32_t vm_id) {
    return ctx ? amdgpu_vm_destroy((struct amdgpu_device *)ctx, vm_id) : -EINVAL;
}

int amdgpu_capi_vm_map(
    void *ctx,
    uint32_t vm_id,
    uint32_t gem_handle,
    uint64_t gpu_va,
    uint64_t size,
    uint64_t target_addr,
    uint8_t is_system,
    uint32_t vm_flags
) {
    return ctx
        ? amdgpu_vm_map((struct amdgpu_device *)ctx, vm_id, gem_handle, gpu_va, size, target_addr, is_system != 0, vm_flags)
        : -EINVAL;
}

int amdgpu_capi_vm_unmap(void *ctx, uint32_t vm_id, uint64_t gpu_va, uint64_t size) {
    return ctx ? amdgpu_vm_unmap((struct amdgpu_device *)ctx, vm_id, gpu_va, size) : -EINVAL;
}

int amdgpu_capi_ring_submit(
    void *ctx,
    uint32_t engine,
    uint32_t vm_id,
    const uint8_t *cmd,
    size_t len,
    uint64_t *out_seq
) {
    return ctx ? amdgpu_ring_submit((struct amdgpu_device *)ctx, engine, vm_id, cmd, len, out_seq) : -EINVAL;
}

uint64_t amdgpu_capi_irqs(void *ctx) {
    return ctx ? ((const struct amdgpu_device *)ctx)->ih.irq_count : 0ULL;
}

uint64_t amdgpu_capi_frames(void *ctx) {
    if (!ctx) return 0ULL;
    const struct amdgpu_device *adev = (const struct amdgpu_device *)ctx;
    if (!adev->dc || adev->dc->active_pipe_count == 0) return 0ULL;
    return adev->dc->pipes[0].flips_completed;
}
