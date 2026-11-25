#include <amdgpu_hw.h>
#include <linux/errno.h>
#include <linux/string.h>

static u16 rd_le16(const u8 *p, size_t off) {
    return (u16)p[off] | ((u16)p[off + 1] << 8);
}

static u32 rd_le32(const u8 *p, size_t off) {
    return (u32)p[off]
        | ((u32)p[off + 1] << 8)
        | ((u32)p[off + 2] << 16)
        | ((u32)p[off + 3] << 24);
}

int amdgpu_ucode_validate_blob(const u8 *data, size_t len, struct amdgpu_ucode_info *out) {
    if (!data || !out || len < sizeof(struct amdgpu_common_fw_hdr)) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));

    u32 size_bytes = rd_le32(data, 0);
    u32 hdr_bytes = rd_le32(data, 4);
    u16 hdr_maj = rd_le16(data, 8);
    u16 hdr_min = rd_le16(data, 10);
    u16 ip_maj = rd_le16(data, 12);
    u16 ip_min = rd_le16(data, 14);
    u32 ucode_ver = rd_le32(data, 16);
    u32 ucode_sz = rd_le32(data, 20);
    u32 ucode_off = rd_le32(data, 24);

    if (hdr_bytes < sizeof(struct amdgpu_common_fw_hdr) || hdr_bytes > len) {
        return -EINVAL;
    }
    if (size_bytes < hdr_bytes || size_bytes > len) {
        return -EINVAL;
    }
    if (hdr_maj == 0 || hdr_maj > 8u) {
        return -EINVAL;
    }
    /* PSP v2.x containers and TOC blobs may carry sub-binary tables with ucode_size_bytes == 0. */
    if (ucode_sz > 0) {
        if (ucode_off < sizeof(struct amdgpu_common_fw_hdr)) {
            return -EINVAL;
        }
        if ((u64)ucode_off + (u64)ucode_sz > (u64)len) {
            return -ERANGE;
        }
    }

    out->loaded = true;
    out->hdr_major = hdr_maj;
    out->hdr_minor = hdr_min;
    out->ip_major = ip_maj;
    out->ip_minor = ip_min;
    out->ucode_version = ucode_ver;
    out->payload_offset = ucode_off;
    out->payload_size = ucode_sz;
    out->total_size = size_bytes;
    out->raw_data = data;

    /* Extract DMCUB v1.0 code/BSS split when header fits. */
    if (hdr_maj == 1u && hdr_bytes >= sizeof(struct amdgpu_dmcub_fw_hdr_v1_0) && len >= sizeof(struct amdgpu_dmcub_fw_hdr_v1_0)) {
        out->inst_const_bytes = rd_le32(data, 32);
        out->bss_data_bytes = rd_le32(data, 36);
    }

    /* Extract PSP v2.x container sub-binary count when present. */
    if (hdr_maj == 2u && hdr_bytes >= sizeof(struct amdgpu_psp_fw_hdr_v2_0) && len >= sizeof(struct amdgpu_psp_fw_hdr_v2_0)) {
        u32 cnt = rd_le32(data, 32);
        if (cnt <= 64u) {
            out->sub_bin_count = cnt;
        }
    }

    return 0;
}

const char *amdgpu_ucode_filename(const struct amdgpu_device *adev, enum amdgpu_ucode_id id) {
    if (!adev) {
        return NULL;
    }
    switch (adev->family) {
        case AMDGPU_FAMILY_RDNA4:
            switch (id) {
                case AMDGPU_UCODE_DMCUB:   return "dcn_4_0_1_dmcub.bin";
                case AMDGPU_UCODE_PSP_SOS: return "psp_14_0_3_sos.bin";
                case AMDGPU_UCODE_PSP_TA:  return "psp_14_0_3_ta.bin";
                case AMDGPU_UCODE_PSP_TOC: return "gc_12_0_1_toc.bin";
                case AMDGPU_UCODE_SMU:     return "smu_14_0_3.bin";
                case AMDGPU_UCODE_GFX_PFP: return "gc_12_0_1_pfp.bin";
                case AMDGPU_UCODE_GFX_ME:  return "gc_12_0_1_me.bin";
                case AMDGPU_UCODE_GFX_MEC: return "gc_12_0_1_mec.bin";
                case AMDGPU_UCODE_GFX_RLC: return "gc_12_0_1_rlc.bin";
                case AMDGPU_UCODE_GFX_IMU: return "gc_12_0_1_imu.bin";
                case AMDGPU_UCODE_GFX_MES: return "gc_12_0_1_uni_mes.bin";
                case AMDGPU_UCODE_SDMA:    return "sdma_7_0_1.bin";
                default: return NULL;
            }
        case AMDGPU_FAMILY_RDNA2_APU:
            switch (id) {
                case AMDGPU_UCODE_DMCUB:   return "dcn_3_1_5_dmcub.bin";
                case AMDGPU_UCODE_PSP_SOS: return "psp_13_0_5_asd.bin";
                case AMDGPU_UCODE_PSP_TA:  return "psp_13_0_5_ta.bin";
                case AMDGPU_UCODE_PSP_TOC: return "psp_13_0_5_toc.bin";
                case AMDGPU_UCODE_GFX_PFP: return "gc_10_3_6_pfp.bin";
                case AMDGPU_UCODE_GFX_ME:  return "gc_10_3_6_me.bin";
                case AMDGPU_UCODE_GFX_MEC: return "gc_10_3_6_mec.bin";
                case AMDGPU_UCODE_GFX_RLC: return "gc_10_3_6_rlc.bin";
                case AMDGPU_UCODE_SDMA:    return "sdma_5_2_6.bin";
                default: return NULL;
            }
        case AMDGPU_FAMILY_RDNA3:
            switch (id) {
                case AMDGPU_UCODE_DMCUB:
                    return (adev->device_id == 0x7480u || adev->device_id == 0x7483u)
                        ? "dcn_3_2_1_dmcub.bin"
                        : "dcn_3_2_0_dmcub.bin";
                case AMDGPU_UCODE_PSP_SOS: return "psp_13_0_0_sos.bin";
                case AMDGPU_UCODE_PSP_TA:  return "psp_13_0_0_ta.bin";
                case AMDGPU_UCODE_SMU:     return "smu_13_0_0.bin";
                case AMDGPU_UCODE_GFX_PFP: return "gc_11_0_0_pfp.bin";
                case AMDGPU_UCODE_GFX_ME:  return "gc_11_0_0_me.bin";
                case AMDGPU_UCODE_GFX_MEC: return "gc_11_0_0_mec.bin";
                case AMDGPU_UCODE_GFX_RLC: return "gc_11_0_0_rlc.bin";
                case AMDGPU_UCODE_GFX_IMU: return "gc_11_0_0_imu.bin";
                case AMDGPU_UCODE_GFX_MES: return "gc_11_0_0_mes_2.bin";
                case AMDGPU_UCODE_SDMA:    return "sdma_6_0_0.bin";
                default: return NULL;
            }
        case AMDGPU_FAMILY_RDNA2:
            switch (id) {
                case AMDGPU_UCODE_DMCUB:   return "sienna_cichlid_dmcub.bin";
                case AMDGPU_UCODE_PSP_SOS: return "sienna_cichlid_sos.bin";
                case AMDGPU_UCODE_PSP_TA:  return "sienna_cichlid_ta.bin";
                case AMDGPU_UCODE_SMU:     return "sienna_cichlid_smc.bin";
                case AMDGPU_UCODE_GFX_PFP: return "sienna_cichlid_pfp.bin";
                case AMDGPU_UCODE_GFX_ME:  return "sienna_cichlid_me.bin";
                case AMDGPU_UCODE_GFX_MEC: return "sienna_cichlid_mec.bin";
                case AMDGPU_UCODE_GFX_RLC: return "sienna_cichlid_rlc.bin";
                case AMDGPU_UCODE_SDMA:    return "sienna_cichlid_sdma.bin";
                default: return NULL;
            }
        default:
            return NULL;
    }
}

int amdgpu_ucode_load_all(struct amdgpu_device *adev) {
    if (!adev || !adev->io.load_fw) {
        return -EINVAL;
    }
    adev->ucode_loaded_count = 0;
    for (u32 i = 0; i < AMDGPU_UCODE_MAX; i++) {
        const char *fname = amdgpu_ucode_filename(adev, (enum amdgpu_ucode_id)i);
        if (!fname) {
            continue;
        }
        const u8 *data = NULL;
        size_t size = 0;
        const void *handle = NULL;
        int rc = adev->io.load_fw(adev->io.ctx, fname, &data, &size, &handle);
        if (rc != 0 || !data || size == 0) {
            continue;
        }
        struct amdgpu_ucode_info info;
        if (amdgpu_ucode_validate_blob(data, size, &info) != 0) {
            if (adev->io.release_fw && handle) {
                adev->io.release_fw(adev->io.ctx, handle);
            }
            continue;
        }
        info.fw_handle = handle;
        adev->ucodes[i] = info;
        adev->ucode_loaded_count++;
    }
    return adev->ucode_loaded_count > 0 ? 0 : -ENOENT;
}

void amdgpu_ucode_release_all(struct amdgpu_device *adev) {
    if (!adev) {
        return;
    }
    for (u32 i = 0; i < AMDGPU_UCODE_MAX; i++) {
        if (adev->ucodes[i].loaded && adev->ucodes[i].fw_handle && adev->io.release_fw) {
            adev->io.release_fw(adev->io.ctx, adev->ucodes[i].fw_handle);
        }
        memset(&adev->ucodes[i], 0, sizeof(adev->ucodes[i]));
    }
    adev->ucode_loaded_count = 0;
}
