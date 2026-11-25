#ifndef _AMDGPU_UCODE_H
#define _AMDGPU_UCODE_H

#include <linux/types.h>

/* Exact upstream AMD firmware binary header structures (MIT). */

struct amdgpu_common_fw_hdr {
    u32 size_bytes;
    u32 header_size_bytes;
    u16 header_version_major;
    u16 header_version_minor;
    u16 ip_version_major;
    u16 ip_version_minor;
    u32 ucode_version;
    u32 ucode_size_bytes;
    u32 ucode_array_offset_bytes;
    u32 crc32;
};

struct amdgpu_dmcub_fw_hdr_v1_0 {
    struct amdgpu_common_fw_hdr header;
    u32 inst_const_bytes;
    u32 bss_data_bytes;
};

struct amdgpu_smc_fw_hdr_v1_0 {
    struct amdgpu_common_fw_hdr header;
    u32 ucode_start_addr;
};

struct amdgpu_smc_fw_hdr_v2_0 {
    struct amdgpu_smc_fw_hdr_v1_0 v1_0;
    u32 ppt_offset_bytes;
    u32 ppt_size_bytes;
};

struct amdgpu_psp_fw_bin_desc {
    u32 fw_type;
    u32 fw_version;
    u32 offset_bytes;
    u32 size_bytes;
};

struct amdgpu_psp_fw_hdr_v2_0 {
    struct amdgpu_common_fw_hdr header;
    u32 psp_fw_bin_count;
};

struct amdgpu_gfx_fw_hdr_v2_0 {
    struct amdgpu_common_fw_hdr header;
    u32 ucode_feature_version;
    u32 ucode_size_bytes;
    u32 ucode_offset_bytes;
    u32 data_size_bytes;
    u32 data_offset_bytes;
    u32 ucode_start_addr_lo;
    u32 ucode_start_addr_hi;
};

struct amdgpu_mes_fw_hdr_v1_0 {
    struct amdgpu_common_fw_hdr header;
    u32 mes_ucode_version;
    u32 mes_ucode_size_bytes;
    u32 mes_ucode_offset_bytes;
    u32 mes_ucode_data_version;
    u32 mes_ucode_data_size_bytes;
    u32 mes_ucode_data_offset_bytes;
    u32 mes_uc_start_addr_lo;
    u32 mes_uc_start_addr_hi;
    u32 mes_data_start_addr_lo;
    u32 mes_data_start_addr_hi;
};

enum amdgpu_ucode_id {
    AMDGPU_UCODE_DMCUB = 0,
    AMDGPU_UCODE_PSP_SOS = 1,
    AMDGPU_UCODE_PSP_TA = 2,
    AMDGPU_UCODE_PSP_TOC = 3,
    AMDGPU_UCODE_SMU = 4,
    AMDGPU_UCODE_GFX_PFP = 5,
    AMDGPU_UCODE_GFX_ME = 6,
    AMDGPU_UCODE_GFX_MEC = 7,
    AMDGPU_UCODE_GFX_RLC = 8,
    AMDGPU_UCODE_GFX_IMU = 9,
    AMDGPU_UCODE_GFX_MES = 10,
    AMDGPU_UCODE_SDMA = 11,
    AMDGPU_UCODE_MAX = 12,
};

struct amdgpu_ucode_info {
    bool loaded;
    u16 hdr_major;
    u16 hdr_minor;
    u16 ip_major;
    u16 ip_minor;
    u32 ucode_version;
    u32 payload_offset;
    u32 payload_size;
    u32 total_size;
    u32 inst_const_bytes;
    u32 bss_data_bytes;
    u32 sub_bin_count;
    const void *fw_handle;
    const u8 *raw_data;
};

struct amdgpu_device;

/* Strict bounds & header validation of an AMD firmware binary buffer. */
int amdgpu_ucode_validate_blob(const u8 *data, size_t len, struct amdgpu_ucode_info *out);

/* Resolve the official sys:/firmware/amdgpu/<file>.bin name for this ASIC & ucode slot. */
const char *amdgpu_ucode_filename(const struct amdgpu_device *adev, enum amdgpu_ucode_id id);

/* Load and validate all available firmware blobs for this ASIC from sys:/firmware/amdgpu/. */
int amdgpu_ucode_load_all(struct amdgpu_device *adev);

/* Release all mapped firmware VMOs cleanly. */
void amdgpu_ucode_release_all(struct amdgpu_device *adev);

#endif
