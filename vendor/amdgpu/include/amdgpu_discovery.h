#ifndef _AMDGPU_DISCOVERY_H
#define _AMDGPU_DISCOVERY_H

#include <linux/types.h>

/* AMD IP Discovery binary table constants & HWIDs (matching upstream discovery.h). */
#define AMDGPU_DISCOVERY_TMR_SIZE          (64u * 1024u)
#define AMDGPU_DISCOVERY_TMR_OFFSET        (64u * 1024u)
#define AMDGPU_BINARY_SIGNATURE            0x28211407u
#define AMDGPU_IP_DISCOVERY_SIGNATURE      0x53445049u /* "IPDS" */
#define AMDGPU_MEM_RSV_SIGNATURE           0x0049524Du /* "MRI"  */
#define AMDGPU_GC_TABLE_ID                 0x4347u

#define AMDGPU_MAX_IP_BLOCKS               128u
#define AMDGPU_MAX_IP_SEGMENTS             8u
#define AMDGPU_MAX_MEM_RESERVED            16u

/* Official AMD IP Hardware IDs (soc15_hw_ip.h). */
#define AMDGPU_HWID_MP1                    1u
#define AMDGPU_HWID_MP0                    255u
#define AMDGPU_HWID_THM                    3u
#define AMDGPU_HWID_SMUIO                  4u
#define AMDGPU_HWID_FUSE                   5u
#define AMDGPU_HWID_CLKA                   6u
#define AMDGPU_HWID_PWR                    10u
#define AMDGPU_HWID_GC                     11u
#define AMDGPU_HWID_UVD                    12u
#define AMDGPU_HWID_VCN                    12u
#define AMDGPU_HWID_AUDIO_AZ               13u
#define AMDGPU_HWID_ACP                    14u
#define AMDGPU_HWID_DCI                    15u
#define AMDGPU_HWID_RSMU                   17u
#define AMDGPU_HWID_MMHUB                  34u
#define AMDGPU_HWID_ATHUB                  35u
#define AMDGPU_HWID_OSSSYS                 40u
#define AMDGPU_HWID_HDP                    41u
#define AMDGPU_HWID_SDMA0                  42u
#define AMDGPU_HWID_SDMA1                  43u
#define AMDGPU_HWID_NBIO                   108u /* NBIF_HWID */
#define AMDGPU_HWID_DMU                    271u /* DMU_HWID (DCN display engine) */
#define AMDGPU_HWID_DCE                    271u
#define AMDGPU_HWID_DIO                    272u

struct amdgpu_ip_block {
    u16 hw_id;
    u8 instance;
    u8 major;
    u8 minor;
    u8 revision;
    u8 num_bases;
    u32 base_addr[AMDGPU_MAX_IP_SEGMENTS]; /* dword MMIO offsets */
};

struct amdgpu_reserved_region {
    u64 offset;
    u64 size;
    u32 type;
};

struct amdgpu_gc_info {
    bool valid;
    u32 num_se;
    u32 num_sa_per_se;
    u32 num_wgp0_per_sa;
    u32 num_wgp1_per_sa;
    u32 num_rb_per_se;
    u32 wave_size;
    u32 lds_size;
};

struct amdgpu_discovery_info {
    bool valid;
    u16 binary_major;
    u16 binary_minor;
    u16 ip_table_version;
    bool base_addr_64_bit;
    u32 block_count;
    struct amdgpu_ip_block blocks[AMDGPU_MAX_IP_BLOCKS];
    u32 reserved_count;
    struct amdgpu_reserved_region reserved[AMDGPU_MAX_MEM_RESERVED];
    struct amdgpu_gc_info gc;
    u64 vram_size_bytes;
};

struct amdgpu_device;

/* Parse a raw IP Discovery binary image (up to 64 KiB) with strict checksum & bounds checks. */
int amdgpu_discovery_parse(const u8 *buf, size_t len, struct amdgpu_discovery_info *out);

/* Read IP Discovery from VRAM top (direct BAR0 fast path with indirect MM_INDEX fallback). */
int amdgpu_discovery_init(struct amdgpu_device *adev);

/* Look up an IP block by HWID and instance number. */
const struct amdgpu_ip_block *amdgpu_discovery_find_ip(
    const struct amdgpu_discovery_info *disc,
    u16 hw_id,
    u8 instance
);

/* Compute the MMIO byte offset for (hw_id, instance, base_idx, dword_off). */
bool amdgpu_discovery_reg_offset(
    const struct amdgpu_discovery_info *disc,
    u16 hw_id,
    u8 instance,
    u8 base_idx,
    u32 reg_dword_off,
    u64 *out_byte_off
);

#endif
