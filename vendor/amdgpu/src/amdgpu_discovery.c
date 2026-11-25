#include <amdgpu_hw.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>

/* Indirect VRAM access registers (BAR5 MMIO byte offsets). */
#define MM_INDEX_OFF           0x0000u
#define MM_DATA_OFF            0x0004u
#define MM_INDEX_HI_OFF        0x0018u
#define MM_INDEX_VRAM_BIT      0x80000000u

/* NBIF RCC_CONFIG_MEMSIZE candidates (dword * 4). */
#define RCC_CONFIG_MEMSIZE_A   (0x0DE3u * 4u)
#define RCC_CONFIG_MEMSIZE_B   (0x0DC3u * 4u)

static u16 rd16(const u8 *b, size_t off) {
    return (u16)b[off] | ((u16)b[off + 1] << 8);
}

static u32 rd32(const u8 *b, size_t off) {
    return (u32)b[off]
        | ((u32)b[off + 1] << 8)
        | ((u32)b[off + 2] << 16)
        | ((u32)b[off + 3] << 24);
}

static u64 rd64(const u8 *b, size_t off) {
    return (u64)rd32(b, off) | ((u64)rd32(b, off + 4) << 32);
}

static u16 byte_sum16(const u8 *b, size_t len) {
    u32 sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += (u32)b[i];
    }
    return (u16)(sum & 0xFFFFu);
}

int amdgpu_discovery_parse(const u8 *buf, size_t len, struct amdgpu_discovery_info *out) {
    if (!buf || !out || len < 72u) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));

    u32 sig = rd32(buf, 0);
    if (sig != AMDGPU_BINARY_SIGNATURE) {
        return -EINVAL;
    }
    u16 bin_maj = rd16(buf, 4);
    u16 bin_min = rd16(buf, 6);
    u16 bin_csum = rd16(buf, 8);
    u16 bin_size = rd16(buf, 10);
    if (bin_size < 72u || (size_t)bin_size > len) {
        return -ERANGE;
    }

    /* Checksum covers binary_header starting immediately after binary_checksum (byte offset 10). */
    u16 calc_bin = byte_sum16(buf + 10, (size_t)bin_size - 10u);
    if (calc_bin != bin_csum) {
        return -EIO;
    }

    /* Locate table_list offset (v1 starts at byte 12; v2 has u16 num_tables + u16 pad at 12..16). */
    size_t tbl_list_off = (bin_maj >= 2u) ? 16u : 12u;
    u32 num_tables = (bin_maj >= 2u) ? (u32)rd16(buf, 12) : 7u;
    if (num_tables == 0 || num_tables > 16u || tbl_list_off + (size_t)num_tables * 8u > (size_t)bin_size) {
        return -EINVAL;
    }

    /* Table 0 = IP_DISCOVERY. */
    u16 ip_off = rd16(buf, tbl_list_off + 0);
    u16 ip_csum = rd16(buf, tbl_list_off + 2);
    u16 ip_size = rd16(buf, tbl_list_off + 4);
    if (ip_size < 80u || (size_t)ip_off + (size_t)ip_size > (size_t)bin_size) {
        return -ERANGE;
    }
    if (byte_sum16(buf + ip_off, ip_size) != ip_csum) {
        return -EIO;
    }

    const u8 *ip_hdr = buf + ip_off;
    if (rd32(ip_hdr, 0) != AMDGPU_IP_DISCOVERY_SIGNATURE) {
        return -EINVAL;
    }
    u16 ip_ver = rd16(ip_hdr, 4);
    u16 num_dies = rd16(ip_hdr, 12);
    if (num_dies == 0 || num_dies > 16u) {
        return -EINVAL;
    }
    /* Gate base_addr_64_bit strictly on ip_discovery_header version >= 4 (matches upstream discovery.h). */
    bool addr64 = (ip_ver >= 4u) && ((ip_hdr[78] & 0x01u) != 0);

    out->binary_major = bin_maj;
    out->binary_minor = bin_min;
    out->ip_table_version = ip_ver;
    out->base_addr_64_bit = addr64;

    size_t bin_end = (size_t)bin_size;
    for (u16 d = 0; d < num_dies; d++) {
        size_t di_off = 14u + (size_t)d * 4u;
        if (di_off + 4u > (size_t)ip_size) {
            break;
        }
        u16 die_off = rd16(ip_hdr, di_off + 2);
        /* In AMD IP Discovery binaries, die_info[d].die_offset is relative to binary start (`buf`). */
        size_t pos = (size_t)die_off;
        if (pos + 4u > bin_end) {
            continue;
        }
        u16 num_ips = rd16(buf, pos + 2);
        pos += 4u;
        for (u16 i = 0; i < num_ips && i < 256u; i++) {
            if (pos + 8u > bin_end) {
                break;
            }
            u16 hw_id = rd16(buf, pos + 0);
            u8 inst = buf[pos + 2];
            u8 nbases = buf[pos + 3];
            u8 maj = buf[pos + 4];
            u8 min = buf[pos + 5];
            u8 rev = buf[pos + 6];
            pos += 8u;

            size_t elem_sz = addr64 ? 8u : 4u;
            size_t base_bytes = (size_t)nbases * elem_sz;
            if (pos + base_bytes > bin_end) {
                break;
            }

            if (out->block_count < AMDGPU_MAX_IP_BLOCKS) {
                struct amdgpu_ip_block *blk = &out->blocks[out->block_count++];
                blk->hw_id = hw_id;
                blk->instance = inst;
                blk->major = maj;
                blk->minor = min;
                blk->revision = rev;
                blk->num_bases = nbases > AMDGPU_MAX_IP_SEGMENTS ? (u8)AMDGPU_MAX_IP_SEGMENTS : nbases;
                for (u8 b = 0; b < blk->num_bases; b++) {
                    if (addr64) {
                        u64 raw64 = rd64(buf, pos + (size_t)b * 8u);
                        blk->base_addr[b] = (u32)(raw64 & 0x3FFFFFFFULL);
                    } else {
                        blk->base_addr[b] = rd32(buf, pos + (size_t)b * 4u);
                    }
                }
            }
            pos += base_bytes;
        }
    }

    /* Optional Table 1 = GC_INFO. */
    if (num_tables > 1u) {
        u16 gc_off = rd16(buf, tbl_list_off + 8u);
        u16 gc_csum = rd16(buf, tbl_list_off + 10u);
        u16 gc_size = rd16(buf, tbl_list_off + 12u);
        if (gc_size >= 64u && (size_t)gc_off + (size_t)gc_size <= (size_t)bin_size
            && byte_sum16(buf + gc_off, gc_size) == gc_csum
            && (rd32(buf, gc_off) & 0xFFFFu) == AMDGPU_GC_TABLE_ID) {
            out->gc.valid = true;
            out->gc.num_se = rd32(buf, (size_t)gc_off + 12u);
            out->gc.num_wgp0_per_sa = rd32(buf, (size_t)gc_off + 16u);
            out->gc.num_wgp1_per_sa = rd32(buf, (size_t)gc_off + 20u);
            out->gc.num_rb_per_se = rd32(buf, (size_t)gc_off + 24u);
            out->gc.wave_size = rd32(buf, (size_t)gc_off + 52u);
            out->gc.lds_size = rd32(buf, (size_t)gc_off + 64u < (size_t)gc_size ? (size_t)gc_off + 64u : (size_t)gc_off + 56u);
        }
    }

    /* Optional Table 6 = MEM_RESERVED_INFO (32-byte gpu_info_header + 16-byte (offset, size) entries). */
    if (num_tables > 6u) {
        u16 mr_off = rd16(buf, tbl_list_off + 6u * 8u);
        u16 mr_csum = rd16(buf, tbl_list_off + 6u * 8u + 2u);
        u16 mr_size = rd16(buf, tbl_list_off + 6u * 8u + 4u);
        if (mr_size >= 32u && (size_t)mr_off + (size_t)mr_size <= (size_t)bin_size
            && byte_sum16(buf + mr_off, mr_size) == mr_csum) {
            size_t roff = (size_t)mr_off + 32u;
            size_t rend = (size_t)mr_off + (size_t)mr_size;
            while (roff + 16u <= rend && out->reserved_count < AMDGPU_MAX_MEM_RESERVED) {
                u64 r_start = rd64(buf, roff);
                u64 r_len = rd64(buf, roff + 8u);
                if (r_len > 0) {
                    out->reserved[out->reserved_count].offset = r_start;
                    out->reserved[out->reserved_count].size = r_len;
                    out->reserved[out->reserved_count].type = 0;
                    out->reserved_count++;
                }
                roff += 16u;
            }
        }
    }

    out->valid = (out->block_count > 0);
    return out->valid ? 0 : -ENOENT;
}

static void read_vram_indirect(struct amdgpu_device *adev, u64 vram_off, u8 *dst, size_t len) {
    for (size_t i = 0; i + 4u <= len; i += 4u) {
        u64 addr = vram_off + (u64)i;
        /* MM_INDEX holds VRAM byte address bits [30:0] with bit 31 selecting VRAM space; MM_INDEX_HI holds addr >> 31. */
        u32 lo = ((u32)addr & 0x7FFFFFFCu) | MM_INDEX_VRAM_BIT;
        u32 hi = (u32)(addr >> 31);
        amdgpu_wreg32(adev, MM_INDEX_OFF, lo);
        amdgpu_wreg32(adev, MM_INDEX_HI_OFF, hi);
        u32 val = amdgpu_rreg32(adev, MM_DATA_OFF);
        dst[i + 0] = (u8)(val & 0xFFu);
        dst[i + 1] = (u8)((val >> 8) & 0xFFu);
        dst[i + 2] = (u8)((val >> 16) & 0xFFu);
        dst[i + 3] = (u8)((val >> 24) & 0xFFu);
    }
}

static void push_candidate(u64 *list, u32 *cnt, u64 bytes) {
    if (bytes < (16ULL << 20) || bytes > (256ULL << 30)) {
        return;
    }
    for (u32 i = 0; i < *cnt; i++) {
        if (list[i] == bytes) {
            return;
        }
    }
    if (*cnt < 8u) {
        list[(*cnt)++] = bytes;
    }
}

int amdgpu_discovery_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    u64 cands[8];
    u32 ncand = 0;

    u32 mem_a = amdgpu_rreg32(adev, RCC_CONFIG_MEMSIZE_A);
    if (mem_a > 0 && mem_a != 0xFFFFFFFFu) {
        push_candidate(cands, &ncand, (u64)mem_a << 20);
    }
    u32 mem_b = amdgpu_rreg32(adev, RCC_CONFIG_MEMSIZE_B);
    if (mem_b > 0 && mem_b != 0xFFFFFFFFu) {
        push_candidate(cands, &ncand, (u64)mem_b << 20);
    }
    if (adev->bar_sizes[0] >= (16ULL << 20)) {
        push_candidate(cands, &ncand, adev->bar_sizes[0]);
    }
    if (ncand == 0) {
        return -ENODEV;
    }

    u8 *buf = (u8 *)kzalloc(AMDGPU_DISCOVERY_TMR_SIZE, GFP_KERNEL);
    if (!buf) {
        return -ENOMEM;
    }

    int rc = -ENOENT;
    for (u32 i = 0; i < ncand; i++) {
        u64 vram_sz = cands[i];
        u64 tmr_off = vram_sz - AMDGPU_DISCOVERY_TMR_OFFSET;

        /* Fast path: read directly from BAR0 VRAM if mapped/accessible. */
        bool read_ok = false;
        if (adev->io.vram_read && vram_sz <= adev->bar_sizes[0]) {
            if (adev->io.vram_read(adev->io.ctx, tmr_off, buf, AMDGPU_DISCOVERY_TMR_SIZE) == 0) {
                read_ok = (rd32(buf, 0) == AMDGPU_BINARY_SIGNATURE);
            }
        }
        /* Fallback: indirect MM_INDEX/MM_INDEX_HI/MM_DATA access (handles non-ReBAR 256 MiB BAR0). */
        if (!read_ok) {
            read_vram_indirect(adev, tmr_off, buf, 256u);
            if (rd32(buf, 0) == AMDGPU_BINARY_SIGNATURE) {
                u32 bsz = rd16(buf, 10);
                size_t to_read = (bsz >= 72u && bsz <= AMDGPU_DISCOVERY_TMR_SIZE)
                    ? (((size_t)bsz + 3u) & ~3u)
                    : AMDGPU_DISCOVERY_TMR_SIZE;
                if (to_read > 256u) {
                    read_vram_indirect(adev, tmr_off + 256u, buf + 256u, to_read - 256u);
                }
                read_ok = true;
            }
        }
        if (read_ok && amdgpu_discovery_parse(buf, AMDGPU_DISCOVERY_TMR_SIZE, &adev->discovery) == 0) {
            adev->discovery.vram_size_bytes = vram_sz;
            rc = 0;
            break;
        }
    }

    kfree(buf);
    if (rc == 0) {
        const struct amdgpu_ip_block *dce = amdgpu_discovery_find_ip(&adev->discovery, AMDGPU_HWID_DCE, 0);
        if (dce) {
            if (dce->major == 4u) {
                adev->dcn_version = DC_DCN_4_0_1;
            } else if (dce->major == 3u && dce->minor == 1u) {
                adev->dcn_version = DC_DCN_3_1_5;
            } else if (dce->major == 3u && (dce->minor == 2u || dce->minor == 5u)) {
                adev->dcn_version = DC_DCN_3_2;
            } else if (dce->major == 3u && dce->minor == 0u) {
                adev->dcn_version = DC_DCN_3_0;
            }
        }
    }
    return rc;
}

const struct amdgpu_ip_block *amdgpu_discovery_find_ip(
    const struct amdgpu_discovery_info *disc,
    u16 hw_id,
    u8 instance
) {
    if (!disc || !disc->valid) {
        return NULL;
    }
    const struct amdgpu_ip_block *first = NULL;
    for (u32 i = 0; i < disc->block_count; i++) {
        if (disc->blocks[i].hw_id == hw_id) {
            if (disc->blocks[i].instance == instance) {
                return &disc->blocks[i];
            }
            if (!first && instance == 0) {
                first = &disc->blocks[i];
            }
        }
    }
    return first;
}

bool amdgpu_discovery_reg_offset(
    const struct amdgpu_discovery_info *disc,
    u16 hw_id,
    u8 instance,
    u8 base_idx,
    u32 reg_dword_off,
    u64 *out_byte_off
) {
    if (!out_byte_off) {
        return false;
    }
    const struct amdgpu_ip_block *blk = amdgpu_discovery_find_ip(disc, hw_id, instance);
    if (!blk || base_idx >= blk->num_bases) {
        return false;
    }
    u64 dword_addr = (u64)blk->base_addr[base_idx] + (u64)reg_dword_off;
    *out_byte_off = dword_addr * 4ULL;
    return true;
}
