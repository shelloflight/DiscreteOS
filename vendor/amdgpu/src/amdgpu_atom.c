#include <amdgpu_hw.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>

static u16 rd16(const u8 *p, size_t off) {
    return (u16)p[off] | ((u16)p[off + 1] << 8);
}

static u32 rd32(const u8 *p, size_t off) {
    return (u32)p[off]
        | ((u32)p[off + 1] << 8)
        | ((u32)p[off + 2] << 16)
        | ((u32)p[off + 3] << 24);
}

int amdgpu_atom_parse(const u8 *rom, size_t len, struct amdgpu_atom_info *out) {
    if (!rom || !out || len < 0x80u || len > AMDGPU_ATOM_ROM_MAX_SIZE) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));
    if (rom[0] != 0x55u || rom[1] != 0xAAu) {
        return -EINVAL;
    }
    u16 hdr_off = rd16(rom, 0x48u);
    if (hdr_off < 0x4Au || (size_t)hdr_off + 36u > len) {
        return -ERANGE;
    }
    /* Signature "ATOM" sits at hdr_off + 4 (matches atom_rom_header_v2_2). */
    if (memcmp(rom + hdr_off + 4u, "ATOM", 4u) != 0) {
        return -EINVAL;
    }

    out->major_rev = rom[hdr_off + 2u];
    out->minor_rev = rom[hdr_off + 3u];
    u16 master_data_off = rd16(rom, (size_t)hdr_off + 32u);
    u16 master_cmd_off = rd16(rom, (size_t)hdr_off + 30u);
    out->rom_size = (u32)len;
    out->rom_ptr = rom;

    /* Parse master data table directory (v2.1+). */
    if (master_data_off >= 4u && (size_t)master_data_off + 8u <= len) {
        u16 dt_sz = rd16(rom, master_data_off);
        if (dt_sz >= 8u && (size_t)master_data_off + (size_t)dt_sz <= len) {
            u32 entries = ((u32)dt_sz - 4u) / 4u;
            if (entries > AMDGPU_ATOM_MAX_DATA_TABLES) {
                entries = AMDGPU_ATOM_MAX_DATA_TABLES;
            }
            for (u32 i = 0; i < entries; i++) {
                u32 off = rd32(rom, (size_t)master_data_off + 4u + (size_t)i * 4u);
                if (off < len) {
                    out->data_table_offsets[i] = (u16)off;
                }
            }
        }
    }

    /* Parse master command table directory. */
    if (master_cmd_off >= 4u && (size_t)master_cmd_off + 8u <= len) {
        u16 ct_sz = rd16(rom, master_cmd_off);
        if (ct_sz >= 8u && (size_t)master_cmd_off + (size_t)ct_sz <= len) {
            u32 entries = ((u32)ct_sz - 4u) / 2u;
            if (entries > AMDGPU_ATOM_MAX_CMD_TABLES) {
                entries = AMDGPU_ATOM_MAX_CMD_TABLES;
            }
            for (u32 i = 0; i < entries; i++) {
                u16 off = rd16(rom, (size_t)master_cmd_off + 4u + (size_t)i * 2u);
                if (off < len) {
                    out->cmd_table_offsets[i] = off;
                }
            }
        }
    }

    /* Table index 1 = firmwareinfo (atom_firmware_info_v3_1..v3_4). */
    u16 fw_off = out->data_table_offsets[1];
    if (fw_off >= 4u && (size_t)fw_off + 36u <= len) {
        out->bootup_sclk_10khz = rd32(rom, (size_t)fw_off + 8u);
        out->bootup_mclk_10khz = rd32(rom, (size_t)fw_off + 12u);
        out->core_refclk_10khz = rd32(rom, (size_t)fw_off + 16u);
        out->display_refclk_10khz = rd32(rom, (size_t)fw_off + 20u);
        out->max_pixel_clock_10khz = rd32(rom, (size_t)fw_off + 24u);
    }
    if (out->core_refclk_10khz == 0) {
        out->core_refclk_10khz = 10000u; /* 100 MHz standard RDNA refclk */
    }
    if (out->display_refclk_10khz == 0) {
        out->display_refclk_10khz = 10000u;
    }

    /* Table index 2 = displayobjectinfo (atom_display_object_path_v2 list). */
    u16 disp_off = out->data_table_offsets[2];
    if (disp_off >= 4u && (size_t)disp_off + 8u <= len) {
        u16 path_cnt = rd16(rom, (size_t)disp_off + 4u);
        if (path_cnt > AMDGPU_ATOM_MAX_DISPLAY_PATHS) {
            path_cnt = AMDGPU_ATOM_MAX_DISPLAY_PATHS;
        }
        for (u16 i = 0; i < path_cnt; i++) {
            size_t poff = (size_t)disp_off + 8u + (size_t)i * 8u;
            if (poff + 8u > len) {
                break;
            }
            struct amdgpu_atom_display_path *dp = &out->paths[out->path_count++];
            dp->connector_type = rom[poff + 0u];
            dp->connector_index = rom[poff + 1u];
            dp->dig_id = rom[poff + 2u];
            dp->aux_id = rom[poff + 3u];
            dp->hpd_id = rom[poff + 4u];
            dp->ddc_id = rom[poff + 5u];
        }
    }

    /* Table index 3 = integratedsysteminfo (APU UMA clock/channel metadata). */
    u16 igp_off = out->data_table_offsets[3];
    if (igp_off >= 4u && (size_t)igp_off + 16u <= len) {
        out->uma_channel_count = rd32(rom, (size_t)igp_off + 8u);
        out->uma_mem_type = rd32(rom, (size_t)igp_off + 12u);
    }

    out->valid = true;
    return 0;
}

int amdgpu_atom_init(struct amdgpu_device *adev) {
    if (!adev) {
        return -EINVAL;
    }
    /* UEFI/VBIOS leaves a copy of the AtomBIOS ROM at VRAM offset 0 on AMD GPUs. */
    if (!adev->io.vram_read) {
        return -ENOENT;
    }
    const size_t probe_len = 64u * 1024u;
    u8 *rom = (u8 *)kzalloc(probe_len, GFP_KERNEL);
    if (!rom) {
        return -ENOMEM;
    }
    int rc = -ENOENT;
    if (adev->io.vram_read(adev->io.ctx, 0, rom, probe_len) == 0) {
        rc = amdgpu_atom_parse(rom, probe_len, &adev->atom);
    }
    /* `rom_ptr` is not kept past free on probe copy. */
    adev->atom.rom_ptr = NULL;
    kfree(rom);
    return rc;
}

int amdgpu_atom_execute_table(
    struct amdgpu_device *adev,
    const u8 *bytecode,
    size_t len,
    u32 *params,
    u32 param_count
) {
    if (!adev || !bytecode || len == 0 || len > 16384u) {
        return -EINVAL;
    }
    u32 regs[16];
    memset(regs, 0, sizeof(regs));
    if (params && param_count > 0) {
        u32 n = param_count > 16u ? 16u : param_count;
        for (u32 i = 0; i < n; i++) {
            regs[i] = params[i];
        }
    }

    size_t pc = 0;
    bool cmp_eq = false;
    u32 steps = 0;
    const u32 max_steps = 4096u;

    while (pc < len && steps < max_steps) {
        u8 op = bytecode[pc++];
        steps++;
        switch (op) {
            case ATOM_OP_NOP:
                break;
            case ATOM_OP_EOT:
                if (params && param_count > 0) {
                    u32 n = param_count > 16u ? 16u : param_count;
                    for (u32 i = 0; i < n; i++) {
                        params[i] = regs[i];
                    }
                }
                return 0;
            case ATOM_OP_MOVE_REG:
                if (pc + 5u > len) return -ERANGE;
                regs[bytecode[pc] & 0x0Fu] = rd32(bytecode, pc + 1u);
                pc += 5u;
                break;
            case ATOM_OP_AND_REG:
                if (pc + 5u > len) return -ERANGE;
                regs[bytecode[pc] & 0x0Fu] &= rd32(bytecode, pc + 1u);
                pc += 5u;
                break;
            case ATOM_OP_OR_REG:
                if (pc + 5u > len) return -ERANGE;
                regs[bytecode[pc] & 0x0Fu] |= rd32(bytecode, pc + 1u);
                pc += 5u;
                break;
            case ATOM_OP_SHL_REG:
                if (pc + 2u > len) return -ERANGE;
                regs[bytecode[pc] & 0x0Fu] <<= (bytecode[pc + 1u] & 31u);
                pc += 2u;
                break;
            case ATOM_OP_SHR_REG:
                if (pc + 2u > len) return -ERANGE;
                regs[bytecode[pc] & 0x0Fu] >>= (bytecode[pc + 1u] & 31u);
                pc += 2u;
                break;
            case ATOM_OP_ADD_REG:
                if (pc + 2u > len) return -ERANGE;
                regs[bytecode[pc] & 0x0Fu] += regs[bytecode[pc + 1u] & 0x0Fu];
                pc += 2u;
                break;
            case ATOM_OP_SUB_REG:
                if (pc + 2u > len) return -ERANGE;
                regs[bytecode[pc] & 0x0Fu] -= regs[bytecode[pc + 1u] & 0x0Fu];
                pc += 2u;
                break;
            case ATOM_OP_CMP_REG:
                if (pc + 5u > len) return -ERANGE;
                cmp_eq = (regs[bytecode[pc] & 0x0Fu] == rd32(bytecode, pc + 1u));
                pc += 5u;
                break;
            case ATOM_OP_JMP:
            case ATOM_OP_JMP_EQ:
            case ATOM_OP_JMP_NE: {
                if (pc + 2u > len) return -ERANGE;
                u16 target = rd16(bytecode, pc);
                pc += 2u;
                bool take = (op == ATOM_OP_JMP) || (op == ATOM_OP_JMP_EQ && cmp_eq) || (op == ATOM_OP_JMP_NE && !cmp_eq);
                if (take) {
                    if ((size_t)target >= len) return -ERANGE;
                    pc = (size_t)target;
                }
                break;
            }
            case ATOM_OP_DELAY_US:
                if (pc + 4u > len) return -ERANGE;
                amdgpu_udelay(adev, rd32(bytecode, pc) > 50000u ? 50000u : rd32(bytecode, pc));
                pc += 4u;
                break;
            case ATOM_OP_MMIO_READ: {
                if (pc + 5u > len) return -ERANGE;
                u8 dst = bytecode[pc] & 0x0Fu;
                u32 reg_byte = rd32(bytecode, pc + 1u);
                pc += 5u;
                if ((reg_byte & 3u) != 0) return -EINVAL;
                regs[dst] = amdgpu_rreg32(adev, (u64)reg_byte);
                break;
            }
            case ATOM_OP_MMIO_WRITE: {
                if (pc + 5u > len) return -ERANGE;
                u8 src = bytecode[pc] & 0x0Fu;
                u32 reg_byte = rd32(bytecode, pc + 1u);
                pc += 5u;
                if ((reg_byte & 3u) != 0) return -EINVAL;
                amdgpu_wreg32(adev, (u64)reg_byte, regs[src]);
                break;
            }
            default:
                return -EINVAL;
        }
    }
    return -ETIMEDOUT;
}
