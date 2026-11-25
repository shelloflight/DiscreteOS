#ifndef _AMDGPU_ATOM_H
#define _AMDGPU_ATOM_H

#include <linux/types.h>

#define AMDGPU_ATOM_ROM_MAX_SIZE           (256u * 1024u)
#define AMDGPU_ATOM_MAX_DISPLAY_PATHS      8u
#define AMDGPU_ATOM_MAX_CMD_TABLES         64u
#define AMDGPU_ATOM_MAX_DATA_TABLES        64u

/* AtomBIOS connector object types (matching upstream atomfirmware.h). */
#define ATOM_CONN_UNKNOWN                  0u
#define ATOM_CONN_DP                       19u
#define ATOM_CONN_HDMI_TYPE_A              12u
#define ATOM_CONN_EDP                      20u
#define ATOM_CONN_USB_TYPE_C               23u

/* AtomBIOS master command table indices. */
#define ATOM_CMD_ASIC_INIT                 0u
#define ATOM_CMD_SET_PIXEL_CLOCK           10u
#define ATOM_CMD_DIG1_ENCODER_CONTROL      12u
#define ATOM_CMD_DIG1_TRANSMITTER_CONTROL  13u

/* AtomBIOS bytecode opcodes supported by the freestanding command interpreter. */
#define ATOM_OP_NOP                        0x00u
#define ATOM_OP_MOVE_REG                   0x01u
#define ATOM_OP_AND_REG                    0x02u
#define ATOM_OP_OR_REG                     0x03u
#define ATOM_OP_SHL_REG                    0x04u
#define ATOM_OP_SHR_REG                    0x05u
#define ATOM_OP_ADD_REG                    0x06u
#define ATOM_OP_SUB_REG                    0x07u
#define ATOM_OP_CMP_REG                    0x08u
#define ATOM_OP_JMP                        0x09u
#define ATOM_OP_JMP_EQ                     0x0Au
#define ATOM_OP_JMP_NE                     0x0Bu
#define ATOM_OP_DELAY_US                   0x0Cu
#define ATOM_OP_MMIO_READ                  0x0Du
#define ATOM_OP_MMIO_WRITE                 0x0Eu
#define ATOM_OP_EOT                        0x5Bu

struct amdgpu_atom_display_path {
    u8 connector_type;
    u8 connector_index;
    u8 dig_id;
    u8 aux_id;
    u8 hpd_id;
    u8 ddc_id;
};

struct amdgpu_atom_info {
    bool valid;
    u8 major_rev;
    u8 minor_rev;
    u32 bootup_sclk_10khz;
    u32 bootup_mclk_10khz;
    u32 core_refclk_10khz;
    u32 display_refclk_10khz;
    u32 max_pixel_clock_10khz;
    u32 uma_channel_count;
    u32 uma_mem_type;
    u32 path_count;
    struct amdgpu_atom_display_path paths[AMDGPU_ATOM_MAX_DISPLAY_PATHS];
    u16 cmd_table_offsets[AMDGPU_ATOM_MAX_CMD_TABLES];
    u16 data_table_offsets[AMDGPU_ATOM_MAX_DATA_TABLES];
    u32 rom_size;
    const u8 *rom_ptr;
};

struct amdgpu_device;

/* Parse an AtomBIOS v2.1/v2.2 VBIOS ROM image safely. */
int amdgpu_atom_parse(const u8 *rom, size_t len, struct amdgpu_atom_info *out);

/* Probe VBIOS ROM from BAR0 VRAM offset 0 or PCI expansion ROM and parse tables. */
int amdgpu_atom_init(struct amdgpu_device *adev);

/* Execute an AtomBIOS command table bytecode stream with bounded instruction & MMIO safety. */
int amdgpu_atom_execute_table(
    struct amdgpu_device *adev,
    const u8 *bytecode,
    size_t len,
    u32 *params,
    u32 param_count
);

#endif
