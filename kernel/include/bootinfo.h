/*
 * BootInfo: handed from a bootloader to kmain in RDI. Two loaders fill it:
 *   BIOS: boot/stage2.asm (fill_bootinfo; stage1.asm writes tsc_stage1)
 *   UEFI: boot/uefi/loader.c (struct bootinfo there)
 * Layout MUST stay in sync with both. Reference: docs/boot.md.
 */
#ifndef DOS_BOOTINFO_H
#define DOS_BOOTINFO_H

#include <stdint.h>
#include "compiler.h"

#define BOOTINFO_MAGIC    0x424F5344u   /* "DSOB" in memory */
#define BOOTINFO_VERSION  5u
#define BOOTINFO_MMAP_MAX 256u

/* E820 memory types (unknown types must be treated as reserved). The UEFI loader converts the
 * UEFI memory map into these. */
enum {
    MMAP_USABLE           = 1,
    MMAP_RESERVED         = 2,
    MMAP_ACPI_RECLAIMABLE = 3,
    MMAP_ACPI_NVS         = 4,
    MMAP_BAD              = 5,
};

enum {
    BOOT_FW_BIOS = 1,
    BOOT_FW_UEFI = 2,
};

/* BootInfo.flags (v4) */
enum {
    BOOT_KERNEL_VERIFIED = 1u << 0,  /* the loader verified the kernel's .dsig (kernel_dsig) */
    BOOT_KERNEL_MEASURED = 1u << 1,  /* the loader measured it into the TPM (UEFI TCG2, PCR 8) */
    BOOT_FLAGS_KNOWN     = 3u,
};

/* BootInfo.kaslr_sources (v5) and kernel_layout.sources: where randomness came from. */
enum {
    KASLR_SRC_RDSEED  = 1u << 0,
    KASLR_SRC_RDRAND  = 1u << 1,
    KASLR_SRC_EFI_RNG = 1u << 2,     /* UEFI EFI_RNG_PROTOCOL */
    KASLR_SRC_TSC     = 1u << 3,     /* timing only: weak */
    KASLR_SRC_KNOWN   = 15u,
};

enum {
    BOOT_FB_NONE = 0,
    BOOT_FB_RGB32 = 1,          /* 32 bits per pixel; channel positions in fb_*_shift */
};

typedef struct PACKED {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t acpi_attrs;
} MemoryMapEntry;

typedef struct PACKED {
    uint32_t magic;          /* +0   BOOTINFO_MAGIC */
    uint32_t version;        /* +4   BOOTINFO_VERSION */
    uint32_t boot_drive;     /* +8   BIOS drive number (0 under UEFI) */
    uint32_t mmap_count;     /* +12 */
    uint64_t mmap_addr;      /* +16  physical address of MemoryMapEntry[mmap_count] */
    uint64_t kernel_phys;    /* +24 */
    uint64_t kernel_size;    /* +32  bytes loaded from disk (excludes .bss) */
    uint64_t tsc_stage1;     /* +40  TSC at the first loader instruction (stage 1 / efi_main) */
    /* v3 */
    uint32_t firmware;       /* +48  BOOT_FW_BIOS / BOOT_FW_UEFI */
    uint32_t flags;          /* +52  BOOT_KERNEL_* (v4) */
    uint64_t rsdp;           /* +56  physical address of the ACPI RSDP (0: scan the BIOS areas) */
    uint64_t efi_system_table; /* +64 physical address (UEFI), 0 under BIOS; boot services are gone */
    uint64_t fb_base;        /* +72  framebuffer (UEFI GOP), physical */
    uint64_t fb_size;        /* +80  bytes */
    uint32_t fb_width;       /* +88  pixels */
    uint32_t fb_height;      /* +92 */
    uint32_t fb_pitch;       /* +96  bytes per scan line */
    uint8_t  fb_type;        /* +100 BOOT_FB_* */
    uint8_t  fb_red_shift;   /* +101 bit position of each 8-bit channel in a pixel */
    uint8_t  fb_green_shift; /* +102 */
    uint8_t  fb_blue_shift;  /* +103 */
    uint64_t tsc_loader_exit; /* +104 TSC just before the jump to the kernel (UEFI: after ExitBootServices) */
    /* v4 */
    uint8_t  kernel_dsig[256]; /* +112 the kernel's verified .dsig (docs/signing.md), if BOOT_KERNEL_VERIFIED */
    /* v5: KASLR */
    uint64_t kernel_virt;    /* +368 virtual address the loader relocated and mapped the image at */
    uint32_t kaslr_sources;  /* +376 KASLR_SRC_* behind the loader's choice (never 0) */
    uint32_t reserved0;      /* +380 0 */
    uint8_t  seed[32];       /* +384 loader entropy for the kernel's own choices (wiped after use) */
} BootInfo;

_Static_assert(sizeof(MemoryMapEntry) == 24, "E820 entry layout");
_Static_assert(sizeof(BootInfo) == 416, "BootInfo layout must match stage2.asm and the UEFI loader");

/* UEFI loader step times (optional, not part of the BootInfo ABI): written by the UEFI loader in the
 * BootInfo page at BOOT_TIMING_OFFSET, after the BootInfo itself. The kernel copies it while the
 * page is still mapped and prints the steps in milliseconds (it knows the TSC frequency; the
 * loader does not). Ignored unless the magic matches and the stamps never go backwards. */
#define BOOT_TIMING_OFFSET 2048u
#define BOOT_TIMING_MAGIC  0x31454D4954534F44ull   /* "DOSTIME1" */
#define BOOT_TIMING_STEPS  12u
struct boot_timing_step {
    char     name[16];      /* NUL-terminated */
    uint64_t tsc;           /* TSC at the end of the step */
};
struct boot_timing {
    uint64_t magic;
    uint32_t count;
    uint32_t reserved;
    uint64_t console_cycles; /* time spent in firmware text output (part of the steps) */
    struct boot_timing_step step[BOOT_TIMING_STEPS];
};
_Static_assert(sizeof(struct boot_timing) == 24 + 24 * BOOT_TIMING_STEPS, "boot timing layout");
_Static_assert(BOOT_TIMING_OFFSET >= 416 && BOOT_TIMING_OFFSET + sizeof(struct boot_timing) <= 4096,
               "boot timing fits in the BootInfo page after the BootInfo");


/* Kernel image header: the first bytes of kernel.bin (kernel/arch/x86_64/entry.asm, section
 * .boothdr). Both loaders read the entry point, sizes and relocation table from it. All values are
 * link-time values (the header itself is never relocated). */
#define KHDR_MAGIC   0x4E524B44u        /* "DKRN" */
#define KHDR_VERSION 2u
struct PACKED kernel_header {
    uint32_t magic;          /* +0  KHDR_MAGIC */
    uint16_t version;        /* +4 */
    uint16_t size;           /* +6  sizeof(struct kernel_header) */
    uint64_t entry;          /* +8  virtual address of _start (at the link address) */
    uint64_t virt_base;      /* +16 virtual address of the first byte of the image (link address) */
    uint64_t phys_base;      /* +24 physical load address */
    uint64_t file_size;      /* +32 bytes with contents (text, rodata, data) */
    uint64_t mem_size;       /* +40 bytes in memory, .bss included */
    uint32_t relr_offset;    /* +48 packed relative relocations (ELF RELR): offset in the image */
    uint32_t relr_size;      /* +52 bytes (a multiple of 8) */
    uint64_t reserved;       /* +56 */
};
_Static_assert(sizeof(struct kernel_header) == 64, "kernel header layout (entry.asm, loaders)");

/* Validate everything the bootloader handed over. Returns NULL on success,
 * otherwise a description of the first problem found. */
const char *bootinfo_validate(const BootInfo *bi);
const char *bootinfo_check(const BootInfo *bi, uintptr_t addr, const MemoryMapEntry *mm);

const char *mmap_type_name(uint32_t type);

#endif
