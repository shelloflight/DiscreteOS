/*
 * KASLR in the loaders (docs/boot.md, "KASLR"): shared by the UEFI loader and the BIOS stage 3.
 * After the kernel's signature has been verified, the loader
 *   1. gathers entropy (RDSEED, RDRAND, the firmware's RNG if any, TSC jitter) through SHA-512,
 *   2. picks a random 2 MiB-aligned virtual base in the kernel image window,
 *   3. applies the image's packed relative relocations (ELF RELR, listed in the kernel header),
 *   4. maps the first GiB of physical memory at that base (the kernel image is at base + 1 MiB).
 * The relocation table is part of the signed image, and every entry is bounds-checked: a bad
 * table is refused, never applied partly outside the image.
 */
#ifndef DOS_BOOT_KASLR_H
#define DOS_BOOT_KASLR_H

#include <stddef.h>
#include <stdint.h>

/* Keep in sync with kernel/include/mm.h and kernel/linker.ld. */
#define KASLR_LINK_BASE    0xFFFFFFFF80000000ull   /* the kernel's link-time virtual base */
#define KASLR_WINDOW       0xFFFFFF8000000000ull   /* PML4 entry 511 */
#define KASLR_WINDOW_END   0xFFFFFFFFC0000000ull   /* + the 1 GiB boot window = 2^64 */
#define KASLR_ALIGN        0x200000ull             /* 2 MiB: the boot window uses 2 MiB pages */
#define KASLR_SLOTS        ((KASLR_WINDOW_END - KASLR_WINDOW) / KASLR_ALIGN)
#define KASLR_BITS         17                       /* floor(log2(KASLR_SLOTS)) = 17 (261632 slots) */

/* BootInfo.kaslr_sources (kernel/include/bootinfo.h) */
#define KASLR_SRC_RDSEED   1u
#define KASLR_SRC_RDRAND   2u
#define KASLR_SRC_EFI_RNG  4u
#define KASLR_SRC_TSC      8u

/* Kernel image header v2 (kernel/include/bootinfo.h, kernel/arch/x86_64/entry.asm). */
#define KHDR_MAGIC   0x4E524B44u
#define KHDR_VERSION 2u
struct __attribute__((packed)) kernel_header {
    uint32_t magic;
    uint16_t version, size;
    uint64_t entry, virt_base, phys_base, file_size, mem_size;
    uint32_t relr_offset, relr_size;
    uint64_t reserved;
};
_Static_assert(sizeof(struct kernel_header) == 64, "kernel header layout");

/* 64 bytes of SHA-512-mixed entropy; `extra` (may be NULL) is the firmware RNG's output, credited
 * as `extra_source`. Returns the KASLR_SRC_* that contributed (TSC always does). */
uint32_t kaslr_entropy(const void *extra, size_t extra_len, uint32_t extra_source, uint8_t out[64]);

/* A random virtual base from 8 bytes of entropy: KASLR_WINDOW + k * KASLR_ALIGN. */
uint64_t kaslr_pick_base(const uint8_t r[8]);

/* Check the header of a verified image (`file_len` bytes). NULL if usable, else why not. */
const char *kaslr_check_header(const struct kernel_header *h, uint64_t file_len);

/* Apply the RELR table of `image` (the loaded copy, file_size bytes, linked at h->virt_base),
 * adding `delta` to every listed 64-bit word. NULL on success, else why the table is invalid
 * (then nothing may run: words before the bad entry are already changed). */
const char *kaslr_relocate(uint8_t *image, const struct kernel_header *h, uint64_t delta);

/* Map physical [0, 1 GiB) at `base` with 2 MiB pages in the PDPT of PML4 entry 511 (`pdpt`, every
 * entry cleared first), using the two zeroed page tables at physical `pd0`/`pd1` (the window may
 * span two PDPT entries). Page tables must be identity-mapped. */
void kaslr_map_window(uint64_t *pdpt, uint64_t base, uint64_t pd0, uint64_t pd1);

#endif
