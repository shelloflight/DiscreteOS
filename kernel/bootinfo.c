/*
 * BootInfo validation. Everything the bootloader hands over is treated as untrusted input:
 * every pointer, count and range is checked before the kernel relies on it.
 */

#include <stddef.h>
#include <stdint.h>
#include "bootinfo.h"
#include "mm.h"

extern char __kernel_start[], __rodata_end[], __bss_start[], __kernel_end[];
extern const struct kernel_header kernel_header;   /* entry.asm: link-time sizes of this image */

/* Both loaders keep BootInfo and the memory map in conventional memory below the EBDA. */
#define LOWMEM_MIN 0x500u
#define LOWMEM_MAX 0x80000u
/* What the boot page tables are guaranteed to identity-map (kmain copies the RSDP through it). */
#define BOOT_IDENTITY_END 0x100000000ull
#define FB_MAX_DIM 16384u

const char *mmap_type_name(uint32_t type)
{
    switch (type) {
    case MMAP_USABLE:           return "usable";
    case MMAP_RESERVED:         return "reserved";
    case MMAP_ACPI_RECLAIMABLE: return "ACPI reclaimable";
    case MMAP_ACPI_NVS:         return "ACPI NVS";
    case MMAP_BAD:              return "bad memory";
    default:                    return "unknown (reserved)";
    }
}

static int overlaps(uint64_t a, uint64_t alen, uint64_t b, uint64_t blen)
{
    return a < b + blen && b < a + alen;
}

static const char *framebuffer_validate(const BootInfo *bi, const MemoryMapEntry *mm)
{
    if (bi->fb_type == BOOT_FB_NONE)
        return (bi->fb_base | bi->fb_size | bi->fb_width | bi->fb_height | bi->fb_pitch) ? "framebuffer fields set without a framebuffer" : NULL;
    if (bi->fb_type != BOOT_FB_RGB32)
        return "unknown framebuffer type";
    if (bi->firmware != BOOT_FW_UEFI)
        return "framebuffer from a BIOS boot";
    if (!bi->fb_width || !bi->fb_height || bi->fb_width > FB_MAX_DIM || bi->fb_height > FB_MAX_DIM)
        return "framebuffer size out of range";
    if (bi->fb_pitch % 4 || bi->fb_pitch / 4 < bi->fb_width || bi->fb_pitch > 4 * FB_MAX_DIM)
        return "framebuffer pitch out of range";
    if (bi->fb_size < (uint64_t)bi->fb_pitch * bi->fb_height || bi->fb_size > (1ull << 32))
        return "framebuffer smaller than its pitch x height (or over 4 GiB)";
    if (!bi->fb_base || bi->fb_base + bi->fb_size < bi->fb_base || bi->fb_base + bi->fb_size > PHYSMAP_MAX)
        return "framebuffer address out of range";
    uint8_t r = bi->fb_red_shift, g = bi->fb_green_shift, b = bi->fb_blue_shift;
    if (r % 8 || g % 8 || b % 8 || r > 24 || g > 24 || b > 24 || r == g || g == b || r == b)
        return "framebuffer channel layout invalid";
    /* Device memory: it must not alias RAM the kernel hands out, nor the kernel image. */
    for (uint32_t i = 0; i < bi->mmap_count; i++)
        if (mm[i].type == MMAP_USABLE && overlaps(bi->fb_base, bi->fb_size, mm[i].base, mm[i].length))
            return "framebuffer overlaps usable RAM";
    return NULL;
}

const char *bootinfo_validate(const BootInfo *bi)
{
    if (!bi)
        return "no BootInfo";
    return bootinfo_check(bi, (uintptr_t)bi, (const MemoryMapEntry *)(uintptr_t)bi->mmap_addr);
}

/* The checks, on a BootInfo found at physical `addr` whose map is readable at `mm` (the self-test
 * runs them on modified copies). `mm` is read only after mmap_addr and mmap_count passed. */
const char *bootinfo_check(const BootInfo *bi, uintptr_t addr, const MemoryMapEntry *mm)
{
    if (addr < LOWMEM_MIN || addr + sizeof(*bi) > LOWMEM_MAX)
        return "BootInfo pointer outside conventional memory";
    if (bi->magic != BOOTINFO_MAGIC)
        return "bad BootInfo magic";
    if (bi->version != BOOTINFO_VERSION)
        return "unsupported BootInfo version";
    if (bi->firmware != BOOT_FW_BIOS && bi->firmware != BOOT_FW_UEFI)
        return "unknown firmware type";
    if (bi->flags & ~BOOT_FLAGS_KNOWN)
        return "reserved BootInfo flags set";
    if ((bi->flags & BOOT_KERNEL_MEASURED) && !(bi->flags & BOOT_KERNEL_VERIFIED))
        return "kernel measured but not verified";
    if (bi->firmware == BOOT_FW_BIOS && (bi->flags & BOOT_KERNEL_MEASURED))
        return "TPM measurement from a BIOS boot";
    if (bi->firmware == BOOT_FW_BIOS && bi->efi_system_table)
        return "UEFI system table from a BIOS boot";

    /* Memory map location and size */
    if (bi->mmap_count == 0 || bi->mmap_count > BOOTINFO_MMAP_MAX)
        return "memory map entry count out of range";
    uint64_t mm_end = bi->mmap_addr + (uint64_t)bi->mmap_count * sizeof(MemoryMapEntry);
    if (bi->mmap_addr < LOWMEM_MIN || mm_end > LOWMEM_MAX)
        return "memory map outside conventional memory";
    if (bi->mmap_addr < addr + sizeof(*bi) && addr < mm_end)
        return "memory map overlaps BootInfo";

    /* Kernel image must be where it was linked, and fully loaded */
    if (bi->kernel_phys != KERNEL_PHYS(__kernel_start))
        return "kernel loaded at wrong address";
    if (bi->kernel_size < ((uint64_t)(uintptr_t)__rodata_end - (uint64_t)(uintptr_t)__kernel_start) ||
        bi->kernel_size > ((uint64_t)(uintptr_t)__bss_start - (uint64_t)(uintptr_t)__kernel_start) + 4096)
        return "kernel size does not match the linked image";

    /* KASLR (v5): the loader says where it put the image; that must be where it runs, inside the
     * image window, 2 MiB-aligned (the boot window maps physical 0 from there), with a source. */
    if (bi->kernel_virt != (uint64_t)(uintptr_t)__kernel_start)
        return "kernel not running where the loader says it relocated it";
    uint64_t vbase = bi->kernel_virt - bi->kernel_phys;
    if (vbase < KIMAGE_WINDOW || vbase >= KIMAGE_WINDOW_END || vbase % LARGE_PAGE_SIZE)
        return "kernel virtual base outside the KASLR window";
    if (!bi->kaslr_sources || (bi->kaslr_sources & ~KASLR_SRC_KNOWN) || bi->reserved0)
        return "KASLR fields invalid";

    /* Entries: non-empty, no wrap-around; the kernel must sit inside usable RAM */
    uint64_t k_start = KERNEL_PHYS(__kernel_start), k_end = KERNEL_PHYS(__kernel_end);
    int kernel_covered = 0;
    for (uint32_t i = 0; i < bi->mmap_count; i++) {
        if (mm[i].length == 0)
            return "memory map has an empty entry";
        if (mm[i].base + mm[i].length < mm[i].base)
            return "memory map entry wraps around";
        if (mm[i].type == MMAP_USABLE && mm[i].base <= k_start && k_end <= mm[i].base + mm[i].length)
            kernel_covered = 1;
    }
    if (!kernel_covered)
        return "kernel is not inside a usable memory region";

    /* ACPI root pointer (UEFI: from the configuration table); kmain copies it while the boot
     * identity map is still live. */
    if (bi->rsdp && (bi->rsdp < LOWMEM_MIN || bi->rsdp + 36 > BOOT_IDENTITY_END))
        return "ACPI RSDP address out of range";

    /* The kernel's .dsig (structure only: the signature itself is checked by verify_boot, kmain):
     * a v1 Ed25519 kernel signature over exactly the bytes of this kernel image. */
    if (bi->flags & BOOT_KERNEL_VERIFIED) {
        const uint8_t *d = bi->kernel_dsig;
        uint64_t size = 0;
        for (int i = 7; i >= 0; i--)
            size = size << 8 | d[32 + i];
        if (d[0] != 'D' || d[1] != 'S' || d[2] != 'I' || d[3] != 'G' || d[4] != 1 || d[5] != 0 || d[6] != 1 || d[7] != 0)
            return "kernel signature record is not a .dsig";
        if (d[8] != 1 || d[9] || d[10] || d[11])
            return "kernel signature record is not for a kernel";
        if (size != kernel_header.file_size)
            return "kernel signature record is for an image of another size";
    }

    return framebuffer_validate(bi, mm);
}
