/*
 * D-KRNL linker script: higher-half, position-independent kernel (KASLR, docs/boot.md).
 *   Link address (VMA): KERNEL_LINK_BASE + 1 MiB  (0xFFFFFFFF80100000)
 *   Physical (LMA):     1 MiB                     (loaded there by both loaders)
 * The image is linked as a static PIE: code reaches everything RIP-relative, and every absolute
 * pointer in data is listed in a packed RELR table (.relr.dyn) inside the image. The loader picks
 * a random base (boot/common/kaslr.c), adds the difference to every listed word, and maps the
 * image there; the link address is used only when the image is relocated by 0.
 * Keep KERNEL_LINK_BASE in sync with kernel/include/mm.h and boot/common/kaslr.h.
 *
 * Sections are grouped into segments by permission and mapped W^X by the VMM (kernel/mm/vmm.c):
 *   text   -> R-X
 *   rodata -> R--  (NX; also the relocation table and the after-relocation-read-only data)
 *   data   -> RW-  (.data + .bss, NX), except .data.ro_after_init: R-- once the VMM is active
 * Each starts on a 4 KiB page boundary; boundary symbols below are used by the VMM.
 * No relocation may land in .text (-z text): the code is pure PIC.
 */

ENTRY(_start)

KERNEL_LINK_BASE = 0xFFFFFFFF80000000;
KERNEL_PHYS      = 0x100000;

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R + X */
    rodata PT_LOAD FLAGS(4);   /* R     */
    data   PT_LOAD FLAGS(6);   /* R + W */
}

SECTIONS
{
    . = KERNEL_LINK_BASE + KERNEL_PHYS;
    __kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_LINK_BASE)
    {
        __text_start = .;
        KEEP(*(.boothdr))                /* kernel image header (entry.asm): first bytes of kernel.bin */
        *(.text._start)
        *(.text .text.*)
        /* Interrupt/syscall entry and exit code (isr.asm, syscall.asm), pages of its own: with KPTI
         * these are the only kernel code pages mapped in user page tables (kernel/mm/kpti.c). */
        . = ALIGN(4K);
        __entry_text_start = .;
        KEEP(*(.entry.text))
        . = ALIGN(4K);
        __entry_text_end = .;
        __text_end = .;
    } :text

    . = ALIGN(4K);
    .rodata : AT(ADDR(.rodata) - KERNEL_LINK_BASE)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)   /* vtables, pointer tables: relocated by the loader, then read-only */
        *(.got .got.*)
        . = ALIGN(8);
        __ksyms_start = .;               /* kernel symbol table (build.ps1, second link) */
        KEEP(*(.ksyms))
        __ksyms_end = .;
    } :rodata

    /* Static-PIE metadata. Only .relr.dyn is used (by the loader); the rest is what LLD always
     * emits for a PIE and stays small. */
    . = ALIGN(8);
    .relr.dyn : AT(ADDR(.relr.dyn) - KERNEL_LINK_BASE) { __relr_start = .; *(.relr.dyn) __relr_end = .; } :rodata
    .rela.dyn : AT(ADDR(.rela.dyn) - KERNEL_LINK_BASE) { *(.rela.dyn) } :rodata
    .dynsym   : AT(ADDR(.dynsym) - KERNEL_LINK_BASE) { *(.dynsym) } :rodata
    .dynstr   : AT(ADDR(.dynstr) - KERNEL_LINK_BASE) { *(.dynstr) } :rodata
    .gnu.hash : AT(ADDR(.gnu.hash) - KERNEL_LINK_BASE) { *(.gnu.hash) } :rodata
    .hash     : AT(ADDR(.hash) - KERNEL_LINK_BASE) { *(.hash) } :rodata
    .dynamic  : AT(ADDR(.dynamic) - KERNEL_LINK_BASE) { *(.dynamic) } :rodata
    . = ALIGN(4K);
    __rodata_end = .;

    . = ALIGN(4K);
    .data : AT(ADDR(.data) - KERNEL_LINK_BASE)
    {
        __data_start = .;
        __ro_after_init_start = .;       /* written before the VMM is active, read-only afterwards */
        *(.data.ro_after_init)
        . = ALIGN(4K);
        __ro_after_init_end = .;
        *(.data .data.*)
        __data_contents_end = .;          /* kernel.bin (objcopy -O binary) ends here */
    } :data

    . = ALIGN(4K);
    .bss : AT(ADDR(.bss) - KERNEL_LINK_BASE)
    {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        . = ALIGN(4K);
        __bss_end = .;
        __data_end = .;
    } :data

    __kernel_end = .;
    /* Kernel header fields (entry.asm): absolute values, so the header itself needs no relocation. */
    __kernel_file_size = __data_contents_end - __kernel_start;
    __kernel_mem_size = __kernel_end - __kernel_start;
    __kernel_entry_link = ABSOLUTE(_start);
    __kernel_start_link = ABSOLUTE(__kernel_start);
    __kernel_relr_offset = __relr_start - __kernel_start;
    __kernel_relr_size = __relr_end - __relr_start;

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame*)
        *(.note*)
        *(.interp)
    }
}

/* Every load-time fix-up must be a packed relative one: the loaders apply nothing else. */
ASSERT(SIZEOF(.rela.dyn) == 0, "kernel: relocations the RELR table cannot hold (non-relative, or an unaligned pointer); the loaders apply RELR only")
ASSERT(__kernel_mem_size < 0x3FF00000, "kernel image must fit the loaders' 1 GiB window")
