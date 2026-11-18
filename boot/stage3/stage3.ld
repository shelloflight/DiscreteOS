/* D-OS BIOS stage 3 (boot/stage3/stage3.c): a flat binary at 0x20000, at most 32 KiB including
 * .bss (stage 2 loads 64 sectors there; the stack is above it, 0x28000-0x2FFFF). The .bss holds the
 * KASLR boot window's two page directories, which must survive until the kernel's VMM is active. */
ENTRY(stage3_main)

SECTIONS
{
    . = 0x20000;
    .text : { *(.text.entry) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        __bss_end = .;
    }
    __stage3_end = .;
    ASSERT(__stage3_end <= 0x28000, "stage 3 does not fit in 32 KiB")
    /DISCARD/ : { *(.comment) *(.eh_frame*) *(.note*) }
}
