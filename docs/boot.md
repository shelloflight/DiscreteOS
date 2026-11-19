# Boot: BIOS and UEFI

One image, `build\discrete.img`, boots on BIOS and UEFI machines. Both loaders verify the kernel,
relocate it to a random base (KASLR) and hand it the same machine state and the same BootInfo, so
the kernel has a single entry contract.

**Code:** `boot/stage1.asm`, `boot/stage2.asm`, `boot/stage3/` (BIOS); `boot/uefi/` (UEFI);
`boot/common/` (signature verifier and KASLR, shared by both); `kernel/include/bootinfo.h` (the
contract); `kernel/bootinfo.c` (validation); `kernel/mm/kaslr.c`; `kernel/drivers/fbcon.c`;
`tools/dbuild` (`dbuild img boot` builds the image).

## Disk image (64 MiB, GPT)

| Where | What |
|---|---|
| LBA 0 | protective MBR; its boot code area is stage 1 |
| LBA 1-33 | GPT (backup at the end of the disk) |
| Partition 1 (LBA 2048) | BIOS boot partition: stage 2, stage 3, the kernel's `.dsig`, then `kernel.bin` |
| Partition 2 `esp` | FAT32 EFI System Partition: `\EFI\BOOT\BOOTX64.EFI`, `\DOS\KERNEL.BIN` |

The image is deterministic (fixed GUIDs and timestamps), so the reproducible-build check covers it.
The LBA constants live in `tools/dbuild/src/img.rs` and are passed to stage 1 and stage 2 as NASM defines.

## Kernel image header

The first 64 bytes of `kernel.bin` (`.boothdr` in `kernel/arch/x86_64/entry.asm`, `struct
kernel_header`): magic `DKRN`, version, size, entry and link base, physical load address (1 MiB),
file and memory sizes, and the RELR relocation table. All fields are link-time constants. Loaders
check every field (`kaslr_check_header`) after the signature and before using any of it.

## BIOS path

Stage 1 (MBR) loads stage 2. Stage 2 reads the E820 map, loads stage 3, the `.dsig` and the kernel
(to 1 MiB), builds page tables and enters long mode. Stage 3 (C) verifies the kernel signature,
applies KASLR, and returns the entry point; it halts on any failure. Screen: VGA text mode.

## UEFI path (`BOOTX64.EFI`)

A small PE32+ application (C + a NASM hand-off stub, built with clang and lld-link `/Brepro`):

1. read `\DOS\KERNEL.BIN`, verify its signature, check the header;
2. allocate the kernel's physical range, copy it, zero `.bss`, relocate to a random base;
3. take the GOP framebuffer and the ACPI RSDP;
4. put BootInfo, page tables and the hand-off stub in low memory (below 512 KiB);
5. identity-map all RAM plus the first GiB at the kernel's random base;
6. `ExitBootServices`, convert the UEFI memory map to E820 types;
7. the stub loads the D-OS GDT, switches CR3 and jumps to the kernel (RDI = BootInfo).

Errors before `ExitBootServices` go to the firmware console (and the loader returns to the
firmware); after it, to COM1. The loader also stamps the TSC per step; the kernel prints the
timings (`Boot: loader steps: ...`).

## BootInfo (`bootinfo.h`, version 5)

Magic, version, firmware (BIOS/UEFI), flags (`BOOT_KERNEL_VERIFIED`, `BOOT_KERNEL_MEASURED`), the
memory map (up to 256 entries), kernel location, RSDP, EFI system table, framebuffer, the verified
`.dsig` record, the kernel's virtual base, KASLR entropy sources and a 32-byte seed (wiped after
use).

`bootinfo_validate` treats all of it as untrusted: placement and overlap, every field's range, map
entries, the kernel's location against the KASLR window, the framebuffer's geometry. The selftest
proves dozens of malformed hand-overs are refused under both firmwares. **Grow the structure only
at the end and bump its version.**

## KASLR

The kernel is a static PIE (`-fpie`, Rust `relocation-model=pie`, `ld.lld -pie -z
pack-relative-relocs -z text`). The only load-time fix-ups are absolute pointers in data, in a
packed RELR table inside the signed image; the link fails if any other relocation appears.

| Region | Chosen by | Alignment | Entropy (QEMU) |
|---|---|---|---|
| Kernel image (top 512 GiB) | loader | 2 MiB | 17 bits |
| Direct map | kernel | 1 GiB | 14-16 bits (depends on physical address width) |
| Heap (1 TiB) | kernel | 1 GiB | 14 bits |
| Thread stacks (1 TiB) | kernel | 1 GiB | 14 bits |

Entropy: RDSEED, RDRAND, the UEFI RNG protocol when present, and TSC samples, mixed with SHA-512. The
loader bounds-checks every RELR entry before applying it. The kernel keeps the layout in
`.data.ro_after_init` (read-only once the VMM runs). Bases are never printed; panic dumps print
the image *offset* so reports can be symbolized against `kernel.elf`.

## Screen

BIOS: VGA text. UEFI: framebuffer console (`fbcon.c`), mapped write-combining, drawn from a shadow
buffer with the 8x16 VGA font, glyphs doubled at 2560 px and wider.

## Tests

`boot`, `uefi`, `uefi-uniproc`, `uefi-selftest` (BootInfo validation), `bios-badsig` and
`uefi-badsig` (a tampered kernel never runs), `kaslr` (three boots, every region base must differ),
`kaslr-host` (loader relocation code on the host), `roinit`.

## Limitations

- The kernel is stored twice (BIOS partition and ESP) so stage 2 needs no FAT32 reader.
- The UEFI loader is not signed for UEFI Secure Boot; the D-OS chain of trust starts at the loader.
- KASLR randomizes the kernel's virtual address only; its physical address stays at 1 MiB.
- UEFI runtime services are not used.
