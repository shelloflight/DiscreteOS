; =============================================================================
; D-OS El Torito BIOS Bootloader (No-Emulation CD-ROM Stage 1)
; Loaded by the BIOS at 0000:7C00 (2048 bytes), 16-bit real mode, DL = CD drive.
;
;   - sets up segments, stack, and COM1; stamps BootInfo.tsc_stage1
;   - loads Stage 2 from ISO block STAGE2_LBA / 4 (2048-byte CD sectors) to 0x7E00
;   - jumps to Stage 2 with DL = boot drive (stage2 detects 2048-byte CD sectors)
; =============================================================================

[bits 16]
[org 0x7C00]

%ifndef STAGE2_LBA
  %error "STAGE2_LBA not defined (build via dbuild)"
%endif
%ifndef STAGE2_SECTORS
  %error "STAGE2_SECTORS not defined (build via dbuild)"
%endif
%if (STAGE2_LBA % 4) != 0
  %error "STAGE2_LBA must be 2048-byte aligned for El Torito boot"
%endif
%if (STAGE2_SECTORS % 4) != 0
  %error "STAGE2_SECTORS must be 2048-byte aligned for El Torito boot"
%endif

STAGE2_ADDR  equ 0x7E00
BOOTINFO_TSC equ 0x4000 + 40

start:
    cli
    xor ax, ax
    mov ds, ax
    mov [boot_drive], dl
    rdtsc
    mov [BOOTINFO_TSC], eax
    mov [BOOTINFO_TSC + 4], edx
    xor ax, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    jmp 0x0000:.flush_cs
.flush_cs:
    sti
    cld

    call serial_init

    mov si, msg_banner
    call print

    ; INT 13h extensions check (required for El Torito CD-ROM LBA reads).
    mov ah, 0x41
    mov bx, 0x55AA
    mov dl, [boot_drive]
    int 0x13
    jc .no_ext
    cmp bx, 0xAA55
    jne .no_ext

    ; Load Stage 2 (2048-byte CD sectors) to 0000:7E00.
    mov si, dap
    mov ah, 0x42
    mov dl, [boot_drive]
    int 0x13
    jc .disk_err

    mov dl, [boot_drive]
    jmp 0x0000:STAGE2_ADDR

.no_ext:
    mov si, msg_no_ext
    jmp fatal
.disk_err:
    mov si, msg_disk
    jmp fatal

serial_init:
    mov dx, 0x3F8 + 1
    xor al, al
    out dx, al
    mov dx, 0x3F8 + 3
    mov al, 0x80
    out dx, al
    mov dx, 0x3F8 + 0
    mov al, 0x01
    out dx, al
    mov dx, 0x3F8 + 1
    xor al, al
    out dx, al
    mov dx, 0x3F8 + 3
    mov al, 0x03
    out dx, al
    mov dx, 0x3F8 + 2
    mov al, 0xC7
    out dx, al
    mov dx, 0x3F8 + 4
    mov al, 0x0B
    out dx, al
    ret

%include "common16.inc"

align 4
dap:
    db 0x10, 0
    dw STAGE2_SECTORS / 4
    dw STAGE2_ADDR, 0x0000
    dq STAGE2_LBA / 4

msg_banner  db "D-OS: stage1 OK", 13, 10, 0
msg_no_ext  db "D-OS: no INT13 ext", 13, 10, 0
msg_disk    db "D-OS: stage2 read error", 13, 10, 0
boot_drive  db 0

times 2048 - ($ - $$) db 0
