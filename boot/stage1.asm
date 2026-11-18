; =============================================================================
; D-OS Stage 1 Bootloader (MBR)
; Loaded by the BIOS at 0000:7C00, 16-bit real mode, boot drive in DL.
;
;   - sets up segments and stack, initialises COM1
;   - loads Stage 2 (STAGE2_SECTORS from STAGE2_LBA) to 0000:7E00 via INT 13h extensions
;   - jumps to Stage 2 with DL = boot drive
;
; STAGE2_LBA / STAGE2_SECTORS are supplied by build.ps1 (-D).
; =============================================================================

[bits 16]
[org 0x7C00]

%ifndef STAGE2_LBA
  %error "STAGE2_LBA not defined (build via build.ps1)"
%endif
%ifndef STAGE2_SECTORS
  %error "STAGE2_SECTORS not defined (build via build.ps1)"
%endif

STAGE2_ADDR  equ 0x7E00
BOOTINFO_TSC equ 0x4000 + 40    ; BootInfo (0x4000) field tsc_stage1, see kernel/include/bootinfo.h

start:
    cli
    xor ax, ax
    mov ds, ax
    mov [boot_drive], dl                ; save before RDTSC clobbers EDX
    rdtsc                               ; boot timing: TSC at (almost) the first stage-1 instruction
    mov [BOOTINFO_TSC], eax             ; -> BootInfo.tsc_stage1 (stage 2 leaves it intact)
    mov [BOOTINFO_TSC + 4], edx
    xor ax, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00              ; stack grows down below the boot sector
    jmp 0x0000:.flush_cs        ; normalise CS:IP to 0000:7Cxx
.flush_cs:
    sti
    cld

    call serial_init

    mov si, msg_banner
    call print

    ; --- INT 13h extensions present? -----------------------------------------
    mov ah, 0x41
    mov bx, 0x55AA
    mov dl, [boot_drive]
    int 0x13
    jc .no_ext
    cmp bx, 0xAA55
    jne .no_ext

    ; --- Load Stage 2 ----------------------------------------------------------
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

; -----------------------------------------------------------------------------
; serial_init: COM1, 115200 baud, 8N1, FIFO enabled, no interrupts
; -----------------------------------------------------------------------------
serial_init:
    mov dx, 0x3F8 + 1           ; IER: disable interrupts
    xor al, al
    out dx, al
    mov dx, 0x3F8 + 3           ; LCR: enable DLAB
    mov al, 0x80
    out dx, al
    mov dx, 0x3F8 + 0           ; divisor low  (1 => 115200 baud)
    mov al, 0x01
    out dx, al
    mov dx, 0x3F8 + 1           ; divisor high
    xor al, al
    out dx, al
    mov dx, 0x3F8 + 3           ; LCR: 8 bits, no parity, 1 stop, DLAB off
    mov al, 0x03
    out dx, al
    mov dx, 0x3F8 + 2           ; FCR: enable + clear FIFOs, 14-byte threshold
    mov al, 0xC7
    out dx, al
    mov dx, 0x3F8 + 4           ; MCR: DTR + RTS + OUT2
    mov al, 0x0B
    out dx, al
    ret

%include "common16.inc"

; -----------------------------------------------------------------------------
align 4
dap:                            ; INT 13h AH=42h disk address packet
    db 0x10, 0                  ; size, reserved
    dw STAGE2_SECTORS           ; sector count
    dw STAGE2_ADDR, 0x0000      ; offset, segment
    dq STAGE2_LBA               ; starting LBA

msg_banner  db "D-OS: stage1 OK", 13, 10, 0
msg_no_ext  db "D-OS: no INT13 ext", 13, 10, 0
msg_disk    db "D-OS: stage2 read error", 13, 10, 0
boot_drive  db 0

; Bytes 440-511 belong to the disk: disk signature and the (protective) MBR partition table, which
; dosimg writes. Stage 1 must fit in the first 440 bytes; only those are copied into the image.
times 440 - ($ - $$) db 0
times 510 - ($ - $$) db 0
dw 0xAA55
