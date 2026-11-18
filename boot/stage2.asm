; =============================================================================
; D-OS Stage 2 Bootloader
; Loaded by Stage 1 at 0000:7E00, 16-bit real mode, DL = boot drive.
;
;   1. Verify the CPU supports 64-bit long mode
;   2. Enable the A20 line
;   3. Collect the BIOS E820 memory map
;   4. Load stage 3 (the signature verifier, boot/stage3) and the kernel's .dsig; load the kernel to
;      KERNEL_PHYS (1 MiB) through a low bounce buffer + unreal mode
;   5. Fill the BootInfo structure
;   6. Enter 32-bit protected mode, build page tables: the first 1 GiB identity-mapped AND mapped at
;      the kernel's link base (higher half, 0xFFFFFFFF80000000), 2 MiB pages
;   7. Enable PAE + EFER.LME + paging -> 64-bit long mode
;   8. Call stage 3: it verifies the kernel's signature, relocates the kernel to a random base
;      (KASLR) and moves the higher-half mapping there; halt if it fails
;   9. Jump to the kernel entry stage 3 returned (higher half) with RDI = &BootInfo
;
; STAGE3_LBA / STAGE3_SECTORS / KSIG_LBA / KERNEL_LBA / KERNEL_SECTORS are supplied by build.ps1 (-D).
;
; Low memory map used by the bootloader:
;   0x1000 - 0x3FFF   page tables (PML4, PDPT low, PD)
;   0x4000 - 0x43FF   BootInfo                (layout: kernel/include/bootinfo.h; +40 set by stage 1)
;   0x4400 - 0x4FFF   E820 entries (max 128 x 24 bytes)
;   0x5000 - 0x5FFF   page table (PDPT high, PML4[511])
;   0x6000 - 0x7BFF   stack (grows down from 0x7C00)
;   0x7C00 - 0x7DFF   stage 1
;   0x7E00 - 0xBDFF   stage 2 (max 16 KiB)
;   0x10000 - 0x17FFF disk bounce buffer
;   0x20000 - 0x27FFF stage 3 (max 32 KiB incl. .bss)
;   0x28000 - 0x2FFFF stage 3 stack
;   0x30000 - 0x301FF the kernel's .dsig
; =============================================================================

[bits 16]
[org 0x7E00]

%ifndef KERNEL_LBA
  %error "KERNEL_LBA not defined (build via build.ps1)"
%endif
%ifndef KERNEL_SECTORS
  %error "KERNEL_SECTORS not defined (build via build.ps1)"
%endif
%ifndef STAGE3_LBA
  %error "STAGE3_LBA not defined (build via build.ps1)"
%endif

PML4            equ 0x1000
PDPT            equ 0x2000
PD              equ 0x3000
PDPT_HIGH       equ 0x5000          ; PML4[511] -> PDPT_HIGH[510] -> PD (same 1 GiB as identity)
BOOTINFO        equ 0x4000
MMAP            equ 0x4400
MMAP_MAX        equ 128
E820_ENTRY_SIZE equ 24

BOUNCE_SEG      equ 0x1000          ; physical 0x10000
BOUNCE_PHYS     equ 0x10000
CHUNK_SECTORS   equ 64              ; 32 KiB per INT 13h read
STAGE3_SEG      equ 0x2000          ; stage 3 at physical 0x20000
STAGE3_PHYS     equ 0x20000
STAGE3_STACK    equ 0x30000
KSIG_SEG        equ 0x3000          ; the kernel's .dsig at physical 0x30000
KSIG_PHYS       equ 0x30000

KERNEL_PHYS     equ 0x100000
BOOTINFO_MAGIC  equ 0x424F5344      ; bytes "DSOB" in memory
BOOTINFO_VER    equ 5               ; +40 tsc_stage1 is written by stage 1
BOOTINFO_SIZE   equ 416
BOOT_FW_BIOS    equ 1
KHDR_MAGIC      equ 0x4E524B44      ; "DKRN": kernel image header (kernel/include/bootinfo.h)

CODE32_SEL      equ 0x08
DATA_SEL        equ 0x10
CODE64_SEL      equ 0x18

stage2_entry:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, 0x7C00
    sti
    cld

    mov [boot_drive], dl

    mov si, msg_stage2
    call print

    call check_long_mode
    call enable_a20
    call read_e820
    call load_stage3
    call load_kernel
    call fill_bootinfo

    mov si, msg_enter_lm
    call print

    ; --- Enter 32-bit protected mode -------------------------------------------
    cli
    lgdt [gdt_desc]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp CODE32_SEL:pm_entry

; -----------------------------------------------------------------------------
; check_long_mode: CPUID present + extended leaf 0x80000001 EDX.LM (bit 29)
; -----------------------------------------------------------------------------
check_long_mode:
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21                ; try to flip EFLAGS.ID
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd                           ; restore original flags
    xor eax, ecx
    jz .fail                        ; ID bit not writable -> no CPUID

    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .fail
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .fail
    ret
.fail:
    mov si, msg_no_lm
    jmp fatal

; -----------------------------------------------------------------------------
; a20_check: AX = 1 if A20 is enabled, 0 if memory wraps at 1 MiB
; -----------------------------------------------------------------------------
a20_check:
    push ds
    push es
    push si
    push di
    xor ax, ax
    mov ds, ax                      ; DS = 0x0000
    not ax
    mov es, ax                      ; ES = 0xFFFF
    mov si, 0x0500                  ; 0x000500
    mov di, 0x0510                  ; 0x100500 (or 0x000500 if wrapping)
    mov al, [ds:si]
    push ax
    mov al, [es:di]
    push ax
    mov byte [ds:si], 0x00
    mov byte [es:di], 0xFF
    cmp byte [ds:si], 0xFF          ; ZF=1 -> wrapped -> A20 off
    pop ax
    mov [es:di], al
    pop ax
    mov [ds:si], al
    mov ax, 0
    je .out
    mov ax, 1
.out:
    pop di
    pop si
    pop es
    pop ds
    ret

; -----------------------------------------------------------------------------
; enable_a20: already on -> BIOS INT 15h 2401h -> fast A20 (port 0x92)
; -----------------------------------------------------------------------------
enable_a20:
    call a20_check
    test ax, ax
    jnz .ok

    mov ax, 0x2401
    int 0x15
    call a20_check
    test ax, ax
    jnz .ok

    in al, 0x92
    test al, 2
    jnz .check_fast
    or al, 2
    and al, 0xFE                    ; never set bit 0 (fast reset)
    out 0x92, al
.check_fast:
    call a20_check
    test ax, ax
    jnz .ok

    mov si, msg_no_a20
    jmp fatal
.ok:
    ret

; -----------------------------------------------------------------------------
; read_e820: store BIOS memory map at MMAP, count in [mmap_count]
; -----------------------------------------------------------------------------
read_e820:
    xor ebx, ebx
    xor bp, bp                      ; entry count
    mov di, MMAP
.loop:
    mov eax, 0xE820
    mov edx, 0x534D4150             ; 'SMAP'
    mov ecx, E820_ENTRY_SIZE
    mov dword [es:di + 20], 1       ; ACPI 3.0 attrs default: "valid"
    int 0x15
    jc .end                         ; CF = end of list (or unsupported if bp==0)
    cmp eax, 0x534D4150
    jne .end
    mov eax, [es:di + 8]            ; skip zero-length entries
    or eax, [es:di + 12]
    jz .skip
    inc bp
    add di, E820_ENTRY_SIZE
    cmp bp, MMAP_MAX
    jae .end
.skip:
    test ebx, ebx
    jnz .loop
.end:
    test bp, bp
    jz .fail
    mov [mmap_count], bp
    ret
.fail:
    mov si, msg_no_e820
    jmp fatal

; -----------------------------------------------------------------------------
; enter_unreal: give FS a 4 GiB limit (base 0) so [fs:e32] reaches all memory
; -----------------------------------------------------------------------------
enter_unreal:
    cli
    push eax
    push bx
    lgdt [gdt_desc]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    mov bx, DATA_SEL
    mov fs, bx                      ; cache 4 GiB limit
    and al, 0xFE
    mov cr0, eax
    xor bx, bx
    mov fs, bx                      ; back to base 0, cached limit stays
    pop bx
    pop eax
    sti
    ret

; -----------------------------------------------------------------------------
; load_stage3: stage 3 (STAGE3_SECTORS from STAGE3_LBA) to 0x20000, the kernel's .dsig (one sector
; at KSIG_LBA) to 0x30000. Both are below 1 MiB: plain real-mode reads.
; -----------------------------------------------------------------------------
load_stage3:
    mov word [dap_count], STAGE3_SECTORS
    mov word [dap_off], 0
    mov word [dap_seg], STAGE3_SEG
    mov dword [dap_lba], STAGE3_LBA
    mov dword [dap_lba + 4], 0
    mov si, dap
    mov ah, 0x42
    mov dl, [boot_drive]
    int 0x13
    jc .err
    mov word [dap_count], 1
    mov word [dap_seg], KSIG_SEG
    mov dword [dap_lba], KSIG_LBA
    mov si, dap
    mov ah, 0x42
    mov dl, [boot_drive]
    int 0x13
    jc .err
    ret
.err:
    mov si, msg_disk3
    jmp fatal

; -----------------------------------------------------------------------------
; load_kernel: read KERNEL_SECTORS from KERNEL_LBA, copy to KERNEL_PHYS
; -----------------------------------------------------------------------------
load_kernel:
    mov dword [ld_lba], KERNEL_LBA
    mov dword [ld_left], KERNEL_SECTORS
    mov dword [ld_dest], KERNEL_PHYS
.next:
    mov eax, [ld_left]
    test eax, eax
    jz .done
    cmp eax, CHUNK_SECTORS
    jbe .count_ok
    mov eax, CHUNK_SECTORS
.count_ok:
    mov [dap_count], ax
    mov word [dap_off], 0
    mov word [dap_seg], BOUNCE_SEG
    mov eax, [ld_lba]
    mov [dap_lba], eax
    mov dword [dap_lba + 4], 0

    mov si, dap
    mov ah, 0x42
    mov dl, [boot_drive]
    int 0x13
    jc .err

    call enter_unreal               ; re-arm every chunk (BIOS may reload FS)
    movzx ecx, word [dap_count]
    shl ecx, 7                      ; sectors -> dwords (512 / 4)
    mov esi, BOUNCE_PHYS
    mov edi, [ld_dest]
.copy:
    mov eax, [fs:esi]
    mov [fs:edi], eax
    add esi, 4
    add edi, 4
    dec ecx
    jnz .copy

    movzx eax, word [dap_count]
    add [ld_lba], eax
    sub [ld_left], eax
    shl eax, 9
    add [ld_dest], eax
    jmp .next
.done:
    ret
.err:
    mov si, msg_disk
    jmp fatal

; -----------------------------------------------------------------------------
; fill_bootinfo: see kernel/include/bootinfo.h (must stay in sync)
; -----------------------------------------------------------------------------
fill_bootinfo:
    mov di, BOOTINFO
    mov dword [di + 0], BOOTINFO_MAGIC
    mov dword [di + 4], BOOTINFO_VER
    movzx eax, byte [boot_drive]
    mov [di + 8], eax
    movzx eax, word [mmap_count]
    mov [di + 12], eax
    mov dword [di + 16], MMAP
    mov dword [di + 20], 0
    mov dword [di + 24], KERNEL_PHYS
    mov dword [di + 28], 0
    mov dword [di + 32], KERNEL_SECTORS * 512
    mov dword [di + 36], 0
    ; +40 tsc_stage1: already filled in by stage 1
    push di
    add di, 48                      ; v3-v5 fields: all 0 except firmware (no RSDP hint, no framebuffer;
    xor ax, ax                      ; stage 3 sets the verified flag, the kernel's .dsig and KASLR)
    mov cx, (BOOTINFO_SIZE - 48) / 2
    rep stosw
    pop di
    mov dword [di + 48], BOOT_FW_BIOS
    ret

%include "common16.inc"

; =============================================================================
; 32-bit protected mode
; =============================================================================
[bits 32]
pm_entry:
    mov ax, DATA_SEL
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7C00

    ; --- Map the first 1 GiB twice: identity + higher half (2 MiB pages) ------------
    mov edi, PML4
    xor eax, eax
    mov ecx, (3 * 4096) / 4
    rep stosd
    mov edi, PDPT_HIGH
    mov ecx, 4096 / 4
    rep stosd

    mov dword [PML4], PDPT | 0x3                ; present | writable
    mov dword [PML4 + 511 * 8], PDPT_HIGH | 0x3
    mov dword [PDPT], PD | 0x3                  ; 0 .. 1 GiB
    mov dword [PDPT_HIGH + 510 * 8], PD | 0x3   ; link base .. +1 GiB (stage 3 moves it: KASLR)

    mov edi, PD
    mov eax, 0x83                   ; present | writable | page size (2 MiB)
    mov ecx, 512
.fill_pd:
    mov [edi], eax
    mov dword [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    loop .fill_pd

    ; --- Long mode -----------------------------------------------------------------
    mov eax, cr4
    or eax, 1 << 5                  ; PAE
    mov cr4, eax

    mov eax, PML4
    mov cr3, eax

    mov ecx, 0xC0000080             ; IA32_EFER
    rdmsr
    or eax, 1 << 8                  ; LME
    wrmsr

    mov eax, cr0
    or eax, 1 << 31                 ; PG (PE already set)
    mov cr0, eax

    jmp CODE64_SEL:lm_entry

; =============================================================================
; 64-bit long mode
; =============================================================================
[bits 64]
default abs                         ; absolute addresses (identity-mapped low memory)
lm_entry:
    mov ax, DATA_SEL
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov rsp, 0x7C00

    cmp dword [KERNEL_PHYS], KHDR_MAGIC    ; kernel image header: magic, then the entry point
    jne .bad_kernel

    ; --- stage 3: the kernel's signature (it reports on COM1 and the screen) ---------------------
    mov rsp, STAGE3_STACK
    mov rdi, KERNEL_PHYS            ; kernel
    mov rsi, KERNEL_SECTORS * 512   ; bytes loaded
    mov rdx, KSIG_PHYS              ; .dsig
    mov rcx, BOOTINFO
    mov rax, STAGE3_PHYS
    call rax
    test rax, rax
    jz .halt                        ; unverified (or unrelocatable) kernel: never run it
    mov rbx, rax                    ; entry at the randomized base (higher half)
    mov rsp, 0x7C00
    rdtsc
    mov [BOOTINFO + 104], eax       ; tsc_loader_exit
    mov [BOOTINFO + 108], edx
    mov edi, BOOTINFO               ; RDI = BootInfo* (physical, identity-mapped; zero-extended)
    jmp rbx                         ; the kernel runs there from its first instruction
.bad_kernel:
    mov dx, 0x3F8                   ; no BIOS any more: report on COM1 directly
    lea rsi, [rel msg_bad_kernel]
.putc:
    lodsb
    test al, al
    jz .halt
    out dx, al
    jmp .putc
.halt:
    cli
    hlt
    jmp .halt

; =============================================================================
; Data
; =============================================================================
align 8
gdt:
    dq 0                            ; 0x00 null
    dq 0x00CF9A000000FFFF           ; 0x08 code32: base 0, 4 GiB, DPL0
    dq 0x00CF92000000FFFF           ; 0x10 data:   base 0, 4 GiB, DPL0
    dq 0x00AF9A000000FFFF           ; 0x18 code64: L=1
gdt_end:

gdt_desc:
    dw gdt_end - gdt - 1
    dd gdt

align 4
dap:
    db 0x10, 0
dap_count   dw 0
dap_off     dw 0
dap_seg     dw 0
dap_lba     dq 0

ld_lba      dd 0
ld_left     dd 0
ld_dest     dd 0
mmap_count  dw 0
boot_drive  db 0

msg_stage2   db "D-OS: stage2 OK", 13, 10, 0
msg_enter_lm db "D-OS: entering long mode", 13, 10, 0
msg_no_lm    db "D-OS: CPU lacks 64-bit long mode", 13, 10, 0
msg_no_a20   db "D-OS: cannot enable A20", 13, 10, 0
msg_no_e820  db "D-OS: E820 memory map unavailable", 13, 10, 0
msg_disk     db "D-OS: kernel read error", 13, 10, 0
msg_disk3    db "D-OS: stage 3 read error", 13, 10, 0
msg_bad_kernel db "D-OS: kernel image header missing", 13, 10, 0
