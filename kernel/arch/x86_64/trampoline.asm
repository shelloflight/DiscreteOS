; =============================================================================
; AP (application processor) startup.
;
; trampoline_start..trampoline_end is a position-dependent blob that smp.c copies to TRAMPOLINE_PHYS
; (0x8000) before each SIPI; the SIPI vector is its page number (0x08), so the AP starts at
; CS:IP = 0x0800:0000 in real mode. It goes real mode -> protected mode -> long mode on a temporary
; page table (identity map of the first 2 MiB + the kernel's upper half), then jumps to ap_entry64
; in the kernel image, which switches to the kernel's own page table. The kernel's page tables
; never get a lower-half mapping.
;
; The blob is never executed in place (it lives in .rodata, NX); every address inside it is
; computed relative to its load address with T(label).
; Parameters (filled in by smp.c for each AP; layout: struct trampoline_params in smp.c):
;   tramp_cr3   temporary PML4 (below 4 GiB)       kernel_cr3  kernel PML4
;   efer        EFER bits to set (LME, NXE)        stack       top of the AP's idle-thread stack
;   percpu      the AP's per-CPU block             entry       ap_entry64
; =============================================================================

default abs                                 ; the blob runs at another address than it is linked at
TRAMPOLINE_PHYS equ 0x8000                  ; keep in sync with smp.c
%define T(label) (TRAMPOLINE_PHYS + (label) - trampoline_start)

section .rodata
global trampoline_start
global trampoline_end
global trampoline_params

align 16
[bits 16]
trampoline_start:
    cli
    cld
    xor ax, ax
    mov ds, ax
    lgdt [T(tgdt_ptr)]
    mov eax, cr0
    or eax, 1                               ; PE
    mov cr0, eax
    jmp dword 0x08:T(pm32)

[bits 32]
pm32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr4
    or eax, 1 << 5                          ; PAE
    mov cr4, eax
    mov eax, [T(p_tramp_cr3)]
    mov cr3, eax
    mov ecx, 0xC0000080                     ; EFER
    rdmsr
    or eax, [T(p_efer)]                     ; LME (+ NXE: the kernel's page tables use NX)
    wrmsr
    mov eax, cr0
    or eax, 0x80010000                      ; PG | WP
    mov cr0, eax                            ; long mode (compatibility) is active now
    jmp 0x18:T(lm64)

[bits 64]
lm64:
    mov rsp, [T(p_stack)]
    mov rdi, [T(p_percpu)]
    mov rbx, [T(p_kernel_cr3)]
    mov rax, [T(p_entry)]
    jmp rax                                 ; into the kernel's upper half

align 8
tgdt:
    dq 0
    dq 0x00CF9A000000FFFF                   ; 0x08 32-bit code
    dq 0x00CF92000000FFFF                   ; 0x10 data
    dq 0x00AF9A000000FFFF                   ; 0x18 64-bit code
tgdt_ptr:
    dw tgdt_ptr - tgdt - 1
    dd T(tgdt)

align 8
trampoline_params:
p_tramp_cr3:  dq 0
p_kernel_cr3: dq 0
p_efer:       dq 0
p_stack:      dq 0
p_percpu:     dq 0
p_entry:      dq 0
trampoline_end:

; -----------------------------------------------------------------------------
; Kernel side: RBX = kernel PML4, RSP = idle stack top, RDI = per-CPU block.
; Interrupts are off; the IDT is still the real-mode one until ap_main loads the kernel's.
; -----------------------------------------------------------------------------
section .text
global ap_entry64
extern ap_main

ap_entry64:
    mov cr3, rbx                            ; kernel page tables (drops the temporary identity map)
    mov rax, rdi                            ; GS base = per-CPU block (locks and `current` need it)
    mov rdx, rdi
    shr rdx, 32
    mov ecx, 0xC0000101                     ; IA32_GS_BASE
    wrmsr
    xor ebp, ebp                            ; end of backtraces
    call ap_main                            ; never returns
.hang:
    cli
    hlt
    jmp .hang
