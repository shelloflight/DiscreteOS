; =============================================================================
; ACPI S3 suspend entry and BSP wake entry.
;
;   int s3_enter(uint64_t pm1a_addr, uint16_t pm1a_val,
;                uint64_t pm1b_addr, uint16_t pm1b_val, uint32_t mmio_mask)
;
; Called on the BSP with interrupts off and all APs parked. Saves BSP CPU state
; (callee-saved GPRs, RSP, RFLAGS, CR0/CR3/CR4, EFER, FS/GS/KERNEL_GS bases, and
; CET SSP when shadow stacks are active), flushes caches (WBINVD), and writes
; SLP_TYP | SLP_EN to PM1b/PM1a.
;
; On S3 wake, firmware jumps to the real-mode trampoline at TRAMPOLINE_PHYS
; (0x8000), which enters 64-bit long mode and jumps to `s3_wake_entry64`. That
; restores all saved CPU state and returns 0 to `power_suspend()` as if
; `s3_enter` had returned normally. If hardware fails to enter S3, `s3_enter`
; returns -1.
; =============================================================================

default rel
[bits 64]

%define MSR_EFER           0xC0000080
%define MSR_FS_BASE        0xC0000100
%define MSR_GS_BASE        0xC0000101
%define MSR_KERNEL_GS_BASE 0xC0000102
%define MSR_S_CET          0x6A2
%define CR4_CET            (1 << 23)

section .bss
align 8
s3_rsp:            resq 1
s3_rbx:            resq 1
s3_rbp:            resq 1
s3_r12:            resq 1
s3_r13:            resq 1
s3_r14:            resq 1
s3_r15:            resq 1
s3_rflags:         resq 1
s3_cr0:            resq 1
s3_cr3:            resq 1
s3_cr4:            resq 1
s3_efer:           resq 1
s3_fs_base:        resq 1
s3_gs_base:        resq 1
s3_kernel_gs_base: resq 1
s3_ssp:            resq 1

section .text
global s3_enter, s3_wake_entry64
extern cet_ss, cet_bsp_wake_token

%macro RDMSR64 2
    mov ecx, %1
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [%2], rax
%endmacro

%macro WRMSR64 2
    mov rax, [%2]
    mov rdx, rax
    shr rdx, 32
    mov ecx, %1
    wrmsr
%endmacro

s3_enter:
    ; Save callee-saved registers and stack pointer (pointing at return address).
    mov [s3_rsp], rsp
    mov [s3_rbx], rbx
    mov [s3_rbp], rbp
    mov [s3_r12], r12
    mov [s3_r13], r13
    mov [s3_r14], r14
    mov [s3_r15], r15
    pushfq
    pop rax
    mov [s3_rflags], rax

    ; Stash arguments across RDMSR/CR reads (we already saved rbx, r12-r15).
    mov r12, rdi                    ; pm1a_addr
    mov r13, rsi                    ; pm1a_val
    mov r14, rdx                    ; pm1b_addr
    mov r15, rcx                    ; pm1b_val
    mov ebx, r8d                    ; mmio_mask

    mov rax, cr0
    mov [s3_cr0], rax
    mov rax, cr3
    mov [s3_cr3], rax
    mov rax, cr4
    mov [s3_cr4], rax

    RDMSR64 MSR_EFER, s3_efer
    RDMSR64 MSR_FS_BASE, s3_fs_base
    RDMSR64 MSR_GS_BASE, s3_gs_base
    RDMSR64 MSR_KERNEL_GS_BASE, s3_kernel_gs_base

    cmp byte [cet_ss], 0
    je .no_save_cet
    rdsspq rax
    mov [s3_ssp], rax
.no_save_cet:

    wbinvd

    ; Write PM1b_CNT first if present (ACPI 6.5, 16.1.6).
    test r14, r14
    jz .do_pm1a
    test ebx, 2
    jnz .pm1b_mmio
    mov rdx, r14
    mov rax, r15
    out dx, ax
    jmp .do_pm1a
.pm1b_mmio:
    mov [r14], r15w

.do_pm1a:
    test ebx, 1
    jnz .pm1a_mmio
    mov rdx, r12
    mov rax, r13
    out dx, ax
    jmp .wait_sleep
.pm1a_mmio:
    mov [r12], r13w

.wait_sleep:
    ; Give the chipset a short window to power down; if S3 does not happen, return -1.
    mov ecx, 20000000
.spin:
    pause
    dec ecx
    jnz .spin

    mov rbx, [s3_rbx]
    mov rbp, [s3_rbp]
    mov r12, [s3_r12]
    mov r13, [s3_r13]
    mov r14, [s3_r14]
    mov r15, [s3_r15]
    mov eax, -1
    ret

; -----------------------------------------------------------------------------
; Reached from trampoline.asm (lm64) after S3 wake. Interrupts are off, paging
; is on via TRAMP_PML4 (identity 0..2 MiB + kernel upper half).
; -----------------------------------------------------------------------------
s3_wake_entry64:
    mov rax, [s3_cr3]
    mov cr3, rax                    ; back to the saved page tables

    WRMSR64 MSR_EFER, s3_efer

    mov rax, [s3_cr0]
    mov cr0, rax

    ; Restore CR4 without CR4.CET first so we can prepare the shadow-stack token safely.
    mov rax, [s3_cr4]
    and rax, ~CR4_CET
    mov cr4, rax

    WRMSR64 MSR_GS_BASE, s3_gs_base
    WRMSR64 MSR_KERNEL_GS_BASE, s3_kernel_gs_base
    WRMSR64 MSR_FS_BASE, s3_fs_base

    mov rsp, [s3_rsp]

    cmp byte [cet_ss], 0
    je .no_restore_cet
    ; RSP % 16 == 8 (return address on stack); align to 16 before the C helper call.
    sub rsp, 8
    mov rdi, [s3_ssp]
    call cet_bsp_wake_token         ; writes restore token & CET MSRs, returns token VA in RAX
    add rsp, 8
    mov rdx, [s3_cr4]
    mov cr4, rdx                    ; enables CR4.CET
    mov ecx, MSR_S_CET
    mov r8, rax                     ; preserve token VA across wrmsr
    mov eax, 1                      ; SH_STK_EN
    xor edx, edx
    wrmsr
    rstorssp [r8]
    mov eax, 1
    incsspq rax                     ; pop previous-SSP token -> SSP == s3_ssp
.no_restore_cet:

    mov rax, [s3_rflags]
    push rax
    popfq

    mov rbx, [s3_rbx]
    mov rbp, [s3_rbp]
    mov r12, [s3_r12]
    mov r13, [s3_r13]
    mov r14, [s3_r14]
    mov r15, [s3_r15]
    xor eax, eax                    ; return 0 (resumed cleanly)
    ret
