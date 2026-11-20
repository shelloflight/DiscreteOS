; =============================================================================
; ACPI S3 suspend entry and BSP wake entry.
;
;   int s3_enter(uint64_t pm1a_addr, uint16_t pm1a_val,
;                uint64_t pm1b_addr, uint16_t pm1b_val, uint32_t mmio_mask)
;
; Called on the BSP with interrupts off and all APs parked. Saves BSP CPU state
; (callee-saved GPRs, RSP, RFLAGS, CR0/CR3/CR4, EFER, FS/GS/KERNEL_GS bases, and
; CET SSP and S_CET when shadow stacks are active), flushes caches (WBINVD), and
; writes PM1b/PM1a twice: SLP_TYP alone, then SLP_TYP | SLP_EN. The values come
; from power.c and keep the register's other bits (SCI_EN above all).
;
; On S3 wake, firmware jumps to the real-mode trampoline at TRAMPOLINE_PHYS
; (0x8000), which enters 64-bit long mode and jumps to `s3_wake_entry64`. That
; restores control registers, MSR bases and RSP, has `s3_resume_cpu` (power.c)
; reload GDT, TR, IDT and the per-CPU MSRs, and only then turns shadow stacks
; back on: the GDT reload uses a far return, which a live shadow stack would
; reject (#CP), and with no IDT yet that is a triple fault inside the firmware's
; resume path. Returns 0 to `power_suspend()` as if `s3_enter` had returned
; normally. If hardware fails to enter S3, `s3_enter` returns -1 with no CPU
; state touched.
; =============================================================================

default rel
[bits 64]

%define MSR_EFER           0xC0000080
%define MSR_FS_BASE        0xC0000100
%define MSR_GS_BASE        0xC0000101
%define MSR_KERNEL_GS_BASE 0xC0000102
%define MSR_S_CET          0x6A2
%define CR4_CET            (1 << 23)
%define SLP_EN             (1 << 13)

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
s3_s_cet:          resq 1

section .text
global s3_enter, s3_wake_entry64
extern cet_ss, s3_resume_cpu

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
    RDMSR64 MSR_S_CET, s3_s_cet
.no_save_cet:

    ; Step 1: SLP_TYP without SLP_EN (PM1b first when present), then flush, then step 2.
    test r14, r14
    jz .typ_a
    mov rdx, r14
    mov eax, r15d
    and eax, ~SLP_EN
    mov ecx, ebx
    shr ecx, 1
    call s3_pm1_write
.typ_a:
    mov rdx, r12
    mov eax, r13d
    and eax, ~SLP_EN
    mov ecx, ebx
    call s3_pm1_write

    wbinvd

    test r14, r14
    jz .en_a
    mov rdx, r14
    mov eax, r15d
    mov ecx, ebx
    shr ecx, 1
    call s3_pm1_write
.en_a:
    mov rdx, r12
    mov eax, r13d
    mov ecx, ebx
    call s3_pm1_write

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

; RDX = I/O port or mapped MMIO address, AX = value, ECX bit 0 = MMIO.
s3_pm1_write:
    test ecx, 1
    jnz .mmio
    out dx, ax
    ret
.mmio:
    mov [rdx], ax
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

    ; GDT, TR, IDT, PAT, XCR0, syscall and mitigation MSRs (C, shadow stacks still off).
    ; RSP % 16 == 8 (return address on stack); align to 16 before the call.
    sub rsp, 8
    mov rdi, [s3_ssp]
    call s3_resume_cpu              ; returns the restore token VA (0 without shadow stacks)
    add rsp, 8

    cmp byte [cet_ss], 0
    je .no_restore_cet
    mov r8, rax                     ; token VA, kept across wrmsr
    mov rdx, [s3_cr4]
    mov cr4, rdx                    ; enables CR4.CET
    WRMSR64 MSR_S_CET, s3_s_cet
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
