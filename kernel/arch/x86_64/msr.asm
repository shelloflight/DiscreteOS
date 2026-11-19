; =============================================================================
; MSR access that survives a missing MSR (cpu.h: msr_read_safe, msr_write_safe).
;
; Firmware tables name MSRs (ACPI _CPC and _PCT registers in "functional fixed hardware"), and a
; CPU may not have the one named. RDMSR/WRMSR of an MSR that does not exist (or a value the CPU
; refuses) raises #GP. The fault path (msr_fixup_try, cpu.c) sees that it happened on one of the
; two instructions below and resumes that same instruction (the return address of a kernel-mode
; IRETQ must match the shadow stack's copy under CET, so it may not move): R8 = 1 tells the
; function it failed, and ECX now names an MSR every x86-64 CPU has, which the instruction reads
; (the TSC) or writes back unchanged (IA32_FMASK, with its current value in EDX:EAX).
; =============================================================================

[bits 64]

section .text
global msr_read_safe, msr_write_safe, msr_insn_read, msr_insn_write

; bool msr_read_safe(uint32_t msr, uint64_t *value)
msr_read_safe:
    mov ecx, edi
    xor r8d, r8d                    ; 1 after a #GP (msr_fixup_try)
msr_insn_read:
    rdmsr
    test r8d, r8d
    jnz .fail
    shl rdx, 32
    mov eax, eax
    or rax, rdx
    mov [rsi], rax
    mov eax, 1
    ret
.fail:
    xor eax, eax
    ret

; bool msr_write_safe(uint32_t msr, uint64_t value)
msr_write_safe:
    mov ecx, edi
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    xor r8d, r8d
msr_insn_write:
    wrmsr
    xor eax, eax
    test r8d, r8d
    sete al
    ret
