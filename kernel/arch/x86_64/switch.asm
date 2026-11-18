; =============================================================================
; Kernel thread context switch.
;   void context_switch(uint64_t *save_rsp, uint64_t new_rsp)
; Saves the callee-saved registers on the current stack, stores RSP into *save_rsp, switches to
; new_rsp and restores the registers saved there. Everything else is caller-saved under the SysV
; ABI, and the kernel uses no FPU/SSE state, so this is the complete thread context.
; Called with interrupts off and the run-queue lock held (kernel/sched/sched.c).
; A new thread's stack is pre-built as: r15 r14 r13 r12 rbx rbp (all 0) | thread_start | 0.
;
; RSB filling (MIT_RSB, spec.c: CPUs that rely on retpolines): the return stack buffer is
; overwritten with 32 harmless entries before the new thread's first `ret`, so a return can never
; use a prediction left by another thread, or fall back to the (user-trainable) branch predictor
; when the buffer runs empty.
; =============================================================================

%define PC_MITIG 60              ; offsetof(struct percpu, mitig)
%define MIT_RSB  8               ; spec.h

[bits 64]

section .text
global context_switch

context_switch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    test byte [gs:PC_MITIG], MIT_RSB
    jz .switch
    mov ecx, 16                     ; 16 x 2 calls = 32 RSB entries
.fill:
    call .one
    int3                            ; speculation only: never returned to
.one:
    call .two
    int3
.two:
    dec ecx
    jnz .fill
    add rsp, 32 * 8                 ; drop the 32 return addresses
.switch:
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
