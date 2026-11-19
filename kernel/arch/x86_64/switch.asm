; =============================================================================
; Kernel thread context switch.
;   void context_switch(uint64_t *save_rsp, uint64_t new_rsp, uint64_t *save_ssp, uint64_t new_ssp)
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
;
; CET shadow stacks (MIT_SHSTK, cet.c): the shadow stack is switched with the thread. RSTORSSP
; takes the restore token left on the next thread's shadow stack (by SAVEPREVSSP when it was
; switched out, or by shstk_new for a new thread, above thread_start); SAVEPREVSSP leaves one on
; this thread's. Its `ret` then finds the same return address on both stacks. The RSB filling's
; calls are popped from the shadow stack too (INCSSP).
; =============================================================================

%define PC_MITIG  60             ; offsetof(struct percpu, mitig)
%define MIT_RSB   8              ; spec.h
%define MIT_SHSTK 16
%define MSR_S_CET 0x6A2          ; cet.h

[bits 64]

section .text
global context_switch, cet_ss_enter

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
    mov eax, 16                     ; 16 x 2 calls = 32 RSB entries
.fill:
    call .one
    int3                            ; speculation only: never returned to
.one:
    call .two
    int3
.two:
    dec eax
    jnz .fill
    add rsp, 32 * 8                 ; drop the 32 return addresses
    test byte [gs:PC_MITIG], MIT_SHSTK
    jz .switch
    mov eax, 32
    incsspq rax                     ; and from the shadow stack
.switch:
    test byte [gs:PC_MITIG], MIT_SHSTK
    jz .stack
    rdsspq rax                      ; this thread's SSP (its `ret` address is on top)
    rstorssp [rcx]                  ; the next thread's shadow stack
    saveprevssp                     ; restore token for this one, just below its SSP
    sub rax, 8
    mov [rdx], rax                  ; where that token is: the next switch back takes it
.stack:
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; void cet_ss_enter(uint64_t restore, uint64_t *ret_slot)  (cet.h: cet_cpu_enable)
; Shadow stacks on for this CPU (CR4.CET is set, interrupts are off). Until RSTORSSP, SSP is 0 and
; nothing may call or return. Our own return address goes into the shadow stack first, through a
; writable alias of the slot above the restore token, so the `ret` below matches; the frames of
; the caller's callers are not on it and are never returned to.
cet_ss_enter:
    mov rax, [rsp]
    mov [rsi], rax
    mov ecx, MSR_S_CET
    mov eax, 1                      ; SH_STK_EN
    xor edx, edx
    wrmsr
    rstorssp [rdi]                  ; SSP -> the restore token (now a previous-SSP token)
    mov eax, 1
    incsspq rax                     ; pop it: SSP -> our return address
    ret
