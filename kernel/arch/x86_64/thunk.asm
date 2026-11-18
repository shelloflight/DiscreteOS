; =============================================================================
; Retpoline thunk (Spectre v2, kernel/arch/x86_64/spec.c).
; The C kernel (-mretpoline-external-thunk) and the Rust kernel (retpoline-external-thunk) compile
; every indirect call and jump as `call/jmp __x86_indirect_thunk_r11` with the target in R11
; (LLVM always uses R11 in 64-bit code). The thunk reaches the target through a `ret` whose
; prediction is the capture loop below, so the indirect branch predictor (which user code can
; train) is never consulted. On CPUs with eIBRS or AutoIBRS spec_detect overwrites it with a
; plain `jmp r11` at boot.
; =============================================================================

[bits 64]

section .text
global __x86_indirect_thunk_r11
align 32
__x86_indirect_thunk_r11:
    call .set_target                ; pushes .capture; the RSB predicts a return there
.capture:
    pause                           ; speculation lands here and spins harmlessly
    lfence
    jmp .capture
.set_target:
    mov [rsp], r11                  ; the real return address: the branch target
    ret
align 32
