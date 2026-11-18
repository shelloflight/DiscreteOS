; =============================================================================
; D-OS UEFI loader: hand-off to the kernel (copied by loader.c to a low, identity-mapped page and
; called there after ExitBootServices; position-independent).
;
;   RCX = struct handoff* (loader.c): +0 BootInfo, +8 CR3, +16 entry, +24 stack, +32 GDT descriptor
;
; Leaves the machine as stage 2 does: our GDT (0x08 code32, 0x10 data, 0x18 code64), our page
; tables, interrupts off, RDI = &BootInfo. CR4.PGE and PCIDE are cleared first, so no global TLB
; entry of the firmware's page tables survives the switch (the kernel turns PGE on again).
; =============================================================================

bits 64
default rel
section .text

global handoff_start
global handoff_end

handoff_start:
    cli
    mov rsi, rcx
    lgdt [rsi + 32]
    mov rax, cr4
    and rax, ~((1 << 7) | (1 << 17))    ; PGE, PCIDE off (flushes every TLB entry)
    mov cr4, rax
    mov rax, [rsi + 8]
    mov cr3, rax                        ; this page is identity-mapped in the new tables too
    mov rsp, [rsi + 24]
    push qword 0x18                     ; CS = code64 of our GDT
    lea rax, [.reload]
    push rax
    o64 retf
.reload:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov rdi, [rsi]                      ; BootInfo*
    mov rax, [rsi + 16]                 ; kernel entry (higher half)
    xor ebp, ebp
    jmp rax
handoff_end:
