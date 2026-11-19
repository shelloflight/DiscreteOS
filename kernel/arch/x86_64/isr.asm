; =============================================================================
; Interrupt entry stubs for all 256 vectors.
; Each stub pushes a uniform frame (dummy error code where the CPU pushes none, then the vector)
; and jumps to isr_common, which saves all GPRs and calls isr_dispatch(struct interrupt_frame *).
; Layout must match struct interrupt_frame in kernel/include/arch.h.
;
; GS: an interrupt from ring 3 arrives with the user's GS base; SWAPGS installs the per-CPU block
; (and swaps back on the way out). The IST vectors (NMI, #DF, #MC) can also hit the few kernel
; instructions around SWAPGS on the syscall path, where CS says "kernel" but GS is still the
; user's: they look at GS_BASE itself (a kernel address is negative). They never return (panic or
; panic stop), so they need no way back.
;
; KPTI (MIT_KPTI in percpu.mitig, kernel/mm/kpti.c): ring 3 runs on page tables that map only this
; section, the IDT, the per-CPU pages and the IST stacks. An entry from ring 3 lands on the CPU's
; entry stack (top of its per-CPU page, TSS.RSP0), switches to the kernel's page tables
; (percpu.cr3), and moves the CPU's frame to the thread's kernel stack. The exit copies the IRETQ
; frame back to the entry stack before switching to the user tables (percpu.user_cr3).
; MDS/TAA (MIT_VERW): VERW clears CPU buffers right before every return to ring 3.
; CET shadow stacks (MIT_SHSTK, cet.c): an entry from ring 3 makes the CPU switch to the thread's
; shadow stack and mark its supervisor token busy; the IRETQ back to ring 3 clears it, since SSP
; points at that token again by then (user_enter sets it busy first, with SETSSBSY).
; =============================================================================

[bits 64]

%define PC_MITIG      60         ; struct percpu offsets (percpu.h)
%define PC_KSTACK     64
%define PC_USER_RSP   72
%define PC_CR3        80
%define PC_ENTRY_TOP  88
%define PC_USER_CR3   96
%define PC_ENTRY_CR3  104
%define MIT_KPTI      1          ; spec.h
%define MIT_VERW      2
%define GDT_KDATA     0x10

section .entry.text progbits alloc exec nowrite align=4096
extern isr_dispatch

; Vectors where the CPU pushes an error code
%define HAS_ERR(v) ((v) == 8 || (v) == 10 || (v) == 11 || (v) == 12 || (v) == 13 || (v) == 14 || (v) == 17 || (v) == 21 || (v) == 29 || (v) == 30)
%define PARANOID(v) ((v) == 2 || (v) == 8 || (v) == 18)

; KPTI: move [vector][error][rip][cs][rflags][rsp][ss] from the entry stack to the thread's kernel
; stack (interrupts are off: every vector is an interrupt gate). Same alignment as before: the
; stack top is 16-byte aligned and the frame is 7 qwords, like the CPU's (5 + vector + error).
%macro TO_KSTACK 0
    push rax
    mov rax, rsp
    mov rsp, [gs:PC_KSTACK]
    push qword [rax + 56]
    push qword [rax + 48]
    push qword [rax + 40]
    push qword [rax + 32]
    push qword [rax + 24]
    push qword [rax + 16]
    push qword [rax + 8]
    mov rax, [rax]
%endmacro

%assign i 0
%rep 256
isr%[i]:
  %if HAS_ERR(i) == 0
    push qword 0
  %endif
    push qword i
  %if PARANOID(i)
    jmp isr_paranoid
  %else
    jmp isr_common
  %endif
%assign i i+1
%endrep

; NMI, #DF, #MC (IST stacks, never return) and a fault on the IRETQ back to ring 3.
isr_paranoid:
    push rax
    push rcx
    push rdx
    mov ecx, 0xC0000101             ; IA32_GS_BASE
    rdmsr
    test edx, edx
    js .kernel_gs                   ; per-CPU block already installed
    swapgs
.kernel_gs:
    test byte [gs:PC_MITIG], MIT_KPTI
    jz .done
    mov rax, [gs:PC_CR3]            ; the kernel's tables (the user's may be loaded)
    test rax, rax
    jz .done
    mov cr3, rax
    ; A fault on the IRETQ to ring 3 is taken on the entry stack: continue on the thread's stack
    ; (the entry stack belongs to the CPU, and the handler may sleep or exit the thread).
    mov rax, [gs:PC_ENTRY_TOP]
    sub rax, rsp
    cmp rax, 4096
    jae .done
    pop rdx
    pop rcx
    pop rax
    TO_KSTACK
    jmp isr_save
.done:
    pop rdx
    pop rcx
    pop rax
    jmp isr_save

; Stack on entry: [vector][error][rip][cs][rflags][rsp][ss]. The CPU aligned RSP to 16 before
; pushing its 5 qwords; +2 (vector, error) +15 GPRs = 22 qwords -> RSP is 16-byte aligned at the call.
isr_common:
    test byte [rsp + 24], 3         ; CS of the interrupted code
    jnz .from_user
    ; Kernel mode. The one kernel instruction that can fault with the user's GS loaded is the
    ; IRETQ back to ring 3 (a bad user frame): take the per-CPU block back. The handler then kills
    ; the process (user_bad_iret) instead of recursing on a user GS.
    push rax
    lea rax, [rel isr_iret]
    cmp [rsp + 24], rax             ; RIP of the interrupted code (one push deeper)
    pop rax
    jne isr_save
    jmp isr_paranoid                ; rare path: look at GS_BASE itself
.from_user:
    swapgs
    test byte [gs:PC_MITIG], MIT_KPTI
    jz isr_save
    push rax
    mov rax, cr3
    mov [gs:PC_ENTRY_CR3], rax      ; the tables ring 3 ran on (checked by the spec test)
    mov rax, [gs:PC_CR3]
    mov cr3, rax
    pop rax
    TO_KSTACK
isr_save:
    ; SWAPGS speculation (CVE-2019-1125): the CPU may predict the CS test above wrongly and run
    ; ahead with the wrong GS base (skip or execute SWAPGS), leaking through a GS-relative load.
    ; Every path (user, kernel, paranoid) joins here, before the first GS access: fence them all.
    lfence
.clac:
    clac                            ; SMAP closed in the handler, even if a user copy was interrupted
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp
    cld
    call isr_dispatch

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16                     ; vector + error code
    test byte [rsp + 8], 3          ; back to ring 3?
    jnz isr_exit_user
    iretq                           ; kernel to kernel: nothing to switch

; Return to ring 3 from the IRETQ frame [rip][cs][rflags][rsp][ss] at RSP: every register already
; holds the user's value, interrupts are off. Also used by syscall.asm (IRETQ returns, new threads).
global isr_exit_user
isr_exit_user:
    test byte [gs:PC_MITIG], MIT_KPTI
    jz .tables_done
    mov [gs:PC_USER_RSP], rax       ; scratch (only the SYSCALL entry uses it, with interrupts off)
    mov rax, rsp
    mov rsp, [gs:PC_ENTRY_TOP]      ; the thread's stack is not mapped in the user tables
    push qword [rax + 32]
    push qword [rax + 24]
    push qword [rax + 16]
    push qword [rax + 8]
    push qword [rax]
    mov rax, [gs:PC_USER_CR3]
    mov cr3, rax
    mov rax, [gs:PC_USER_RSP]
.tables_done:
    test byte [gs:PC_MITIG], MIT_VERW
    jz .buffers_done
    verw [rel verw_selector]        ; clear CPU buffers (MD_CLEAR); flags come back from the frame
.buffers_done:
    swapgs
global isr_iret
isr_iret:
    iretq

; VERW's operand: any valid selector (the kernel's data segment). In this section, so it is mapped
; in both page tables.
global verw_selector
verw_selector:
    dw GDT_KDATA

; Pointer table: relocated at load (KASLR), so it lives in .data.rel.ro (read-only once mapped).
section .data.rel.ro progbits alloc noexec write align=8
align 8
global isr_stub_table
isr_stub_table:
%assign i 0
%rep 256
    dq isr%[i]
%assign i i+1
%endrep

global isr_smap_site
isr_smap_site:
    dq isr_save.clac
