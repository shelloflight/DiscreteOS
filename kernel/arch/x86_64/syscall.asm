; =============================================================================
; Ring 3 entry and exit (see kernel/arch/x86_64/user.c).
;
;   syscall_entry   SYSCALL lands here (IA32_LSTAR). Interrupts are off (IA32_FMASK clears IF,
;                   TF, DF, AC, NT, IOPL). Builds a struct interrupt_frame (arch.h) on the thread's
;                   kernel stack, so syscalls, interrupts and faults from user mode all look alike,
;                   and calls syscall_dispatch (Rust), which puts the result in frame.rax. It
;                   returns 0 to go back with SYSRET, or 1 when the registers were replaced
;                   (exception return, forwarded syscall): then every register comes back from
;                   the frame through the interrupt exit path (IRETQ), since SYSRET clobbers RCX
;                   and R11.
;   user_enter      first entry of a new user thread into ring 3 (IRETQ).
;   user_enter_frame first entry with every register from a frame (after a START exception).
;   user_copy       copy_from_user / copy_to_user: the only code that touches user memory, with
;                   SMAP opened (STAC) just for the copy. A page fault inside it is fixed up by the
;                   exception handler (user_copy_fault -> user_copy_fixup), so a bad user pointer
;                   is an error code, never a kernel crash.
;
; GS: in the kernel GS_BASE is the per-CPU block; in user mode it is 0 and KERNEL_GS_BASE holds
; the per-CPU block. SWAPGS on every entry from and exit to ring 3.
;
; KPTI and VERW (isr.asm header, spec.c): the SYSCALL entry switches to the kernel's page tables
; before touching the kernel stack; SYSRET switches back to the user's last (after the final
; kernel memory access) and clears CPU buffers. The entry and exit code is in .entry.text, the
; only kernel code mapped in the user page tables.
; =============================================================================

[bits 64]

%define PC_KSTACK    64          ; offsetof(struct percpu, kstack_top)   (percpu.h)
%define PC_USER_RSP  72          ; offsetof(struct percpu, user_rsp)
%define PC_MITIG     60          ; offsetof(struct percpu, mitig)
%define PC_CR3       80          ; offsetof(struct percpu, cr3)
%define PC_USER_CR3  96          ; offsetof(struct percpu, user_cr3)
%define MIT_KPTI     1           ; spec.h
%define MIT_VERW     2
%define UCODE        0x23        ; GDT_UCODE | 3
%define UDATA        0x1B        ; GDT_UDATA | 3
%define USER_TOP     0x00007FFFFFFF0000
%define VEC_SYSCALL  0x100       ; frame.vector of a syscall (not an IDT vector)
; RFLAGS bits user mode may keep: CF PF AF ZF SF TF DF OF AC ID (never IOPL, NT, VM, ...)
%define USER_FLAGS   0x240DD5

; struct interrupt_frame offsets
%define F_RAX   112
%define F_RIP   136
%define F_RFLAGS 152
%define F_RSP   160

section .entry.text progbits alloc exec nowrite align=4096
extern syscall_dispatch
extern user_bad_return
extern isr_exit_user
extern verw_selector

global syscall_entry
syscall_entry:
    swapgs
    mov [gs:PC_USER_RSP], rsp
    test byte [gs:PC_MITIG], MIT_KPTI
    jz .kernel_tables
    mov rsp, [gs:PC_CR3]            ; RSP is free here: the kernel's page tables
    mov cr3, rsp
.kernel_tables:
    mov rsp, [gs:PC_KSTACK]
    push qword UDATA                ; ss
    push qword [gs:PC_USER_RSP]     ; rsp
    push r11                        ; rflags (saved by SYSCALL)
    push qword UCODE                ; cs
    push rcx                        ; rip (saved by SYSCALL)
    push qword 0                    ; error
    push qword VEC_SYSCALL          ; vector
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
    xor ebp, ebp                    ; backtraces stop here, never follow a user frame pointer
    mov rdi, rsp
    sti
    call syscall_dispatch           ; may not return (thread exit); otherwise frame.rax = result
    cli
    test rax, rax
    jnz syscall_restore
    ; fall through: return to user mode with SYSRET

; Return to ring 3 from the frame at RSP (interrupts off). SYSRET clobbers RCX and R11, which
; SYSCALL clobbered already. A RIP at or above USER_TOP can never come from a SYSCALL (nothing can
; be mapped there), and SYSRET to a non-canonical RIP would fault in ring 0 with the user's RSP:
; refuse it.
syscall_return:
    mov rcx, [rsp + F_RIP]
    mov rax, USER_TOP
    cmp rcx, rax
    jae .bad
    mov r11, [rsp + F_RFLAGS]
    and r11, USER_FLAGS
    or r11, 0x202                   ; IF + reserved bit 1
    mov r15, [rsp + 0]
    mov r14, [rsp + 8]
    mov r13, [rsp + 16]
    mov r12, [rsp + 24]
    mov r10, [rsp + 40]
    mov r9,  [rsp + 48]
    mov r8,  [rsp + 56]
    mov rbp, [rsp + 64]
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    mov rdx, [rsp + 88]
    mov rbx, [rsp + 104]
    mov rax, [rsp + F_RSP]
    mov [gs:PC_USER_RSP], rax
    mov rax, [rsp + F_RAX]
    test byte [gs:PC_MITIG], MIT_KPTI   ; flags are free: SYSRET takes RFLAGS from R11
    jz .tables_done
    mov rsp, [gs:PC_USER_CR3]       ; the kernel stack is gone from here on
    mov cr3, rsp
.tables_done:
    mov rsp, [gs:PC_USER_RSP]
    test byte [gs:PC_MITIG], MIT_VERW
    jz .buffers_done
    verw [rel verw_selector]
.buffers_done:
    swapgs
    o64 sysret
.bad:
    mov rdi, rsp
    sti
    call user_bad_return            ; kills the thread; does not return
    ud2

; Return to ring 3 with every register from the frame (interrupts off). The frame's CS and SS are
; the user selectors this entry pushed; RIP, RSP and RFLAGS were validated by the kernel. A bad
; frame faults on isr_iret, where the fault path kills the process (user_bad_iret_check).
syscall_restore:
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
    jmp isr_exit_user               ; KPTI, VERW, SWAPGS, IRETQ

; void user_enter(uint64_t rip, uint64_t rsp, uint64_t arg0, uint64_t arg1)
; New user thread: ring 3 at rip with rsp, arg0 in RDI, arg1 in RSI, every other register 0.
global user_enter
user_enter:
    cli
    push qword UDATA                ; ss
    push rsi                        ; rsp
    push qword 0x202                ; rflags: IF
    push qword UCODE                ; cs
    push rdi                        ; rip
    mov rdi, rdx
    mov rsi, rcx
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    jmp isr_exit_user

; void user_enter_frame(const struct interrupt_frame *f)
; New user thread whose supervisor set its registers (START exception): the frame (on this
; thread's kernel stack, validated by the caller, user CS/SS) is popped by syscall_restore.
global user_enter_frame
user_enter_frame:
    cli
    mov rsp, rdi
    jmp syscall_restore

section .text

; uint64_t user_copy(void *dst, const void *src, uint64_t n)
; Returns the number of bytes NOT copied (0 = success). The caller has checked that the user side
; of the range lies below USER_TOP. STAC/CLAC are NOPed at boot on CPUs without SMAP (user.c).
global user_copy, user_copy_fault, user_copy_fixup
user_copy:
    mov rcx, rdx
user_copy_stac:
    stac
user_copy_fault:                    ; the only instruction that may fault on a user address
    rep movsb
user_copy_fixup:                    ; a fault above resumes here with RCX = bytes left
user_copy_clac:
    clac
    mov rax, rcx
    ret

; Addresses of every STAC/CLAC (patched to NOPs when the CPU has no SMAP).
; Pointer table: relocated at load (KASLR), so it lives in .data.rel.ro (read-only once mapped).
section .data.rel.ro progbits alloc noexec write align=8
global smap_sites, smap_sites_end
smap_sites:
    dq user_copy_stac
    dq user_copy_clac
smap_sites_end:
