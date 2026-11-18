; =============================================================================
; D-KRNL 64-bit entry point
; State on entry (from a loader: boot/stage2.asm + stage 3, or boot/uefi):
;   - 64-bit long mode, paging enabled, identity-mapped low memory; the first GiB of physical
;     memory also mapped at the (randomized) base the image was relocated to
;   - RDI = pointer to BootInfo
;   - interrupts disabled
; Position-independent: every address is taken RIP-relative (the image runs wherever KASLR put it).
; =============================================================================

[bits 64]

; --- Kernel image header (struct kernel_header, kernel/include/bootinfo.h): the first 64 bytes of
; kernel.bin. Both loaders take the entry point, load address, sizes and the relocation table from
; here. Every field is an absolute symbol from linker.ld (link-time values), so the header needs no
; relocation itself: a loader that moves the image by D adds D to entry and virt_base.
section .boothdr progbits alloc noexec nowrite align=16
extern __kernel_entry_link
extern __kernel_start_link
extern __kernel_file_size
extern __kernel_mem_size
extern __kernel_relr_offset
extern __kernel_relr_size
global kernel_header
kernel_header:
    dd 0x4E524B44                   ; "DKRN"
    dw 2                            ; version (2: relocatable, RELR table)
    dw 64                           ; size
    dq __kernel_entry_link          ; entry (link-time virtual address)
    dq __kernel_start_link          ; virtual base at link time (KERNEL_LINK_BASE + physical)
    dq 0x100000                     ; physical load address (KERNEL_PHYS in linker.ld)
    dq __kernel_file_size           ; bytes with contents (text, rodata, data)
    dq __kernel_mem_size            ; bytes in memory (.bss included)
    dd __kernel_relr_offset         ; RELR table: offset from the image start
    dd __kernel_relr_size           ; RELR table: bytes
    dq 0

; Own section so the linker script places _start at KERNEL_BASE regardless of object order.
section .text._start progbits alloc exec nowrite align=16
global _start
extern kmain
extern __bss_start
extern __bss_end
extern __stack_chk_guard
extern bsp_percpu_page             ; percpu.c: the boot CPU block (struct percpu at offset 0)
global kernel_entry_tsc

_start:
    cli
    rdtsc                           ; boot timing: first kernel instruction
    shl rdx, 32
    or rax, rdx
    mov r13, rax                    ; keep until .bss is zeroed

    mov r12, rdi                    ; BootInfo* (survives CPUID/RDTSC below)
    lea rsp, [rel stack_top]
    xor rbp, rbp
    cld

    ; --- zero .bss ---------------------------------------------------------------
    lea rdi, [rel __bss_start]
    lea rcx, [rel __bss_end]
    sub rcx, rdi
    xor eax, eax
    rep stosb

    mov [rel kernel_entry_tsc], r13

    ; --- per-CPU block of the boot CPU (GS base): locks and `current` need it from kmain on ---
    lea rax, [rel bsp_percpu_page]
    mov [rax], rax                  ; percpu.self
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000101             ; IA32_GS_BASE
    wrmsr

    ; --- stack protector canary --------------------------------------------------
    ; RDRAND when available (retried, it may transiently fail), else a mixed TSC value.
    ; All-ones and zero are refused even with CF=1: some AMD CPUs return ~0 with CF set
    ; (erratum, e.g. after S3 resume), which would make the canary a known constant.
    mov eax, 1
    cpuid
    bt ecx, 30                      ; CPUID.1:ECX.RDRAND
    jnc .canary_tsc
    mov ecx, 10
.rdrand_retry:
    rdrand rax
    jnc .rdrand_next
    lea rdx, [rax + 1]
    cmp rdx, 1                      ; rax + 1 <= 1  <=>  rax is ~0 or 0
    ja .canary_set
.rdrand_next:
    dec ecx
    jnz .rdrand_retry
.canary_tsc:
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rdx, 0x9E3779B97F4A7C15     ; golden-ratio mix so the value isn't a plain counter
    imul rax, rdx
    xor rax, r13
.canary_set:
    xor al, al                      ; low byte 0: terminator canary
    mov [rel __stack_chk_guard], rax

    mov rdi, r12
    call kmain

.hang:
    cli
    hlt
    jmp .hang

section .data
align 8
kernel_entry_tsc: dq 0

; Boot stack with a guard page below it (left unmapped by the VMM; an overflow faults into it
; and is reported via the #DF IST stack).
section .bss nobits alloc noexec write align=4096
global boot_stack_guard
boot_stack_guard:
    resb 4096
stack_bottom:
    resb 16384
stack_top:
