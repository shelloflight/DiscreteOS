/* x86-64 descriptor tables, interrupt vectors and the interrupt frame. */
#ifndef DOS_ARCH_H
#define DOS_ARCH_H

#include <stdint.h>
#include "compiler.h"

/* GDT selectors. Order matters for SYSCALL/SYSRET (STAR): kernel code, kernel data, user data, user code. */
#define GDT_KCODE 0x08
#define GDT_KDATA 0x10
#define GDT_UDATA 0x18
#define GDT_UCODE 0x20
#define GDT_TSS   0x28

/* IST slots (TSS.IST1..3): separate known-good stacks for faults that can hit a broken stack. */
#define IST_DOUBLE_FAULT 1
#define IST_NMI          2
#define IST_MACHINE_CHECK 3

/* Interrupt vector layout */
#define VEC_TIMER       0x20        /* Local APIC timer */
#define VEC_IRQ_BASE    0x30        /* ISA IRQ n (via I/O APIC) -> 0x30 + n */
#define VEC_DEV_BASE    0x40        /* device interrupts (MSI/MSI-X, user-driver IRQ lines): */
#define VEC_DEV_END     0xE0        /*   [VEC_DEV_BASE, VEC_DEV_END), irq_vector_alloc() */
#define VEC_PIC_BASE    0xE0        /* legacy PIC remapped here and masked (spurious only) */
#define VEC_IPI         0xF0        /* inter-processor interrupt (reason bits in percpu.ipi_pending) */
#define VEC_APIC_ERROR  0xFE
#define VEC_SPURIOUS    0xFF

/* Register state pushed by isr.asm (lowest address first). */
struct interrupt_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector, error;
    uint64_t rip, cs, rflags, rsp, ss;   /* pushed by the CPU */
};

typedef void (*irq_handler_t)(struct interrupt_frame *f);

/* 64-bit TSS: stacks for privilege changes and the IST stacks. One per CPU (in its per-CPU block). */
struct PACKED tss {
    uint32_t reserved0;
    uint64_t rsp[3];        /* stacks for privilege changes (ring 3 -> 0 uses rsp[0]) */
    uint64_t reserved1;
    uint64_t ist[7];        /* IST1..IST7 */
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
};
_Static_assert(sizeof(struct tss) == 104, "TSS layout");

#define GDT_ENTRIES 7       /* null, kcode, kdata, udata, ucode, TSS (2 slots) */
#define IST_COUNT   3

struct percpu;
void gdt_init(void);                                         /* boot CPU */
void gdt_init_cpu(struct percpu *pc, const uint64_t ist_top[IST_COUNT]);   /* load this CPU's GDT + TSS */
void gdt_resume_cpu(struct percpu *pc);                      /* S3: reload GDT, clear TSS busy, reload LTR + SYSCALL */
void idt_init(void);
void idt_load(void);                                         /* APs: load the shared IDT */
void backtrace_print(uint64_t rip, uint64_t rbp);             /* frame-pointer backtrace (exceptions.c) */
void interrupt_register(uint8_t vector, irq_handler_t h);
/* A free device vector (its handler calls the Rust device layer), or -1; and back. */
extern uint64_t irq_unexpected;    /* interrupts on a vector with no handler */
extern uint64_t irq_unexpected_last;
int  irq_vector_alloc(void);
void irq_vector_free(int vector);

void isr_dispatch(struct interrupt_frame *f);                 /* called from isr.asm */
NORETURN void exception_handler(struct interrupt_frame *f);   /* CPU exceptions 0-31 */

void pic_disable(void);

#endif
