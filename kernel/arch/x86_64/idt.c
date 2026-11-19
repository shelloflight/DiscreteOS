/* IDT setup and interrupt dispatch. */

#include <stdint.h>
#include "apic.h"
#include "arch.h"
#include "compiler.h"
#include "cpu.h"
#include "panic.h"
#include "ktime.h"
#include "percpu.h"
#include "ktest.h"
#include "profile.h"
#include "smp.h"
#include "spinlock.h"
#include "thread.h"
#include "user.h"

struct PACKED idt_entry {
    uint16_t offset_lo;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_hi;
    uint32_t zero;
};

struct PACKED dtr {
    uint16_t limit;
    uint64_t base;
};

#define GATE_INTERRUPT 0x8E   /* present, DPL0, 64-bit interrupt gate (IF cleared on entry) */

extern const uint64_t isr_stub_table[256];

/* One page of its own: KPTI maps it into the user page tables (the CPU reads it on every entry). */
struct idt_entry idt[256] __attribute__((aligned(4096)));
_Static_assert(sizeof(idt) == 4096, "the IDT is one page");
static irq_handler_t    handlers[256];

static void idt_set(uint8_t vec, uint64_t handler, uint8_t ist)
{
    idt[vec] = (struct idt_entry){
        .offset_lo  = (uint16_t)handler,
        .selector   = GDT_KCODE,
        .ist        = ist,
        .type_attr  = GATE_INTERRUPT,
        .offset_mid = (uint16_t)(handler >> 16),
        .offset_hi  = (uint32_t)(handler >> 32),
        .zero       = 0,
    };
}

void idt_init(void)
{
    for (int v = 0; v < 256; v++)
        idt_set((uint8_t)v, isr_stub_table[v], 0);

    /* INT3 may be used from ring 3 (breakpoints, __debugbreak in Windows programs, SIGTRAP on
     * Linux): it raises #BP, a trap delivered like any user fault. Every other software INT from
     * ring 3 is still a #GP. */
    idt[3].type_attr = GATE_INTERRUPT | 0x60;
    idt[2].ist  = IST_NMI;
    idt[8].ist  = IST_DOUBLE_FAULT;
    idt[18].ist = IST_MACHINE_CHECK;
    idt_load();
}

void idt_load(void)
{
    /* Computed at run time: as a constant the compiler would emit a packed template whose
     * unaligned pointer needs a load-time relocation the RELR format cannot express. */
    uint64_t base = (uint64_t)(uintptr_t)idt;
    __asm__("" : "+r"(base));
    struct dtr idtr = { sizeof(idt) - 1, base };
    __asm__ volatile("lidt %0" : : "m"(idtr) : "memory");
}

void interrupt_register(uint8_t vector, irq_handler_t h)
{
    KASSERT(vector >= 32);
    handlers[vector] = h;
}

/* ---- device interrupt vectors (MSI/MSI-X, I/O APIC lines given to user-space drivers) ---------
 * Allocated from [VEC_DEV_BASE, VEC_DEV_END); each one is delivered to the boot CPU and handed to
 * the Rust device layer (dkrnl_dev_irq), which signals the interrupt object bound to it. */
void dkrnl_dev_irq(uint32_t vector);            /* kernel/rust/src/dev/irq.rs */

static spinlock_t vec_lk = SPINLOCK_INIT("irq.vectors", LOCK_RANK_LEAF);
static uint64_t   vec_used[(VEC_DEV_END - VEC_DEV_BASE + 63) / 64];

static void dev_irq(struct interrupt_frame *f) { dkrnl_dev_irq((uint32_t)f->vector); }

/* Interrupts on a vector nothing was ever set up for (with interrupt remapping, none can come
 * from a device: the drivers test checks this stays 0 after a forged interrupt). */
uint64_t irq_unexpected;
uint64_t irq_unexpected_last;    /* the last such vector (diagnostics) */

int irq_vector_alloc(void)
{
    int v = -1;
    uint64_t fl = spin_lock_irqsave(&vec_lk);
    for (int i = 0; i < VEC_DEV_END - VEC_DEV_BASE; i++) {
        if (!(vec_used[i / 64] & (1ull << (i % 64)))) {
            vec_used[i / 64] |= 1ull << (i % 64);
            v = VEC_DEV_BASE + i;
            break;
        }
    }
    spin_unlock_irqrestore(&vec_lk, fl);
    if (v >= 0)
        handlers[v] = dev_irq;
    return v;
}

void irq_vector_free(int v)
{
    KASSERT(v >= VEC_DEV_BASE && v < VEC_DEV_END);
    int i = v - VEC_DEV_BASE;
    uint64_t fl = spin_lock_irqsave(&vec_lk);
    KASSERT(vec_used[i / 64] & (1ull << (i % 64)));
    vec_used[i / 64] &= ~(1ull << (i % 64));
    spin_unlock_irqrestore(&vec_lk, fl);
}

void isr_dispatch(struct interrupt_frame *f)
{
    uint64_t v = f->vector;
    tlb_lazy_exit();                              /* woken from idle: flush first if a shootdown skipped us */
#ifdef KTEST_SPEC
    if (f->cs & 3)
        ktest_spec_user_entry();                  /* which page tables ring 3 ran on (KPTI) */
#endif

    if (v < 32) {
        if (v != 2 && v != 8 && v != 18 && (f->cs & 3)) {
            user_fault(f);                        /* handled (resume), or the process dies */
            user_return_check(f);
            return;
        }
        user_bad_iret_check(f);                   /* IRETQ to a bad user frame: the process dies */
        if (user_copy_fixup_try(f))
            return;                               /* bad user pointer: user_copy returns an error */
        if (msr_fixup_try(f))
            return;                               /* missing MSR: msr_read_safe / msr_write_safe fail */
        exception_handler(f);
    }

    if (v == VEC_SPURIOUS)
        return;                                   /* spurious APIC interrupt: no EOI */
    if (v >= VEC_PIC_BASE && v < VEC_PIC_BASE + 16)
        return;                                   /* masked legacy PIC can still raise spurious IRQs */

    struct percpu *pc = percpu();
    struct interrupt_frame *outer = pc->irq_frame;
    pc->irq_frame = f;                            /* watchdog: what this CPU was doing */
    pc->irq_depth++;
    pc->irqs++;
    uint64_t t0 = __atomic_load_n(&profile_active, __ATOMIC_RELAXED) ? time_ns() : 0;
    if (handlers[v])
        handlers[v](f);
    else
        __atomic_fetch_add(&irq_unexpected, 1, __ATOMIC_RELAXED), irq_unexpected_last = v;
    if (t0)
        lat_record(&lat_irq, time_ns() - t0);
    lapic_eoi();
    pc->irq_depth--;
    pc->irq_frame = outer;
    sched_preempt_irq();                          /* interrupt exit is a preemption point */
    user_return_check(f);                         /* back to ring 3: a killed thread ends here */
}
