/*
 * Per-CPU data, reached through the GS base (IA32_GS_BASE).
 *
 * The boot CPU's block is static and installed by entry.asm before any C code runs, so every lock
 * and every `current` lookup works from the first instruction of kmain. Each AP gets its own block
 * (one page, so no two CPUs share a cache line) from smp.c before it starts. Hot fields are read
 * with one GS-relative instruction (`current`, CPU number, preemption count), which is atomic with
 * respect to interrupts and migration.
 *
 * KPTI (kernel/arch/x86_64/spec.c): each block is exactly one page, mapped into the user page
 * tables too, because the entry code reads it (GS-relative) before switching to the kernel's page
 * tables. It holds scheduler state and pointers, never user data or keys.
 */
#ifndef DOS_PERCPU_H
#define DOS_PERCPU_H

#include <stddef.h>
#include <stdint.h>
#include "arch.h"
#include "cpupm.h"
#include "ktime.h"
#include "thread.h"

#define MSR_FS_BASE        0xC0000100
#define MSR_GS_BASE        0xC0000101
#define MSR_KERNEL_GS_BASE 0xC0000102

#define MAX_CPUS           64           /* affinity and shootdown masks are 64-bit */
#define LOCKDEP_DEPTH      16

struct percpu {
    struct percpu  *self;            /* 0:  GS:0 -> this block */
    uint32_t        cpu_id;          /* 8:  logical CPU number (0 = boot CPU) */
    uint32_t        preempt_count;   /* 12: spinlocks held (+ explicit preempt_disable) */
    struct thread  *current;         /* 16: running thread (NULL until the scheduler runs here) */
    uint32_t        irq_depth;       /* 24: >0 while in an interrupt handler */
    uint32_t        need_resched;    /* 28: set when a better thread is ready */
    uint32_t        ipi_pending;     /* 32: IPI_* reasons, set by other CPUs (atomic) */
    uint32_t        apic_id;         /* 36 */

    bool            online;
    uint32_t        tlb_lazy;        /* 1 while halted in idle: shootdowns skip it (see smp.c) */
    uint32_t        tlb_stale;       /* a shootdown skipped it: flush everything when leaving idle */
    uint32_t        idle_polling;    /* idle and polling need_resched: wake-ups need no IPI */
    uint32_t        cur_prio;        /* priority of `current` (0 for idle), read by other CPUs */
    uint32_t        mitig;           /* 60: MIT_* entry/exit mitigations on this CPU (spec.h) */
    uint64_t        kstack_top;      /* 64: `current`'s kernel stack top (SYSCALL entry, TSS.RSP0) */
    uint64_t        user_rsp;        /* 72: user RSP while the SYSCALL entry switches stacks */
    uint64_t        cr3;             /* 80: page tables loaded on this CPU (0 = not tracked yet) */
    uint64_t        entry_top;       /* 88: top of this CPU's entry stack (KPTI: TSS.RSP0) */
    uint64_t        user_cr3;        /* 96: KPTI: the user page tables of `uspace` (exit to ring 3) */
    uint64_t        entry_cr3;       /* 104: KPTI: CR3 found on the last interrupt from ring 3 (tests) */
    uint64_t        ss_token;        /* 112: shadow stacks: the running user thread's supervisor
                                      * shadow-stack token (IA32_PL0_SSP), cleared on exit to ring 3 */
    uint64_t        u_cet;           /* IA32_U_CET as last written here (shadow stacks) */
    uint64_t        last_uid;        /* id of the user address space that ran last here (IBPB) */
    struct uspace  *uspace;          /* user address space loaded (NULL: the kernel's) */
    struct runqueue rq;
    struct thread  *idle;
    struct thread  *switched_from;   /* set before a switch; read by the thread switched to */
    struct thread  *post_list;       /* switched-out threads with work left (exit, migration) */
    struct ktimer   slice_timer;     /* round-robin preemption; armed only when needed */
    uint64_t        slice_end_ns;    /* when the current thread's slice ends */
    struct timer_base timers;        /* this CPU's timers (ktime.c) */
    struct interrupt_frame *irq_frame;   /* innermost interrupt frame (watchdog backtraces) */

    /* watchdog (smp.c) */
    struct ktimer   wd_timer;
    volatile uint64_t wd_beat_ns;    /* last heartbeat; stale = this CPU stopped taking interrupts */
    uint64_t        wd_switches;     /* `switches` at the last heartbeat */
    uint64_t        wd_stuck_since;  /* soft lockup: no switch while equal/higher work waits */
    bool            wd_reported;

    /* descriptor tables (gdt.c) */
    uint64_t        gdt[GDT_ENTRIES] __attribute__((aligned(16)));
    struct tss      tss __attribute__((aligned(16)));
    uint64_t        ist_guard[IST_COUNT];   /* guard page below each IST stack (APs) */
    uint64_t        ssp_table[8] __attribute__((aligned(8)));   /* shadow stacks: IA32_INTERRUPT_SSP_TABLE
                                      * (entry n = the token of IST n's shadow stack; 0 unused) */

    /* lock-order checking, test builds (spinlock.c) */
    const struct spinlock *held[LOCKDEP_DEPTH];
    uint32_t        held_n;

    /* idle states (cpupm.c) */
    uint64_t        idle_avg_ns;     /* recent idle periods (moving average): what the next may be */
    uint64_t        idle_count[CPUPM_MAX_CSTATES], idle_ns[CPUPM_MAX_CSTATES];

    /* stats */
    uint64_t        switches, preemptions, irqs, timer_irqs, ipis, steals, tlb_flushes;
};

_Static_assert(offsetof(struct percpu, self) == 0, "percpu layout (GS:0)");
_Static_assert(offsetof(struct percpu, cpu_id) == 8, "percpu layout");
_Static_assert(offsetof(struct percpu, preempt_count) == 12, "percpu layout");
_Static_assert(offsetof(struct percpu, current) == 16, "percpu layout");
_Static_assert(offsetof(struct percpu, irq_depth) == 24, "percpu layout");
_Static_assert(offsetof(struct percpu, need_resched) == 28, "percpu layout");
_Static_assert(offsetof(struct percpu, ipi_pending) == 32, "percpu layout");
_Static_assert(offsetof(struct percpu, tlb_lazy) == 44, "TLB_LAZY_OFFSET in smp.h");
_Static_assert(offsetof(struct percpu, kstack_top) == 64, "PC_KSTACK in syscall.asm");
_Static_assert(offsetof(struct percpu, user_rsp) == 72, "PC_USER_RSP in syscall.asm");
_Static_assert(offsetof(struct percpu, mitig) == 60, "PC_MITIG in isr.asm / syscall.asm");
_Static_assert(offsetof(struct percpu, entry_top) == 88, "PC_ENTRY_TOP in isr.asm");
_Static_assert(offsetof(struct percpu, cr3) == 80, "PC_CR3 in isr.asm / syscall.asm");
_Static_assert(offsetof(struct percpu, user_cr3) == 96, "PC_USER_CR3 in isr.asm / syscall.asm");
_Static_assert(offsetof(struct percpu, entry_cr3) == 104, "PC_ENTRY_CR3 in isr.asm");
_Static_assert(offsetof(struct percpu, ss_token) == 112, "PC_SS_TOKEN in isr.asm / syscall.asm");
/* The rest of the page is this CPU's entry stack (KPTI: TSS.RSP0, mapped in the user page tables):
 * at least 1 KiB for an interrupt frame and the frame of a fault on the IRETQ back to ring 3. */
#define PERCPU_ENTRY_STACK_MIN 1024
_Static_assert(sizeof(struct percpu) <= 4096 - PERCPU_ENTRY_STACK_MIN, "per-CPU block + entry stack: one page");

/* The boot CPU's block: a page of its own, like an AP's (KPTI maps it for user mode). */
union percpu_page {
    struct percpu pc;
    uint8_t       page[4096];
};
_Static_assert(sizeof(union percpu_page) == 4096, "one page");
extern union percpu_page bsp_percpu_page;
#define bsp_percpu (bsp_percpu_page.pc)
extern struct percpu *cpus[MAX_CPUS];       /* by CPU number; NULL where no CPU was started */
extern uint32_t       cpu_slots;            /* entries of cpus[] in use (online or not) */

static inline struct percpu *percpu(void)
{
    struct percpu *p;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(p));
    return p;
}

static inline struct thread *current_thread(void)
{
    struct thread *t;
    __asm__ volatile("movq %%gs:16, %0" : "=r"(t));
    return t;
}

static inline uint32_t percpu_cpu_id(void)
{
    uint32_t id;
    __asm__ volatile("movl %%gs:8, %0" : "=r"(id));
    return id;
}

static inline uint32_t percpu_irq_depth(void)
{
    uint32_t d;
    __asm__ volatile("movl %%gs:24, %0" : "=r"(d));
    return d;
}

/* Note: a thread can migrate between any two statements unless interrupts or preemption are off.
 * Use the single-instruction accessors above, or disable interrupts before calling percpu(). */
static inline void preempt_disable(void) { __asm__ volatile("incl %%gs:12" ::: "memory"); }
static inline void preempt_enable_no_resched(void) { __asm__ volatile("decl %%gs:12" ::: "memory"); }

/* Install `p` as this CPU's per-CPU block (after reloading segment registers, or on an AP). */
void percpu_install(struct percpu *p);

#endif
