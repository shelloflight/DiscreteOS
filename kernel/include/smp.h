/*
 * Multi-core support (kernel/arch/x86_64/smp.c, trampoline.asm).
 *
 *   Bring-up:   every enabled CPU in the ACPI MADT is started with INIT-SIPI-SIPI through a
 *               real-mode trampoline below 1 MiB; each gets its own GDT/TSS/IST stacks, LAPIC
 *               timer, per-CPU block and idle thread.
 *   IPIs:       one vector (VEC_IPI) with reason bits in the target's per-CPU block.
 *   TLB:        unmapping kernel memory flushes it on every online CPU before the frames are reused
 *               (synchronous shootdown). CPUs spinning with interrupts off still answer (smp_poll).
 *   Panic:      the panicking CPU stops all others with an NMI before printing.
 *   Watchdog:   each CPU sends a heartbeat every second; a CPU silent for 5 s (interrupts off, hung)
 *               is reported with an NMI backtrace and a panic. A CPU that stops switching while
 *               equal-priority work waits (preemption disabled too long) gets a soft-lockup warning.
 */
#ifndef DOS_SMP_H
#define DOS_SMP_H

#include <stdbool.h>
#include <stdint.h>
#include "arch.h"
#include "bootinfo.h"
#include "compiler.h"

#define IPI_RESCHED (1u << 0)    /* run the scheduler (sched_ipi) */
#define IPI_TLB     (1u << 1)    /* answer the current TLB shootdown request */
#define TLB_LAZY_OFFSET 44       /* offsetof(struct percpu, tlb_lazy), checked in percpu.h */

void     smp_init(const BootInfo *bi);   /* boot CPU, after sched_init: start the APs */
bool     smp_active(void);               /* more than one CPU online */
uint32_t smp_cpus(void);                 /* CPUs online */
uint64_t smp_online_mask(void);
void     smp_send(uint32_t target, uint32_t reason);   /* IPI to one CPU (no-op for this CPU) */
void     smp_print(void);
uint64_t smp_shootdowns(void);           /* TLB shootdowns that interrupted other CPUs (stats) */
uint64_t smp_lazy_skips(void);           /* idle CPUs a shootdown did not have to interrupt */

/* Flush [va, va + pages * 4 KiB) from every other online CPU's TLB, and wait until they have.
 * The caller has already changed the page tables and flushed its own TLB. */
void     tlb_shootdown(uint64_t va, uint64_t pages);
/* The same for the CPUs in `which` only (a user address space: the CPUs that have it loaded). */
void     tlb_shootdown_cpus(uint64_t va, uint64_t pages, uint64_t which);
void     tlb_flush_local(uint64_t va, uint64_t pages);

/* Lazy TLB for idle CPUs: an idle CPU marks itself lazy before halting; shootdowns then skip it
 * (no IPI to wake it) and mark it stale instead, and it flushes its whole TLB on the first
 * interrupt, before the handler runs. tlb_lazy_exit() is called at interrupt entry. */
void     tlb_lazy_enter(void);
void     tlb_lazy_exit_slow(void);
static inline void tlb_lazy_exit(void)
{
    uint32_t lazy;
    __asm__ volatile("movl %%gs:%c1, %0" : "=r"(lazy) : "i"(TLB_LAZY_OFFSET));
    if (UNLIKELY(lazy))
        tlb_lazy_exit_slow();
}

/* Answer pending TLB shootdowns. Called from loops that spin with interrupts off. */
void     smp_poll_slow(void);
static inline void smp_poll(void)
{
    uint32_t pending;
    __asm__ volatile("movl %%gs:32, %0" : "=r"(pending));
    if (UNLIKELY(pending & IPI_TLB))
        smp_poll_slow();
}

/* Panic support: stop every other CPU (NMI); a CPU picked by the watchdog prints its backtrace
 * first. smp_nmi() is the NMI handler during a panic (does not return). */
void     smp_stop_others(void);
void     smp_dump_target(void);          /* after smp_stop_others: let the picked CPU report */
bool     smp_nmi(struct interrupt_frame *f);

/* Fault reports: "double-fault stack of CPU 2" etc. for AP IST guard pages. */
const char *smp_guard_name(uint64_t va, uint32_t *cpu_out);

#endif
