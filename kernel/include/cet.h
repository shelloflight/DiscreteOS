/*
 * CET supervisor shadow stacks (kernel/arch/x86_64/cet.c, docs/hardening.md).
 *
 * Every kernel thread and every IST stack has a shadow stack: the CPU pushes each return address
 * on it as well and faults (#CP) when a `ret` finds a different one on the normal stack, so a
 * kernel stack overwrite can no longer redirect a return.
 */
#ifndef DOS_CET_H
#define DOS_CET_H

#include <stdbool.h>
#include <stdint.h>

struct percpu;
struct thread;

#define MSR_U_CET          0x6A0
#define MSR_S_CET          0x6A2
#define MSR_PL0_SSP        0x6A4
#define MSR_PL3_SSP        0x6A7
#define MSR_ISST           0x6A8        /* IA32_INTERRUPT_SSP_TABLE_ADDR */
#define S_CET_SH_STK_EN    1ull
#define U_CET_SH_STK_EN    1ull
#define CR4_CET            (1ull << 23)

/* Shadow stacks in use: decided once, before any thread. User shadow stacks (ring 3, per
 * process: user/thread.rs) are available exactly when this is set. */
extern bool cet_ss;

/* Boot CPU, after spec_detect, the VMM and the heap, before sched_init: decide, and give the boot
 * CPU its IST shadow stacks. */
void cet_init(void);

/* An AP's IST shadow stacks (smp.c, before it starts). False when out of memory. */
bool cet_cpu_alloc(struct percpu *pc);

/* switch.asm: S_CET on, SSP from the restore token at `restore`; the caller's return address is
 * written into the shadow stack through `ret_slot` (a writable alias) first. */
void cet_ss_enter(uint64_t restore, uint64_t *ret_slot);

/* Halves of cet_cpu_enable (cet.c). */
uint64_t *cet_cpu_prepare(struct percpu *pc, struct thread *t, uint64_t *restore);
void cet_cpu_enabled(struct percpu *pc);

/* Switch shadow stacks on for this CPU, on thread t's shadow stack (interrupts off). Inlined into
 * a function that never returns (kmain, ap_main): the frames above it were made without a shadow
 * stack, so nothing may return into them. Only cet_ss_enter's own return address (into that
 * function) is put on the new shadow stack. */
static inline __attribute__((always_inline)) void cet_cpu_enable(struct percpu *pc, struct thread *t)
{
    uint64_t restore;
    uint64_t *slot = cet_cpu_prepare(pc, t, &restore);
    cet_ss_enter(restore, slot);
    cet_cpu_enabled(pc);
}

/* sched.c: a shadow stack in a stack-region slot (0: a new one) for thread t (NULL: an IST
 * stack). Returns its supervisor token, or 0 when out of memory. */
uint64_t shstk_new(struct thread *t, uint64_t slot, uint64_t first_ret);

void cet_print(void);
/* S3 resume: write a restore token below `ssp`, restore CET MSRs on BSP, and return token VA. */
uint64_t cet_bsp_wake_token(uint64_t ssp);
/* S3 resume: reset an AP idle thread's shadow stack restore token before `cet_cpu_enable`. */
void cet_ap_reset(struct thread *idle);

#endif
