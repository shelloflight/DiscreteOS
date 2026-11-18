/* Per-CPU blocks (see percpu.h). The boot CPU's block is installed by entry.asm; APs get theirs
 * from smp.c. */

#include <stdint.h>
#include "cpu.h"
#include "percpu.h"

/* A whole page, like an AP's block: KPTI maps it into the user page tables (percpu.h), and
 * nothing else may share that page. */
__attribute__((aligned(4096))) union percpu_page bsp_percpu_page = { .pc = {
    .rq     = { .lock = SPINLOCK_INIT("sched", LOCK_RANK_SCHED) },
    .timers = TIMER_BASE_INIT,
} };

struct percpu *cpus[MAX_CPUS] = { &bsp_percpu };
uint32_t       cpu_slots = 1;

void percpu_install(struct percpu *p)
{
    p->self = p;
    wrmsr(MSR_GS_BASE, (uint64_t)(uintptr_t)p);
    wrmsr(MSR_KERNEL_GS_BASE, 0);    /* user GS (SWAPGS) */
}
