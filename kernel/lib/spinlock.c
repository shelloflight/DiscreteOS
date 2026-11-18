/*
 * Spinlocks: test-and-test-and-set with PAUSE. Fast path is one XCHG; everything else
 * (self-deadlock check, stuck timeout) lives on the contended path, so it costs nothing uncontended.
 * Test builds (-DKTEST) add LOCKDEP: a per-CPU held-lock stack that enforces the rank order.
 * Waiting CPUs answer TLB shootdowns (smp_poll), so spinning with interrupts off can't deadlock
 * against a CPU that waits for our flush while holding the lock.
 * Every held spinlock counts in the per-CPU preemption count (GS:12); releasing the last one is a
 * preemption point (a higher-priority thread woken meanwhile runs right away).
 */

#include <stdint.h>
#include "compiler.h"
#include "cpu.h"
#include "panic.h"
#include "printf.h"
#include "spinlock.h"
#include "percpu.h"
#include "smp.h"

#define RFLAGS_IF (1ull << 9)

/* A lock held for this long is a bug (deadlock, lost unlock). Seconds of TSC; generous for emulators. */
#define STUCK_SECONDS 5
#define STUCK_FALLBACK_CYCLES (1ull << 34)

#if defined(KTEST) && !defined(KTEST_HWBENCH)   /* hwbench: release lock costs */
#define LOCKDEP 1
/* The held-lock stack is per CPU (percpu.h): a lock is held by a CPU, and a thread switches out
 * holding exactly its run queue lock, which the next thread on that CPU releases. */

static void lockdep_acquire(const spinlock_t *l, bool trylock)
{
    if (panic_in_progress())
        return;
    struct percpu *pc = percpu();
    for (unsigned i = 0; i < pc->held_n; i++)
        if (pc->held[i] == l)
            panic("spinlock self-deadlock: '%s' is already held by this CPU", l->name);
    if (!trylock)                                    /* a trylock never waits, so it cannot deadlock */
        for (unsigned i = 0; i < pc->held_n; i++)
            if (pc->held[i]->rank >= l->rank)
                panic("lock order violation: acquiring '%s' (rank %u) while holding '%s' (rank %u)",
                      l->name, l->rank, pc->held[i]->name, pc->held[i]->rank);
    if (pc->held_n == LOCKDEP_DEPTH)
        panic("lockdep: more than %d locks held", LOCKDEP_DEPTH);
    pc->held[pc->held_n++] = l;
}

static void lockdep_release(const spinlock_t *l)
{
    if (panic_in_progress())
        return;
    struct percpu *pc = percpu();
    for (unsigned i = pc->held_n; i-- > 0;) {
        if (pc->held[i] == l) {
            for (unsigned j = i; j + 1 < pc->held_n; j++)
                pc->held[j] = pc->held[j + 1];
            pc->held_n--;
            return;
        }
    }
    panic("lockdep: releasing '%s', which this CPU does not hold", l->name);
}

unsigned spin_held_count(void) { return percpu()->held_n; }

void spin_dump_held(void)
{
    struct percpu *pc = percpu();
    if (!pc->held_n)
        return;
    kprintf("Held locks (innermost last):\n");
    for (unsigned i = 0; i < pc->held_n; i++)
        kprintf("  %s (rank %u)\n", pc->held[i]->name, pc->held[i]->rank);
}
#else
#define LOCKDEP 0
static inline void lockdep_acquire(const spinlock_t *l, bool trylock) { (void)l; (void)trylock; }
static inline void lockdep_release(const spinlock_t *l) { (void)l; }
unsigned spin_held_count(void) { return 0; }
void spin_dump_held(void) {}
#endif

static inline bool try_acquire(spinlock_t *l)
{
    return __atomic_exchange_n(&l->locked, 1u, __ATOMIC_ACQUIRE) == 0;
}

static NOINLINE void spin_contended(spinlock_t *l)
{
    uint32_t me = this_cpu() + 1;
    if (__atomic_load_n(&l->owner, __ATOMIC_RELAXED) == me && !panic_in_progress())
        panic("spinlock self-deadlock: '%s' is already held by this CPU", l->name);

    uint64_t limit = tsc_hz ? tsc_hz * STUCK_SECONDS : STUCK_FALLBACK_CYCLES;
    uint64_t start = rdtsc();
    do {
        while (__atomic_load_n(&l->locked, __ATOMIC_RELAXED)) {
            cpu_pause();
            smp_poll();                  /* the holder may be waiting for our TLB flush */
            if (rdtsc() - start > limit && !panic_in_progress())
                panic("spinlock stuck: '%s' held by CPU %u for over %d s", l->name,
                      __atomic_load_n(&l->owner, __ATOMIC_RELAXED) - 1, STUCK_SECONDS);
        }
    } while (!try_acquire(l));
}

void spin_lock(spinlock_t *l)
{
    preempt_disable();
    if (LOCKDEP)
        lockdep_acquire(l, false);
    if (UNLIKELY(!try_acquire(l)))
        spin_contended(l);
    __atomic_store_n(&l->owner, this_cpu() + 1, __ATOMIC_RELAXED);
}

bool spin_trylock(spinlock_t *l)
{
    preempt_disable();
    if (!try_acquire(l)) {
        preempt_enable_no_resched();
        return false;
    }
    if (LOCKDEP)
        lockdep_acquire(l, true);
    __atomic_store_n(&l->owner, this_cpu() + 1, __ATOMIC_RELAXED);
    return true;
}

/* Cheap test first: only call into the scheduler when a reschedule is pending. */
static inline void maybe_preempt(void)
{
    uint32_t pending;
    __asm__ volatile("movl %%gs:28, %0" : "=r"(pending));
    if (UNLIKELY(pending))
        preempt_check();
}

static inline void unlock_raw(spinlock_t *l)
{
    if (LOCKDEP) {
        if (l->owner != this_cpu() + 1 && !panic_in_progress())
            panic("unlock of spinlock '%s', which this CPU does not hold", l->name);
        lockdep_release(l);
    }
    __atomic_store_n(&l->owner, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&l->locked, 0u, __ATOMIC_RELEASE);
    preempt_enable_no_resched();
}

void spin_unlock(spinlock_t *l)
{
    unlock_raw(l);
    maybe_preempt();
}

uint64_t spin_lock_irqsave(spinlock_t *l)
{
    uint64_t flags;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(flags) : : "memory");
    spin_lock(l);
    return flags;
}

void spin_unlock_irqrestore(spinlock_t *l, uint64_t flags)
{
    unlock_raw(l);
    if (flags & RFLAGS_IF) {
        cpu_sti();
        maybe_preempt();
    }
}

void spin_unlock_irqrestore_noresched(spinlock_t *l, uint64_t flags)
{
    unlock_raw(l);
    if (flags & RFLAGS_IF)
        cpu_sti();
}

bool spin_held_by_me(const spinlock_t *l)
{
    return l->locked && l->owner == this_cpu() + 1;
}

bool spin_trylock_irqsave(spinlock_t *l, uint64_t *flags)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(f) : : "memory");
    if (spin_trylock(l)) {
        *flags = f;
        return true;
    }
    if (f & RFLAGS_IF)
        cpu_sti();
    return false;
}
