/*
 * Spinlocks (C API; Rust wraps the same struct in kernel/rust/src/sync.rs).
 *
 *   spin_lock / spin_unlock                  plain lock (caller guarantees no IRQ handler takes it)
 *   spin_lock_irqsave / spin_unlock_irqrestore   lock with local interrupts off (safe against IRQs)
 *
 * Every lock has a name and a rank (lock-order class). Locks must be taken in strictly increasing rank
 * (spin_trylock is exempt: it cannot deadlock, which lets the scheduler take another CPU's run queue).
 * Holding a spinlock disables preemption (per-CPU count); dropping the last one is a preemption point.
 * Always on:   self-deadlock detection (a CPU re-taking a lock it holds) and a stuck-lock timeout
 *              on the contended path, both panic with the lock's name (fail closed, no silent hang).
 *              A CPU spinning on a lock still answers TLB shootdown requests (smp_poll), so a CPU that
 *              waits for a shootdown while holding a lock can never deadlock with it.
 * Test builds: lock-order validation (LOCKDEP), unlock-by-non-owner checks, held locks listed on panic.
 *
 * Layout is part of the C/Rust ABI (kernel/rust/src/ffi.rs); keep both in sync.
 */
#ifndef DOS_SPINLOCK_H
#define DOS_SPINLOCK_H

#include <stdbool.h>
#include <stdint.h>

typedef struct spinlock {
    volatile uint32_t locked;   /* 0 = free, 1 = held */
    uint32_t          owner;    /* holder's CPU number + 1 (0 = none) */
    uint32_t          rank;     /* lock-order class, see LOCK_RANK_* */
    uint32_t          reserved;
    const char       *name;
} spinlock_t;

_Static_assert(sizeof(spinlock_t) == 24, "spinlock_t layout is shared with Rust");

/* Lock order (outermost first). A lock may only be taken while every held lock has a lower rank. */
enum {
    LOCK_RANK_TEST    = 5,      /* ktest-only locks */
    LOCK_RANK_CHANNELS = 6,     /* Rust: registry of live channel ends (cycle collection; queues nest inside) */
    LOCK_RANK_DEVICE  = 7,      /* Rust device layer: one device's state (may allocate, then IOMMU/PCI) */
    LOCK_RANK_OBJECT  = 8,      /* Rust object layer: handle tables, VMARs (never nested) */
    LOCK_RANK_PROC_THREADS = 9, /* Rust: a process's list of user threads */
    LOCK_RANK_HEAP    = 10,
    LOCK_RANK_KSTACK  = 15,     /* kernel-stack address allocator */
    LOCK_RANK_USPACE  = 18,     /* a user address space's page tables (taken under its VMAR lock) */
    LOCK_RANK_VMM     = 20,
    LOCK_RANK_TLB     = 22,     /* TLB shootdown (one at a time, system-wide) */
    LOCK_RANK_IOMMU   = 25,     /* Rust: an IOMMU unit's tables and registers (takes the PMM lock) */
    LOCK_RANK_PCI     = 26,     /* Rust: legacy PCI configuration ports */
    LOCK_RANK_PMM     = 30,
    LOCK_RANK_PORT    = 33,     /* Rust: a port's rings (posted from signal updates, no wait queue held) */
    LOCK_RANK_INTR    = 34,     /* a thread's interruptible-wait state (thread_interrupt) */
    LOCK_RANK_WAITQ   = 35,    /* wait queues inside mutex/semaphore/event */
    LOCK_RANK_THREADS = 37,     /* list of all threads */
    LOCK_RANK_SCHED   = 40,     /* per-CPU run queue */
    LOCK_RANK_TIMER   = 45,
    LOCK_RANK_CONSOLE = 50,
    LOCK_RANK_KLOG    = 60,
    LOCK_RANK_LEAF    = 100,    /* takes no other lock while held */
};

#define SPINLOCK_INIT(n, r) { .locked = 0, .owner = 0, .rank = (r), .reserved = 0, .name = (n) }

void     spin_lock(spinlock_t *l);
void     spin_unlock(spinlock_t *l);
bool     spin_trylock(spinlock_t *l);
uint64_t spin_lock_irqsave(spinlock_t *l);                  /* returns saved RFLAGS */
void     spin_unlock_irqrestore(spinlock_t *l, uint64_t flags);
bool     spin_trylock_irqsave(spinlock_t *l, uint64_t *flags);
/* Scheduler only: unlock + restore without the preemption check (it is already switching). */
void     spin_unlock_irqrestore_noresched(spinlock_t *l, uint64_t flags);
bool     spin_held_by_me(const spinlock_t *l);

/* Number of locks the current CPU holds (tracked in test builds; 0 otherwise). */
unsigned spin_held_count(void);
/* Print the held-lock stack (test builds; called from the panic path). */
void     spin_dump_held(void);

/* Current CPU number, from the per-CPU block (GS base, see percpu.h; installed before kmain). */
static inline uint32_t this_cpu(void)
{
    uint32_t id;
    __asm__ volatile("movl %%gs:8, %0" : "=r"(id));
    return id;
}

#endif
