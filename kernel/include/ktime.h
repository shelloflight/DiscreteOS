/*
 * Time API (kernel/ktime.c).
 *
 * Monotonic clock: TSC-based, counted from kernel entry, never goes backwards. Returns 0 until the
 * TSC is calibrated (tsc_init). Cost: one RDTSC + one 64x64->128 multiply (no division).
 *
 * Timers: one-shot or periodic callbacks, tickless: the APIC timer fires exactly at the earliest
 * deadline (TSC-deadline mode, else LAPIC one-shot), so resolution is microseconds, not a tick.
 * The caller owns the `struct ktimer` (no allocation). Callbacks run in interrupt context with
 * interrupts off and no locks held: keep them short. A periodic timer may cancel itself from its
 * callback.
 *
 * Per CPU: every CPU has its own timer list and programs only its own LAPIC timer. A timer is armed
 * on the CPU that starts it, and its callback runs there. It may be cancelled from any CPU; the
 * caller must not start the same timer from two CPUs at once.
 */
#ifndef DOS_KTIME_H
#define DOS_KTIME_H

#include <stdbool.h>
#include <stdint.h>

#define NS_PER_US 1000ull
#define NS_PER_MS 1000000ull
#define NS_PER_S  1000000000ull

void     time_init(void);       /* after tsc_init(): sets up the cycles -> ns conversion */
uint64_t time_ns(void);
uint64_t time_us(void);
uint64_t time_cycles_to_ns(uint64_t cycles);

#include "spinlock.h"

struct ktimer;
typedef void (*ktimer_fn)(struct ktimer *t, void *ctx);

/* One CPU's timers (lives in its per-CPU block). */
struct timer_base {
    spinlock_t     lock;
    struct ktimer *head;         /* sorted by deadline, earliest first */
    uint64_t       programmed;   /* deadline this CPU's timer hardware is set for */
    struct ktimer *running;      /* callback being run right now (timer_cancel_sync waits for it) */
};

#define TIMER_BASE_INIT { SPINLOCK_INIT("timers", LOCK_RANK_TIMER), 0, UINT64_MAX, 0 }

struct ktimer {
    struct ktimer     *next;
    uint64_t           deadline_ns;
    uint64_t           period_ns;   /* 0 = one-shot */
    ktimer_fn          fn;
    void              *ctx;
    struct timer_base *base;        /* CPU it was last armed on */
    bool               pending;     /* armed (also true while a periodic callback runs) */
    bool               queued;      /* internal: linked into the timer list */
};

_Static_assert(sizeof(struct ktimer) == 56, "ktimer layout is shared with Rust (RawKtimer)");

void timer_start_oneshot(struct ktimer *t, uint64_t delay_ns, ktimer_fn fn, void *ctx);
void timer_start_periodic(struct ktimer *t, uint64_t period_ns, ktimer_fn fn, void *ctx);
bool timer_cancel(struct ktimer *t);   /* true if it was still pending */
/* timer_cancel, and if the callback is running on another CPU right now, wait until it returns.
 * Afterwards the callback no longer touches anything. Not from the timer's own callback. */
bool timer_cancel_sync(struct ktimer *t);

void time_tick(void);                  /* called from the APIC timer interrupt (this CPU's timers) */

#endif
