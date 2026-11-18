/*
 * Monotonic clock and timer callbacks (see ktime.h).
 *
 * Clock: ns = ((tsc - epoch) * mult) >> 32, mult = 2^32 * 1e9 / tsc_hz (precomputed; no division
 * in the hot path). Epoch is the kernel-entry TSC, so timestamps read as "time since boot".
 *
 * Timers: one list per CPU (in its per-CPU block), sorted by deadline, protected by that CPU's
 * IRQ-safe timer lock. Tickless: each CPU's APIC timer is programmed for the head of its own list
 * only (apic.c), so interrupts happen exactly when a timer is due and never otherwise. A timer is
 * armed on the CPU that starts it; cancelling works from any CPU (it locks the timer's base).
 */

#include <stdint.h>
#include "apic.h"
#include "cpu.h"
#include "ktime.h"
#include "panic.h"
#include "percpu.h"
#include "smp.h"
#include "spinlock.h"

static uint64_t mult;        /* 0 until time_init(): time_ns() returns 0 */

void time_init(void)
{
    KASSERT(tsc_hz);
    mult = (NS_PER_S << 32) / tsc_hz;
}

uint64_t time_cycles_to_ns(uint64_t cycles)
{
    return (uint64_t)(((unsigned __int128)cycles * mult) >> 32);
}

uint64_t time_ns(void)
{
    return time_cycles_to_ns(rdtsc() - kernel_entry_tsc);
}

uint64_t time_us(void) { return time_ns() / NS_PER_US; }

/* ---- timers ------------------------------------------------------------------------ */

/* Point this CPU's hardware at its earliest deadline (base lock held, base is this CPU's). */
static void rearm(struct timer_base *b, bool force)
{
    uint64_t next = b->head ? b->head->deadline_ns : TIMER_NONE;
    if (force || next != b->programmed) {
        b->programmed = next;
        timer_program(next);
    }
}

static void enqueue(struct timer_base *b, struct ktimer *t)
{
    struct ktimer **pp = &b->head;
    while (*pp && (*pp)->deadline_ns <= t->deadline_ns)
        pp = &(*pp)->next;
    t->next = *pp;
    *pp = t;
    t->base = b;
    t->queued = true;
}

static void dequeue(struct timer_base *b, struct ktimer *t)
{
    for (struct ktimer **pp = &b->head; *pp; pp = &(*pp)->next) {
        if (*pp == t) {
            *pp = t->next;
            break;
        }
    }
    t->next = NULL;
    t->queued = false;
}

static void start(struct ktimer *t, uint64_t delay_ns, uint64_t period_ns, ktimer_fn fn, void *ctx)
{
    KASSERT(fn);
    uint64_t f = irq_save();                      /* stay on this CPU while choosing its base */
    struct timer_base *mine = &percpu()->timers;
    struct timer_base *old = t->base;
    if (old && old != mine) {                     /* last armed on another CPU: take it off there */
        spin_lock(&old->lock);
        if (t->queued && t->base == old)
            dequeue(old, t);
        spin_unlock(&old->lock);
    }
    spin_lock(&mine->lock);
    if (t->queued)
        dequeue(mine, t);
    t->fn = fn;
    t->ctx = ctx;
    t->period_ns = period_ns;
    t->deadline_ns = time_ns() + delay_ns;
    t->pending = true;
    enqueue(mine, t);
    rearm(mine, false);
    spin_unlock_irqrestore(&mine->lock, f);
}

void timer_start_oneshot(struct ktimer *t, uint64_t delay_ns, ktimer_fn fn, void *ctx)
{
    start(t, delay_ns, 0, fn, ctx);
}

void timer_start_periodic(struct ktimer *t, uint64_t period_ns, ktimer_fn fn, void *ctx)
{
    KASSERT(period_ns);
    start(t, period_ns, period_ns, fn, ctx);
}

static bool cancel(struct ktimer *t, bool sync)
{
    struct timer_base *b = t->base;
    if (!b)
        return false;                             /* never started */
    uint64_t f = spin_lock_irqsave(&b->lock);
    bool was = t->pending;
    if (t->queued)
        dequeue(b, t);
    t->pending = false;
    if (b == &percpu()->timers)
        rearm(b, false);                          /* another CPU's hardware just fires early, harmlessly */
    bool wait = sync && b->running == t && b != &percpu()->timers;
    spin_unlock_irqrestore(&b->lock, f);

    /* The callback is running on another CPU right now: wait for it to return. */
    if (wait) {
        while (__atomic_load_n(&b->running, __ATOMIC_ACQUIRE) == t) {
            cpu_pause();
            smp_poll();
        }
    }
    return was;
}

bool timer_cancel(struct ktimer *t) { return cancel(t, false); }
bool timer_cancel_sync(struct ktimer *t) { return cancel(t, true); }

void time_tick(void)
{
    struct timer_base *b = &percpu()->timers;     /* interrupt context: interrupts are off */
    uint64_t now = time_ns();
    spin_lock(&b->lock);
    while (b->head && b->head->deadline_ns <= now) {
        struct ktimer *t = b->head;
        dequeue(b, t);
        t->pending = t->period_ns != 0;           /* one-shot: done; periodic: stays armed */
        b->running = t;

        spin_unlock(&b->lock);                    /* callback runs without the lock (may re-arm/cancel) */
        t->fn(t, t->ctx);
        spin_lock(&b->lock);
        __atomic_store_n(&b->running, NULL, __ATOMIC_RELEASE);

        if (t->period_ns && t->pending && !t->queued && t->base == b) {
            t->deadline_ns += t->period_ns;       /* drift-free; skip missed periods instead of bursting */
            if (t->deadline_ns <= now)
                t->deadline_ns = now + t->period_ns;
            enqueue(b, t);
        }
    }
    rearm(b, true);                               /* the hardware event was consumed */
    spin_unlock(&b->lock);
}
