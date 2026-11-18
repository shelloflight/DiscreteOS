/*
 * Wait queues and the blocking primitives built on them (see wait.h).
 *
 * Lock order: a wait queue lock (rank 35) is taken first, then a run queue lock (40, to wake).
 * Timeouts: the timer callback runs on the CPU the thread blocked on, possibly while a waker on
 * another CPU wakes it. Both take the wait queue lock and only the one that still finds the thread
 * on the queue wakes it (and an atomic state change makes the wake itself exclusive). The woken
 * thread cancels its own timer synchronously (sched_block), so a callback never outlives the wait.
 */

#include <stdint.h>
#include "panic.h"
#include "percpu.h"
#include "thread.h"
#include "wait.h"

/* ---- wait queues ------------------------------------------------------------------------- */

static void wq_append(struct waitq *wq, struct thread *t)
{
    t->wq = wq;
    t->wq_next = NULL;
    t->wq_prev = wq->tail;
    if (wq->tail)
        wq->tail->wq_next = t;
    else
        wq->head = t;
    wq->tail = t;
}

static void wq_remove(struct waitq *wq, struct thread *t)
{
    if (t->wq_prev)
        t->wq_prev->wq_next = t->wq_next;
    else
        wq->head = t->wq_next;
    if (t->wq_next)
        t->wq_next->wq_prev = t->wq_prev;
    else
        wq->tail = t->wq_prev;
    t->wq = NULL;
    t->wq_next = t->wq_prev = NULL;
}

static uint64_t deadline_of(uint64_t timeout_ns)
{
    if (timeout_ns == WAIT_FOREVER)
        return 0;
    uint64_t now = time_ns();
    return timeout_ns > UINT64_MAX - now ? 0 : now + timeout_ns;
}

int waitq_wait(struct waitq *wq, uint64_t flags, uint64_t deadline_ns)
{
    struct thread *cur = current_thread();
    if (cur->intr_wq == wq && __atomic_load_n(&cur->kill, __ATOMIC_SEQ_CST)) {
        spin_unlock_irqrestore(&wq->lock, flags);   /* killed before it could block */
        return WAIT_INTERRUPTED;
    }
    cur->timeout_wq = deadline_ns ? wq : NULL;     /* read by the timeout callback, stable until we return */
    wq_append(wq, cur);
    int r = sched_block(&wq->lock, flags, deadline_ns);
    cur->timeout_wq = NULL;
    return r;
}

struct thread *waitq_wake_one(struct waitq *wq)
{
    struct thread *t = wq->head;
    if (!t)
        return NULL;
    wq_remove(wq, t);
    sched_wake(t, WAIT_OK);
    return t;
}

unsigned waitq_wake_if(struct waitq *wq, bool (*match)(const struct thread *w, const void *ctx), const void *ctx)
{
    unsigned n = 0;
    for (struct thread *t = wq->head, *next; t; t = next) {
        next = t->wq_next;
        if (match(t, ctx)) {
            wq_remove(wq, t);
            sched_wake(t, WAIT_OK);
            n++;
        }
    }
    return n;
}

unsigned waitq_wake_all(struct waitq *wq)
{
    unsigned n = 0;
    while (waitq_wake_one(wq))
        n++;
    return n;
}

unsigned waitq_wake_all_sync(struct waitq *wq)
{
    unsigned n = 0;
    for (struct thread *t; (t = wq->head) != NULL; n++) {
        wq_remove(wq, t);
        sched_wake_sync(t, WAIT_OK);
    }
    return n;
}

void wait_timeout_cb(struct ktimer *tm, void *thread)
{
    (void)tm;
    struct thread *t = thread;
    struct waitq *wq = t->timeout_wq;
    if (!wq) {                                        /* plain sleep */
        sched_wake(t, WAIT_TIMEOUT);
        return;
    }
    uint64_t f = spin_lock_irqsave(&wq->lock);
    if (t->wq == wq) {                                /* still waiting: nobody woke it first */
        wq_remove(wq, t);
        sched_wake(t, WAIT_TIMEOUT);
    }
    spin_unlock_irqrestore(&wq->lock, f);
}

/* ---- interruptible waits (killing user threads) -------------------------------------------------
 * The waiter publishes its wait queue in intr_wq (under its intr_lock) before taking the queue's
 * lock, and checks `kill` under the queue's lock before blocking (waitq_wait). The killer sets
 * `kill`, then takes intr_lock and, if a wait is published, the queue's lock, and wakes the
 * thread if it is on that queue. Holding intr_lock keeps the queue alive: the waiter can only
 * finish its wait (and drop the object the queue lives in) after taking intr_lock itself. */

bool thread_wait_intr_begin(struct waitq *wq)
{
    struct thread *cur = current_thread();
    uint64_t f = spin_lock_irqsave(&cur->intr_lock);
    cur->intr_wq = wq;
    spin_unlock_irqrestore(&cur->intr_lock, f);
    if (__atomic_load_n(&cur->kill, __ATOMIC_SEQ_CST)) {
        thread_wait_intr_end();
        return false;
    }
    return true;
}

void thread_wait_intr_end(void)
{
    struct thread *cur = current_thread();
    uint64_t f = spin_lock_irqsave(&cur->intr_lock);
    cur->intr_wq = NULL;
    spin_unlock_irqrestore(&cur->intr_lock, f);
}

void thread_interrupt(struct thread *t)
{
    uint64_t f = spin_lock_irqsave(&t->intr_lock);
    struct waitq *wq = t->intr_wq;
    if (wq) {
        spin_lock(&wq->lock);
        if (t->wq == wq) {
            wq_remove(wq, t);
            sched_wake(t, WAIT_INTERRUPTED);
        }
        spin_unlock(&wq->lock);
    }
    spin_unlock_irqrestore(&t->intr_lock, f);
}

/* Blocking primitives may only be used by threads, never by interrupt handlers. */
static struct thread *must_be_thread(const char *what, const struct waitq *wq)
{
    /* GS-relative single reads: a thread may migrate between two statements. */
    struct thread *cur = current_thread();
    if (!cur)
        panic("%s '%s' used before the scheduler started", what, wq->lock.name);
    if (percpu_irq_depth())
        panic("%s '%s' used in interrupt context", what, wq->lock.name);
    return cur;
}

/* ---- mutex ------------------------------------------------------------------------------------ */

void kmutex_init(struct kmutex *m, const char *name) { *m = (struct kmutex)KMUTEX_INIT(name); }

void kmutex_lock(struct kmutex *m)
{
    struct thread *cur = must_be_thread("mutex", &m->wq);
    uint64_t f = spin_lock_irqsave(&m->wq.lock);
    if (!m->owner) {
        m->owner = cur;
        spin_unlock_irqrestore(&m->wq.lock, f);
        return;
    }
    if (m->owner == cur)
        panic("mutex '%s' deadlock: already held by thread '%s'", m->wq.lock.name, cur->name);
    waitq_wait(&m->wq, f, 0);                        /* ownership is handed to us by unlock */
    KASSERT(m->owner == cur);
}

bool kmutex_trylock(struct kmutex *m)
{
    struct thread *cur = must_be_thread("mutex", &m->wq);
    uint64_t f = spin_lock_irqsave(&m->wq.lock);
    bool ok = !m->owner;
    if (ok)
        m->owner = cur;
    spin_unlock_irqrestore(&m->wq.lock, f);
    return ok;
}

void kmutex_unlock(struct kmutex *m)
{
    struct thread *cur = must_be_thread("mutex", &m->wq);
    uint64_t f = spin_lock_irqsave(&m->wq.lock);
    if (m->owner != cur)
        panic("mutex '%s' unlocked by thread '%s', which does not own it", m->wq.lock.name, cur->name);
    m->owner = m->wq.head;                           /* FIFO hand-off (NULL if nobody waits) */
    if (m->owner)
        waitq_wake_one(&m->wq);
    spin_unlock_irqrestore(&m->wq.lock, f);
}

bool kmutex_held_by_me(const struct kmutex *m) { return m->owner && m->owner == current_thread(); }

/* ---- semaphore ------------------------------------------------------------------------------- */

void ksem_init(struct ksem *s, const char *name, int64_t count) { *s = (struct ksem)KSEM_INIT(name, count); }

bool ksem_down_timeout(struct ksem *s, uint64_t timeout_ns)
{
    uint64_t f = spin_lock_irqsave(&s->wq.lock);
    if (s->count > 0) {
        s->count--;
        spin_unlock_irqrestore(&s->wq.lock, f);
        return true;
    }
    if (!timeout_ns) {
        spin_unlock_irqrestore(&s->wq.lock, f);
        return false;
    }
    must_be_thread("semaphore", &s->wq);
    return waitq_wait(&s->wq, f, deadline_of(timeout_ns)) == WAIT_OK;   /* unit handed over by up */
}

void ksem_down(struct ksem *s) { ksem_down_timeout(s, WAIT_FOREVER); }

void ksem_up(struct ksem *s)
{
    uint64_t f = spin_lock_irqsave(&s->wq.lock);
    if (!waitq_wake_one(&s->wq))
        s->count++;
    spin_unlock_irqrestore(&s->wq.lock, f);
}

/* ---- event --------------------------------------------------------------------------------------- */

void kevent_init(struct kevent *e, const char *name, bool auto_reset)
{
    *e = (struct kevent)KEVENT_INIT(name, auto_reset ? 1u : 0u);
}

bool kevent_wait(struct kevent *e, uint64_t timeout_ns)
{
    uint64_t f = spin_lock_irqsave(&e->wq.lock);
    if (e->signaled) {
        if (e->auto_reset)
            e->signaled = 0;
        spin_unlock_irqrestore(&e->wq.lock, f);
        return true;
    }
    if (!timeout_ns) {
        spin_unlock_irqrestore(&e->wq.lock, f);
        return false;
    }
    must_be_thread("event", &e->wq);
    return waitq_wait(&e->wq, f, deadline_of(timeout_ns)) == WAIT_OK;
}

void kevent_signal(struct kevent *e)
{
    uint64_t f = spin_lock_irqsave(&e->wq.lock);
    if (e->auto_reset) {
        if (!waitq_wake_one(&e->wq))
            e->signaled = 1;                         /* nobody waiting: the next wait passes */
    } else {
        e->signaled = 1;
        waitq_wake_all(&e->wq);
    }
    spin_unlock_irqrestore(&e->wq.lock, f);
}

void kevent_reset(struct kevent *e)
{
    uint64_t f = spin_lock_irqsave(&e->wq.lock);
    e->signaled = 0;
    spin_unlock_irqrestore(&e->wq.lock, f);
}
