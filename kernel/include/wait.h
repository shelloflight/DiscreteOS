/*
 * Blocking primitives (kernel/sched/wait.c): wait queues, mutexes, semaphores, events.
 *
 *   kmutex  sleeping lock with an owner; FIFO hand-off to the next waiter (fair, no stampede).
 *           Re-locking a mutex you own, or unlocking one you don't, panics with names.
 *   ksem    counting semaphore; ksem_up is safe from interrupt handlers.
 *   kevent  manual-reset (wakes everyone, stays signaled) or auto-reset (wakes one, then clears);
 *           kevent_signal is safe from interrupt handlers.
 *
 * Waits take a relative timeout in ns: WAIT_FOREVER, or 0 to poll without blocking. They return true
 * when the object was acquired/signaled and false on timeout.
 *
 * Layouts are shared with Rust (kernel/rust/src/ffi.rs); keep both in sync.
 */
#ifndef DOS_WAIT_H
#define DOS_WAIT_H

#include <stdbool.h>
#include <stdint.h>
#include "spinlock.h"
#include "thread.h"

struct waitq {
    spinlock_t     lock;
    struct thread *head, *tail;
};
_Static_assert(sizeof(struct waitq) == 40, "waitq layout is shared with Rust");

#define WAITQ_INIT(n) { SPINLOCK_INIT(n, LOCK_RANK_WAITQ), NULL, NULL }

/* Caller holds wq->lock (irqsave, `flags`). Returns WAIT_OK/WAIT_TIMEOUT with the lock released. */
int            waitq_wait(struct waitq *wq, uint64_t flags, uint64_t deadline_ns);
/* Caller holds wq->lock. Wakes the oldest waiter (returned, or NULL) / every waiter (count). */
struct thread *waitq_wake_one(struct waitq *wq);
unsigned       waitq_wake_all(struct waitq *wq);
/* waitq_wake_all for a waker that is about to block (synchronous IPC): the woken threads are
 * queued on this CPU when they may run here, so the next switch goes straight to them. */
unsigned       waitq_wake_all_sync(struct waitq *wq);
/* Caller holds wq->lock. Wakes every waiter for which match(waiter, ctx) is true. */
unsigned       waitq_wake_if(struct waitq *wq, bool (*match)(const struct thread *w, const void *ctx),
                             const void *ctx);

struct kmutex {
    struct waitq   wq;
    struct thread *owner;
};
_Static_assert(sizeof(struct kmutex) == 48, "kmutex layout is shared with Rust");
#define KMUTEX_INIT(n) { WAITQ_INIT(n), NULL }

void kmutex_init(struct kmutex *m, const char *name);
void kmutex_lock(struct kmutex *m);
bool kmutex_trylock(struct kmutex *m);
void kmutex_unlock(struct kmutex *m);
bool kmutex_held_by_me(const struct kmutex *m);

struct ksem {
    struct waitq wq;
    int64_t      count;
};
_Static_assert(sizeof(struct ksem) == 48, "ksem layout is shared with Rust");
#define KSEM_INIT(n, c) { WAITQ_INIT(n), (c) }

void ksem_init(struct ksem *s, const char *name, int64_t count);
void ksem_down(struct ksem *s);
bool ksem_down_timeout(struct ksem *s, uint64_t timeout_ns);
void ksem_up(struct ksem *s);

struct kevent {
    struct waitq wq;
    uint32_t     signaled;
    uint32_t     auto_reset;
};
_Static_assert(sizeof(struct kevent) == 48, "kevent layout is shared with Rust");
#define KEVENT_INIT(n, auto_reset) { WAITQ_INIT(n), 0, (auto_reset) }

void kevent_init(struct kevent *e, const char *name, bool auto_reset);
bool kevent_wait(struct kevent *e, uint64_t timeout_ns);
void kevent_signal(struct kevent *e);
void kevent_reset(struct kevent *e);

#endif
