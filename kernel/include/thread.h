/*
 * Kernel threads and the scheduler (kernel/sched/sched.c, kernel/arch/x86_64/switch.asm).
 *
 * Threads: each has a 16 KiB kernel stack in its own slot of the kernel-stack region, with an
 * unmapped guard page directly below it (overflow faults and is reported with the thread's name).
 * Stack addresses are never reused, so a stale pointer into a dead thread's stack faults.
 *
 * Scheduling: strict priorities (32 levels, higher runs first), round-robin with a 5 ms slice among
 * equal priorities, O(1) selection (bitmap + per-priority FIFO). Preemptive: a wake-up of a
 * higher-priority thread switches immediately (at the next preemption point: interrupt exit or
 * dropping the last spinlock). Tickless: there is no periodic tick; the timer is programmed only
 * for the next timer deadline or slice end, and an idle CPU sleeps until then.
 *
 * SMP: one run queue per CPU. A woken thread goes back to the CPU it last ran on (warm caches),
 * unless that CPU is busy with equal or higher priority work and another allowed CPU is idle. A CPU
 * that runs out of work steals a ready thread from another CPU's queue, and a CPU that queues a
 * thread it cannot run right away kicks an idle CPU (IPI) to come and take it. Threads may be
 * pinned to a set of CPUs (affinity mask); new threads inherit their creator's mask.
 *
 * Rules (checked, panic on violation): no blocking in interrupt context, no blocking while holding a
 * spinlock, no blocking in the idle thread.
 */
#ifndef DOS_THREAD_H
#define DOS_THREAD_H

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
#include "ktime.h"
#include "spinlock.h"

#define THREAD_PRIO_IDLE    0      /* idle thread only (never queued) */
#define THREAD_PRIO_LOW     8
#define THREAD_PRIO_NORMAL  16
#define THREAD_PRIO_HIGH    24
#define THREAD_PRIO_MAX     31
#define THREAD_PRIO_LEVELS  32

#define THREAD_NAME_MAX     24
#define KSTACK_SIZE         (16 * 1024)
#define SHSTK_SIZE          (8 * 1024)      /* CET supervisor shadow stack per thread (cet.c) */

#define SCHED_SLICE_NS      (5 * NS_PER_MS)

#define THREAD_AFFINITY_ALL (~0ull)
#define THREAD_CPU(n)       (1ull << (n))

/* THREAD_WAKING: a waker has claimed a blocked thread and is queueing it (wake-ups are decided by
 * an atomic BLOCKED -> WAKING transition, so two wakers can never both queue a thread). */
enum thread_state { THREAD_READY, THREAD_RUNNING, THREAD_BLOCKED, THREAD_WAKING, THREAD_DEAD };

typedef int (*thread_fn)(void *arg);

struct waitq;

struct thread {
    uint64_t           rsp;            /* saved stack pointer; must stay first (switch.asm) */
    uint32_t           magic;
    uint32_t           tid;
    uint32_t           state;          /* enum thread_state; changed atomically */
    uint8_t            prio;
    bool               on_cpu;         /* still running on (or switching off) its stack */
    bool               detached;       /* exit lock */
    bool               joined;         /* exit lock: someone is (or was) joining it */
    bool               exited;         /* exit lock: off its stack for good, may be freed */
    bool               migrating;      /* switched out only to move to another CPU */
    bool               static_stack;   /* boot thread: stack is part of the kernel image */
    uint32_t           cpu;            /* CPU it runs on, or last ran on / is queued on */
    uint64_t           affinity;       /* CPUs it may run on (bit n = CPU n) */
    char               name[THREAD_NAME_MAX];

    thread_fn          fn;
    void              *arg;
    int                exit_code;
    uint64_t           kstack_guard;   /* guard page below the stack (0 for static stacks) */
    uint64_t           kstack_top;
    /* CET supervisor shadow stack (0 when shadow stacks are off; cet.c): */
    uint64_t           ssp;            /* while switched out: its restore token (context_switch) */
    uint64_t           ss_token;       /* supervisor token at the top (IA32_PL0_SSP for ring-3 entries) */
    uint64_t           ss_slot;        /* stack-region slot holding it */

    struct thread     *rq_next;        /* run queue link */
    struct waitq      *wq;             /* wait queue it is blocked on, if any */
    struct thread     *wq_next, *wq_prev;
    struct waitq      *timeout_wq;     /* wait queue of a timed wait (stable while its timer runs) */
    int                wait_result;
    struct ktimer      wake_timer;     /* sleep / wait timeout */
    struct thread     *join_target;    /* thread this one is waiting to join */
    struct thread     *reap_next;
    struct thread     *post_next;      /* per-CPU list of switched-out threads with work left */
    struct thread     *all_next, *all_prev;

    /* user threads (user.c): NULL/0 for kernel threads */
    struct uspace     *uspace;         /* address space loaded while it runs */
    void              *user;           /* Rust user-thread state (process, thread object) */
    uint8_t           *fpu;            /* FPU state (XSAVE or FXSAVE area, 64-aligned), saved/restored on switches */
    void              *fpu_alloc;      /* the allocation behind `fpu` */
    uint64_t           fs_base, gs_base;   /* user segment bases, saved/restored on switches */
    uint64_t           ussp;           /* user shadow stack: its SSP while switched out (IA32_PL3_SSP) */
    bool               ushstk;         /* runs ring 3 with a shadow stack (IA32_U_CET.SH_STK_EN) */
    uint32_t           kill;           /* exit at the next return to user mode (atomic) */
    spinlock_t         intr_lock;      /* protects intr_wq (thread_interrupt) */
    struct waitq      *intr_wq;        /* wait queue of an interruptible wait in progress */

    uint64_t           runtime_ns, switched_in_ns, switches;
    uint64_t           woken_ns;       /* when it last became ready (wake-to-run latency) */
    uint64_t           handoff_until;  /* woken by a waker about to block here: no other CPU may
                                        * take it before this time (ns; 0 = none) */
#ifdef KTEST
    uint32_t           fault_kinds;    /* fault injection (fault.h) */
    bool               fault_fired;
    uint64_t           fault_countdown;
#endif
};

struct runqueue {
    spinlock_t     lock;               /* the scheduler lock of this CPU */
    uint32_t       bitmap;             /* bit p set: queue p is non-empty */
    uint32_t       nr_ready;
    struct thread *head[THREAD_PRIO_LEVELS], *tail[THREAD_PRIO_LEVELS];
};

/* ---- thread API ---------------------------------------------------------------- */

/* Create a thread that runs fn(arg); it is ready immediately and returns fn's result as its exit
 * code. Returns NULL when out of memory. A thread must be joined or detached exactly once.
 * thread_create inherits the creator's CPU affinity; thread_create_on sets it (must include an
 * online CPU). */
struct thread *thread_create(const char *name, thread_fn fn, void *arg, unsigned prio);
struct thread *thread_create_on(const char *name, thread_fn fn, void *arg, unsigned prio, uint64_t affinity);
/* Restrict the current thread to `mask` (moves it now if this CPU is not in it). False if `mask`
 * holds no online CPU. */
bool           thread_set_affinity(uint64_t mask);
uint32_t       thread_cpu(void);                     /* CPU the caller is running on */
NORETURN void  thread_exit(int code);
int            thread_join(struct thread *t);        /* waits, frees the thread, returns exit code */
void           thread_detach(struct thread *t);      /* freed by the reaper when it exits */
void           thread_yield(void);
void           thread_sleep_ns(uint64_t ns);
struct thread *thread_current(void);
uint32_t       thread_count(void);                   /* live threads (not yet freed) */

/* ---- scheduler ------------------------------------------------------------------- */

void sched_init(void);          /* after heap + timer: boot context becomes thread "kmain" */
bool sched_running(void);
void schedule(void);            /* give up the CPU if something better is ready */
void sched_preempt_irq(void);   /* interrupt exit (isr_dispatch) */
void preempt_check(void);       /* after the last spinlock is dropped */
void sched_ipi(void);           /* reschedule IPI: another CPU queued work for this one */
void sched_print(void);
void sched_panic_info(void);    /* current thread, for panic reports */
void sched_dump_threads(bool lockfree);   /* thread table (kdb, crash dump) */
void sched_dump_cpus(void);              /* per-CPU state (kdb, crash dump) */

/* SMP bring-up (smp.c): the idle thread of CPU `cpu`, whose stack the AP starts on, and the AP's
 * entry into the scheduler (runs the idle loop). */
struct thread *sched_alloc_idle(uint32_t cpu_id);
NORETURN void  sched_start_ap(void);
void           sched_freeze_aps(bool on);         /* S3: stop scheduling threads on APs */
void           sched_drain_ap(uint32_t cpu_id);   /* S3: move queued threads from parked AP to BSP */
/* A fresh guarded kernel stack (guard page + KSTACK_SIZE) for IST stacks; 0 when out of memory. */
uint64_t       kstack_new(uint64_t *guard);
#ifdef KTEST
void           kstack_test_near_end(void);           /* see vm_test_near_end (mm.h) */
#endif

/* ---- user threads (sched.c, arch/x86_64/user.c) ------------------------------------------
 * A user thread is a kernel thread that enters ring 3 (user_enter) and comes back into the kernel
 * through syscalls, interrupts and faults on its own kernel stack. Switching to it loads its
 * address space (CR3), its FPU/SSE state and its kernel stack (TSS.RSP0, SYSCALL entry).
 * It ends with uthread_exit(), on its own: when it asks to, when it faults, or when it finds
 * `kill` set on a return to user mode (thread_kill also interrupts an interruptible wait and
 * kicks its CPU, so a killed thread stops promptly wherever it is). */
#define USER_PRIO (THREAD_PRIO_NORMAL - 4)  /* below kernel threads: user code cannot starve them */

struct uspace;
struct waitq;
/* Like thread_create, with the address space and the Rust state set before it first runs. ussp:
 * the top of its user shadow stack (0: none; only when cet_ss). */
struct thread *thread_create_user(const char *name, thread_fn fn, void *arg, struct uspace *as, void *user,
                                  uint64_t ussp);
NORETURN void  user_enter(uint64_t rip, uint64_t rsp, uint64_t arg0, uint64_t arg1);   /* syscall.asm */
struct interrupt_frame;
NORETURN void  user_enter_frame(const struct interrupt_frame *f);   /* syscall.asm: every register from f */
NORETURN void  uthread_exit(int code);       /* current user thread: leave its address space and exit */
void           thread_kill(struct thread *t);
/* Interruptible waits: begin before taking the wait queue's lock (false: killed, don't wait);
 * waitq_wait then returns WAIT_INTERRUPTED when the thread is killed. */
bool           thread_wait_intr_begin(struct waitq *wq);
void           thread_wait_intr_end(void);
void           thread_interrupt(struct thread *t);
void          *thread_user_state(void);      /* current thread's Rust user state (NULL: kernel thread) */
uint32_t       thread_tid_of(const struct thread *t);
bool           thread_kill_pending(void);    /* current thread was killed (user threads) */
/* The current user thread's FS (which = 0) or GS (1) base; set takes a canonical user address. */
uint64_t       uthread_get_base(uint32_t which);
void           uthread_set_base(uint32_t which, uint64_t value);
/* The current user thread's shadow-stack pointer in ring 3 (0: it has none). set takes an SSP the
 * kernel saved itself (when it delivered an exception), never one from user space. */
uint64_t       uthread_get_ssp(void);
void           uthread_set_ssp(uint64_t ssp);

/* Name of the thread whose stack guard page contains `va`, or NULL (fault reports). */
const char *thread_guard_name(uint64_t va);

/* ---- low level (wait.c) ------------------------------------------------------------ */

#define WAIT_OK       0
#define WAIT_TIMEOUT  1
#define WAIT_INTERRUPTED 2     /* the waiting user thread was killed (interruptible waits only) */
#define WAIT_FOREVER  UINT64_MAX

/* Block the current thread. `held` (may be NULL) is a spinlock taken with irqsave(`flags`); it is
 * released once the thread is marked blocked, so a wake-up can't be lost. deadline_ns: absolute
 * time_ns() for a timeout, 0 for none. Returns WAIT_OK or WAIT_TIMEOUT. */
int  sched_block(spinlock_t *held, uint64_t flags, uint64_t deadline_ns);
/* Make a blocked thread ready (any context, any CPU; no run queue lock held). No effect if it is
 * not blocked. Returns true if this call woke it. */
bool sched_wake(struct thread *t, int result);
/* sched_wake for a waker that is about to block: queue `t` on this CPU if its affinity allows,
 * without preempting the waker (it gives the CPU up itself). The IPC fast path's direct switch. */
bool sched_wake_sync(struct thread *t, int result);
uint32_t sched_cpu_id(void);                   /* the CPU the caller runs on */
/* Timeout of a sleep or wait (wait.c): takes the thread off its wait queue and wakes it. */
void wait_timeout_cb(struct ktimer *tm, void *thread);

/* Interrupt-state helpers */
static inline uint64_t irq_save(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(f) : : "memory");
    return f;
}

static inline void irq_restore(uint64_t f)
{
    if (f & (1ull << 9))
        __asm__ volatile("sti" ::: "memory");
}

#endif
