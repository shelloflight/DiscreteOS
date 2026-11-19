/*
 * Scheduler and kernel threads (see thread.h for the model and rules).
 *
 * Locking
 *   - Each CPU's run queue lock ("sched", rank 40) protects its queue and its scheduling state. It is
 *     held across context_switch(): the thread that switches out takes it, the thread that resumes
 *     drops it (finish_switch + unlock). Every thread is therefore switched out with exactly one
 *     spinlock held, which the scheduler checks ("blocked while holding a spinlock").
 *   - Waking is decided without any lock: an atomic BLOCKED -> WAKING transition makes exactly one
 *     waker the owner of the thread, which then queues it on the chosen CPU (one run queue lock at a
 *     time; no two run queue locks are ever nested, except a trylock when stealing).
 *   - A thread that is still switching out on its old CPU (on_cpu) is not queued elsewhere until it
 *     is off its stack.
 *   - Exit/join/detach bookkeeping and the reap list are protected by the lock of exit_wq. Work that
 *     needs other locks after a switch (an exited thread to report, a thread to migrate) is put on
 *     the CPU's post_list and done right after the run queue lock is dropped.
 *
 * SMP placement: wake-ups go to the thread's last CPU (warm caches) unless that CPU is busy with
 * equal or higher priority and an allowed CPU is idle. A CPU that runs out of work steals; a CPU
 * that has to queue a preempted thread kicks an idle CPU to take it.
 */

#include <stdint.h>
#include "apic.h"
#include "cet.h"
#include "cpupm.h"
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "profile.h"
#include "rust.h"
#include "smp.h"
#include "spec.h"
#include "string.h"
#include "thread.h"
#include "wait.h"

#define THREAD_MAGIC      0x54485244u   /* "THRD" */
#define THREAD_DEAD_MAGIC 0x44454144u   /* "DEAD": freed, catches use-after-free of a handle */

extern void context_switch(uint64_t *save_rsp, uint64_t new_rsp,
                           uint64_t *save_ssp, uint64_t new_ssp);   /* switch.asm */
extern char boot_stack_guard[];                                      /* entry.asm */

static spinlock_t      kstack_lk = SPINLOCK_INIT("kstack", LOCK_RANK_KSTACK);
static uint64_t        kstack_next;      /* sched_init: KSTACK_BASE (chosen at boot, KASLR) */
static bool            kstack_wrapped;
static spinlock_t      threads_lk = SPINLOCK_INIT("threads", LOCK_RANK_THREADS);
static struct thread  *all_threads;
static uint32_t        nthreads;
static uint32_t        next_tid = 1;
static struct thread   boot_thread;
static struct thread  *reaper;
static struct waitq    exit_wq = WAITQ_INIT("threads.exit");   /* joiners + reaper; exit bookkeeping */
static struct thread  *reap_list;                               /* exited detached threads (exit_wq.lock) */
static uint64_t        idle_mask;                               /* CPUs running their idle thread */
static bool            running;

static NORETURN void thread_start(void);

/* This CPU's need_resched in one GS-relative read (valid even if the caller migrates right after). */
static inline uint32_t resched_pending(void)
{
    uint32_t r;
    __asm__ volatile("movl %%gs:28, %0" : "=r"(r));
    return r;
}

static inline uint32_t tstate(const struct thread *t) { return __atomic_load_n(&t->state, __ATOMIC_ACQUIRE); }
static inline void set_state(struct thread *t, uint32_t s) { __atomic_store_n(&t->state, s, __ATOMIC_RELEASE); }

/* ---- kernel stacks ------------------------------------------------------------------ */

/* A slot in the kernel-stack region: [guard page][KSTACK_SIZE stack][unmapped gap]. Slots are
 * handed out in address order and reused only after the allocator has gone round the whole 1 TiB
 * region (32 M stacks), skipping slots still in use, so a stale pointer into a dead thread's stack
 * keeps faulting for as long as possible while the region never runs out. */
static uint64_t kstack_slot(void)
{
    uint64_t f = spin_lock_irqsave(&kstack_lk);
    for (unsigned tries = 0; tries < 4096; tries++) {
        uint64_t slot = kstack_next;
        kstack_next += KSTACK_SLOT;
        if (kstack_next >= KSTACK_BASE + KSTACK_REGION) {
            kstack_next = KSTACK_BASE;
            kstack_wrapped = true;
        }
        if (!kstack_wrapped || vmm_translate(slot + PAGE_SIZE) == VMM_NOT_MAPPED) {
            spin_unlock_irqrestore(&kstack_lk, f);
            return slot;
        }
    }
    panic("kernel stack region: no free slot");
}

#ifdef KTEST
void kstack_test_near_end(void)
{
    uint64_t f = spin_lock_irqsave(&kstack_lk);
    kstack_next = KSTACK_BASE + KSTACK_REGION - 8 * KSTACK_SLOT;
    spin_unlock_irqrestore(&kstack_lk, f);
}
#endif

uint64_t kstack_new(uint64_t *guard)
{
    uint64_t slot = kstack_slot();
    uint64_t base = slot + PAGE_SIZE;
    for (unsigned i = 0; i < KSTACK_SIZE / PAGE_SIZE; i++) {
        uint64_t pa = pmm_alloc_zeroed();
        if (!pa || !vmm_try_map_page(base + i * PAGE_SIZE, pa, VMM_W)) {
            if (pa)
                pmm_free(pa);
            vmm_unmap_free(base, i);
            return 0;
        }
    }
    *guard = slot;
    return base + KSTACK_SIZE;
}

/* A slot's last SHSTK_SIZE bytes: [guard page][stack][unmapped page][shadow stack]. A shadow stack
 * that overflows runs into the unmapped page. */
_Static_assert(PAGE_SIZE + KSTACK_SIZE + PAGE_SIZE + SHSTK_SIZE <= KSTACK_SLOT, "stack slot layout");

static bool kstack_alloc(struct thread *t)
{
    t->kstack_top = kstack_new(&t->kstack_guard);
    if (!t->kstack_top)
        return false;
    if (cet_ss && !shstk_new(t, t->kstack_guard, (uint64_t)(uintptr_t)thread_start)) {
        vmm_unmap_free(t->kstack_guard + PAGE_SIZE, KSTACK_SIZE / PAGE_SIZE);
        return false;
    }
    return true;
}

/* Shadow stack in `slot` for thread t, or a lone one (t NULL: IST stacks). Layout from the top:
 * the supervisor token (busy while the thread is in the kernel after an entry from ring 3), the
 * first return address of context_switch (`ret`, thread_start) and a restore token for it.
 * Written through the direct map before the page is mapped read-only + dirty. Returns the token,
 * or 0 when out of memory. */
uint64_t shstk_new(struct thread *t, uint64_t slot, uint64_t first_ret)
{
    if (!slot)
        slot = kstack_slot();
    uint64_t base = slot + KSTACK_SLOT - SHSTK_SIZE;
    uint64_t top = base + SHSTK_SIZE;
    uint64_t pas[SHSTK_SIZE / PAGE_SIZE];
    for (unsigned i = 0; i < SHSTK_SIZE / PAGE_SIZE; i++) {
        pas[i] = pmm_alloc_zeroed();
        if (!pas[i]) {
            while (i--)
                pmm_free(pas[i]);
            return 0;
        }
    }
    uint64_t *last = (uint64_t *)((uint8_t *)phys_to_virt(pas[SHSTK_SIZE / PAGE_SIZE - 1]) + PAGE_SIZE);
    last[-1] = top - 8;                           /* supervisor token: its own address, not busy */
    last[-2] = first_ret;                         /* popped by context_switch's `ret` */
    last[-3] = (top - 16) | 1;                    /* restore token (64-bit): SSP = top - 16 */
    for (unsigned i = 0; i < SHSTK_SIZE / PAGE_SIZE; i++) {
        if (!vmm_try_map_page(base + i * PAGE_SIZE, pas[i], VMM_SHSTK)) {
            vmm_unmap_free(base, i);
            for (unsigned j = i; j < SHSTK_SIZE / PAGE_SIZE; j++)
                pmm_free(pas[j]);
            return 0;
        }
    }
    if (t) {
        t->ssp = top - 24;
        t->ss_token = top - 8;
        t->ss_slot = slot;
    }
    return top - 8;
}

static void shstk_free(struct thread *t)
{
    if (t->ss_slot)
        vmm_unmap_free(t->ss_slot + KSTACK_SLOT - SHSTK_SIZE, SHSTK_SIZE / PAGE_SIZE);
}

/* ---- run queue -------------------------------------------------------------------------- */

static inline unsigned top_prio(const struct runqueue *rq) { return 31u - (unsigned)__builtin_clz(rq->bitmap); }

static void rq_push(struct runqueue *rq, struct thread *t)
{
    unsigned p = t->prio;
    t->rq_next = NULL;
    if (rq->tail[p])
        rq->tail[p]->rq_next = t;
    else
        rq->head[p] = t;
    rq->tail[p] = t;
    rq->bitmap |= 1u << p;
    rq->nr_ready++;
}

static struct thread *rq_pop(struct runqueue *rq)
{
    if (!rq->bitmap)
        return NULL;
    unsigned p = top_prio(rq);
    struct thread *t = rq->head[p];
    rq->head[p] = t->rq_next;
    if (!rq->head[p]) {
        rq->tail[p] = NULL;
        rq->bitmap &= ~(1u << p);
    }
    rq->nr_ready--;
    t->rq_next = NULL;
    return t;
}

/* Highest-priority queued thread that may run on `cpu` (for stealing), unlinked; NULL if none. */
static struct thread *rq_take_for(struct runqueue *rq, uint32_t target)
{
    uint64_t now = time_ns();
    for (uint32_t bm = rq->bitmap; bm; ) {
        unsigned p = 31u - (unsigned)__builtin_clz(bm);
        struct thread *prev = NULL;
        for (struct thread *t = rq->head[p]; t; prev = t, t = t->rq_next) {
            if (!(t->affinity & THREAD_CPU(target)) || __atomic_load_n(&t->on_cpu, __ATOMIC_ACQUIRE) ||
                now < t->handoff_until)
                continue;
            if (prev)
                prev->rq_next = t->rq_next;
            else
                rq->head[p] = t->rq_next;
            if (rq->tail[p] == t)
                rq->tail[p] = prev;
            if (!rq->head[p])
                rq->bitmap &= ~(1u << p);
            rq->nr_ready--;
            t->rq_next = NULL;
            return t;
        }
        bm &= ~(1u << p);
    }
    return NULL;
}

/* ---- time slices -------------------------------------------------------------------------- */

/* Round robin among equal priorities, without touching the timer hardware on every switch (a LAPIC
 * write is an uncached MMIO access, and a VM exit under virtualization). A switch only records when
 * the new thread's slice ends; the slice timer is armed lazily, only while another thread of the
 * same priority is waiting, and when it fires it checks whether the slice really ran out. The slice
 * timer of a CPU is only ever armed by that CPU (timers fire where they are armed). */

static bool contended(const struct percpu *pc)
{
    const struct thread *cur = pc->current;
    return cur != pc->idle && pc->rq.bitmap && top_prio(&pc->rq) >= cur->prio;
}

static void slice_expired(struct ktimer *tm, void *ctx)
{
    struct percpu *pc = ctx;
    uint64_t f = spin_lock_irqsave(&pc->rq.lock);
    if (contended(pc)) {
        uint64_t now = time_ns();
        if (now >= pc->slice_end_ns)
            pc->need_resched = 1;                 /* acted on at interrupt exit */
        else                                      /* a switch renewed the slice meanwhile */
            timer_start_oneshot(tm, pc->slice_end_ns - now, slice_expired, pc);
    }
    spin_unlock_irqrestore(&pc->rq.lock, f);
}

/* rq lock of this CPU held. `now`: a new thread just got the CPU (fresh slice); 0 otherwise. */
static void update_slice(struct percpu *pc, uint64_t now)
{
    if (now)
        pc->slice_end_ns = now + SCHED_SLICE_NS;
    if (!contended(pc) || pc->slice_timer.pending)
        return;                                   /* uncontended: a pending timer just expires */
    if (!now) {
        now = time_ns();
        if (pc->slice_end_ns <= now)              /* had the CPU to itself for a while: fresh slice */
            pc->slice_end_ns = now + SCHED_SLICE_NS;
    }
    timer_start_oneshot(&pc->slice_timer, pc->slice_end_ns - now, slice_expired, pc);
}

/* ---- placement ------------------------------------------------------------------------------ */

static volatile bool aps_freezing;

void sched_freeze_aps(bool on)
{
    __atomic_store_n(&aps_freezing, on, __ATOMIC_SEQ_CST);
}

void sched_drain_ap(uint32_t cpu_id)
{
    if (cpu_id == 0 || cpu_id >= cpu_slots || !cpus[cpu_id])
        return;
    struct percpu *ap = cpus[cpu_id];
    struct percpu *bsp = &bsp_percpu;
    for (;;) {
        uint64_t f = spin_lock_irqsave(&ap->rq.lock);
        struct thread *t = rq_pop(&ap->rq);
        spin_unlock_irqrestore(&ap->rq.lock, f);
        if (!t)
            break;
        t->cpu = 0;
        f = spin_lock_irqsave(&bsp->rq.lock);
        rq_push(&bsp->rq, t);
        spin_unlock_irqrestore(&bsp->rq.lock, f);
    }
}

static inline uint64_t allowed_cpus(const struct thread *t)
{
    if (__atomic_load_n(&aps_freezing, __ATOMIC_ACQUIRE))
        return THREAD_CPU(0);
    uint64_t m = t->affinity & smp_online_mask();
    return m ? m : THREAD_CPU(0);                 /* affinity is validated when set; never empty */
}

/* Kick one idle CPU in `allowed` (other than this one) so it comes and steals work. */
/* Make an idle CPU look for work. A CPU that is polling in its idle loop sees need_resched by
 * itself; only a halted one needs an IPI. Protocol (store, full barrier, load on both sides):
 *   waker: need_resched = 1; fence; if !idle_polling: IPI
 *   idle:  idle_polling = 0; fence; if need_resched: run the scheduler, else halt
 * At least one side sees the other's store, so a wake-up is never lost. */
static void wake_idle_cpu(uint32_t target)
{
    struct percpu *o = cpus[target];
    __atomic_store_n(&o->need_resched, 1u, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if (!__atomic_load_n(&o->idle_polling, __ATOMIC_RELAXED))
        smp_send(target, IPI_RESCHED);
}

static void kick_idle(uint64_t allowed)
{
    uint64_t idle = __atomic_load_n(&idle_mask, __ATOMIC_RELAXED) & allowed & ~THREAD_CPU(percpu_cpu_id());
    if (idle)
        wake_idle_cpu((uint32_t)__builtin_ctzll(idle));
}

/* CPU to queue a woken thread on. Unlocked reads: a stale answer only costs a steal later. */
static uint32_t select_cpu(const struct thread *t)
{
    uint64_t allowed = allowed_cpus(t);
    uint32_t last = t->cpu;
    if ((allowed & THREAD_CPU(last)) && __atomic_load_n(&cpus[last]->cur_prio, __ATOMIC_RELAXED) < t->prio)
        return last;                              /* idle there, or it preempts: warm caches win */
    uint64_t idle = __atomic_load_n(&idle_mask, __ATOMIC_RELAXED) & allowed;
    if (idle) {
        uint32_t me = percpu_cpu_id();
        return (idle & THREAD_CPU(me)) ? me : (uint32_t)__builtin_ctzll(idle);
    }
    return (allowed & THREAD_CPU(last)) ? last : (uint32_t)__builtin_ctzll(allowed);
}

/* A thread handed off by a synchronous wake stays reserved for this CPU this long: the waker
 * blocks within a few hundred ns. Without it, an idle CPU steals the thread in that gap and every
 * cross-process call pays two cross-CPU wake-ups. If the waker keeps running, the thread runs here
 * at its next switch, or anywhere once this has passed. */
#define HANDOFF_NS 20000u

/* Queue a thread this caller owns (state WAKING) on a suitable CPU, preempting if it should run now.
 * `sync`: the waker is about to block, so queue it here (if allowed) and let the waker's own
 * switch pick it: a direct switch, no IPI, warm caches for the message just passed. */
static void enqueue_woken(struct thread *t, bool sync)
{
    uint32_t me = percpu_cpu_id();
    bool here = sync && (allowed_cpus(t) & THREAD_CPU(me));
    uint32_t target = here ? me : select_cpu(t);
    t->handoff_until = here ? time_ns() + HANDOFF_NS : 0;
    if (target != t->cpu) {
        /* It may still be switching out on its old CPU: its stack is in use until on_cpu clears. */
        while (__atomic_load_n(&t->on_cpu, __ATOMIC_ACQUIRE)) {
            cpu_pause();
            smp_poll();
        }
        t->cpu = target;
    }
    struct percpu *pc = cpus[target];
    uint64_t f = spin_lock_irqsave(&pc->rq.lock);
    bool local = pc == percpu();
    set_state(t, THREAD_READY);
    rq_push(&pc->rq, t);
    bool kick = false;
    if (t->prio > pc->cur_prio) {
        kick = !pc->need_resched;
        pc->need_resched = 1;                      /* local: acted on when the lock is dropped */
    } else if (local) {
        update_slice(pc, 0);
    } else {
        kick = contended(pc) && !pc->slice_timer.pending;   /* the target arms its own slice timer */
    }
    spin_unlock_irqrestore(&pc->rq.lock, f);
    if (kick && !local) {
        __atomic_thread_fence(__ATOMIC_SEQ_CST);  /* need_resched (set above) before reading idle_polling */
        if (!__atomic_load_n(&pc->idle_polling, __ATOMIC_RELAXED))
            smp_send(target, IPI_RESCHED);
    }
}

static bool wake_thread(struct thread *t, int result)
{
    uint32_t expect = THREAD_BLOCKED;
    if (!__atomic_compare_exchange_n(&t->state, &expect, THREAD_WAKING, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return false;
    t->wait_result = result;
    t->woken_ns = time_ns();
    enqueue_woken(t, false);
    return true;
}

static bool wake_thread_sync(struct thread *t, int result)
{
    uint32_t expect = THREAD_BLOCKED;
    if (!__atomic_compare_exchange_n(&t->state, &expect, THREAD_WAKING, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return false;
    t->wait_result = result;
    t->woken_ns = time_ns();
    enqueue_woken(t, true);
    return true;
}

/* ---- switching ----------------------------------------------------------------------------- */

/* Steal a ready thread from another CPU (this CPU's rq lock held). Trylock only: two idle CPUs
 * stealing from each other must not deadlock. */
static struct thread *steal(struct percpu *pc)
{
    for (uint32_t k = 1; k < cpu_slots; k++) {
        struct percpu *v = cpus[(pc->cpu_id + k) % cpu_slots];
        if (!v || !v->online || !__atomic_load_n(&v->rq.nr_ready, __ATOMIC_RELAXED))
            continue;
        if (!spin_trylock(&v->rq.lock))
            continue;
        struct thread *t = rq_take_for(&v->rq, pc->cpu_id);
        spin_unlock(&v->rq.lock);
        if (t) {
            t->cpu = pc->cpu_id;
            pc->steals++;
            return t;
        }
    }
    return NULL;
}

/* Runs in the thread that was switched to (rq lock held): finish what the previous one started. */
static void finish_switch(struct percpu *pc)
{
    struct thread *from = pc->switched_from;
    pc->switched_from = NULL;
    if (tstate(from) == THREAD_DEAD || from->migrating) {
        from->post_next = pc->post_list;           /* finished after the rq lock is dropped */
        pc->post_list = from;
    }
    __atomic_store_n(&from->on_cpu, false, __ATOMIC_RELEASE);   /* other CPUs may take it now */
}

/* User-mode state of the thread switched to (rq lock held, interrupts off):
 *  - FPU/SSE registers: the kernel never uses them, so they always hold the state of the user
 *    thread that ran last on this CPU. Saved when a user thread switches out, restored when one
 *    switches in (kernel threads in between leave them alone).
 *  - Page tables: the thread's address space, or the kernel's own for kernel threads, so no CPU
 *    keeps a dead process's page tables loaded. Written only when they change; kernel mappings
 *    are global and survive the switch.
 *  - Kernel stack for entries from ring 3 (TSS.RSP0, and the SYSCALL entry's copy). */
/* Load `as` (NULL: the kernel's page tables) on this CPU (interrupts off). Each address space
 * tracks the CPUs that have it loaded, and unmapping shoots down only those: a CPU joins before
 * its CR3 write and leaves after the next one, so it is listed whenever it may hold entries. */
static void load_uspace(struct percpu *pc, struct uspace *as)
{
    uint64_t cr3 = as ? as->pml4 : vmm_kernel_pml4();
    if (pc->cr3 == cr3)
        return;
    uint64_t me = THREAD_CPU(pc->cpu_id);
    struct uspace *old = pc->uspace;
    if (as)
        __atomic_fetch_or(&as->cpus, me, __ATOMIC_SEQ_CST);
    write_cr3(cr3);
    if (old)
        __atomic_fetch_and(&old->cpus, ~me, __ATOMIC_SEQ_CST);
    pc->cr3 = cr3;
    pc->user_cr3 = as ? as->upml4 : 0;   /* KPTI: what the exit to ring 3 loads */
    pc->uspace = as;
}

/* User segment bases: FS_BASE is the user's while in the kernel (the kernel never uses FS);
 * KERNEL_GS_BASE holds the user's GS base (SWAPGS put the per-CPU block in GS_BASE). Read back on
 * switch-out, since a program can change them itself (loading a segment selector). */
#define MSR_FS_BASE        0xC0000100
#define MSR_KERNEL_GS_BASE 0xC0000102

static void switch_user_state(struct percpu *pc, struct thread *prev, struct thread *next)
{
    if (prev->fpu) {
        fpu_save(prev->fpu);
        prev->fs_base = rdmsr(MSR_FS_BASE);
        prev->gs_base = rdmsr(MSR_KERNEL_GS_BASE);
        if (prev->ushstk)
            prev->ussp = rdmsr(MSR_PL3_SSP);     /* CALL/RET in ring 3 moved it */
    }
    if (next->fpu) {
        fpu_restore(next->fpu);
        wrmsr(MSR_FS_BASE, next->fs_base);
        wrmsr(MSR_KERNEL_GS_BASE, next->gs_base);
        /* User shadow stacks: on for this thread or off (U_CET written only when it changes);
         * the next return to ring 3 loads SSP from PL3_SSP. */
        uint64_t u_cet = next->ushstk ? U_CET_SH_STK_EN : 0;
        if (pc->u_cet != u_cet) {
            wrmsr(MSR_U_CET, u_cet);
            pc->u_cet = u_cet;
        }
        if (next->ushstk)
            wrmsr(MSR_PL3_SSP, next->ussp);
    }
    load_uspace(pc, next->uspace);
    /* IBPB: a thread of another process: branch predictions trained by the previous one must
     * not steer it (kernel threads in between keep the last user's id). */
    if (next->uspace && next->uspace->id != pc->last_uid) {
        if (pc->mitig & MIT_IBPB)
            spec_ibpb();
        pc->last_uid = next->uspace->id;
    }
    /* Shadow stacks: an entry from ring 3 switches to the user thread's own shadow stack (its
     * token); kernel threads never run ring 3, so the last user thread's stays loaded. */
    if ((pc->mitig & MIT_SHSTK) && next->user && pc->ss_token != next->ss_token) {
        wrmsr(MSR_PL0_SSP, next->ss_token);
        pc->ss_token = next->ss_token;
    }
    pc->kstack_top = next->kstack_top;
    if (!(pc->mitig & MIT_KPTI))
        pc->tss.rsp[0] = next->kstack_top;   /* KPTI: entries land on the entry stack instead */
}

/* Pick the next thread and switch to it (rq lock held, interrupts off). Returns when the calling
 * thread runs again, possibly on another CPU. */
static void switch_locked(struct percpu *pc)
{
    struct thread *prev = pc->current;
    bool requeued = false;
    if (tstate(prev) == THREAD_RUNNING && prev != pc->idle) {
        set_state(prev, THREAD_READY);
        rq_push(&pc->rq, prev);        /* round robin: back of its priority's queue */
        requeued = true;
    }
    struct thread *next;
    if (__atomic_load_n(&aps_freezing, __ATOMIC_ACQUIRE) && pc->cpu_id != 0) {
        next = pc->idle;
    } else {
        next = rq_pop(&pc->rq);
        if (!next && cpu_slots > 1)
            next = steal(pc);
        if (!next)
            next = pc->idle;
    }
    set_state(next, THREAD_RUNNING);
    next->handoff_until = 0;
    pc->need_resched = 0;
    if (next == prev) {
        update_slice(pc, 0);
        return;
    }
    if (requeued)
        kick_idle(allowed_cpus(prev));            /* prev waits here: an idle CPU can take it */

    uint64_t now = time_ns();
    prev->runtime_ns += now - prev->switched_in_ns;
    if (next != pc->idle && next->woken_ns > next->switched_in_ns)
        lat_note(&lat_wakeup, now - next->woken_ns);     /* woken since it last ran */
    next->switched_in_ns = now;
    next->switches++;
    next->cpu = pc->cpu_id;
    pc->switches++;
    pc->current = next;
    __atomic_store_n(&pc->cur_prio, next->prio, __ATOMIC_RELAXED);
    if (next == pc->idle)
        __atomic_fetch_or(&idle_mask, THREAD_CPU(pc->cpu_id), __ATOMIC_RELAXED);
    else if (prev == pc->idle)
        __atomic_fetch_and(&idle_mask, ~THREAD_CPU(pc->cpu_id), __ATOMIC_RELAXED);
    pc->switched_from = prev;
    next->on_cpu = true;
    update_slice(pc, now);
    switch_user_state(pc, prev, next);

    context_switch(&prev->rsp, next->rsp, &prev->ssp, next->ssp);

    finish_switch(percpu());
}

/* rq lock held: take this CPU's post-switch work (done by run_posts once the lock is dropped). */
static inline struct thread *take_posts(struct percpu *pc)
{
    struct thread *t = pc->post_list;
    pc->post_list = NULL;
    return t;
}

static bool joiner_of(const struct thread *w, const void *dead)
{
    const struct thread *t = dead;
    return w->join_target == t || (t->detached && w == reaper);
}

/* Post-switch work runs with preemption disabled: a wake-up here may make a better thread ready,
 * and switching to it from inside would nest schedule() calls (the caller checks need_resched
 * afterwards instead). */
static void run_posts(struct thread *t)
{
    if (!t)
        return;
    preempt_disable();
    while (t) {
        struct thread *next = t->post_next;
        t->post_next = NULL;
        if (t->migrating) {                        /* off its old CPU now: queue it on an allowed one */
            t->migrating = false;
            wake_thread(t, WAIT_OK);
        } else {                                   /* exited: report to its joiner or the reaper */
            uint64_t f = spin_lock_irqsave(&exit_wq.lock);
            t->exited = true;
            if (t->detached) {
                t->reap_next = reap_list;
                reap_list = t;
            }
            waitq_wake_if(&exit_wq, joiner_of, t);
            spin_unlock_irqrestore(&exit_wq.lock, f);
        }
        t = next;
    }
    preempt_enable_no_resched();
}

static void check_can_block(struct percpu *pc, const char *what, uint32_t locks)
{
    struct thread *cur = pc->current;
    if (pc->irq_depth)
        panic("%s in interrupt context (thread '%s')", what, cur->name);
    if (cur == pc->idle)
        panic("%s in the idle thread", what);
    if (pc->preempt_count != locks)               /* only the run queue lock (+ the waited-on lock) */
        panic("thread '%s' blocked while holding a spinlock (%s)", cur->name, what);
}

void schedule(void)
{
    /* Loop here rather than re-entering schedule() from an unlock: when we resume, the switch that
     * brought us back, or the post-switch work, may already have made a better thread ready.
     * Recursing for that would grow this thread's stack on every round trip. */
    for (;;) {
        uint64_t f = irq_save();                   /* first: `pc` must stay this CPU's block */
        struct percpu *pc = percpu();
        if (!pc->current) {                        /* before the scheduler runs on this CPU */
            irq_restore(f);
            return;
        }
        spin_lock(&pc->rq.lock);
        if (pc->preempt_count != 1)
            panic("schedule() while holding a spinlock (thread '%s')", pc->current->name);
        do {
            switch_locked(pc);
            pc = percpu();
        } while (pc->need_resched);
        struct thread *posts = take_posts(pc);
        spin_unlock_irqrestore_noresched(&pc->rq.lock, f);
        if (!posts)
            return;
        run_posts(posts);
        if (!resched_pending())
            return;
    }
}

static uint64_t read_rflags(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0" : "=r"(f));
    return f;
}

void preempt_check(void)
{
    struct percpu *pc = percpu();
    if (!pc->need_resched || pc->preempt_count || pc->irq_depth || !pc->current || panic_in_progress())
        return;
    if (!(read_rflags() & (1ull << 9)))           /* caller has interrupts off: not a preemption point */
        return;
    schedule();
}

void sched_preempt_irq(void)
{
    struct percpu *pc = percpu();
    if (!pc->need_resched || pc->preempt_count || pc->irq_depth || !pc->current || panic_in_progress())
        return;
    pc->preemptions++;
    schedule();                                    /* the interrupt frame stays on this thread's stack */
}

/* IPI_RESCHED: another CPU queued work here (or wants an idle CPU to steal). Interrupt context. */
void sched_ipi(void)
{
    struct percpu *pc = percpu();
    if (!pc->current)
        return;
    spin_lock(&pc->rq.lock);
    if (pc->current == pc->idle)
        pc->need_resched = 1;                      /* look for work (own queue, then steal) */
    else
        update_slice(pc, 0);                       /* a waiting equal-priority thread: start the slice timer */
    spin_unlock(&pc->rq.lock);
}

/* ---- blocking and waking ------------------------------------------------------------------- */

int sched_block(spinlock_t *held, uint64_t flags, uint64_t deadline_ns)
{
    struct percpu *pc = percpu();
    struct thread *cur = pc->current;
    spin_lock(&pc->rq.lock);                       /* interrupts are already off (irqsave by caller) */
    check_can_block(pc, "blocking", held ? 2 : 1);
    cur->wait_result = WAIT_OK;
    if (deadline_ns) {
        uint64_t now = time_ns();
        timer_start_oneshot(&cur->wake_timer, deadline_ns > now ? deadline_ns - now : 0, wait_timeout_cb, cur);
    }
    set_state(cur, THREAD_BLOCKED);                /* before `held` is dropped: no wake-up can be lost */
    if (held)
        spin_unlock(held);
    switch_locked(pc);
    pc = percpu();
    struct thread *posts = take_posts(pc);
    int r = cur->wait_result;
    spin_unlock_irqrestore(&pc->rq.lock, flags);
    run_posts(posts);
    preempt_check();
    if (deadline_ns)
        timer_cancel_sync(&cur->wake_timer);       /* woken first: the timeout must not fire later */
    return r;
}

bool sched_wake(struct thread *t, int result) { return wake_thread(t, result); }
bool sched_wake_sync(struct thread *t, int result) { return wake_thread_sync(t, result); }
uint32_t sched_cpu_id(void) { return percpu_cpu_id(); }

/* ---- thread API ---------------------------------------------------------------------------- */

static void list_add(struct thread *t)
{
    uint64_t f = spin_lock_irqsave(&threads_lk);
    t->tid = next_tid++;
    t->all_prev = NULL;
    t->all_next = all_threads;
    if (all_threads)
        all_threads->all_prev = t;
    all_threads = t;
    nthreads++;
    spin_unlock_irqrestore(&threads_lk, f);
}

static void list_remove(struct thread *t)
{
    uint64_t f = spin_lock_irqsave(&threads_lk);
    if (t->all_prev)
        t->all_prev->all_next = t->all_next;
    else
        all_threads = t->all_next;
    if (t->all_next)
        t->all_next->all_prev = t->all_prev;
    nthreads--;
    spin_unlock_irqrestore(&threads_lk, f);
}

static void set_name(struct thread *t, const char *name)
{
    size_t n = strnlen(name, THREAD_NAME_MAX - 1);
    memcpy(t->name, name, n);
    t->name[n] = '\0';
}

/* Allocate a thread with its stack prepared to start in thread_start(); not yet runnable. */
static struct thread *thread_alloc(const char *name, thread_fn fn, void *arg, unsigned prio)
{
    struct thread *t = kmalloc(sizeof(*t));
    if (!t)
        return NULL;
    if (!kstack_alloc(t)) {
        kfree(t);
        return NULL;
    }
    t->magic = THREAD_MAGIC;
    t->prio = (uint8_t)prio;
    t->fn = fn;
    t->arg = arg;
    t->state = THREAD_BLOCKED;
    t->cpu = percpu_cpu_id();
    t->affinity = THREAD_AFFINITY_ALL;
    set_name(t, name);
    t->intr_lock = (spinlock_t)SPINLOCK_INIT("thread.intr", LOCK_RANK_INTR);

    /* Initial frame popped by context_switch: 6 zeroed callee-saved registers (RBP = 0 ends
     * backtraces), return into thread_start, and a zero "return address" above it so thread_start
     * sees a correctly aligned stack (RSP = 8 mod 16 at function entry). */
    uint64_t *sp = (uint64_t *)(uintptr_t)t->kstack_top;
    *--sp = 0;
    *--sp = (uint64_t)(uintptr_t)thread_start;
    for (int i = 0; i < 6; i++)
        *--sp = 0;
    t->rsp = (uint64_t)(uintptr_t)sp;

    list_add(t);
    return t;
}

static void thread_free(struct thread *t)
{
    KASSERT(t->exited && !t->on_cpu && !t->static_stack);
    list_remove(t);
    vmm_unmap_free(t->kstack_guard + PAGE_SIZE, KSTACK_SIZE / PAGE_SIZE);
    shstk_free(t);
    t->magic = THREAD_DEAD_MAGIC;
    kfree(t);
}

static void check_thread(const struct thread *t)
{
    if (!t || t->magic != THREAD_MAGIC)
        panic("invalid thread handle %p", (const void *)t);
}

struct thread *thread_create_on(const char *name, thread_fn fn, void *arg, unsigned prio, uint64_t affinity)
{
    KASSERT(fn && name && prio >= 1 && prio <= THREAD_PRIO_MAX);
    if (!(affinity & smp_online_mask()))
        panic("thread '%s': affinity %#llx contains no online CPU", name, (unsigned long long)affinity);
    struct thread *t = thread_alloc(name, fn, arg, prio);
    if (!t)
        return NULL;
    t->affinity = affinity;
    wake_thread(t, WAIT_OK);                       /* queue it; higher priority than us here: runs now */
    return t;
}

/* Initial FPU state of a user thread: what FNINIT + LDMXCSR(0x1F80) give (all exceptions masked,
 * round to nearest, empty x87 stack, AVX state zero). With XSAVE the header (XSTATE_BV = 0) makes
 * XRSTOR load the init state of every component; MXCSR still comes from the legacy area. */
struct thread *thread_create_user(const char *name, thread_fn fn, void *arg, struct uspace *as, void *user,
                                  uint64_t ussp)
{
    KASSERT(!ussp || cet_ss);
    void *raw = kmalloc(cpu.fpu_size + 64);          /* zeroed */
    if (!raw)
        return NULL;
    uint8_t *fpu = (uint8_t *)(((uintptr_t)raw + 63) & ~(uintptr_t)63);   /* XSAVE needs 64 */
    *(uint16_t *)(fpu + 0) = 0x037F;               /* FCW */
    *(uint32_t *)(fpu + 24) = 0x1F80;              /* MXCSR */
    struct thread *t = thread_alloc(name, fn, arg, USER_PRIO);
    if (!t) {
        kfree(raw);
        return NULL;
    }
    t->uspace = as;
    t->user = user;
    t->fpu = fpu;
    t->fpu_alloc = raw;
    t->fs_base = 0;
    t->gs_base = 0;
    t->ussp = ussp;
    t->ushstk = ussp != 0;
    t->affinity = THREAD_AFFINITY_ALL;
    wake_thread(t, WAIT_OK);
    return t;
}

void *thread_user_state(void) { return current_thread()->user; }

uint64_t uthread_get_base(uint32_t which)
{
    uint64_t f = irq_save();                       /* no switch between the read and the MSR */
    uint64_t v = rdmsr(which ? MSR_KERNEL_GS_BASE : MSR_FS_BASE);
    irq_restore(f);
    return v;
}

void uthread_set_base(uint32_t which, uint64_t value)
{
    KASSERT(value < USER_TOP);                     /* canonical: WRMSR would #GP otherwise */
    struct thread *t = current_thread();
    KASSERT(t->fpu);
    uint64_t f = irq_save();
    if (which) {
        t->gs_base = value;
        wrmsr(MSR_KERNEL_GS_BASE, value);
    } else {
        t->fs_base = value;
        wrmsr(MSR_FS_BASE, value);
    }
    irq_restore(f);
}

uint64_t uthread_get_ssp(void)
{
    struct thread *t = current_thread();
    uint64_t f = irq_save();                       /* no switch between the check and the MSR */
    uint64_t v = t->ushstk ? rdmsr(MSR_PL3_SSP) : 0;
    irq_restore(f);
    return v;
}

void uthread_set_ssp(uint64_t ssp)
{
    struct thread *t = current_thread();
    KASSERT(t->ushstk && ssp && ssp < USER_TOP && !(ssp & 7));
    uint64_t f = irq_save();
    t->ussp = ssp;
    wrmsr(MSR_PL3_SSP, ssp);
    irq_restore(f);
}

void uthread_exit(int code)
{
    struct thread *t = current_thread();
    KASSERT(t->user);
    /* Leave the address space first: the Rust state below may hold its last reference. */
    uint64_t f = irq_save();
    struct percpu *pc = percpu();
    t->uspace = NULL;
    load_uspace(pc, NULL);
    void *fpu = t->fpu_alloc;
    t->fpu = NULL;                                 /* no more saves into it */
    t->fpu_alloc = NULL;
    t->ushstk = false;                             /* never in ring 3 again; its shadow stack goes below */
    irq_restore(f);
    kfree(fpu);
    void *user = t->user;
    t->user = NULL;
    dkrnl_uthread_finish(user, code);              /* drops the process and thread references */
    thread_exit(code);
}

void thread_kill(struct thread *t)
{
    __atomic_store_n(&t->kill, 1u, __ATOMIC_SEQ_CST);
    thread_interrupt(t);                           /* blocked in a syscall: wake it */
    if (__atomic_load_n(&t->on_cpu, __ATOMIC_ACQUIRE))
        smp_send(t->cpu, IPI_RESCHED);             /* in user mode on another CPU: make it enter the kernel */
}

struct thread *thread_create(const char *name, thread_fn fn, void *arg, unsigned prio)
{
    return thread_create_on(name, fn, arg, prio, current_thread()->affinity);
}

static NORETURN void thread_start(void)
{
    struct percpu *pc = percpu();
    finish_switch(pc);
    struct thread *posts = take_posts(pc);
    spin_unlock(&pc->rq.lock);
    cpu_sti();
    run_posts(posts);
    preempt_check();
    struct thread *t = current_thread();
    thread_exit(t->fn(t->arg));
}

void thread_exit(int code)
{
    irq_save();                                    /* first: no migration between here and the lock */
    struct percpu *pc = percpu();
    struct thread *cur = pc->current;
    if (cur->static_stack || cur == pc->idle)
        panic("thread '%s' may not exit", cur->name);
    cur->exit_code = code;
    spin_lock(&pc->rq.lock);
    check_can_block(pc, "exit", 1);
    set_state(cur, THREAD_DEAD);
    switch_locked(pc);
    panic("dead thread '%s' was scheduled", cur->name);
}

int thread_join(struct thread *t)
{
    check_thread(t);
    struct thread *cur = current_thread();
    if (t == cur)
        panic("thread '%s' tried to join itself", cur->name);
    uint64_t f = spin_lock_irqsave(&exit_wq.lock);
    if (t->detached || t->joined)
        panic("thread '%s' joined twice or after detach", t->name);
    t->joined = true;
    while (!t->exited) {
        cur->join_target = t;
        waitq_wait(&exit_wq, f, 0);                /* woken by run_posts once t is off its stack */
        f = spin_lock_irqsave(&exit_wq.lock);
    }
    cur->join_target = NULL;
    int code = t->exit_code;
    spin_unlock_irqrestore(&exit_wq.lock, f);
    thread_free(t);
    return code;
}

void thread_detach(struct thread *t)
{
    check_thread(t);
    uint64_t f = spin_lock_irqsave(&exit_wq.lock);
    if (t->detached || t->joined)
        panic("thread '%s' detached twice or while being joined", t->name);
    t->detached = true;
    if (t->exited) {
        t->reap_next = reap_list;
        reap_list = t;
        waitq_wake_if(&exit_wq, joiner_of, t);
    }
    spin_unlock_irqrestore(&exit_wq.lock, f);
}

void thread_yield(void) { schedule(); }

void thread_sleep_ns(uint64_t ns)
{
    if (!ns) {
        thread_yield();
        return;
    }
    uint64_t f = irq_save();
    sched_block(NULL, f, time_ns() + ns);
}

struct thread *thread_current(void) { return current_thread(); }
uint32_t thread_cpu(void) { return percpu_cpu_id(); }

bool thread_set_affinity(uint64_t mask)
{
    struct thread *cur = current_thread();
    if (!(mask & smp_online_mask()))
        return false;
    uint64_t f = irq_save();
    cur->affinity = mask;                          /* stealing honours it from now on */
    struct percpu *pc = percpu();
    if (mask & THREAD_CPU(pc->cpu_id)) {
        irq_restore(f);
        return true;
    }
    /* Switch out as "migrating"; the next thread here queues us on an allowed CPU (run_posts). */
    spin_lock(&pc->rq.lock);
    check_can_block(pc, "migration", 1);
    cur->migrating = true;
    set_state(cur, THREAD_BLOCKED);
    switch_locked(pc);
    pc = percpu();
    struct thread *posts = take_posts(pc);
    spin_unlock_irqrestore(&pc->rq.lock, f);
    run_posts(posts);
    preempt_check();
    return true;
}

uint32_t thread_count(void)
{
    uint64_t f = spin_lock_irqsave(&threads_lk);
    uint32_t n = nthreads;
    spin_unlock_irqrestore(&threads_lk, f);
    return n;
}

/* ---- system threads ------------------------------------------------------------------------ */

/* Under a hypervisor, waking a halted virtual CPU with an IPI costs tens of microseconds (exits on
 * both sides, host thread wake-up). An idle CPU therefore polls need_resched for a short while
 * before halting, and wakers skip the IPI while it polls. On bare metal the IPI is cheap and
 * polling would only burn power, so the CPU goes straight to an idle state (cpupm.c: MWAIT or
 * an ACPI C-state, where a store to need_resched or an interrupt wakes it). */
#define IDLE_POLL_US 30

static NORETURN void idle_loop(void)
{
    uint64_t poll_cycles = cpu.hypervisor ? tsc_hz / 1000000 * IDLE_POLL_US : 0;
    for (;;) {
        cpu_cli();
        struct percpu *pc = percpu();   /* the idle thread never migrates */
        if (__atomic_load_n(&aps_freezing, __ATOMIC_ACQUIRE) && pc->cpu_id != 0)
            smp_ap_park(pc);            /* never returns; AP wakes via INIT-SIPI on resume */
        if (pc->need_resched) {         /* e.g. a kick from another CPU, or work queued here */
            cpu_sti();
            schedule();
            continue;
        }
        if (poll_cycles) {
            __atomic_exchange_n(&pc->idle_polling, 1u, __ATOMIC_SEQ_CST);
            cpu_sti();
            uint64_t end = rdtsc() + poll_cycles;
            while (!__atomic_load_n(&pc->need_resched, __ATOMIC_RELAXED) && rdtsc() < end)
                cpu_pause();
            cpu_cli();
            __atomic_exchange_n(&pc->idle_polling, 0u, __ATOMIC_SEQ_CST);
            if (__atomic_load_n(&pc->need_resched, __ATOMIC_RELAXED))
                continue;
        }
        cpupm_idle(pc);                 /* the deepest idle state worth it; returns with IF=1 */
    }
}

static int idle_main(void *arg)
{
    (void)arg;
    idle_loop();
}

static int reaper_main(void *arg)
{
    (void)arg;
    for (;;) {
        uint64_t f = spin_lock_irqsave(&exit_wq.lock);
        while (!reap_list) {
            waitq_wait(&exit_wq, f, 0);
            f = spin_lock_irqsave(&exit_wq.lock);
        }
        struct thread *t = reap_list;
        reap_list = NULL;
        spin_unlock_irqrestore(&exit_wq.lock, f);
        while (t) {
            struct thread *next = t->reap_next;
            thread_free(t);
            t = next;
        }
    }
}

void sched_init(void)
{
    struct percpu *pc = percpu();
    kstack_next = KSTACK_BASE;

    /* The boot context becomes thread "kmain" on the boot stack (guard page: entry.asm). */
    struct thread *b = &boot_thread;
    b->magic = THREAD_MAGIC;
    b->prio = THREAD_PRIO_NORMAL;
    b->state = THREAD_RUNNING;
    b->on_cpu = true;
    b->static_stack = true;
    b->cpu = pc->cpu_id;
    b->affinity = THREAD_AFFINITY_ALL;
    b->kstack_guard = (uint64_t)(uintptr_t)boot_stack_guard;
    b->kstack_top = b->kstack_guard + PAGE_SIZE + KSTACK_SIZE;
    set_name(b, "kmain");
    if (cet_ss && !shstk_new(b, 0, 0))            /* its first return address: cet_ss_enter's */
        panic("cannot allocate the boot thread's shadow stack");
    b->intr_lock = (spinlock_t)SPINLOCK_INIT("thread.intr", LOCK_RANK_INTR);
    list_add(b);
    b->switched_in_ns = time_ns();
    pc->current = b;
    pc->cur_prio = b->prio;
    pc->online = true;

    pc->idle = sched_alloc_idle(pc->cpu_id);
    if (!pc->idle)
        panic("cannot create the idle thread");
    pc->idle->state = THREAD_READY;
    pc->idle->on_cpu = false;
    reaper = thread_create("reaper", reaper_main, NULL, THREAD_PRIO_HIGH);
    if (!reaper)
        panic("cannot create the reaper thread");
    running = true;
}

struct thread *sched_alloc_idle(uint32_t cpu_id)
{
    struct thread *t = thread_alloc("idle", idle_main, NULL, THREAD_PRIO_IDLE);
    if (!t)
        return NULL;
    t->cpu = cpu_id;
    t->affinity = THREAD_CPU(cpu_id);
    t->state = THREAD_RUNNING;                     /* an AP starts directly on this stack */
    t->on_cpu = true;
    return t;
}

void sched_start_ap(void)
{
    struct percpu *pc = percpu();
    struct thread *idle = pc->idle;
    idle->switched_in_ns = time_ns();
    pc->cur_prio = 0;
    pc->current = idle;
    __atomic_fetch_or(&idle_mask, THREAD_CPU(pc->cpu_id), __ATOMIC_RELAXED);
    idle_loop();
}

bool sched_running(void) { return running; }

void sched_print(void)
{
    kprintf("Scheduler: preemptive, %u priorities, %llu ms slice, O(1) run queue, tickless (%s); %u threads\n",
            THREAD_PRIO_LEVELS, (unsigned long long)(SCHED_SLICE_NS / NS_PER_MS), timer_mode(), thread_count());
}

void sched_panic_info(void)
{
    struct percpu *pc = percpu();
    struct thread *t = pc->current;
    if (t)
        kprintf("  in thread '%s' (tid %u) on CPU %u\n", t->name, t->tid, pc->cpu_id);
}

const char *thread_guard_name(uint64_t va)
{
    for (struct thread *t = all_threads; t; t = t->all_next)    /* lock-free: fault/panic path */
        if (!t->static_stack && t->kstack_guard && va >= t->kstack_guard && va < t->kstack_guard + PAGE_SIZE)
            return t->name;
    return NULL;
}

uint32_t thread_tid_of(const struct thread *t) { return t->tid; }
bool thread_kill_pending(void) { return __atomic_load_n(&current_thread()->kill, __ATOMIC_ACQUIRE) != 0; }

/* ---- inspection (kdb console commands, crash dump) ---------------------------------------- */

static const char *state_name(uint32_t s)
{
    static const char *const names[] = { "ready", "running", "blocked", "waking", "dead" };
    return s < 5 ? names[s] : "?";
}

/* Thread list. `lockfree`: during a panic (other CPUs stopped; the list lock may be held). */
void sched_dump_threads(bool lockfree)
{
    uint64_t f = 0;
    if (!lockfree)
        f = spin_lock_irqsave(&threads_lk);
    kprintf("  TID  NAME                     STATE    CPU PRIO  SWITCHES  RUNTIME(ms)  KIND\n");
    for (struct thread *t = all_threads; t; t = t->all_next)
        kprintf("  %-4u %-24s %-8s %-3u %-4u  %-8llu  %-11llu  %s\n", t->tid, t->name, state_name(t->state),
                t->cpu, t->prio, (unsigned long long)t->switches, (unsigned long long)(t->runtime_ns / NS_PER_MS),
                t->uspace ? "user" : "kernel");
    kprintf("  %u threads\n", nthreads);
    if (!lockfree)
        spin_unlock_irqrestore(&threads_lk, f);
}

void sched_dump_cpus(void)
{
    kprintf("  CPU  ONLINE  CURRENT                  READY  SWITCHES  IRQS      PREEMPT  TLB-FLUSHES\n");
    for (uint32_t c = 0; c < cpu_slots; c++) {
        struct percpu *o = cpus[c];
        if (!o)
            continue;
        struct thread *cur = o->current;
        kprintf("  %-4u %-7s %-24s %-6u %-9llu %-9llu %-8llu %llu\n", c, o->online ? "yes" : "no",
                cur ? cur->name : "-", o->rq.nr_ready, (unsigned long long)o->switches,
                (unsigned long long)o->irqs, (unsigned long long)o->preemptions,
                (unsigned long long)o->tlb_flushes);
    }
}
