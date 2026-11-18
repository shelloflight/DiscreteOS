/* Sampling profiler and latency histograms (see profile.h). */

#include <stdint.h>
#include "arch.h"
#include "ksyms.h"
#include "ktime.h"
#include "mm.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "profile.h"
#include "string.h"
#include "thread.h"

#define SAMPLES_PER_CPU 4096

struct cpu_prof {
    struct ktimer timer;
    uint64_t      rip[SAMPLES_PER_CPU];
    uint32_t      n;
    uint64_t      user, idle, dropped;
};

uint32_t profile_active;
struct lat_hist lat_syscall = { .name = "syscall" };
struct lat_hist lat_wakeup  = { .name = "wakeup" };
struct lat_hist lat_irq     = { .name = "irq" };

static struct cpu_prof *prof[MAX_CPUS];    /* allocated by the first profile_start */
static uint64_t period_ns;

/* Timer callback (interrupt context, this CPU): the interrupted context is the timer interrupt's
 * frame. */
static void sample(struct ktimer *t, void *ctx)
{
    (void)t;
    (void)ctx;
    struct percpu *pc = percpu();
    struct cpu_prof *p = prof[pc->cpu_id];
    const struct interrupt_frame *f = pc->irq_frame;
    if (!f || !p)
        return;
    if (f->cs & 3)
        p->user++;
    else if (pc->current == pc->idle)
        p->idle++;
    else if (p->n < SAMPLES_PER_CPU)
        p->rip[p->n++] = f->rip;
    else
        p->dropped++;
}

/* Runs pinned on one CPU: arm (or disarm) that CPU's sampling timer. */
static int arm_cpu(void *arg)
{
    struct cpu_prof *p = prof[thread_cpu()];
    if (!p)
        return 0;
    if (arg)
        timer_start_periodic(&p->timer, period_ns, sample, NULL);
    else
        timer_cancel_sync(&p->timer);
    return 0;
}

static void on_each_cpu(void *arg)
{
    struct thread *t[MAX_CPUS] = { 0 };
    for (uint32_t c = 0; c < cpu_slots; c++)
        if (cpus[c] && cpus[c]->online)
            t[c] = thread_create_on("prof.arm", arm_cpu, arg, THREAD_PRIO_HIGH, THREAD_CPU(c));
    for (uint32_t c = 0; c < cpu_slots; c++)
        if (t[c])
            thread_join(t[c]);
}

void profile_start(uint32_t hz)
{
    KASSERT(hz > 0 && hz <= 100000);
    profile_stop();
    for (uint32_t c = 0; c < cpu_slots; c++) {
        if (!prof[c])
            prof[c] = kmalloc(sizeof(struct cpu_prof));   /* zeroed; kept for later sessions */
        else
            memset(prof[c], 0, sizeof(struct cpu_prof));
    }
    struct lat_hist *hs[] = { &lat_syscall, &lat_wakeup, &lat_irq };
    for (unsigned i = 0; i < 3; i++) {
        const char *name = hs[i]->name;
        memset(hs[i], 0, sizeof(*hs[i]));
        hs[i]->name = name;
    }
    period_ns = NS_PER_S / hz;
    __atomic_store_n(&profile_active, 1u, __ATOMIC_RELEASE);
    on_each_cpu((void *)1);
}

void profile_stop(void)
{
    if (!__atomic_exchange_n(&profile_active, 0u, __ATOMIC_ACQ_REL))
        return;
    on_each_cpu(NULL);
}

void lat_record(struct lat_hist *h, uint64_t ns)
{
    unsigned b = ns ? 63u - (unsigned)__builtin_clzll(ns) : 0;
    if (b >= LAT_BUCKETS)
        b = LAT_BUCKETS - 1;
    __atomic_fetch_add(&h->bucket[b], 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&h->count, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&h->sum_ns, ns, __ATOMIC_RELAXED);
    uint64_t m = __atomic_load_n(&h->max_ns, __ATOMIC_RELAXED);
    while (ns > m && !__atomic_compare_exchange_n(&h->max_ns, &m, ns, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        ;
}

#define MAX_FUNCS 256

const char *profile_print(unsigned top)
{
    static struct { uint64_t fn; uint32_t n; } funcs[MAX_FUNCS];
    unsigned nf = 0;
    uint64_t kernel = 0, user = 0, idle = 0, dropped = 0, other = 0;
    for (uint32_t c = 0; c < cpu_slots; c++) {
        struct cpu_prof *p = prof[c];
        if (!p)
            continue;
        user += p->user;
        idle += p->idle;
        dropped += p->dropped;
        for (uint32_t i = 0; i < p->n; i++) {
            kernel++;
            uint64_t off = 0;
            if (!ksym_lookup(p->rip[i], &off)) {
                other++;
                continue;
            }
            uint64_t fn = p->rip[i] - off;
            unsigned k = 0;
            while (k < nf && funcs[k].fn != fn)
                k++;
            if (k == nf) {
                if (nf == MAX_FUNCS) {
                    other++;
                    continue;
                }
                funcs[nf].fn = fn;
                funcs[nf].n = 0;
                nf++;
            }
            funcs[k].n++;
        }
    }
    uint64_t total = kernel + user + idle + dropped;
    kprintf("PROFILE: %llu samples at %llu Hz: kernel %llu%%, user %llu%%, idle %llu%% (%llu dropped)\n",
            (unsigned long long)total, (unsigned long long)(period_ns ? NS_PER_S / period_ns : 0),
            (unsigned long long)(total ? kernel * 100 / total : 0), (unsigned long long)(total ? user * 100 / total : 0),
            (unsigned long long)(total ? idle * 100 / total : 0), (unsigned long long)dropped);
    const char *best = NULL;
    for (unsigned r = 0; r < top && r < nf; r++) {
        unsigned m = r;
        for (unsigned k = r + 1; k < nf; k++)
            if (funcs[k].n > funcs[m].n)
                m = k;
        uint64_t fn = funcs[m].fn;
        uint32_t n = funcs[m].n;
        funcs[m] = funcs[r];
        funcs[r].fn = fn;
        funcs[r].n = n;
        uint64_t off = 0;
        const char *name = ksym_lookup(fn, &off);
        if (r == 0) {
            best = name;
            kprintf("PROFILE: top %s\n", name ? name : "?");
        }
        kprintf("PROFILE:   %3llu.%llu%%  %s\n", (unsigned long long)(n * 100 / (kernel ? kernel : 1)),
                (unsigned long long)(n * 1000 / (kernel ? kernel : 1) % 10), name ? name : "?");
    }
    if (other)
        kprintf("PROFILE:   (%llu kernel samples outside known functions)\n", (unsigned long long)other);
    return best;
}

static void lat_print(const struct lat_hist *h)
{
    uint64_t n = __atomic_load_n(&h->count, __ATOMIC_RELAXED);
    if (!n) {
        kprintf("LATENCY %s: no samples\n", h->name);
        return;
    }
    kprintf("LATENCY %s: %llu samples, mean %llu ns, max %llu ns\n", h->name, (unsigned long long)n,
            (unsigned long long)(h->sum_ns / n), (unsigned long long)h->max_ns);
    for (unsigned b = 0; b < LAT_BUCKETS; b++) {
        uint64_t c = h->bucket[b];
        if (!c)
            continue;
        char bar[41];
        unsigned w = (unsigned)(c * 40 / n);
        for (unsigned i = 0; i < 40; i++)
            bar[i] = i < w ? '#' : (i == 0 ? '|' : ' ');
        bar[40] = '\0';
        kprintf("  %10llu ns+ %8llu %s\n", b ? 1ull << b : 0ull, (unsigned long long)c, bar);
    }
}

void lat_print_all(void)
{
    lat_print(&lat_syscall);
    lat_print(&lat_wakeup);
    lat_print(&lat_irq);
}
