/*
 * CPU power management: idle states and performance control (cpupm.h, docs/power.md).
 *
 * Idle. The idle loop (sched.c) calls cpupm_idle with interrupts off once nothing is ready. It
 * picks the deepest state whose target residency fits the expected idle time: the time until
 * this CPU's next timer (tickless: known exactly), capped by twice the recent average idle period
 * (wake-ups by interrupts and IPIs are not predictable, the recent past is a fair guess).
 *   - MWAIT: MONITOR arms the cache line of need_resched first, so a CPU queueing work here only
 *     stores to it (idle_polling tells wakers no IPI is needed). Entered with IF=0 and the
 *     "interrupt breaks MWAIT" extension, so the time slept is measured before the handler runs.
 *   - I/O: reading the _CST port enters the state (IF=0 too; an interrupt ends it). Wakers IPI.
 *   - HLT: STI; HLT. Under a hypervisor the idle loop polls a little first (sched.c).
 * States deeper than C1 need bare metal, an APIC timer that keeps running (ARAT) and an invariant
 * TSC (the clock). An I/O-entered C3 needs the caches kept coherent with bus masters, which only
 * AMD family 17h and later guarantee (Linux's assumption too); elsewhere such states are skipped.
 * The table is swapped as a whole (two static tables, a pointer published with release order),
 * so the idle loop of another CPU never sees a half-written one.
 *
 * Performance. In order of preference:
 *   - ACPI _CPC (CPPC) with registers this kernel reaches: functional fixed hardware (MSR fields;
 *     AMD Zen's CPPC MSRs, Intel's HWP MSRs), I/O ports or constants. CPPC is enabled and the CPU
 *     chooses its own speed between the lowest non-linear and the highest performance, guided by
 *     the energy-performance preference (EPP) when the platform has one.
 *   - Intel HWP without _CPC: the same through IA32_HWP_REQUEST.
 *   - _PSS P-states: the kernel sets the fastest one (performance); no load-driven governor yet.
 * Every register is written on its own CPU (a kernel thread pinned there) through msr_*_safe, so
 * an MSR the CPU does not have only disables the feature, never the kernel.
 */

#include <stdbool.h>
#include <stdint.h>
#include "cpu.h"
#include "cpupm.h"
#include "ktime.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "smp.h"
#include "string.h"
#include "thread.h"

/* ---- idle states ---------------------------------------------------------------------------- */

struct cstate {
    uint8_t  entry;              /* enum cpupm_entry */
    uint8_t  type;               /* ACPI type */
    uint32_t arg;                /* MWAIT hint or I/O port */
    uint64_t latency_ns, residency_ns;
};

struct ctable {
    unsigned      n;
    struct cstate s[CPUPM_MAX_CSTATES];
};

static struct ctable tables[2];
static struct ctable *active = &tables[0];
static bool mwait_ok;                     /* bare metal, MONITOR/MWAIT, break on interrupt with IF=0 */
static unsigned cst_skipped;              /* _CST entries not used */
static const char *deep_off;              /* why only C1 is used, or NULL */
#ifdef KTEST
bool cpupm_test_force_deep;               /* KTEST_CPUPM: deep states under a hypervisor too */
#else
#define cpupm_test_force_deep false
#endif

static inline void cpu_monitor(const volatile void *addr)
{
    __asm__ volatile(".byte 0x0f, 0x01, 0xc8" : : "a"(addr), "c"(0), "d"(0) : "memory");   /* MONITOR */
}

static inline void cpu_mwait(uint32_t hint, uint32_t ext)
{
    __asm__ volatile(".byte 0x0f, 0x01, 0xc9" : : "a"(hint), "c"(ext) : "memory");           /* MWAIT */
}

static inline uint32_t io_in(uint16_t port, unsigned width)
{
    uint32_t v;
    if (width >= 32)
        __asm__ volatile("inl %w1, %0" : "=a"(v) : "Nd"(port));
    else if (width >= 16) {
        uint16_t w;
        __asm__ volatile("inw %w1, %w0" : "=a"(w) : "Nd"(port));
        v = w;
    } else {
        uint8_t b;
        __asm__ volatile("inb %w1, %b0" : "=a"(b) : "Nd"(port));
        v = b;
    }
    return v;
}

static inline void io_out(uint16_t port, unsigned width, uint32_t v)
{
    if (width >= 32)
        __asm__ volatile("outl %0, %w1" : : "a"(v), "Nd"(port));
    else if (width >= 16)
        __asm__ volatile("outw %w0, %w1" : : "a"((uint16_t)v), "Nd"(port));
    else
        __asm__ volatile("outb %b0, %w1" : : "a"((uint8_t)v), "Nd"(port));
}

static struct cstate c1(void)
{
    struct cstate s = { .entry = mwait_ok ? CPUPM_MWAIT : CPUPM_HLT, .type = 1, .arg = 0,
                        .latency_ns = 1000, .residency_ns = 0 };
    return s;
}

void cpupm_init(void)
{
    mwait_ok = !cpu.hypervisor && cpu.monitor && cpu.mwait_irq;
    tables[0].n = 1;
    tables[0].s[0] = c1();
    active = &tables[0];
    kprintf("Idle: %s\n", mwait_ok ? "MWAIT C1 (a store to need_resched wakes an idle CPU, no IPI)"
                        : cpu.hypervisor ? "HLT (under a hypervisor, after a short poll)"
                        : "HLT (no MWAIT with interrupt break)");
}

/* Deepest state worth entering: its target residency fits the expected idle time. */
static unsigned pick(const struct ctable *t, struct percpu *pc, uint64_t now)
{
    if (t->n == 1)
        return 0;
    uint64_t next = __atomic_load_n(&pc->timers.programmed, __ATOMIC_RELAXED);
    uint64_t expect = next > now ? next - now : 0;
    if (expect > pc->idle_avg_ns * 2)
        expect = pc->idle_avg_ns * 2;
    unsigned best = 0;
    for (unsigned i = 1; i < t->n; i++)
        if (t->s[i].residency_ns <= expect)
            best = i;
    return best;
}

void cpupm_idle(struct percpu *pc)
{
    const struct ctable *t = __atomic_load_n(&active, __ATOMIC_ACQUIRE);
    uint64_t start = time_ns();
    unsigned i = pick(t, pc, start);
    const struct cstate *s = &t->s[i];
    tlb_lazy_enter();                       /* shootdowns stop interrupting this CPU */
    switch (s->entry) {
    case CPUPM_MWAIT:
        __atomic_exchange_n(&pc->idle_polling, 1u, __ATOMIC_SEQ_CST);   /* wakers: a store is enough */
        cpu_monitor(&pc->need_resched);
        if (!__atomic_load_n(&pc->need_resched, __ATOMIC_SEQ_CST))
            cpu_mwait(s->arg, 1);           /* ECX[0]: an interrupt ends it even with IF=0 */
        __atomic_exchange_n(&pc->idle_polling, 0u, __ATOMIC_SEQ_CST);
        break;
    case CPUPM_IO:
        (void)io_in((uint16_t)s->arg, 8);   /* enters the state; an interrupt ends it */
        break;
    default:
        cpu_idle();                         /* STI; HLT: the handler runs before we measure */
        cpu_cli();
        break;
    }
    tlb_lazy_exit();                        /* woken by a store: no interrupt entry did it */
    uint64_t slept = time_ns() - start;
    pc->idle_avg_ns = (pc->idle_avg_ns * 7 + slept) / 8;
    pc->idle_count[i]++;
    pc->idle_ns[i] += slept;
    cpu_sti();
}

static void idle_from_cst(const struct cpupm_desc *d)
{
    struct ctable *t = (active == &tables[0]) ? &tables[1] : &tables[0];
    bool deep = (!cpu.hypervisor && cpu.arat && cpu.invariant_tsc) || cpupm_test_force_deep;
    deep_off = cpu.hypervisor ? "under a hypervisor" : !cpu.arat ? "the APIC timer stops in them (no ARAT)"
             : !cpu.invariant_tsc ? "the TSC is not invariant" : NULL;
    bool coherent_io_c3 = strcmp(cpu.vendor, "AuthenticAMD") == 0 && cpu.family >= 0x17;
    t->n = 0;
    t->s[t->n++] = c1();
    cst_skipped = 0;
    unsigned n = d->ncstates < CPUPM_MAX_CSTATES ? d->ncstates : CPUPM_MAX_CSTATES;
    for (unsigned k = 0; k < n; k++) {
        const struct cpupm_cstate *c = &d->cst[k];
        if (c->type <= 1) {                 /* C1: MWAIT with the firmware's hint, else as at boot */
            if (c->entry == CPUPM_MWAIT && mwait_ok)
                t->s[0].arg = c->arg;
            t->s[0].latency_ns = (uint64_t)c->latency_us * 1000;
            continue;
        }
        bool usable = deep && t->n < CPUPM_MAX_CSTATES &&
                      ((c->entry == CPUPM_MWAIT && mwait_ok) ||
                       (c->entry == CPUPM_IO && (c->type == 2 || coherent_io_c3)));
        uint64_t lat = (uint64_t)c->latency_us * 1000;
        if (!usable || lat <= t->s[t->n - 1].latency_ns) {   /* deeper means slower to leave */
            cst_skipped++;
            continue;
        }
        t->s[t->n++] = (struct cstate){ .entry = (uint8_t)c->entry, .type = (uint8_t)c->type,
                                        .arg = c->arg, .latency_ns = lat, .residency_ns = 2 * lat };
    }
    __atomic_store_n(&active, t, __ATOMIC_RELEASE);
}

/* ---- performance control ------------------------------------------------------------------- */

#define MSR_PM_ENABLE        0x770       /* Intel HWP */
#define MSR_HWP_CAPABILITIES 0x771
#define MSR_HWP_REQUEST      0x774

enum perf_kind { PERF_NONE, PERF_CPC, PERF_HWP, PERF_PSS };

static struct {
    enum perf_kind     kind;
    struct cpupm_desc  d;                /* the firmware's description (copy) */
    enum cpupm_policy  policy;
    uint32_t           cpus_ok, cpus_failed;
    uint32_t           highest_min, highest_max, lowest, nominal;   /* abstract performance units */
    spinlock_t         lock;             /* the fields above while CPUs report */
} perf = { .lock = SPINLOCK_INIT("cpupm", LOCK_RANK_LEAF) };

static uint64_t field_mask(unsigned width) { return width >= 64 ? ~0ull : (1ull << width) - 1; }

static bool reg_read(const struct cpupm_reg *r, uint64_t *v)
{
    unsigned w = r->bit_width ? r->bit_width : 64;
    switch (r->kind) {
    case CPUPM_REG_INT:
        *v = r->value;
        return true;
    case CPUPM_REG_MSR: {
        uint64_t raw;
        if (!msr_read_safe((uint32_t)r->value, &raw))
            return false;
        *v = (raw >> r->bit_offset) & field_mask(w);
        return true;
    }
    case CPUPM_REG_IO:
        *v = (io_in((uint16_t)r->value, w) >> r->bit_offset) & field_mask(w);
        return true;
    default:
        return false;
    }
}

static bool reg_write(const struct cpupm_reg *r, uint64_t v)
{
    unsigned w = r->bit_width ? r->bit_width : 64;
    uint64_t m = field_mask(w) << r->bit_offset;
    switch (r->kind) {
    case CPUPM_REG_MSR: {
        uint64_t raw = 0;
        if (m != ~0ull && !msr_read_safe((uint32_t)r->value, &raw))
            return false;
        return msr_write_safe((uint32_t)r->value, (raw & ~m) | ((v << r->bit_offset) & m));
    }
    case CPUPM_REG_IO:
        io_out((uint16_t)r->value, w, (uint32_t)(v << r->bit_offset));
        return true;
    default:
        return false;
    }
}

static bool reg_usable(const struct cpupm_reg *r)
{
    return r->kind == CPUPM_REG_INT || r->kind == CPUPM_REG_MSR || r->kind == CPUPM_REG_IO;
}

static bool reg_present(const struct cpupm_reg *r)
{
    return r->kind == CPUPM_REG_MSR || r->kind == CPUPM_REG_IO;
}

static uint8_t epp_for(enum cpupm_policy p)
{
    return p == CPUPM_PERFORMANCE ? 0x00 : p == CPUPM_POWERSAVE ? 0xFF : 0x80;
}

/* Request range for a policy: the CPU picks its speed inside [lo, hi]. */
static void range_for(enum cpupm_policy p, uint64_t highest, uint64_t nominal, uint64_t lowest_nl,
                      uint64_t lowest, uint64_t *lo, uint64_t *hi)
{
    *hi = p == CPUPM_POWERSAVE && nominal ? nominal : highest;    /* power saving: no boost */
    *lo = p == CPUPM_PERFORMANCE && nominal ? nominal : p == CPUPM_POWERSAVE ? lowest : lowest_nl;
    if (*lo > *hi)
        *lo = *hi;
}

struct perf_job {
    bool             enable;             /* first run: switch CPPC / HWP on */
    enum cpupm_policy policy;
};

static bool cpc_cpu(const struct perf_job *j, uint64_t *highest_out)
{
    const struct cpupm_desc *d = &perf.d;
    uint64_t highest, nominal = 0, lowest_nl = 0, lowest = 0;
    if (j->enable && reg_present(&d->enable) && !reg_write(&d->enable, 1))
        return false;
    if (j->enable && reg_present(&d->autonomous))
        reg_write(&d->autonomous, 1);
    if (!reg_read(&d->highest, &highest) || !highest)
        return false;
    reg_read(&d->nominal, &nominal);
    if (!reg_read(&d->lowest_nonlinear, &lowest_nl))
        lowest_nl = 0;
    if (!reg_read(&d->lowest, &lowest))
        lowest = lowest_nl;
    if (!lowest_nl)
        lowest_nl = lowest;
    uint64_t lo, hi;
    range_for(j->policy, highest, nominal, lowest_nl, lowest, &lo, &hi);
    bool ok = reg_write(&d->max, hi) && reg_write(&d->min, lo);
    if (reg_present(&d->desired))
        ok = reg_write(&d->desired, 0) && ok;              /* 0: no request, the CPU decides */
    if (reg_present(&d->epp))
        ok = reg_write(&d->epp, epp_for(j->policy)) && ok;
    *highest_out = highest;
    uint64_t f = spin_lock_irqsave(&perf.lock);
    perf.nominal = (uint32_t)nominal;
    perf.lowest = (uint32_t)lowest;
    spin_unlock_irqrestore(&perf.lock, f);
    return ok;
}

static bool hwp_cpu(const struct perf_job *j, uint64_t *highest_out)
{
    uint64_t caps;
    if (j->enable && !msr_write_safe(MSR_PM_ENABLE, 1))
        return false;
    if (!msr_read_safe(MSR_HWP_CAPABILITIES, &caps))
        return false;
    uint64_t highest = caps & 0xFF, nominal = (caps >> 8) & 0xFF, efficient = (caps >> 16) & 0xFF,
             lowest = (caps >> 24) & 0xFF;
    if (!highest)
        return false;                                      /* no usable capabilities (emulators) */
    uint64_t lo, hi;
    range_for(j->policy, highest, nominal, efficient ? efficient : lowest, lowest, &lo, &hi);
    uint64_t req = lo | (hi << 8);                         /* desired 0: autonomous */
    if (cpu.hwp_epp)
        req |= (uint64_t)epp_for(j->policy) << 24;
    *highest_out = highest;
    uint64_t f = spin_lock_irqsave(&perf.lock);
    perf.nominal = (uint32_t)nominal;
    perf.lowest = (uint32_t)lowest;
    spin_unlock_irqrestore(&perf.lock, f);
    return msr_write_safe(MSR_HWP_REQUEST, req);
}

static bool pss_cpu(const struct perf_job *j)
{
    const struct cpupm_desc *d = &perf.d;
    unsigned idx = j->policy == CPUPM_POWERSAVE ? d->npstates - 1 : 0;
    uint64_t v = d->pss_control[idx];
    struct cpupm_reg r = d->pct_control;
    if (r.kind == CPUPM_REG_MSR && strcmp(cpu.vendor, "GenuineIntel") == 0) {
        r.bit_offset = 0;                                  /* IA32_PERF_CTL: the target in bits 15:0 */
        r.bit_width = 16;
    }
    return reg_write(&r, v);
}

static int perf_cpu_main(void *arg)
{
    const struct perf_job *j = arg;
    uint64_t highest = 0;
    bool ok = perf.kind == PERF_CPC ? cpc_cpu(j, &highest)
            : perf.kind == PERF_HWP ? hwp_cpu(j, &highest)
            : perf.kind == PERF_PSS ? pss_cpu(j) : false;
    uint64_t f = spin_lock_irqsave(&perf.lock);
    if (ok) {
        perf.cpus_ok++;
        if (highest && (!perf.highest_min || highest < perf.highest_min))
            perf.highest_min = (uint32_t)highest;
        if (highest > perf.highest_max)
            perf.highest_max = (uint32_t)highest;
    } else {
        perf.cpus_failed++;
    }
    spin_unlock_irqrestore(&perf.lock, f);
    return 0;
}

/* Run the job on every online CPU (a thread pinned to each), and wait for all of them. */
static void perf_run(const struct perf_job *j)
{
    struct thread *t[MAX_CPUS] = { 0 };
    uint32_t n = cpu_slots;
    uint64_t f = spin_lock_irqsave(&perf.lock);
    perf.cpus_ok = perf.cpus_failed = 0;
    perf.highest_min = perf.highest_max = 0;
    spin_unlock_irqrestore(&perf.lock, f);
    for (uint32_t c = 0; c < n; c++) {
        if (!cpus[c] || !__atomic_load_n(&cpus[c]->online, __ATOMIC_ACQUIRE))
            continue;
        t[c] = thread_create_on("cpupm", perf_cpu_main, (void *)j, THREAD_PRIO_HIGH, THREAD_CPU(c));
        if (!t[c]) {
            f = spin_lock_irqsave(&perf.lock);
            perf.cpus_failed++;                            /* out of memory: that CPU stays as it was */
            spin_unlock_irqrestore(&perf.lock, f);
        }
    }
    for (uint32_t c = 0; c < n; c++)
        if (t[c])
            thread_join(t[c]);
}

static const char *const policy_names[] = { "performance", "balanced", "power saving" };

static void print(bool per_cpu);

static void perf_print(void)
{
    const struct cpupm_desc *d = &perf.d;
    switch (perf.kind) {
    case PERF_NONE:
        kprintf("Performance: no control the kernel drives (%s)\n",
                cpu.amd_cppc ? "AMD CPPC in the CPU, but no usable _CPC from the firmware"
                : cpu.hypervisor ? "under a hypervisor" : "no _CPC, HWP or _PSS");
        return;
    case PERF_CPC:
    case PERF_HWP:
        if (!perf.cpus_ok) {
            kprintf("Performance: %s refused on %u CPU(s) (left as the firmware set them)\n",
                    perf.kind == PERF_CPC ? "ACPI CPPC (_CPC)" : "Intel HWP", perf.cpus_failed);
            return;
        }
        kprintf("Performance: %s, autonomous, %s (EPP %#x); highest %u",
                perf.kind == PERF_CPC ? "ACPI CPPC (_CPC)" : "Intel HWP", policy_names[perf.policy],
                epp_for(perf.policy), perf.highest_max);
        if (perf.highest_min != perf.highest_max)
            kprintf(" (%u on the slowest core)", perf.highest_min);
        kprintf(", nominal %u, lowest %u", perf.nominal, perf.lowest);
        if (perf.kind == PERF_CPC && d->cpc_nominal_mhz)
            kprintf(" (%u-%u MHz)", d->cpc_lowest_mhz, d->cpc_nominal_mhz);
        break;
    case PERF_PSS:
        kprintf("Performance: ACPI P-states (_PSS, %u: %u-%u MHz), set to %u MHz", d->npstates,
                d->pss_mhz[d->npstates - 1], d->pss_mhz[0],
                d->pss_mhz[perf.policy == CPUPM_POWERSAVE ? d->npstates - 1 : 0]);
        break;
    }
    kprintf("; %u CPU(s)", perf.cpus_ok);
    if (perf.cpus_failed)
        kprintf(", %u refused (left as the firmware set them)", perf.cpus_failed);
    kprintf("\n");
}

bool cpupm_set_policy(enum cpupm_policy p)
{
    if (perf.kind == PERF_NONE)
        return false;
    perf.policy = p;
    struct perf_job j = { .enable = false, .policy = p };
    perf_run(&j);
    return perf.cpus_ok > 0;
}

void cpupm_resume(void)
{
    if (perf.kind == PERF_NONE)
        return;
    struct perf_job j = { .enable = true, .policy = perf.policy };
    perf_run(&j);
}

void cpupm_configure(const struct cpupm_desc *d)
{
    if (d) {
        perf.d = *d;
        idle_from_cst(d);
    }
    const struct cpupm_desc *pd = &perf.d;
    bool cpc = d && pd->cpc && reg_usable(&pd->highest) && reg_present(&pd->max) && reg_present(&pd->min);
    bool hwp = cpu.hwp && !cpu.hypervisor && strcmp(cpu.vendor, "GenuineIntel") == 0;
    bool pss = d && pd->npstates && reg_present(&pd->pct_control) && !cpu.hypervisor;
    perf.kind = cpc ? PERF_CPC : hwp ? PERF_HWP : pss ? PERF_PSS : PERF_NONE;
    perf.policy = perf.kind == PERF_PSS ? CPUPM_PERFORMANCE : CPUPM_BALANCED;
    if (perf.kind != PERF_NONE) {
        struct perf_job j = { .enable = true, .policy = perf.policy };
        perf_run(&j);
        if (!perf.cpus_ok && perf.kind == PERF_CPC && hwp) {
            perf.kind = PERF_HWP;                          /* _CPC named registers we could not use */
            perf_run(&j);
        }
    }
    print(false);
}

void cpupm_print(void) { print(true); }

static void print(bool per_cpu)
{
    const struct ctable *t = __atomic_load_n(&active, __ATOMIC_ACQUIRE);
    kprintf("Idle: ");
    for (unsigned i = 0; i < t->n; i++) {
        const struct cstate *s = &t->s[i];
        kprintf("%sC%u ", i ? ", " : "", i + 1);
        if (s->entry == CPUPM_MWAIT)
            kprintf("MWAIT %#x", s->arg);
        else if (s->entry == CPUPM_IO)
            kprintf("I/O %#x", s->arg);
        else
            kprintf("HLT");
        kprintf(" (%llu us)", (unsigned long long)(s->latency_ns / 1000));
    }
    if (perf.d.ncstates)
        kprintf(" from _CST");
    if (cst_skipped)
        kprintf("; %u _CST state(s) not used%s%s", cst_skipped, deep_off ? ": " : "", deep_off ? deep_off : "");
    kprintf("\n");
    for (uint32_t c = 0; c < cpu_slots; c++) {
        struct percpu *pc = cpus[c];
        if (!per_cpu || !pc || !pc->online)
            continue;
        kprintf("  CPU %u:", c);
        for (unsigned i = 0; i < t->n; i++)
            kprintf(" C%u %llu x %llu ms", i + 1, (unsigned long long)pc->idle_count[i],
                    (unsigned long long)(pc->idle_ns[i] / NS_PER_MS));
        kprintf("\n");
    }
    perf_print();
}
