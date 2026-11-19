/*
 * Multi-core support: AP bring-up, IPIs, TLB shootdown, panic stop, watchdog (see smp.h).
 *
 * Bring-up: all APs get INIT at once (one 10 ms wait for all of them), then a SIPI each, one at a
 * time because they share the trampoline. Each AP starts on the stack of its own idle thread,
 * switches to the kernel page tables, loads its own GDT/TSS (IST stacks with guard pages), the
 * shared IDT, its LAPIC and timer, then joins the scheduler. An AP that does not answer within a
 * second is parked again with INIT and the system continues without it.
 */

#include <stdint.h>
#include "acpi.h"
#include "apic.h"
#include "arch.h"
#include "cet.h"
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "percpu.h"
#include "spec.h"
#include "printf.h"
#include "smp.h"
#include "string.h"
#include "thread.h"

#define TRAMPOLINE_PHYS 0x8000ull         /* keep in sync with trampoline.asm (SIPI vector 0x08) */
#define TRAMP_PML4      0x9000ull         /* temporary page tables for the AP's switch to long mode */
#define TRAMP_PDPT      0xA000ull
#define TRAMP_PD        0xB000ull
#define TRAMP_END       0xC000ull

#define PTE_P  (1ull << 0)
#define PTE_W  (1ull << 1)
#define PTE_PS (1ull << 7)
#define EFER_LME (1ull << 8)
#define CR4_PGE  (1ull << 7)

#define INIT_WAIT_US     10000            /* INIT -> SIPI delay (MP specification) */
#define SIPI_WAIT_MS     10               /* second SIPI if the first got no answer */
#define START_TIMEOUT_MS 1000
#define STUCK_SECONDS    5                /* TLB shootdown answer */

#define WD_PERIOD_NS     NS_PER_S
#define WD_HARD_NS       (8 * NS_PER_S)   /* longer than the 5 s stuck-lock/shootdown checks, which say more */
#define WD_SOFT_NS       (5 * NS_PER_S)

struct trampoline_params {                /* layout: trampoline.asm */
    uint64_t tramp_cr3, kernel_cr3, efer, stack, percpu, entry;
};

extern const char trampoline_start[], trampoline_end[], trampoline_params[];
extern char ap_entry64[], ap_resume_entry64[];

NORETURN void ap_main(struct percpu *pc);        /* from trampoline.asm */
NORETURN void ap_resume_main(struct percpu *pc); /* from trampoline.asm (S3 resume) */

static uint64_t   online_mask = 1;        /* CPU 0 (boot CPU) */
static uint32_t   online_count = 1;
static uint64_t   bsp_cr0, bsp_cr4, bsp_efer_nx;
static bool       low_ram_ok;             /* true if 0x8000-0xBFFF is usable low RAM */
static uint64_t   suspended_ap_mask;      /* APs parked for S3, to restart on resume */
static volatile uint32_t aps_parked;
static uint64_t   start_tsc;              /* TSC just before a SIPI: the AP's TSC must not be behind it */
static uint64_t   bringup_us;

static spinlock_t tlb_lk = SPINLOCK_INIT("tlb", LOCK_RANK_TLB);
static struct { uint64_t va, pages; } tlb_req;
static uint64_t   tlb_pending;            /* CPUs that still have to flush tlb_req */
static uint64_t   shootdowns, lazy_skips;

bool     smp_active(void) { return __atomic_load_n(&online_count, __ATOMIC_RELAXED) > 1; }
uint32_t smp_cpus(void) { return __atomic_load_n(&online_count, __ATOMIC_RELAXED); }
uint64_t smp_online_mask(void) { return __atomic_load_n(&online_mask, __ATOMIC_RELAXED); }

/* ---- IPIs ---------------------------------------------------------------------------------- */

void smp_send(uint32_t target, uint32_t reason)
{
    struct percpu *pc = cpus[target];
    if (!pc || !__atomic_load_n(&pc->online, __ATOMIC_ACQUIRE) || target == percpu_cpu_id())
        return;
    /* Only the first sender of a reason interrupts the target; later ones find the bit already set
     * and are covered by the IPI that is on its way. */
    if (!(__atomic_fetch_or(&pc->ipi_pending, reason, __ATOMIC_SEQ_CST) & reason))
        lapic_send_ipi(pc->apic_id, VEC_IPI);
}

static void tlb_answer(struct percpu *pc)
{
    uint64_t me = THREAD_CPU(pc->cpu_id);
    if (!(__atomic_load_n(&tlb_pending, __ATOMIC_ACQUIRE) & me))
        return;
    __atomic_store_n(&pc->tlb_stale, 0u, __ATOMIC_RELAXED);   /* set by this request (we were not lazy) */
    tlb_flush_local(tlb_req.va, tlb_req.pages);
    pc->tlb_flushes++;
    __atomic_fetch_and(&tlb_pending, ~me, __ATOMIC_RELEASE);
}

static void ipi_irq(struct interrupt_frame *f)
{
    (void)f;
    struct percpu *pc = percpu();
    pc->ipis++;
    uint32_t why = __atomic_exchange_n(&pc->ipi_pending, 0u, __ATOMIC_ACQ_REL);
    if (why & IPI_TLB)
        tlb_answer(pc);
    if (why & IPI_RESCHED)
        sched_ipi();
}

void smp_poll_slow(void)
{
    uint64_t f = irq_save();              /* flush and acknowledge on the same CPU */
    struct percpu *pc = percpu();
    if (__atomic_fetch_and(&pc->ipi_pending, ~IPI_TLB, __ATOMIC_ACQ_REL) & IPI_TLB)
        tlb_answer(pc);
    irq_restore(f);
}

/* ---- TLB ------------------------------------------------------------------------------------- */

static void tlb_flush_all(void)
{
    uint64_t cr4 = read_cr4();
    if (cr4 & CR4_PGE) {                  /* toggling PGE drops global (kernel) entries too */
        write_cr4(cr4 & ~CR4_PGE);
        write_cr4(cr4);
    } else {
        write_cr3(read_cr3());
    }
}

void tlb_flush_local(uint64_t va, uint64_t pages)
{
    if (pages > 32) {
        tlb_flush_all();
        return;
    }
    for (uint64_t i = 0; i < pages; i++)
        __asm__ volatile("invlpg (%0)" : : "r"(va + i * PAGE_SIZE) : "memory");
}

/* Lazy TLB protocol (Dekker-style; both sides store, full barrier, then load):
 *   initiator: tlb_stale = 1; barrier; if tlb_lazy, skip the IPI
 *   idle CPU:  tlb_lazy = 0;  barrier; if tlb_stale, flush everything
 * At least one side sees the other's store, so a skipped CPU always flushes before it runs
 * anything but the interrupt entry stub (kernel text and its own idle stack, never freed). */
void tlb_lazy_enter(void)
{
    struct percpu *pc = percpu();                 /* idle loop, interrupts off */
    __atomic_exchange_n(&pc->tlb_lazy, 1u, __ATOMIC_SEQ_CST);
}

void tlb_lazy_exit_slow(void)
{
    struct percpu *pc = percpu();                 /* interrupt entry */
    __atomic_exchange_n(&pc->tlb_lazy, 0u, __ATOMIC_SEQ_CST);
    if (__atomic_exchange_n(&pc->tlb_stale, 0u, __ATOMIC_SEQ_CST)) {
        tlb_flush_all();
        pc->tlb_flushes++;
    }
}

void tlb_shootdown(uint64_t va, uint64_t pages) { tlb_shootdown_cpus(va, pages, ~0ull); }

void tlb_shootdown_cpus(uint64_t va, uint64_t pages, uint64_t which)
{
    if (!smp_active())
        return;
    uint64_t f = spin_lock_irqsave(&tlb_lk);
    uint64_t targets = 0;
    for (uint64_t m = smp_online_mask() & which & ~THREAD_CPU(percpu_cpu_id()); m; m &= m - 1) {
        struct percpu *o = cpus[__builtin_ctzll(m)];
        __atomic_exchange_n(&o->tlb_stale, 1u, __ATOMIC_SEQ_CST);
        if (__atomic_load_n(&o->tlb_lazy, __ATOMIC_SEQ_CST))
            lazy_skips++;                         /* idle: flushes itself when it wakes up */
        else
            targets |= m & -m;
    }
    if (targets) {
        tlb_req.va = va;
        tlb_req.pages = pages;
        __atomic_store_n(&tlb_pending, targets, __ATOMIC_RELEASE);
        for (uint64_t m = targets; m; m &= m - 1)
            smp_send((uint32_t)__builtin_ctzll(m), IPI_TLB);

        uint64_t start = rdtsc(), limit = tsc_hz * STUCK_SECONDS;
        while (__atomic_load_n(&tlb_pending, __ATOMIC_ACQUIRE)) {
            cpu_pause();
            smp_poll();
            if (rdtsc() - start > limit && !panic_in_progress())
                panic("TLB shootdown: CPU %u did not answer within %d s",
                      (unsigned)__builtin_ctzll(__atomic_load_n(&tlb_pending, __ATOMIC_RELAXED)), STUCK_SECONDS);
        }
        shootdowns++;
    }
    spin_unlock_irqrestore(&tlb_lk, f);
}

/* ---- watchdog ---------------------------------------------------------------------------------- */

static uint32_t wd_fired;                 /* one hard-lockup report */
static uint32_t dump_cpu = UINT32_MAX;    /* CPU that prints its backtrace when stopped (watchdog) */
static volatile uint32_t dump_go, dump_done, stopped;

/* Soft lockup: this CPU has not switched for WD_SOFT_NS although a thread of equal or higher
 * priority is waiting here, i.e. preemption has been disabled that long. Warn once per episode.
 * Unlocked reads (interrupt context; the interrupted code may hold the run queue lock). */
static void soft_check(struct percpu *pc, uint64_t now)
{
    struct thread *cur = pc->current;
    uint32_t bm = pc->rq.bitmap;
    bool waiting = cur && cur != pc->idle && bm && 31u - (unsigned)__builtin_clz(bm) >= cur->prio;
    if (pc->switches != pc->wd_switches || !waiting) {
        pc->wd_switches = pc->switches;
        pc->wd_stuck_since = now;
        pc->wd_reported = false;
        return;
    }
    if (pc->wd_reported || now - pc->wd_stuck_since < WD_SOFT_NS)
        return;
    pc->wd_reported = true;
    kprintf("watchdog: soft lockup on CPU %u: thread '%s' not preempted for %llu s while other threads "
            "wait (preemption disabled, %u spinlock(s) held)\n", pc->cpu_id, cur->name,
            (unsigned long long)((now - pc->wd_stuck_since) / NS_PER_S), pc->preempt_count);
    if (pc->irq_frame)
        backtrace_print(pc->irq_frame->rip, pc->irq_frame->rbp);
}

static void wd_tick(struct ktimer *t, void *ctx)
{
    (void)t;
    (void)ctx;
    struct percpu *pc = percpu();
    uint64_t now = time_ns();
    pc->wd_beat_ns = now;
    soft_check(pc, now);

    /* Hard lockup: another CPU's heartbeat stopped, so its timer interrupts stopped. */
    for (uint32_t c = 0; c < cpu_slots; c++) {
        struct percpu *o = cpus[c];
        if (!o || o == pc || !o->online)
            continue;
        uint64_t beat = o->wd_beat_ns;
        if (!beat || now < beat + WD_HARD_NS)
            continue;
        uint32_t expect = 0;
        if (!__atomic_compare_exchange_n(&wd_fired, &expect, 1u, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return;
        kprintf("watchdog: CPU %u is not responding: no heartbeat for %llu ms (interrupts off or hung)\n",
                c, (unsigned long long)((now - beat) / NS_PER_MS));
        dump_cpu = c;
        panic("watchdog: hard lockup on CPU %u", c);
    }
}

static void watchdog_start(struct percpu *pc)
{
    pc->wd_beat_ns = time_ns();
    pc->wd_stuck_since = pc->wd_beat_ns;
    timer_start_periodic(&pc->wd_timer, WD_PERIOD_NS, wd_tick, NULL);   /* armed on this CPU */
}

/* ---- panic support ------------------------------------------------------------------------------ */

void smp_stop_others(void)
{
    if (!smp_active())
        return;
    uint32_t me = percpu_cpu_id(), others = 0;
    for (uint32_t c = 0; c < cpu_slots; c++) {
        if (c != me && cpus[c] && cpus[c]->online) {
            lapic_send_nmi(cpus[c]->apic_id);
            others++;
        }
    }
    uint64_t start = rdtsc(), limit = tsc_hz / 10;        /* 100 ms */
    while (stopped < others && rdtsc() - start < limit)
        cpu_pause();
}

void smp_dump_target(void)
{
    if (dump_cpu == UINT32_MAX)
        return;
    dump_go = 1;
    uint64_t start = rdtsc(), limit = tsc_hz;              /* 1 s */
    while (!dump_done && rdtsc() - start < limit)
        cpu_pause();
}

bool smp_nmi(struct interrupt_frame *f)
{
    if (!panic_claimed() || panic_owner_is_me())
        return false;                                       /* a real NMI: reported as an exception */
    struct percpu *pc = percpu();
    __atomic_add_fetch(&stopped, 1, __ATOMIC_RELEASE);
    if (pc->cpu_id == dump_cpu) {
        uint64_t start = rdtsc(), limit = tsc_hz * 2;
        while (!dump_go && rdtsc() - start < limit)
            cpu_pause();
        kprintf("NMI backtrace of CPU %u (thread '%s'), interrupts %s:\n", pc->cpu_id,
                pc->current ? pc->current->name : "?", (f->rflags & (1u << 9)) ? "on" : "off");
        kprintf("  RIP=%016llx  RSP=%016llx  RBP=%016llx\n", (unsigned long long)f->rip,
                (unsigned long long)f->rsp, (unsigned long long)f->rbp);
        backtrace_print(f->rip, f->rbp);
        dump_done = 1;
    }
    cpu_halt_forever();
}

const char *smp_guard_name(uint64_t va, uint32_t *cpu_out)
{
    static const char *const names[IST_COUNT] = { "double-fault stack", "NMI stack", "machine-check stack" };
    for (uint32_t c = 1; c < cpu_slots; c++) {
        if (!cpus[c])
            continue;
        for (int i = 0; i < IST_COUNT; i++) {
            uint64_t g = cpus[c]->ist_guard[i];
            if (g && va >= g && va < g + PAGE_SIZE) {
                *cpu_out = c;
                return names[i];
            }
        }
    }
    return NULL;
}

/* ---- AP bring-up ------------------------------------------------------------------------------- */

void ap_main(struct percpu *pc)
{
    write_cr0(bsp_cr0);
    write_cr4(bsp_cr4);                                     /* PGE, SMEP, SMAP, UMIP like the boot CPU */
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | bsp_efer_nx);
    cpu_init_pat();                                         /* same memory types as the boot CPU */
    uint64_t ist[IST_COUNT];
    for (int i = 0; i < IST_COUNT; i++)
        ist[i] = pc->tss.ist[i];
    gdt_init_cpu(pc, ist);
    idt_load();
    if (cet_ss)
        cet_cpu_enable(pc, pc->idle);                      /* ap_main never returns (cet.h) */
    lapic_init_ap();
    timer_init_ap();
    bool tsc_behind = rdtsc() < start_tsc;

    /* Online: from now on TLB shootdowns include this CPU. Flush once more, so nothing cached
     * before joining can be stale. */
    uint64_t f = spin_lock_irqsave(&tlb_lk);
    __atomic_fetch_or(&online_mask, THREAD_CPU(pc->cpu_id), __ATOMIC_RELEASE);
    __atomic_add_fetch(&online_count, 1, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&tlb_lk, f);
    tlb_flush_all();
    if (tsc_behind)
        kprintf("SMP: warning: TSC of CPU %u is behind the boot CPU (unsynchronized TSCs)\n", pc->cpu_id);
    watchdog_start(pc);
    __atomic_store_n(&pc->online, true, __ATOMIC_RELEASE);
    sched_start_ap();
}

void ap_resume_main(struct percpu *pc)
{
    write_cr0(bsp_cr0);
    write_cr4(bsp_cr4);
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | bsp_efer_nx);
    cpu_init_pat();
    gdt_resume_cpu(pc);
    idt_load();
    if (cet_ss) {
        cet_ap_reset(pc->idle);
        cet_cpu_enable(pc, pc->idle);
    }
    lapic_init_ap();
    timer_init_ap();
    time_resume_cpu();

    uint64_t f = spin_lock_irqsave(&tlb_lk);
    __atomic_fetch_or(&online_mask, THREAD_CPU(pc->cpu_id), __ATOMIC_RELEASE);
    __atomic_add_fetch(&online_count, 1, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&tlb_lk, f);
    tlb_flush_all();
    watchdog_start(pc);
    __atomic_store_n(&pc->online, true, __ATOMIC_RELEASE);
    sched_start_ap();
}

static struct trampoline_params *install_trampoline(uint64_t entry)
{
    size_t len = (size_t)((uintptr_t)trampoline_end - (uintptr_t)trampoline_start);
    KASSERT(len <= TRAMP_PML4 - TRAMPOLINE_PHYS);
    uint8_t *tr = vmm_map_phys(TRAMPOLINE_PHYS, TRAMP_END - TRAMPOLINE_PHYS, VMM_W);
    memset(tr, 0, TRAMP_END - TRAMPOLINE_PHYS);
    memcpy(tr, trampoline_start, len);
    uint64_t *pml4 = (uint64_t *)(tr + (TRAMP_PML4 - TRAMPOLINE_PHYS));
    uint64_t *pdpt = (uint64_t *)(tr + (TRAMP_PDPT - TRAMPOLINE_PHYS));
    uint64_t *pd   = (uint64_t *)(tr + (TRAMP_PD - TRAMPOLINE_PHYS));
    pml4[0] = TRAMP_PDPT | PTE_P | PTE_W;
    pdpt[0] = TRAMP_PD | PTE_P | PTE_W;
    pd[0]   = PTE_P | PTE_W | PTE_PS;
    const uint64_t *kpml4 = phys_to_virt(vmm_kernel_pml4());
    for (int i = 256; i < 512; i++)
        pml4[i] = kpml4[i];
    struct trampoline_params *prm = (struct trampoline_params *)(tr + (trampoline_params - trampoline_start));
    prm->tramp_cr3 = TRAMP_PML4;
    prm->kernel_cr3 = vmm_kernel_pml4();
    prm->efer = EFER_LME | bsp_efer_nx;
    prm->stack = TRAMP_END;
    prm->percpu = (uint64_t)(uintptr_t)&bsp_percpu;
    prm->entry = entry;
    return prm;
}

bool smp_low_ram_ok(void) { return low_ram_ok; }

uint32_t smp_setup_s3_trampoline(uint64_t entry)
{
    KASSERT(low_ram_ok);
    (void)install_trampoline(entry);
    __asm__ volatile("mfence" ::: "memory");
    return (uint32_t)TRAMPOLINE_PHYS;
}

void smp_clear_s3_trampoline(void)
{
    if (!low_ram_ok)
        return;
    uint8_t *tr = vmm_map_phys(TRAMPOLINE_PHYS, TRAMP_END - TRAMPOLINE_PHYS, VMM_W);
    memset(tr, 0, TRAMP_END - TRAMPOLINE_PHYS);
}

NORETURN void smp_ap_park(struct percpu *pc)
{
    cpu_cli();
    timer_cancel(&pc->wd_timer);
    timer_cancel(&pc->slice_timer);
    timer_program(TIMER_NONE);
    uint64_t f = spin_lock_irqsave(&tlb_lk);
    __atomic_fetch_and(&online_mask, ~THREAD_CPU(pc->cpu_id), __ATOMIC_RELEASE);
    __atomic_sub_fetch(&online_count, 1, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&tlb_lk, f);
    __atomic_store_n(&pc->online, false, __ATOMIC_RELEASE);
    __asm__ volatile("wbinvd" ::: "memory");
    __atomic_add_fetch(&aps_parked, 1, __ATOMIC_RELEASE);
    for (;;) {
        cpu_cli();
        __asm__ volatile("hlt");
    }
}

bool smp_suspend(void)
{
    timer_cancel(&bsp_percpu.wd_timer);
    uint64_t mask = smp_online_mask() & ~1ull;
    suspended_ap_mask = mask;
    if (!mask)
        return true;

    __atomic_store_n(&aps_parked, 0u, __ATOMIC_RELEASE);
    sched_freeze_aps(true);
    uint32_t expected = 0;
    for (uint64_t m = mask; m; m &= m - 1) {
        uint32_t c = (uint32_t)__builtin_ctzll(m);
        __atomic_store_n(&cpus[c]->need_resched, 1u, __ATOMIC_RELEASE);
        smp_send(c, IPI_RESCHED);
        expected++;
    }
    uint64_t start = rdtsc(), limit = tsc_hz * 5;
    while (__atomic_load_n(&aps_parked, __ATOMIC_ACQUIRE) < expected) {
        if (rdtsc() - start > limit) {
            kprintf("SMP: S3 suspend: only %u of %u AP(s) parked\n",
                    __atomic_load_n(&aps_parked, __ATOMIC_RELAXED), expected);
            sched_freeze_aps(false);
            return false;
        }
        cpu_pause();
        smp_poll();
    }
    for (uint64_t m = mask; m; m &= m - 1)
        sched_drain_ap((uint32_t)__builtin_ctzll(m));
    return true;
}

static bool start_ap(struct percpu *pc, struct trampoline_params *prm);

void smp_resume(void)
{
    sched_freeze_aps(false);
    uint64_t mask = suspended_ap_mask;
    suspended_ap_mask = 0;
    if (mask && low_ram_ok) {
        struct trampoline_params *prm = install_trampoline((uint64_t)(uintptr_t)ap_resume_entry64);
        for (uint64_t m = mask; m; m &= m - 1)
            lapic_send_init(cpus[__builtin_ctzll(m)]->apic_id);
        tsc_delay_us(INIT_WAIT_US);
        for (uint64_t m = mask; m; m &= m - 1)
            start_ap(cpus[__builtin_ctzll(m)], prm);
        smp_clear_s3_trampoline();
    }
    if (smp_active())
        watchdog_start(&bsp_percpu);
}

static struct percpu *ap_alloc(uint32_t apic_id)
{
    uint64_t pa = pmm_alloc_zeroed();
    if (!pa)
        return NULL;
    struct percpu *pc = phys_to_virt(pa);                   /* one page: no shared cache lines */
    pc->self = pc;
    pc->cpu_id = cpu_slots;
    pc->apic_id = apic_id;
    pc->rq.lock = (spinlock_t)SPINLOCK_INIT("sched", LOCK_RANK_SCHED);
    pc->timers = (struct timer_base)TIMER_BASE_INIT;
    for (int i = 0; i < IST_COUNT; i++) {
        pc->tss.ist[i] = kstack_new(&pc->ist_guard[i]);
        if (!pc->tss.ist[i])
            return NULL;
    }
    kpti_map_cpu(pc, pc->tss.ist, KSTACK_SIZE);   /* KPTI: what this CPU's entries need */
    if (cet_ss && !cet_cpu_alloc(pc))
        return NULL;
    pc->idle = sched_alloc_idle(pc->cpu_id);
    return pc->idle ? pc : NULL;
}

static bool wait_online(const struct percpu *pc, uint64_t ms)
{
    uint64_t start = rdtsc(), limit = tsc_hz / 1000 * ms;
    while (!__atomic_load_n(&pc->online, __ATOMIC_ACQUIRE)) {
        if (rdtsc() - start > limit)
            return false;
        cpu_pause();
    }
    return true;
}

static bool start_ap(struct percpu *pc, struct trampoline_params *prm)
{
    prm->stack = pc->idle->kstack_top;
    prm->percpu = (uint64_t)(uintptr_t)pc;
    start_tsc = rdtsc();
    __asm__ volatile("mfence" ::: "memory");
    lapic_send_sipi(pc->apic_id, (uint8_t)(TRAMPOLINE_PHYS >> 12));
    if (wait_online(pc, SIPI_WAIT_MS))
        return true;
    lapic_send_sipi(pc->apic_id, (uint8_t)(TRAMPOLINE_PHYS >> 12));
    if (wait_online(pc, START_TIMEOUT_MS))
        return true;
    lapic_send_init(pc->apic_id);                            /* park it: it must not run stale code */
    kprintf("SMP: CPU %u (APIC id %u) did not start; continuing without it\n", pc->cpu_id, pc->apic_id);
    return false;
}

static bool low_ram_usable(const BootInfo *bi, uint64_t start, uint64_t end)
{
    const MemoryMapEntry *mm = (const MemoryMapEntry *)(uintptr_t)bi->mmap_addr;
    for (uint32_t i = 0; i < bi->mmap_count; i++)
        if (mm[i].type == MMAP_USABLE && mm[i].base <= start && mm[i].base + mm[i].length >= end)
            return true;
    return false;
}

void smp_init(const BootInfo *bi)
{
    interrupt_register(VEC_IPI, ipi_irq);
    bsp_cr0 = read_cr0();
    bsp_cr4 = read_cr4();
    bsp_efer_nx = rdmsr(MSR_EFER) & EFER_NXE;
    low_ram_ok = low_ram_usable(bi, TRAMPOLINE_PHYS, TRAMP_END);
    if (!acpi.madt || acpi.cpu_count < 2) {
        kprintf("SMP: 1 CPU (%s)\n", acpi.madt ? "the only one in the MADT" : "no ACPI MADT");
        return;
    }
    if (!low_ram_ok) {
        kprintf("SMP: memory %#llx-%#llx for the AP trampoline is not usable RAM; using 1 CPU\n",
                TRAMPOLINE_PHYS, TRAMP_END - 1);
        return;
    }
    uint64_t t0 = rdtsc();
    struct trampoline_params *prm = install_trampoline((uint64_t)(uintptr_t)ap_entry64);

    /* Per-CPU blocks, IST stacks and idle threads first, then INIT for all APs at once. */
    uint32_t first = cpu_slots;
    for (uint32_t i = 0; i < acpi.cpu_count && cpu_slots < MAX_CPUS; i++) {
        if (acpi.cpu_apic[i] == bsp_percpu.apic_id)
            continue;
        struct percpu *pc = ap_alloc(acpi.cpu_apic[i]);
        if (!pc) {
            kprintf("SMP: out of memory preparing CPU with APIC id %u\n", acpi.cpu_apic[i]);
            break;
        }
        cpus[cpu_slots++] = pc;
    }
    uint32_t count = cpu_slots < MAX_CPUS ? cpu_slots : MAX_CPUS;
    for (uint32_t c = first; c < count; c++)
        lapic_send_init(cpus[c]->apic_id);
    tsc_delay_us(INIT_WAIT_US);
    for (uint32_t c = first; c < count; c++)
        start_ap(cpus[c], prm);

    smp_clear_s3_trampoline();                               /* nothing executable left in low memory */
    bringup_us = tsc_to_us(rdtsc() - t0);
    if (smp_active())
        watchdog_start(&bsp_percpu);
    smp_print();
}

void smp_print(void)
{
    kprintf("SMP: %u CPUs online (%s), started in %llu.%03llu ms%s\n", smp_cpus(),
            lapic_x2apic() ? "x2APIC" : "xAPIC", (unsigned long long)(bringup_us / 1000),
            (unsigned long long)(bringup_us % 1000), smp_active() ? "; watchdog on" : "");
}

uint64_t smp_shootdowns(void) { return shootdowns; }
uint64_t smp_lazy_skips(void) { return lazy_skips; }
