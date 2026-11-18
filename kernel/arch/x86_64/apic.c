/*
 * Local APIC + tickless timer + IPIs, and I/O APIC interrupt routing.
 * LAPIC: x2APIC mode (registers are MSRs, 32-bit APIC IDs, one-write IPIs) when the CPU supports it,
 * else xAPIC (MMIO). Timer: tickless one-shot "clock event" (TSC-deadline mode where available, else
 * LAPIC one-shot). Every CPU programs only its own LAPIC.
 */

#include <stdint.h>
#include "acpi.h"
#include "apic.h"
#include "spinlock.h"
#include "arch.h"
#include "cpu.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "mm.h"
#include "ktime.h"

/* ---- Local APIC ---------------------------------------------------------------- */

#define LAPIC_ID          0x020
#define LAPIC_VERSION     0x030
#define LAPIC_TPR         0x080
#define LAPIC_EOI         0x0B0
#define LAPIC_SVR         0x0F0
#define LAPIC_ESR         0x280
#define LAPIC_ICR_LO      0x300
#define LAPIC_ICR_HI      0x310
#define LAPIC_LVT_TIMER   0x320
#define LAPIC_LVT_LINT0   0x350
#define LAPIC_LVT_ERROR   0x370
#define LAPIC_TIMER_INIT  0x380
#define LAPIC_TIMER_CUR   0x390
#define LAPIC_TIMER_DIV   0x3E0

#define LVT_MASKED        (1u << 16)
#define APIC_BASE_ENABLE  (1ull << 11)
#define APIC_BASE_X2APIC  (1ull << 10)
#define APIC_DEFAULT_BASE 0xFEE00000ull
#define TIMER_DIV_16      0x3
#define X2APIC_MSR(reg)   (0x800u + ((reg) >> 4))

#define ICR_FIXED         (0u << 8)
#define ICR_NMI           (4u << 8)
#define ICR_INIT          (5u << 8)
#define ICR_STARTUP       (6u << 8)
#define ICR_PENDING       (1u << 12)
#define ICR_ASSERT        (1u << 14)

static volatile uint32_t *lapic;          /* xAPIC MMIO (unused in x2APIC mode) */
static bool x2apic;
static bool ready;

static uint32_t lapic_read(uint32_t reg)
{
    if (x2apic)
        return (uint32_t)rdmsr(X2APIC_MSR(reg));
    return lapic[reg / 4];
}

static void lapic_write(uint32_t reg, uint32_t v)
{
    if (x2apic)
        wrmsr(X2APIC_MSR(reg), v);
    else
        lapic[reg / 4] = v;
}

uint32_t lapic_id(void) { return x2apic ? lapic_read(LAPIC_ID) : lapic_read(LAPIC_ID) >> 24; }
bool lapic_x2apic(void) { return x2apic; }

void lapic_eoi(void)
{
    if (ready)
        lapic_write(LAPIC_EOI, 0);
}

static void lapic_error_irq(struct interrupt_frame *f)
{
    (void)f;
    lapic_write(LAPIC_ESR, 0);
    kprintf("APIC: error on CPU %u, ESR=%#x\n", percpu_cpu_id(), lapic_read(LAPIC_ESR));
}

/* Enable this CPU's LAPIC in the chosen mode and set up its local vectors. */
static void lapic_setup(void)
{
    uint64_t msr = rdmsr(MSR_APIC_BASE);
    if (!(msr & APIC_BASE_ENABLE)) {
        msr |= APIC_BASE_ENABLE;                         /* disabled -> xAPIC first (SDM order) */
        wrmsr(MSR_APIC_BASE, msr);
    }
    if (x2apic && !(msr & APIC_BASE_X2APIC))
        wrmsr(MSR_APIC_BASE, msr | APIC_BASE_X2APIC);

    lapic_write(LAPIC_TPR, 0);                           /* accept all priorities */
    lapic_write(LAPIC_LVT_LINT0, LVT_MASKED);            /* PIC virtual-wire input: unused */
    lapic_write(LAPIC_LVT_ERROR, VEC_APIC_ERROR);
    lapic_write(LAPIC_ESR, 0);
    lapic_write(LAPIC_ESR, 0);
    lapic_write(LAPIC_SVR, 0x100 | VEC_SPURIOUS);        /* software enable + spurious vector */
    lapic_write(LAPIC_EOI, 0);
}

void lapic_init(void)
{
    if (!cpu.apic)
        panic("CPU has no local APIC (required)");

    uint64_t msr = rdmsr(MSR_APIC_BASE);
    uint64_t base = msr & 0x000FFFFFFFFFF000ull;
    if (!base)
        base = APIC_DEFAULT_BASE;
    if (acpi.madt && acpi.lapic_addr && acpi.lapic_addr != base)
        kprintf("APIC: ACPI reports LAPIC at %#llx, MSR says %#llx (using MSR)\n",
                (unsigned long long)acpi.lapic_addr, (unsigned long long)base);

    /* x2APIC: no MMIO, an IPI is a single MSR write, APIC IDs above 255 work. If firmware left the
     * CPU in x2APIC mode it cannot simply go back to xAPIC, so that is honoured too. */
    x2apic = cpu.x2apic || (msr & APIC_BASE_X2APIC);
    if (!x2apic)
        lapic = vmm_map_phys(base, 4096, VMM_W | VMM_UC);
    interrupt_register(VEC_APIC_ERROR, lapic_error_irq);
    lapic_setup();
    ready = true;
    bsp_percpu.apic_id = lapic_id();

    kprintf("APIC: local APIC id %u, version %#x, %s\n", lapic_id(), lapic_read(LAPIC_VERSION) & 0xFF,
            x2apic ? "x2APIC mode" : "xAPIC mode (MMIO)");
}

void lapic_init_ap(void) { lapic_setup(); }

/* ---- IPIs ----------------------------------------------------------------------------- */

static void icr_send(uint32_t apic_id, uint32_t low)
{
    uint64_t f = irq_save();                  /* an interrupt handler must not send between our writes */
    if (x2apic) {
        /* x2APIC MSR writes are not serializing: make earlier stores (the IPI's reason bits)
         * visible before the interrupt can arrive. */
        __asm__ volatile("mfence; lfence" ::: "memory");
        wrmsr(X2APIC_MSR(LAPIC_ICR_LO), ((uint64_t)apic_id << 32) | low);
    } else {
        lapic_write(LAPIC_ICR_HI, apic_id << 24);
        lapic_write(LAPIC_ICR_LO, low);
        for (uint32_t i = 0; i < 1000000 && (lapic_read(LAPIC_ICR_LO) & ICR_PENDING); i++)
            cpu_pause();                      /* bounded: delivery normally takes < 1 us */
    }
    irq_restore(f);
}

void lapic_send_ipi(uint32_t apic_id, uint8_t vector) { icr_send(apic_id, ICR_FIXED | ICR_ASSERT | vector); }
void lapic_send_nmi(uint32_t apic_id) { icr_send(apic_id, ICR_NMI | ICR_ASSERT); }
void lapic_send_init(uint32_t apic_id) { icr_send(apic_id, ICR_INIT | ICR_ASSERT); }
void lapic_send_sipi(uint32_t apic_id, uint8_t page) { icr_send(apic_id, ICR_STARTUP | ICR_ASSERT | page); }

/* ---- Timer: tickless clock event ---------------------------------------------------------
 * There is no periodic tick. ktime.c programs the next interrupt for the earliest timer deadline
 * (sleeps, timeouts, the scheduler's slice end), so an idle CPU stays asleep until there is work.
 *   TSC-deadline mode: the interrupt fires when the TSC reaches a value (exact, no conversion drift).
 *   LAPIC one-shot:    count down from a calibrated count (fallback; also if TSC-deadline misbehaves).
 * Calibration is done once on the boot CPU; every LAPIC timer runs from the same clock.
 */

#define LVT_TSC_DEADLINE (2u << 17)
#define MSR_TSC_DEADLINE 0x6E0
#define CALIBRATE_US     5000
#define MAX_PROGRAM_NS   NS_PER_S        /* far deadlines are reached in steps (fits the LAPIC counter) */

static enum { CE_TSC_DEADLINE, CE_ONESHOT } ce_mode;
static uint64_t lapic_per_ns;            /* LAPIC counts per ns, 32.32 fixed point */
static uint64_t tsc_per_ns;              /* TSC cycles per ns, 32.32 fixed point */
static uint64_t lapic_rate;              /* LAPIC counts per second (divide by 16) */

static uint64_t per_ns(uint64_t hz)      /* hz / 1e9 in 32.32, without 128-bit division */
{
    uint64_t q = hz / NS_PER_S, r = hz % NS_PER_S;
    return (q << 32) + (r << 32) / NS_PER_S;
}

static uint64_t mul_fp32(uint64_t a, uint64_t m) { return (uint64_t)(((unsigned __int128)a * m) >> 32); }

static void timer_irq(struct interrupt_frame *f)
{
    (void)f;
    percpu()->timer_irqs++;
    time_tick();
}

uint64_t timer_irqs(void)
{
    uint64_t n = 0;
    for (uint32_t i = 0; i < cpu_slots; i++)
        if (cpus[i])
            n += cpus[i]->timer_irqs;
    return n;
}

const char *timer_mode(void) { return ce_mode == CE_TSC_DEADLINE ? "TSC-deadline" : "LAPIC one-shot"; }

static void set_mode(void)
{
    lapic_write(LAPIC_TIMER_INIT, 0);
    if (ce_mode == CE_TSC_DEADLINE) {
        lapic_write(LAPIC_LVT_TIMER, VEC_TIMER | LVT_TSC_DEADLINE);
        __asm__ volatile("mfence" ::: "memory");   /* SDM: LVT write must land before the MSR write */
    } else {
        lapic_write(LAPIC_TIMER_DIV, TIMER_DIV_16);
        lapic_write(LAPIC_LVT_TIMER, VEC_TIMER);   /* one-shot */
    }
}

void timer_init(void)
{
    KASSERT(ready && tsc_hz);

    /* Count LAPIC timer ticks over a TSC-measured window. */
    lapic_write(LAPIC_TIMER_DIV, TIMER_DIV_16);
    lapic_write(LAPIC_LVT_TIMER, LVT_MASKED);
    lapic_write(LAPIC_TIMER_INIT, 0xFFFFFFFFu);
    tsc_delay_us(CALIBRATE_US);
    uint32_t elapsed = 0xFFFFFFFFu - lapic_read(LAPIC_TIMER_CUR);
    lapic_write(LAPIC_TIMER_INIT, 0);

    lapic_rate = (uint64_t)elapsed * (1000000 / CALIBRATE_US);
    if (lapic_rate < 1000)
        panic("APIC timer calibration failed");
    lapic_per_ns = per_ns(lapic_rate);
    tsc_per_ns = per_ns(tsc_hz);

    interrupt_register(VEC_TIMER, timer_irq);
    ce_mode = cpu.tsc_deadline ? CE_TSC_DEADLINE : CE_ONESHOT;
    set_mode();

    kprintf("APIC timer: bus %llu MHz, tickless (%s)\n",
            (unsigned long long)(lapic_rate * 16 / 1000000), timer_mode());
}

void timer_init_ap(void) { set_mode(); }

void timer_use_oneshot(void)
{
    if (ce_mode == CE_TSC_DEADLINE)
        wrmsr(MSR_TSC_DEADLINE, 0);
    ce_mode = CE_ONESHOT;
    set_mode();
}

void timer_program(uint64_t deadline_ns)
{
    if (deadline_ns == TIMER_NONE) {               /* nothing pending: no interrupts at all */
        if (ce_mode == CE_TSC_DEADLINE)
            wrmsr(MSR_TSC_DEADLINE, 0);
        else
            lapic_write(LAPIC_TIMER_INIT, 0);
        return;
    }
    uint64_t now = time_ns();
    uint64_t delta = deadline_ns > now ? deadline_ns - now : 0;
    if (delta > MAX_PROGRAM_NS)
        delta = MAX_PROGRAM_NS;

    if (ce_mode == CE_TSC_DEADLINE) {
        wrmsr(MSR_TSC_DEADLINE, rdtsc() + mul_fp32(delta, tsc_per_ns));   /* past value: fires now */
    } else {
        uint64_t count = mul_fp32(delta, lapic_per_ns);
        lapic_write(LAPIC_TIMER_INIT, count ? (uint32_t)count : 1u);     /* 1 s < 2^32 counts */
    }
}

/* ---- I/O APIC ---------------------------------------------------------------------- */

#define IOAPIC_REGSEL  0x00
#define IOAPIC_WIN     0x10
#define IOAPIC_VER     0x01
#define IOAPIC_REDTBL  0x10
#define IOAPIC_DEFAULT 0xFEC00000ull

struct ioapic {
    volatile uint32_t *mmio;
    uint32_t gsi_base, count;
};

static struct ioapic ioapics[ACPI_MAX_IOAPIC];
static uint32_t ioapic_n;

static uint32_t ioapic_read(const struct ioapic *io, uint32_t reg)
{
    io->mmio[IOAPIC_REGSEL / 4] = reg;
    return io->mmio[IOAPIC_WIN / 4];
}

static void ioapic_write(const struct ioapic *io, uint32_t reg, uint32_t v)
{
    io->mmio[IOAPIC_REGSEL / 4] = reg;
    io->mmio[IOAPIC_WIN / 4] = v;
}

static void ioapic_add(uint64_t addr, uint32_t gsi_base)
{
    if (ioapic_n == ACPI_MAX_IOAPIC || addr >= PHYSMAP_SIZE) {
        kprintf("IOAPIC: cannot use I/O APIC at %#llx\n", (unsigned long long)addr);
        return;
    }
    struct ioapic *io = &ioapics[ioapic_n++];
    io->mmio = vmm_map_phys(addr, 4096, VMM_W | VMM_UC);
    io->gsi_base = gsi_base;
    io->count = ((ioapic_read(io, IOAPIC_VER) >> 16) & 0xFF) + 1;

    for (uint32_t i = 0; i < io->count; i++) {                /* start fully masked */
        ioapic_write(io, IOAPIC_REDTBL + 2 * i, LVT_MASKED);
        ioapic_write(io, IOAPIC_REDTBL + 2 * i + 1, 0);
    }
    kprintf("IOAPIC: %u inputs at %#llx (GSI %u-%u)\n", io->count, (unsigned long long)addr,
            gsi_base, gsi_base + io->count - 1);
}

void ioapic_init(void)
{
    if (acpi.madt && acpi.ioapic_count) {
        for (uint32_t i = 0; i < acpi.ioapic_count; i++)
            ioapic_add(acpi.ioapic[i].addr, acpi.ioapic[i].gsi_base);
    } else {
        ioapic_add(IOAPIC_DEFAULT, 0);
    }
    if (!ioapic_n)
        panic("no usable I/O APIC");
}

/* REGSEL/WIN pairs must not interleave: routes change at run time (user-space drivers). */
static spinlock_t ioapic_lk = SPINLOCK_INIT("ioapic", LOCK_RANK_LEAF);

static bool ioapic_set_isa(uint8_t irq, uint8_t vector, bool masked)
{
    uint32_t gsi = irq;
    uint16_t flags = 0;                      /* ISA default: active high, edge triggered */
    for (uint32_t i = 0; i < acpi.iso_count; i++) {
        if (acpi.iso[i].irq == irq) {
            gsi = acpi.iso[i].gsi;
            flags = acpi.iso[i].flags;
        }
    }

    for (uint32_t i = 0; i < ioapic_n; i++) {
        struct ioapic *io = &ioapics[i];
        if (gsi < io->gsi_base || gsi >= io->gsi_base + io->count)
            continue;
        uint32_t pin = gsi - io->gsi_base;
        uint32_t low = vector;               /* fixed delivery, physical destination */
        if ((flags & 0x3) == 0x3)
            low |= 1u << 13;                 /* active low */
        if (((flags >> 2) & 0x3) == 0x3)
            low |= 1u << 15;                 /* level triggered */
        if (masked)
            low = LVT_MASKED;
        uint64_t f = spin_lock_irqsave(&ioapic_lk);
        /* Always the boot CPU: device interrupts are handled there (irq_target_apic()). */
        ioapic_write(io, IOAPIC_REDTBL + 2 * pin + 1, bsp_percpu.apic_id << 24);
        ioapic_write(io, IOAPIC_REDTBL + 2 * pin, low);
        spin_unlock_irqrestore(&ioapic_lk, f);
        return true;
    }
    return false;
}

bool ioapic_route_isa_irq(uint8_t irq, uint8_t vector) { return ioapic_set_isa(irq, vector, false); }
void ioapic_mask_isa_irq(uint8_t irq) { (void)ioapic_set_isa(irq, 0, true); }
uint32_t irq_target_apic(void) { return bsp_percpu.apic_id; }
