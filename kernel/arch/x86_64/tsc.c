/*
 * TSC frequency calibration. Order of preference:
 *   1. CPUID leaf 0x15 (exact, no waiting)
 *   2. PIT channel 2 one-shot over 5 ms
 *   3. CPUID leaf 0x16 base frequency (approximate)
 */

#include <stdint.h>
#include "cpu.h"
#include "printf.h"

uint64_t tsc_hz;
static const char *tsc_source = "none";

#define PIT_HZ        1193182ull
#define PIT_WINDOW_MS 5

static uint64_t tsc_from_cpuid15(void)
{
    uint32_t r[4];
    if (cpu.max_leaf < 0x15)
        return 0;
    cpuid(0x15, 0, r);                       /* EAX denominator, EBX numerator, ECX crystal Hz */
    if (!r[0] || !r[1] || !r[2])
        return 0;
    return (uint64_t)r[2] * r[1] / r[0];
}

static uint64_t tsc_from_pit(void)
{
    const uint16_t count = (uint16_t)(PIT_HZ * PIT_WINDOW_MS / 1000);

    outb(0x61, (uint8_t)((inb(0x61) & ~0x02) | 0x01));   /* gate ch2 on, speaker off */
    outb(0x43, 0xB0);                                   /* ch2, lo/hi byte, mode 0 */
    outb(0x42, (uint8_t)count);
    outb(0x42, (uint8_t)(count >> 8));

    uint64_t start = rdtsc();
    /* Bounded wait: give up after ~2^34 cycles (seconds on any real CPU) if there is no PIT. */
    while (!(inb(0x61) & 0x20)) {
        if (rdtsc() - start > (1ull << 34))
            return 0;
    }
    uint64_t cycles = rdtsc() - start;
    return cycles * 1000 / PIT_WINDOW_MS;
}

static uint64_t tsc_from_cpuid16(void)
{
    uint32_t r[4];
    if (cpu.max_leaf < 0x16)
        return 0;
    cpuid(0x16, 0, r);                       /* EAX base MHz */
    return (uint64_t)(r[0] & 0xFFFF) * 1000000ull;
}

void tsc_init(void)
{
    if ((tsc_hz = tsc_from_cpuid15()))
        tsc_source = "CPUID 0x15";
    else if ((tsc_hz = tsc_from_pit()))
        tsc_source = "PIT";
    else if ((tsc_hz = tsc_from_cpuid16()))
        tsc_source = "CPUID 0x16 (approx.)";
    else {
        tsc_hz = 1000000000ull;
        tsc_source = "ASSUMED 1 GHz";
    }

    kprintf("TSC: %llu MHz (%s%s)\n", (unsigned long long)(tsc_hz / 1000000), tsc_source,
            cpu.invariant_tsc ? ", invariant" : ", not invariant");
}

uint64_t tsc_to_us(uint64_t cycles)
{
    return tsc_hz ? cycles / (tsc_hz / 1000000 ? tsc_hz / 1000000 : 1) : 0;
}

void tsc_delay_us(uint64_t us)
{
    uint64_t end = rdtsc() + us * (tsc_hz / 1000000);
    while (rdtsc() < end)
        cpu_pause();
}
