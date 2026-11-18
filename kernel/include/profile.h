/*
 * Sampling profiler and latency histograms (kernel/lib/profile.c).
 *
 * Profiler: while on, every online CPU samples where it was interrupted at `hz` (a periodic timer
 * per CPU, so the tickless kernel only takes these interrupts while profiling). Kernel samples are
 * attributed to functions through the kernel symbol table; user and idle time are counted apart.
 *
 * Histograms: log2 buckets of nanoseconds for syscalls, wake-up-to-run latency and interrupt
 * handlers. They record only while the profiler is on (`profile_active`: one load on the hot
 * paths when it is off, which is always outside profiling sessions).
 *
 * Interface: kdb `prof [ms]` (sample for ms, then print), `lat` (histograms so far).
 */
#ifndef DOS_PROFILE_H
#define DOS_PROFILE_H

#include <stdbool.h>
#include <stdint.h>

#define LAT_BUCKETS 40

struct lat_hist {
    const char *name;
    uint64_t    count, sum_ns, max_ns;
    uint64_t    bucket[LAT_BUCKETS];     /* bucket i: [2^i, 2^(i+1)) ns; bucket 0 also holds 0 */
};

extern uint32_t profile_active;          /* read directly by hot paths (C and Rust) */
extern struct lat_hist lat_syscall, lat_wakeup, lat_irq;

void profile_start(uint32_t hz);         /* reset samples and histograms, start sampling */
void profile_stop(void);
/* Print the share of kernel / user / idle time and the top `top` kernel functions; returns the
 * name of the busiest kernel function (NULL if none). */
const char *profile_print(unsigned top);
void lat_record(struct lat_hist *h, uint64_t ns);
void lat_print_all(void);

static inline void lat_note(struct lat_hist *h, uint64_t ns)
{
    if (__atomic_load_n(&profile_active, __ATOMIC_RELAXED))
        lat_record(h, ns);
}

#endif
