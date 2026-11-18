/* Benchmark harness (see bench.h). Only built into test images. */
#ifdef KTEST

#include <stdint.h>
#include "bench.h"
#include "cpu.h"
#include "ktime.h"
#include "printf.h"

#define BATCH 64

void bench_run(const char *name, bench_fn fn, void *ctx, uint32_t iterations)
{
    for (uint32_t i = 0; i < BATCH; i++)         /* warm caches, TLB, slab free lists */
        fn(ctx);

    uint64_t best = UINT64_MAX, total = 0, ops = 0;
    for (uint32_t done = 0; done < iterations; done += BATCH) {
        uint64_t t0 = rdtsc();
        for (uint32_t i = 0; i < BATCH; i++)
            fn(ctx);
        uint64_t dt = rdtsc() - t0;
        if (dt < best)
            best = dt;
        total += dt;
        ops += BATCH;
    }
    uint64_t per = best / BATCH;
    uint64_t ns10 = time_cycles_to_ns(best * 10 / BATCH);   /* tenths of ns */
    kprintf("BENCH %s: %llu cycles/op (%llu.%llu ns), mean %llu cycles/op\n", name,
            (unsigned long long)per, (unsigned long long)(ns10 / 10), (unsigned long long)(ns10 % 10),
            (unsigned long long)(total / ops));
}

#endif /* KTEST */
