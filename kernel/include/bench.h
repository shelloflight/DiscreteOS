/*
 * Benchmark harness (test builds only; build.ps1 test -Case bench).
 * Runs `fn` in batches, reports the best batch (steady state, least interference) and the mean,
 * in cycles and nanoseconds per operation:
 *   BENCH <name>: <best> cycles/op (<ns> ns), mean <cycles> cycles/op
 */
#ifndef DOS_BENCH_H
#define DOS_BENCH_H

#include <stdint.h>

typedef void (*bench_fn)(void *ctx);

void bench_run(const char *name, bench_fn fn, void *ctx, uint32_t iterations);

#endif
