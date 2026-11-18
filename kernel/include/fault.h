/*
 * Fault injection (test builds only, kernel/lib/fault.c): make the n-th allocation of the calling
 * thread fail, to prove that every out-of-memory path fails cleanly (no panic, no leak).
 *
 *   fault_inject_arm(FAULT_KMALLOC | FAULT_PMM, n);   // the n-th matching allocation fails (n >= 1)
 *   ... operation under test ...
 *   bool fired = fault_inject_disarm();               // false: the operation made fewer than n
 *
 * Scoped to the arming thread (other threads and interrupt handlers are never affected), and
 * one-shot: only the n-th allocation fails, later ones succeed. Release images contain none of it.
 */
#ifndef DOS_FAULT_H
#define DOS_FAULT_H

#include <stdbool.h>
#include <stdint.h>

#define FAULT_KMALLOC (1u << 0)
#define FAULT_PMM     (1u << 1)

#ifdef KTEST
void fault_inject_arm(uint32_t kinds, uint64_t nth);
bool fault_inject_disarm(void);
bool fault_should_fail(uint32_t kind);    /* allocator hook */
#else
static inline bool fault_should_fail(uint32_t kind) { (void)kind; return false; }
#endif

#endif
