/*
 * In-kernel test hooks. Only compiled into test images (build.ps1 test builds variants with -DKTEST -DKTEST_<NAME>).
 * Release images contain no test code.
 */
#ifndef DOS_KTEST_H
#define DOS_KTEST_H

#include "bootinfo.h"

#ifdef KTEST
extern const BootInfo *ktest_bootinfo;   /* set by kmain before ktest_run() */
void ktest_run(void);
const char *ktest_init_args(void);       /* what init runs in this test image */
void ktest_after_init(int code);         /* init exited (called by its watcher) */
void ktest_spec_user_entry(void);        /* KTEST_SPEC: an interrupt from ring 3 (idt.c) */
#define ktest_set_bootinfo(bi) (ktest_bootinfo = (bi))
#else
static inline void ktest_run(void) {}
#define ktest_set_bootinfo(bi) ((void)(bi))
#endif

#endif
