/*
 * Transient-execution (speculative execution) mitigations: kernel/arch/x86_64/spec.c.
 * Chosen once on the boot CPU from CPUID and IA32_ARCH_CAPABILITIES, applied on every CPU.
 * docs/hardening.md has the table: what each one protects against and how it is tested.
 */
#ifndef DOS_SPEC_H
#define DOS_SPEC_H

#include <stdbool.h>
#include <stdint.h>

/* percpu.mitig bits, read by the entry code (isr.asm, syscall.asm, switch.asm): keep in sync. */
#define MIT_KPTI  1u     /* separate user page tables: switch CR3 on entry and exit */
#define MIT_VERW  2u     /* clear CPU buffers (VERW) before returning to user mode */
#define MIT_IBPB  4u     /* flush branch predictions when another process's thread runs */
#define MIT_RSB   8u     /* refill the return stack buffer on context switch */
#define MIT_SHSTK 16u    /* CET supervisor shadow stacks are on (cet.c): switch them with threads,
                          * mark/clear the busy token on ring-3 entry/exit */

enum spec_v2 { V2_RETPOLINE, V2_EIBRS, V2_AUTOIBRS };

struct spec_state {
    bool     intel, amd;
    bool     arch_cap_present;
    uint64_t arch_cap;          /* IA32_ARCH_CAPABILITIES (0 when absent) */
    bool     meltdown;          /* affected: kernel memory readable through a faulting load */
    bool     mds, taa;          /* affected: CPU buffers leak across privilege levels */
    bool     md_clear;          /* VERW clears those buffers (microcode) */
    bool     ibpb_ok;           /* IBPB command available */
    bool     forced;            /* test build: every mitigation forced on (KTEST_SPEC) */
    enum spec_v2 v2;
    uint32_t mitig;             /* MIT_* for every CPU */
};

extern struct spec_state spec;

void spec_detect(void);                 /* boot CPU, from cpu_init, while kernel text is writable */
void spec_cpu_init(void);               /* every CPU: MSRs and percpu.mitig (user_cpu_init) */
void spec_ibpb(void);                  /* flush indirect branch predictions (MIT_IBPB) */
void spec_print(void);
const char *spec_summary(char *buf, unsigned size);   /* one line for the boot summary */

/* KPTI (kernel/mm/kpti.c) */
bool kpti_on(void);
void kpti_init(void);                   /* after vmm_activate: the entry mappings, boot CPU */
void kpti_map_cpu(const void *percpu_page, const uint64_t ist_top[3], unsigned ist_size);   /* each AP */
uint64_t kpti_user_pml4_new(uint64_t kernel_pml4);   /* 0 = out of memory */
void kpti_user_pml4_sync(uint64_t kernel_pml4, uint64_t user_pml4, unsigned from, unsigned to);
uint64_t kpti_shadow_pages(void);       /* pages of kernel memory visible in user page tables */
void kpti_print(void);
int  kpti_classify_pml4(uint64_t pa);   /* 1: user tables, 0: the kernel's half, -1: unknown */
bool kpti_selfcheck(char *why, unsigned size);   /* ktest: user tables map only the entry pages */

/* Speculation-safe index: `i` if i < size, else 0, also on a mispredicted bounds check (the
 * mask is computed without a branch). Call it after the real bounds check. */
static inline uint64_t array_index_nospec(uint64_t i, uint64_t size)
{
    uint64_t mask;
    __asm__("cmp %2, %1\n\tsbb %0, %0" : "=r"(mask) : "r"(i), "r"(size) : "cc");
    return i & mask;
}

#endif
