/* x86-64 CPU primitives: port I/O, MSRs, control registers, CPUID, feature detection. */
#ifndef DOS_CPU_H
#define DOS_CPU_H

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"

/* ---- port I/O ---------------------------------------------------------------- */
static inline void outb(uint16_t port, uint8_t v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(port)); }

static inline uint8_t inb(uint16_t port)
{
    uint8_t v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static inline void io_wait(void) { outb(0x80, 0); }

/* ---- timing ------------------------------------------------------------------ */
static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* ---- CPUID / MSR ------------------------------------------------------------- */
static inline void cpuid(uint32_t leaf, uint32_t sub, uint32_t r[4])
{
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t v)
{
    __asm__ volatile("wrmsr" : : "c"(msr), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)) : "memory");
}

#define MSR_APIC_BASE 0x1B
#define MSR_EFER      0xC0000080
#define MSR_PAT       0x277
#define EFER_NXE      (1ull << 11)

/* ---- control registers ------------------------------------------------------- */
#define DEFINE_CR(n)                                                                     \
    static inline uint64_t read_cr##n(void)                                              \
    {                                                                                    \
        uint64_t v;                                                                      \
        __asm__ volatile("mov %%cr" #n ", %0" : "=r"(v));                                \
        return v;                                                                        \
    }                                                                                    \
    static inline void write_cr##n(uint64_t v) { __asm__ volatile("mov %0, %%cr" #n : : "r"(v) : "memory"); }
DEFINE_CR(0)
DEFINE_CR(2)
DEFINE_CR(3)
DEFINE_CR(4)
#undef DEFINE_CR

#define CR0_MP   (1ull << 1)
#define CR0_EM   (1ull << 2)
#define CR0_TS   (1ull << 3)
#define CR0_NE   (1ull << 5)
#define CR0_WP   (1ull << 16)
#define CR4_OSFXSR     (1ull << 9)
#define CR4_OSXMMEXCPT (1ull << 10)
#define CR4_UMIP (1ull << 11)
#define CR4_SMEP (1ull << 20)
#define CR4_SMAP (1ull << 21)

/* ---- interrupts / halting ---------------------------------------------------- */
static inline void cpu_cli(void) { __asm__ volatile("cli" ::: "memory"); }
static inline void cpu_sti(void) { __asm__ volatile("sti" ::: "memory"); }
static inline void cpu_pause(void) { __asm__ volatile("pause"); }

/* Enable interrupts and sleep until the next one (STI's one-instruction shadow makes this race-free). */
static inline void cpu_idle(void) { __asm__ volatile("sti; hlt" ::: "memory"); }

static inline NORETURN void cpu_halt_forever(void)
{
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* ---- feature detection (arch/x86_64/cpu.c) ---------------------------------- */
struct cpu_info {
    char     vendor[13];
    char     brand[49];
    uint32_t max_leaf, max_ext_leaf;
    bool     apic, x2apic, tsc_deadline, invariant_tsc, rdrand, hypervisor;
    bool     rdrand_broken;          /* CPUID says RDRAND, but it failed the boot self-check */
    bool     nx, smep, smap, umip;
    bool     cet_ss, cet_ibt;     /* CET shadow stacks / indirect branch tracking supported (use: cet.c) */
    bool     pat;                    /* PAT: entry 1 is write-combining (cpu_init_pat), VMM_WC */
    bool     xsave;                  /* XSAVE enabled (CR4.OSXSAVE, XCR0 = xcr0) */
    uint64_t xcr0;                   /* state components saved for user threads */
    uint32_t fpu_size;               /* bytes of FPU state per user thread (XSAVE or FXSAVE area) */
};

extern struct cpu_info cpu;

#define CR4_OSXSAVE (1ull << 18)

/* User FPU state: XSAVE when the CPU has it (x87, SSE, AVX, AVX-512 as supported), else FXSAVE. */
static inline void xsetbv(uint32_t reg, uint64_t v)
{
    __asm__ volatile("xsetbv" : : "c"(reg), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)) : "memory");
}

static inline void fpu_save(void *area)
{
    if (cpu.xsave)
        __asm__ volatile("xsave64 (%0)" : : "r"(area), "a"(0xFFFFFFFFu), "d"(0xFFFFFFFFu) : "memory");
    else
        __asm__ volatile("fxsave64 (%0)" : : "r"(area) : "memory");
}

static inline void fpu_restore(const void *area)
{
    if (cpu.xsave)
        __asm__ volatile("xrstor64 (%0)" : : "r"(area), "a"(0xFFFFFFFFu), "d"(0xFFFFFFFFu) : "memory");
    else
        __asm__ volatile("fxrstor64 (%0)" : : "r"(area) : "memory");
}

/* This CPU's XCR0 (every CPU, after CR4 is set up). */
void cpu_init_xsave(void);
void cpu_init_pat(void);             /* every CPU: PAT entry 1 = WC (no-op without PAT) */

/* Detect features and enable CPU protections (WP, NX, SMEP, SMAP, UMIP). */
void cpu_init(void);
void cpu_print_info(void);

/* 64 random bits: RDRAND when available and sane, otherwise a mixed TSC value (weak; logged at
 * boot). RDRAND results of all-ones or zero are refused (AMD erratum: ~0 with CF=1). */
uint64_t cpu_random64(void);

/* TSC value captured by entry.asm on the very first kernel instruction. */
extern uint64_t kernel_entry_tsc;

/* ---- TSC calibration (arch/x86_64/tsc.c) ------------------------------------ */
extern uint64_t tsc_hz;
void     tsc_init(void);
uint64_t tsc_to_us(uint64_t cycles);
void     tsc_delay_us(uint64_t us);

#endif
