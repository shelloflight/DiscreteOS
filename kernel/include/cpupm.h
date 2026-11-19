/*
 * CPU power management: idle states and performance control (kernel/arch/x86_64/cpupm.c,
 * docs/power.md).
 *
 * Idle: an idle CPU waits in the deepest C-state worth its exit latency. At boot that is MWAIT C1
 * on bare metal (a store to need_resched wakes it: no IPI needed) or HLT; once the AML namespace is
 * loaded, the processor's _CST adds deeper states (MWAIT hints, I/O-port reads).
 *
 * Performance: ACPI _CPC (CPPC; its "functional fixed hardware" registers are MSR fields), Intel
 * HWP or AMD's CPPC MSRs run the CPU autonomously with an energy-performance preference; only
 * _PSS (P-states) is driven by the kernel: the fastest one.
 */
#ifndef DOS_CPUPM_H
#define DOS_CPUPM_H

#include <stdbool.h>
#include <stdint.h>

struct percpu;

#define CPUPM_MAX_CSTATES 6
#define CPUPM_MAX_PSTATES 16

enum cpupm_entry { CPUPM_HLT, CPUPM_MWAIT, CPUPM_IO };

/* One _CST entry, as the AML side read it (shared with Rust: dev/cpupm.rs). */
struct cpupm_cstate {
    uint32_t entry;          /* enum cpupm_entry */
    uint32_t type;           /* ACPI C-state type 1, 2 or 3 */
    uint32_t arg;            /* MWAIT hint (EAX) or I/O port */
    uint32_t latency_us;
};

/* A _CPC or _PCT element: a constant, an MSR field ("functional fixed hardware") or an I/O port. */
enum cpupm_reg_kind { CPUPM_REG_NONE, CPUPM_REG_INT, CPUPM_REG_MSR, CPUPM_REG_IO };
struct cpupm_reg {
    uint32_t kind;           /* enum cpupm_reg_kind */
    uint8_t  bit_offset, bit_width;
    uint16_t reserved;
    uint64_t value;          /* the constant, the MSR number or the port */
};

/* What the firmware describes for the processors (the first present one stands for all). */
struct cpupm_desc {
    uint32_t ncstates;
    uint32_t npstates;
    struct cpupm_cstate cst[CPUPM_MAX_CSTATES];
    /* _CPC (CPPC, revision 2 or 3); cpc = 0: none, or registers this kernel cannot reach (PCC) */
    uint32_t cpc;
    uint32_t cpc_lowest_mhz, cpc_nominal_mhz;
    uint32_t reserved;
    struct cpupm_reg highest, nominal, lowest_nonlinear, lowest;
    struct cpupm_reg desired, min, max, enable, autonomous, epp;
    /* _PSS / _PCT */
    struct cpupm_reg pct_control;
    uint32_t pss_mhz[CPUPM_MAX_PSTATES];
    uint64_t pss_control[CPUPM_MAX_PSTATES];
};
_Static_assert(sizeof(struct cpupm_reg) == 16, "cpupm_reg layout is shared with Rust");
_Static_assert(sizeof(struct cpupm_desc) == 120 + 11 * 16 + 64 + 128, "cpupm_desc layout is shared with Rust");

enum cpupm_policy { CPUPM_PERFORMANCE, CPUPM_BALANCED, CPUPM_POWERSAVE };

void cpupm_init(void);                          /* boot CPU, after cpu_init and time_init */
void cpupm_idle(struct percpu *pc);             /* idle loop: interrupts off, returns with them on */
/* The ACPI thread, once: the firmware's description (NULL: none, e.g. no AML). Configures every
 * CPU (may block). */
void cpupm_configure(const struct cpupm_desc *d);
/* Energy-performance preference for every CPU (CPPC/HWP), or the P-state (_PSS). May block.
 * False when the CPU has no performance control the kernel drives. */
bool cpupm_set_policy(enum cpupm_policy p);
void cpupm_print(void);                         /* idle and performance state (kdb) */
#ifdef KTEST
extern bool cpupm_test_force_deep;              /* use deep _CST states even under a hypervisor */
#endif

#endif
