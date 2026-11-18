/*
 * Transient-execution mitigations, chosen from what the CPU reports (spec.h, docs/hardening.md).
 *
 *  - Meltdown (Intel without RDCL_NO): a user load from a kernel address faults, but the CPU may
 *    use the value speculatively first. KPTI: user mode runs on page tables holding only the
 *    entry pages (kernel/mm/kpti.c); the entry code switches CR3.
 *  - Spectre v2 (branch target injection): user code trains the indirect branch predictor to
 *    send a kernel indirect branch to a gadget. eIBRS (Intel) or AutoIBRS (AMD) stop predictions
 *    made in user mode from applying in the kernel; without them every indirect branch goes
 *    through a retpoline (thunk.asm, compiler `retpoline-external-thunk`), and the return stack
 *    buffer is refilled on context switch so a `ret` never falls back to the branch predictor.
 *    With eIBRS/AutoIBRS the thunk is patched to a plain `jmp r11` here.
 *  - IBPB when a thread of another process runs: one process cannot steer another's branches.
 *  - MDS / TAA (Intel without MDS_NO / TAA_NO): data left in CPU buffers can be sampled; VERW
 *    (with the MD_CLEAR microcode) clears them before every return to user mode.
 *  - Spectre v1 (bounds-check bypass): user-controlled indices are clamped without a branch
 *    (array_index_nospec): the syscall number and the handle slot index. The SWAPGS fence is in
 *    isr.asm.
 * Decided once on the boot CPU; every CPU applies the same policy (spec_cpu_init) and reports a
 * CPU that differs.
 */

#include "spec.h"
#include "compiler.h"
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "string.h"

#define MSR_SPEC_CTRL      0x48
#define MSR_PRED_CMD       0x49
#define MSR_ARCH_CAP       0x10A
#define SPEC_CTRL_IBRS     (1ull << 0)
#define PRED_CMD_IBPB      (1ull << 0)
#define EFER_AUTOIBRS      (1ull << 21)

#define ARCH_CAP_RDCL_NO   (1ull << 0)
#define ARCH_CAP_IBRS_ALL  (1ull << 1)
#define ARCH_CAP_MDS_NO    (1ull << 5)
#define ARCH_CAP_TAA_NO    (1ull << 8)

struct spec_state spec RO_AFTER_INIT;

extern uint8_t __x86_indirect_thunk_r11[];   /* thunk.asm */

static bool bit(uint32_t v, unsigned n) { return (v >> n) & 1u; }

struct cpu_bits {
    bool arch_cap_present, md_clear, spec_ctrl, rtm, amd_ibpb, autoibrs;
    uint64_t arch_cap;
};

static void read_bits(struct cpu_bits *b)
{
    uint32_t r[4];
    memset(b, 0, sizeof(*b));
    if (cpu.max_leaf >= 7) {
        cpuid(7, 0, r);
        b->rtm = bit(r[1], 11);
        b->md_clear = bit(r[3], 10);
        b->spec_ctrl = bit(r[3], 26);            /* IBRS + IBPB (Intel enumeration) */
        b->arch_cap_present = bit(r[3], 29);
    }
    if (b->arch_cap_present)
        b->arch_cap = rdmsr(MSR_ARCH_CAP);
    if (cpu.max_ext_leaf >= 0x80000008u) {
        cpuid(0x80000008u, 0, r);
        b->amd_ibpb = bit(r[1], 12);
    }
    if (cpu.max_ext_leaf >= 0x80000021u) {
        cpuid(0x80000021u, 0, r);
        b->autoibrs = bit(r[0], 8);
    }
}

/* With eIBRS/AutoIBRS a plain indirect branch is safe: `jmp r11` (41 FF E3) replaces the
 * retpoline. Runs while kernel text is still writable (cpu_init, before CR0.WP). */
static void patch_thunk(void)
{
    uint8_t *p = __x86_indirect_thunk_r11;
    KASSERT(p[0] == 0xE8);                       /* call (the retpoline's first instruction) */
    p[0] = 0x41;
    p[1] = 0xFF;
    p[2] = 0xE3;
    for (unsigned i = 3; i < 16; i++)
        p[i] = 0xCC;                             /* int3: nothing may run past the jump */
}

void spec_detect(void)
{
    struct cpu_bits b;
    read_bits(&b);
    spec.intel = !strcmp(cpu.vendor, "GenuineIntel");
    spec.amd = !strcmp(cpu.vendor, "AuthenticAMD") || !strcmp(cpu.vendor, "HygonGenuine");
    spec.arch_cap_present = b.arch_cap_present;
    spec.arch_cap = b.arch_cap;
    spec.md_clear = b.md_clear;
    spec.ibpb_ok = b.spec_ctrl || b.amd_ibpb;

    spec.meltdown = spec.intel && !(b.arch_cap & ARCH_CAP_RDCL_NO);
    spec.mds = spec.intel && !(b.arch_cap & ARCH_CAP_MDS_NO);
    spec.taa = spec.intel && b.rtm && !(b.arch_cap & ARCH_CAP_TAA_NO);

    if (spec.intel && b.spec_ctrl && (b.arch_cap & ARCH_CAP_IBRS_ALL))
        spec.v2 = V2_EIBRS;
    else if (spec.amd && b.autoibrs)
        spec.v2 = V2_AUTOIBRS;
    else
        spec.v2 = V2_RETPOLINE;

    uint32_t m = 0;
    if (spec.meltdown)
        m |= MIT_KPTI;
    if ((spec.mds || spec.taa) && spec.md_clear)
        m |= MIT_VERW;
    if (spec.ibpb_ok)
        m |= MIT_IBPB;
    if (spec.v2 == V2_RETPOLINE)
        m |= MIT_RSB;
#ifdef KTEST_SPEC
    /* Test build: every entry/exit path on, whatever the CPU (VERW runs on any CPU; it only
     * clears buffers with MD_CLEAR). IBPB needs the MSR, so it stays as detected. */
    spec.forced = true;
    m |= MIT_KPTI | MIT_VERW | MIT_RSB;
#endif
    spec.mitig = m;

    if (spec.v2 != V2_RETPOLINE)
        patch_thunk();
}

/* Every CPU (from user_cpu_init, after its per-CPU block is installed). */
void spec_cpu_init(void)
{
    struct percpu *pc = percpu();
    if (spec.v2 == V2_EIBRS)
        wrmsr(MSR_SPEC_CTRL, rdmsr(MSR_SPEC_CTRL) | SPEC_CTRL_IBRS);
    else if (spec.v2 == V2_AUTOIBRS)
        wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_AUTOIBRS);
    pc->mitig = spec.mitig;

    if (pc != &bsp_percpu) {
        /* The policy came from the boot CPU; a CPU that reports more vulnerabilities than it
         * covers would run unprotected. Not seen on real machines; say so if it happens. */
        struct cpu_bits b;
        read_bits(&b);
        if (b.arch_cap != spec.arch_cap || b.md_clear != spec.md_clear)
            kprintf("warning: CPU %u reports different speculation capabilities (ARCH_CAPABILITIES %#llx, "
                    "boot CPU %#llx); mitigations follow the boot CPU\n",
                    pc->cpu_id, (unsigned long long)b.arch_cap, (unsigned long long)spec.arch_cap);
    }
}

void spec_ibpb(void)
{
    wrmsr(MSR_PRED_CMD, PRED_CMD_IBPB);
}

static const char *v2_name(void)
{
    switch (spec.v2) {
    case V2_EIBRS:    return "eIBRS";
    case V2_AUTOIBRS: return "AutoIBRS";
    default:          return "retpolines + RSB filling";
    }
}

void spec_print(void)
{
    const char *melt = !spec.meltdown ? (spec.mitig & MIT_KPTI ? "not affected, KPTI forced on (test)" : "not affected, KPTI off")
                                      : "affected, KPTI on";
    kprintf("Speculation: Meltdown %s; Spectre v2 %s; IBPB %s\n", melt, v2_name(),
            spec.ibpb_ok ? "on process switch" : "not available (no microcode support)");
    const char *mds;
    if (!spec.mds && !spec.taa)
        mds = spec.mitig & MIT_VERW ? "not affected, VERW forced on (test)" : "not affected";
    else if (spec.mitig & MIT_VERW)
        mds = "affected, VERW on return to user";
    else
        mds = "affected, NOT mitigated (no MD_CLEAR microcode)";
    kprintf("Speculation: MDS/TAA %s; Spectre v1 index clamping (syscall numbers, handles), SWAPGS fence\n", mds);
    if (spec.arch_cap_present)
        kprintf("Speculation: IA32_ARCH_CAPABILITIES %#llx\n", (unsigned long long)spec.arch_cap);
}

const char *spec_summary(char *buf, unsigned size)
{
    ksnprintf(buf, size, "KPTI %s, Spectre v2 %s, IBPB %s, VERW %s", (spec.mitig & MIT_KPTI) ? "on" : "off (not needed)",
              v2_name(), spec.ibpb_ok ? "on" : "unavailable",
              (spec.mitig & MIT_VERW) ? "on" : (spec.mds || spec.taa) ? "UNAVAILABLE" : "off (not needed)");
    return buf;
}
