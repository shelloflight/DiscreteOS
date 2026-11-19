/* CPU feature detection and hardware protection setup. */

#include "cpu.h"
#include "printf.h"
#include "spec.h"
#include "string.h"
#include "user.h"

struct cpu_info cpu;

static bool bit(uint32_t v, unsigned n) { return (v >> n) & 1u; }
static void rdrand_check(void);

void cpu_init(void)
{
    uint32_t r[4];

    cpuid(0, 0, r);
    cpu.max_leaf = r[0];
    memcpy(cpu.vendor + 0, &r[1], 4);
    memcpy(cpu.vendor + 4, &r[3], 4);
    memcpy(cpu.vendor + 8, &r[2], 4);
    cpu.vendor[12] = '\0';

    cpuid(0x80000000u, 0, r);
    cpu.max_ext_leaf = r[0];

    if (cpu.max_leaf >= 1) {
        cpuid(1, 0, r);
        cpu.apic         = bit(r[3], 9);
        cpu.x2apic       = bit(r[2], 21);
        cpu.tsc_deadline = bit(r[2], 24);
        cpu.rdrand       = bit(r[2], 30);
        cpu.hypervisor   = bit(r[2], 31);
        cpu.pat          = bit(r[3], 16);
        cpu.monitor      = bit(r[2], 3);
        cpu.family       = (r[0] >> 8) & 0xF;
        if (cpu.family == 0xF)
            cpu.family += (r[0] >> 20) & 0xFF;
        if (cpu.rdrand)
            rdrand_check();
    }
    if (cpu.max_leaf >= 5 && cpu.monitor) {
        cpuid(5, 0, r);
        cpu.mwait_irq = bit(r[2], 0) && bit(r[2], 1);
        cpu.mwait_substates = r[3];
    }
    if (cpu.max_leaf >= 6) {
        cpuid(6, 0, r);
        cpu.arat = bit(r[0], 2);
        cpu.hwp = bit(r[0], 7);
        cpu.hwp_epp = cpu.hwp && bit(r[0], 10);
    }
    if (cpu.max_leaf >= 7) {
        cpuid(7, 0, r);
        cpu.smep = bit(r[1], 7);
        cpu.smap = bit(r[1], 20);
        cpu.umip = bit(r[2], 2);
        cpu.cet_ss = bit(r[2], 7);
        cpu.cet_ibt = bit(r[3], 20);
    }
    if (cpu.max_ext_leaf >= 0x80000001u) {
        cpuid(0x80000001u, 0, r);
        cpu.nx = bit(r[3], 20);
    }
    if (cpu.max_ext_leaf >= 0x80000007u) {
        cpuid(0x80000007u, 0, r);
        cpu.invariant_tsc = bit(r[3], 8);
    }
    if (cpu.max_ext_leaf >= 0x80000008u && strcmp(cpu.vendor, "AuthenticAMD") == 0) {
        cpuid(0x80000008u, 0, r);
        cpu.amd_cppc = bit(r[1], 27);
    }
    if (cpu.max_ext_leaf >= 0x80000004u) {
        for (uint32_t i = 0; i < 3; i++) {
            cpuid(0x80000002u + i, 0, r);
            memcpy(cpu.brand + 16 * i, r, 16);
        }
        cpu.brand[48] = '\0';
        size_t skip = 0;
        while (cpu.brand[skip] == ' ')
            skip++;
        memmove(cpu.brand, cpu.brand + skip, sizeof(cpu.brand) - skip);
        size_t len = strlen(cpu.brand);  /* AMD pads the model name with spaces at the end too */
        while (len && cpu.brand[len - 1] == ' ')
            cpu.brand[--len] = 0;
    }

    /* --- Protections ---------------------------------------------------------------
     * WP:   supervisor writes honour read-only pages (needed for W^X in the kernel)
     * NX:   allow non-executable pages
     * SMEP: kernel never executes user pages;  SMAP: kernel never touches user data implicitly
     * UMIP: user code can't read descriptor-table registers (SGDT/SIDT/...) */
    spec_detect();                        /* speculation mitigations; may patch the retpoline thunk */
    user_smap_patch();                    /* before WP: kernel text is still writable here */
    write_cr0((read_cr0() | CR0_WP | CR0_MP | CR0_NE) & ~(CR0_EM | CR0_TS));   /* FPU for user threads */
    if (cpu.nx)
        wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_NXE);

    uint64_t cr4 = read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT;   /* FXSAVE/SSE for user threads */
    if (cpu.smep) cr4 |= CR4_SMEP;
    if (cpu.smap) cr4 |= CR4_SMAP;
    if (cpu.umip) cr4 |= CR4_UMIP;

    /* XSAVE: user threads get every state component the CPU has among x87, SSE, AVX and
     * AVX-512 (opmask, ZMM_Hi256, Hi16_ZMM); others (MPX, PT, AMX, ...) stay disabled. */
    cpu.fpu_size = 512;
    if (cpu.max_leaf >= 0xD) {
        cpuid(1, 0, r);
        if (bit(r[2], 26)) {
            cpuid(0xD, 0, r);
            uint64_t supported = ((uint64_t)r[3] << 32) | r[0];
            uint64_t want = 0x7 | 0xE0;                  /* x87 SSE AVX | opmask ZMM_Hi256 Hi16_ZMM */
            cpu.xcr0 = supported & want;
            if ((cpu.xcr0 & 0xE0) != 0xE0)
                cpu.xcr0 &= ~0xE0ull;                    /* AVX-512 only as a whole */
            if (!(cpu.xcr0 & 4))
                cpu.xcr0 &= ~0xE0ull;
            cpu.xsave = true;
            cr4 |= CR4_OSXSAVE;
        }
    }
    write_cr4(cr4);
    cpu_init_pat();
    if (cpu.xsave) {
        cpu_init_xsave();
        /* The area must hold every enabled component: the end of the furthest one (sub-leaf i:
         * EAX size, EBX offset). EBX of sub-leaf 0 should say the same, but some hypervisors
         * (WHPX) report it for the boot XCR0 (576 bytes with AVX-512 on): never take less. */
        uint32_t s[4];
        uint32_t size = 576;                             /* legacy area + XSAVE header */
        for (unsigned i = 2; i < 64; i++) {
            if (!(cpu.xcr0 & (1ull << i)))
                continue;
            cpuid(0xD, i, s);
            if (s[1] + s[0] > size)
                size = s[1] + s[0];
        }
        cpuid(0xD, 0, s);
        if (s[1] > size)
            size = s[1];
        cpu.fpu_size = size;
    }
}

/* PAT: entries 0-3 keep their power-on meaning except entry 1 (PWT alone), which becomes
 * write-combining for framebuffers (VMM_WC). PCD+PWT (entry 3) stays UC for MMIO. Entries 4-7 mirror
 * 0-3. Nothing maps with PWT alone before this runs, so no stale WT lines need flushing. */
void cpu_init_pat(void)
{
    if (cpu.pat)
        wrmsr(MSR_PAT, 0x0007010600070106ull);   /* UC UC- WC WB, twice */
}

void cpu_init_xsave(void)
{
    if (cpu.xsave)
        xsetbv(0, cpu.xcr0);
}

/* One RDRAND value, retried on transient failure. All-ones and zero are refused even with CF=1:
 * some AMD CPUs return ~0 with CF set (erratum, e.g. after S3 resume). */
static bool rdrand64(uint64_t *out)
{
    for (int i = 0; i < 10; i++) {
        uint64_t v;
        uint8_t ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok));
        if (ok && v != 0 && v != ~0ull) {
            *out = v;
            return true;
        }
    }
    return false;
}

/* Boot self-check: a working RDRAND gives distinct, valid values. A stuck one is disabled, so
 * every user of cpu_random64 falls back (and the weak seed is reported) instead of trusting it. */
static void rdrand_check(void)
{
    uint64_t prev = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t v;
        if (!rdrand64(&v) || v == prev) {
            cpu.rdrand = false;
            cpu.rdrand_broken = true;
            return;
        }
        prev = v;
    }
}

uint64_t cpu_random64(void)
{
    uint64_t v;
    if (cpu.rdrand && rdrand64(&v))
        return v;
    /* Fallback: splitmix64 over a counter stepped by the golden ratio, mixed with the TSC, so
     * two calls in the same TSC tick still differ. Not cryptographic. */
    static uint64_t state;
    uint64_t z = __atomic_add_fetch(&state, 0x9E3779B97F4A7C15ull, __ATOMIC_RELAXED) + rdtsc();
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static const char *onoff(bool b) { return b ? "on" : "OFF (unsupported)"; }

void cpu_print_info(void)
{
    kprintf("CPU: %s (%s)\n", cpu.brand[0] ? cpu.brand : "unknown model", cpu.vendor);
    kprintf("Protections: WP on, NX %s, SMEP %s, SMAP %s, UMIP %s\n",
            onoff(cpu.nx), onoff(cpu.smep), onoff(cpu.smap), onoff(cpu.umip));
    /* Whether the kernel uses them: cet.c (shadow stacks). Kernel IBT needs every indirect-branch
     * target marked, which the pinned stable Rust cannot do (-Zcf-protection). */
    kprintf("CET: shadow stacks %s, IBT %s by this CPU\n",
            cpu.cet_ss ? "supported" : "not supported", cpu.cet_ibt ? "supported" : "not supported");
    if (cpu.xsave)
        kprintf("FPU: XSAVE for user threads, %u bytes per thread (x87 SSE%s%s)\n", cpu.fpu_size,
                (cpu.xcr0 & 4) ? " AVX" : "", (cpu.xcr0 & 0xE0) ? " AVX-512" : "");
    else
        kprintf("FPU: FXSAVE for user threads (x87 SSE; no XSAVE)\n");
}

/* #GP on the RDMSR/WRMSR of msr_read_safe / msr_write_safe (msr.asm): tell the function (R8 = 1)
 * and run the same instruction again on an MSR that cannot fault: RDMSR of the TSC, WRMSR of
 * IA32_FMASK with the value it holds. RIP stays (CET: a kernel IRETQ must return where the shadow
 * stack says). Kernel mode only; anything else is a real fault. */
#define MSR_TSC   0x10
#define MSR_FMASK 0xC0000084
extern const char msr_insn_read[], msr_insn_write[];

bool msr_fixup_try(struct interrupt_frame *f)
{
    if (f->vector != 13 || (f->cs & 3))
        return false;
    if (f->rip != (uint64_t)(uintptr_t)msr_insn_read && f->rip != (uint64_t)(uintptr_t)msr_insn_write)
        return false;
    if (f->rip == (uint64_t)(uintptr_t)msr_insn_read) {
        f->rcx = MSR_TSC;
    } else {
        uint64_t v = rdmsr(MSR_FMASK);    /* the same on every CPU (user_cpu_init) */
        f->rcx = MSR_FMASK;
        f->rax = (uint32_t)v;
        f->rdx = v >> 32;
    }
    f->r8 = 1;
    return true;
}
