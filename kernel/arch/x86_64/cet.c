/*
 * CET supervisor shadow stacks (docs/hardening.md).
 *
 * Every thread has a shadow stack next to its kernel stack (sched.c: shstk_new), every CPU one per
 * IST stack (IA32_INTERRUPT_SSP_TABLE). CALL pushes the return address on both stacks, RET compares
 * them and raises #CP on a mismatch: a kernel stack overwrite cannot redirect a return.
 *
 * Who switches what:
 *   - context_switch (switch.asm): RSTORSSP to the next thread's restore token, SAVEPREVSSP leaves
 *     one on the previous thread's shadow stack;
 *   - an interrupt from ring 3: the CPU loads IA32_PL0_SSP (the running user thread's supervisor
 *     token, set when it is switched in) and marks the token busy; SYSCALL does not switch, so
 *     the entry does it (SETSSBSY);
 *   - the IRETQ back to ring 3 clears the busy token (SSP is on it again by then; user_enter
 *     marks it busy first, SETSSBSY); SYSRET does not, so that return clears it (CLRSSBSY);
 *   - NMI, #DF, #MC: the CPU takes the IST stack's shadow stack from the table.
 *
 * User shadow stacks (ring 3) come with them: a process whose image asks for them (ELF property
 * SHSTK, user/elf.rs) gets one per thread, made by the kernel (user/thread.rs). IA32_U_CET and
 * IA32_PL3_SSP (the user SSP while the thread is in the kernel) are switched with the thread
 * (sched.c: switch_user_state).
 *
 * Off (reported at boot) when the CPU has none, when KPTI runs entries on per-CPU stacks, and when
 * Spectre v2 needs retpolines (their thunk rewrites its own return address).
 */

#include <stdbool.h>
#include <stdint.h>
#include "arch.h"
#include "cet.h"
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "spec.h"
#include "thread.h"

bool cet_ss;
static const char *cet_off = "not supported by this CPU";

bool cet_cpu_alloc(struct percpu *pc)
{
    for (int i = 1; i <= IST_COUNT; i++) {
        uint64_t token = shstk_new(NULL, 0, 0);
        if (!token)
            return false;
        pc->ssp_table[i] = token;          /* entry n: IST n */
    }
    return true;
}

void cet_init(void)
{
    if (!cpu.cet_ss)
        return;
    if (spec.mitig & MIT_KPTI) {
        cet_off = "off: KPTI is in use";
        return;
    }
    if (spec.v2 == V2_RETPOLINE) {
        cet_off = "off: Spectre v2 needs retpolines here (their thunk rewrites its return address)";
        return;
    }
    if (!cet_cpu_alloc(&bsp_percpu))
        panic("CET: cannot allocate the boot CPU's IST shadow stacks");
    cet_ss = true;
}

uint64_t *cet_cpu_prepare(struct percpu *pc, struct thread *t, uint64_t *restore)
{
    KASSERT(cet_ss && t->ss_token && t->ssp == t->ss_token - 16);   /* never switched out yet */
    write_cr4(read_cr4() | CR4_CET);
    wrmsr(MSR_ISST, (uint64_t)(uintptr_t)pc->ssp_table);
    wrmsr(MSR_PL0_SSP, 0);                 /* no user thread yet; set when one is switched in */
    pc->ss_token = 0;
    wrmsr(MSR_U_CET, 0);                   /* ring 3: per thread (sched.c: switch_user_state) */
    wrmsr(MSR_PL3_SSP, 0);
    pc->u_cet = 0;
    *restore = t->ssp;
    uint64_t va = t->ssp + 8;              /* the first return address, above the restore token */
    uint64_t pa = vmm_translate(va & ~(uint64_t)(PAGE_SIZE - 1));
    if (pa == VMM_NOT_MAPPED)
        panic("CET: shadow stack of '%s' not mapped", t->name);
    return (uint64_t *)((uint8_t *)phys_to_virt(pa) + (va & (PAGE_SIZE - 1)));
}

void cet_cpu_enabled(struct percpu *pc)
{
    pc->mitig |= MIT_SHSTK;
}

uint64_t cet_bsp_wake_token(uint64_t ssp)
{
    struct percpu *pc = &bsp_percpu;
    uint64_t tok_va = ssp - 8;
    uint64_t pa = vmm_translate(tok_va & ~(uint64_t)(PAGE_SIZE - 1));
    if (pa == VMM_NOT_MAPPED)
        panic("CET: BSP shadow stack not mapped on S3 resume");
    uint64_t *alias = (uint64_t *)((uint8_t *)phys_to_virt(pa) + (tok_va & (PAGE_SIZE - 1)));
    *alias = ssp | 1;                      /* 64-bit restore token for RSTORSSP: (tok_va + 8) | 1 */
    wrmsr(MSR_ISST, (uint64_t)(uintptr_t)pc->ssp_table);
    wrmsr(MSR_PL0_SSP, pc->ss_token);
    wrmsr(MSR_U_CET, pc->u_cet);
    wrmsr(MSR_PL3_SSP, pc->current ? pc->current->ussp : 0);
    cet_cpu_enabled(pc);                   /* restore MIT_SHSTK after gdt_resume_cpu -> spec_cpu_init */
    return tok_va;
}

void cet_ap_reset(struct thread *idle)
{
    if (!cet_ss || !idle || !idle->ss_token)
        return;
    idle->ssp = idle->ss_token - 16;
    uint64_t pa = vmm_translate(idle->ssp & ~(uint64_t)(PAGE_SIZE - 1));
    if (pa != VMM_NOT_MAPPED) {
        uint64_t *alias = (uint64_t *)((uint8_t *)phys_to_virt(pa) + (idle->ssp & (PAGE_SIZE - 1)));
        *alias = (idle->ssp + 8) | 1;      /* 64-bit restore token for RSTORSSP */
    }
}

void cet_print(void)
{
    if (cet_ss)
        kprintf("CET: supervisor shadow stacks on (every kernel thread and IST stack, %u KiB each); "
                "user shadow stacks for programs that ask for them; "
                "IBT not enabled (the Rust compiler cannot mark branch targets yet)\n", SHSTK_SIZE / 1024);
    else
        kprintf("CET: supervisor shadow stacks %s; IBT %s\n", cet_off,
                cpu.cet_ibt ? "not enabled (the Rust compiler cannot mark branch targets yet)" : "not supported");
}
