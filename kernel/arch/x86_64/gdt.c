/*
 * Kernel GDT + TSS, one pair per CPU (in its per-CPU block).
 * Layout is fixed for SYSCALL/SYSRET: kernel code, kernel data, user data, user code (see arch.h).
 * The TSS provides IST stacks for faults that may happen on a broken stack, and has no I/O
 * permission bitmap, so user mode can never access I/O ports directly.
 */

#include <stdint.h>
#include "arch.h"
#include "compiler.h"
#include "cpu.h"
#include "mm.h"
#include "percpu.h"
#include "spec.h"
#include "user.h"

struct PACKED dtr {
    uint16_t limit;
    uint64_t base;
};

#define IST_STACK_SIZE 16384
_Static_assert(IST_STACK_SIZE == KSTACK_SIZE, "KPTI maps IST stacks as KSTACK_SIZE (kpti.c)");

/* The boot CPU's IST stacks are part of the kernel image, each directly above an unmapped guard
 * page. APs get theirs from the kernel-stack region (smp.c). */
struct guarded_stack {
    uint8_t guard[4096];
    uint8_t stack[IST_STACK_SIZE];
} __attribute__((aligned(4096)));

static struct guarded_stack ist_stacks[IST_COUNT];
static const char *const ist_names[IST_COUNT] = { "double-fault stack", "NMI stack", "machine-check stack" };

void gdt_init_cpu(struct percpu *pc, const uint64_t ist_top[IST_COUNT])
{
    uint64_t *gdt = pc->gdt;
    struct tss *tss = &pc->tss;

    gdt[0] = 0;                              /* null */
    gdt[1] = 0x00AF9A000000FFFFull;          /* 0x08 kernel code: 64-bit, DPL0 */
    gdt[2] = 0x00CF92000000FFFFull;          /* 0x10 kernel data: DPL0 */
    gdt[3] = 0x00CFF2000000FFFFull;          /* 0x18 user data:   DPL3 */
    gdt[4] = 0x00AFFA000000FFFFull;          /* 0x20 user code:   64-bit, DPL3 */

    for (int i = 0; i < IST_COUNT; i++)
        tss->ist[i] = ist_top[i];
    tss->iomap_base = sizeof(*tss);          /* no I/O bitmap: all ports denied to ring 3 */
    /* KPTI: entries from ring 3 land on the entry stack at the top of the per-CPU page (mapped in
     * the user page tables); otherwise on the thread's kernel stack (set on every switch). */
    pc->entry_top = (uint64_t)(uintptr_t)pc + PAGE_SIZE;
    if (spec.mitig & MIT_KPTI)
        tss->rsp[0] = pc->entry_top;

    uint64_t base = (uint64_t)(uintptr_t)tss;
    uint64_t limit = sizeof(*tss) - 1;
    gdt[5] = (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (0x89ull << 40) |   /* present, 64-bit TSS */
             (((limit >> 16) & 0xF) << 48) | (((base >> 24) & 0xFF) << 56);
    gdt[6] = base >> 32;

    struct dtr gdtr = { GDT_ENTRIES * 8 - 1, (uint64_t)(uintptr_t)gdt };

    __asm__ volatile(
        "lgdt %0\n\t"
        "pushq %1\n\t"                       /* reload CS with a far return */
        "leaq 1f(%%rip), %%rax\n\t"
        "pushq %%rax\n\t"
        "lretq\n"
        "1:\n\t"
        "movw %2, %%ax\n\t"
        "movw %%ax, %%ds\n\t"
        "movw %%ax, %%es\n\t"
        "movw %%ax, %%ss\n\t"
        "xorw %%ax, %%ax\n\t"
        "movw %%ax, %%fs\n\t"
        "movw %%ax, %%gs\n\t"
        "movw %3, %%ax\n\t"
        "ltr %%ax"
        :
        : "m"(gdtr), "i"(GDT_KCODE), "i"(GDT_KDATA), "i"(GDT_TSS)
        : "rax", "memory");

    /* Loading GS above may clear its base: re-install this CPU's per-CPU block. */
    percpu_install(pc);
    user_cpu_init();
}

void gdt_resume_cpu(struct percpu *pc)
{
    uint64_t fs_base = rdmsr(MSR_FS_BASE);
    uint64_t kgs_base = rdmsr(MSR_KERNEL_GS_BASE);
    /* Clear the 64-bit TSS busy bit (type 0xB -> 0x9) before reloading TR. */
    pc->gdt[5] &= ~(1ull << 41);
    struct dtr gdtr = { GDT_ENTRIES * 8 - 1, (uint64_t)(uintptr_t)pc->gdt };
    __asm__ volatile(
        "lgdt %0\n\t"
        "pushq %1\n\t"
        "leaq 1f(%%rip), %%rax\n\t"
        "pushq %%rax\n\t"
        "lretq\n"
        "1:\n\t"
        "movw %2, %%ax\n\t"
        "movw %%ax, %%ds\n\t"
        "movw %%ax, %%es\n\t"
        "movw %%ax, %%ss\n\t"
        "xorw %%ax, %%ax\n\t"
        "movw %%ax, %%fs\n\t"
        "movw %%ax, %%gs\n\t"
        "movw %3, %%ax\n\t"
        "ltr %%ax"
        :
        : "m"(gdtr), "i"(GDT_KCODE), "i"(GDT_KDATA), "i"(GDT_TSS)
        : "rax", "memory");
    percpu_install(pc);
    wrmsr(MSR_FS_BASE, fs_base);
    wrmsr(MSR_KERNEL_GS_BASE, kgs_base);
    user_cpu_init();
}

void gdt_init(void)
{
    uint64_t top[IST_COUNT];
    for (int i = 0; i < IST_COUNT; i++) {
        top[i] = (uint64_t)(uintptr_t)(ist_stacks[i].stack + IST_STACK_SIZE);
        vmm_add_guard(ist_stacks[i].guard, ist_names[i]);
    }
    gdt_init_cpu(&bsp_percpu, top);
}
