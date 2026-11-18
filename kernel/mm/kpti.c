/*
 * KPTI: kernel page-table isolation, on CPUs affected by Meltdown (spec.c decides).
 *
 * Every user address space gets a second PML4, loaded while ring 3 runs. Its lower half is the
 * same as the kernel-side PML4's (the same PDPTs: one set of user page tables), kept equal by
 * uspace_map/uspace_free_tables. Its upper half comes from one "shadow" kernel half built here,
 * which maps only what the CPU needs to enter the kernel:
 *   - the entry code (.entry.text: isr.asm, syscall.asm), read + execute;
 *   - the IDT, read-only;
 *   - each CPU's per-CPU page (GDT, TSS, the GS-relative fields the entry code reads, and the
 *     entry stack at its top), read/write;
 *   - each CPU's IST stacks (NMI, #DF, #MC), read/write.
 * No other kernel memory (image, heap, direct map, thread stacks) is mapped while user code runs,
 * so a Meltdown-style load from ring 3 has nothing to read. The shadow mappings are not global
 * and PGE is off under KPTI (vmm_activate), so no kernel TLB entry survives the switch to ring 3.
 *
 * Shadow PML4 entries are copied into each new user PML4, so they must all exist before the first
 * address space is created: every CPU is mapped at boot (smp_init), before init starts.
 */

#include <stdint.h>
#include "arch.h"
#include "compiler.h"
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "spec.h"
#include "string.h"

#define PTE_P    (1ull << 0)
#define PTE_W    (1ull << 1)
#define PTE_PS   (1ull << 7)
#define PTE_NX   (1ull << 63)
#define PTE_ADDR 0x000FFFFFFFFFF000ull

extern char __entry_text_start[], __entry_text_end[];
extern uint8_t idt[];                    /* idt.c: one page */

static uint64_t shadow_l4;               /* physical; only entries 256-511 are used */
static uint64_t shadow_pages, shadow_tables;
static bool     sealed;                  /* a user PML4 exists: no new shadow PML4 entries */

bool kpti_on(void) { return (spec.mitig & MIT_KPTI) != 0; }

static inline uint64_t *tbl(uint64_t pa) { return (uint64_t *)phys_to_virt(pa); }
static inline unsigned ix(uint64_t va, int level) { return (unsigned)(va >> (12 + 9 * (level - 1))) & 511; }

static void shadow_map_page(uint64_t va, uint32_t flags)
{
    uint64_t pa = vmm_translate(va);
    if (pa == VMM_NOT_MAPPED)
        panic("KPTI: %#llx is not mapped in the kernel", (unsigned long long)va);
    uint64_t *t = tbl(shadow_l4);
    for (int l = 4; l > 1; l--) {
        uint64_t *e = &t[ix(va, l)];
        if (!(*e & PTE_P)) {
            if (l == 4 && sealed)
                panic("KPTI: a new kernel PML4 entry is needed after user page tables exist (%#llx)",
                      (unsigned long long)va);
            uint64_t n = pmm_alloc_zeroed();
            if (!n)
                panic("KPTI: out of memory for the shadow page tables");
            *e = n | PTE_P | PTE_W;
            shadow_tables++;
        }
        KASSERT(!(*e & PTE_PS));
        t = tbl(*e & PTE_ADDR);
    }
    uint64_t *e = &t[ix(va, 1)];
    uint64_t leaf = (pa & PTE_ADDR) | PTE_P;
    if (flags & VMM_W)
        leaf |= PTE_W;
    if (!(flags & VMM_X) && cpu.nx)
        leaf |= PTE_NX;
    if (*e & PTE_P) {
        KASSERT(*e == leaf);              /* mapped twice (pages shared by two ranges): same page */
        return;
    }
    *e = leaf;
    shadow_pages++;
}

static void shadow_map(uint64_t start, uint64_t end, uint32_t flags)
{
    for (uint64_t va = start & ~(PAGE_SIZE - 1); va < end; va += PAGE_SIZE)
        shadow_map_page(va, flags);
}

void kpti_map_cpu(const void *percpu_page, const uint64_t ist_top[IST_COUNT], unsigned ist_size)
{
    if (!kpti_on())
        return;
    uint64_t p = (uint64_t)(uintptr_t)percpu_page;
    KASSERT(!(p & (PAGE_SIZE - 1)));
    shadow_map(p, p + PAGE_SIZE, VMM_W);
    for (int i = 0; i < IST_COUNT; i++)
        shadow_map(ist_top[i] - ist_size, ist_top[i], VMM_W);
}

void kpti_init(void)
{
    if (!kpti_on())
        return;
    shadow_l4 = pmm_alloc_zeroed();
    if (!shadow_l4)
        panic("KPTI: out of memory for the shadow PML4");
    shadow_map((uint64_t)(uintptr_t)__entry_text_start, (uint64_t)(uintptr_t)__entry_text_end, VMM_X);
    shadow_map((uint64_t)(uintptr_t)idt, (uint64_t)(uintptr_t)idt + PAGE_SIZE, 0);
    kpti_map_cpu(&bsp_percpu, bsp_percpu.tss.ist, KSTACK_SIZE);   /* IST stacks: KSTACK_SIZE (gdt.c) */
}

uint64_t kpti_user_pml4_new(uint64_t kernel_pml4)
{
    KASSERT(kpti_on() && shadow_l4);
    uint64_t pa = pmm_alloc_zeroed();
    if (!pa)
        return 0;
    __atomic_store_n(&sealed, true, __ATOMIC_RELAXED);
    memcpy(tbl(pa), tbl(kernel_pml4), 256 * sizeof(uint64_t));
    memcpy(tbl(pa) + 256, tbl(shadow_l4) + 256, 256 * sizeof(uint64_t));
    return pa;
}

void kpti_user_pml4_sync(uint64_t kernel_pml4, uint64_t user_pml4, unsigned from, unsigned to)
{
    KASSERT(to < 256);
    for (unsigned i = from; i <= to; i++)
        tbl(user_pml4)[i] = tbl(kernel_pml4)[i];
}

uint64_t kpti_shadow_pages(void) { return shadow_pages; }

void kpti_print(void)
{
    if (!kpti_on())
        return;
    kprintf("KPTI: user page tables map %llu kernel pages (entry code, IDT, per-CPU pages, IST stacks), "
            "%llu shadow page tables; global pages off\n",
            (unsigned long long)shadow_pages, (unsigned long long)shadow_tables);
}

/* ---- self-check (ktest) ---------------------------------------------------------------------- */

static bool allowed(uint64_t va)
{
    uint64_t es = (uint64_t)(uintptr_t)__entry_text_start, ee = (uint64_t)(uintptr_t)__entry_text_end;
    if (va >= es && va < ee)
        return true;
    if (va == (uint64_t)(uintptr_t)idt)
        return true;
    for (uint32_t c = 0; c < cpu_slots; c++) {
        const struct percpu *pc = cpus[c];
        if (!pc)
            continue;
        if (va == (uint64_t)(uintptr_t)pc)
            return true;
        for (int i = 0; i < IST_COUNT; i++)
            if (va >= pc->tss.ist[i] - KSTACK_SIZE && va < pc->tss.ist[i])
                return true;
    }
    return false;
}

static uint64_t shadow_lookup(uint64_t va)
{
    const uint64_t *t = tbl(shadow_l4);
    for (int l = 4; l >= 1; l--) {
        uint64_t e = t[ix(va, l)];
        if (!(e & PTE_P))
            return 0;
        if (l == 1)
            return e;
        t = tbl(e & PTE_ADDR);
    }
    return 0;
}

/* Walk the whole shadow kernel half: every mapped page must be one of the entry pages, with the
 * expected rights; and a sample of what must stay hidden must be absent. */
bool kpti_selfcheck(char *why, unsigned size)
{
    if (!shadow_l4) {
        ksnprintf(why, size, "KPTI is off");
        return false;
    }
    uint64_t seen = 0;
    const uint64_t *l4 = tbl(shadow_l4);
    for (unsigned a = 256; a < 512; a++) {
        if (!(l4[a] & PTE_P))
            continue;
        const uint64_t *l3 = tbl(l4[a] & PTE_ADDR);
        for (unsigned b = 0; b < 512; b++) {
            if (!(l3[b] & PTE_P))
                continue;
            if (l3[b] & PTE_PS) {
                ksnprintf(why, size, "a 1 GiB page in the shadow tables");
                return false;
            }
            const uint64_t *l2 = tbl(l3[b] & PTE_ADDR);
            for (unsigned c = 0; c < 512; c++) {
                if (!(l2[c] & PTE_P))
                    continue;
                if (l2[c] & PTE_PS) {
                    ksnprintf(why, size, "a 2 MiB page in the shadow tables");
                    return false;
                }
                const uint64_t *l1 = tbl(l2[c] & PTE_ADDR);
                for (unsigned d = 0; d < 512; d++) {
                    if (!(l1[d] & PTE_P))
                        continue;
                    uint64_t va = 0xFFFF000000000000ull | ((uint64_t)a << 39) | ((uint64_t)b << 30) |
                                  ((uint64_t)c << 21) | ((uint64_t)d << 12);
                    if (!allowed(va)) {
                        ksnprintf(why, size, "kernel page %#llx is mapped for user mode", (unsigned long long)va);
                        return false;
                    }
                    if ((l1[d] & PTE_ADDR) != (vmm_translate(va) & PTE_ADDR)) {
                        ksnprintf(why, size, "page %#llx maps a different frame", (unsigned long long)va);
                        return false;
                    }
                    if ((l1[d] & (1ull << 2)) || (l1[d] & (1ull << 8))) {
                        ksnprintf(why, size, "page %#llx is user-accessible or global", (unsigned long long)va);
                        return false;
                    }
                    bool code = va >= (uint64_t)(uintptr_t)__entry_text_start && va < (uint64_t)(uintptr_t)__entry_text_end;
                    if (code == !!(l1[d] & PTE_NX) && cpu.nx) {
                        ksnprintf(why, size, "page %#llx: wrong execute permission", (unsigned long long)va);
                        return false;
                    }
                    if (code && (l1[d] & PTE_W)) {
                        ksnprintf(why, size, "entry code page %#llx is writable", (unsigned long long)va);
                        return false;
                    }
                    seen++;
                }
            }
        }
    }
    if (seen != shadow_pages) {
        ksnprintf(why, size, "%llu pages found, %llu mapped", (unsigned long long)seen, (unsigned long long)shadow_pages);
        return false;
    }
    /* What Meltdown would be after: none of it may be reachable. */
    extern char __text_start[], __data_start[];
    static const char *const names[] = { "kernel code", "kernel data", "kernel heap", "direct map (kernel page tables)",
                                         "this thread's stack" };
    uint64_t probes[] = {
        (uint64_t)(uintptr_t)__text_start, (uint64_t)(uintptr_t)__data_start, HEAP_BASE,
        (uint64_t)(uintptr_t)phys_to_virt(vmm_kernel_pml4()), (uint64_t)(uintptr_t)&seen,
    };
    for (unsigned i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        if (allowed(probes[i] & ~(PAGE_SIZE - 1)))
            continue;                    /* (the boot CPU's stack is not one of these) */
        if (shadow_lookup(probes[i])) {
            ksnprintf(why, size, "%s (%#llx) is mapped for user mode", names[i], (unsigned long long)probes[i]);
            return false;
        }
    }
    ksnprintf(why, size, "%llu kernel pages mapped for user mode, all entry pages", (unsigned long long)seen);
    return true;
}

/* The tables an interrupt from ring 3 found loaded (percpu.entry_cr3): user tables (their upper
 * half is the shadow) or kernel tables (an exit path that forgot to switch). -1: unknown/freed. */
int kpti_classify_pml4(uint64_t pa)
{
    if (!shadow_l4 || !pa)
        return -1;
    const uint64_t *t = tbl(pa & PTE_ADDR);
    if (!memcmp(t + 256, tbl(shadow_l4) + 256, 256 * sizeof(uint64_t)))
        return 1;
    if (!memcmp(t + 256, tbl(vmm_kernel_pml4()) + 256, 256 * sizeof(uint64_t)))
        return 0;
    return -1;
}
