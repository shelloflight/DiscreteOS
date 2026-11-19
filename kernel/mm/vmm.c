/*
 * Kernel virtual memory: builds the kernel's own page tables and replaces the bootloader's RWX
 * identity map.
 *
 *  - Kernel image: 4 KiB pages, W^X per section (text R-X, rodata R, data/bss RW+NX), global.
 *  - Direct map: RAM (usable + ACPI) at PHYSMAP_BASE, RW+NX, 2 MiB pages where possible. The kernel
 *    image is excluded, so its code has no writable alias.
 *  - Nothing is mapped in the lower half: NULL and any user-range access fault.
 *  - Guard pages (stacks) are never mapped.
 * W^X is enforced on every mapping (KASSERT), and existing mappings are never silently replaced.
 * Unmapping flushes the page from every CPU's TLB (shootdown) before returning, and frames are only
 * freed after that, so no CPU can keep using a stale translation to reused memory.
 */

#include <stdint.h>
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "printf.h"
#include "smp.h"
#include "spec.h"
#include "spinlock.h"
#include "string.h"

extern char __kernel_start[], __kernel_end[];
extern char __text_start[], __text_end[], __rodata_start[], __rodata_end[], __data_start[];
extern char __ro_after_init_start[], __ro_after_init_end[];

#define PTE_P    (1ull << 0)
#define PTE_W    (1ull << 1)
#define PTE_U    (1ull << 2)
#define PTE_PWT  (1ull << 3)
#define PTE_PCD  (1ull << 4)
#define PTE_D    (1ull << 6)
#define PTE_PS   (1ull << 7)
#define PTE_G    (1ull << 8)
#define PTE_NX   (1ull << 63)
#define PTE_ADDR 0x000FFFFFFFFFF000ull

#define CR4_PGE  (1ull << 7)
#define MAX_GUARDS 16

uint64_t phys_offset;              /* 0 = boot identity map; PHYSMAP_BASE once active */

/* Serialises page-table changes, and walks: page tables of the heap and stack regions are freed
 * when they become empty. */
static spinlock_t vmm_lk = SPINLOCK_INIT("vmm", LOCK_RANK_VMM);
static uint64_t pml4_pa;
static bool     active;
static uint64_t nx_bit;

static struct { uint64_t va; const char *name; } guards[MAX_GUARDS];
static unsigned guard_count;

static uint64_t stat_tables, stat_large, stat_small, kernel_pdpts;

static inline uint64_t *table(uint64_t pa) { return (uint64_t *)phys_to_virt(pa); }
static inline unsigned idx(uint64_t va, int level) { return (unsigned)(va >> (12 + 9 * (level - 1))) & 511; }

bool vmm_active(void) { return active; }
uint64_t vmm_kernel_pml4(void) { return pml4_pa; }

static uint64_t leaf_bits(uint64_t va, uint32_t flags)
{
    uint64_t e = PTE_P;
    if (flags & VMM_W)
        e |= PTE_W;
    if (!(flags & VMM_X))
        e |= nx_bit;
    if (flags & VMM_UC)
        e |= PTE_PCD | PTE_PWT;
    else if (flags & VMM_WC)
        e |= cpu.pat ? PTE_PWT : PTE_PCD | PTE_PWT;   /* PAT entry 1 = WC (cpu_init_pat) */
    if (flags & VMM_SHSTK)
        e |= PTE_D;                /* not writable + dirty = a shadow-stack page (CET) */
    if (va >= PHYSMAP_BASE)
        e |= PTE_G;                /* kernel half: survives address-space switches */
    return e;
}

/* Entry for `va` at `level` (1 = 4 KiB PTE, 2 = 2 MiB PDE) in the tree at `root`. NULL if not
 * present (and !create), if a large page above blocks the walk, or if a page table could not be
 * allocated (*oom set; tables created so far stay: they are empty and reused by the next walk).
 * New tables get `dir` (restrictions live in the leaf entries) and are counted in *count. */
static uint64_t *walk_in(uint64_t root, uint64_t va, int level, bool create, bool *oom, uint64_t *count, uint64_t dir)
{
    uint64_t *t = table(root);
    for (int l = 4; l > level; l--) {
        uint64_t *e = &t[idx(va, l)];
        if (!(*e & PTE_P)) {
            if (!create)
                return NULL;
            uint64_t pa = pmm_alloc_zeroed();
            if (!pa) {
                *oom = true;
                return NULL;
            }
            (*count)++;
            *e = pa | dir;
        } else if (*e & PTE_PS) {
            return NULL;
        }
        t = table(*e & PTE_ADDR);
    }
    return &t[idx(va, level)];
}

static uint64_t *walk_oom(uint64_t va, int level, bool create, bool *oom)
{
    return walk_in(pml4_pa, va, level, create, oom, &stat_tables, PTE_P | PTE_W);
}

static void check_wx(uint64_t va, uint32_t flags)
{
    if ((flags & VMM_W) && (flags & VMM_X))
        panic("VMM: W^X violation: writable + executable mapping requested at %#llx", (unsigned long long)va);
    if ((flags & VMM_SHSTK) && (flags & (VMM_W | VMM_X)))
        panic("VMM: a shadow stack may be neither writable nor executable (%#llx)", (unsigned long long)va);
}

static uint64_t *walk(uint64_t va, int level, bool create)
{
    bool oom = false;
    uint64_t *e = walk_oom(va, level, create, &oom);
    if (oom)
        panic("VMM: out of memory for page tables");
    return e;
}

/* False only when out of memory for a page table. */
static bool map_page_nolock(uint64_t va, uint64_t pa, uint32_t flags)
{
    check_wx(va, flags);
    KASSERT(((va | pa) & (PAGE_SIZE - 1)) == 0);
    bool oom = false;
    uint64_t *e = walk_oom(va, 1, true, &oom);
    if (oom)
        return false;
    if (!e)
        panic("VMM: %#llx lies inside a large page", (unsigned long long)va);
    if (*e & PTE_P)
        panic("VMM: %#llx is already mapped", (unsigned long long)va);
    *e = pa | leaf_bits(va, flags);
    stat_small++;
    return true;
}

bool vmm_try_map_page(uint64_t va, uint64_t pa, uint32_t flags)
{
    uint64_t f = spin_lock_irqsave(&vmm_lk);
    bool ok = map_page_nolock(va, pa, flags);
    spin_unlock_irqrestore(&vmm_lk, f);
    return ok;
}

void vmm_map_page(uint64_t va, uint64_t pa, uint32_t flags)
{
    if (!vmm_try_map_page(va, pa, flags))
        panic("VMM: out of memory for page tables");
}

/* 2 MiB mapping; returns false if anything already occupies that slot. */
static bool map_large(uint64_t va, uint64_t pa, uint32_t flags)
{
    check_wx(va, flags);
    uint64_t *e = walk(va, 2, true);
    if (!e || (*e & PTE_P))
        return false;
    *e = pa | leaf_bits(va, flags) | PTE_PS;
    stat_large++;
    return true;
}

/* Unmapping. Order matters for SMP safety:
 *   1. clear the PTEs (non-present; the frame address is kept to find it again in step 3), and if a
 *      page table of the heap or kernel-stack region ends up empty, detach it from its PDE (and its
 *      page directory too, if that is left empty);
 *   2. flush every CPU's TLB for the range (this also drops cached paging-structure entries for it);
 *   3. only now free the frames and the detached page tables.
 * Without step 1's detaching, page tables of the never-reused heap/stack addresses would pile up
 * for ever (found by the soak test). Work is done in pieces of up to UNMAP_CHUNKS page tables. */
#define UNMAP_CHUNKS 8

static bool reclaimable(uint64_t va)
{
    return (va >= HEAP_BASE && va < HEAP_BASE + HEAP_SIZE) || (va >= KSTACK_BASE && va < KSTACK_BASE + KSTACK_REGION);
}

static void unmap_piece(uint64_t va, uint64_t end, bool free_frames)
{
    struct { uint64_t *pt; uint64_t pt_pa, first, last; bool detached; } ch[UNMAP_CHUNKS];
    unsigned n = 0;
    uint64_t cleared = 0;

    for (uint64_t c = va; c < end && n < UNMAP_CHUNKS; c = (c & ~(LARGE_PAGE_SIZE - 1)) + LARGE_PAGE_SIZE) {
        uint64_t *pde = walk(c, 2, false);
        if (!pde || !(*pde & PTE_P) || (*pde & PTE_PS))
            continue;
        uint64_t cend = (c & ~(LARGE_PAGE_SIZE - 1)) + LARGE_PAGE_SIZE;
        if (cend > end)
            cend = end;
        uint64_t *pt = table(*pde & PTE_ADDR);
        for (uint64_t a = c; a < cend; a += PAGE_SIZE) {
            uint64_t *e = &pt[idx(a, 1)];
            if (*e & PTE_P) {
                *e &= PTE_ADDR;             /* not present; frame address kept for step 3 */
                cleared++;
            }
        }
        bool empty = reclaimable(c);
        for (unsigned i = 0; empty && i < 512; i++)
            if (pt[i] & PTE_P)
                empty = false;
        ch[n].pt = pt;
        ch[n].pt_pa = *pde & PTE_ADDR;
        ch[n].first = c;
        ch[n].last = cend;
        ch[n].detached = empty;
        if (empty)
            *pde = 0;                       /* no walk can reach this table any more */
        n++;
    }
    /* A page directory (1 GiB) left without page tables is detached the same way. */
    uint64_t pd_free[UNMAP_CHUNKS];
    unsigned npd = 0;
    bool detached_any = false;
    for (unsigned k = 0; k < n; k++) {
        if (!ch[k].detached)
            continue;
        detached_any = true;
        uint64_t *pdpte = walk(ch[k].first, 3, false);
        if (!pdpte || !(*pdpte & PTE_P) || (*pdpte & PTE_PS))
            continue;
        const uint64_t *pd = table(*pdpte & PTE_ADDR);
        bool empty = true;
        for (unsigned i = 0; empty && i < 512; i++)
            if (pd[i])
                empty = false;
        if (empty) {
            pd_free[npd++] = *pdpte & PTE_ADDR;
            *pdpte = 0;
        }
    }
    if (cleared || detached_any) {
        tlb_flush_local(va, (end - va) / PAGE_SIZE);
        tlb_shootdown(va, (end - va) / PAGE_SIZE);   /* other CPUs answer even while spinning on vmm_lk */
    }
    for (unsigned k = 0; k < n; k++) {
        for (uint64_t a = ch[k].first; a < ch[k].last; a += PAGE_SIZE) {
            uint64_t *e = &ch[k].pt[idx(a, 1)];
            if (*e && !(*e & PTE_P)) {
                if (free_frames)
                    pmm_free(*e & PTE_ADDR);
                *e = 0;
            }
        }
        if (ch[k].detached) {
            pmm_free(ch[k].pt_pa);
            stat_tables--;
        }
    }
    for (unsigned k = 0; k < npd; k++) {
        pmm_free(pd_free[k]);
        stat_tables--;
    }
}

static void unmap_range(uint64_t va, uint64_t pages, bool free_frames)
{
    uint64_t end = va + pages * PAGE_SIZE;
    uint64_t f = spin_lock_irqsave(&vmm_lk);
    while (va < end) {
        uint64_t piece = (va & ~(LARGE_PAGE_SIZE - 1)) + UNMAP_CHUNKS * LARGE_PAGE_SIZE;
        if (piece > end)
            piece = end;
        unmap_piece(va, piece, free_frames);
        va = piece;
    }
    spin_unlock_irqrestore(&vmm_lk, f);
}

void vmm_unmap_page(uint64_t va) { unmap_range(va, 1, false); }
void vmm_unmap_range(uint64_t va, uint64_t pages) { unmap_range(va, pages, false); }
void vmm_unmap_free(uint64_t va, uint64_t pages) { unmap_range(va, pages, true); }

/* Lock-free walk: only safe where page tables cannot be freed underneath (vmm_lk held, or a panic
 * with every other CPU stopped). */
uint64_t vmm_translate_nolock(uint64_t va)
{
    uint64_t *t = table(pml4_pa);
    for (int l = 4; l >= 1; l--) {
        uint64_t e = t[idx(va, l)];
        if (!(e & PTE_P))
            return VMM_NOT_MAPPED;
        if (l == 1)
            return (e & PTE_ADDR) | (va & (PAGE_SIZE - 1));
        if (l <= 3 && (e & PTE_PS)) {
            uint64_t span = 1ull << (12 + 9 * (l - 1));
            return ((e & PTE_ADDR) & ~(span - 1)) | (va & (span - 1));
        }
        t = table(e & PTE_ADDR);
    }
    return VMM_NOT_MAPPED;
}

uint64_t vmm_translate(uint64_t va)
{
    uint64_t f = spin_lock_irqsave(&vmm_lk);
    uint64_t pa = vmm_translate_nolock(va);
    spin_unlock_irqrestore(&vmm_lk, f);
    return pa;
}

void *vmm_map_phys(uint64_t pa, uint64_t size, uint32_t flags)
{
    KASSERT(!(flags & VMM_X));
    if (size == 0 || pa + size < pa || pa + size > PHYSMAP_SIZE)
        panic("VMM: bad physical range %#llx+%#llx", (unsigned long long)pa, (unsigned long long)size);
    uint64_t start = pa & ~(PAGE_SIZE - 1);
    uint64_t end = (pa + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint64_t f = spin_lock_irqsave(&vmm_lk);
    for (uint64_t p = start; p < end; p += PAGE_SIZE)
        if (vmm_translate_nolock(PHYSMAP_BASE + p) == VMM_NOT_MAPPED)
            if (!map_page_nolock(PHYSMAP_BASE + p, p, flags))
                panic("VMM: out of memory for page tables");
    spin_unlock_irqrestore(&vmm_lk, f);
    return (void *)(uintptr_t)(PHYSMAP_BASE + pa);
}

/* The leaf entry mapping va (any level), or 0. Caller holds vmm_lk. */
static uint64_t leaf_nolock(uint64_t va)
{
    uint64_t *t = table(pml4_pa);
    for (int l = 4; l >= 1; l--) {
        uint64_t e = t[idx(va, l)];
        if (!(e & PTE_P))
            return 0;
        if (l == 1 || (l <= 3 && (e & PTE_PS)))
            return e;
        t = table(e & PTE_ADDR);
    }
    return 0;
}

void *vmm_map_phys_exact(uint64_t pa, uint64_t size, uint32_t flags)
{
    if (size == 0 || pa + size < pa || pa + size > PHYSMAP_SIZE)
        return NULL;
    void *p = vmm_map_phys(pa, size, flags);
    uint64_t start = pa & ~(PAGE_SIZE - 1);
    uint64_t end = (pa + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    bool ok = true;
    uint64_t f = spin_lock_irqsave(&vmm_lk);
    for (uint64_t a = start; a < end && ok; a += PAGE_SIZE) {
        uint64_t e = leaf_nolock(PHYSMAP_BASE + a);
        ok = e != 0 && !!(e & PTE_W) == !!(flags & VMM_W) && !!(e & PTE_PCD) == !!(flags & VMM_UC);
    }
    spin_unlock_irqrestore(&vmm_lk, f);
    return ok ? p : NULL;
}

/* ---- guard pages ------------------------------------------------------------------------ */

static bool is_guard(uint64_t va)
{
    for (unsigned i = 0; i < guard_count; i++)
        if (guards[i].va == va)
            return true;
    return false;
}

void vmm_add_guard(const void *page, const char *name)
{
    uint64_t va = (uint64_t)(uintptr_t)page;
    KASSERT((va & (PAGE_SIZE - 1)) == 0);
    if (guard_count == MAX_GUARDS)
        panic("VMM: too many guard pages");
    guards[guard_count].va = va;
    guards[guard_count].name = name;
    guard_count++;
    if (active)
        vmm_unmap_page(va);
}

const char *vmm_guard_name(uint64_t va)
{
    for (unsigned i = 0; i < guard_count; i++)
        if (va >= guards[i].va && va < guards[i].va + PAGE_SIZE)
            return guards[i].name;
    return NULL;
}

/* ---- building the kernel address space ------------------------------------------------------ */

static void map_ram(uint64_t start, uint64_t end)
{
    uint64_t p = start;
    while (p < end) {
        if (!(p & (LARGE_PAGE_SIZE - 1)) && end - p >= LARGE_PAGE_SIZE &&
            map_large(PHYSMAP_BASE + p, p, VMM_W)) {
            p += LARGE_PAGE_SIZE;
            continue;
        }
        if (vmm_translate_nolock(PHYSMAP_BASE + p) == VMM_NOT_MAPPED)
            vmm_map_page(PHYSMAP_BASE + p, p, VMM_W);
        p += PAGE_SIZE;
    }
}

static void map_kernel(const char *start, const char *end, uint32_t flags)
{
    for (uint64_t va = (uint64_t)(uintptr_t)start; va < (uint64_t)(uintptr_t)end; va += PAGE_SIZE)
        if (!is_guard(va))
            vmm_map_page(va, KERNEL_PHYS(va), flags);
}

void vmm_build(const BootInfo *bi)
{
    KASSERT(!active);
    nx_bit = cpu.nx ? PTE_NX : 0;
    pml4_pa = pmm_alloc_zeroed();
    if (!pml4_pa)
        panic("VMM: out of memory for the kernel PML4");

    /* Direct map: usable + ACPI RAM, minus the kernel image (no writable alias of kernel code). */
    uint64_t k_start = KERNEL_PHYS(__kernel_start), k_end = KERNEL_PHYS(__kernel_end);
    const MemoryMapEntry *mm = (const MemoryMapEntry *)(uintptr_t)bi->mmap_addr;
    for (uint32_t i = 0; i < bi->mmap_count; i++) {
        uint32_t t = mm[i].type;
        if (t != MMAP_USABLE && t != MMAP_ACPI_RECLAIMABLE && t != MMAP_ACPI_NVS)
            continue;
        uint64_t s = (mm[i].base + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        uint64_t e = (mm[i].base + mm[i].length) & ~(PAGE_SIZE - 1);
        if (e > PHYSMAP_SIZE)
            e = PHYSMAP_SIZE;
        if (e <= s)
            continue;
        if (s < k_start)
            map_ram(s, e < k_start ? e : k_start);
        if (e > k_end)
            map_ram(s > k_end ? s : k_end, e);
    }

    /* Kernel image, W^X by section. */
    map_kernel(__text_start, __text_end, VMM_X);
    map_kernel(__rodata_start, __rodata_end, 0);
    map_kernel(__ro_after_init_start, __ro_after_init_end, 0);   /* written before this, never after */
    map_kernel(__ro_after_init_end, __kernel_end, VMM_W);

    /* Every kernel-half PML4 entry gets its PDPT now, so the kernel half of a user address space
     * is a plain copy of entries 256-511 and never has to be synced (1 MiB of PDPTs at most).
     * Kernel PML4 entries are never removed (unmap_piece only detaches PDs and PTs). */
    uint64_t *top = table(pml4_pa);
    for (unsigned i = 256; i < 512; i++) {
        if (top[i] & PTE_P)
            continue;
        uint64_t pa = pmm_alloc_zeroed();
        if (!pa)
            panic("VMM: out of memory for the kernel half");
        top[i] = pa | PTE_P | PTE_W;
        stat_tables++;
        kernel_pdpts++;
    }
}

/* ---- user address spaces --------------------------------------------------------------------- */

uint64_t uspace_kernel_tables(void) { return kernel_pdpts; }

struct uspace *uspace_create(void)
{
    struct uspace *as = kmalloc(sizeof(*as));
    if (!as)
        return NULL;
    uint64_t pa = pmm_alloc_zeroed();
    if (!pa) {
        kfree(as);
        return NULL;
    }
    as->lock = (spinlock_t)SPINLOCK_INIT("uspace", LOCK_RANK_USPACE);
    as->pml4 = pa;
    as->tables = 0;
    as->cpus = 0;
    as->upml4 = 0;
    static uint64_t next_id;
    as->id = __atomic_add_fetch(&next_id, 1, __ATOMIC_RELAXED);
    memcpy(table(pa) + 256, table(pml4_pa) + 256, 256 * sizeof(uint64_t));   /* shared kernel half */
    if (kpti_on()) {
        as->upml4 = kpti_user_pml4_new(pa);
        if (!as->upml4) {
            pmm_free(pa);
            kfree(as);
            return NULL;
        }
    }
    return as;
}

uint64_t uspace_free_tables(struct uspace *as)
{
    KASSERT(!__atomic_load_n(&as->cpus, __ATOMIC_SEQ_CST));   /* nobody runs in it any more */
    uint64_t f = spin_lock_irqsave(&as->lock);
    uint64_t *l4 = table(as->pml4);
    for (unsigned i = 0; i < 256; i++) {
        if (!(l4[i] & PTE_P))
            continue;
        uint64_t *l3 = table(l4[i] & PTE_ADDR);
        for (unsigned j = 0; j < 512; j++) {
            if (!(l3[j] & PTE_P))
                continue;
            uint64_t *l2 = table(l3[j] & PTE_ADDR);
            for (unsigned k = 0; k < 512; k++)
                if (l2[k] & PTE_P)
                    pmm_free(l2[k] & PTE_ADDR);
            pmm_free(l3[j] & PTE_ADDR);
        }
        pmm_free(l4[i] & PTE_ADDR);
        l4[i] = 0;
        if (as->upml4)
            table(as->upml4)[i] = 0;
    }
    uint64_t n = as->tables;
    as->tables = 0;
    spin_unlock_irqrestore(&as->lock, f);
    return n;
}

void uspace_destroy(struct uspace *as)
{
    uspace_free_tables(as);
    if (as->upml4)
        pmm_free(as->upml4);
    pmm_free(as->pml4);
    kfree(as);
}

static bool user_range_ok(uint64_t va, uint64_t pages)
{
    return !(va & (PAGE_SIZE - 1)) && va >= USER_BASE && pages && pages <= (USER_TOP - va) / PAGE_SIZE;
}

/* Clear [va, va + pages) (lock held). Whole page tables that are absent are skipped. */
static uint64_t clear_user(struct uspace *as, uint64_t va, uint64_t pages)
{
    uint64_t end = va + pages * PAGE_SIZE, cleared = 0;
    bool oom = false;
    for (uint64_t a = va; a < end; ) {
        uint64_t *pde = walk_in(as->pml4, a, 2, false, &oom, &as->tables, 0);
        uint64_t next = (a & ~(LARGE_PAGE_SIZE - 1)) + LARGE_PAGE_SIZE;
        if (next > end)
            next = end;
        if (pde && (*pde & PTE_P)) {
            uint64_t *pt = table(*pde & PTE_ADDR);
            for (; a < next; a += PAGE_SIZE)
                if (pt[idx(a, 1)] & PTE_P) {
                    pt[idx(a, 1)] = 0;
                    cleared++;
                }
        }
        a = next;
    }
    return cleared;
}

static void shoot(struct uspace *as, uint64_t va, uint64_t pages)
{
    tlb_flush_local(va, pages);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);   /* PTEs cleared before reading who has it loaded */
    tlb_shootdown_cpus(va, pages, __atomic_load_n(&as->cpus, __ATOMIC_SEQ_CST));
}

bool uspace_map(struct uspace *as, uint64_t va, const uint64_t *frames, uint64_t pages, uint32_t flags,
                uint64_t *new_tables)
{
    check_wx(va, flags);
    KASSERT(user_range_ok(va, pages));
    uint64_t leaf = PTE_P | PTE_U;
    if (flags & VMM_W)
        leaf |= PTE_W;
    if (!(flags & VMM_X))
        leaf |= nx_bit;
    if (flags & VMM_UC)
        leaf |= PTE_PCD | PTE_PWT;           /* device memory (MMIO BARs of user-space drivers) */
    uint64_t f = spin_lock_irqsave(&as->lock);
    uint64_t before = as->tables;
    for (uint64_t i = 0; i < pages; i++) {
        bool oom = false;
        uint64_t a = va + i * PAGE_SIZE;
        uint64_t *e = walk_in(as->pml4, a, 1, true, &oom, &as->tables, PTE_P | PTE_W | PTE_U);
        if (as->upml4 && !(table(as->upml4)[idx(a, 4)] & PTE_P))
            kpti_user_pml4_sync(as->pml4, as->upml4, idx(a, 4), idx(a, 4));   /* a new top-level table */
        if (!e) {
            KASSERT(oom);                   /* user trees never contain large pages */
            if (i && clear_user(as, va, i))
                shoot(as, va, i);           /* another thread may already have touched them */
            *new_tables = as->tables - before;   /* empty tables stay (and stay counted) */
            spin_unlock_irqrestore(&as->lock, f);
            return false;
        }
        if (*e & PTE_P)
            panic("VMM: user page %#llx is already mapped", (unsigned long long)a);
        KASSERT(!(frames[i] & ~PTE_ADDR) && frames[i]);
        *e = frames[i] | leaf;
    }
    *new_tables = as->tables - before;
    spin_unlock_irqrestore(&as->lock, f);
    return true;
}

void uspace_unmap(struct uspace *as, uint64_t va, uint64_t pages)
{
    KASSERT(user_range_ok(va, pages));
    uint64_t f = spin_lock_irqsave(&as->lock);
    if (clear_user(as, va, pages))
        shoot(as, va, pages);
    spin_unlock_irqrestore(&as->lock, f);
}

uint64_t uspace_translate(struct uspace *as, uint64_t va)
{
    if (va >= USER_TOP)
        return VMM_NOT_MAPPED;
    uint64_t f = spin_lock_irqsave(&as->lock);
    bool oom = false;
    uint64_t *e = walk_in(as->pml4, va & ~(PAGE_SIZE - 1), 1, false, &oom, &as->tables, 0);
    uint64_t pa = (e && (*e & PTE_P)) ? (*e & PTE_ADDR) | (va & (PAGE_SIZE - 1)) : VMM_NOT_MAPPED;
    spin_unlock_irqrestore(&as->lock, f);
    return pa;
}

uint64_t uspace_tables_needed(uint64_t va, uint64_t pages)
{
    uint64_t last = va + pages * PAGE_SIZE - 1;
    return ((last >> 21) - (va >> 21) + 1) + ((last >> 30) - (va >> 30) + 1) + ((last >> 39) - (va >> 39) + 1);
}

void vmm_activate(void)
{
    KASSERT(pml4_pa && !active);
    /* Global pages: kernel TLB entries survive CR3 switches. Not under KPTI: they would survive
     * the switch to the user page tables too, and keep the kernel reachable from ring 3. */
    if (kpti_on())
        write_cr4(read_cr4() & ~CR4_PGE);
    else
        write_cr4(read_cr4() | CR4_PGE);
    write_cr3(pml4_pa);
    phys_offset = PHYSMAP_BASE;
    active = true;
}

void vmm_print(void)
{
    kprintf("VMM: kernel W^X (text RX, rodata + ro-after-init R, data RW+NX), %llu x 2 MiB + %llu x 4 KiB pages, "
            "%llu page tables, %u guard pages, NULL page unmapped\n",
            (unsigned long long)stat_large, (unsigned long long)stat_small,
            (unsigned long long)stat_tables, guard_count);
}
