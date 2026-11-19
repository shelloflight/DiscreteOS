/*
 * Memory management: physical frames (PMM), kernel page tables (VMM) and the kernel heap.
 *
 * Kernel virtual layout (upper half, shared by every address space: PML4 entries 256-511 are
 * allocated at boot and copied into each user address space, so they never need syncing).
 * KASLR (kernel/mm/kaslr.c, docs/boot.md): every region sits at a random base inside its window,
 * chosen once per boot; the bases are read-only after early boot.
 *   window 0xFFFF800000000000 - 0xFFFFD00000000000  direct map of physical memory (RAM + on-demand
 *          MMIO/firmware), RW + NX; 1 GiB-aligned base, sized by the CPU's physical address width
 *   window 0xFFFFD00000000000 - 0xFFFFE80000000000  kernel heap region for large allocations (1 TiB,
 *          guard page between each)
 *   window 0xFFFFE80000000000 - 0xFFFFFF8000000000  kernel thread stacks (1 TiB; guard page below
 *          each, addresses never reused)
 *   window 0xFFFFFF8000000000 - 0xFFFFFFFFC0000000  kernel image, W^X per section: relocated by the
 *          loader to a random 2 MiB-aligned base (+ the 1 MiB physical offset)
 */
#ifndef DOS_MM_H
#define DOS_MM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "bootinfo.h"
#include "spinlock.h"

#define PAGE_SIZE        4096ull
#define LARGE_PAGE_SIZE  0x200000ull

/* KASLR windows (see above). Keep the image window in sync with boot/common/kaslr.h. */
#define PHYSMAP_WINDOW      0xFFFF800000000000ull
#define PHYSMAP_WINDOW_END  0xFFFFD00000000000ull
#define HEAP_WINDOW         0xFFFFD00000000000ull
#define HEAP_WINDOW_END     0xFFFFE80000000000ull
#define KSTACK_WINDOW       0xFFFFE80000000000ull
#define KSTACK_WINDOW_END   0xFFFFFF8000000000ull
#define KIMAGE_WINDOW       0xFFFFFF8000000000ull
#define KIMAGE_WINDOW_END   0xFFFFFFFFC0000000ull   /* + the loaders' 1 GiB boot window = 2^64 */
#define KERNEL_LINK_BASE    0xFFFFFFFF80000000ull   /* linker.ld: the image's base if not moved */
#define KERNEL_LOAD_PHYS    0x100000ull             /* physical load address (fixed, linker.ld) */

/* The randomized bases (kaslr.c). RO_AFTER_INIT: chosen before the VMM is built, then read-only. */
struct kernel_layout {
    uint64_t physmap;       /* direct map: physical address pa is at physmap + pa */
    uint64_t physmap_size;  /* physical addresses below this are reachable (<= PHYSMAP_MAX) */
    uint64_t heap;          /* large-allocation region, HEAP_SIZE bytes */
    uint64_t kstack;        /* thread-stack region, KSTACK_REGION bytes */
    uint64_t image_bits, physmap_bits, heap_bits, kstack_bits;   /* entropy of each choice */
    uint32_t sources;       /* KASLR_SRC_* that fed the kernel's choice (and the loader's) */
};
extern struct kernel_layout kernel_layout;

#define PHYSMAP_BASE     (kernel_layout.physmap)
#define PHYSMAP_MAX      (1ull << 46)            /* at most 64 TiB of physical address space */
#define PHYSMAP_SIZE     (kernel_layout.physmap_size)   /* this boot: the CPU's physical address width */
#define HEAP_BASE        (kernel_layout.heap)
#define HEAP_SIZE        (1ull << 40)            /* 1 TiB of heap address space */
#define KSTACK_BASE      (kernel_layout.kstack)  /* kernel thread stacks: one slot per thread, never reused */
#define KSTACK_REGION    (1ull << 40)
#define KSTACK_SLOT      (32 * 1024ull)          /* guard page + 16 KiB stack + unmapped gap */

#define LOW_MEMORY_END   0x100000ull             /* below 1 MiB: BIOS, bootloader, AP trampoline */

/* Where the image runs: computed RIP-relative, so it is right wherever the loader put it. The
 * physical load address is fixed, so the image's virtual base minus it maps physical 0. */
extern char __kernel_start[];
static inline uint64_t kernel_vbase(void) { return (uint64_t)(uintptr_t)__kernel_start - KERNEL_LOAD_PHYS; }
/* How far the loader moved the image from its link address (0: not moved). */
static inline uint64_t kaslr_offset(void) { return kernel_vbase() - KERNEL_LINK_BASE; }

/* Physical address of a kernel-image symbol. */
#define KERNEL_PHYS(va)  ((uint64_t)(uintptr_t)(va) - kernel_vbase())

/* KASLR (kernel/mm/kaslr.c): pick the region bases (before pmm_init/vmm_build); report. */
void kaslr_init(const BootInfo *bi);
void kaslr_print(void);

/* 0 until the VMM is active (boot identity map), PHYSMAP_BASE afterwards. */
extern uint64_t phys_offset;

/* Temporary access to physical memory. Before vmm_activate() only the first 1 GiB is reachable. */
static inline void *phys_to_virt(uint64_t pa) { return (void *)(uintptr_t)(pa + phys_offset); }

/* ---- PMM (kernel/mm/pmm.c) ---------------------------------------------------------- */
void     pmm_init(const BootInfo *bi);
uint64_t pmm_alloc(void);              /* one 4 KiB frame, or 0 when out of memory */
uint64_t pmm_alloc_zeroed(void);
uint64_t pmm_alloc_contig_zeroed(uint64_t frames);   /* contiguous, zeroed; 0 if none */
void     pmm_free(uint64_t pa);        /* panics on double free or reserved frames */
uint64_t pmm_free_frames(void);
uint64_t pmm_total_frames(void);
void     pmm_print(void);
/* Does [pa, pa+len) overlap RAM (usable or ACPI-reclaimable, or the first MiB)? Device memory
 * handed to user space (BARs) must not. */
bool     pmm_range_is_ram(uint64_t pa, uint64_t len);

/* ---- VMM (kernel/mm/vmm.c) ---------------------------------------------------------- */
#define VMM_W   (1u << 0)   /* writable */
#define VMM_X   (1u << 1)   /* executable (never together with VMM_W: W^X) */
#define VMM_UC  (1u << 2)   /* uncached (MMIO) */
#define VMM_WC  (1u << 3)   /* write-combining (framebuffers); uncached without PAT */

#define VMM_NOT_MAPPED (~0ull)

void     vmm_build(const BootInfo *bi);   /* create kernel page tables (not yet active) */
void     vmm_activate(void);              /* switch CR3; drops the bootloader's identity map */
bool     vmm_active(void);
void     vmm_map_page(uint64_t va, uint64_t pa, uint32_t flags);     /* panics if out of memory */
bool     vmm_try_map_page(uint64_t va, uint64_t pa, uint32_t flags); /* false if out of memory */
void     vmm_unmap_page(uint64_t va);
void     vmm_unmap_range(uint64_t va, uint64_t pages);    /* unmapped pages in the range are skipped */
void     vmm_unmap_free(uint64_t va, uint64_t pages);     /* unmap + pmm_free the frames (after the shootdown) */
uint64_t vmm_kernel_pml4(void);           /* physical address of the kernel PML4 */
uint64_t vmm_translate(uint64_t va);      /* physical address, or VMM_NOT_MAPPED */
uint64_t vmm_translate_nolock(uint64_t va);   /* fault/panic reports only (other CPUs stopped) */

/* Map a physical range (MMIO, firmware tables) into the direct map and return its permanent
 * virtual address. Pages that are already mapped are left as they are. */
void    *vmm_map_phys(uint64_t pa, uint64_t size, uint32_t flags);
/* Like vmm_map_phys, but NULL (nothing changed) if a page was already mapped with other write or
 * cache attributes (a firmware table page mapped read-only, for example). */
void    *vmm_map_phys_exact(uint64_t pa, uint64_t size, uint32_t flags);

/* Guard pages: never mapped; faults on them are reported by name. */
void        vmm_add_guard(const void *page, const char *name);
const char *vmm_guard_name(uint64_t va);
void        vmm_print(void);

/* ---- User address spaces (vmm.c) ----------------------------------------------------
 * The lower half below USER_TOP, one per process. Leaf entries point at frames owned by VMOs
 * (the Rust object layer): unmapping never frees frames, and the caller frees them only after
 * uspace_unmap() has returned (the range is shot down on every CPU first). Page tables are
 * counted (`tables`) so the object layer can charge them to the process's memory quota; they
 * are freed when the address space is destroyed. */
#define USER_BASE  0x200000ull              /* the first 2 MiB stay unmapped (NULL + small offsets) */
#define USER_TOP   0x00007FFFFFFF0000ull    /* below the canonical hole, with a gap (SYSRET safety) */

struct uspace {
    spinlock_t lock;
    uint64_t   pml4;        /* physical address (CR3) */
    uint64_t   tables;      /* lower-half page tables in use (the PML4 itself not counted) */
    uint64_t   cpus;        /* CPUs that have it loaded: the only TLB shootdown targets (atomic) */
    uint64_t   upml4;       /* KPTI: the PML4 loaded while ring 3 runs (0 without KPTI; kpti.c) */
    uint64_t   id;          /* unique, never reused (IBPB: "another process ran here") */
};

struct uspace *uspace_create(void);          /* NULL when out of memory */
void     uspace_destroy(struct uspace *as);  /* no CPU may still use it; the leaves must be unmapped */
/* Free every lower-half page table (after the last thread left; nothing mapped); returns how many. */
uint64_t uspace_free_tables(struct uspace *as);
/* Map `pages` frames at va (VMM_W / VMM_X, never both). False when out of memory (nothing mapped). */
bool     uspace_map(struct uspace *as, uint64_t va, const uint64_t *frames, uint64_t pages, uint32_t flags,
                    uint64_t *new_tables);   /* page tables this call allocated (also on failure) */
void     uspace_unmap(struct uspace *as, uint64_t va, uint64_t pages);
uint64_t uspace_translate(struct uspace *as, uint64_t va);   /* physical address, or VMM_NOT_MAPPED */
/* Page tables a mapping of [va, va + pages) could need at most (quota reservation). */
uint64_t uspace_tables_needed(uint64_t va, uint64_t pages);
uint64_t uspace_kernel_tables(void);         /* PDPTs pre-allocated for the shared kernel half */

/* ---- Heap (kernel/mm/heap.c) -------------------------------------------------------- */
void  heap_init(void);
void *kmalloc(size_t size);   /* zeroed, 16-byte aligned; NULL if size is 0 or too large */
void  kfree(void *ptr);       /* panics on invalid pointers, double free, corruption */
void  heap_print(void);
uint64_t heap_live_allocs(void);   /* allocations not yet freed (leak checks) */

#ifdef KTEST
/* Move the heap's and the kernel-stack region's next-address pointers close to the end of their
 * regions, so the following allocations exercise the wrap-around (kmain.c / ktest only). */
void  vm_test_near_end(void);
#endif

#endif
