/*
 * Hardened kernel heap.
 *
 * Small objects (<= 1024 bytes): slab pages (one 4 KiB frame, in the direct map) per size class.
 *   - Free-list pointers are encoded with a random secret and the slot address (safe-linking):
 *     a corrupted or forged pointer is detected before it is followed.
 *   - Freed objects are poisoned; the poison is verified when the slot is reused (use-after-free).
 *   - A per-slab allocation bitmap catches double frees and frees of never-allocated slots.
 * Large objects (> 1024 bytes): pages in the heap region, right-aligned against an unmapped guard
 *   page, so writing past the end faults immediately. Freed large allocations are unmapped and their
 *   address range is never reused, so a use-after-free faults too.
 * All memory returned is zeroed.
 */

#include <stdint.h>
#include "cpu.h"
#include "fault.h"
#include "kasan.h"
#include "mm.h"
#include "panic.h"
#include "printf.h"
#include "spinlock.h"
#include "string.h"

#define SLAB_MAGIC     0x534C4142u     /* "SLAB" */
#define SLAB_HEADER    64u
#define POISON         0xDEu
#define POISON_CHECK   64u             /* bytes verified on reuse (after the free-list pointer) */
#define NUM_CLASSES    7
#define MAX_SMALL      1024u
#define MAX_ALLOC      (64ull << 20)   /* 64 MiB sanity limit per allocation */

static const uint16_t class_size[NUM_CLASSES] = { 16, 32, 64, 128, 256, 512, 1024 };

struct slab {
    uint32_t     magic;
    uint16_t     obj_size;
    uint16_t     capacity;
    uint16_t     free_count;
    uint16_t     reserved;
    uint64_t     free_head;      /* encoded */
    struct slab *next;           /* next slab of this class with free slots */
    uint64_t     used[4];        /* allocation bitmap (max 252 objects) */
};
_Static_assert(sizeof(struct slab) <= SLAB_HEADER, "slab header too large");

static struct slab *partial[NUM_CLASSES];
static spinlock_t   heap_lk = SPINLOCK_INIT("heap", LOCK_RANK_HEAP);
static uint64_t     secret;
static uint64_t     heap_next;                           /* heap_init: HEAP_BASE + a leading guard page */
static uint64_t     stat_slabs, stat_large_pages, stat_allocs, stat_frees;

static inline uint64_t encode(uint64_t next, const void *slot) { return next ^ secret ^ (uint64_t)(uintptr_t)slot; }

static int size_class(size_t size)
{
    for (int c = 0; c < NUM_CLASSES; c++)
        if (size <= class_size[c])
            return c;
    return -1;
}

static inline uint8_t *slab_obj(struct slab *s, unsigned i) { return (uint8_t *)s + SLAB_HEADER + (size_t)i * s->obj_size; }

static NORETURN void heap_corrupt(const char *what, const void *p)
{
    panic("heap: %s (object %p)", what, p);
}

static struct slab *slab_new(int c)
{
    uint64_t pa = pmm_alloc();
    if (!pa)
        return NULL;
    struct slab *s = phys_to_virt(pa);
    memset(s, 0, SLAB_HEADER);
    s->magic = SLAB_MAGIC;
    s->obj_size = class_size[c];
    s->capacity = (uint16_t)((PAGE_SIZE - SLAB_HEADER) / s->obj_size);
    s->free_count = s->capacity;
    kasan_slab_new(s, s->obj_size);

    memset(slab_obj(s, 0), POISON, (size_t)s->capacity * s->obj_size);
    uint64_t next = 0;
    for (int i = s->capacity - 1; i >= 0; i--) {     /* free list in address order */
        uint8_t *obj = slab_obj(s, (unsigned)i);
        *(uint64_t *)obj = encode(next, obj);
        next = (uint64_t)(uintptr_t)obj;
    }
    s->free_head = encode(next, &s->free_head);
    stat_slabs++;
    return s;
}

/* Index of `p` in slab `s`, or -1 if it is not exactly a slot start. */
static int slot_index(struct slab *s, const uint8_t *p)
{
    const uint8_t *first = slab_obj(s, 0);
    if (p < first)
        return -1;
    uint64_t off = (uint64_t)(p - first);
    if (off % s->obj_size || off / s->obj_size >= s->capacity)
        return -1;
    return (int)(off / s->obj_size);
}

static void *small_alloc(int c)
{
    struct slab *s = partial[c];
    if (!s) {
        s = slab_new(c);
        if (!s)
            return NULL;
        partial[c] = s;
    }

    uint8_t *obj = (uint8_t *)(uintptr_t)encode(s->free_head, &s->free_head);
    int i = obj ? slot_index(s, obj) : -1;
    if (i < 0)
        heap_corrupt("free list corrupted", obj);
    if (s->used[i / 64] & (1ull << (i % 64)))
        heap_corrupt("free list points at an allocated object", obj);

    for (size_t k = 8; k < s->obj_size && k < 8 + POISON_CHECK; k++)
        if (obj[k] != POISON)
            heap_corrupt("use-after-free detected (freed object was modified)", obj);

    s->free_head = encode(encode(*(uint64_t *)obj, obj), &s->free_head);
    s->used[i / 64] |= 1ull << (i % 64);
    if (--s->free_count == 0)
        partial[c] = s->next;                         /* slab is full: leave the partial list */

    memset(obj, 0, s->obj_size);
    return obj;
}

static void small_free(uint8_t *obj)
{
    struct slab *s = (struct slab *)((uint64_t)(uintptr_t)obj & ~(PAGE_SIZE - 1));
    if (s->magic != SLAB_MAGIC)
        heap_corrupt("kfree of a pointer that kmalloc never returned", obj);
    int i = slot_index(s, obj);
    if (i < 0)
        heap_corrupt("kfree of a pointer into the middle of an object", obj);
    if (!(s->used[i / 64] & (1ull << (i % 64))))
        heap_corrupt("double free", obj);

    s->used[i / 64] &= ~(1ull << (i % 64));
    kasan_free(obj, s->obj_size);
    memset(obj, POISON, s->obj_size);
    uint64_t head = encode(s->free_head, &s->free_head);
    *(uint64_t *)obj = encode(head, obj);
    s->free_head = encode((uint64_t)(uintptr_t)obj, &s->free_head);

    if (s->free_count++ == 0) {                       /* was full: back on the partial list */
        int c = size_class(s->obj_size);
        s->next = partial[c];
        partial[c] = s;
    }
}

/* First mapped page in [va, va + pages), or 0 if none. */
static uint64_t first_mapped(uint64_t va, uint64_t pages)
{
    for (uint64_t i = 0; i < pages; i++)
        if (vmm_translate(va + i * PAGE_SIZE) != VMM_NOT_MAPPED)
            return va + i * PAGE_SIZE;
    return 0;
}

/* Address space for a large allocation. Addresses are handed out in increasing order and a freed
 * range is only reused after the allocator has gone round the whole 1 TiB region (wrap-around),
 * so a use-after-free keeps faulting for as long as possible while the region never runs out.
 * After a wrap, ranges still in use (with their guard pages on both sides) are skipped. */
static uint64_t large_va(uint64_t pages)
{
    static bool wrapped;
    uint64_t need = (pages + 1) * PAGE_SIZE;                 /* + trailing guard page */
    for (unsigned tries = 0; tries < 1024; tries++) {
        if (heap_next + need > HEAP_BASE + HEAP_SIZE) {
            heap_next = HEAP_BASE + PAGE_SIZE;
            wrapped = true;
        }
        uint64_t va = heap_next;
        uint64_t busy = wrapped ? first_mapped(va - PAGE_SIZE, pages + 2) : 0;
        if (!busy) {
            heap_next += need;
            return va;
        }
        heap_next = busy + 2 * PAGE_SIZE;                    /* past the live page and a guard */
    }
    return 0;
}

static void *large_alloc(size_t size)
{
    uint64_t bytes = (size + 15) & ~15ull;
    uint64_t pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t va = large_va(pages);
    if (!va)
        return NULL;

    for (uint64_t i = 0; i < pages; i++) {
        uint64_t pa = pmm_alloc_zeroed();
        if (!pa || !vmm_try_map_page(va + i * PAGE_SIZE, pa, VMM_W)) {
            if (pa)
                pmm_free(pa);
            vmm_unmap_free(va, i);
            return NULL;
        }
    }
    stat_large_pages += pages;                        /* the trailing guard page stays unmapped */

    /* Right-align so that the first byte past the object is the guard page. */
    return (void *)(uintptr_t)(va + pages * PAGE_SIZE - bytes);
}

static void large_free(void *ptr)
{
    uint64_t va = (uint64_t)(uintptr_t)ptr & ~(PAGE_SIZE - 1);
    if (vmm_translate(va) == VMM_NOT_MAPPED)
        heap_corrupt("double free or invalid pointer (large allocation)", ptr);
    if (vmm_translate(va - PAGE_SIZE) != VMM_NOT_MAPPED)
        heap_corrupt("kfree of a pointer into the middle of a large allocation", ptr);

    uint64_t pages = 0;
    while (vmm_translate(va + pages * PAGE_SIZE) != VMM_NOT_MAPPED)   /* up to the trailing guard page */
        pages++;
    vmm_unmap_free(va, pages);                        /* one TLB shootdown for the whole object */
    stat_large_pages -= pages;
}

void heap_init(void)
{
    secret = cpu_random64() | 1;
    heap_next = HEAP_BASE + PAGE_SIZE;   /* the base is chosen at boot (KASLR) */
}

void *kmalloc(size_t size)
{
    if (size == 0 || size > MAX_ALLOC)
        return NULL;
    if (fault_should_fail(FAULT_KMALLOC))
        return NULL;
    int c = size_class(size);
    uint64_t f = spin_lock_irqsave(&heap_lk);
    void *p = c >= 0 ? small_alloc(c) : large_alloc(size);
    if (p)
        stat_allocs++;
    if (p && c >= 0)
        kasan_alloc(p, size, class_size[c]);
    spin_unlock_irqrestore(&heap_lk, f);
    return p;
}

uint64_t heap_live_allocs(void)
{
    uint64_t f = spin_lock_irqsave(&heap_lk);
    uint64_t n = stat_allocs - stat_frees;
    spin_unlock_irqrestore(&heap_lk, f);
    return n;
}

void kfree(void *ptr)
{
    if (!ptr)
        return;
    uint64_t a = (uint64_t)(uintptr_t)ptr;
    uint64_t f = spin_lock_irqsave(&heap_lk);
    stat_frees++;
    if (a >= HEAP_BASE && a < HEAP_BASE + HEAP_SIZE)
        large_free(ptr);
    else if (a >= PHYSMAP_BASE && a < PHYSMAP_BASE + PHYSMAP_SIZE)
        small_free(ptr);
    else
        heap_corrupt("kfree of a non-heap pointer", ptr);
    spin_unlock_irqrestore(&heap_lk, f);
}

void heap_print(void)
{
    kprintf("Heap: %u size classes (16-%u B, hardened slabs), large allocations guard-paged; "
            "%llu live allocations, %llu slab pages, %llu large pages\n",
            NUM_CLASSES, MAX_SMALL, (unsigned long long)(stat_allocs - stat_frees),
            (unsigned long long)stat_slabs, (unsigned long long)stat_large_pages);
}

#ifdef KTEST
#include "thread.h"

void vm_test_near_end(void)
{
    uint64_t f = spin_lock_irqsave(&heap_lk);
    heap_next = HEAP_BASE + HEAP_SIZE - 40 * PAGE_SIZE;
    spin_unlock_irqrestore(&heap_lk, f);
    kstack_test_near_end();
}
#endif
