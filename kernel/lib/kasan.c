/*
 * KASAN-style heap shadow (see kasan.h). Built into every image but empty unless KTEST_KASAN;
 * this file itself is never instrumented (build.ps1).
 *
 * Shadow layout: a table indexed by physical frame number holds, for each slab page, the frame of
 * its shadow (0 = not a slab page: never checked). A shadow frame uses its first 512 bytes: one
 * byte per 8-byte granule of the slab page; the slab's object size follows (for reports).
 */
#ifdef KTEST_KASAN

#include <stdbool.h>
#include <stdint.h>
#include "kasan.h"
#include "ksyms.h"
#include "mm.h"
#include "panic.h"
#include "printf.h"

#define SHADOW_FREED    0xFBu     /* a freed slot */
#define SHADOW_REDZONE  0xFAu     /* slab header, unused tail of a slot */
#define MAX_FRAMES      (1u << 20)          /* physical memory covered: 4 GiB */

static uint32_t *shadow_of;                 /* pfn -> shadow frame pfn (a large heap allocation) */
static bool      ready;

void kasan_init(void)
{
    shadow_of = kmalloc(MAX_FRAMES * sizeof(uint32_t));   /* zeroed; outside the image (layout unchanged) */
    if (!shadow_of)
        panic("KASAN: no memory for the shadow table");
    ready = true;
    kprintf("KASAN: heap shadow on (slab objects; every C load and store is checked)\n");
}

static uint8_t *shadow_page(uint64_t va)
{
    if (!shadow_of || va < PHYSMAP_BASE || va >= PHYSMAP_BASE + ((uint64_t)MAX_FRAMES << 12))
        return NULL;
    uint32_t s = shadow_of[(va - PHYSMAP_BASE) >> 12];
    return s ? (uint8_t *)phys_to_virt((uint64_t)s << 12) : NULL;
}

static void fill(uint8_t *sh, uint64_t off, uint64_t len, uint8_t v)
{
    for (uint64_t g = off >> 3; g < (off + len + 7) >> 3; g++)
        sh[g] = v;
}

#define SLAB_HEADER 64u               /* heap.c */
#define SH_OBJ_SIZE 512u              /* offset of the object size in a shadow frame */

void kasan_slab_new(void *page, size_t obj_size)
{
    uint64_t va = (uint64_t)(uintptr_t)page;
    uint64_t pa = va - PHYSMAP_BASE;
    if (!shadow_of || pa >> 12 >= MAX_FRAMES)
        return;
    uint64_t sp = pmm_alloc();
    if (!sp)
        return;                               /* out of memory: this page simply is not checked */
    uint8_t *sh = phys_to_virt(sp);
    fill(sh, 0, PAGE_SIZE, SHADOW_FREED);
    fill(sh, 0, SLAB_HEADER, SHADOW_REDZONE);
    *(uint16_t *)(sh + SH_OBJ_SIZE) = (uint16_t)obj_size;
    shadow_of[pa >> 12] = (uint32_t)(sp >> 12);
}

void kasan_alloc(void *obj, size_t size, size_t slot)
{
    uint64_t va = (uint64_t)(uintptr_t)obj;
    uint8_t *sh = shadow_page(va);
    if (!sh)
        return;
    uint64_t off = va & (PAGE_SIZE - 1);      /* slots are 16-byte aligned: granules never straddle */
    fill(sh, off, slot, SHADOW_REDZONE);
    fill(sh, off, size & ~7ull, 0);
    if (size & 7)
        sh[(off + size) >> 3] = (uint8_t)(size & 7);
}

void kasan_free(void *obj, size_t slot)
{
    uint64_t va = (uint64_t)(uintptr_t)obj;
    uint8_t *sh = shadow_page(va);
    if (sh)
        fill(sh, va & (PAGE_SIZE - 1), slot, SHADOW_FREED);
}

/* Where the bad byte is relative to its allocation (for the report). */
static void describe(uint8_t *sh, uint64_t va, uint8_t bad)
{
    uint64_t off = va & (PAGE_SIZE - 1);
    uint64_t obj = *(uint16_t *)(sh + SH_OBJ_SIZE);
    if (off < SLAB_HEADER || !obj) {
        kprintf("KASAN: the address is in a slab header\n");
        return;
    }
    uint64_t start = SLAB_HEADER + (off - SLAB_HEADER) / obj * obj;
    uint64_t base = va - (off - start);
    if (bad == SHADOW_FREED) {
        kprintf("KASAN: %llu bytes into a freed %llu-byte slot at %#llx\n", (unsigned long long)(off - start),
                (unsigned long long)obj, (unsigned long long)base);
        return;
    }
    uint64_t usable = 0;
    for (uint64_t g = start >> 3; g < (start + obj) >> 3; g++) {
        uint8_t v = sh[g];
        if (v == 0)
            usable += 8;
        else {
            if (v < 8)
                usable += v;
            break;
        }
    }
    kprintf("KASAN: %llu bytes past the end of a %llu-byte allocation at %#llx (slot of %llu bytes)\n",
            (unsigned long long)(off - start - usable), (unsigned long long)usable, (unsigned long long)base,
            (unsigned long long)obj);
}

static NORETURN void report(uint64_t va, uint64_t size, bool write, uint8_t bad, uint64_t ip)
{
    uint64_t symoff = 0;
    const char *sym = ksym_lookup(ip, &symoff);
    const char *kind = bad == SHADOW_FREED ? "use-after-free" : "slab-out-of-bounds";
    kprintf("KASAN: %s %s of size %llu at %#llx by %s+%#llx\n", kind, write ? "write" : "read",
            (unsigned long long)size, (unsigned long long)va, sym ? sym : "?", (unsigned long long)symoff);
    describe(shadow_page(va), va, bad);
    panic("KASAN: %s %s of size %llu at %#llx", kind, write ? "write" : "read", (unsigned long long)size,
          (unsigned long long)va);
}

static inline void check(uint64_t va, uint64_t size, bool write, uint64_t ip)
{
    if (!ready || size == 0)
        return;
    uint8_t *sh = shadow_page(va);
    if (!sh)
        return;
    uint64_t last = va + size - 1;
    if ((last & ~(PAGE_SIZE - 1)) != (va & ~(PAGE_SIZE - 1))) {
        check(va, PAGE_SIZE - (va & (PAGE_SIZE - 1)), write, ip);   /* split at the page edge */
        check(last & ~(PAGE_SIZE - 1), (last & (PAGE_SIZE - 1)) + 1, write, ip);
        return;
    }
    for (uint64_t a = va; a <= last; a = (a | 7) + 1) {
        uint8_t v = sh[(a & (PAGE_SIZE - 1)) >> 3];
        if (v == 0)
            continue;
        uint64_t hi = last < (a | 7) ? last : (a | 7);   /* last byte touched in this granule */
        if (v < 8 && (hi & 7) < v)
            continue;
        report(a, size, write, v, ip);
    }
}

#define IP ((uint64_t)(uintptr_t)__builtin_return_address(0))
#define DEFINE_CHECKS(n)                                                                    \
    void __asan_load##n##_noabort(uint64_t a);                                              \
    void __asan_store##n##_noabort(uint64_t a);                                             \
    void __asan_load##n##_noabort(uint64_t a) { check(a, n, false, IP); }                  \
    void __asan_store##n##_noabort(uint64_t a) { check(a, n, true, IP); }                  \
    void __asan_load##n(uint64_t a);                                                        \
    void __asan_store##n(uint64_t a);                                                       \
    void __asan_load##n(uint64_t a) { check(a, n, false, IP); }                            \
    void __asan_store##n(uint64_t a) { check(a, n, true, IP); }
DEFINE_CHECKS(1)
DEFINE_CHECKS(2)
DEFINE_CHECKS(4)
DEFINE_CHECKS(8)
DEFINE_CHECKS(16)

void __asan_loadN_noabort(uint64_t a, uint64_t n);
void __asan_storeN_noabort(uint64_t a, uint64_t n);
void __asan_loadN(uint64_t a, uint64_t n);
void __asan_storeN(uint64_t a, uint64_t n);
void __asan_loadN_noabort(uint64_t a, uint64_t n) { check(a, n, false, IP); }
void __asan_storeN_noabort(uint64_t a, uint64_t n) { check(a, n, true, IP); }
void __asan_loadN(uint64_t a, uint64_t n) { check(a, n, false, IP); }
void __asan_storeN(uint64_t a, uint64_t n) { check(a, n, true, IP); }

/* Instrumented code calls these instead of the mem* intrinsics. */
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *memmove(void *d, const void *s, size_t n);
void *__asan_memcpy(void *d, const void *s, size_t n);
void *__asan_memset(void *d, int c, size_t n);
void *__asan_memmove(void *d, const void *s, size_t n);
void *__asan_memcpy(void *d, const void *s, size_t n)
{
    check((uint64_t)(uintptr_t)s, n, false, IP);
    check((uint64_t)(uintptr_t)d, n, true, IP);
    return memcpy(d, s, n);
}
void *__asan_memset(void *d, int c, size_t n)
{
    check((uint64_t)(uintptr_t)d, n, true, IP);
    return memset(d, c, n);
}
void *__asan_memmove(void *d, const void *s, size_t n)
{
    check((uint64_t)(uintptr_t)s, n, false, IP);
    check((uint64_t)(uintptr_t)d, n, true, IP);
    return memmove(d, s, n);
}

void __asan_handle_no_return(void);
void __asan_handle_no_return(void) {}

#endif /* KTEST_KASAN */
