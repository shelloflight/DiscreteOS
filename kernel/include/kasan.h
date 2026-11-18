/*
 * KASAN-style heap checking for the C kernel (test builds with build.ps1 -Kasan; kernel/lib/kasan.c).
 *
 * The compiler (clang -fsanitize=kernel-address, outline mode) calls a check before every load and
 * store in instrumented C code. The check consults a shadow for the heap's slab pages: one shadow
 * byte per 8 bytes of a slab page (0: all 8 usable, 1..7: the first n, otherwise poisoned: slab
 * header, the unused tail of a slot, a freed slot). A bad access panics with its kind
 * (slab-out-of-bounds, use-after-free), size, address and the code that made it.
 *
 * What it adds over the hardened heap: overflows into the slack of a slot or into the next
 * object (the slab classes round up), and reads of freed objects (the heap's poison only catches
 * writes, on reuse). Large allocations are already guard-paged and never reused.
 * Not covered: Rust code (not instrumented; it uses the same heap), globals, stacks.
 */
#ifndef DOS_KASAN_H
#define DOS_KASAN_H

#include <stddef.h>

#ifdef KTEST_KASAN
void kasan_init(void);                                /* after the heap: prints the status line */
void kasan_slab_new(void *page, size_t obj_size);     /* a new slab page: everything poisoned */
void kasan_alloc(void *obj, size_t size, size_t slot);/* [obj, obj+size) usable, the slot rest not */
void kasan_free(void *obj, size_t slot);              /* the whole slot: freed */
#else
static inline void kasan_init(void) {}
static inline void kasan_slab_new(void *page, size_t obj_size) { (void)page; (void)obj_size; }
static inline void kasan_alloc(void *obj, size_t size, size_t slot) { (void)obj; (void)size; (void)slot; }
static inline void kasan_free(void *obj, size_t slot) { (void)obj; (void)slot; }
#endif

#endif
