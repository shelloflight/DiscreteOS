/*
 * KASLR: kernel address space layout randomization (docs/boot.md, "KASLR").
 *
 * The loader already moved the kernel image to a random 2 MiB-aligned base in its window and
 * applied the image's relocations (boot/common/kaslr.c). Here the kernel picks the other region
 * bases, before the PMM and VMM use them:
 *   - direct map: 1 GiB-aligned, anywhere its span (the CPU's physical address width) fits
 *   - heap region, thread-stack region: 1 GiB-aligned, 1 TiB each
 * Randomness: the loader's seed (BootInfo v5, from RDSEED/RDRAND/EFI_RNG_PROTOCOL/TSC) mixed with
 * the kernel's own (cpu_random64: RDRAND, else TSC-based). The bases live in kernel_layout, which
 * is RO_AFTER_INIT: read-only once the VMM is active.
 * Nothing prints the bases in a release kernel (the kernel log is meant to become readable from
 * user space); the panic report prints the image offset so a crash can be symbolized offline.
 */

#include <stdint.h>
#include "bootinfo.h"
#include "compiler.h"
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "printf.h"

#define GIB (1ull << 30)

struct kernel_layout kernel_layout RO_AFTER_INIT;

static uint64_t mix_state;

/* splitmix64 over the seed words and fresh CPU randomness. */
static uint64_t next_random(void)
{
    uint64_t z = (mix_state += 0x9E3779B97F4A7C15ull) ^ cpu_random64();
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/* Uniform in [0, n) (multiply-shift; the bias for n < 2^32 is below 2^-32). */
static uint64_t below(uint64_t n) { return (uint64_t)(((unsigned __int128)next_random() * n) >> 64); }

static uint64_t log2_floor(uint64_t n)
{
    uint64_t b = 0;
    while (n >>= 1)
        b++;
    return b;
}

/* A random `align`-aligned base for `size` bytes inside [lo, hi); *bits = entropy. */
static uint64_t pick(uint64_t lo, uint64_t hi, uint64_t size, uint64_t align, uint64_t *bits)
{
    KASSERT(hi > lo && hi - lo >= size);
    uint64_t slots = (hi - lo - size) / align + 1;
    *bits = log2_floor(slots);
    return lo + below(slots) * align;
}

static unsigned phys_address_bits(void)
{
    uint32_t r[4];
    cpuid(0x80000000u, 0, r);
    if (r[0] < 0x80000008u)
        return 36;
    cpuid(0x80000008u, 0, r);
    unsigned b = r[0] & 0xFF;
    return b < 32 ? 32 : b;
}

void kaslr_init(const BootInfo *bi)
{
    for (unsigned i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (unsigned j = 0; j < 8; j++)
            w |= (uint64_t)bi->seed[8 * i + j] << (8 * j);
        mix_state ^= w;
        next_random();
    }
    struct kernel_layout *l = &kernel_layout;
    l->sources = bi->kaslr_sources | (cpu.rdrand ? KASLR_SRC_RDRAND : KASLR_SRC_TSC);

    unsigned pbits = phys_address_bits();
    l->physmap_size = pbits >= 46 ? PHYSMAP_MAX : 1ull << pbits;
    l->physmap = pick(PHYSMAP_WINDOW, PHYSMAP_WINDOW_END, l->physmap_size, GIB, &l->physmap_bits);
    l->heap = pick(HEAP_WINDOW, HEAP_WINDOW_END, HEAP_SIZE, GIB, &l->heap_bits);
    l->kstack = pick(KSTACK_WINDOW, KSTACK_WINDOW_END, KSTACK_REGION, GIB, &l->kstack_bits);
    l->image_bits = log2_floor((KIMAGE_WINDOW_END - KIMAGE_WINDOW) / LARGE_PAGE_SIZE);
    mix_state = 0;
}

static void source_names(char *out, size_t n, uint32_t s)
{
    static const char *const names[] = { "RDSEED", "RDRAND", "EFI RNG", "TSC" };
    size_t k = 0;
    out[0] = '\0';
    for (unsigned i = 0; i < 4; i++)
        if (s & (1u << i))
            k += (size_t)ksnprintf(out + k, n - k, "%s%s", k ? ", " : "", names[i]);
}

void kaslr_print(void)
{
    const struct kernel_layout *l = &kernel_layout;
    char src[48];
    source_names(src, sizeof(src), l->sources);
    kprintf("KASLR: image %llu bits, direct map %llu bits, heap %llu bits, stacks %llu bits (%s)\n",
            (unsigned long long)l->image_bits, (unsigned long long)l->physmap_bits,
            (unsigned long long)l->heap_bits, (unsigned long long)l->kstack_bits, src);
    if (!(l->sources & ~KASLR_SRC_TSC))
        kprintf("warning: KASLR seeded from the TSC only (no hardware random number generator)\n");
}
