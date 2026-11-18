/* KASLR in the loaders: see kaslr.h. Freestanding C, no firmware calls. */

#include "kaslr.h"
#include "dcrypto.h"

#define GIB       (1ull << 30)
#define PT_P      1ull
#define PT_W      2ull
#define PT_PS     0x80ull

static inline uint64_t rdtsc64(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)hi << 32 | lo;
}

static void cpuid2(uint32_t leaf, uint32_t sub, uint32_t r[4])
{
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}

/* One value from RDSEED (seed = 1) or RDRAND, retried; 0 and ~0 are refused even with CF set
 * (a known AMD erratum returns ~0). */
static int hw_random(int seed, uint64_t *out)
{
    for (int i = 0; i < 32; i++) {
        uint64_t v;
        uint8_t ok;
        if (seed)
            __asm__ volatile("rdseed %0; setc %1" : "=r"(v), "=qm"(ok));
        else
            __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok));
        if (ok && v != 0 && v != ~0ull) {
            *out = v;
            return 1;
        }
        __asm__ volatile("pause");
    }
    return 0;
}

uint32_t kaslr_entropy(const void *extra, size_t extra_len, uint32_t extra_source, uint8_t out[64])
{
    struct sha512 s;
    sha512_init(&s);
    uint32_t sources = KASLR_SRC_TSC;
    uint32_t r[4];
    cpuid2(0, 0, r);
    uint32_t max = r[0];
    cpuid2(1, 0, r);
    int has_rdrand = (r[2] >> 30) & 1, has_rdseed = 0;
    if (max >= 7) {
        cpuid2(7, 0, r);
        has_rdseed = (r[1] >> 18) & 1;
    }
    /* A stuck generator (the same value twice) is not credited. */
    for (int kind = 1; kind >= 0; kind--) {
        if (kind ? !has_rdseed : !has_rdrand)
            continue;
        uint64_t prev = 0, v;
        int good = 0;
        for (int i = 0; i < 8; i++) {
            if (!hw_random(kind, &v))
                break;
            sha512_update(&s, &v, sizeof(v));
            good += v != prev;
            prev = v;
        }
        if (good == 8)
            sources |= kind ? KASLR_SRC_RDSEED : KASLR_SRC_RDRAND;
    }
    if (extra && extra_len) {
        sha512_update(&s, extra, extra_len);
        sources |= extra_source;
    }
    /* TSC jitter: timing of the hash itself, 64 samples. Weak on its own, but never absent. */
    for (int i = 0; i < 64; i++) {
        uint64_t t = rdtsc64();
        sha512_update(&s, &t, sizeof(t));
    }
    sha512_final(&s, out);
    return sources;
}

uint64_t kaslr_pick_base(const uint8_t b[8])
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = v << 8 | b[i];
    uint64_t k = (uint64_t)(((unsigned __int128)v * KASLR_SLOTS) >> 64);
    return KASLR_WINDOW + k * KASLR_ALIGN;
}

const char *kaslr_check_header(const struct kernel_header *h, uint64_t file_len)
{
    if (h->magic != KHDR_MAGIC || h->version != KHDR_VERSION || h->size != sizeof(*h))
        return "not a relocatable D-KRNL image (bad image header)";
    if (h->phys_base < (1ull << 20) || h->phys_base % 4096 || h->virt_base != KASLR_LINK_BASE + h->phys_base)
        return "kernel load address invalid";
    if (h->file_size < sizeof(*h) || h->file_size > file_len || h->mem_size < h->file_size ||
        h->mem_size > (256ull << 20) || h->phys_base + h->mem_size > GIB)
        return "kernel image sizes invalid";
    if (h->entry < h->virt_base + sizeof(*h) || h->entry >= h->virt_base + h->file_size)
        return "kernel entry point outside the image";
    if (h->relr_offset % 8 || h->relr_size % 8 || h->relr_offset < sizeof(*h) ||
        (uint64_t)h->relr_offset + h->relr_size > h->file_size)
        return "kernel relocation table outside the image";
    return 0;
}

const char *kaslr_relocate(uint8_t *image, const struct kernel_header *h, uint64_t delta)
{
    const uint64_t *relr = (const uint64_t *)(image + h->relr_offset);
    uint64_t n = h->relr_size / 8, where = 0;
    uint64_t lo = h->virt_base, hi = h->virt_base + h->file_size - 8;     /* a word fits from lo..hi */
    uint64_t t_lo = h->virt_base + h->relr_offset, t_hi = t_lo + h->relr_size;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t w = relr[i];
        if (!(w & 1)) {                     /* an address: relocate it, a bitmap may follow */
            if (w < lo || w > hi || w % 8 || (w + 8 > t_lo && w < t_hi))
                return "kernel relocation outside the image";
            *(uint64_t *)(image + (w - lo)) += delta;
            where = w + 8;
            continue;
        }
        if (!where)
            return "kernel relocation table starts with a bitmap";
        for (unsigned b = 1; b < 64; b++) {  /* bit b: the word at where + (b - 1) * 8 */
            if (!((w >> b) & 1))
                continue;
            uint64_t a = where + (uint64_t)(b - 1) * 8;
            if (a < lo || a > hi || (a + 8 > t_lo && a < t_hi))
                return "kernel relocation outside the image";
            *(uint64_t *)(image + (a - lo)) += delta;
        }
        where += 63 * 8;
    }
    return 0;
}

void kaslr_map_window(uint64_t *pdpt, uint64_t base, uint64_t pd0, uint64_t pd1)
{
    for (int i = 0; i < 512; i++)
        pdpt[i] = 0;
    int first = (int)((base >> 30) & 511);
    for (uint64_t i = 0; i < 512; i++) {
        uint64_t va = base + i * KASLR_ALIGN;
        int e = (int)((va >> 30) & 511);
        uint64_t pd = e == first ? pd0 : pd1;
        pdpt[e] = pd | PT_P | PT_W;
        ((uint64_t *)(uintptr_t)pd)[(va >> 21) & 511] = (i * KASLR_ALIGN) | PT_P | PT_W | PT_PS;
    }
}
