/*
 * Physical memory manager: one bit per 4 KiB frame (1 = used).
 *
 * The E820 map is untrusted: usable ranges are rounded inward, everything else is rounded outward and
 * applied last, so overlapping or bogus entries can never free reserved memory. Low memory (<1 MiB),
 * the kernel image and the bitmap itself are always reserved. Frees are checked (double free, reserved
 * or out-of-range frames panic).
 */

#include <stdint.h>
#include "fault.h"
#include "mm.h"
#include "panic.h"
#include "printf.h"
#include "spinlock.h"
#include "string.h"

extern char __kernel_start[], __kernel_end[];

#define BOOT_REACHABLE (1ull << 30)   /* boot identity map covers the first 1 GiB */

static uint64_t bitmap_phys, bitmap_words, bitmap_bytes;
static uint64_t max_frames, free_frames, total_frames;
static uint64_t hint;   /* word index to start searching from */
static spinlock_t pmm_lk = SPINLOCK_INIT("pmm", LOCK_RANK_PMM);

static inline uint64_t *bm(void) { return (uint64_t *)phys_to_virt(bitmap_phys); }

static uint64_t align_up(uint64_t v) { return (v + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1); }
static uint64_t align_down(uint64_t v) { return v & ~(PAGE_SIZE - 1); }

static unsigned popcount64(uint64_t v)
{
    v = v - ((v >> 1) & 0x5555555555555555ull);
    v = (v & 0x3333333333333333ull) + ((v >> 2) & 0x3333333333333333ull);
    v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0Full;
    return (unsigned)((v * 0x0101010101010101ull) >> 56);
}

/* Mark frames [first, last) used or free; word-at-a-time for the middle. */
static void mark(uint64_t first, uint64_t last, bool used)
{
    uint64_t *b = bm();
    if (last > max_frames)
        last = max_frames;
    while (first < last && (first & 63)) {
        if (used) b[first / 64] |= 1ull << (first & 63);
        else      b[first / 64] &= ~(1ull << (first & 63));
        first++;
    }
    while (first + 64 <= last) {
        b[first / 64] = used ? ~0ull : 0;
        first += 64;
    }
    while (first < last) {
        if (used) b[first / 64] |= 1ull << (first & 63);
        else      b[first / 64] &= ~(1ull << (first & 63));
        first++;
    }
}

static void mark_used_range(uint64_t start, uint64_t end)    /* rounded outward */
{
    if (end > start)
        mark(align_down(start) / PAGE_SIZE, align_up(end) / PAGE_SIZE, true);
}

static void mark_free_range(uint64_t start, uint64_t end)    /* rounded inward */
{
    uint64_t s = align_up(start), e = align_down(end);
    if (e > s)
        mark(s / PAGE_SIZE, e / PAGE_SIZE, false);
}

static const BootInfo *boot_bi;   /* kmain's validated copy (lives for ever) */

bool pmm_range_is_ram(uint64_t pa, uint64_t len)
{
    const MemoryMapEntry *mm = (const MemoryMapEntry *)(uintptr_t)boot_bi->mmap_addr;
    uint64_t end = pa + len;
    if (end < pa)
        return true;                           /* wraps: treat as overlapping (refuse) */
    for (uint32_t i = 0; i < boot_bi->mmap_count; i++) {
        if (mm[i].type != MMAP_USABLE && mm[i].type != MMAP_ACPI_RECLAIMABLE)
            continue;
        if (pa < mm[i].base + mm[i].length && mm[i].base < end)
            return true;
    }
    return pa < LOW_MEMORY_END;                /* BIOS, bootloader, trampoline: never a BAR */
}

void pmm_init(const BootInfo *bi)
{
    boot_bi = bi;
    const MemoryMapEntry *mm = (const MemoryMapEntry *)(uintptr_t)bi->mmap_addr;
    uint64_t k_start = KERNEL_PHYS(__kernel_start), k_end = KERNEL_PHYS(__kernel_end);

    /* Size the bitmap by the highest usable address. */
    uint64_t top = 0;
    for (uint32_t i = 0; i < bi->mmap_count; i++)
        if (mm[i].type == MMAP_USABLE && align_down(mm[i].base + mm[i].length) > top)
            top = align_down(mm[i].base + mm[i].length);
    if (top > PHYSMAP_SIZE)
        top = PHYSMAP_SIZE;
    max_frames = top / PAGE_SIZE;
    bitmap_words = (max_frames + 63) / 64;
    bitmap_bytes = bitmap_words * 8;

    /* Place the bitmap in usable RAM above the kernel, reachable through the boot identity map. */
    uint64_t need = align_up(bitmap_bytes);
    for (uint32_t i = 0; i < bi->mmap_count && !bitmap_phys; i++) {
        if (mm[i].type != MMAP_USABLE)
            continue;
        uint64_t s = align_up(mm[i].base), e = align_down(mm[i].base + mm[i].length);
        if (s < k_end)
            s = k_end;
        if (e > BOOT_REACHABLE)
            e = BOOT_REACHABLE;
        if (e > s && e - s >= need)
            bitmap_phys = s;
    }
    if (!bitmap_phys)
        panic("PMM: no room for the frame bitmap (%llu bytes)", (unsigned long long)bitmap_bytes);

    memset(bm(), 0xFF, bitmap_bytes);                  /* everything used by default */
    for (uint32_t i = 0; i < bi->mmap_count; i++)
        if (mm[i].type == MMAP_USABLE)
            mark_free_range(mm[i].base, mm[i].base + mm[i].length);
    for (uint32_t i = 0; i < bi->mmap_count; i++)     /* non-usable wins over overlaps */
        if (mm[i].type != MMAP_USABLE)
            mark_used_range(mm[i].base, mm[i].base + mm[i].length);
    mark_used_range(0, LOW_MEMORY_END);
    mark_used_range(k_start, k_end);
    mark_used_range(bitmap_phys, bitmap_phys + bitmap_bytes);

    free_frames = 0;
    for (uint64_t w = 0; w < bitmap_words; w++)
        free_frames += 64 - popcount64(bm()[w]);
    total_frames = free_frames;
    hint = 0;
}

static uint64_t alloc_nolock(void)
{
    uint64_t *b = bm();
    for (uint64_t n = 0; n < bitmap_words; n++) {
        uint64_t w = hint + n;
        if (w >= bitmap_words)
            w -= bitmap_words;
        if (b[w] == ~0ull)
            continue;
        unsigned bit = (unsigned)__builtin_ctzll(~b[w]);
        uint64_t frame = w * 64 + bit;
        if (frame >= max_frames)
            continue;
        b[w] |= 1ull << bit;
        free_frames--;
        hint = w;
        uint64_t pa = frame * PAGE_SIZE;
        KASSERT(vmm_active() || pa + PAGE_SIZE <= BOOT_REACHABLE);
        return pa;
    }
    return 0;
}

uint64_t pmm_alloc(void)
{
    if (fault_should_fail(FAULT_PMM))
        return 0;
    uint64_t f = spin_lock_irqsave(&pmm_lk);
    uint64_t pa = alloc_nolock();
    spin_unlock_irqrestore(&pmm_lk, f);
    return pa;
}

uint64_t pmm_alloc_zeroed(void)
{
    uint64_t pa = pmm_alloc();
    if (pa)
        memset(phys_to_virt(pa), 0, PAGE_SIZE);
    return pa;
}

/* `frames` physically contiguous frames, zeroed (tables a device reads by index, such as an
 * IOMMU device table). A first-fit scan of the bitmap; boot-time use only. 0 when none is free. */
uint64_t pmm_alloc_contig_zeroed(uint64_t frames)
{
    if (frames == 0 || frames > max_frames || fault_should_fail(FAULT_PMM))
        return 0;
    uint64_t f = spin_lock_irqsave(&pmm_lk);
    uint64_t *b = bm(), run = 0, first = 0, pa = 0;
    for (uint64_t i = 0; i < max_frames; i++) {
        if (b[i / 64] & (1ull << (i & 63))) {
            run = 0;
            continue;
        }
        if (run++ == 0)
            first = i;
        if (run == frames) {
            mark(first, first + frames, true);
            free_frames -= frames;
            pa = first * PAGE_SIZE;
            break;
        }
    }
    spin_unlock_irqrestore(&pmm_lk, f);
    if (pa)
        memset(phys_to_virt(pa), 0, frames * PAGE_SIZE);
    return pa;
}

void pmm_free(uint64_t pa)
{
    uint64_t frame = pa / PAGE_SIZE;
    if ((pa & (PAGE_SIZE - 1)) || frame >= max_frames)
        panic("PMM: free of invalid frame %#llx", (unsigned long long)pa);
    if (pa < LOW_MEMORY_END ||
        (pa >= KERNEL_PHYS(__kernel_start) && pa < KERNEL_PHYS(__kernel_end)) ||
        (pa >= bitmap_phys && pa < bitmap_phys + bitmap_bytes))
        panic("PMM: free of reserved frame %#llx", (unsigned long long)pa);

    uint64_t f = spin_lock_irqsave(&pmm_lk);
    uint64_t *b = bm();
    uint64_t w = frame / 64, bit = 1ull << (frame & 63);
    if (!(b[w] & bit))
        panic("PMM: double free of frame %#llx", (unsigned long long)pa);
    b[w] &= ~bit;
    free_frames++;
    if (w < hint)
        hint = w;
    spin_unlock_irqrestore(&pmm_lk, f);
}

uint64_t pmm_free_frames(void) { return free_frames; }
uint64_t pmm_total_frames(void) { return total_frames; }

void pmm_print(void)
{
    kprintf("PMM: %llu MiB free of %llu MiB usable, bitmap %llu KiB at %#llx\n",
            (unsigned long long)(free_frames * PAGE_SIZE >> 20),
            (unsigned long long)(total_frames * PAGE_SIZE >> 20),
            (unsigned long long)((bitmap_bytes + 1023) / 1024), (unsigned long long)bitmap_phys);
}
