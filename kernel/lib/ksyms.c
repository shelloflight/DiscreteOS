/*
 * Kernel symbol table: every text symbol, sorted by address, linked into the image by the
 * second link of build.ps1 (section .ksyms after .rodata, so the first link's function
 * addresses stay valid). Used for symbolized backtraces in panic and fault reports.
 *
 * Layout: header { 'KSYM', count, string-table offset }, then `count` entries of
 * { offset from __text_start, name offset }, then the NUL-terminated names. Read-only data.
 */

#include <stdint.h>
#include "ksyms.h"

extern const char __ksyms_start[], __ksyms_end[], __text_start[], __text_end[];

#define KSYM_MAGIC 0x4D59534Bu

struct ksym_entry {
    uint32_t off, name;
};

static uint64_t ksyms_size(void) { return (uint64_t)(uintptr_t)__ksyms_end - (uint64_t)(uintptr_t)__ksyms_start; }

static const uint32_t *header(void)
{
    const uint32_t *h = (const uint32_t *)(const void *)__ksyms_start;
    if (ksyms_size() < 12 || h[0] != KSYM_MAGIC)
        return 0;
    uint64_t need = 12 + 8ull * h[1];
    if (need > ksyms_size() || h[2] > ksyms_size())
        return 0;
    return h;
}

uint32_t ksym_count(void)
{
    const uint32_t *h = header();
    return h ? h[1] : 0;
}

const char *ksym_lookup(uint64_t addr, uint64_t *offset)
{
    const uint32_t *h = header();
    uint64_t text = (uint64_t)(uintptr_t)__text_start;
    if (!h || !h[1] || addr < text || addr >= (uint64_t)(uintptr_t)__text_end)
        return 0;
    const struct ksym_entry *e = (const struct ksym_entry *)(h + 3);
    uint32_t off = (uint32_t)(addr - text), lo = 0, hi = h[1];
    if (off < e[0].off)
        return 0;
    while (hi - lo > 1) {                      /* last entry with e.off <= off */
        uint32_t mid = lo + (hi - lo) / 2;
        if (e[mid].off <= off)
            lo = mid;
        else
            hi = mid;
    }
    *offset = off - e[lo].off;
    return __ksyms_start + h[2] + e[lo].name;
}
