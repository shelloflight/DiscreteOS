/*
 * Host test of the loaders' KASLR code (boot/common/kaslr.c), built with MinGW gcc by
 * build.ps1 (case kaslr-host).
 *   test_kaslr                 synthetic images: relocation applied exactly to the listed words,
 *                              bad tables and headers refused, bases in the window and spread out
 *   test_kaslr list KERNEL.BIN print every address the image's RELR table relocates (hex, one per
 *                              line): build.ps1 compares it with llvm-readobj's decoding of kernel.elf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kaslr.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

#define IMG 0x4000u
#define BASE (KASLR_LINK_BASE + 0x100000)

static uint8_t img[IMG];

static struct kernel_header make(uint64_t *relr, unsigned n)
{
    memset(img, 0, sizeof(img));
    struct kernel_header h = { KHDR_MAGIC, KHDR_VERSION, 64, BASE + 0x100, BASE, 0x100000, IMG, IMG, 0x3000, n * 8, 0 };
    memcpy(img, &h, sizeof(h));
    memcpy(img + 0x3000, relr, n * 8);
    for (unsigned i = 0x40; i < 0x3000; i += 8) {   /* every word holds a link-time pointer */
        uint64_t v = BASE + i;
        memcpy(img + i, &v, 8);
    }
    return h;
}

static uint64_t word(unsigned off)
{
    uint64_t v;
    memcpy(&v, img + off, 8);
    return v;
}

static void synthetic(void)
{
    /* address 0x100, bitmap: words 0x108 (bit 1), 0x118 (bit 3), 0x100+8+62*8 (bit 63);
     * address 0x2000, then a bitmap continuing 63 words later with bit 1 */
    uint64_t relr[] = { BASE + 0x100, (1ull << 1) | (1ull << 3) | (1ull << 63) | 1, BASE + 0x2000, 1 | (1ull << 1) | 0, 1 | (1ull << 2) };
    struct kernel_header h = make(relr, 5);
    CHECK(kaslr_check_header(&h, IMG) == NULL);
    uint64_t delta = 0xFFFFFF8000000000ull - KASLR_LINK_BASE;
    CHECK(kaslr_relocate(img, &h, delta) == NULL);
    unsigned want[] = { 0x100, 0x108, 0x118, 0x100 + 8 + 62 * 8, 0x2000, 0x2008, 0x2008 + 63 * 8 + 8 };
    unsigned moved = 0;
    for (unsigned off = 0x40; off < 0x3000; off += 8) {
        int listed = 0;
        for (unsigned k = 0; k < sizeof(want) / sizeof(want[0]); k++)
            listed |= want[k] == off;
        uint64_t expect = BASE + off + (listed ? delta : 0);
        if (word(off) != expect) {
            printf("FAIL: word at %#x is %#llx, want %#llx\n", off, (unsigned long long)word(off), (unsigned long long)expect);
            fails++;
        }
        moved += listed;
    }
    CHECK(moved == 7);

    /* refused tables */
    uint64_t out_lo[] = { BASE - 8 };
    h = make(out_lo, 1);
    CHECK(kaslr_relocate(img, &h, delta) != NULL);
    uint64_t out_hi[] = { BASE + IMG - 4 };
    h = make(out_hi, 1);
    CHECK(kaslr_relocate(img, &h, delta) != NULL);
    uint64_t unaligned[] = { BASE + 0x102 };
    h = make(unaligned, 1);
    CHECK(kaslr_relocate(img, &h, delta) != NULL);
    uint64_t bitmap_first[] = { 3 };
    h = make(bitmap_first, 1);
    CHECK(kaslr_relocate(img, &h, delta) != NULL);
    uint64_t into_table[] = { BASE + 0x3000 };
    h = make(into_table, 1);
    CHECK(kaslr_relocate(img, &h, delta) != NULL);
    uint64_t bitmap_past_end[] = { BASE + IMG - 16, 1 | (1ull << 2) };
    h = make(bitmap_past_end, 2);
    CHECK(kaslr_relocate(img, &h, delta) != NULL);

    /* refused headers */
    uint64_t ok[] = { BASE + 0x100 };
    h = make(ok, 1);
    struct kernel_header b = h;
    b.version = 1;
    CHECK(kaslr_check_header(&b, IMG) != NULL);
    b = h; b.relr_offset = 0x3004;
    CHECK(kaslr_check_header(&b, IMG) != NULL);
    b = h; b.relr_size = IMG;
    CHECK(kaslr_check_header(&b, IMG) != NULL);
    b = h; b.virt_base += 0x1000;
    CHECK(kaslr_check_header(&b, IMG) != NULL);
    b = h; b.entry = BASE + IMG;
    CHECK(kaslr_check_header(&b, IMG) != NULL);
    b = h;
    CHECK(kaslr_check_header(&b, IMG - 8) != NULL);   /* file shorter than the header says */

    /* bases: in the window, aligned, the whole range reachable, and spread out */
    uint8_t r[8];
    memset(r, 0, 8);
    CHECK(kaslr_pick_base(r) == KASLR_WINDOW);
    memset(r, 0xFF, 8);
    uint64_t top = kaslr_pick_base(r);
    CHECK(top == KASLR_WINDOW_END - KASLR_ALIGN);
    CHECK(top + (1ull << 30) - 1 > top);    /* the 1 GiB boot window never wraps past 2^64 */
    unsigned distinct = 0;
    uint64_t seen[64];
    for (int i = 0; i < 64; i++) {
        uint8_t e[64];
        uint32_t src = kaslr_entropy(NULL, 0, 0, e);
        CHECK(src & KASLR_SRC_TSC);
        uint64_t b2 = kaslr_pick_base(e);
        CHECK(b2 >= KASLR_WINDOW && b2 < KASLR_WINDOW_END && b2 % KASLR_ALIGN == 0);
        int dup = 0;
        for (unsigned k = 0; k < distinct; k++)
            dup |= seen[k] == b2;
        if (!dup)
            seen[distinct++] = b2;
    }
    CHECK(distinct >= 60);   /* 64 draws from 261632 slots: a collision or two at most */

    /* the window mapping: physical 0..1 GiB from the base, across two PDPT entries */
    static uint64_t pdpt[512], pd[2][512] __attribute__((aligned(4096)));   /* page tables: 4 KiB-aligned */
    uint64_t base = KASLR_WINDOW + 5 * (1ull << 30) + 7 * KASLR_ALIGN;
    kaslr_map_window(pdpt, base, (uint64_t)(uintptr_t)pd[0], (uint64_t)(uintptr_t)pd[1]);
    CHECK((pdpt[5] & ~0xFFFull) == (uint64_t)(uintptr_t)pd[0] && (pdpt[6] & ~0xFFFull) == (uint64_t)(uintptr_t)pd[1]);
    CHECK((pd[0][7] & ~0xFFFull) == 0 && (pd[0][511] & ~0xFFFull) == 504 * KASLR_ALIGN && (pd[1][6] & ~0xFFFull) == 511 * KASLR_ALIGN);
    CHECK(pd[0][6] == 0 && pd[1][7] == 0);
}

static int list(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 2;
    static uint8_t buf[64 << 20];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    struct kernel_header h;
    if (n < sizeof(h))
        return 2;
    memcpy(&h, buf, sizeof(h));
    const char *why = kaslr_check_header(&h, n);
    if (why) {
        printf("bad header: %s\n", why);
        return 1;
    }
    /* Relocate by delta = 1 on a copy; every word that changed by exactly 1 was listed. */
    static uint8_t copy[64 << 20];
    memcpy(copy, buf, n);
    why = kaslr_relocate(copy, &h, 1);
    if (why) {
        printf("bad table: %s\n", why);
        return 1;
    }
    for (uint64_t off = 0; off + 8 <= h.file_size; off += 8) {
        uint64_t a, b;
        memcpy(&a, buf + off, 8);
        memcpy(&b, copy + off, 8);
        if (b == a + 1)
            printf("%016llx\n", (unsigned long long)(h.virt_base + off));
        else if (a != b)
            return 3;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "list") == 0)
        return list(argv[2]);
    synthetic();
    if (fails)
        printf("kaslr: %d check(s) FAILED\n", fails);
    else
        printf("kaslr: relocation, refused tables/headers, base choice, window mapping OK\n");
    return fails ? 1 : 0;
}
