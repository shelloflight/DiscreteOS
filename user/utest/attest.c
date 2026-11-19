/*
 * Remote attestation from ring 3 (docs/attestation.md).
 *
 *   test_attest()   (utest all) the attest syscall's contract: a report for our nonce, same key
 *                   for every report of this boot, refused buffers and pointers; attest_activate
 *                   refuses challenges it cannot answer.
 *   attest_print()  (utest attest) what a program does for a remote party: take its nonce, get a
 *                   report, send it. Here "sending" is printing the report in hex on the log; the
 *                   test harness (build.ps1 Test-AttestReport) plays the remote verifier with
 *                   dosimg attest-verify against the build's reference kernel and key.
 */

#include "utest.h"

#define REPORT_MAGIC "DOSATT01"
#define OFF_NONCE 24
#define OFF_AK    88
#define OFF_COUNT 184

static uint8_t report[DOS_ATTEST_MAX];
static uint8_t report2[DOS_ATTEST_MAX];

static uint32_t u32_at(const uint8_t *b, uint32_t o)
{
    return (uint32_t)b[o] | (uint32_t)b[o + 1] << 8 | (uint32_t)b[o + 2] << 16 | (uint32_t)b[o + 3] << 24;
}

/* A nonce as a remote party would choose it: unpredictable (RDRAND when present, mixed with the TSC). */
static void make_nonce(uint8_t n[32])
{
    uint64_t x = rdtsc() * 0x9E3779B97F4A7C15ull;
    for (int i = 0; i < 4; i++) {
        uint64_t r = 0;
        unsigned char ok = 0;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(r), "=qm"(ok));
        x ^= (ok ? r : 0) + rdtsc();
        x ^= x >> 29;
        x *= 0xBF58476D1CE4E5B9ull;
        memcpy(n + 8 * i, &x, 8);
    }
}

void test_attest(void)
{
    uint8_t n1[32], n2[32];
    make_nonce(n1);
    make_nonce(n2);
    int64_t len = dos_attest(n1, report, sizeof(report));
    CHECK(len > 0 && len <= (int64_t)DOS_ATTEST_MAX);
    if (len <= 0)
        return;
    CHECK(memcmp(report, REPORT_MAGIC, 8) == 0);
    CHECK(memcmp(report + OFF_NONCE, n1, 32) == 0);
    uint32_t events = u32_at(report, OFF_COUNT);
    uint32_t tpm = (uint64_t)len >= 188 + 92ull * events + 4 ? u32_at(report, 188 + 92 * events) : 0xFFFFFFFFu;
    CHECK(events >= 2 && (uint64_t)len == 188 + 92ull * events + 4 + tpm + 64);   /* kernel + attestation key at least */
    int64_t len2 = dos_attest(n2, report2, sizeof(report2));
    CHECK(len2 >= len);
    CHECK(memcmp(report2 + OFF_NONCE, n2, 32) == 0);
    CHECK(memcmp(report2 + OFF_AK, report + OFF_AK, 32) == 0);          /* one key per boot */
    CHECK(memcmp(report2 + len2 - 64, report + len - 64, 64) != 0);     /* a new signature */
    /* Contract: too small = nothing written; bad pointers are refused, never followed. */
    memset(report2, 0x5A, 64);
    EXPECT(dos_attest(n1, report2, (uint64_t)len - 1), DOS_ERR_BUFFER_TOO_SMALL);
    CHECK(report2[0] == 0x5A);
    EXPECT(dos_attest((const uint8_t *)KERNEL_ADDR, report, sizeof(report)), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_attest(n1, (void *)KERNEL_ADDR, sizeof(report)), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_attest(n1, (void *)UNMAPPED, sizeof(report)), DOS_ERR_BAD_ADDRESS);
    /* attest_activate: a challenge that is not for this TPM is refused (no TPM: not supported). */
    static uint8_t challenge[DOS_ATTEST_CHALLENGE];
    uint8_t cred[32];
    memset(challenge, 0x11, sizeof(challenge));
    EXPECT(dos_attest_activate(challenge, cred), tpm ? DOS_ERR_ACCESS_DENIED : DOS_ERR_NOT_SUPPORTED);
    EXPECT(dos_attest_activate((const uint8_t *)KERNEL_ADDR, cred), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_attest_activate(challenge, (uint8_t *)KERNEL_ADDR), DOS_ERR_BAD_ADDRESS);
    dos_printf("utest: attest: %ld-byte report, %u events, TPM evidence %u bytes, same key for every report of this boot, bad buffers and challenges refused\n",
               len, events, tpm);
}

static void hex_line(const char *tag, const uint8_t *b, uint32_t n)
{
    static const char digits[] = "0123456789abcdef";
    char line[2 * 64 + 1];
    for (uint32_t i = 0; i < n; i++) {
        line[2 * i] = digits[b[i] >> 4];
        line[2 * i + 1] = digits[b[i] & 15];
    }
    line[2 * n] = 0;
    dos_printf("utest: %s %s\n", tag, line);
}

int attest_print(void)
{
    uint8_t nonce[32];
    make_nonce(nonce);
    int64_t len = dos_attest(nonce, report, sizeof(report));
    if (len <= 0) {
        dos_printf("utest: attest FAILED: %ld (%s)\n", len, dos_status(len));
        return 1;
    }
    hex_line("attest nonce", nonce, 32);
    for (int64_t off = 0; off < len; off += 64)
        hex_line("attest data", report + off, (uint32_t)(len - off < 64 ? len - off : 64));
    dos_printf("utest: attest report: %ld bytes\n", len);
    return 0;
}
