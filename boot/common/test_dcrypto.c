/*
 * Host test of the boot loaders' verifier (dcrypto.c), built by build.ps1 (case crypto-host) with
 * the devbox's MinGW gcc:
 *   test_dcrypto                          RFC 8032 / FIPS 180 vectors and rejection cases
 *   test_dcrypto <pubhex> <file> <dsig> <expect: ok|bad>
 *                                         cross-check: a .dsig made by the Rust signer (dosimg)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dcrypto.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static void unhex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static const char *vec[3][4] = {
    { "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
    { "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
    { "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
};

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*len ? *len : 1);
    if (fread(b, 1, *len, f) != *len) {
        fclose(f);
        free(b);
        return NULL;
    }
    fclose(f);
    return b;
}

int main(int argc, char **argv)
{
    if (argc == 5) {
        uint8_t pub[32];
        size_t clen, dlen;
        unhex(argv[1], pub, 32);
        uint8_t *c = slurp(argv[2], &clen), *d = slurp(argv[3], &dlen);
        if (!c || !d || dlen != DSIG_SIZE) {
            printf("cannot read inputs\n");
            return 2;
        }
        int kind = d[8];
        enum dsig_result r = dsig_verify(d, (uint32_t)kind, pub, c, clen, NULL);
        int want_ok = strcmp(argv[4], "ok") == 0;
        printf("C verifier: %s: %s\n", argv[2], dsig_result_text(r));
        return (r == DSIG_OK) == want_ok ? 0 : 1;
    }

    uint8_t h[64], want[64];
    struct sha512 s;
    sha512_init(&s);
    sha512_update(&s, "abc", 3);
    sha512_final(&s, h);
    unhex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", want, 64);
    CHECK(memcmp(h, want, 64) == 0);

    for (int i = 0; i < 3; i++) {
        uint8_t pub[32], sig[64], msg[2];
        size_t mlen = strlen(vec[i][1]) / 2;
        unhex(vec[i][0], pub, 32);
        unhex(vec[i][1], msg, mlen);
        unhex(vec[i][2], sig, 64);
        CHECK(ed25519_verify(pub, msg, mlen, sig) == 0);
        sig[5] ^= 1;
        CHECK(ed25519_verify(pub, msg, mlen, sig) != 0);
        sig[5] ^= 1;
        msg[0] ^= 1;
        CHECK(ed25519_verify(pub, msg, mlen ? mlen : 1, sig) != 0);
        msg[0] ^= 1;
        /* non-canonical S (S + L) */
        static const uint8_t L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
        unsigned carry = 0;
        for (int j = 0; j < 32; j++) {
            unsigned v = sig[32 + j] + L[j] + carry;
            sig[32 + j] = (uint8_t)v;
            carry = v >> 8;
        }
        CHECK(ed25519_verify(pub, msg, mlen, sig) != 0);
    }
    printf("C verifier: SHA-512 and RFC 8032 vectors %s\n", fails ? "FAILED" : "pass; tampering, other messages and non-canonical S refused");
    return fails ? 1 : 0;
}
