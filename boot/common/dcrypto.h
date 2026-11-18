/*
 * Boot-time signature verification (C, freestanding): SHA-512, Ed25519 verification (RFC 8032)
 * and the .dsig format (docs/signing.md). Used by the UEFI loader and the BIOS stage 3. The kernel
 * and the host tools use the Rust implementation (user/lib/crypto); the tests cross-check both.
 */
#ifndef DOS_DCRYPTO_H
#define DOS_DCRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---- SHA-512 ---- */
struct sha512 {
    uint64_t h[8];
    uint8_t  buf[128];
    size_t   n;
    uint64_t len;           /* bytes (images are far below 2^61) */
};
void sha512_init(struct sha512 *s);
void sha512_update(struct sha512 *s, const void *data, size_t len);
void sha512_final(struct sha512 *s, uint8_t out[64]);

/* ---- Ed25519 ---- */
/* 0 if `sig` is a valid signature of m[0..len) by `pub` (strict: canonical S and key). */
int ed25519_verify(const uint8_t pub[32], const uint8_t *m, size_t len, const uint8_t sig[64]);

/* ---- .dsig (256 bytes) ---- */
#define DSIG_SIZE        256
#define DSIG_SIGNED      192
#define DSIG_KIND_KERNEL 1
#define DSIG_KIND_PROGRAM 2

enum dsig_result {
    DSIG_OK = 0,
    DSIG_BAD_FORMAT,        /* not a v1 Ed25519 .dsig */
    DSIG_WRONG_KIND,
    DSIG_UNKNOWN_KEY,       /* signed by another key */
    DSIG_BAD_CONTENT,       /* size or SHA-512 of the content differs */
    DSIG_BAD_SIGNATURE,
};
const char *dsig_result_text(enum dsig_result r);

/* Verify `dsig` for content[0..len) (hashed here) of `kind` against `pub`. On success the content's
 * SHA-512 is in hash_out (may be NULL). */
enum dsig_result dsig_verify(const uint8_t dsig[DSIG_SIZE], uint32_t kind, const uint8_t pub[32],
                             const void *content, uint64_t len, uint8_t hash_out[64]);

/* The first 16 bytes of SHA-512(pub) */
void dsig_key_id(const uint8_t pub[32], uint8_t id[16]);

#endif
