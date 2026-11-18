/*
 * Boot-time signature verification: SHA-512 (FIPS 180-4), Ed25519 verification (RFC 8032) and the
 * .dsig format. See dcrypto.h.
 *
 * The Ed25519 arithmetic follows TweetNaCl (Bernstein et al., public domain): field elements are
 * 16 signed 16-bit limbs in int64, points (X:Y:Z:T). The curve constants (d, 2d, sqrt(-1), the base
 * point) are computed at first use rather than tabulated. Not constant-time: it only handles
 * public data (signatures, public keys, the image being booted).
 */

#include "dcrypto.h"

#define FOR(i, n) for (i = 0; i < (n); ++i)

static void bytecopy(void *d, const void *s, size_t n)
{
    uint8_t *a = d;
    const uint8_t *b = s;
    while (n--)
        *a++ = *b++;
}

static int bytes_differ(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    while (n--)
        d |= *a++ ^ *b++;
    return d != 0;
}

/* ---- SHA-512 ------------------------------------------------------------------------------- */

static const uint64_t K[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull,
    0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull, 0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull, 0x983e5152ee66dfabull,
    0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull,
    0x53380d139d95b3dfull, 0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull, 0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull,
    0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 0xca273eceea26619cull,
    0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull, 0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

static uint64_t ror(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_block(uint64_t h[8], const uint8_t *b)
{
    uint64_t w[80], v[8];
    int i, j;
    FOR(i, 16) {
        w[i] = 0;
        FOR(j, 8) w[i] = w[i] << 8 | b[8 * i + j];
    }
    for (i = 16; i < 80; i++)
        w[i] = w[i - 16] + (ror(w[i - 15], 1) ^ ror(w[i - 15], 8) ^ (w[i - 15] >> 7)) + w[i - 7] +
               (ror(w[i - 2], 19) ^ ror(w[i - 2], 61) ^ (w[i - 2] >> 6));
    FOR(i, 8) v[i] = h[i];
    FOR(i, 80) {
        uint64_t t1 = v[7] + (ror(v[4], 14) ^ ror(v[4], 18) ^ ror(v[4], 41)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + K[i] + w[i];
        uint64_t t2 = (ror(v[0], 28) ^ ror(v[0], 34) ^ ror(v[0], 39)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        for (j = 7; j > 0; j--)
            v[j] = v[j - 1];
        v[4] += t1;
        v[0] = t1 + t2;
    }
    FOR(i, 8) h[i] += v[i];
}

void sha512_init(struct sha512 *s)
{
    static const uint64_t iv[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                                    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
    int i;
    FOR(i, 8) s->h[i] = iv[i];
    s->n = 0;
    s->len = 0;
}

void sha512_update(struct sha512 *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    s->len += len;
    while (len) {
        if (s->n == 0 && len >= 128) {
            sha512_block(s->h, p);
            p += 128;
            len -= 128;
            continue;
        }
        size_t k = 128 - s->n < len ? 128 - s->n : len;
        bytecopy(s->buf + s->n, p, k);
        s->n += k;
        p += k;
        len -= k;
        if (s->n == 128) {
            sha512_block(s->h, s->buf);
            s->n = 0;
        }
    }
}

void sha512_final(struct sha512 *s, uint8_t out[64])
{
    uint64_t bits = s->len * 8;
    int i, j;
    uint8_t pad = 0x80, zero = 0, lenb[16] = { 0 };
    sha512_update(s, &pad, 1);
    while (s->n != 112)
        sha512_update(s, &zero, 1);
    FOR(i, 8) lenb[15 - i] = (uint8_t)(bits >> (8 * i));
    lenb[7] = (uint8_t)(s->len >> 61);                 /* high bits of the 128-bit length */
    sha512_update(s, lenb, 16);
    FOR(i, 8) FOR(j, 8) out[8 * i + j] = (uint8_t)(s->h[i] >> (56 - 8 * j));
}

/* ---- field arithmetic mod 2^255 - 19 (TweetNaCl) -------------------------------------------- */

typedef int64_t gf[16];

static const gf gf0 = { 0 }, gf1 = { 1 };
static gf D, D2, I, BX, BY;
static int consts_ready;

static void set25519(gf r, const gf a) { int i; FOR(i, 16) r[i] = a[i]; }

static void car25519(gf o)
{
    int i;
    int64_t c;
    FOR(i, 16) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536;      /* c << 16, without shifting a negative value */
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t t, i, c = ~(b - 1);
    FOR(i, 16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    int i, j, b;
    gf m, t;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    FOR(i, 16) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static int neq25519(const gf a, const gf b)
{
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return bytes_differ(c, d, 32);
}

static uint8_t par25519(const gf a)
{
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void unpack25519(gf o, const uint8_t *n)
{
    int i;
    FOR(i, 16) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) { int i; FOR(i, 16) o[i] = a[i] + b[i]; }
static void Z(gf o, const gf a, const gf b) { int i; FOR(i, 16) o[i] = a[i] - b[i]; }

static void M(gf o, const gf a, const gf b)
{
    int64_t i, j, t[31];
    FOR(i, 31) t[i] = 0;
    FOR(i, 16) FOR(j, 16) t[i + j] += a[i] * b[j];
    FOR(i, 15) t[i] += 38 * t[i + 16];
    FOR(i, 16) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

static void inv25519(gf o, const gf i)
{
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4)
            M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

static void pow2523(gf o, const gf i)
{
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 250; a >= 0; a--) {
        S(c, c);
        if (a != 1)
            M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

/* ---- points ------------------------------------------------------------------------------------ */

static void add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], uint8_t b)
{
    int i;
    FOR(i, 4) sel25519(p[i], q[i], b);
}

static void pack(uint8_t *r, gf p[4])
{
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}

static void scalarmult(gf p[4], gf q[4], const uint8_t *s)
{
    int i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        uint8_t b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(gf p[4], const uint8_t *s)
{
    gf q[4];
    set25519(q[0], BX);
    set25519(q[1], BY);
    set25519(q[2], gf1);
    M(q[3], BX, BY);
    scalarmult(p, q, s);
}

/* -P from its encoding; -1 if it is not a point (or its y is not canonical). */
static int unpackneg(gf r[4], const uint8_t p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    uint8_t y[32], back[32];
    bytecopy(y, p, 32);
    y[31] &= 0x7f;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    pack25519(back, r[1]);
    if (bytes_differ(back, y, 32))
        return -1;                          /* y >= p */
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);
    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);
    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);
    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num))
        M(r[0], r[0], I);
    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num))
        return -1;
    uint8_t xb[32];
    pack25519(xb, r[0]);
    int xzero = !bytes_differ(xb, (const uint8_t[32]){ 0 }, 32);
    if (xzero && (p[31] >> 7))
        return -1;
    if (par25519(r[0]) == (p[31] >> 7))
        Z(r[0], gf0, r[0]);
    M(r[3], r[0], r[1]);
    return 0;
}

static void pow_bytes(gf o, const gf b, const uint8_t e[32])
{
    gf r;
    int i;
    set25519(r, gf1);
    for (i = 255; i >= 0; i--) {
        S(r, r);
        if ((e[i / 8] >> (i & 7)) & 1)
            M(r, r, b);
    }
    set25519(o, r);
}

static void init_consts(void)
{
    if (consts_ready)
        return;
    gf n = { 0xDB41, 1 }, den = { 0xDB42, 1 }, two = { 2 }, four = { 4 }, five = { 5 }, t;
    inv25519(t, den);
    M(D, n, t);
    Z(D, gf0, D);                           /* d = -121665 / 121666 */
    A(D2, D, D);
    uint8_t e[32];
    int i;
    FOR(i, 32) e[i] = 0xff;
    e[0] = 0xfb;
    e[31] = 0x1f;                           /* (p - 1) / 4 */
    pow_bytes(I, two, e);
    inv25519(t, five);
    M(BY, four, t);                         /* base point: y = 4/5, x even */
    uint8_t yb[32];
    pack25519(yb, BY);
    gf q[4];
    consts_ready = 1;                       /* unpackneg needs D and I */
    unpackneg(q, yb);
    Z(BX, gf0, q[0]);
}

/* ---- scalars mod L (TweetNaCl) ------------------------------------------------------------------ */

static const int64_t L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

static void modL(uint8_t *r, int64_t x[64])
{
    int64_t carry, i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    FOR(j, 32) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    FOR(j, 32) x[j] -= carry * L[j];
    FOR(i, 32) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void reduce(uint8_t *r)
{
    int64_t x[64], i;
    FOR(i, 64) x[i] = (int64_t)(uint64_t)r[i];
    FOR(i, 64) r[i] = 0;
    modL(r, x);
}

static int scalar_canonical(const uint8_t *s)
{
    for (int i = 31; i >= 0; i--) {
        if (s[i] < (uint8_t)L[i])
            return 1;
        if (s[i] > (uint8_t)L[i])
            return 0;
    }
    return 0;
}

int ed25519_verify(const uint8_t pub[32], const uint8_t *m, size_t len, const uint8_t sig[64])
{
    init_consts();
    if (!scalar_canonical(sig + 32))
        return -1;
    gf p[4], q[4];
    if (unpackneg(q, pub))
        return -1;
    uint8_t h[64], t[32];
    struct sha512 s;
    sha512_init(&s);
    sha512_update(&s, sig, 32);
    sha512_update(&s, pub, 32);
    sha512_update(&s, m, len);
    sha512_final(&s, h);
    reduce(h);
    scalarmult(p, q, h);                    /* [k](-A) */
    scalarbase(q, sig + 32);                /* [S]B */
    add(p, q);
    pack(t, p);
    return bytes_differ(sig, t, 32) ? -1 : 0;
}

/* ---- .dsig ---------------------------------------------------------------------------------- */

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void dsig_key_id(const uint8_t pub[32], uint8_t id[16])
{
    uint8_t h[64];
    struct sha512 s;
    sha512_init(&s);
    sha512_update(&s, pub, 32);
    sha512_final(&s, h);
    bytecopy(id, h, 16);
}

const char *dsig_result_text(enum dsig_result r)
{
    switch (r) {
    case DSIG_OK:            return "valid";
    case DSIG_BAD_FORMAT:    return "not a D-OS signature (.dsig v1)";
    case DSIG_WRONG_KIND:    return "signature is for another kind of file";
    case DSIG_UNKNOWN_KEY:   return "signed by an unknown key";
    case DSIG_BAD_CONTENT:   return "content does not match the signature (modified?)";
    case DSIG_BAD_SIGNATURE: return "signature is invalid";
    }
    return "?";
}

enum dsig_result dsig_verify(const uint8_t d[DSIG_SIZE], uint32_t kind, const uint8_t pub[32], const void *content,
                             uint64_t len, uint8_t hash_out[64])
{
    static const uint8_t magic[4] = { 'D', 'S', 'I', 'G' };
    if (bytes_differ(d, magic, 4) || d[4] != 1 || d[5] != 0 || d[6] != 1 || d[7] != 0 || rd32(d + 12) != 0)
        return DSIG_BAD_FORMAT;
    if (rd32(d + 8) != kind)
        return DSIG_WRONG_KIND;
    uint8_t id[16];
    dsig_key_id(pub, id);
    if (bytes_differ(d + 16, id, 16))
        return DSIG_UNKNOWN_KEY;
    uint64_t size = 0;
    for (int i = 7; i >= 0; i--)
        size = size << 8 | d[32 + i];
    uint8_t h[64];
    struct sha512 s;
    sha512_init(&s);
    sha512_update(&s, content, (size_t)len);
    sha512_final(&s, h);
    if (size != len || bytes_differ(d + 40, h, 64))
        return DSIG_BAD_CONTENT;
    if (ed25519_verify(pub, d, DSIG_SIGNED, d + DSIG_SIGNED))
        return DSIG_BAD_SIGNATURE;
    if (hash_out)
        bytecopy(hash_out, h, 64);
    return DSIG_OK;
}
