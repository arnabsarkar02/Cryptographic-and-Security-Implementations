/* keccak.c - compact SHA-3 / SHAKE implementation (FIPS 202) */
#include "keccak.h"
#include <string.h>

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static const int ROTC[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                             27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
static const int PILN[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                             15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

/* The Keccak-f[1600] permutation */
static void keccakf(uint64_t st[25]) {
    uint64_t t, bc[5];
    for (int r = 0; r < 24; r++) {
        /* theta */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        /* rho and pi */
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = PILN[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, ROTC[i]);
            t = bc[0];
        }
        /* chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        /* iota */
        st[0] ^= RC[r];
    }
}

void keccak_init(keccak_ctx *c, unsigned rate, uint8_t ds) {
    memset(c, 0, sizeof *c);
    c->rate = rate;
    c->ds = ds;
}

void keccak_absorb(keccak_ctx *c, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        c->s[c->pos >> 3] ^= (uint64_t)in[i] << (8 * (c->pos & 7));
        if (++c->pos == c->rate) {
            keccakf(c->s);
            c->pos = 0;
        }
    }
}

static void finalize(keccak_ctx *c) {
    c->s[c->pos >> 3] ^= (uint64_t)c->ds << (8 * (c->pos & 7));
    c->s[(c->rate - 1) >> 3] ^= (uint64_t)0x80 << (8 * ((c->rate - 1) & 7));
    keccakf(c->s);
    c->pos = 0;
    c->squeezing = 1;
}

void keccak_squeeze(keccak_ctx *c, uint8_t *out, size_t len) {
    if (!c->squeezing) finalize(c);
    for (size_t i = 0; i < len; i++) {
        if (c->pos == c->rate) {
            keccakf(c->s);
            c->pos = 0;
        }
        out[i] = (uint8_t)(c->s[c->pos >> 3] >> (8 * (c->pos & 7)));
        c->pos++;
    }
}

static void oneshot(unsigned rate, uint8_t ds, uint8_t *out, size_t outlen,
                    const uint8_t *in, size_t inlen) {
    keccak_ctx c;
    keccak_init(&c, rate, ds);
    keccak_absorb(&c, in, inlen);
    keccak_squeeze(&c, out, outlen);
}

void sha3_256(uint8_t out[32], const uint8_t *in, size_t n) { oneshot(136, 0x06, out, 32, in, n); }
void sha3_512(uint8_t out[64], const uint8_t *in, size_t n) { oneshot(72, 0x06, out, 64, in, n); }
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t n) { oneshot(168, 0x1F, out, outlen, in, n); }
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t n) { oneshot(136, 0x1F, out, outlen, in, n); }
