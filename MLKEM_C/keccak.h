/* keccak.h - minimal SHA-3 / SHAKE (FIPS 202) used by ML-KEM (FIPS 203, Sec. 4.1) */
#ifndef KECCAK_H
#define KECCAK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t s[25];   /* Keccak state (1600 bits)                      */
    unsigned pos;     /* current byte position inside the rate portion  */
    unsigned rate;    /* rate in bytes (168 SHAKE128, 136 SHA3-256/SHAKE256, 72 SHA3-512) */
    uint8_t  ds;      /* domain-separation byte (0x06 SHA3, 0x1F SHAKE) */
    int      squeezing;
} keccak_ctx;

/* Incremental API (this is what SHAKE128.Init/Absorb/Squeeze in the spec map to) */
void keccak_init(keccak_ctx *c, unsigned rate, uint8_t ds);
void keccak_absorb(keccak_ctx *c, const uint8_t *in, size_t len);
void keccak_squeeze(keccak_ctx *c, uint8_t *out, size_t len);

/* One-shot helpers */
void sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen);
void sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen);
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/* XOF wrapper from Section 4.1 */
#define XOF_RATE 168
static inline void xof_init(keccak_ctx *c) { keccak_init(c, 168, 0x1F); }
#define xof_absorb  keccak_absorb
#define xof_squeeze keccak_squeeze

#endif
