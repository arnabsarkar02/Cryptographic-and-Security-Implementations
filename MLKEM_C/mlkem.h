/* mlkem.h - ML-KEM (FIPS 203) educational implementation */
#ifndef MLKEM_H
#define MLKEM_H

#include <stddef.h>
#include <stdint.h>

/* Table 2 of FIPS 203: the five variable parameters (n = 256, q = 3329 are fixed). */
typedef struct {
    const char *name;
    int k, eta1, eta2, du, dv;
} mlkem_params;

extern const mlkem_params MLKEM_512;
extern const mlkem_params MLKEM_768;
extern const mlkem_params MLKEM_1024;

/* Sizes in bytes (Table 3 / Algorithms 16-18) */
#define MLKEM_EK_BYTES(p)  (384 * (p)->k + 32)
#define MLKEM_DK_BYTES(p)  (768 * (p)->k + 96)
#define MLKEM_CT_BYTES(p)  (32 * ((p)->du * (p)->k + (p)->dv))
#define MLKEM_SS_BYTES     32

/* Maximum sizes over all parameter sets (handy for static buffers) */
#define MLKEM_MAX_EK 1568
#define MLKEM_MAX_DK 3168
#define MLKEM_MAX_CT 1568

/* ---- Main API (Section 7) ----------------------------------------------
 * Return 0 on success, negative on failure:
 *   -1 : input checking failed (bad length / bad key)
 *   -2 : random bit generation failed
 */
int mlkem_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk);                       /* Alg. 19 */
int mlkem_encaps(const mlkem_params *p, const uint8_t *ek, size_t ek_len,
                 uint8_t *ct, uint8_t ss[32]);                                          /* Alg. 20 */
int mlkem_decaps(const mlkem_params *p, const uint8_t *dk, size_t dk_len,
                 const uint8_t *ct, size_t ct_len, uint8_t ss[32]);                     /* Alg. 21 */

/* ---- Deterministic internal algorithms (Section 6): for testing only ---- */
void mlkem_keygen_internal(const mlkem_params *p, const uint8_t d[32], const uint8_t z[32],
                           uint8_t *ek, uint8_t *dk);                                   /* Alg. 16 */
void mlkem_encaps_internal(const mlkem_params *p, const uint8_t *ek, const uint8_t m[32],
                           uint8_t *ct, uint8_t ss[32]);                                /* Alg. 17 */
void mlkem_decaps_internal(const mlkem_params *p, const uint8_t *dk, const uint8_t *ct,
                           uint8_t ss[32]);                                             /* Alg. 18 */

/* ---- Building blocks exposed so the tests can check them (Section 4) ---- */
const uint16_t *mlkem_zetas(void);                                   /* zeta^BitRev7(i) mod q, Appendix A */
void mlkem_ntt(uint16_t f[256]);                                     /* Alg. 9  (in place)  */
void mlkem_ntt_inv(uint16_t f[256]);                                 /* Alg. 10 (in place)  */
void mlkem_multiply_ntts(uint16_t h[256], const uint16_t f[256], const uint16_t g[256]); /* Alg. 11 */

#endif
