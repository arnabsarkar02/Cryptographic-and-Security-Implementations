/* mlkem.c - ML-KEM (FIPS 203) educational implementation.
 *
 * The code follows the pseudocode of the standard as literally as possible.
 * Comments say which Algorithm / Section each piece comes from.
 *
 * NOT hardened for production: it prefers clarity over speed and uses plain '%'
 * on secret data (not guaranteed constant-time). Use a vetted library
 * (e.g. liboqs, mlkem-native) for real systems.
 */
#include "mlkem.h"
#include "keccak.h"

#include <stdio.h>
#include <string.h>

#define N 256
#define Q 3329
#define MAXK 4

const mlkem_params MLKEM_512  = {"ML-KEM-512",  2, 3, 2, 10, 4};
const mlkem_params MLKEM_768  = {"ML-KEM-768",  3, 2, 2, 10, 4};
const mlkem_params MLKEM_1024 = {"ML-KEM-1024", 4, 2, 2, 11, 5};

/* A polynomial (element of R_q or T_q) is an array of 256 integers mod q (Sec. 2.4.4) */
typedef uint16_t poly[N];

/* ------------------------------------------------------------------------ */
/* Small utilities                                                           */
/* ------------------------------------------------------------------------ */

/* Wipe memory in a way the compiler may not optimise away (Section 3.3: destroy intermediates). */
static void secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* Returns 0 if a == b, nonzero otherwise, without early exit. */
static uint8_t ct_diff(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++) r |= a[i] ^ b[i];
    return r;
}

/* Random bytes from the OS. NOTE: the standard requires an *approved* RBG
 * (SP 800-90A/B/C). /dev/urandom is fine for coursework, not for certification. */
static int rand_bytes(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(out, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

/* ------------------------------------------------------------------------ */
/* Section 4.1: cryptographic functions                                      */
/* ------------------------------------------------------------------------ */

/* PRF_eta(s, b) = SHAKE256(s || b, 8*64*eta)  (4.3) */
static void PRF(uint8_t *out, int eta, const uint8_t s[32], uint8_t b) {
    uint8_t in[33];
    memcpy(in, s, 32);
    in[32] = b;
    shake256(out, 64 * eta, in, 33);
}

/* H(s) = SHA3-256(s) */
static void H(uint8_t out[32], const uint8_t *in, size_t n) { sha3_256(out, in, n); }

/* J(s) = SHAKE256(s, 8*32) */
static void J(uint8_t out[32], const uint8_t *in, size_t n) { shake256(out, 32, in, n); }

/* G(c) = SHA3-512(c), split into (a, b) */
static void G(uint8_t a[32], uint8_t b[32], const uint8_t *in, size_t n) {
    uint8_t t[64];
    sha3_512(t, in, n);
    memcpy(a, t, 32);
    memcpy(b, t + 32, 32);
    secure_zero(t, sizeof t);
}

/* ------------------------------------------------------------------------ */
/* Section 4.2.1: encoding, compression                                      */
/* ------------------------------------------------------------------------ */

/* Algorithm 5: ByteEncode_d. F has 256 entries; B receives 32*d bytes.
 * Bit i*d+j of the stream is bit j of F[i]; bytes are little-endian bit order (Alg. 3). */
static void byte_encode(int d, const uint16_t F[N], uint8_t *B) {
    memset(B, 0, 32 * d);
    for (int i = 0; i < N; i++) {
        uint16_t a = F[i];
        for (int j = 0; j < d; j++) {
            size_t bit = (size_t)i * d + j;
            B[bit >> 3] |= (uint8_t)(((a >> j) & 1) << (bit & 7));
        }
    }
}

/* Algorithm 6: ByteDecode_d. For d = 12 the result is reduced mod q. */
static void byte_decode(int d, const uint8_t *B, uint16_t F[N]) {
    for (int i = 0; i < N; i++) {
        uint32_t v = 0;
        for (int j = 0; j < d; j++) {
            size_t bit = (size_t)i * d + j;
            v |= (uint32_t)((B[bit >> 3] >> (bit & 7)) & 1) << j;
        }
        F[i] = (uint16_t)(d == 12 ? v % Q : v);
    }
}

/* Compress_d(x) = round(2^d / q * x) mod 2^d  (4.7), in exact integer arithmetic.
 * round(y) = floor(y + 1/2)  =>  floor((2*2^d*x + q) / (2q)). */
static uint16_t compress(int d, uint16_t x) {
    uint32_t t = (((uint32_t)x << (d + 1)) + Q) / (2 * Q);
    return (uint16_t)(t & ((1u << d) - 1));
}

/* Decompress_d(y) = round(q / 2^d * y)  (4.8) */
static uint16_t decompress(int d, uint16_t y) {
    return (uint16_t)(((uint32_t)2 * Q * y + (1u << d)) >> (d + 1));
}

/* ------------------------------------------------------------------------ */
/* Section 4.3: NTT                                                          */
/* ------------------------------------------------------------------------ */

static uint16_t zetas[128];   /* zeta^BitRev7(i) mod q          (Appendix A, first table)  */
static uint16_t gammas[128];  /* zeta^(2*BitRev7(i)+1) mod q    (Appendix A, second table) */
static int tables_ready = 0;

static int bitrev7(int r) {
    int x = 0;
    for (int i = 0; i < 7; i++) { x = (x << 1) | (r & 1); r >>= 1; }
    return x;
}

static uint16_t powmod(uint32_t b, uint32_t e) {
    uint32_t r = 1;
    b %= Q;
    while (e) {
        if (e & 1) r = r * b % Q;
        b = b * b % Q;
        e >>= 1;
    }
    return (uint16_t)r;
}

/* zeta = 17 is a primitive 256-th root of unity mod 3329. (Not thread-safe lazy init.) */
static void init_tables(void) {
    if (tables_ready) return;
    for (int i = 0; i < 128; i++) {
        int br = bitrev7(i);
        zetas[i]  = powmod(17, br);
        gammas[i] = powmod(17, 2 * br + 1);
    }
    tables_ready = 1;
}

const uint16_t *mlkem_zetas(void) { init_tables(); return zetas; }

/* Algorithm 9: NTT (in place) */
void mlkem_ntt(uint16_t f[N]) {
    init_tables();
    int i = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            uint32_t zeta = zetas[i++];
            for (int j = start; j < start + len; j++) {
                uint32_t t = zeta * f[j + len] % Q;
                f[j + len] = (uint16_t)((f[j] + Q - t) % Q);
                f[j]       = (uint16_t)((f[j] + t) % Q);
            }
        }
    }
}

/* Algorithm 10: inverse NTT (in place) */
void mlkem_ntt_inv(uint16_t f[N]) {
    init_tables();
    int i = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            uint32_t zeta = zetas[i--];
            for (int j = start; j < start + len; j++) {
                uint32_t t = f[j];
                f[j]       = (uint16_t)((t + f[j + len]) % Q);
                f[j + len] = (uint16_t)(zeta * ((f[j + len] + Q - t) % Q) % Q);
            }
        }
    }
    for (int j = 0; j < N; j++) f[j] = (uint16_t)((uint32_t)f[j] * 3303 % Q); /* 3303 = 128^-1 mod q */
}

/* Algorithm 12: BaseCaseMultiply, product of (a0+a1 X)(b0+b1 X) mod (X^2 - gamma) */
static void base_case_multiply(uint16_t *c0, uint16_t *c1, uint32_t a0, uint32_t a1,
                               uint32_t b0, uint32_t b1, uint32_t gamma) {
    *c0 = (uint16_t)((a0 * b0 + (a1 * b1 % Q) * gamma) % Q);
    *c1 = (uint16_t)((a0 * b1 + a1 * b0) % Q);
}

/* Algorithm 11: MultiplyNTTs */
void mlkem_multiply_ntts(uint16_t h[N], const uint16_t f[N], const uint16_t g[N]) {
    init_tables();
    for (int i = 0; i < 128; i++)
        base_case_multiply(&h[2 * i], &h[2 * i + 1], f[2 * i], f[2 * i + 1],
                           g[2 * i], g[2 * i + 1], gammas[i]);
}

static void poly_add(uint16_t r[N], const uint16_t a[N], const uint16_t b[N]) {
    for (int i = 0; i < N; i++) r[i] = (uint16_t)((a[i] + b[i]) % Q);
}

static void poly_sub(uint16_t r[N], const uint16_t a[N], const uint16_t b[N]) {
    for (int i = 0; i < N; i++) r[i] = (uint16_t)((a[i] + Q - b[i]) % Q);
}

/* ------------------------------------------------------------------------ */
/* Section 4.2.2: sampling                                                   */
/* ------------------------------------------------------------------------ */

/* Algorithm 7: SampleNTT. B = 32-byte seed || 2 index bytes (34 bytes). */
static void sample_ntt(const uint8_t B[34], uint16_t a[N]) {
    keccak_ctx ctx;
    xof_init(&ctx);
    xof_absorb(&ctx, B, 34);
    int j = 0;
    while (j < N) {
        uint8_t C[3];
        xof_squeeze(&ctx, C, 3);
        uint16_t d1 = (uint16_t)(C[0] + 256 * (C[1] & 15));
        uint16_t d2 = (uint16_t)((C[1] >> 4) + 16 * C[2]);
        if (d1 < Q) a[j++] = d1;
        if (d2 < Q && j < N) a[j++] = d2;
    }
}

static int get_bit(const uint8_t *B, size_t i) { return (B[i >> 3] >> (i & 7)) & 1; }

/* Algorithm 8: SamplePolyCBD_eta. B has 64*eta bytes. */
static void sample_poly_cbd(int eta, const uint8_t *B, uint16_t f[N]) {
    for (int i = 0; i < N; i++) {
        int x = 0, y = 0;
        for (int j = 0; j < eta; j++) {
            x += get_bit(B, (size_t)2 * i * eta + j);
            y += get_bit(B, (size_t)2 * i * eta + eta + j);
        }
        f[i] = (uint16_t)((x - y + Q) % Q);
    }
}

/* Matrix A-hat[i][j] = SampleNTT(rho || j || i)   (note the index order, see Appendix C.2) */
static void gen_matrix(uint16_t A[MAXK][MAXK][N], const uint8_t rho[32], int k) {
    uint8_t B[34];
    memcpy(B, rho, 32);
    for (int i = 0; i < k; i++)
        for (int j = 0; j < k; j++) {
            B[32] = (uint8_t)j;
            B[33] = (uint8_t)i;
            sample_ntt(B, A[i][j]);
        }
}

/* ------------------------------------------------------------------------ */
/* Section 5: K-PKE component scheme (NOT to be used on its own!)            */
/* ------------------------------------------------------------------------ */

/* Algorithm 13: K-PKE.KeyGen(d) -> (ek_PKE [384k+32 bytes], dk_PKE [384k bytes]) */
static void kpke_keygen(const mlkem_params *p, const uint8_t d[32], uint8_t *ek, uint8_t *dk) {
    int k = p->k;
    uint8_t in[33], rho[32], sigma[32];
    uint16_t A[MAXK][MAXK][N];
    uint16_t s[MAXK][N], e[MAXK][N], t[MAXK][N], tmp[N];
    uint8_t buf[64 * 3];
    uint8_t Nctr = 0;

    memcpy(in, d, 32);
    in[32] = (uint8_t)k;                       /* domain separation by k */
    G(rho, sigma, in, 33);                     /* (rho, sigma) <- G(d || k) */

    gen_matrix(A, rho, k);

    for (int i = 0; i < k; i++) {              /* s */
        PRF(buf, p->eta1, sigma, Nctr++);
        sample_poly_cbd(p->eta1, buf, s[i]);
    }
    for (int i = 0; i < k; i++) {              /* e */
        PRF(buf, p->eta1, sigma, Nctr++);
        sample_poly_cbd(p->eta1, buf, e[i]);
    }
    for (int i = 0; i < k; i++) { mlkem_ntt(s[i]); mlkem_ntt(e[i]); }

    for (int i = 0; i < k; i++) {              /* t-hat = A-hat o s-hat + e-hat */
        memcpy(t[i], e[i], sizeof(poly));
        for (int j = 0; j < k; j++) {
            mlkem_multiply_ntts(tmp, A[i][j], s[j]);
            poly_add(t[i], t[i], tmp);
        }
    }

    for (int i = 0; i < k; i++) byte_encode(12, t[i], ek + 384 * i);
    memcpy(ek + 384 * k, rho, 32);             /* ek_PKE = ByteEncode12(t) || rho */
    for (int i = 0; i < k; i++) byte_encode(12, s[i], dk + 384 * i);

    secure_zero(in, sizeof in);  secure_zero(sigma, sizeof sigma);
    secure_zero(s, sizeof s);    secure_zero(e, sizeof e);
    secure_zero(buf, sizeof buf);
}

/* Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r) -> c [32(du*k+dv) bytes] */
static void kpke_encrypt(const mlkem_params *p, const uint8_t *ek, const uint8_t m[32],
                         const uint8_t r[32], uint8_t *c) {
    int k = p->k, du = p->du, dv = p->dv;
    uint16_t A[MAXK][MAXK][N];
    uint16_t t[MAXK][N], y[MAXK][N], e1[MAXK][N], u[MAXK][N];
    uint16_t e2[N], v[N], mu[N], tmp[N], cmp[N];
    uint8_t buf[64 * 3];
    uint8_t Nctr = 0;

    for (int i = 0; i < k; i++) byte_decode(12, ek + 384 * i, t[i]);
    const uint8_t *rho = ek + 384 * k;
    gen_matrix(A, rho, k);

    for (int i = 0; i < k; i++) {              /* y  ~ CBD_eta1 */
        PRF(buf, p->eta1, r, Nctr++);
        sample_poly_cbd(p->eta1, buf, y[i]);
    }
    for (int i = 0; i < k; i++) {              /* e1 ~ CBD_eta2 */
        PRF(buf, p->eta2, r, Nctr++);
        sample_poly_cbd(p->eta2, buf, e1[i]);
    }
    PRF(buf, p->eta2, r, Nctr);                /* e2 ~ CBD_eta2 */
    sample_poly_cbd(p->eta2, buf, e2);

    for (int i = 0; i < k; i++) mlkem_ntt(y[i]);

    for (int i = 0; i < k; i++) {              /* u = NTT^-1(A^T o y) + e1 */
        memset(u[i], 0, sizeof(poly));
        for (int j = 0; j < k; j++) {
            mlkem_multiply_ntts(tmp, A[j][i], y[j]);   /* A transposed: A[j][i] */
            poly_add(u[i], u[i], tmp);
        }
        mlkem_ntt_inv(u[i]);
        poly_add(u[i], u[i], e1[i]);
    }

    byte_decode(1, m, mu);                     /* mu = Decompress_1(ByteDecode_1(m)) */
    for (int i = 0; i < N; i++) mu[i] = decompress(1, mu[i]);

    memset(v, 0, sizeof v);                    /* v = NTT^-1(t^T o y) + e2 + mu */
    for (int j = 0; j < k; j++) {
        mlkem_multiply_ntts(tmp, t[j], y[j]);
        poly_add(v, v, tmp);
    }
    mlkem_ntt_inv(v);
    poly_add(v, v, e2);
    poly_add(v, v, mu);

    for (int i = 0; i < k; i++) {              /* c1 = ByteEncode_du(Compress_du(u)) */
        for (int x = 0; x < N; x++) cmp[x] = compress(du, u[i][x]);
        byte_encode(du, cmp, c + 32 * du * i);
    }
    for (int x = 0; x < N; x++) cmp[x] = compress(dv, v[x]);   /* c2 */
    byte_encode(dv, cmp, c + 32 * du * k);

    secure_zero(y, sizeof y);   secure_zero(e1, sizeof e1);   secure_zero(e2, sizeof e2);
    secure_zero(mu, sizeof mu); secure_zero(buf, sizeof buf);
}

/* Algorithm 15: K-PKE.Decrypt(dk_PKE, c) -> m [32 bytes] */
static void kpke_decrypt(const mlkem_params *p, const uint8_t *dk, const uint8_t *c, uint8_t m[32]) {
    int k = p->k, du = p->du, dv = p->dv;
    uint16_t u[MAXK][N], s[MAXK][N], vp[N], w[N], tmp[N];

    for (int i = 0; i < k; i++) {              /* u' */
        byte_decode(du, c + 32 * du * i, u[i]);
        for (int x = 0; x < N; x++) u[i][x] = decompress(du, u[i][x]);
    }
    byte_decode(dv, c + 32 * du * k, vp);      /* v' */
    for (int x = 0; x < N; x++) vp[x] = decompress(dv, vp[x]);

    for (int i = 0; i < k; i++) byte_decode(12, dk + 384 * i, s[i]);

    for (int i = 0; i < k; i++) mlkem_ntt(u[i]);
    memset(w, 0, sizeof w);                    /* w = v' - NTT^-1(s^T o NTT(u')) */
    for (int j = 0; j < k; j++) {
        mlkem_multiply_ntts(tmp, s[j], u[j]);
        poly_add(w, w, tmp);
    }
    mlkem_ntt_inv(w);
    poly_sub(w, vp, w);

    for (int x = 0; x < N; x++) w[x] = compress(1, w[x]);
    byte_encode(1, w, m);

    secure_zero(s, sizeof s);
    secure_zero(w, sizeof w);
}

/* ------------------------------------------------------------------------ */
/* Section 6: internal (deterministic) ML-KEM algorithms                     */
/* ------------------------------------------------------------------------ */

/* Algorithm 16 */
void mlkem_keygen_internal(const mlkem_params *p, const uint8_t d[32], const uint8_t z[32],
                           uint8_t *ek, uint8_t *dk) {
    int k = p->k;
    kpke_keygen(p, d, ek, dk);                 /* ek = ek_PKE, dk starts with dk_PKE */
    /* dk = dk_PKE || ek || H(ek) || z */
    memcpy(dk + 384 * k, ek, 384 * k + 32);
    H(dk + 768 * k + 32, ek, 384 * k + 32);
    memcpy(dk + 768 * k + 64, z, 32);
}

/* Algorithm 17 */
void mlkem_encaps_internal(const mlkem_params *p, const uint8_t *ek, const uint8_t m[32],
                           uint8_t *ct, uint8_t ss[32]) {
    uint8_t in[64], r[32];
    memcpy(in, m, 32);
    H(in + 32, ek, MLKEM_EK_BYTES(p));         /* m || H(ek) */
    G(ss, r, in, 64);                          /* (K, r) <- G(m || H(ek)) */
    kpke_encrypt(p, ek, m, r, ct);
    secure_zero(in, sizeof in);
    secure_zero(r, sizeof r);
}

/* Algorithm 18 */
void mlkem_decaps_internal(const mlkem_params *p, const uint8_t *dk, const uint8_t *ct,
                           uint8_t ss[32]) {
    int k = p->k;
    size_t ctlen = MLKEM_CT_BYTES(p);
    const uint8_t *dk_pke = dk;
    const uint8_t *ek_pke = dk + 384 * k;
    const uint8_t *h      = dk + 768 * k + 32;
    const uint8_t *z      = dk + 768 * k + 64;

    uint8_t mp[32], in[64], Kp[32], rp[32], Kbar[32];
    uint8_t zc[32 + MLKEM_MAX_CT];
    uint8_t cp[MLKEM_MAX_CT];

    kpke_decrypt(p, dk_pke, ct, mp);           /* m' */

    memcpy(in, mp, 32);
    memcpy(in + 32, h, 32);
    G(Kp, rp, in, 64);                         /* (K', r') <- G(m' || h) */

    memcpy(zc, z, 32);
    memcpy(zc + 32, ct, ctlen);
    J(Kbar, zc, 32 + ctlen);                   /* K-bar <- J(z || c) */

    kpke_encrypt(p, ek_pke, mp, rp, cp);       /* c' <- K-PKE.Encrypt(ek_PKE, m', r') */

    /* Implicit rejection, done without branching on the secret comparison result:
     * if c != c' output K-bar, else K'. */
    uint8_t diff = ct_diff(ct, cp, ctlen);
    uint8_t mask = (uint8_t)(-(int)((diff | (uint8_t)-diff) >> 7)); /* 0xFF if diff != 0 else 0x00 */
    for (int i = 0; i < 32; i++) ss[i] = (uint8_t)((Kp[i] & ~mask) | (Kbar[i] & mask));

    secure_zero(mp, sizeof mp);   secure_zero(in, sizeof in);
    secure_zero(Kp, sizeof Kp);   secure_zero(rp, sizeof rp);
    secure_zero(Kbar, sizeof Kbar);
    secure_zero(zc, sizeof zc);   secure_zero(cp, sizeof cp);
}

/* ------------------------------------------------------------------------ */
/* Section 7: main ML-KEM algorithms (with randomness and input checking)    */
/* ------------------------------------------------------------------------ */

/* Algorithm 19 */
int mlkem_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk) {
    uint8_t d[32], z[32];
    if (rand_bytes(d, 32) != 0 || rand_bytes(z, 32) != 0) return -2;
    mlkem_keygen_internal(p, d, z, ek, dk);
    secure_zero(d, sizeof d);
    secure_zero(z, sizeof z);
    return 0;
}

/* Encapsulation key check (Section 7.2): type check + modulus check */
static int check_ek(const mlkem_params *p, const uint8_t *ek, size_t ek_len) {
    if (ek_len != (size_t)MLKEM_EK_BYTES(p)) return -1;                 /* type check */
    uint16_t F[N];
    uint8_t B[384];
    for (int i = 0; i < p->k; i++) {                                    /* modulus check */
        byte_decode(12, ek + 384 * i, F);
        byte_encode(12, F, B);
        if (memcmp(B, ek + 384 * i, 384) != 0) return -1;
    }
    return 0;
}

/* Algorithm 20 */
int mlkem_encaps(const mlkem_params *p, const uint8_t *ek, size_t ek_len,
                 uint8_t *ct, uint8_t ss[32]) {
    if (check_ek(p, ek, ek_len) != 0) return -1;
    uint8_t m[32];
    if (rand_bytes(m, 32) != 0) return -2;
    mlkem_encaps_internal(p, ek, m, ct, ss);
    secure_zero(m, sizeof m);
    return 0;
}

/* Algorithm 21, with the decapsulation input check of Section 7.3 */
int mlkem_decaps(const mlkem_params *p, const uint8_t *dk, size_t dk_len,
                 const uint8_t *ct, size_t ct_len, uint8_t ss[32]) {
    int k = p->k;
    if (ct_len != (size_t)MLKEM_CT_BYTES(p)) return -1;                 /* ciphertext type check */
    if (dk_len != (size_t)MLKEM_DK_BYTES(p)) return -1;                 /* dk type check */
    uint8_t test[32];
    H(test, dk + 384 * k, 384 * k + 32);                                /* hash check */
    if (memcmp(test, dk + 768 * k + 32, 32) != 0) return -1;
    mlkem_decaps_internal(p, dk, ct, ss);
    return 0;
}
