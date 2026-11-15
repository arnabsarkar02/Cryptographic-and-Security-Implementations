/* test.c - self-checks for the ML-KEM implementation */
#include "keccak.h"
#include "mlkem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (cond) printf("  [ok]   %s\n", msg);                       \
        else { printf("  [FAIL] %s\n", msg); failures++; }            \
    } while (0)

static void to_hex(char *dst, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) sprintf(dst + 2 * i, "%02x", b[i]);
}

static int hex_eq(const uint8_t *b, size_t n, const char *hex) {
    char buf[300];
    to_hex(buf, b, n);
    return strcmp(buf, hex) == 0;
}

static void test_keccak(void) {
    printf("Keccak / SHA-3 known answers\n");
    uint8_t out[64];
    sha3_256(out, (const uint8_t *)"", 0);
    CHECK(hex_eq(out, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), "SHA3-256(\"\")");
    sha3_256(out, (const uint8_t *)"abc", 3);
    CHECK(hex_eq(out, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), "SHA3-256(\"abc\")");
    sha3_512(out, (const uint8_t *)"", 0);
    CHECK(hex_eq(out, 64, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                          "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"), "SHA3-512(\"\")");
    shake128(out, 32, (const uint8_t *)"", 0);
    CHECK(hex_eq(out, 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"), "SHAKE128(\"\")");
    shake256(out, 32, (const uint8_t *)"", 0);
    CHECK(hex_eq(out, 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"), "SHAKE256(\"\")");

    /* incremental squeeze must equal one-shot (multi-block, odd chunk sizes) */
    uint8_t a[500], b[500];
    shake128(a, 500, (const uint8_t *)"hello", 5);
    keccak_ctx c;
    keccak_init(&c, 168, 0x1F);
    keccak_absorb(&c, (const uint8_t *)"he", 2);
    keccak_absorb(&c, (const uint8_t *)"llo", 3);
    keccak_squeeze(&c, b, 3);
    keccak_squeeze(&c, b + 3, 200);
    keccak_squeeze(&c, b + 203, 297);
    CHECK(memcmp(a, b, 500) == 0, "SHAKE128 incremental == one-shot");
}

static void test_zetas(void) {
    printf("NTT tables (Appendix A)\n");
    const uint16_t *z = mlkem_zetas();
    static const uint16_t first8[8] = {1, 1729, 2580, 3289, 2642, 630, 1897, 848};
    CHECK(memcmp(z, first8, sizeof first8) == 0, "zeta^BitRev7(i), i=0..7 match Appendix A");
    CHECK(z[64] == 17 && z[127] == 2154 && z[8] == 1062, "spot checks z[8], z[64], z[127]");
}

static void test_ntt(void) {
    printf("NTT arithmetic\n");
    uint16_t f[256], g[256], F[256], G[256], H[256], ref[256];
    int32_t acc[256];
    srand(1);
    for (int i = 0; i < 256; i++) { f[i] = rand() % 3329; g[i] = rand() % 3329; }

    memcpy(F, f, sizeof f);
    mlkem_ntt(F);
    mlkem_ntt_inv(F);
    CHECK(memcmp(F, f, sizeof f) == 0, "NTT^-1(NTT(f)) == f");

    /* schoolbook multiplication in Z_q[X]/(X^256 + 1) */
    memset(acc, 0, sizeof acc);
    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 256; j++) {
            int idx = i + j;
            int64_t prod = (int64_t)f[i] * g[j] % 3329;
            if (idx >= 256) { idx -= 256; prod = -prod; }
            acc[idx] = (int32_t)((acc[idx] + prod) % 3329);
        }
    for (int i = 0; i < 256; i++) ref[i] = (uint16_t)((acc[i] % 3329 + 3329) % 3329);

    memcpy(F, f, sizeof f); memcpy(G, g, sizeof g);
    mlkem_ntt(F); mlkem_ntt(G);
    mlkem_multiply_ntts(H, F, G);
    mlkem_ntt_inv(H);
    CHECK(memcmp(H, ref, sizeof ref) == 0, "NTT-domain product == schoolbook product in R_q");
}

static void test_kem(const mlkem_params *p) {
    printf("%s\n", p->name);
    size_t ek_n = MLKEM_EK_BYTES(p), dk_n = MLKEM_DK_BYTES(p), ct_n = MLKEM_CT_BYTES(p);
    static uint8_t ek[MLKEM_MAX_EK], dk[MLKEM_MAX_DK], ct[MLKEM_MAX_CT];
    uint8_t K1[32], K2[32];

    int expected_ek = p->k == 2 ? 800 : p->k == 3 ? 1184 : 1568;
    int expected_dk = p->k == 2 ? 1632 : p->k == 3 ? 2400 : 3168;
    int expected_ct = p->k == 2 ? 768 : p->k == 3 ? 1088 : 1568;
    CHECK((int)ek_n == expected_ek && (int)dk_n == expected_dk && (int)ct_n == expected_ct,
          "key / ciphertext sizes match Table 3");

    int ok = 1;
    for (int iter = 0; iter < 200; iter++) {
        if (mlkem_keygen(p, ek, dk) != 0) { ok = 0; break; }
        if (mlkem_encaps(p, ek, ek_n, ct, K1) != 0) { ok = 0; break; }
        if (mlkem_decaps(p, dk, dk_n, ct, ct_n, K2) != 0) { ok = 0; break; }
        if (memcmp(K1, K2, 32) != 0) { ok = 0; break; }
    }
    CHECK(ok, "200 x (keygen, encaps, decaps): K == K'");

    /* a tampered ciphertext must give a *different* key (implicit rejection), not an error */
    mlkem_keygen(p, ek, dk);
    mlkem_encaps(p, ek, ek_n, ct, K1);
    ct[5] ^= 0x01;
    int rc = mlkem_decaps(p, dk, dk_n, ct, ct_n, K2);
    CHECK(rc == 0 && memcmp(K1, K2, 32) != 0, "tampered ciphertext -> implicit rejection (different key)");
    uint8_t K3[32];
    mlkem_decaps(p, dk, dk_n, ct, ct_n, K3);
    CHECK(memcmp(K2, K3, 32) == 0, "implicit-rejection key is deterministic");
    ct[5] ^= 0x01;

    /* input checks */
    CHECK(mlkem_encaps(p, ek, ek_n - 1, ct, K1) == -1, "wrong-length ek rejected");
    CHECK(mlkem_decaps(p, dk, dk_n, ct, ct_n - 1, K2) == -1, "wrong-length ciphertext rejected");
    uint8_t bad[MLKEM_MAX_EK];
    memcpy(bad, ek, ek_n);
    bad[0] = 0xFF; bad[1] = 0xFF;                 /* first 12-bit coeff = 4095 >= q */
    CHECK(mlkem_encaps(p, bad, ek_n, ct, K1) == -1, "ek with coefficient >= q rejected (modulus check)");
    static uint8_t baddk[MLKEM_MAX_DK];
    memcpy(baddk, dk, dk_n);
    baddk[384 * p->k + 3] ^= 1;
    CHECK(mlkem_decaps(p, baddk, dk_n, ct, ct_n, K2) == -1, "dk with corrupted embedded ek rejected (hash check)");

    /* deterministic internal functions are, well, deterministic */
    uint8_t d[32], z[32], m[32];
    memset(d, 0x11, 32); memset(z, 0x22, 32); memset(m, 0x33, 32);
    static uint8_t ekA[MLKEM_MAX_EK], dkA[MLKEM_MAX_DK], ekB[MLKEM_MAX_EK], dkB[MLKEM_MAX_DK];
    static uint8_t ctA[MLKEM_MAX_CT], ctB[MLKEM_MAX_CT];
    uint8_t KA[32], KB[32];
    mlkem_keygen_internal(p, d, z, ekA, dkA);
    mlkem_keygen_internal(p, d, z, ekB, dkB);
    mlkem_encaps_internal(p, ekA, m, ctA, KA);
    mlkem_encaps_internal(p, ekB, m, ctB, KB);
    CHECK(!memcmp(ekA, ekB, ek_n) && !memcmp(dkA, dkB, dk_n) && !memcmp(ctA, ctB, ct_n) && !memcmp(KA, KB, 32),
          "same seeds -> identical keys / ciphertext / secret");
}

int main(void) {
    test_keccak();
    test_zetas();
    test_ntt();
    test_kem(&MLKEM_512);
    test_kem(&MLKEM_768);
    test_kem(&MLKEM_1024);
    printf("\n%s (%d failure%s)\n", failures ? "SOME TESTS FAILED" : "ALL TESTS PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
