/* demo.c - the Alice/Bob flow of Figure 1 in FIPS 203 */
#include "mlkem.h"

#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *b, size_t n, size_t show) {
    printf("%-22s (%4zu bytes) ", label, n);
    for (size_t i = 0; i < show && i < n; i++) printf("%02x", b[i]);
    if (show < n) printf("...");
    printf("\n");
}

int main(void) {
    const mlkem_params *p = &MLKEM_768;   /* NIST's recommended default */
    static uint8_t ek[MLKEM_MAX_EK], dk[MLKEM_MAX_DK], ct[MLKEM_MAX_CT];
    uint8_t K_bob[32], K_alice[32];

    printf("Parameter set: %s\n\n", p->name);

    /* Alice: KeyGen */
    if (mlkem_keygen(p, ek, dk) != 0) { fprintf(stderr, "keygen failed\n"); return 1; }
    print_hex("encapsulation key", ek, MLKEM_EK_BYTES(p), 16);
    print_hex("decapsulation key", dk, MLKEM_DK_BYTES(p), 16);

    /* Bob: Encaps using Alice's encapsulation key */
    if (mlkem_encaps(p, ek, MLKEM_EK_BYTES(p), ct, K_bob) != 0) { fprintf(stderr, "encaps failed\n"); return 1; }
    print_hex("ciphertext", ct, MLKEM_CT_BYTES(p), 16);
    print_hex("Bob's shared key K", K_bob, 32, 32);

    /* Alice: Decaps using her decapsulation key and Bob's ciphertext */
    if (mlkem_decaps(p, dk, MLKEM_DK_BYTES(p), ct, MLKEM_CT_BYTES(p), K_alice) != 0) { fprintf(stderr, "decaps failed\n"); return 1; }
    print_hex("Alice's shared key K'", K_alice, 32, 32);

    printf("\nK == K' ? %s\n", memcmp(K_bob, K_alice, 32) == 0 ? "YES" : "NO");
    return 0;
}
