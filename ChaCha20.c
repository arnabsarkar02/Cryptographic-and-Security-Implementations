#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Include the header for x86/x64 hardware intrinsics like __rdtsc()
#if defined(_MSC_VER)
    #include <intrin.h>
#else
    #include <x86intrin.h>
#endif

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))


void quarter_round(uint32_t *state, int a, int b, int c, int d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 7);
}

void column_round(uint32_t *state) {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
}

void diagonal_round(uint32_t *state) {
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

void permute(uint32_t *state) {
	int i;
    for (i = 0; i < 10; i++) {
        column_round(state);
        diagonal_round(state);
    }
}

void increment_counter(uint32_t *state) {
    if (++state[12] == 0) {
        ++state[13];
    }
}

void chacha20_init(uint32_t *state, const uint8_t *key, const uint8_t *nonce, uint64_t counter) {
	int i;
    state[0] = 0x61707865;
    state[1] = 0x3320646E;
    state[2] = 0x79622D32;
    state[3] = 0x6B206574;

    for (i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4]) | 
                       (((uint32_t)key[i*4 + 1]) << 8) | 
                       (((uint32_t)key[i*4 + 2]) << 16) | 
                       (((uint32_t)key[i*4 + 3]) << 24);
    }

    state[12] = (uint32_t)(counter & 0xFFFFFFFF);
    state[13] = (uint32_t)(counter >> 32);

    state[14] = ((uint32_t)nonce[0]) | (((uint32_t)nonce[1]) << 8) | 
                (((uint32_t)nonce[2]) << 16) | (((uint32_t)nonce[3]) << 24);
                
    state[15] = ((uint32_t)nonce[4]) | (((uint32_t)nonce[5]) << 8) | 
                (((uint32_t)nonce[6]) << 16) | (((uint32_t)nonce[7]) << 24);
}

void chacha20_encrypt(uint32_t *initial_state, const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t state[16];
    uint8_t keystream[64];
    size_t i, j;

    for (i = 0; i < len; i += 64) {
        memcpy(state, initial_state, sizeof(state));
        permute(state);

        for (j = 0; j < 16; j++) {
            state[j] += initial_state[j];
        }

        for (j = 0; j < 16; j++) {
            keystream[j*4]     = (uint8_t)(state[j]);
            keystream[j*4 + 1] = (uint8_t)(state[j] >> 8);
            keystream[j*4 + 2] = (uint8_t)(state[j] >> 16);
            keystream[j*4 + 3] = (uint8_t)(state[j] >> 24);
        }

        size_t block_len = (len - i) < 64 ? (len - i) : 64;
        for (j = 0; j < block_len; j++) {
            out[i + j] = in[i + j] ^ keystream[j];
        }

        increment_counter(initial_state);
    }
}


int main() {
	size_t i;
    uint8_t key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    uint8_t nonce[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    
    uint32_t state[16];
    char message[1024];
    uint8_t ciphertext[1024];
    uint8_t decrypted[1024];

    printf("Type a message to encrypt: ");
    if (fgets(message, sizeof(message), stdin) == NULL) return 1;
    message[strcspn(message, "\n")] = '\0';
    size_t msg_len = strlen(message);
    if (msg_len == 0) return 0;


    chacha20_init(state, key, nonce, 1);
    chacha20_encrypt(state, (const uint8_t*)message, ciphertext, msg_len);

    unsigned long long start_cycles, end_cycles;
    
    chacha20_init(state, key, nonce, 1); // Reset state before measuring
    
    start_cycles = __rdtsc(); // Read Time-Stamp Counter before
    chacha20_encrypt(state, (const uint8_t*)message, ciphertext, msg_len);
    end_cycles = __rdtsc();   // Read Time-Stamp Counter after


    unsigned long long total_cycles = end_cycles - start_cycles;

    printf("\n--- HARDWARE PROFILING RESULTS ---\n");
    printf("Message length : %zu bytes\n", msg_len);
    printf("CPU Cycles     : %llu\n", total_cycles);
    if (msg_len > 0) {
        printf("Cycles/Byte    : %.2f\n", (double)total_cycles / msg_len);
    }

    printf("\n--- VERIFYING OUTPUT ---\n");
    printf("Ciphertext (HEX): ");
    for (i = 0; i < msg_len; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    chacha20_init(state, key, nonce, 1);
    chacha20_encrypt(state, ciphertext, decrypted, msg_len);
    decrypted[msg_len] = '\0';
    
    printf("Decrypted Msg   : %s\n", decrypted);

    return 0;
}
