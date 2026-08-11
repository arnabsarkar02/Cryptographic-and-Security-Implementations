#include <stdio.h>
#include <string.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

// Define the RC4 state structure
typedef struct {
    unsigned char S[256];
    unsigned char i;
    unsigned char j;
} rc4_state;

// Safe swap macro
#define SWAP(a, b) do { unsigned char temp = (a); (a) = (b); (b) = temp; } while(0)

// Algorithm 1: RC4 Key Scheduling Algorithm (KSA)
void rc4_ksa(rc4_state *state, const unsigned char *key, int key_len) {
    int i;
    int j = 0; 

    for (i = 0; i < 256; i++) {
        state->S[i] = (unsigned char)i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + state->S[i] + key[i % key_len]) % 256;
        SWAP(state->S[i], state->S[j]);
    }

    state->i = 0;
    state->j = 0;
}

// Algorithm 2: Pure PRGA Function
// This solely updates the internal state and returns a single keystream byte.
unsigned char rc4_prga_byte(rc4_state *state) {
    state->i = (state->i + 1) % 256;
    state->j = (state->j + state->S[state->i]) % 256;
    
    SWAP(state->S[state->i], state->S[state->j]);
    
    return state->S[(state->S[state->i] + state->S[state->j]) % 256];
}

// Encryption/Decryption Function
// Fetches the keystream bytes from the PRGA and XORs them with the input data.
void rc4_encrypt(rc4_state *state, unsigned char *data, int data_len) {
	int k;
    for (k = 0; k < data_len; k++) {
        unsigned char keystream_byte = rc4_prga_byte(state);
        data[k] ^= keystream_byte;
    }
}

int main() {
    unsigned char key[257] = "secret_key_for_testing";
    unsigned char data[8192]; 
    memset(data, 'A', sizeof(data)); // Fill with dummy data
    int data_len = sizeof(data);
    
    rc4_state state;
    uint64_t start, end;
    uint64_t ksa_total_cycles, prga_total_cycles;
    
    int iterations = 10000;
    int key_len = strlen((char *)key);
	int iter;
	
    // --- 1. Measure KSA (10,000 times) ---
    start = __rdtsc();
    for (iter = 0; iter < iterations; iter++) {
        rc4_ksa(&state, key, key_len);
    }
    end = __rdtsc();
    
    ksa_total_cycles = end - start;
    uint64_t ksa_avg_cycles = ksa_total_cycles / iterations;
    
    // --- 2. Measure PRGA (10,000 times) ---
    // Re-initialize state once before testing PRGA to ensure valid state
    rc4_ksa(&state, key, key_len);

    start = __rdtsc();
    for (iter = 0; iter < iterations; iter++) {
        rc4_encrypt(&state, data, data_len);
    }
    end = __rdtsc();
    
    prga_total_cycles = end - start;
    
    // --- 3. Calculate and Report ---
    // Total bytes processed = bytes per iteration * number of iterations
    uint64_t total_bytes_processed = (uint64_t)data_len * iterations;
    double prga_cycles_per_byte = (double)prga_total_cycles / total_bytes_processed;

    printf("========================================\n");
    printf("Performance Measurements (%d Iterations)\n", iterations);
    printf("========================================\n");
    printf("Data Size Encrypted per run: %d bytes\n", data_len);
    printf("Total Bytes Encrypted:       %llu bytes\n", (unsigned long long)total_bytes_processed);
    printf("Average KSA Cycles:          %llu cycles\n", (unsigned long long)ksa_avg_cycles);
    
    printf("PRGA Cycles per Byte:        %.2f cycles/byte\n", prga_cycles_per_byte);
    printf("========================================\n");

    return 0;
}
