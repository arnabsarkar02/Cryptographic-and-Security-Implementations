#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // For uint64_t

//header for the __rdtsc() intrinsic based on the compiler
#ifdef _WIN32
    #include <intrin.h>
#else
    #include <x86intrin.h>
#endif

#define Nb 4  //The number of columns comprising a state in AES.

int Nr = 0;  //Initialize the number of rounds
int Nk = 0;  //Initialize th number of 32-bit words in the key
unsigned char in[16], out[16], state[4][4];
// in - it is the array that holds the CipherText to be decrypted.
// out - it is the array that holds the output of the for decryption.
// state - the array that holds the intermediate results during decryption.

unsigned char RoundKey[240]; // The array that stores the round keys.

// The Key input to the AES Program
unsigned char Key[32];

const unsigned char rsbox[256] = { 
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
  , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
  , 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
  , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
  , 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
  , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
  , 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
  , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
  , 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
  , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
  , 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
  , 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
  , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
  , 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
  , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
  , 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

unsigned char getSBoxInvert(unsigned char num)
{
    return rsbox[num];
}

const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

unsigned char getSBoxValue(unsigned char num)
{
    return sbox[num];
}

const unsigned char Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb 
};
// This function produces Nb(Nr+1) round keys. 
void KeyExpansion()
{
    int i, j;
    unsigned char temp[4], k;
    
    // The first round key is the key itself.
    for (i = 0; i < Nk; i++)
    {    
        RoundKey[i * 4] = Key[i * 4];
        RoundKey[i * 4 + 1] = Key[i * 4 + 1];
        RoundKey[i * 4 + 2] = Key[i * 4 + 2];
        RoundKey[i * 4 + 3] = Key[i * 4 + 3];
    }
    
    // All other round keys are found from the previous round keys.
    while (i < (Nb * (Nr + 1)))
    {
        for (j = 0; j < 4; j++)
        {
            temp[j] = RoundKey[(i - 1) * 4 + j];
        }
        
        if (i % Nk == 0)
        {
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            
            // Function Subword() logic
            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);
            temp[0] = temp[0] ^ Rcon[i / Nk];
        }
        else if (Nk > 6 && (i % Nk == 4))
        {
            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);
        }
        
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
        i++;
    }
}

// This function adds the round key to state.
void AddRoundKey(int round)
{
    int i;
    unsigned char *rk = &RoundKey[round * 16];
    for (i = 0; i < 4; i++)
    {
        state[0][i] ^= rk[i * 4 + 0];
        state[1][i] ^= rk[i * 4 + 1];
        state[2][i] ^= rk[i * 4 + 2];
        state[3][i] ^= rk[i * 4 + 3];
    }
}

//Forward SubBytes for Encryption
void SubBytes()
{
    int i;
    for (i = 0; i < 4; i++)
    {
        state[0][i] = sbox[state[0][i]];
        state[1][i] = sbox[state[1][i]];
        state[2][i] = sbox[state[2][i]];
        state[3][i] = sbox[state[3][i]];
    }
}

void InvSubBytes()
{
    int i;
    for (i = 0; i < 4; i++)
    {
        state[0][i] = rsbox[state[0][i]];
        state[1][i] = rsbox[state[1][i]];
        state[2][i] = rsbox[state[2][i]];
        state[3][i] = rsbox[state[3][i]];
    }
}
//Forward ShiftRows for Encryption (Shifts Left instead of Right)
void ShiftRows()
{
    unsigned char temp;
    // Rotate first row 1 columns to left
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    
    // Rotate second row 2 columns to left
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    // Rotate third row 3 columns to left
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

// The ShiftRows() function shifts the rows in the state to the left.
void InvShiftRows()
{
    unsigned char temp;
    // Rotate first row 1 columns to right
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    
    // Rotate second row 2 columns to right
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    // Rotate third row 3 columns to right
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

static inline unsigned char xtime(unsigned char x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static inline unsigned char Multiply(unsigned char x, unsigned char y) {
    unsigned char result = 0;
    unsigned char temp = x;
    while (y) {
        if (y & 1) result ^= temp;
        temp = xtime(temp);
        y >>= 1;
    }
    return result;
}
//Forward MixColumns for Encryption (Multiplies by 0x02 and 0x03)
void MixColumns()
{
    int i;
    unsigned char t, tm, tmp;
    for (i = 0; i < 4; i++)
    {
        // Calculate the XOR sum of the column
        t = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        
        // Save the original first byte before it is overwritten
        tmp = state[0][i];
        
        // Apply the optimized shifting logic
        tm = state[0][i] ^ state[1][i]; tm = xtime(tm); state[0][i] ^= tm ^ t;
        tm = state[1][i] ^ state[2][i]; tm = xtime(tm); state[1][i] ^= tm ^ t;
        tm = state[2][i] ^ state[3][i]; tm = xtime(tm); state[2][i] ^= tm ^ t;
        tm = state[3][i] ^ tmp;         tm = xtime(tm); state[3][i] ^= tm ^ t;
    }
}

//
void InvMixColumns()
{
    int i;
    unsigned char a, b, c, d;
    unsigned char u, v;
    
    for (i = 0; i < 4; i++)
    {
        a = state[0][i];
        b = state[1][i];
        c = state[2][i];
        d = state[3][i];
        
        // for Inverse MixCol
        u = xtime(xtime(a ^ c));
        v = xtime(xtime(b ^ d));
        
        a ^= u;
        b ^= v;
        c ^= u;
        d ^= v;
        
        // Forward MixColumns logic applied to the pre-processed bytes
        unsigned char t = a ^ b ^ c ^ d;
        unsigned char tmp = a;
        unsigned char tm;
        
        tm = a ^ b; tm = xtime(tm); state[0][i] = a ^ tm ^ t;
        tm = b ^ c; tm = xtime(tm); state[1][i] = b ^ tm ^ t;
        tm = c ^ d; tm = xtime(tm); state[2][i] = c ^ tm ^ t;
        tm = d ^ tmp; tm = xtime(tm); state[3][i] = d ^ tm ^ t;
    }
}
//Forward Cipher Function for Encryption
void Cipher()
{
    int i, j, round = 0;
    
    // Copy the input PlainText to state array.
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[j][i] = in[i * 4 + j];
        }
    }
    
    // Initial Round Key Addition
    AddRoundKey(0);
    
    // Forward Rounds (1 to Nr-1)
    for (round = 1; round < Nr; round++)
    {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }
    
    // Final Round (No MixColumns)
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
    
    // Copy the state array to output array (CipherText).
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            out[i * 4 + j] = state[j][i];
        }
    }
}


// InvCipher is the main function that decrypts the CipherText.
void InvCipher()
{
    int i, j, round = 0;
    
    // Copy the input CipherText to state array.
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[j][i] = in[i * 4 + j];
        }
    }
    
    // Add the First round key to the state before starting the rounds.
    AddRoundKey(Nr);
    
    // There will be Nr rounds.
    for (round = Nr - 1; round > 0; round--)
    {
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(round);
        InvMixColumns();
    }
    
    // The last round is given below.
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);
    
    // Copy the state array to output array.
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            out[i * 4 + j] = state[j][i];
        }
    }
}


int main()
{
    int i;
    // Variables for cycle counting
    uint64_t start_cycles, end_cycles, total_encrypt_cycles, total_decrypt_cycles;
    double avg_encrypt_cycles, avg_decrypt_cycles;
    double encrypt_cpb, decrypt_cpb;
    
    //Define the number of iterations for the benchmark
    const int NUM_ITERATIONS = 10000;
    int iter;
    
    //For AES-256
    Nr = 256;      // Represents bit size initially
    Nk = Nr / 32;  // Nk = 8 (Number of 32-bit words in a 256-bit key)
    Nr = Nk + 6;   // Nr = 14 (Number of rounds for AES-256)
    
    //NIST AES-256 Test Vector Key (32 Bytes / 256 bits)
    unsigned char myKey[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    
    //NIST Test Vector Plaintext (16 Bytes / 128 bits block)
    unsigned char myPlainText[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    printf("\n--- INPUT ---\n");
    printf("AES-256 Key:\n");
    for (i = 0; i < Nk * 4; i++) // Nk * 4 = 32 bytes
    {
        Key[i] = myKey[i];
        printf("%02x ", Key[i]);
    }
    
    printf("\n\nPlainText:\n");
    for (i = 0; i < Nb * 4; i++) // Nb * 4 = 16 bytes
    {
        in[i] = myPlainText[i];
        printf("%02x ", in[i]);
    }
    printf("\n");
    
    // Expand the 256-bit Key to generate 14 round keys
    KeyExpansion();
    
    // --- MEASURE ENCRYPTION CYCLES (10,000 Iterations) ---
    start_cycles = __rdtsc(); // Start counter
    for (iter = 0; iter < NUM_ITERATIONS; iter++) 
    {
        Cipher();
    }
    end_cycles = __rdtsc();   // Stop counter
    // Calculate average
    total_encrypt_cycles = end_cycles - start_cycles;
    avg_encrypt_cycles = (double)total_encrypt_cycles / NUM_ITERATIONS;
    encrypt_cpb = avg_encrypt_cycles / 16.0;
    
    printf("\n--- ENCRYPTION RESULT ---\n");
    printf("CipherText:\n");
    for (i = 0; i < Nb * 4; i++)
    {
        printf("%02x ", out[i]);
    }
    printf("\nAverage Encryption CPU Cycles (over %d runs): %.2f\n", NUM_ITERATIONS, avg_encrypt_cycles);
    printf("Encryption Cycles Per Byte (CPB): %.2f\n", encrypt_cpb);
    
    // To test decryption immediately after, copy the generated CipherText (out) back into 'in'
    for (i = 0; i < 16; i++) 
    {
        in[i] = out[i];
    }
    
    // Run the Inverse Cipher to decrypt the CipherText back to PlainText
    // --- MEASURE DECRYPTION CYCLES (10,000 Iterations) ---
    start_cycles = __rdtsc(); // Start counter
    for (iter = 0; iter < NUM_ITERATIONS; iter++) 
    {
        InvCipher();
    }
    end_cycles = __rdtsc();   // Stop counter
    
    // Calculate average
    total_decrypt_cycles = end_cycles - start_cycles;
    avg_decrypt_cycles = (double)total_decrypt_cycles / NUM_ITERATIONS;
    decrypt_cpb = avg_decrypt_cycles / 16.0;
    
    printf("\n--- DECRYPTION RESULT ---\n");
    printf("Decrypted PlainText:\n");
    for (i = 0; i < Nb * 4; i++)
    {
        printf("%02x ", out[i]);
    }
    printf("\nAverage Decryption CPU Cycles (over %d runs): %.2f\n\n", NUM_ITERATIONS, avg_decrypt_cycles);
    printf("Decryption Cycles Per Byte (CPB): %.2f\n\n", decrypt_cpb);
    return 0;
}
