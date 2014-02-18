#include <string.h>
#include <avr/io.h>
//#ifndef __arm__
#include <avr/pgmspace.h>
/*#else
#define PROGMEM // empty
#define pgm_read_byte(x) (*(x))
#define pgm_read_word(x) (*(x))
#define pgm_read_float(x) (*(x))
#define PSTR(x) x
#endif*/
#include "./sha256.h"

//Initialize array of round constants:
//(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
uint32_t sha256_k[BLOCK_LENGTH] PROGMEM = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//Initialize hash values:
//(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
uint32_t sha_init_state[8] PROGMEM = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*
Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w_array[i], 0 ≤ i ≤ 63
Note 3: The compression function uses 8 working variables, a through h
Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    and when parsing message block data from bytes to words, for example,
    the first word of the input message "abc" after padding is 0x61626380
*/

uint32_t sha256 (uint32_t* message, uint32_t* result) {
    uint32_t bits = sizeof(message);
    segments = bits / sizeof(message[0]);
    //Pre-processing:
    //append the bit '1' to the message///////////////////////////////////////////////////////////

    if(bits > 448){
        //length (modulo 512 in bits) is 448.
        uint32_t sub_segment = segments-14;
        uint32_t sub_result[sub_segment]; 
        uint32_t sub_message[sub_segment]; 

        for(i=0; i<sub_segment; i++){
            sub_message[i] = message[i+14];
        }
        uint32_t result_size = sha256(&sub_message, &sub_result); //Process the message in successive 512-bit chunks:

        //process subresult
        for(i=0; i<sub_segment; i++){
            result[i+16] = sub_result[i];
        }
    }

    uint32_t w_array[BLOCK_LENGTH];
    uint32_t temp_array[8];
    //append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    w_array[15] = bits;

    //copy chunk into first 16 words w_array[0..15] of the message schedule array
    for(i=0; i<(MID_HASH-2); i++){
        w_array[i] = message[i];
    }

    //Extend the first 16 words into the remaining 48 words w_array[16..63] of the message schedule array:
    for(i=MID_HASH; i<BLOCK_LENGTH; i++){
        s0 = ror32(w_array[i-15], 7) ^ ror32(w_array[i-15], 18) ^ (w_array[i-15]>>3);
        s1 = ror32(w_array[i-2], 17) ^ ror32(w_array[i-2], 19) ^ (w_array[i-2]>>10);
        w_array[i] = w_array[i-16] + s0 + w_array[i-7] + s1;
    }

    //Initialize working variables to current hash value
    for(i=0; i<8; i++){
        temp_array[i] = sha_init_state[i];
    }

    //Compression function main loop:
    for(i=0; i<BLOCK_LENGTH; i++){
        S1 = ror32(temp_array[4], 6) ^ ror32(temp_array[4], 11) ^ ror32(temp_array[4], 25);
        ch = (temp_array[4] & temp_array[5]) ^ ((not temp_array[4]) & temp_array[6]);
        temp1 = temp_array[7] + S1 + ch + sha256_k[i] + w_array[i];
        S0 = ror32(temp_array[0], 2) ^ ror32(temp_array[0], 13) ^ ror32(temp_array[0], 22);

        maj = (temp_array[0] & temp_array[1]) ^ (temp_array[0] & temp_array[2]) ^ (temp_array[1] & temp_array[2]);
     
        temp_array[7] = temp_array[6];
        temp_array[6] = temp_array[5];
        temp_array[5] = temp_array[4];
        temp_array[4] = temp_array[3] + temp1;
        temp_array[3] = temp_array[2];
        temp_array[2] = temp_array[1];
        temp_array[1] = temp_array[0];
        temp_array[0] = temp1 + S0 + maj;
    }

    //Add the compressed chunk to the current hash value:
    for(i=0; i<8; i++){
        sha_init_state[i] += temp_array[i];
    }

    //produce the final hash array returned as a pointer
    for(i=0; i<8; i++){
        result[i] = sha_init_state[i];
    }
    return sizeof(result);
}

uint8_t* hmac256 (const uint8_t* key, uint8_t message) {
    uint16_t i;
    uint16_t opad = [0x5c * BLOCK_LENGTH]; // Where BLOCK_LENGTH is that of the underlying hash function
    uint16_t ipad = [0x36 * BLOCK_LENGTH];

    if(length(key) > BLOCK_LENGTH){
        key = sha256(key); // Where 'hash' is the underlying hash function
    }

    for(i=0; i<length(key); i++){
        ipad[i] = ipad[i] ^ key[i];
        opad[i] = opad[i] ^ key[i];
    }

    return sha256(opad || sha256(ipad || message)); // Where || is concatenation
} 