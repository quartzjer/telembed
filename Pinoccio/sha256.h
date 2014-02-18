#ifndef Sha256_h
#define Sha256_h

#include <inttypes.h>

#define MID_HASH 16
#define HASH_LENGTH 32
#define BLOCK_LENGTH 64
#define BUFFER_SIZE 64

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

#define ror32(number, bits) ((number << (32-bits)) | (number >> bits))

uint32_t sha256 (uint32_t* message, uint32_t* result);
uint8_t* hmac256 (const uint8_t* key, int key_length);

#endif


