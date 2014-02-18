#include "ecc.h"

#include <string.h>

#define restrict __restrict__

typedef struct EccPoint
{
    uint8_t x[ECC_BYTES];
    uint8_t y[ECC_BYTES];
} EccPoint;

#define MAX_TRIES 16

#define Curve_P_1 {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF}
#define Curve_P_2 {0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_P_3 {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_P_4 {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}

#define Curve_B_1 {0xD3, 0x5E, 0xEE, 0x2C, 0x3C, 0x99, 0x24, 0xD8, \
                   0x3D, 0xF4, 0x79, 0x10, 0xC1, 0x79, 0x75, 0xE8}
#define Curve_B_2 {0x45, 0xFA, 0x65, 0xC5, 0xAD, 0xD4, 0xD4, 0x81, \
                   0x9F, 0xF8, 0xAC, 0x65, 0x8B, 0x7A, 0xBD, 0x54, \
                   0xFC, 0xBE, 0x97, 0x1C}
#define Curve_B_3 {0xB1, 0xB9, 0x46, 0xC1, 0xEC, 0xDE, 0xB8, 0xFE, \
                   0x49, 0x30, 0x24, 0x72, 0xAB, 0xE9, 0xA7, 0x0F, \
                   0xE7, 0x80, 0x9C, 0xE5, 0x19, 0x05, 0x21, 0x64}
#define Curve_B_4 {0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B, \
                   0xF6, 0xB0, 0x53, 0xCC, 0xB0, 0x06, 0x1D, 0x65, \
                   0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD, 0xEB, 0xB3, \
                   0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A}

#define Curve_G_1 { \
    {0x86, 0x5B, 0x2C, 0xA5, 0x7C, 0x60, 0x28, 0x0C, \
        0x2D, 0x9B, 0x89, 0x8B, 0x52, 0xF7, 0x1F, 0x16}, \
    {0x83, 0x7A, 0xED, 0xDD, 0x92, 0xA2, 0x2D, 0xC0, \
        0x13, 0xEB, 0xAF, 0x5B, 0x39, 0xC8, 0x5A, 0xCF}}

#define Curve_G_2 { \
    {0x82, 0xFC, 0xCB, 0x13, 0xB9, 0x8B, 0xC3, 0x68, \
        0x89, 0x69, 0x64, 0x46, 0x28, 0x73, 0xF5, 0x8E, \
        0x68, 0xB5, 0x96, 0x4A}, \
    {0x32, 0xFB, 0xC5, 0x7A, 0x37, 0x51, 0x23, 0x04, \
        0x12, 0xC9, 0xDC, 0x59, 0x7D, 0x94, 0x68, 0x31, \
        0x55, 0x28, 0xA6, 0x23}}

#define Curve_G_3 { \
    {0x12, 0x10, 0xFF, 0x82, 0xFD, 0x0A, 0xFF, 0xF4, \
        0x00, 0x88, 0xA1, 0x43, 0xEB, 0x20, 0xBF, 0x7C, \
        0xF6, 0x90, 0x30, 0xB0, 0x0E, 0xA8, 0x8D, 0x18}, \
    {0x11, 0x48, 0x79, 0x1E, 0xA1, 0x77, 0xF9, 0x73, \
        0xD5, 0xCD, 0x24, 0x6B, 0xED, 0x11, 0x10, 0x63, \
        0x78, 0xDA, 0xC8, 0xFF, 0x95, 0x2B, 0x19, 0x07}}

#define Curve_G_4 { \
    {0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4, \
        0xA0, 0x33, 0xEB, 0x2D, 0x81, 0x7D, 0x03, 0x77, \
        0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8, \
        0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B}, \
    {0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB, \
        0xCE, 0x5E, 0x31, 0x6B, 0x57, 0x33, 0xCE, 0x2B, \
        0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E, \
        0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F}}

#define Curve_N_1 {0x15, 0xA1, 0x38, 0x90, 0x1B, 0x0D, 0xA3, 0x75, \
                   0x00, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF}
#define Curve_N_2 {0x57, 0x22, 0x75, 0xCA, 0xD3, 0xAE, 0x27, 0xF9, \
                   0xC8, 0xF4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00} /* 01 */
#define Curve_N_3 {0x31, 0x28, 0xD2, 0xB4, 0xB1, 0xC9, 0x6B, 0x14, \
                   0x36, 0xF8, 0xDE, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_N_4 {0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3, \
                   0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}

static uint8_t curve_p[ECC_BYTES] = ECC_CONCAT(Curve_P_, ECC_CURVE);
static uint8_t curve_b[ECC_BYTES] = ECC_CONCAT(Curve_B_, ECC_CURVE);
static EccPoint curve_G = ECC_CONCAT(Curve_G_, ECC_CURVE);
static uint8_t curve_n[ECC_BYTES] = ECC_CONCAT(Curve_N_, ECC_CURVE);

static int fake_RNG(uint8_t *p_dest, unsigned p_size)
{
    return 0;
}

static int test_RNG(uint8_t *p_dest, unsigned p_size)
{
    static uint64_t l_rand = 88172645463325252ull;
    
    while(p_size)
    {
        l_rand ^= (l_rand << 13);
        l_rand ^= (l_rand >> 7);
        l_rand ^= (l_rand << 17);
        
        uint8_t l_cpy = (p_size >= 8 ? 8 : p_size);
        memcpy(p_dest, &l_rand, l_cpy);
        p_dest += l_cpy;
        p_size -= l_cpy;
    }
    
    return 1;
}

static RNG_Function g_rng = &test_RNG;

void ecc_set_rng(RNG_Function p_rng)
{
    g_rng = p_rng;
}

static void vli_clear(uint8_t *p_vli)
{
    uint8_t i;
    for(i=0; i<ECC_BYTES; ++i)
    {
        p_vli[i] = 0;
    }
}

/* Returns 1 if p_vli == 0, 0 otherwise. */
static uint8_t vli_isZero(const uint8_t *p_vli)
{
    uint8_t i;
    for(i = 0; i < ECC_BYTES; ++i)
    {
        if(p_vli[i])
        {
            return 0;
        }
    }
    return 1;
}

/* Returns nonzero if bit p_bit of p_vli is set. */
static uint8_t vli_testBit(const uint8_t *p_vli, uint16_t p_bit)
{
    return (p_vli[p_bit/8] & ((uint8_t)1 << (p_bit % 8)));
}

/* Counts the number of 8-bit "digits" in p_vli. */
static uint8_t vli_numDigits(const uint8_t *p_vli)
{
    int8_t i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for(i = ECC_BYTES - 1; i >= 0 && p_vli[i] == 0; --i)
    {
    }

    return (i + 1);
}

/* Counts the number of bits required for p_vli. */
static int16_t vli_numBits(const uint8_t *p_vli)
{
    uint8_t i;
    uint8_t l_digit;
    
    uint8_t l_numDigits = vli_numDigits(p_vli);
    if(l_numDigits == 0)
    {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for(i=0; l_digit; ++i)
    {
        l_digit >>= 1;
    }
    
    return ((int16_t)(l_numDigits - 1) * 8 + i);
}

/* Sets p_dest = p_src. */
static void vli_set(uint8_t *p_dest, const uint8_t *p_src)
{
    uint8_t i;
    for(i=0; i<ECC_BYTES; ++i)
    {
        p_dest[i] = p_src[i];
    }
}

/* Returns sign of p_left - p_right. */
static int8_t vli_cmp(uint8_t *p_left, uint8_t *p_right)
{
    int8_t i;
    for(i = ECC_BYTES-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

/* Computes p_result = p_in << c, returning carry. Can modify in place (if p_result == p_in). 0 < p_shift < 8. */
static uint8_t vli_lshift(uint8_t *p_result, uint8_t *p_in, uint8_t p_shift)
{
    uint8_t l_carry = 0;
    uint8_t i;
    for(i = 0; i < ECC_BYTES; ++i)
    {
        uint8_t l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (8 - p_shift);
    }
    
    return l_carry;
}

/* Computes p_vli = p_vli >> 1. */
static void vli_rshift1(uint8_t *p_vli)
{
    uint8_t *l_end = p_vli;
    uint8_t l_carry = 0;
    
    p_vli += ECC_BYTES;
    while(p_vli-- > l_end)
    {
        uint8_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << 7;
    }
}

#define DEC_1 0
#define DEC_2 1
#define DEC_3 2
#define DEC_4 3
#define DEC_5 4
#define DEC_6 5
#define DEC_7 6
#define DEC_8 7
#define DEC_9 8
#define DEC_10 9
#define DEC_11 10
#define DEC_12 11
#define DEC_13 12
#define DEC_14 13
#define DEC_15 14
#define DEC_16 15
#define DEC_17 16
#define DEC_18 17
#define DEC_19 18
#define DEC_20 19
#define DEC_21 20
#define DEC_22 21
#define DEC_23 22
#define DEC_24 23
#define DEC_25 24
#define DEC_26 25
#define DEC_27 26
#define DEC_28 27
#define DEC_29 28
#define DEC_30 29
#define DEC_31 30
#define DEC_32 31

#define DEC(N) ECC_CONCAT(DEC_, N)

#define REPEAT_1(stuff) stuff
#define REPEAT_2(stuff) REPEAT_1(stuff) stuff
#define REPEAT_3(stuff) REPEAT_2(stuff) stuff
#define REPEAT_4(stuff) REPEAT_3(stuff) stuff
#define REPEAT_5(stuff) REPEAT_4(stuff) stuff
#define REPEAT_6(stuff) REPEAT_5(stuff) stuff
#define REPEAT_7(stuff) REPEAT_6(stuff) stuff
#define REPEAT_8(stuff) REPEAT_7(stuff) stuff
#define REPEAT_9(stuff) REPEAT_8(stuff) stuff
#define REPEAT_10(stuff) REPEAT_9(stuff) stuff
#define REPEAT_11(stuff) REPEAT_10(stuff) stuff
#define REPEAT_12(stuff) REPEAT_11(stuff) stuff
#define REPEAT_13(stuff) REPEAT_12(stuff) stuff
#define REPEAT_14(stuff) REPEAT_13(stuff) stuff
#define REPEAT_15(stuff) REPEAT_14(stuff) stuff
#define REPEAT_16(stuff) REPEAT_15(stuff) stuff
#define REPEAT_17(stuff) REPEAT_16(stuff) stuff
#define REPEAT_18(stuff) REPEAT_17(stuff) stuff
#define REPEAT_19(stuff) REPEAT_18(stuff) stuff
#define REPEAT_20(stuff) REPEAT_19(stuff) stuff
#define REPEAT_21(stuff) REPEAT_20(stuff) stuff
#define REPEAT_22(stuff) REPEAT_21(stuff) stuff
#define REPEAT_23(stuff) REPEAT_22(stuff) stuff
#define REPEAT_24(stuff) REPEAT_23(stuff) stuff
#define REPEAT_25(stuff) REPEAT_24(stuff) stuff
#define REPEAT_26(stuff) REPEAT_25(stuff) stuff
#define REPEAT_27(stuff) REPEAT_26(stuff) stuff
#define REPEAT_28(stuff) REPEAT_27(stuff) stuff
#define REPEAT_29(stuff) REPEAT_28(stuff) stuff
#define REPEAT_30(stuff) REPEAT_29(stuff) stuff
#define REPEAT_31(stuff) REPEAT_30(stuff) stuff
#define REPEAT_32(stuff) REPEAT_31(stuff) stuff

#define REPEAT(N, stuff) ECC_CONCAT(REPEAT_, N)(stuff)

/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
static uint8_t vli_add(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
#if (ECC_ASM == ecc_asm_avr)
    uint8_t l_carry = 0; /* carry = 0 initially */
    uint8_t l_left;
    uint8_t l_right;

    asm volatile (
        "ld %[left], x+ \n\t"  /* Load left word. */
        "ld %[right], y+ \n\t" /* Load right word. */
        "add %[left], %[right] \n\t" /* Add the first word. */
        "st z+, %[left] \n\t"  /* Store the first result word. */
        
        /* Now we just do the remaining words with the carry bit (using ADC) */
        REPEAT(DEC(ECC_BYTES), "ld %[left], x+ \n\t"
            "ld %[right], y+ \n\t"
            "adc %[left], %[right] \n\t"
            "st z+, %[left] \n\t")
        
        "adc %[carry], %[carry] \n\t"    /* Store carry bit in l_carry. */

        : "+z" (p_result), "+x" (p_left), "+y" (p_right), [carry] "+r" (l_carry), [left] "=r" (l_left), [right] "=r" (l_right)
        :
        : "cc", "memory"
    );
    return l_carry;
#else
    uint8_t l_carry = 0;
    uint8_t i;
    for(i=0; i<ECC_BYTES; ++i)
    {
        uint16_t l_sum = (uint16_t)p_left[i] + p_right[i] + l_carry;
        p_result[i] = (uint8_t)l_sum;
        l_carry = l_sum >> 8;
    }
    return l_carry;
#endif
}

/* Computes p_result = p_left - p_right, returning borrow. Can modify in place. */
static uint8_t vli_sub(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
#if (ECC_ASM == ecc_asm_avr)
    uint8_t l_borrow = 0; /* borrow = 0 initially */
    uint8_t l_left;
    uint8_t l_right;

    asm volatile (
        "ld %[left], x+ \n\t"  /* Load left word. */
        "ld %[right], y+ \n\t" /* Load right word. */
        "sub %[left], %[right] \n\t" /* Subtract the first word. */
        "st z+, %[left] \n\t"  /* Store the first result word. */
        
        /* Now we just do the remaining words with the carry bit (using SBC) */
        REPEAT(DEC(ECC_BYTES), "ld %[left], x+ \n\t"
        "ld %[right], y+ \n\t"
        "sbc %[left], %[right] \n\t"
        "st z+, %[left] \n\t")
        
        "adc %[borrow], %[borrow] \n\t"    /* Store carry bit in l_carry. */

        : "+z" (p_result), "+x" (p_left), "+y" (p_right), [borrow] "+r" (l_borrow), [left] "=r" (l_left), [right] "=r" (l_right)
        :
        : "cc", "memory"
    );
    return l_borrow;
#else
    uint8_t l_borrow = 0;
    uint8_t i;
    for(i=0; i<ECC_BYTES; ++i)
    {
        uint16_t l_diff = (uint16_t)p_left[i] - p_right[i] - l_borrow;
        p_result[i] = (uint8_t)l_diff;
        l_borrow = (l_diff >> 8) & 0x01;
    }
    return l_borrow;
#endif
}

static void vli_mult(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
    uint16_t r01 = 0;
    uint8_t r2 = 0;
    
    uint8_t i, k;
    
    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < ECC_BYTES*2 - 1; ++k)
    {
        uint8_t l_min = (k < ECC_BYTES ? 0 : (k + 1) - ECC_BYTES);
        for(i=l_min; i<=k && i<ECC_BYTES; ++i)
        {
            uint16_t l_product = (uint16_t)p_left[i] * p_right[k-i];
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint8_t)r01;
        r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
        r2 = 0;
    }
    
    p_result[ECC_BYTES*2 - 1] = (uint8_t)r01;
}

#if ECC_SQUARE_FUNC

static void vli_square(uint8_t *p_result, uint8_t *p_left)
{
    uint16_t r01 = 0;
    uint8_t r2 = 0;
    
    uint8_t i, k;
    for(k=0; k < ECC_BYTES*2 - 1; ++k)
    {
        uint8_t l_min = (k < ECC_BYTES ? 0 : (k + 1) - ECC_BYTES);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint16_t l_product = (uint16_t)p_left[i] * p_left[k-i];
            if(i < k-i)
            {
                r2 += l_product >> 15;
                l_product *= 2;
            }
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint8_t)r01;
        r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
        r2 = 0;
    }
    
    p_result[ECC_BYTES*2 - 1] = (uint8_t)r01;
}

#else /* ECC_SQUARE_FUNC */

#define vli_square(result, left, size) vli_mult((result), (left), (left), (size))
    
#endif /* ECC_SQUARE_FUNC */


/* Computes p_result = (p_left + p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modAdd(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
{
    uint8_t l_carry = vli_add(p_result, p_left, p_right);
    if(l_carry || vli_cmp(p_result, p_mod) >= 0)
    { /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        vli_sub(p_result, p_result, p_mod);
    }
}

/* Computes p_result = (p_left - p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modSub(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
{
    uint8_t l_borrow = vli_sub(p_result, p_left, p_right);
    if(l_borrow)
    { /* In this case, p_result == -diff == (max int) - diff.
         Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
        vli_add(p_result, p_result, p_mod);
    }
}

#if ECC_CURVE == secp128r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint8_t * restrict p_result, uint8_t *restrict p_product)
{
    /* TODO */
}

#elif ECC_CURVE == secp160r1

//static void omega_mult(uint8_t * restrict p_result, uint8_t * restrict p_right)
static void omega_mult(uint8_t * __restrict__ p_result, uint8_t * __restrict__ p_right)
{
    uint8_t l_carry;
    uint8_t i;
    
    /* Multiply by (2^31 + 1). */
    vli_set(p_result + 4, p_right); /* 2^32 */
    vli_rshift1(p_result + 4); /* 2^31 */
    p_result[3] = p_right[0] << 7; /* get last bit from shift */
    
    l_carry = vli_add(p_result, p_result, p_right); /* 2^31 + 1 */
    for(i = ECC_BYTES; l_carry; ++i)
    {
        uint16_t l_sum = (uint16_t)p_result[i] + l_carry;
        p_result[i] = (uint8_t)l_sum;
        l_carry = l_sum >> 8;
    }
}

// /* Computes p_result = p_product % curve_p
//     see http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf page 354 */
// static void vli_mmod_fast(uint8_t *restrict p_result, uint8_t *restrict p_product)
// {
//     uint8_t l_tmp[2*ECC_BYTES] = {0};
//     uint8_t l_carry;
//     
//     omega_mult(l_tmp, p_product + ECC_BYTES); /* (Rq, q) = q * c */
//     
//     l_carry = vli_add(p_result, p_product, l_tmp); /* (C, r) = r + q       */
//     if(!vli_isZero(l_tmp + ECC_BYTES)) /* if Rq > 0 */
//     {
//         vli_clear(p_product);
//         omega_mult(p_product, l_tmp + ECC_BYTES); /* Rq*c */
//         l_carry += vli_add(p_result, p_result, p_product); /* (C1, r) = r + Rq*c */
//     }
// 
//     while(l_carry > 0)
//     {
//         --l_carry;
//         vli_sub(p_result, p_result, curve_p);
//     }
//     
//     while(vli_cmp(p_result, curve_p) > 0)
//     {
//         vli_sub(p_result, p_result, curve_p);
//     }
// }

/* Computes p_result = p_product % curve_p
    see PDF "Comparing Elliptic Curve Cryptography and RSA on 8-bit CPUs"
    section "Curve-Specific Optimizations" */
static void vli_mmod_fast(uint8_t * restrict p_result, uint8_t * restrict p_product)
{
    uint8_t l_tmp[2*ECC_BYTES];
     
    while(!vli_isZero(p_product + ECC_BYTES)) /* While c1 != 0 */
    {
        uint8_t l_carry = 0;
        uint8_t i;
        
        vli_clear(l_tmp);
        vli_clear(l_tmp + ECC_BYTES);
        omega_mult(l_tmp, p_product + ECC_BYTES); /* tmp = w * c1 */
        vli_clear(p_product + ECC_BYTES); /* p = c0 */
        
        /* (c1, c0) = c0 + w * c1 */
        for(i=0; i<ECC_BYTES+4; ++i)
        {
            uint16_t l_sum = (uint16_t)p_product[i] + l_tmp[i] + l_carry;
            p_product[i] = (uint8_t)l_sum;
            l_carry = l_sum >> 8;
        }
        p_product[ECC_BYTES+4] = l_carry;
    }
    
    while(vli_cmp(p_product, curve_p) > 0)
    {
        vli_sub(p_product, p_product, curve_p);
    }
    vli_set(p_result, p_product);
}

#elif ECC_CURVE == secp192r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint64_t *restrict p_result, uint64_t *restrict p_product)
{
    /* TODO */
}

#elif ECC_CURVE == secp256r1

/* Computes p_result = p_product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
static void vli_mmod_fast(uint64_t *restrict p_result, uint64_t *restrict p_product)
{
    /* TODO */
}

#endif


/* Computes p_result = (p_left * p_right) % curve_p. */
static void vli_modMult_fast(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
    uint8_t l_product[2 * ECC_BYTES];
    vli_mult(l_product, p_left, p_right);
    vli_mmod_fast(p_result, l_product);
}

#if ECC_SQUARE_FUNC

/* Computes p_result = p_left^2 % curve_p. */
static void vli_modSquare_fast(uint8_t *p_result, uint8_t *p_left)
{
    uint8_t l_product[2 * ECC_BYTES];
    vli_square(l_product, p_left);
    vli_mmod_fast(p_result, l_product);
}

#else /* ECC_SQUARE_FUNC */

#define vli_modSquare_fast(result, left) vli_modMult_fast((result), (left), (left))
    
#endif /* ECC_SQUARE_FUNC */


#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void vli_modInv(uint8_t *p_result, uint8_t *p_input, uint8_t *p_mod)
{
    uint8_t a[ECC_BYTES], b[ECC_BYTES], u[ECC_BYTES], v[ECC_BYTES];
    uint8_t l_carry;
    int l_cmpResult;
    
    if(vli_isZero(p_input))
    {
        vli_clear(p_result);
        return;
    }

    vli_set(a, p_input);
    vli_set(b, p_mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);
    
    while((l_cmpResult = vli_cmp(a, b)) != 0)
    {
        l_carry = 0;
        if(EVEN(a))
        {
            vli_rshift1(a);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[ECC_BYTES-1] |= 0x80;
            }
        }
        else if(EVEN(b))
        {
            vli_rshift1(b);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[ECC_BYTES-1] |= 0x80;
            }
        }
        else if(l_cmpResult > 0)
        {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if(vli_cmp(u, v) < 0)
            {
                vli_add(u, u, p_mod);
            }
            vli_sub(u, u, v);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[ECC_BYTES-1] |= 0x80;
            }
        }
        else
        {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if(vli_cmp(v, u) < 0)
            {
                vli_add(v, v, p_mod);
            }
            vli_sub(v, v, u);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[ECC_BYTES-1] |= 0x80;
            }
        }
    }
    
    vli_set(p_result, u);
}

/* ------ Point operations ------ */

/* Returns 1 if p_point is the point at infinity, 0 otherwise. */
static int EccPoint_isZero(EccPoint *p_point)
{
    return (vli_isZero(p_point->x) && vli_isZero(p_point->y));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Double in place */
static void EccPoint_double_jacobian(uint8_t * restrict X1, uint8_t * restrict Y1, uint8_t * restrict Z1)
{
    /* t1 = X, t2 = Y, t3 = Z */
    uint8_t t4[ECC_BYTES];
    uint8_t t5[ECC_BYTES];
    
    if(vli_isZero(Z1))
    {
        return;
    }
    
    vli_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
    vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(t4, t4);   /* t4 = y1^4 */
    vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */
    
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
    vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
    vli_modSub(Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
    vli_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */
    
    vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
    if(vli_testBit(X1, 0))
    {
        uint8_t l_carry = vli_add(X1, X1, curve_p);
        vli_rshift1(X1);
        X1[ECC_BYTES-1] |= l_carry << 7;
    }
    else
    {
        vli_rshift1(X1);
    }
    /* t1 = 3/2*(x1^2 - z1^4) = B */
    
    vli_modSquare_fast(Z1, X1);      /* t3 = B^2 */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
    vli_modSub(t5, t5, Z1, curve_p); /* t5 = A - x3 */
    vli_modMult_fast(X1, X1, t5);    /* t1 = B * (A - x3) */
    vli_modSub(t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */
    
    vli_set(X1, Z1);
    vli_set(Z1, Y1);
    vli_set(Y1, t4);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uint8_t * restrict X1, uint8_t * restrict Y1, uint8_t * restrict Z)
{
    uint8_t t1[ECC_BYTES];

    vli_modSquare_fast(t1, Z);    /* z^2 */
    vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
    vli_modMult_fast(t1, t1, Z);  /* z^3 */
    vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uint8_t * restrict X1, uint8_t * restrict Y1,
    uint8_t * restrict X2, uint8_t * restrict Y2, const uint8_t * restrict p_initialZ)
{
    uint8_t z[ECC_BYTES];
    
    vli_set(X2, X1);
    vli_set(Y2, Y1);
    
    vli_clear(z);
    z[0] = 1;
    if(p_initialZ)
    {
        vli_set(z, p_initialZ);
    }

    apply_z(X1, Y1, z);
    
    EccPoint_double_jacobian(X1, Y1, z);
    
    apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(uint8_t * restrict X1, uint8_t * restrict Y1, uint8_t * restrict X2, uint8_t * restrict Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint8_t t5[ECC_BYTES];
    
    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */
    vli_modSquare_fast(t5, Y2);      /* t5 = (y2 - y1)^2 = D */
    
    vli_modSub(t5, t5, X1, curve_p); /* t5 = D - B */
    vli_modSub(t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */
    vli_modSub(X2, X2, X1, curve_p); /* t3 = C - B */
    vli_modMult_fast(Y1, Y1, X2);    /* t2 = y1*(C - B) */
    vli_modSub(X2, X1, t5, curve_p); /* t3 = B - x3 */
    vli_modMult_fast(Y2, Y2, X2);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */
    
    vli_set(X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uint8_t * restrict X1, uint8_t * restrict Y1, uint8_t * restrict X2, uint8_t * restrict Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint8_t t5[ECC_BYTES];
    uint8_t t6[ECC_BYTES];
    uint8_t t7[ECC_BYTES];
    
    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modAdd(t5, Y2, Y1, curve_p); /* t4 = y2 + y1 */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */

    vli_modSub(t6, X2, X1, curve_p); /* t6 = C - B */
    vli_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) */
    vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
    vli_modSquare_fast(X2, Y2);      /* t3 = (y2 - y1)^2 */
    vli_modSub(X2, X2, t6, curve_p); /* t3 = x3 */
    
    vli_modSub(t7, X1, X2, curve_p); /* t7 = B - x3 */
    vli_modMult_fast(Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */
    
    vli_modSquare_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */
    vli_modSub(t7, t7, t6, curve_p); /* t7 = x3' */
    vli_modSub(t6, t7, X1, curve_p); /* t6 = x3' - B */
    vli_modMult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub(Y1, t6, Y1, curve_p); /* t2 = y3' */
    
    vli_set(X1, t7);
}

static void EccPoint_mult(EccPoint * restrict p_result, EccPoint * restrict p_point,
    const uint8_t * restrict p_scalar, const uint8_t * restrict p_initialZ)
{
    /* R0 and R1 */
    uint8_t Rx[2][ECC_BYTES];
    uint8_t Ry[2][ECC_BYTES];
    uint8_t z[ECC_BYTES];
    
    int16_t i;
    uint8_t nb;
    
    vli_set(Rx[1], p_point->x);
    vli_set(Ry[1], p_point->y);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

    for(i = vli_numBits(p_scalar) - 2; i > 0; --i)
    {
        nb = !vli_testBit(p_scalar, i);
        XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    }

    nb = !vli_testBit(p_scalar, 0);
    XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
    
    /* Find final 1/Z value. */
    vli_modSub(z, Rx[1], Rx[0], curve_p); /* X1 - X0 */
    vli_modMult_fast(z, z, Ry[1-nb]);     /* Yb * (X1 - X0) */
    vli_modMult_fast(z, z, p_point->x);   /* xP * Yb * (X1 - X0) */
    vli_modInv(z, z, curve_p);            /* 1 / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, p_point->y);   /* yP / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, Rx[1-nb]);     /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    
    apply_z(Rx[0], Ry[0], z);
    
    vli_set(p_result->x, Rx[0]);
    vli_set(p_result->y, Ry[0]);
}

/* Compute a = sqrt(a) (mod curve_p). */
static void mod_sqrt(uint8_t a[ECC_BYTES])
{
    int16_t i;
    uint8_t p1[ECC_BYTES] = {1};
    uint8_t l_result[ECC_BYTES] = {1};
    
    /* Since curve_p == 3 (mod 4) for all supported curves, we can
       compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
    vli_add(p1, curve_p, p1); /* p1 = curve_p + 1 */
    for(i = vli_numBits(p1) - 1; i > 1; --i)
    {
        vli_modSquare_fast(l_result, l_result);
        if(vli_testBit(p1, i))
        {
            vli_modMult_fast(l_result, l_result, a);
        }
    }
    vli_set(a, l_result);
}

static void vli_flip(uint8_t * restrict p_dest, const uint8_t * restrict p_src)
{
    uint8_t i;
    for(i=0; i<ECC_BYTES; ++i)
    {
        p_dest[i] = p_src[(ECC_BYTES - 1) - i];
    }
}

static void ecc_point_decompress(EccPoint *p_point, const uint8_t p_compressed[ECC_BYTES+1])
{
    uint8_t _3[ECC_BYTES] = {3}; /* -a = 3 */
    vli_flip(p_point->x, p_compressed + 1);
    
    vli_modSquare_fast(p_point->y, p_point->x); /* y = x^2 */
    vli_modSub(p_point->y, p_point->y, _3, curve_p); /* y = x^2 - 3 */
    vli_modMult_fast(p_point->y, p_point->y, p_point->x); /* y = x^3 - 3x */
    vli_modAdd(p_point->y, p_point->y, curve_b, curve_p); /* y = x^3 - 3x + b */
    
    mod_sqrt(p_point->y);
    
    if((p_point->y[0] & 0x01) != (p_compressed[0] & 0x01))
    {
        vli_sub(p_point->y, curve_p, p_point->y);
    }
}

int ecc_make_key(uint8_t p_publicKey[ECC_BYTES+1], uint8_t p_privateKey[ECC_BYTES])
{
    EccPoint l_public;
    uint8_t l_private[ECC_BYTES];
    uint8_t l_tries = 0;
    
    do
    {
        if(!g_rng(l_private, ECC_BYTES) || (l_tries++ >= MAX_TRIES))
        {
            return 0;
        }
        if(vli_isZero(l_private))
        {
            continue;
        }
    
        /* Make sure the private key is in the range [1, n-1].
           For the supported curves, n is always large enough that we only need to subtract once at most. */
    #if ECC_CURVE != secp160r1
        if(vli_cmp(curve_n, l_private) != 1)
        {
            vli_sub(l_private, l_private, curve_n);
        }
    #endif

        EccPoint_mult(&l_public, &curve_G, l_private, 0);
    } while(EccPoint_isZero(&l_public));
    
    vli_flip(p_privateKey, l_private);
    vli_flip(p_publicKey + 1, l_public.x);
    p_publicKey[0] = 2 + (l_public.y[0] & 0x01);
    return 1;
}

int ecdh_shared_secret(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_privateKey[ECC_BYTES], uint8_t p_secret[ECC_BYTES])
{
    EccPoint l_public;
    uint8_t l_private[ECC_BYTES];
    uint8_t l_random[ECC_BYTES];
    
    if(!g_rng(l_random, ECC_BYTES))
    {
        return 0;
    }
    
    vli_flip(l_private, p_privateKey);
    ecc_point_decompress(&l_public, p_publicKey);
    
    EccPoint l_product;
    EccPoint_mult(&l_product, &l_public, l_private, l_random);
    
    vli_flip(p_secret, l_product.x);
    
    return !EccPoint_isZero(&l_product);
}
