/*  chacha20 SIMD implementation under Public Domain License.
    Written by Daniel Glinka. Do not trust this implmementation.
    This was a small project to learn the chacha algorithm and
    optimizing with SIMD instructions.
*/

#include <stdio.h> // fprintf
#include <string.h>
#define assert(cond, msg) do                                                   \
{                                                                              \
    if (!(cond))                                                               \
    {                                                                          \
      fprintf(stderr, "Fatal error: %s:%d: dgl_assertion '%s' failed with %s\n",   \
      __FILE__, __LINE__, #cond, #msg);                                        \
      __builtin_trap();                                                        \
    }                                                                          \
} while(0)

#define array_count(array) (sizeof(array) / sizeof((array)[0]))

typedef unsigned char      uint8 ;
typedef   signed char       int8 ;
typedef unsigned short     uint16;
typedef   signed short      int16;
typedef unsigned int       uint32;
typedef   signed int        int32;
typedef unsigned long long uint64;
typedef          long long  int64;
typedef          float     real32;
typedef          double    real64;
typedef          int32     bool32;
#include <stddef.h>
typedef size_t usize;
#define true 1
#define false 0

#ifdef BIG_ENDIAN
#include <byteswap.h>
#endif

static uint32
rotl_uint32(uint32 x, uint32 n) {
    assert(n < 32, "N must be in the range 1-31.");
    return (x<<n) | (x>>(32-n));
}

static void
quarter_round(uint32 *a_, uint32 *b_, uint32 *c_, uint32 *d_)
{
    uint32 a = *a_;
    uint32 b = *b_;
    uint32 c = *c_;
    uint32 d = *d_;

    a += b; d ^= a; d = rotl_uint32(d, 16);
    c += d; b ^= c; b = rotl_uint32(b, 12);
    a += b; d ^= a; d = rotl_uint32(d, 8);
    c += d; b ^= c; b = rotl_uint32(b, 7);

    *a_ = a;
    *b_ = b;
    *c_ = c;
    *d_ = d;
}

static uint32
pack4_uint8(uint8 *src)
{
    // NOTE(dgl): values are stored in little endian order
    uint32 result = 0;
    result = (uint32)((src[3] << 24) |
                    (src[2] << 16) |
                    (src[1] << 8) |
                    (src[0] << 0));

    return(result);
}

static void
build_block(uint8 *key, uint8 *nonce, uint32 counter, uint32 *matrix, int32 rounds)
{
    uint8 *constant = (uint8 *)"expand 32-byte k";

    uint32 *dest = matrix;

    *dest++ = pack4_uint8(constant);
    *dest++ = pack4_uint8(constant +  4);
    *dest++ = pack4_uint8(constant +  8);
    *dest++ = pack4_uint8(constant + 12);

    *dest++ = pack4_uint8(key);
    *dest++ = pack4_uint8(key +  4);
    *dest++ = pack4_uint8(key +  8);
    *dest++ = pack4_uint8(key + 12);
    *dest++ = pack4_uint8(key + 16);
    *dest++ = pack4_uint8(key + 20);
    *dest++ = pack4_uint8(key + 24);
    *dest++ = pack4_uint8(key + 28);

#ifdef BIG_ENDIAN
    *dest++ = bswap_32(counter);
#else
    *dest++ = counter;
#endif

    *dest++ = pack4_uint8(nonce);
    *dest++ = pack4_uint8(nonce + 4);
    *dest++ = pack4_uint8(nonce + 8);

    assert((dest - matrix) == 16, "Matrix size does not match block");

    uint32 temp_m[16] = {};
    memcpy(temp_m, matrix, sizeof(*matrix)*16);

#ifdef DEBUG_PRINT
    printf("Block setup for %d: \n", counter);
    for(int32 index = 0; index < 16; ++index)
    {
        printf("%.8x ", matrix[index]);
        if(index % 4 == 3)
        {
            printf("\n");
        }
    }
    pritnf("\n");
#endif

    while(rounds > 0)
    {
        rounds -= 2;
        quarter_round(temp_m + 0, temp_m + 4, temp_m +  8, temp_m + 12);
        quarter_round(temp_m + 1, temp_m + 5, temp_m +  9, temp_m + 13);
        quarter_round(temp_m + 2, temp_m + 6, temp_m + 10, temp_m + 14);
        quarter_round(temp_m + 3, temp_m + 7, temp_m + 11, temp_m + 15);
        quarter_round(temp_m + 0, temp_m + 5, temp_m + 10, temp_m + 15);
        quarter_round(temp_m + 1, temp_m + 6, temp_m + 11, temp_m + 12);
        quarter_round(temp_m + 2, temp_m + 7, temp_m +  8, temp_m + 13);
        quarter_round(temp_m + 3, temp_m + 4, temp_m +  9, temp_m + 14);
    }

    for(int32 index = 0; index < array_count(temp_m); ++index)
    {
        matrix[index] += temp_m[index];

#ifdef BIG_ENDIAN
        // NOTE(dgl): Am I correct that this is needed on big endian systems?
        // we get the right results without this swap.
        // At the end of 20 rounds (or 10 iterations of the above list), we add
        // the original input words to the output words, and serialize the
        // result by sequencing the words one-by-one in little-endian order.
        // (https://tools.ietf.org/html/rfc7539#section-2.1)
        matrix[index] = bswap_32(matrix[index]);
#endif
    }

#ifdef DEBUG_PRINT
    printf("Final matrix for %d: \n", counter);
    for(int32 index = 0; index < 16; ++index)
    {
        printf("%.8x ", matrix[index]);
        if(index % 4 == 3)
        {
            printf("\n");
        }
    }
    printf("\n");
#endif
}

// NOTE(dgl): We do not check the key/nonce sizes.
static void
chacha_encrypt_internal(uint8 *key, uint8 *nonce, uint32 block_counter, int32 rounds, uint8 *buffer, usize buffer_count)
{
    uint32 matrix[16] = {};
    uint8 *block = (uint8 *)matrix;

    for(usize index = 0; index < buffer_count; ++index)
    {
        int32 mod = index % 64;
        if(mod == 0)
        {
            build_block(key, nonce, block_counter, matrix, rounds);
            block_counter++;
        }
        buffer[index] ^= *(block + mod);
    }
}

static void
chacha_encrypt(uint8 *key, usize key_count, uint8 *buffer, usize buffer_count)
{

    // TODO(dgl): hash key
    // then this check will be obsolete.
    assert(key_count == 32, "Key must be 32 bytes");
    uint32 block_counter = 1;
    int32 rounds = 20;

    // TODO(dgl): generate random nonce
    uint8 nonce[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };

    chacha_encrypt_internal(key, nonce, block_counter, rounds, buffer, buffer_count);

}

int main()
{
    uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    //char *message = "Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.";
    //usize message_count = strlen(message);
    uint8 message[] = { 0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d };
    usize message_count = array_count(message);
    uint8 buffer[1024] = {};
    memcpy(buffer, message, message_count);

#ifdef DEBUG_PRINT
    for(int32 index = 0; index < message_count; ++index)
    {
        printf("%x ", buffer[index]);
    }
    printf("\n");
#endif

    chacha_encrypt(key, array_count(key), buffer, message_count);

#ifdef DEBUG_PRINT
    printf("\n");
    for(int32 index = 0; index < message_count; ++index)
    {
        printf("0x%.2x, ", buffer[index]);
        if(index % 16 == 15)
        {
            //printf("\n");
        }
    }
    printf("\n");
#endif

    printf("%s\n", buffer);
    return(0);
}


