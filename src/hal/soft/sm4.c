/* SM4 分组密码算法，按 GB/T 32907-2016 实现 */
#include "sm4.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* S 盒 */
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

/* 系统参数 FK */
static const uint32_t SM4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

/* 固定参数 CK */
static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

/* 读 4 字节大端为 32 位字 */
static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* 32 位字按大端写入 4 字节 */
static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* 非线性变换 tau */
static uint32_t tau(uint32_t x)
{
    uint8_t b[4];
    b[0] = SM4_SBOX[(x >> 24) & 0xff];
    b[1] = SM4_SBOX[(x >> 16) & 0xff];
    b[2] = SM4_SBOX[(x >> 8) & 0xff];
    b[3] = SM4_SBOX[x & 0xff];
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

/* 线性变换 L（加密轮函数） */
static uint32_t L(uint32_t b)
{
    return b ^ ROTL32(b, 2) ^ ROTL32(b, 10) ^ ROTL32(b, 18) ^ ROTL32(b, 24);
}

/* 线性变换 L'（密钥扩展） */
static uint32_t Lp(uint32_t b)
{
    return b ^ ROTL32(b, 13) ^ ROTL32(b, 23);
}

/* 合成置换 T（轮函数用）：T(x)=L(tau(x)) */
static uint32_t T(uint32_t x)
{
    return L(tau(x));
}

/* 合成置换 T'（密钥扩展用）：T'(x)=L'(tau(x)) */
static uint32_t Tp(uint32_t x)
{
    return Lp(tau(x));
}

/* 生成 32 轮加密轮密钥 rk[0..31] */
void sm4_set_encrypt_key(const uint8_t key[SM4_KEY_LEN], uint32_t rk[32])
{
    uint32_t k[36];
    int i;

    for (i = 0; i < 4; i++)
        k[i] = load_be32(key + 4 * i) ^ SM4_FK[i];

    for (i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ Tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]);
        rk[i] = k[i + 4];
    }
}

/* 生成 32 轮解密轮密钥（加密轮密钥逆序） */
void sm4_set_decrypt_key(const uint8_t key[SM4_KEY_LEN], uint32_t rk[32])
{
    uint32_t rk_enc[32];
    int i;

    sm4_set_encrypt_key(key, rk_enc);
    for (i = 0; i < 32; i++)
        rk[i] = rk_enc[31 - i];
}

/* 单分组 SM4 加密：out = ENC_rk(in) */
void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[SM4_BLOCK_LEN],
                       uint8_t out[SM4_BLOCK_LEN])
{
    uint32_t x[36];
    uint32_t tmp;
    int i;

    for (i = 0; i < 4; i++)
        x[i] = load_be32(in + 4 * i);

    for (i = 0; i < 32; i++) {
        tmp = x[i] ^ T(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]);
        x[i + 4] = tmp;
    }

    store_be32(out, x[35]);
    store_be32(out + 4, x[34]);
    store_be32(out + 8, x[33]);
    store_be32(out + 12, x[32]);
}

/* 单分组 SM4 解密：out = DEC_rk(in) */
void sm4_decrypt_block(const uint32_t rk[32], const uint8_t in[SM4_BLOCK_LEN],
                       uint8_t out[SM4_BLOCK_LEN])
{
    uint32_t x[36];
    uint32_t tmp;
    int i;

    for (i = 0; i < 4; i++)
        x[i] = load_be32(in + 4 * i);

    for (i = 0; i < 32; i++) {
        tmp = x[i] ^ T(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]);
        x[i + 4] = tmp;
    }

    store_be32(out, x[35]);
    store_be32(out + 4, x[34]);
    store_be32(out + 8, x[33]);
    store_be32(out + 12, x[32]);
}

/* ECB 模式整段加密（len 须为 16 的倍数） */
void sm4_ecb_encrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t *in, uint8_t *out, size_t len)
{
    uint32_t rk[32];
    size_t i;

    sm4_set_encrypt_key(key, rk);
    for (i = 0; i < len; i += SM4_BLOCK_LEN)
        sm4_encrypt_block(rk, in + i, out + i);
}

/* ECB 模式整段解密（len 须为 16 的倍数） */
void sm4_ecb_decrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t *in, uint8_t *out, size_t len)
{
    uint32_t rk[32];
    size_t i;

    sm4_set_decrypt_key(key, rk);
    for (i = 0; i < len; i += SM4_BLOCK_LEN)
        sm4_decrypt_block(rk, in + i, out + i);
}

/* CBC 模式整段加密（iv 为 NULL 时取全 0；len 须为 16 的倍数） */
void sm4_cbc_encrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t iv[SM4_BLOCK_LEN],
                     const uint8_t *in, uint8_t *out, size_t len)
{
    uint32_t rk[32];
    uint8_t prev[SM4_BLOCK_LEN];
    uint8_t block[SM4_BLOCK_LEN];
    size_t i, j;

    sm4_set_encrypt_key(key, rk);
    if (iv != NULL)
        memcpy(prev, iv, SM4_BLOCK_LEN);
    else
        memset(prev, 0, SM4_BLOCK_LEN);

    for (i = 0; i < len; i += SM4_BLOCK_LEN) {
        for (j = 0; j < SM4_BLOCK_LEN; j++)
            block[j] = in[i + j] ^ prev[j];
        sm4_encrypt_block(rk, block, out + i);
        memcpy(prev, out + i, SM4_BLOCK_LEN);
    }
}

/* CBC 模式整段解密（iv 为 NULL 时取全 0；len 须为 16 的倍数） */
void sm4_cbc_decrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t iv[SM4_BLOCK_LEN],
                     const uint8_t *in, uint8_t *out, size_t len)
{
    uint32_t rk[32];
    uint8_t prev[SM4_BLOCK_LEN];
    uint8_t cur[SM4_BLOCK_LEN];
    size_t i, j;

    sm4_set_decrypt_key(key, rk);
    if (iv != NULL)
        memcpy(prev, iv, SM4_BLOCK_LEN);
    else
        memset(prev, 0, SM4_BLOCK_LEN);

    for (i = 0; i < len; i += SM4_BLOCK_LEN) {
        memcpy(cur, in + i, SM4_BLOCK_LEN);
        sm4_decrypt_block(rk, in + i, out + i);
        for (j = 0; j < SM4_BLOCK_LEN; j++)
            out[i + j] ^= prev[j];
        memcpy(prev, cur, SM4_BLOCK_LEN);
    }
}
