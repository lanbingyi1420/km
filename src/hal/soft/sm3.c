/* SM3 哈希算法，按 GB/T 32905-2016 实现 */
#include "sm3.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

/* 初始 IV */
static const uint32_t SM3_IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

static const uint32_t T0 = 0x79cc4519; /* j in [0,15] */
static const uint32_t T1 = 0x7a879d8a; /* j in [16,63] */

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* 消息扩展 + 压缩函数（处理一个 512 位分组） */
static void sm3_compress(sm3_ctx_t *ctx, const uint8_t block[64])

{
    uint32_t w[68];
    uint32_t w1[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t ss1, ss2, tt1, tt2;
    uint32_t t;
    int j;

    for (j = 0; j < 16; j++)
        w[j] = load_be32(block + 4 * j);

    for (j = 16; j < 68; j++) {
        w[j] = P1(w[j - 16] ^ w[j - 9] ^ ROTL32(w[j - 3], 15))
               ^ ROTL32(w[j - 13], 7) ^ w[j - 6];
    }
    for (j = 0; j < 64; j++)
        w1[j] = w[j] ^ w[j + 4];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (j = 0; j < 64; j++) {
        t = (j < 16) ? T0 : T1;
        ss1 = ROTL32(ROTL32(a, 12) + e + ROTL32(t, j % 32), 7);
        ss2 = ss1 ^ ROTL32(a, 12);
        tt1 = (j < 16 ? FF0(a, b, c) : FF1(a, b, c)) + d + ss2 + w1[j];
        tt2 = (j < 16 ? GG0(e, f, g) : GG1(e, f, g)) + h + ss1 + w[j];
        d = c;
        c = ROTL32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = ROTL32(f, 19);
        f = e;
        e = P0(tt2);
    }

    ctx->state[0] ^= a;
    ctx->state[1] ^= b;
    ctx->state[2] ^= c;
    ctx->state[3] ^= d;
    ctx->state[4] ^= e;
    ctx->state[5] ^= f;
    ctx->state[6] ^= g;
    ctx->state[7] ^= h;
}

/* 初始化 SM3 上下文（加载初始 IV，清零计数与缓冲） */
void sm3_init(sm3_ctx_t *ctx)
{
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->total_bits = 0;
    ctx->buf_len = 0;
}

/* 追加输入数据到上下文，满 64 字节即压缩一个分组 */
void sm3_update(sm3_ctx_t *ctx, const uint8_t *in, size_t len)
{
    ctx->total_bits += (uint64_t)len * 8;

    if (ctx->buf_len > 0) {
        size_t need = 64 - ctx->buf_len;
        if (len >= need) {
            memcpy(ctx->buffer + ctx->buf_len, in, need);
            sm3_compress(ctx, ctx->buffer);
            ctx->buf_len = 0;
            in += need;
            len -= need;
        } else {
            memcpy(ctx->buffer + ctx->buf_len, in, len);
            ctx->buf_len += len;
            return;
        }
    }

    while (len >= 64) {
        sm3_compress(ctx, in);
        in += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer, in, len);
        ctx->buf_len = len;
    }
}

/* 结束 SM3 计算：填充（0x80 + 长度）并输出 32 字节摘要，随后清零上下文 */
void sm3_final(sm3_ctx_t *ctx, uint8_t out[SM3_DIGEST_LEN])
{
    uint8_t pad[72];
    size_t pad_len;
    size_t i;
    uint64_t bits = ctx->total_bits;

    pad[0] = 0x80;
    pad_len = (ctx->buf_len < 56) ? (56 - ctx->buf_len) : (120 - ctx->buf_len);
    memset(pad + 1, 0, pad_len - 1);
    /* 大端 64 位长度 */
    for (i = 0; i < 8; i++)
        pad[pad_len + i] = (uint8_t)(bits >> (56 - 8 * i));

    sm3_update(ctx, pad, pad_len + 8);

    for (i = 0; i < 8; i++)
        store_be32(out + 4 * i, ctx->state[i]);

    memset(ctx, 0, sizeof(*ctx));
}

/* 一次性计算 SM3 摘要：SM3(in[0..len)) -> out[32] */
void sm3_digest(const uint8_t *in, size_t len, uint8_t out[SM3_DIGEST_LEN])
{
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, in, len);
    sm3_final(&ctx, out);
}
