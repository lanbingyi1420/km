/* SM2 签名/验签/密钥生成（GB/T 32918.2-2016 / GM/T 0003.2）
 *
 * 默认用户标识 IDA = "1234567812345678"（GB/T 32918.2 示例值），
 * ZA = SM3(ENTL || IDA || a || b || Gx || Gy || Px || Py)。 */
#include "sm2.h"
#include "sm2_bignum.h"
#include "sm2_rng.h"
#include "sm3.h"
#include <string.h>

#define SM2_IDA_DEFAULT     "1234567812345678"
#define SM2_IDA_DEFAULT_LEN 16

/* ---------- 内部辅助 ---------- */

/* ZA = SM3(ENTL || IDA || a || b || Gx || Gy || Px || Py) */
static void sm2_compute_za(const uint8_t pubkey[SM2_PUBKEY_LEN],
                           const uint8_t *ida, size_t ida_len,
                           uint8_t za[SM3_DIGEST_LEN])
{
    sm3_ctx_t ctx;
    uint8_t entl[2];
    uint8_t abuf[32], bbuf[32], gx[32], gy[32];
    uint16_t bits = (uint16_t)(ida_len * 8);

    entl[0] = (uint8_t)(bits >> 8);
    entl[1] = (uint8_t)(bits & 0xFF);

    sm2_bn_to_bytes(&SM2_A, abuf);
    sm2_bn_to_bytes(&SM2_B, bbuf);
    sm2_bn_to_bytes(&SM2_GX, gx);
    sm2_bn_to_bytes(&SM2_GY, gy);

    sm3_init(&ctx);
    sm3_update(&ctx, entl, 2);
    sm3_update(&ctx, ida, ida_len);
    sm3_update(&ctx, abuf, 32);
    sm3_update(&ctx, bbuf, 32);
    sm3_update(&ctx, gx, 32);
    sm3_update(&ctx, gy, 32);
    sm3_update(&ctx, pubkey, 64); /* Px || Py */
    sm3_final(&ctx, za);
}

/* e = SM3(ZA || M) */
static void sm2_compute_e(const uint8_t za[SM3_DIGEST_LEN],
                          const uint8_t *data, size_t data_len,
                          sm2_bn_t *e)
{
    sm3_ctx_t ctx;
    uint8_t d[SM3_DIGEST_LEN];

    sm3_init(&ctx);
    sm3_update(&ctx, za, SM3_DIGEST_LEN);
    sm3_update(&ctx, data, data_len);
    sm3_final(&ctx, d);
    sm2_bn_from_bytes(e, d);
}

/* ---------- 公共接口 ---------- */

/* 由私钥计算公钥：pubkey = prikey·G（64 字节 x||y，无 0x04 前缀）；失败返回 -1 */
int sm2_pubkey_from_prikey(const uint8_t prikey[SM2_PRIKEY_LEN],
                           uint8_t pubkey[SM2_PUBKEY_LEN])
{
    sm2_bn_t d;
    sm2_pt_a g, p;

    if (prikey == NULL || pubkey == NULL)
        return -1;
    sm2_bn_from_bytes(&d, prikey);
    if (sm2_bn_is_zero(&d) || sm2_bn_cmp(&d, &SM2_N) >= 0)
        return -1;

    sm2_bn_copy(&g.x, &SM2_GX);
    sm2_bn_copy(&g.y, &SM2_GY);
    if (sm2_ecc_mul(&SM2_P, &d, &g, &p) != 0)
        return -1;

    sm2_bn_to_bytes(&p.x, pubkey);
    sm2_bn_to_bytes(&p.y, pubkey + 32);
    return 0;
}

/* 生成 SM2 密钥对：d ∈ [1, n-1]，pubkey=64B x||y；失败返回 -1 */
int sm2_gen_keypair(uint8_t pubkey[SM2_PUBKEY_LEN], uint8_t prikey[SM2_PRIKEY_LEN])
{
    sm2_bn_t d;
    uint8_t kb[32];
    int i;

    if (pubkey == NULL || prikey == NULL)
        return -1;

    for (i = 0; i < 64; i++) {
        if (sm2_rng_bytes(kb, sizeof(kb)) != 0)
            return -1;
        sm2_bn_from_bytes(&d, kb);
        if (sm2_bn_is_zero(&d) || sm2_bn_cmp(&d, &SM2_N) >= 0)
            continue; /* 重采随机数 */
        sm2_bn_to_bytes(&d, prikey);
        if (sm2_pubkey_from_prikey(prikey, pubkey) == 0) {
            memset(kb, 0, sizeof(kb));
            return 0;
        }
    }
    memset(kb, 0, sizeof(kb));
    return -1;
}

/* SM2 签名：对 data 计算签名 sig=64B r||s（默认 IDA）；失败返回 -1 */
int sm2_sign(const uint8_t prikey[SM2_PRIKEY_LEN], const uint8_t *data,
             size_t data_len, uint8_t sig[SM2_SIG_LEN])
{
    sm2_bn_t d, k, e, r, s, tmp, inv;
    sm2_pt_a g, gk;
    uint8_t pub[SM2_PUBKEY_LEN];
    uint8_t za[SM3_DIGEST_LEN];
    uint8_t kb[32];
    int i;

    if (prikey == NULL || data == NULL || sig == NULL)
        return -1;

    sm2_bn_from_bytes(&d, prikey);
    if (sm2_bn_is_zero(&d) || sm2_bn_cmp(&d, &SM2_N) >= 0)
        return -1;

    /* 由 d 计算公钥 → ZA → e */
    sm2_bn_copy(&g.x, &SM2_GX);
    sm2_bn_copy(&g.y, &SM2_GY);
    if (sm2_ecc_mul(&SM2_P, &d, &g, &gk) != 0)
        return -1;
    {
        uint8_t xb[32], yb[32];
        sm2_bn_to_bytes(&gk.x, xb);
        sm2_bn_to_bytes(&gk.y, yb);
        memcpy(pub, xb, 32);
        memcpy(pub + 32, yb, 32);
    }
    sm2_compute_za(pub, (const uint8_t *)SM2_IDA_DEFAULT, SM2_IDA_DEFAULT_LEN, za);
    sm2_compute_e(za, data, data_len, &e);

    for (i = 0; i < 64; i++) {
        /* k ∈ [1, n-1] */
        do {
            if (sm2_rng_bytes(kb, sizeof(kb)) != 0) {
                memset(kb, 0, sizeof(kb));
                return -1;
            }
            sm2_bn_from_bytes(&k, kb);
        } while (sm2_bn_is_zero(&k) || sm2_bn_cmp(&k, &SM2_N) >= 0);

        /* (x1, y1) = kG */
        if (sm2_ecc_mul_base(&k, &gk) != 0)
            continue;
        /* r = (e + x1) mod n */
        sm2_mod_add(&SM2_N, &e, &gk.x, &r);
        if (sm2_bn_is_zero(&r))
            continue;
        /* r + k == n → 重选 k */
        sm2_mod_add(&SM2_N, &r, &k, &tmp);
        if (sm2_bn_is_zero(&tmp))
            continue;

        /* s = (1+d)^{-1} · (k - r·d) mod n */
        {
            sm2_bn_t one;
            sm2_bn_zero(&one);
            one.w[7] = 1;
            sm2_mod_add(&SM2_N, &d, &one, &tmp);   /* 1 + d */
        }
        if (sm2_bn_cmp(&tmp, &SM2_N) >= 0)
            sm2_mod_sub(&SM2_N, &tmp, &SM2_N, &tmp); /* (1+d) mod n */
        if (sm2_mod_inv(&SM2_N, &tmp, &inv) != 0)
            continue;
        sm2_mod_mul(&SM2_N, &r, &d, &tmp);     /* r·d */
        sm2_mod_sub(&SM2_N, &k, &tmp, &tmp);   /* k - r·d */
        sm2_mod_mul(&SM2_N, &inv, &tmp, &s);
        if (sm2_bn_is_zero(&s))
            continue;

        sm2_bn_to_bytes(&r, sig);
        sm2_bn_to_bytes(&s, sig + SM2_PRIKEY_LEN);
        memset(kb, 0, sizeof(kb));
        return 0;
    }
    memset(kb, 0, sizeof(kb));
    return -1;
}

/* SM2 验签：验证 pubkey 对 data 的签名 sig（默认 IDA）；有效返回 0，无效/失败返回 -1 */
int sm2_verify(const uint8_t pubkey[SM2_PUBKEY_LEN], const uint8_t *data,
               size_t data_len, const uint8_t sig[SM2_SIG_LEN])
{
    sm2_bn_t r, s, e, t, rr;
    sm2_pt_a p, sg, tp, sum;
    uint8_t za[SM3_DIGEST_LEN];

    if (pubkey == NULL || data == NULL || sig == NULL)
        return -1;

    /* r, s ∈ [1, n-1] */
    sm2_bn_from_bytes(&r, sig);
    sm2_bn_from_bytes(&s, sig + SM2_PRIKEY_LEN);
    if (sm2_bn_is_zero(&r) || sm2_bn_cmp(&r, &SM2_N) >= 0 ||
        sm2_bn_is_zero(&s) || sm2_bn_cmp(&s, &SM2_N) >= 0)
        return -1;

    sm2_compute_za(pubkey, (const uint8_t *)SM2_IDA_DEFAULT, SM2_IDA_DEFAULT_LEN, za);
    sm2_compute_e(za, data, data_len, &e);

    /* t = (r + s) mod n；t == 0 无效 */
    sm2_mod_add(&SM2_N, &r, &s, &t);
    if (sm2_bn_is_zero(&t))
        return -1;

    {
        uint8_t xb[32], yb[32];
        memcpy(xb, pubkey, 32);
        memcpy(yb, pubkey + 32, 32);
        sm2_bn_from_bytes(&p.x, xb);
        sm2_bn_from_bytes(&p.y, yb);
    }

    /* (x1, y1) = sG + tP */
    if (sm2_ecc_mul_base(&s, &sg) != 0)
        return -1;
    if (sm2_ecc_mul(&SM2_P, &t, &p, &tp) != 0)
        return -1;
    if (sm2_ecc_add_affine(&SM2_P, &sg, &tp, &sum) != 0)
        return -1;

    /* R = (e + x1) mod n；R == r 有效 */
    sm2_mod_add(&SM2_N, &e, &sum.x, &rr);
    return (sm2_bn_cmp(&rr, &r) == 0) ? 0 : -1;
}

/* 密钥派生函数：KDF(z, klen) 输出前 klen 字节（GB/T 32918.3 第 5.4.3 节） */
void sm2_kdf(const uint8_t *z, size_t zlen, size_t klen, uint8_t *out)
{
    uint32_t ct = 1;
    size_t off = 0;
    sm3_ctx_t ctx;
    uint8_t ctbuf[4];
    uint8_t h[SM3_DIGEST_LEN];

    if (z == NULL || out == NULL || zlen == 0)
        return;

    /* KDF(Z, klen)：Ki = SM3(Z || 0x0000000i)，取前 klen 字节 */
    while (off < klen) {
        size_t take = (klen - off < SM3_DIGEST_LEN) ? (klen - off) : SM3_DIGEST_LEN;
        ctbuf[0] = (uint8_t)(ct >> 24);
        ctbuf[1] = (uint8_t)(ct >> 16);
        ctbuf[2] = (uint8_t)(ct >> 8);
        ctbuf[3] = (uint8_t)ct;
        sm3_init(&ctx);
        sm3_update(&ctx, z, zlen);
        sm3_update(&ctx, ctbuf, sizeof(ctbuf));
        sm3_final(&ctx, h);
        memcpy(out + off, h, take);
        off += take;
        ct++;
    }
}
