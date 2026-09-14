#ifndef KM_SM2_BIGNUM_H
#define KM_SM2_BIGNUM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 固定 256 位大数（8 × 32-bit 字，大端字序） */
typedef struct {
    uint32_t w[8];
} sm2_bn_t;

/* sm2p256v1 曲线参数 */
extern const sm2_bn_t SM2_P;   /* 素数 p */
extern const sm2_bn_t SM2_N;   /* 曲线阶 n */
extern const sm2_bn_t SM2_A;   /* a = p - 3 */
extern const sm2_bn_t SM2_B;
extern const sm2_bn_t SM2_GX;  /* 基点 G 的 x */
extern const sm2_bn_t SM2_GY;  /* 基点 G 的 y */

void sm2_bn_zero(sm2_bn_t *r);
void sm2_bn_copy(sm2_bn_t *r, const sm2_bn_t *a);
void sm2_bn_from_bytes(sm2_bn_t *r, const uint8_t b[32]); /* 大端 */
void sm2_bn_to_bytes(const sm2_bn_t *r, uint8_t b[32]);   /* 大端 */
int  sm2_bn_is_zero(const sm2_bn_t *a);
int  sm2_bn_is_odd(const sm2_bn_t *a);
/* a<b:-1  a==b:0  a>b:1 */
int  sm2_bn_cmp(const sm2_bn_t *a, const sm2_bn_t *b);

/* 模运算（模数 m 为 256 位） */
void sm2_mod_add(const sm2_bn_t *m, const sm2_bn_t *a,
                 const sm2_bn_t *b, sm2_bn_t *r);
void sm2_mod_sub(const sm2_bn_t *m, const sm2_bn_t *a,
                 const sm2_bn_t *b, sm2_bn_t *r);
/* t 为 512 位（16 字），约减到 mod m */
void sm2_mod_reduce(const sm2_bn_t *m, const uint32_t t[16], sm2_bn_t *r);
void sm2_mod_mul(const sm2_bn_t *m, const sm2_bn_t *a,
                 const sm2_bn_t *b, sm2_bn_t *r);
/* 模逆：a^{-1} mod m（m 须为素数） */
int  sm2_mod_inv(const sm2_bn_t *m, const sm2_bn_t *a, sm2_bn_t *r);

/* 仿射点 */
typedef struct {
    sm2_bn_t x;
    sm2_bn_t y;
} sm2_pt_a;

/* Jacobian 投影点 */
typedef struct {
    sm2_bn_t x;
    sm2_bn_t y;
    sm2_bn_t z;
} sm2_pt_j;

/* 点加倍（a=-3 优化），模数 m 传入 */
void sm2_ecc_double(const sm2_bn_t *m, const sm2_pt_j *p, sm2_pt_j *r);
/* 点加：Jacobian + 仿射（mixed），r 输出 Jacobian */
void sm2_ecc_add_mixed(const sm2_bn_t *m, const sm2_pt_j *p,
                       const sm2_pt_a *q, sm2_pt_j *r);
/* 标量乘 kP（double-and-add），成功返回 0；输出为仿射 */
int  sm2_ecc_mul(const sm2_bn_t *m, const sm2_bn_t *k,
                 const sm2_pt_a *p, sm2_pt_a *r);
/* 仿射点加 P1 + P2 */
int  sm2_ecc_add_affine(const sm2_bn_t *m, const sm2_pt_a *p1,
                        const sm2_pt_a *p2, sm2_pt_a *r);
/* 基点多倍 kG */
int  sm2_ecc_mul_base(const sm2_bn_t *k, sm2_pt_a *r);
/* Jacobian 转仿射（z 求逆） */
int  sm2_ecc_to_affine(const sm2_bn_t *m, const sm2_pt_j *p, sm2_pt_a *r);

#ifdef __cplusplus
}
#endif

#endif /* KM_SM2_BIGNUM_H */
