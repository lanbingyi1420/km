/* SM2 固定 256 位大数运算与 sm2p256v1 曲线点运算（GB/T 32918.2/32918.5）
 *
 * 实现说明：
 * - 大数：8 × 32-bit 字，大端字序（w[0] 为最高字）
 * - 模乘：schoolbook 64 位累加得 512 位乘积，逐位二进制约减（mod_reduce）
 * - 模逆：费马小定理 a^(m-2) mod m（模数须为素数）
 * - 曲线：Jacobian 投影坐标，点加倍用 a=-3 优化公式，
 *        混合加用 add-2007-bl 公式，标量乘为 double-and-add */
#include "sm2_bignum.h"
#include <string.h>

/* ---------- sm2p256v1 曲线参数（大端 32 位字序） ---------- */
const sm2_bn_t SM2_P = {
    {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
     0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF}
};
const sm2_bn_t SM2_N = {
    {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
     0x7203DF6B, 0x21C6052B, 0x53BBF409, 0x39D54123}
};
const sm2_bn_t SM2_A = {
    {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
     0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFC}
};
const sm2_bn_t SM2_B = {
    {0x28E9FA9E, 0x9D9F5E34, 0x4D5A9E4B, 0xCF6509A7,
     0xF39789F5, 0x15AB8F92, 0xDDBCBD41, 0x4D940E93}
};
const sm2_bn_t SM2_GX = {
    {0x32C4AE2C, 0x1F198119, 0x5F990446, 0x6A39C994,
     0x8FE30BBF, 0xF2660BE1, 0x715A4589, 0x334C74C7}
};
const sm2_bn_t SM2_GY = {
    {0xBC3736A2, 0xF4F6779C, 0x59BDCEE3, 0x6B692153,
     0xD0A9877C, 0xC62A4740, 0x02DF32E5, 0x2139F0A0}
};

/* ---------- 基本运算（trivial，保留实现） ---------- */

/* 将 r 清零（256 位全 0） */
void sm2_bn_zero(sm2_bn_t *r)
{
    memset(r, 0, sizeof(*r));
}

/* 复制大数 a 到 r */
void sm2_bn_copy(sm2_bn_t *r, const sm2_bn_t *a)
{
    memcpy(r, a, sizeof(*r));
}

/* 由 32 字节大端字节串构造大数 r */
void sm2_bn_from_bytes(sm2_bn_t *r, const uint8_t b[32])
{
    int i;
    for (i = 0; i < 8; i++) {
        r->w[i] = ((uint32_t)b[i * 4] << 24) |
                  ((uint32_t)b[i * 4 + 1] << 16) |
                  ((uint32_t)b[i * 4 + 2] << 8) |
                  (uint32_t)b[i * 4 + 3];
    }
}

/* 将大数 r 序列化为 32 字节大端字节串 */
void sm2_bn_to_bytes(const sm2_bn_t *r, uint8_t b[32])
{
    int i;
    for (i = 0; i < 8; i++) {
        b[i * 4]     = (uint8_t)(r->w[i] >> 24);
        b[i * 4 + 1] = (uint8_t)(r->w[i] >> 16);
        b[i * 4 + 2] = (uint8_t)(r->w[i] >> 8);
        b[i * 4 + 3] = (uint8_t)r->w[i];
    }
}

/* 判断 a 是否为零，返回 1=是 0=否 */
int sm2_bn_is_zero(const sm2_bn_t *a)
{
    int i;
    uint32_t acc = 0;
    for (i = 0; i < 8; i++)
        acc |= a->w[i];
    return acc == 0;
}

/* 判断 a 是否为奇数，返回 1=是 0=否 */
int sm2_bn_is_odd(const sm2_bn_t *a)
{
    return (int)(a->w[7] & 1);
}

/* 比较 a 与 b：返回 1(a>b) / 0(a==b) / -1(a<b) */
int sm2_bn_cmp(const sm2_bn_t *a, const sm2_bn_t *b)
{
    int i;
    for (i = 0; i < 8; i++) {
        if (a->w[i] > b->w[i]) return 1;
        if (a->w[i] < b->w[i]) return -1;
    }
    return 0;
}

/* ---------- 内部辅助 ---------- */

/* 大端 8 字减法：r -= a；返回借位（0=无借位） */
static uint32_t bn_sub8(uint32_t r[8], const uint32_t a[8])
{
    uint32_t borrow = 0;
    int j;
    for (j = 7; j >= 0; j--) {
        uint64_t s = (uint64_t)r[j] - a[j] - borrow;
        r[j] = (uint32_t)s;
        borrow = (uint32_t)((s >> 32) & 1);
    }
    return borrow;
}

/* 读取第 bit 位（0 = LSB）；x 为 words 个 32 位字（大端） */
static uint32_t bn_bit(const uint32_t *x, int words, int bit)
{
    return (x[words - 1 - (bit >> 5)] >> (bit & 31)) & 1;
}

/* 8×8 字 → 16 字乘积（大端） */
static void bn_mul(const uint32_t a[8], const uint32_t b[8], uint32_t o[16])
{
    int i, j;
    memset(o, 0, 16 * sizeof(uint32_t));
    for (i = 0; i < 8; i++) {
        uint32_t carry = 0;
        for (j = 0; j < 8; j++) {
            uint64_t s = (uint64_t)a[7 - i] * (uint64_t)b[7 - j]
                       + (uint64_t)o[15 - (i + j)] + carry;
            o[15 - (i + j)] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
        }
        {
            uint32_t k = 7 - i;
            while (carry) {
                uint64_t s = (uint64_t)o[k] + carry;
                o[k] = (uint32_t)s;
                carry = (uint32_t)(s >> 32);
                if (k == 0)
                    break;
                k--;
            }
        }
    }
}

/* ---------- 模运算 ---------- */

/* 模加：r = (a + b) mod m */
void sm2_mod_add(const sm2_bn_t *m, const sm2_bn_t *a,
                 const sm2_bn_t *b, sm2_bn_t *r)
{
    uint32_t carry = 0;
    int j;

    for (j = 7; j >= 0; j--) {
        uint64_t s = (uint64_t)a->w[j] + b->w[j] + carry;
        r->w[j] = (uint32_t)s;
        carry = (uint32_t)(s >> 32);
    }
    if (carry) {
        /* (carry:r) = 2^256 + r；减去 m：r = r + (~m + 1) */
        uint32_t c = 1;
        for (j = 7; j >= 0; j--) {
            uint64_t s = (uint64_t)r->w[j] + (~m->w[j] & 0xFFFFFFFFu) + c;
            r->w[j] = (uint32_t)s;
            c = (uint32_t)(s >> 32);
        }
    }
    if (sm2_bn_cmp(r, m) >= 0)
        bn_sub8(r->w, m->w);
}

/* 模减：r = (a - b) mod m */
void sm2_mod_sub(const sm2_bn_t *m, const sm2_bn_t *a,
                 const sm2_bn_t *b, sm2_bn_t *r)
{
    uint32_t borrow = 0;
    int j;

    for (j = 7; j >= 0; j--) {
        uint64_t s = (uint64_t)a->w[j] - b->w[j] - borrow;
        r->w[j] = (uint32_t)s;
        borrow = (uint32_t)((s >> 32) & 1);
    }
    if (borrow) {
        /* 补加 m */
        uint32_t c = 0;
        for (j = 7; j >= 0; j--) {
            uint64_t s = (uint64_t)r->w[j] + m->w[j] + c;
            r->w[j] = (uint32_t)s;
            c = (uint32_t)(s >> 32);
        }
    }
    if (sm2_bn_cmp(r, m) >= 0)
        bn_sub8(r->w, m->w);
}

/* 二进制模约减：512 位乘积 t 对 m 取模得 r（逐位左移比较减） */
void sm2_mod_reduce(const sm2_bn_t *m, const uint32_t t[16], sm2_bn_t *r)
{
    uint32_t rem[8] = {0};
    uint32_t carry = 0; /* 第 256 位溢出位 */
    int i, j;

    /* 二进制模约减：从最高位到最低位逐位移入，
     * 每轮保持 r < m 不变式（r = (carry:rem) 最多 257 位，
     * 左移后减一次 m 即回到 < m）。 */
    for (i = 511; i >= 0; i--) {
        uint32_t c_in = bn_bit(t, 16, i);
        for (j = 7; j >= 0; j--) {
            uint32_t out = rem[j] >> 31;
            rem[j] = (rem[j] << 1) | c_in;
            c_in = out;
        }
        carry = c_in;
        if (carry || sm2_bn_cmp((const sm2_bn_t *)rem, m) >= 0)
            bn_sub8(rem, m->w); /* 减后必 < m < 2^256，carry 归零 */
    }
    memcpy(r, rem, sizeof(rem));
}

/* 模乘：r = (a × b) mod m */
void sm2_mod_mul(const sm2_bn_t *m, const sm2_bn_t *a,
                 const sm2_bn_t *b, sm2_bn_t *r)
{
    uint32_t t[16];
    bn_mul(a->w, b->w, t);
    sm2_mod_reduce(m, t, r);
}

/* 模逆：r = a^(-1) mod m（费马小定理快速幂，m 须为素数）；失败返回 -1 */
int sm2_mod_inv(const sm2_bn_t *m, const sm2_bn_t *a, sm2_bn_t *r)
{
    sm2_bn_t e, base, res;
    int i, j;

    if (sm2_bn_is_zero(a) || sm2_bn_cmp(a, m) >= 0)
        return -1;

    /* e = m - 2 */
    sm2_bn_copy(&e, m);
    {
        uint32_t borrow = 0;
        for (j = 7; j >= 0; j--) {
            uint64_t s = (uint64_t)e.w[j] - ((j == 7) ? 2u : 0u) - borrow;
            e.w[j] = (uint32_t)s;
            borrow = (uint32_t)((s >> 32) & 1);
        }
    }

    sm2_bn_copy(&base, a);
    sm2_bn_zero(&res);
    res.w[7] = 1; /* res = 1 */

    /* 快速幂：res = a^(m-2) mod m */
    for (i = 255; i >= 0; i--) {
        sm2_mod_mul(m, &res, &res, &res);
        if (bn_bit(e.w, 8, i))
            sm2_mod_mul(m, &res, &base, &res);
    }

    if (sm2_bn_is_zero(&res))
        return -1;
    sm2_bn_copy(r, &res);
    return 0;
}

/* ---------- 曲线点运算 ---------- */

/* Jacobian 点倍：r = 2P（a=-3 优化公式）；P=O 时 r=O */
void sm2_ecc_double(const sm2_bn_t *m, const sm2_pt_j *p, sm2_pt_j *r)
{
    sm2_bn_t z2, y2, t, s, u, m3, x3, y3, z3;

    if (sm2_bn_is_zero(&p->z)) {
        sm2_bn_zero(&r->x);
        sm2_bn_zero(&r->y);
        sm2_bn_zero(&r->z);
        return;
    }
    /* z2 = Z1² */
    sm2_mod_mul(m, &p->z, &p->z, &z2);
    /* y2 = Y1² */
    sm2_mod_mul(m, &p->y, &p->y, &y2);
    /* s = 4·X1·Y1² */
    sm2_mod_mul(m, &p->x, &y2, &s);
    sm2_mod_add(m, &s, &s, &s);
    sm2_mod_add(m, &s, &s, &s);
    /* t = X1 - Z2；u = X1 + Z2；m3 = 3·t·u */
    sm2_mod_sub(m, &p->x, &z2, &t);
    sm2_mod_add(m, &p->x, &z2, &u);
    sm2_mod_mul(m, &t, &u, &m3);
    sm2_mod_add(m, &m3, &m3, &u);   /* u = 2·m3 */
    sm2_mod_add(m, &u, &m3, &m3);   /* m3 = 3·m3 */
    /* x3 = M² - 2S */
    sm2_mod_mul(m, &m3, &m3, &x3);
    sm2_mod_add(m, &s, &s, &u);     /* u = 2S */
    sm2_mod_sub(m, &x3, &u, &x3);
    /* y3 = M·(S - X3) - 8·Y1⁴ */
    sm2_mod_sub(m, &s, &x3, &t);    /* t = S - X3 */
    sm2_mod_mul(m, &m3, &t, &u);    /* u = M·(S-X3) */
    sm2_mod_mul(m, &y2, &y2, &y3);  /* y3 = Y1⁴ */
    sm2_mod_add(m, &y3, &y3, &y3);  /* 2·Y1⁴ */
    sm2_mod_add(m, &y3, &y3, &y3);  /* 4·Y1⁴ */
    sm2_mod_add(m, &y3, &y3, &y3);  /* 8·Y1⁴ */
    sm2_mod_sub(m, &u, &y3, &y3);
    /* z3 = 2·Y1·Z1 */
    sm2_mod_mul(m, &p->y, &p->z, &z3);
    sm2_mod_add(m, &z3, &z3, &z3);

    sm2_bn_copy(&r->x, &x3);
    sm2_bn_copy(&r->y, &y3);
    sm2_bn_copy(&r->z, &z3);
}

/* Jacobian + 仿射混合加：r = P + Q（add-2007-bl 公式）；P=O 时 r=Q 转 Jacobian */
void sm2_ecc_add_mixed(const sm2_bn_t *m, const sm2_pt_j *p,
                       const sm2_pt_a *q, sm2_pt_j *r)
{
    sm2_bn_t z1z1, u2, s2, h, hh, i_, j_, v, x3, y3, z3, t;

    if (sm2_bn_is_zero(&p->z)) {
        /* P = O → Q 转 Jacobian（Z=1） */
        sm2_bn_copy(&r->x, &q->x);
        sm2_bn_copy(&r->y, &q->y);
        sm2_bn_zero(&r->z);
        r->z.w[7] = 1;
        return;
    }
    /* Z1Z1 = Z1² */
    sm2_mod_mul(m, &p->z, &p->z, &z1z1);
    /* U2 = x2·Z1Z1 */
    sm2_mod_mul(m, &q->x, &z1z1, &u2);
    /* S2 = y2·Z1·Z1Z1 */
    sm2_mod_mul(m, &p->z, &z1z1, &s2);
    sm2_mod_mul(m, &q->y, &s2, &s2);
    /* H = U2 - X1 */
    sm2_mod_sub(m, &u2, &p->x, &h);
    if (sm2_bn_is_zero(&h)) {
        if (sm2_bn_cmp(&s2, &p->y) == 0) {
            sm2_ecc_double(m, p, r);   /* P == Q */
        } else {
            sm2_bn_zero(&r->x);        /* P + (-P) = O */
            sm2_bn_zero(&r->y);
            sm2_bn_zero(&r->z);
        }
        return;
    }
    /* HH = H²；I = 4·HH；J = H·I */
    sm2_mod_mul(m, &h, &h, &hh);
    sm2_mod_add(m, &hh, &hh, &i_);
    sm2_mod_add(m, &i_, &i_, &i_);
    sm2_mod_mul(m, &h, &i_, &j_);
    /* t = 2·(S2 - Y1) */
    sm2_mod_sub(m, &s2, &p->y, &t);
    sm2_mod_add(m, &t, &t, &t);
    /* V = X1·I */
    sm2_mod_mul(m, &p->x, &i_, &v);
    /* X3 = t² - J - 2V（2V 放 u2，保留原始 V） */
    sm2_mod_mul(m, &t, &t, &x3);
    sm2_mod_sub(m, &x3, &j_, &x3);
    sm2_mod_add(m, &v, &v, &u2);       /* u2 = 2V */
    sm2_mod_sub(m, &x3, &u2, &x3);
    /* Y3 = t·(V - X3) - 2·Y1·J */
    sm2_mod_sub(m, &v, &x3, &v);       /* V - X3 */
    sm2_mod_mul(m, &t, &v, &y3);
    sm2_mod_mul(m, &p->y, &j_, &v);    /* Y1·J */
    sm2_mod_add(m, &v, &v, &v);        /* 2·Y1·J */
    sm2_mod_sub(m, &y3, &v, &y3);
    /* Z3 = (Z1 + H)² - Z1Z1 - HH */
    sm2_mod_add(m, &p->z, &h, &z3);
    sm2_mod_mul(m, &z3, &z3, &z3);
    sm2_mod_sub(m, &z3, &z1z1, &z3);
    sm2_mod_sub(m, &z3, &hh, &z3);

    sm2_bn_copy(&r->x, &x3);
    sm2_bn_copy(&r->y, &y3);
    sm2_bn_copy(&r->z, &z3);
}

/* Jacobian 坐标转仿射：r = p/Z²，r = p/Z³；P=O 时 r=O；失败返回 -1 */
int sm2_ecc_to_affine(const sm2_bn_t *m, const sm2_pt_j *p, sm2_pt_a *r)
{
    sm2_bn_t zi, zi2;

    if (sm2_bn_is_zero(&p->z)) {
        sm2_bn_zero(&r->x);
        sm2_bn_zero(&r->y);
        return 0;
    }
    if (sm2_mod_inv(m, &p->z, &zi) != 0)
        return -1;
    sm2_mod_mul(m, &zi, &zi, &zi2);        /* Z⁻² */
    sm2_mod_mul(m, &p->x, &zi2, &r->x);
    sm2_mod_mul(m, &zi, &zi2, &zi2);       /* Z⁻³ */
    sm2_mod_mul(m, &p->y, &zi2, &r->y);
    return 0;
}

/* 仿射点加：r = P1 + P2（含 P1==P2 加倍；P1=-P2 返回 -1 由调用方处理） */
int sm2_ecc_add_affine(const sm2_bn_t *m, const sm2_pt_a *p1,
                       const sm2_pt_a *p2, sm2_pt_a *r)
{
    sm2_bn_t lam, t1, t2, x3, y3;

    if (sm2_bn_cmp(&p1->x, &p2->x) != 0) {
        /* λ = (y2 - y1)/(x2 - x1) */
        sm2_mod_sub(m, &p2->y, &p1->y, &t1);
        sm2_mod_sub(m, &p2->x, &p1->x, &t2);
        if (sm2_mod_inv(m, &t2, &lam) != 0)
            return -1;
        sm2_mod_mul(m, &t1, &lam, &lam);
    } else {
        /* P == Q：加倍 λ = (3x² + a)/(2y)，a = p-3 → 3(x²-1)/(2y) */
        if (sm2_bn_cmp(&p1->y, &p2->y) != 0 || sm2_bn_is_zero(&p1->y))
            return -1; /* P + (-P) = O，调用方需单独处理 */
        sm2_mod_mul(m, &p1->x, &p1->x, &t1);        /* x² */
        {
            sm2_bn_t one;
            sm2_bn_zero(&one);
            one.w[7] = 1;
            sm2_mod_sub(m, &t1, &one, &t1);         /* x² - 1 */
        }
        sm2_mod_add(m, &t1, &t1, &t2);              /* t2 = 2(x²-1) */
        sm2_mod_add(m, &t2, &t1, &t1);              /* t1 = 3(x²-1) */
        sm2_mod_add(m, &p1->y, &p1->y, &t2);        /* t2 = 2y */
        if (sm2_mod_inv(m, &t2, &lam) != 0)
            return -1;
        sm2_mod_mul(m, &t1, &lam, &lam);
    }
    /* x3 = λ² - x1 - x2 */
    sm2_mod_mul(m, &lam, &lam, &x3);
    sm2_mod_sub(m, &x3, &p1->x, &x3);
    sm2_mod_sub(m, &x3, &p2->x, &x3);
    /* y3 = λ(x1 - x3) - y1 */
    sm2_mod_sub(m, &p1->x, &x3, &t1);
    sm2_mod_mul(m, &lam, &t1, &y3);
    sm2_mod_sub(m, &y3, &p1->y, &y3);

    sm2_bn_copy(&r->x, &x3);
    sm2_bn_copy(&r->y, &y3);
    return 0;
}

/* 仿射标量乘：r = k·P（先验算 P 在曲线上，double-and-add 从高位到低位）；失败返回 -1 */
int sm2_ecc_mul(const sm2_bn_t *m, const sm2_bn_t *k,
                const sm2_pt_a *p, sm2_pt_a *r)
{
    sm2_pt_j acc, t;
    int i;

    /* P 须在曲线上：y² = x³ + a·x + b（mod m，m 为 p） */
    {
        sm2_bn_t a1, a2;
        sm2_mod_mul(m, &p->x, &p->x, &a1);
        sm2_mod_mul(m, &a1, &p->x, &a1);      /* x³ */
        sm2_mod_mul(m, &SM2_A, &p->x, &a2);   /* a·x */
        sm2_mod_add(m, &a1, &a2, &a1);
        sm2_mod_add(m, &a1, &SM2_B, &a1);     /* x³ + ax + b */
        sm2_mod_mul(m, &p->y, &p->y, &a2);    /* y² */
        if (sm2_bn_cmp(&a1, &a2) != 0)
            return -1;
    }

    /* acc = O */
    sm2_bn_zero(&acc.x);
    sm2_bn_zero(&acc.y);
    sm2_bn_zero(&acc.z);

    /* double-and-add（从最高位到最低位） */
    for (i = 255; i >= 0; i--) {
        if (sm2_bn_is_zero(&acc.z)) {
            sm2_bn_zero(&t.x);
            sm2_bn_zero(&t.y);
            sm2_bn_zero(&t.z);
        } else {
            sm2_ecc_double(m, &acc, &t);
        }
        if (bn_bit(k->w, 8, i)) {
            if (sm2_bn_is_zero(&t.z)) {
                sm2_bn_copy(&acc.x, &p->x);
                sm2_bn_copy(&acc.y, &p->y);
                sm2_bn_zero(&acc.z);
                acc.z.w[7] = 1;
            } else {
                sm2_ecc_add_mixed(m, &t, p, &acc);
            }
        } else {
            sm2_bn_copy(&acc.x, &t.x);
            sm2_bn_copy(&acc.y, &t.y);
            sm2_bn_copy(&acc.z, &t.z);
        }
    }

    if (sm2_bn_is_zero(&acc.z)) {
        sm2_bn_zero(&r->x);
        sm2_bn_zero(&r->y);
        return 0; /* k·P = O */
    }
    return sm2_ecc_to_affine(m, &acc, r);
}

/* 基点标量乘：r = k·G（sm2p256v1 基点）；失败返回 -1 */
int sm2_ecc_mul_base(const sm2_bn_t *k, sm2_pt_a *r)
{
    sm2_pt_a g;
    sm2_bn_copy(&g.x, &SM2_GX);
    sm2_bn_copy(&g.y, &SM2_GY);
    return sm2_ecc_mul(&SM2_P, k, &g, r);
}
