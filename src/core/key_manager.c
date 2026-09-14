/* ============================================================
 * KeyManager：密钥创建（经 CryptoHAL）与 PKCS#10 CSR 导出
 * CSR 为自研最小 DER 编码（core/der.c），签名使用 SM2（ZA 在算法层计算）
 * ============================================================ */

#include "km_key.h"
#include "km_log.h"
#include "hal/crypto_hal.h"
#include "der.h"

#include <stdio.h>
#include <string.h>

/* ---------- 算法 OID 编码（DER） ---------- */

static const uint8_t OID_EC_PUBKEY[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};      /* 1.2.840.10045.2.1 */
static const uint8_t OID_SM2_P256[]  = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D}; /* 1.2.156.10197.1.301 */
static const uint8_t OID_SM2_SIGN[]  = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75}; /* 1.2.156.10197.1.501 */

static const uint8_t OID_CN[] = {0x55, 0x04, 0x03};
static const uint8_t OID_O[]  = {0x55, 0x04, 0x0A};
static const uint8_t OID_C[]  = {0x55, 0x04, 0x06};
static const uint8_t OID_ST[] = {0x55, 0x04, 0x08};
static const uint8_t OID_L[]  = {0x55, 0x04, 0x07};
static const uint8_t OID_OU[] = {0x55, 0x04, 0x0B};

/* ---------- 小型 DER 构建器（向后包裹，避免两级缓冲） ---------- */

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
} der_w;

/* 向 DER 构建器追加裸字节；超出容量返回 -1 */
static int w_app_bytes(der_w *w, const uint8_t *d, size_t n)
{
    if (w->len + n > w->cap)
        return -1;
    if (n != 0)
        memcpy(w->buf + w->len, d, n);
    w->len += n;
    return 0;
}

/* 向 DER 构建器追加 TLV 三元组（tag + 长度 + 值） */
static int w_app_tlv(der_w *w, uint8_t tag, const uint8_t *v, size_t n)
{
    uint8_t tmp[9];
    size_t nt = km_der_write_len(tmp, sizeof(tmp), n);
    if (nt == 0 || w->len + 1 + nt + n > w->cap)
        return -1;
    w->buf[w->len] = tag;
    memcpy(w->buf + w->len + 1, tmp, nt);
    if (n != 0)
        memcpy(w->buf + w->len + 1 + nt, v, n);
    w->len += 1 + nt + n;
    return 0;
}

/* 在已构建内容前包裹 TLV 头 */
static int w_wrap(der_w *w, uint8_t tag)
{
    uint8_t tmp[9];
    size_t nt = km_der_write_len(tmp, sizeof(tmp), w->len);
    size_t need = 1 + nt;

    if (nt == 0 || w->len + need > w->cap)
        return -1;
    memmove(w->buf + need, w->buf, w->len);
    w->buf[0] = tag;
    memcpy(w->buf + 1, tmp, nt);
    w->len += need;
    return 0;
}

/* 解析 subject 为 RDN 序列并写入 Name（最小编码：支持 CN/O/C/ST/L/OU） */
/* 按 RDN 键名返回 DER 编码的 X.500 属性 OID；不支持的键返回 NULL */
static const uint8_t *oid_for_key(const char *key, size_t klen)
{
    if (klen == 2 && memcmp(key, "CN", 2) == 0) return OID_CN;
    if (klen == 1 && memcmp(key, "O", 1) == 0)  return OID_O;
    if (klen == 1 && memcmp(key, "C", 1) == 0)  return OID_C;
    if (klen == 2 && memcmp(key, "ST", 2) == 0) return OID_ST;
    if (klen == 1 && memcmp(key, "L", 1) == 0)  return OID_L;
    if (klen == 2 && memcmp(key, "OU", 2) == 0) return OID_OU;
    return NULL;
}

/* 解析 "CN=x,O=y,C=z" 形式的 subject 并编码为 DER Name（SEQUENCE OF RDN）；失败返回 -1 */
static int build_subject(der_w *w, const char *subject)
{
    const char *p = subject;

    if (subject == NULL || subject[0] == '\0') {
        /* 空 Name：SEQUENCE {} */
        return w_wrap(w, 0x30);
    }
    while (*p != '\0') {
        const char *comma, *eq;
        const char *val, *vend;
        size_t klen;
        const uint8_t *oid;
        size_t vlen;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        comma = strchr(p, ',');
        eq = strchr(p, '=');
        if (eq == NULL || (comma != NULL && comma < eq))
            return -1;
        klen = (size_t)(eq - p);
        oid = oid_for_key(p, klen);
        if (oid == NULL)
            return -1;
        val = eq + 1;
        while (*val == ' ' || *val == '\t') val++;
        vend = (comma != NULL) ? comma : (p + strlen(p));
        while (vend > val && (vend[-1] == ' ' || vend[-1] == '\t')) vend--;
        vlen = (size_t)(vend - val);

        if (vlen > 256 || vlen == 0)
            return -1;

        /* RDN = SET OF ATV；ATV = SEQUENCE { OID, UTF8String }，独立构建后追加 */
        {
            uint8_t rdn_buf[512];
            der_w r;
            r.buf = rdn_buf;
            r.cap = sizeof(rdn_buf);
            r.len = 0;
            if (w_app_tlv(&r, 0x06, oid, 3) != 0)   /* subject 属性 OID 均为 3 字节 */
                return -1;
            if (w_app_tlv(&r, 0x0C, (const uint8_t *)val, vlen) != 0)
                return -1;
            if (w_wrap(&r, 0x30) != 0)              /* ATV */
                return -1;
            if (w_wrap(&r, 0x31) != 0)              /* SET */
                return -1;
            if (w_app_bytes(w, r.buf, r.len) != 0)
                return -1;
        }

        p = (comma != NULL) ? comma + 1 : vend;
    }
    return w_wrap(w, 0x30); /* Name = SEQUENCE OF RDN */
}

/* ---------- 公共接口 ---------- */

/* 创建指定类型的 SM2 密钥对并经 HAL 加密落盘，输出 24 位十六进制 key_id */
km_err_t km_key_create(key_type_t type, char key_id[KM_KEY_ID_LEN])
{
    const CryptoHAL *hal = km_hal_get();
    int rc;

    if (hal == NULL || hal->key_gen_store == NULL)
        return KM_ERR_INIT_FAIL;
    if (type < KEY_TYPE_ROOT || type > KEY_TYPE_ENC || key_id == NULL)
        return KM_ERR_BAD_PARAM;

    rc = hal->key_gen_store((int)type, key_id);
    if (rc != 0)
        return KM_ERR_CRYPTO;

    km_auditlog_write(EVT_KEY_GENERATED, "sm2 key generated");
    km_oplog_write(LOG_LEVEL_INFO, "key: sm2 key created, type=%d id=%s", (int)type, key_id);
    return KM_ERR_OK;
}

/* 导出指定密钥的 PKCS#10 CSR（PEM 格式）：自研 DER 编码 + SM2 签名 */
km_err_t km_key_export_csr(const char *key_id,
                           const char *subject,
                           char *csr_pem,
                           size_t *csr_len)
{
    const CryptoHAL *hal = km_hal_get();
    static const int type_order[3] = { KEY_TYPE_SIGN, KEY_TYPE_ENC, KEY_TYPE_ROOT };
    uint8_t pri[KM_SM2_PRIKEY_LEN], pub[KM_SM2_PUBKEY_LEN];
    uint8_t sig[KM_SM2_SIG_LEN];
    uint8_t der[2048];
    der_w w;
    char b64[2800];
    size_t b64_len;
    size_t pem_need;
    int i, loaded = 0;

    if (hal == NULL || hal->key_load == NULL || hal->sm2_sign == NULL)
        return KM_ERR_INIT_FAIL;
    if (key_id == NULL || csr_pem == NULL || csr_len == NULL)
        return KM_ERR_BAD_PARAM;

    /* 按 SIGN → ENC → ROOT 顺序加载密钥（取首个可用） */
    for (i = 0; i < 3; i++) {
        if (hal->key_load(type_order[i], key_id, pri, pub) == 0) {
            loaded = 1;
            break;
        }
    }
    if (!loaded)
        return KM_ERR_KEY_NOT_FOUND;

    w.buf = der;
    w.cap = sizeof(der);
    w.len = 0;

    /* certificationRequestInfo = SEQUENCE { version, subject, subjectPKInfo, attributes } */
    /* 1) version = INTEGER 0 */
    {
        const uint8_t zero = 0x00;
        if (w_app_tlv(&w, 0x02, &zero, 1) != 0)
            return KM_ERR_BUF_TOO_SMALL;
    }
    /* 2) subject Name */
    if (build_subject(&w, subject) != 0)
        return KM_ERR_FORMAT;
    /* 3) subjectPKInfo = SEQUENCE { AlgorithmIdentifier, BIT STRING pubkey } */
    {
        /* BIT STRING: unused_bits=0 || pubkey */
        uint8_t bit_head = 0x00;
        if (w_app_bytes(&w, &bit_head, 1) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        if (w_app_bytes(&w, pub, sizeof(pub)) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        if (w_wrap(&w, 0x03) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        /* AlgorithmIdentifier = SEQUENCE { OID ecPublicKey, OID sm2p256v1 } */
        if (w_app_tlv(&w, 0x06, OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY)) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        if (w_app_tlv(&w, 0x06, OID_SM2_P256, sizeof(OID_SM2_P256)) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        if (w_wrap(&w, 0x30) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        if (w_wrap(&w, 0x30) != 0)
            return KM_ERR_BUF_TOO_SMALL;
    }
    /* 4) attributes [0] IMPLICIT SET OF → 空 */
    if (w_wrap(&w, 0xA0) != 0)
        return KM_ERR_BUF_TOO_SMALL;
    /* 包 certificationRequestInfo */
    if (w_wrap(&w, 0x30) != 0)
        return KM_ERR_BUF_TOO_SMALL;

    /* 对 tbs（certificationRequestInfo）签名 */
    if (hal->sm2_sign(pri, w.buf, w.len, sig) != 0) {
        memset(pri, 0, sizeof(pri));
        return KM_ERR_CRYPTO;
    }
    memset(pri, 0, sizeof(pri));

    /* signatureAlgorithm = SEQUENCE { OID sm2signWithSM3 } */
    if (w_app_tlv(&w, 0x06, OID_SM2_SIGN, sizeof(OID_SM2_SIGN)) != 0)
        return KM_ERR_BUF_TOO_SMALL;
    if (w_wrap(&w, 0x30) != 0)
        return KM_ERR_BUF_TOO_SMALL;

    /* signature = BIT STRING { unused=0, r||s } */
    {
        uint8_t bit_head = 0x00;
        if (w_app_bytes(&w, &bit_head, 1) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        if (w_app_bytes(&w, sig, sizeof(sig)) != 0)
            return KM_ERR_BUF_TOO_SMALL;
        if (w_wrap(&w, 0x03) != 0)
            return KM_ERR_BUF_TOO_SMALL;
    }
    /* CertificationRequest */
    if (w_wrap(&w, 0x30) != 0)
        return KM_ERR_BUF_TOO_SMALL;

    /* base64 → PEM 包络 */
    b64_len = km_base64_encode(w.buf, w.len, b64, sizeof(b64));
    if (b64_len == 0)
        return KM_ERR_BUF_TOO_SMALL;
    pem_need = strlen("-----BEGIN CERTIFICATE REQUEST-----\n") +
               b64_len +
               strlen("\n-----END CERTIFICATE REQUEST-----\n") + 1;
    if (pem_need > *csr_len)
        return KM_ERR_BUF_TOO_SMALL;

    {
        size_t off = 0;
        static const char beg[] = "-----BEGIN CERTIFICATE REQUEST-----\n";
        static const char end[] = "\n-----END CERTIFICATE REQUEST-----\n";
        memcpy(csr_pem + off, beg, sizeof(beg) - 1); off += sizeof(beg) - 1;
        memcpy(csr_pem + off, b64, b64_len); off += b64_len;
        memcpy(csr_pem + off, end, sizeof(end)); off += sizeof(end);
        csr_pem[off - 1] = '\0';
        *csr_len = off;
    }

    km_oplog_write(LOG_LEVEL_INFO, "key: PKCS#10 CSR exported, id=%s", key_id);
    return KM_ERR_OK;
}
