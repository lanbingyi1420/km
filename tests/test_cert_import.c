#include "km_test.h"
#include "km_api.h"
#include "core/der.h"
#include "core/cert_validator.h"
#include "hal/crypto_hal.h"
#include "sm2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#define TEST_MASTER "km-master-key-for-unit-test-0123456789"

/* 算法 OID（与 key_manager.c 一致的 DER 编码） */
static const uint8_t OID_EC_PUBKEY[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static const uint8_t OID_SM2_P256[]  = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D};
static const uint8_t OID_SM2_SIGN[]  = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75};
static const uint8_t OID_CN[]        = {0x55, 0x04, 0x03};

static void ensure_dir(const char *d)
{
#ifdef _WIN32
    _mkdir(d);
#else
    mkdir(d, 0700);
#endif
}

static void ap(uint8_t *b, size_t *o, size_t cap, const uint8_t *d, size_t n)
{
    if (*o + n <= cap) {
        memcpy(b + *o, d, n);
        *o += n;
    }
}

static size_t t_o(uint8_t *b, size_t cap, const uint8_t *oid, size_t n)
{
    return km_der_write_tlv(b, cap, 0x06, oid, n);
}

static size_t t_utf8(uint8_t *b, size_t cap, const char *s)
{
    return km_der_write_tlv(b, cap, 0x0C, (const uint8_t *)s, strlen(s));
}

static size_t t_utc(uint8_t *b, size_t cap, const char *s)
{
    return km_der_write_tlv(b, cap, 0x17, (const uint8_t *)s, strlen(s));
}

static size_t t_bits(uint8_t *b, size_t cap, const uint8_t *v, size_t n)
{
    uint8_t tmp[200];
    tmp[0] = 0x00;
    memcpy(tmp + 1, v, n);
    return km_der_write_tlv(b, cap, 0x03, tmp, n + 1);
}

/* Name = SEQUENCE { SET { SEQUENCE { OID CN, UTF8String } } } */
static size_t build_name(uint8_t *out, size_t cap, const char *cn)
{
    uint8_t atv[128];
    size_t al = 0;
    uint8_t rdn[160], set[200];
    size_t rl, sl;
    al += t_o(atv + al, sizeof(atv) - al, OID_CN, sizeof(OID_CN));
    al += t_utf8(atv + al, sizeof(atv) - al, cn);
    rl = km_der_write_tlv(rdn, sizeof(rdn), 0x30, atv, al);
    sl = km_der_write_tlv(set, sizeof(set), 0x31, rdn, rl);
    return km_der_write_tlv(out, cap, 0x30, set, sl);
}

/* AlgorithmIdentifier = SEQUENCE { OID } */
static size_t build_alg(uint8_t *out, size_t cap, const uint8_t *oid, size_t olen)
{
    uint8_t alg[96];
    size_t al = t_o(alg, sizeof(alg), oid, olen);
    return km_der_write_tlv(out, cap, 0x30, alg, al);
}

/* 构建结构合法的最小 X.509 证书（SM2 算法标识）
 * pub 为 64B SM2 公钥（NULL 时使用固定占位字节）；
 * pri 为签名私钥（非 NULL 时对 tbsCertificate 做真实 SM2 签名，否则签名占位）。 */
static void build_cert(uint8_t *cert, size_t *cert_len, const char *cn,
                       const uint8_t *pub, const uint8_t *pri)
{
    static const uint8_t stub_pub[KM_SM2_PUBKEY_LEN] = {
        0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39
    };
    static const uint8_t stub_sig[KM_SM2_SIG_LEN] = { 0x77 };
    const uint8_t *pubk = (pub != NULL) ? pub : stub_pub;
    uint8_t sigbuf[KM_SM2_SIG_LEN];
    const uint8_t *sigk;
    const uint8_t one = 0x01;
    uint8_t b[2048];
    size_t o = 0;

    /* serialNumber = INTEGER 1 */
    {
        uint8_t serial[16];
        size_t sl = km_der_write_tlv(serial, sizeof(serial), 0x02, &one, 1);
        ap(b, &o, sizeof(b), serial, sl);
    }
    /* signature = AlgorithmIdentifier { sm2signWithSM3 } */
    {
        uint8_t alg_seq[112];
        size_t asl = build_alg(alg_seq, sizeof(alg_seq), OID_SM2_SIGN, sizeof(OID_SM2_SIGN));
        ap(b, &o, sizeof(b), alg_seq, asl);
    }
    /* issuer = Name */
    {
        uint8_t name[256];
        size_t nl = build_name(name, sizeof(name), cn);
        ap(b, &o, sizeof(b), name, nl);
    }
    /* validity = SEQUENCE { UTCTime, UTCTime }（2024-01-01 ~ 2034-12-31 UTC） */
    {
        uint8_t vd[64];
        size_t vl = 0;
        uint8_t vseq[80];
        size_t vsl;
        vl += t_utc(vd + vl, sizeof(vd) - vl, "240101000000Z");
        vl += t_utc(vd + vl, sizeof(vd) - vl, "341231235959Z");
        vsl = km_der_write_tlv(vseq, sizeof(vseq), 0x30, vd, vl);
        ap(b, &o, sizeof(b), vseq, vsl);
    }
    /* subject = Name */
    {
        uint8_t name[256];
        size_t nl = build_name(name, sizeof(name), cn);
        ap(b, &o, sizeof(b), name, nl);
    }
    /* subjectPublicKeyInfo = SEQUENCE { AlgorithmIdentifier, BIT STRING } */
    {
        uint8_t alg2[160];
        size_t a2 = 0;
        uint8_t alg2_seq[176];
        size_t a2l;
        uint8_t bits[128];
        size_t bl;
        uint8_t spki[340];
        size_t so = 0;
        uint8_t spki_seq[360];
        size_t ssl;
        /* AlgorithmIdentifier = SEQUENCE { OID ecPublicKey, OID sm2p256v1 } */
        a2 += t_o(alg2 + a2, sizeof(alg2) - a2, OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY));
        a2 += t_o(alg2 + a2, sizeof(alg2) - a2, OID_SM2_P256, sizeof(OID_SM2_P256));
        a2l = km_der_write_tlv(alg2_seq, sizeof(alg2_seq), 0x30, alg2, a2);
        bl = t_bits(bits, sizeof(bits), pubk, KM_SM2_PUBKEY_LEN);
        ap(spki, &so, sizeof(spki), alg2_seq, a2l);
        ap(spki, &so, sizeof(spki), bits, bl);
        ssl = km_der_write_tlv(spki_seq, sizeof(spki_seq), 0x30, spki, so);
        ap(b, &o, sizeof(b), spki_seq, ssl);
    }

    /* tbs = SEQUENCE { 上述字段 }；随后用 pri（若给定）对 tbsCertificate 做真实 SM2 签名 */
    {
        uint8_t tbs_seq[2100];
        size_t tbs_len = km_der_write_tlv(tbs_seq, sizeof(tbs_seq), 0x30, b, o);
        /* signatureAlgorithm */
        uint8_t sigalg_seq[112];
        size_t sal = build_alg(sigalg_seq, sizeof(sigalg_seq), OID_SM2_SIGN, sizeof(OID_SM2_SIGN));
        /* signatureValue = BIT STRING：真实签名或固定占位 */
        if (pri != NULL) {
            if (sm2_sign(pri, tbs_seq, tbs_len, sigbuf) != 0)
                memset(sigbuf, 0x77, sizeof(sigbuf));
            sigk = sigbuf;
        } else {
            sigk = stub_sig;
        }
        uint8_t sigbits[96];
        size_t sbl = t_bits(sigbits, sizeof(sigbits), sigk, KM_SM2_SIG_LEN);
        /* Certificate = SEQUENCE { tbs, sigAlg, sigValue } */
        {
            uint8_t out[2400];
            size_t co = 0;
            ap(out, &co, sizeof(out), tbs_seq, tbs_len);
            ap(out, &co, sizeof(out), sigalg_seq, sal);
            ap(out, &co, sizeof(out), sigbits, sbl);
            *cert_len = km_der_write_tlv(cert, 4096, 0x30, out, co);
        }
    }
}

void test_cert_import(void)
{
    km_oplog_cfg_t ocfg;
    uint8_t der[4096];
    size_t der_len = 0;
    km_x509_t cert;
    char pem[4096];
    size_t pem_len;
    size_t b64_len;
    char path[512];
    FILE *fp;

    ensure_dir("out");
#ifdef _WIN32
    _putenv_s("KM_MASTER_KEY", TEST_MASTER);
    _putenv_s(KM_CERT_DIR_ENV, "out/testcerts");
#else
    setenv("KM_MASTER_KEY", TEST_MASTER, 1);
    setenv(KM_CERT_DIR_ENV, "out/testcerts", 1);
#endif

    memset(&ocfg, 0, sizeof(ocfg));
    ocfg.level = LOG_LEVEL_ERROR;
    ocfg.console = 1;
    ocfg.to_file = 0;
    KM_TEST_ASSERT_EQ_INT(km_log_init2("out/oplog_cert", "out/audit_cert", &ocfg), KM_ERR_OK);

    /* ---------- Base64 往返 ---------- */
    {
        const uint8_t in[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        char b64[64];
        uint8_t back[64];
        size_t olen = 0;
        size_t bl = km_base64_encode(in, sizeof(in), b64, sizeof(b64));
        KM_TEST_ASSERT(bl > 0);
        KM_TEST_ASSERT_EQ_INT(km_base64_decode(b64, bl, back, sizeof(back), &olen), 0);
        KM_TEST_ASSERT_EQ_INT((int)olen, (int)sizeof(in));
        KM_TEST_ASSERT(memcmp(in, back, sizeof(in)) == 0);
    }

    /* ---------- DER TLV 读取 ---------- */
    {
        size_t off = 0;
        uint8_t tag;
        const uint8_t *v;
        size_t vlen;
        const uint8_t seq[] = {0x30, 0x0A, 0x02, 0x01, 0x01, 0x0C, 0x05, 'h', 'e', 'l', 'l', 'o'};
        KM_TEST_ASSERT_EQ_INT(km_der_read_tlv(seq, sizeof(seq), &off, &tag, &v, &vlen), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT(tag, 0x30);
        KM_TEST_ASSERT_EQ_INT((int)vlen, 10);
    }

    /* ---------- 构造证书 → PEM → 解析 ---------- */
    build_cert(der, &der_len, "KM-Device", NULL, NULL);
    KM_TEST_ASSERT(der_len > 40);

    {
        static const char beg[] = "-----BEGIN CERTIFICATE-----\n";
        static const char end[] = "\n-----END CERTIFICATE-----\n";
        size_t beg_len = sizeof(beg) - 1;
        size_t end_len = sizeof(end) - 1;
        memcpy(pem, beg, beg_len);
        b64_len = km_base64_encode(der, der_len, pem + beg_len, sizeof(pem) - beg_len);
        KM_TEST_ASSERT(b64_len > 0);
        memcpy(pem + beg_len + b64_len, end, end_len);
        pem_len = beg_len + b64_len + end_len;
        pem[pem_len] = '\0';
    }

    /* PEM → DER 往返 */
    {
        uint8_t der2[4096];
        size_t der2_len = 0;
        KM_TEST_ASSERT_EQ_INT(km_pem_to_der(pem, pem_len,
                                            "-----BEGIN CERTIFICATE-----",
                                            "-----END CERTIFICATE-----",
                                            der2, sizeof(der2), &der2_len), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)der2_len, (int)der_len);
        KM_TEST_ASSERT(memcmp(der2, der, der_len) == 0);
    }

    /* X.509 解析与有效期 */
    KM_TEST_ASSERT_EQ_INT(km_x509_parse(der, der_len, &cert), KM_ERR_OK);
    KM_TEST_ASSERT(cert.has_validity);
    KM_TEST_ASSERT(cert.has_pubkey);
    KM_TEST_ASSERT(strstr(cert.subject, "KM-Device") != NULL);
    KM_TEST_ASSERT_EQ_INT((int)(cert.not_before / 86400), 19723); /* 2024-01-01 */
    KM_TEST_ASSERT_EQ_INT((int)(cert.not_after / 86400), 23740);  /* 2034-12-31 */
    KM_TEST_ASSERT_EQ_INT(km_x509_valid_at(&cert, (int64_t)1704067200), 1); /* 2024-01-01 */
    KM_TEST_ASSERT_EQ_INT(km_x509_valid_at(&cert, (int64_t)2051193600), 1); /* 2034-12-31 00:00:00 */
    KM_TEST_ASSERT_EQ_INT(km_x509_valid_at(&cert, (int64_t)2051222400), 0); /* 2035-01-01（已过期） */

    /* ---------- 根证书导入（信任锚，结构合法即存） ---------- */
    ensure_dir("out/testcerts");
    KM_TEST_ASSERT_EQ_INT(km_cert_import_root(pem, pem_len), KM_ERR_OK);
    snprintf(path, sizeof(path), "%s/root.crt", getenv(KM_CERT_DIR_ENV));
    fp = fopen(path, "rb");
    KM_TEST_ASSERT(fp != NULL);
    if (fp != NULL)
        fclose(fp);

    /* ---------- 设备证书导入：真实 SM2 签名链 ---------- */
    {
        static const char beg[] = "-----BEGIN CERTIFICATE-----\n";
        static const char end[] = "\n-----END CERTIFICATE-----\n";
        size_t beg_len = sizeof(beg) - 1;
        size_t end_len = sizeof(end) - 1;
        soft_crypto_cfg_t cfg;
        km_err_t rc;
        uint8_t r_pub[KM_SM2_PUBKEY_LEN], r_pri[KM_SM2_PRIKEY_LEN];
        uint8_t d_pub[KM_SM2_PUBKEY_LEN], d_pri[KM_SM2_PRIKEY_LEN];
        uint8_t root_der[4096], dev_der[4096];
        size_t root_der_len = 0, dev_der_len = 0;
        char root_pem[4096], dev_pem[4096];
        size_t root_pem_len = 0, dev_pem_len = 0;

        cfg.key_dir = "out/testkeys";
        cfg.master_key_env = "KM_MASTER_KEY";
        KM_TEST_ASSERT_EQ_INT(km_hal_init(CRYPTO_PROVIDER_SOFT, &cfg), KM_ERR_OK);

        /* 根密钥对 + 自签名根证书；设备密钥对 + 根私钥签名的设备证书 */
        KM_TEST_ASSERT_EQ_INT(sm2_gen_keypair(r_pub, r_pri), 0);
        build_cert(root_der, &root_der_len, "KM-Root", r_pub, r_pri);
        KM_TEST_ASSERT(root_der_len > 40);
        KM_TEST_ASSERT_EQ_INT(sm2_gen_keypair(d_pub, d_pri), 0);
        build_cert(dev_der, &dev_der_len, "KM-Device", d_pub, r_pri);
        KM_TEST_ASSERT(dev_der_len > 40);

        /* DER → PEM 工具 */
        root_pem_len = 0;
        {
            size_t b64;
            memcpy(root_pem, beg, beg_len);
            b64 = km_base64_encode(root_der, root_der_len,
                                   root_pem + beg_len, sizeof(root_pem) - beg_len);
            KM_TEST_ASSERT(b64 > 0);
            memcpy(root_pem + beg_len + b64, end, end_len);
            root_pem_len = beg_len + b64 + end_len;
            root_pem[root_pem_len] = '\0';
        }
        dev_pem_len = 0;
        {
            size_t b64;
            memcpy(dev_pem, beg, beg_len);
            b64 = km_base64_encode(dev_der, dev_der_len,
                                   dev_pem + beg_len, sizeof(dev_pem) - beg_len);
            KM_TEST_ASSERT(b64 > 0);
            memcpy(dev_pem + beg_len + b64, end, end_len);
            dev_pem_len = beg_len + b64 + end_len;
            dev_pem[dev_pem_len] = '\0';
        }

        /* 先导入根证书（信任锚），再用根公钥验签设备证书 */
        KM_TEST_ASSERT_EQ_INT(km_cert_import_root(root_pem, root_pem_len), KM_ERR_OK);
        rc = km_cert_import_device(dev_pem, dev_pem_len);
        KM_TEST_ASSERT_EQ_INT(rc, KM_ERR_OK);

        /* 负面：篡改设备证书签名（改签名末字节）→ 验签失败被拒 */
        dev_der[dev_der_len - 1] ^= 0x01;
        {
            size_t b64;
            memcpy(dev_pem, beg, beg_len);
            b64 = km_base64_encode(dev_der, dev_der_len,
                                   dev_pem + beg_len, sizeof(dev_pem) - beg_len);
            KM_TEST_ASSERT(b64 > 0);
            memcpy(dev_pem + beg_len + b64, end, end_len);
            dev_pem_len = beg_len + b64 + end_len;
            dev_pem[dev_pem_len] = '\0';
        }
        rc = km_cert_import_device(dev_pem, dev_pem_len);
        KM_TEST_ASSERT_EQ_INT(rc, KM_ERR_CERT_INVALID);

        km_hal_deinit();
    }

    km_log_deinit();
}
