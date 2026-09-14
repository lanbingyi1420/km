/* ============================================================
 * CertValidator：PEM/DER 解析、有效期检查、SM2 验签链（最小实现）
 * 零第三方依赖：自研 base64/DER TLV 解析（core/der.c）
 * ============================================================ */

#include "cert_validator.h"
#include "der.h"
#include "hal/crypto_hal.h"
#include "km_log.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

/* ---------- 内部工具 ---------- */

/* 创建证书目录（Windows: _mkdir / Linux: mkdir 0700） */
static void cert_mkdir(const char *path)
{
#ifdef _WIN32
    _mkdir(path);
#else
    mkdir(path, 0700);
#endif
}

/* 返回证书存储目录（KM_CERT_DIR_ENV 环境变量优先，否则编译期默认路径） */
static const char *cert_dir(void)
{
    static char buf[256];
    const char *env = getenv(KM_CERT_DIR_ENV);
    if (env != NULL && env[0] != '\0') {
        strncpy(buf, env, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        return buf;
    }
    return KM_CERT_DEFAULT_DIR;
}

/* 读取整个文件到 buf（NUL 结尾），返回文件字节数；失败返回 -1 */
static int read_file_all(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    if (len != NULL)
        *len = n;
    return 0;
}

/* 公历日期 → 1970-01-01 起的天数（Howard Hinnant civil algorithm） */
static int64_t days_from_civil(int y, int m, int d)
{
    y -= (m <= 2);
    {
        int64_t era = (y >= 0 ? y : y - 399) / 400;
        unsigned yoe = (unsigned)(y - (int)(era * 400));
        unsigned doy = (153u * (m + (m > 2 ? -3 : 9)) + 2) / 5 + (unsigned)(d - 1);
        unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + (int64_t)doe - 719468;
    }
}

/* 解析 ASN.1 Time（UTCTime / GeneralizedTime，均要求 Z 结尾）为 Unix 秒 */
static int parse_time(const uint8_t *v, size_t vlen, int64_t *out)
{
    int y, mo, d, h, mi, s;
    int idx = 0;

    if (vlen < 13 || v[vlen - 1] != 'Z')
        return -1;
    if (vlen == 13) { /* UTCTime: YYMMDDHHMMSSZ */
        y = (v[0] - '0') * 10 + (v[1] - '0');
        if (y < 50) y += 2000; else y += 1900;
        idx = 2;
    } else if (vlen == 15) { /* GeneralizedTime: YYYYMMDDHHMMSSZ */
        y = (v[0] - '0') * 1000 + (v[1] - '0') * 100 +
            (v[2] - '0') * 10 + (v[3] - '0');
        idx = 4;
    } else {
        return -1;
    }
    mo = (v[idx] - '0') * 10 + (v[idx + 1] - '0'); idx += 2;
    d  = (v[idx] - '0') * 10 + (v[idx + 1] - '0'); idx += 2;
    h  = (v[idx] - '0') * 10 + (v[idx + 1] - '0'); idx += 2;
    mi = (v[idx] - '0') * 10 + (v[idx + 1] - '0'); idx += 2;
    s  = (v[idx] - '0') * 10 + (v[idx + 1] - '0'); idx += 2;

    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60)
        return -1;
    *out = days_from_civil(y, mo, d) * 86400 +
           (int64_t)h * 3600 + (int64_t)mi * 60 + s;
    return 0;
}

/* 解析 Name（RDNSequence），提取 CN / O 拼接为 "CN=.., O=.." */
static int parse_name(const uint8_t *v, size_t vlen, char *out, size_t cap)
{
    size_t off = 0;
    char   cn[128] = "";
    char   o[128]  = "";
    size_t cn_len = 0, o_len = 0;

    out[0] = '\0';
    /* v 为 Name 的内容（RDNSequence，不含 SEQUENCE 头） */
    {
        /* RDNSequence: 若干 RDN（每个 RDN = SET） */
        while (off < vlen) {
            uint8_t rtag;
            const uint8_t *rval;
            size_t rlen, roff = off;
            if (km_der_read_tlv(v, vlen, &roff, &rtag, &rval, &rlen) != KM_ERR_OK)
                return -1;
            if (rtag != 0x31) /* SET OF AttributeTypeAndValue */
                return -1;
            {
                size_t ao = 0;
                /* 每个 ATV = SEQUENCE { OID, value }，取第一个即可 */
                while (ao < rlen) {
                    uint8_t atag;
                    const uint8_t *aval;
                    size_t alen, aoff = ao;
                    if (km_der_read_tlv(rval, rlen, &aoff, &atag, &aval, &alen) != KM_ERR_OK)
                        break;
                    ao = aoff;
                    if (atag != 0x30)
                        continue;
                    /* OID + value */
                    {
                        uint8_t otag;
                        const uint8_t *oid;
                        size_t olen2, oo = 0;
                        const uint8_t *txt;
                        size_t tlen;
                        if (km_der_read_tlv(aval, alen, &oo, &otag, &oid, &olen2) != KM_ERR_OK)
                            continue;
                        {
                            size_t vv = oo;
                            uint8_t vtag;
                            const uint8_t *vval;
                            size_t vvlen;
                            if (km_der_read_tlv(aval, alen, &vv, &vtag, &vval, &vvlen) != KM_ERR_OK)
                                continue;
                            txt = vval;
                            tlen = vvlen;
                        }
                        /* CN = 2.5.4.3 → {0x55,0x04,0x03}；O = 2.5.4.10 → {0x55,0x04,0x0A} */
                        if (olen2 == 3 && oid[0] == 0x55 && oid[1] == 0x04) {
                            size_t n = tlen < sizeof(cn) - 1 ? tlen : sizeof(cn) - 1;
                            if (oid[2] == 0x03) {
                                memcpy(cn, txt, n); cn[n] = '\0'; cn_len = n;
                            } else if (oid[2] == 0x0A) {
                                memcpy(o, txt, n); o[n] = '\0'; o_len = n;
                            }
                        }
                    }
                }
            }
            off = roff;
        }
    }

    {
        size_t n = 0;
        if (cn_len > 0) {
            n += (size_t)snprintf(out + n, cap > n ? cap - n : 0, "CN=%s", cn);
        }
        if (o_len > 0) {
            if (n > 0)
                n += (size_t)snprintf(out + n, cap > n ? cap - n : 0, ", ");
            n += (size_t)snprintf(out + n, cap > n ? cap - n : 0, "O=%s", o);
        }
    }
    return 0;
}

/* 解析 subjectPublicKeyInfo 提取 SM2 公钥 */
static int parse_spki(const uint8_t *v, size_t vlen, uint8_t *pub, size_t *pub_len)
{
    size_t off = 0;
    uint8_t tag;
    const uint8_t *val;
    size_t vlen2;

    /* v 为 subjectPublicKeyInfo 内容：AlgorithmIdentifier + BIT STRING */
    if (km_der_read_tlv(v, vlen, &off, &tag, &val, &vlen2) != KM_ERR_OK || tag != 0x30)
        return -1; /* AlgorithmIdentifier */
    if (km_der_read_tlv(v, vlen, &off, &tag, &val, &vlen2) != KM_ERR_OK || tag != 0x03)
        return -1; /* BIT STRING */
    if (vlen2 < 1 + KM_SM2_PUBKEY_LEN || val[0] != 0) /* unused_bits 必须为 0 */
        return -1;
    memcpy(pub, val + 1, KM_SM2_PUBKEY_LEN);
    *pub_len = KM_SM2_PUBKEY_LEN;
    return 0;
}

/* ---------- 公开解析接口 ---------- */

/* 长度限定的子串搜索：在 hay[0..hay_len) 内查找 needle；
 * 找到返回其偏移，未找到返回 hay_len（避免依赖 '\0' 结尾的 strstr 越界） */
static size_t memfind(const uint8_t *hay, size_t hay_len,
                      const char *needle, size_t nlen)
{
    size_t i;

    if (hay == NULL || needle == NULL || nlen == 0 || nlen > hay_len)
        return hay_len;
    for (i = 0; i + nlen <= hay_len; i++) {
        if (hay[i] == (uint8_t)needle[0] &&
            memcmp(hay + i, needle, nlen) == 0)
            return i;
    }
    return hay_len;
}

/* 从 PEM 文本提取 BEGIN/END 标记间的 base64 并解码为 DER；失败返回 KM_ERR_FORMAT。
 * 长度限定解析：不要求 PEM 以 '\0' 结尾，可零拷贝处理 TLV/文件块数据 */
km_err_t km_pem_to_der(const char *pem, size_t len,
                       const char *begin_marker, const char *end_marker,
                       uint8_t *der, size_t cap, size_t *der_len)
{
    const uint8_t *base;
    size_t b_len, e_len, b_off, e_off;

    if (pem == NULL || der == NULL || der_len == NULL)
        return KM_ERR_BAD_PARAM;

    b_len = strlen(begin_marker);
    e_len = strlen(end_marker);
    b_off = memfind((const uint8_t *)pem, len, begin_marker, b_len);
    if (b_off == len)
        return KM_ERR_FORMAT;
    base = (const uint8_t *)pem + b_off + b_len;
    e_off = memfind(base, len - b_off - b_len, end_marker, e_len);
    if (e_off == len - b_off - b_len)
        return KM_ERR_FORMAT;

    if (km_base64_decode((const char *)base, e_off, der, cap, der_len) != 0)
        return KM_ERR_FORMAT;
    return KM_ERR_OK;
}

/* 解析 X.509 证书 DER：提取 tbs/签名/有效期/issuer/subject/公钥；失败返回 KM_ERR_FORMAT */
km_err_t km_x509_parse(const uint8_t *der, size_t len, km_x509_t *cert)
{
    size_t off = 0;
    size_t tbs_off = 0;
    uint8_t tag;
    const uint8_t *val;
    size_t vlen;

    if (der == NULL || cert == NULL)
        return KM_ERR_BAD_PARAM;
    memset(cert, 0, sizeof(*cert));

    /* Certificate = SEQUENCE { tbs, sigAlg, sigValue } */
    if (km_der_read_tlv(der, len, &off, &tag, &val, &vlen) != KM_ERR_OK || tag != 0x30)
        return KM_ERR_FORMAT;
    if (off != len) /* 顶层 SEQUENCE 后不应有尾随字节 */
        return KM_ERR_FORMAT;

    cert->tbs = val; /* tbsCertificate TLV 起始（顶层 SEQUENCE 第一个子元素） */

    /* tbsCertificate = SEQUENCE */
    {
        uint8_t ttag;
        const uint8_t *tval;
        size_t tvlen;
        if (km_der_read_tlv(val, vlen, &tbs_off, &ttag, &tval, &tvlen) != KM_ERR_OK ||
            ttag != 0x30)
            return KM_ERR_FORMAT;
        cert->tbs_len = tbs_off; /* tbs TLV 完整长度（tag + len + 内容） */

        /* [0] version（可选，v1 证书无此字段） */
        {
            size_t v_off = 0;
            uint8_t vtag;
            const uint8_t *vval;
            size_t vvlen;
            {
                size_t poff = 0;
                uint8_t ptag;
                const uint8_t *pval;
                size_t plen;
                if (km_der_read_tlv(tval, tvlen, &poff, &ptag, &pval, &plen) == KM_ERR_OK &&
                    ptag == 0xA0) {
                    v_off = poff; /* 跳过 version，指向 serialNumber */
                }
            }
            /* serialNumber = INTEGER */
            if (km_der_read_tlv(tval, tvlen, &v_off, &vtag, &vval, &vvlen) != KM_ERR_OK ||
                vtag != 0x02)
                return KM_ERR_FORMAT;
            /* signature = AlgorithmIdentifier */
            if (km_der_read_tlv(tval, tvlen, &v_off, &vtag, &vval, &vvlen) != KM_ERR_OK ||
                vtag != 0x30)
                return KM_ERR_FORMAT;
            /* issuer = Name */
            if (km_der_read_tlv(tval, tvlen, &v_off, &vtag, &vval, &vvlen) != KM_ERR_OK ||
                vtag != 0x30)
                return KM_ERR_FORMAT;
            parse_name(vval, vvlen, cert->issuer, sizeof(cert->issuer));
            /* validity = SEQUENCE { Time, Time } */
            {
                size_t vt_off = v_off; /* 从已推进的位置继续 */
                uint8_t vt_tag;
                const uint8_t *vt_val;
                size_t vt_len;
                const uint8_t *t1;
                size_t t1_len;
                if (km_der_read_tlv(tval, tvlen, &vt_off, &vt_tag, &vt_val, &vt_len) != KM_ERR_OK ||
                    vt_tag != 0x30)
                    return KM_ERR_FORMAT;
                v_off = vt_off;
                {
                    size_t tt_off = 0;
                    uint8_t tt_tag;
                    if (km_der_read_tlv(vt_val, vt_len, &tt_off, &tt_tag, &t1, &t1_len) != KM_ERR_OK)
                        return KM_ERR_FORMAT;
                    if (tt_tag != 0x17 && tt_tag != 0x18)
                        return KM_ERR_FORMAT;
                }
                {
                    size_t tt_off = 0;
                    uint8_t tt_tag;
                    const uint8_t *t2;
                    size_t t2_len;
                    /* 重新读 notBefore */
                    km_der_read_tlv(vt_val, vt_len, &tt_off, &tt_tag, &t1, &t1_len);
                    if (km_der_read_tlv(vt_val, vt_len, &tt_off, &tt_tag, &t2, &t2_len) != KM_ERR_OK)
                        return KM_ERR_FORMAT;
                    if (tt_tag != 0x17 && tt_tag != 0x18)
                        return KM_ERR_FORMAT;
                    if (parse_time(t1, t1_len, &cert->not_before) != 0 ||
                        parse_time(t2, t2_len, &cert->not_after) != 0)
                        return KM_ERR_FORMAT;
                    cert->has_validity = 1;
                }
            }
            /* subject = Name */
            if (km_der_read_tlv(tval, tvlen, &v_off, &vtag, &vval, &vvlen) != KM_ERR_OK ||
                vtag != 0x30)
                return KM_ERR_FORMAT;
            parse_name(vval, vvlen, cert->subject, sizeof(cert->subject));
            /* subjectPublicKeyInfo */
            if (km_der_read_tlv(tval, tvlen, &v_off, &vtag, &vval, &vvlen) != KM_ERR_OK ||
                vtag != 0x30)
                return KM_ERR_FORMAT;
            {
                size_t plen = 0;
                if (parse_spki(vval, vvlen, cert->pubkey, &plen) == 0)
                    cert->has_pubkey = 1;
            }
        }
    }

    /* 剩余（在顶层 SEQUENCE 内容内，tbs 之后）：sigAlg + sigValue */
    {
        size_t tail = tbs_off; /* 顶层内容内，tbs TLV 之后 */
        uint8_t ttag;
        const uint8_t *tval;
        size_t tvlen;
        if (km_der_read_tlv(val, vlen, &tail, &ttag, &tval, &tvlen) != KM_ERR_OK ||
            ttag != 0x30)
            return KM_ERR_FORMAT; /* signatureAlgorithm */
        if (km_der_read_tlv(val, vlen, &tail, &ttag, &tval, &tvlen) != KM_ERR_OK ||
            ttag != 0x03)
            return KM_ERR_FORMAT; /* signatureValue BIT STRING */
        if (tvlen < 1 || tval[0] != 0)
            return KM_ERR_FORMAT;
        cert->sig = tval + 1;
        cert->sig_len = tvlen - 1;
    }

    return KM_ERR_OK;
}

/* 检查证书在 now 时刻是否处于有效期内；有效返回 1，无有效期信息返回 0 */
int km_x509_valid_at(const km_x509_t *cert, int64_t now)
{
    if (!cert->has_validity)
        return 0;
    return now >= cert->not_before && now <= cert->not_after;
}

/* ---------- 公共导入工具 ---------- */

/* 校验证书文件名安全：仅允许字母数字 _ - .，且不含路径分隔符与 ".." */
static int cert_name_valid(const char *name)
{
    size_t i, n;

    if (name == NULL)
        return 0;
    n = strlen(name);
    if (n == 0 || n > KM_CERT_NAME_MAX)
        return 0;
    for (i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    if (strstr(name, "..") != NULL) /* 防目录穿越 */
        return 0;
    return 1;
}

/* 拼接证书文件绝对路径到 path */
static void cert_file_path(char *path, size_t cap, const char *name)
{
    snprintf(path, cap, "%s/%s", cert_dir(), name);
}

/* 写入证书文件（已校验 name），失败返回 KM_ERR_FILE */
static km_err_t cert_store_file(const char *name, const char *pem, size_t len)
{
    char path[512];
    FILE *fp;
    km_err_t rc = KM_ERR_FILE;

    cert_mkdir(cert_dir());
    cert_file_path(path, sizeof(path), name);
    fp = fopen(path, "wb");
    if (fp == NULL)
        return KM_ERR_FILE;
    if (fwrite(pem, 1, len, fp) == len)
        rc = KM_ERR_OK;
    fclose(fp);
    return rc;
}

/* certlist.json（纯输出记录，Q0）追加/更新：
 * 结构：{ "root_cert":[{profile_id, cert}], "dev_cert":[{profile_id,
 *       sign_cert, enc_cert, key_index}], "client_cert":[] }
 * 以 key_index（签名槽）分组设备证书；root 以 cert 文件名去重。
 * 文件不存在则新建；无法解析视为空（输出记录不参与运行管理）。 */
static km_err_t certlist_update(int cert_use, const char *name, int key_index)
{
    char path[512];
    char *text = NULL;
    cJSON *root = NULL;
    cJSON *arr;
    km_err_t rc = KM_ERR_OK;

    cert_file_path(path, sizeof(path), KM_CERTLIST_FILE);

    {
        char buf[8192];
        size_t n = 0;
        if (read_file_all(path, buf, sizeof(buf), &n) == 0 && n > 0)
            root = cJSON_Parse(buf);
    }
    if (root == NULL)
        root = cJSON_CreateObject();
    if (root == NULL)
        return KM_ERR_FILE;

    if (cert_use == 0) {
        /* 根证书：root_cert 数组 */
        arr = cJSON_GetObjectItem(root, "root_cert");
        if (arr == NULL) {
            arr = cJSON_CreateArray();
            cJSON_AddItemToObject(root, "root_cert", arr);
        }
        {
            cJSON *cur = arr->child;
            int found = 0, max_pid = 0;
            for (; cur != NULL; cur = cur->next) {
                cJSON *cert = cJSON_GetObjectItem(cur, "cert");
                cJSON *pid = cJSON_GetObjectItem(cur, "profile_id");
                if (pid != NULL && pid->valueint > max_pid)
                    max_pid = pid->valueint;
                if (cert != NULL && cert->valuestring != NULL &&
                    strcmp(cert->valuestring, name) == 0)
                    found = 1;
            }
            if (!found) {
                cJSON *item = cJSON_CreateObject();
                cJSON_AddNumberToObject(item, "profile_id", max_pid + 1);
                cJSON_AddStringToObject(item, "cert", name);
                cJSON_AddItemToArray(arr, item);
            }
        }
    } else {
        /* 设备证书：按签名槽 key_index 分组（sign=奇数 1,3..；enc=偶数 2,4..） */
        int sign_index = (cert_use == KM_CERT_USE_SIGN) ? key_index : key_index - 1;
        arr = cJSON_GetObjectItem(root, "dev_cert");
        if (arr == NULL) {
            arr = cJSON_CreateArray();
            cJSON_AddItemToObject(root, "dev_cert", arr);
        }
        {
            cJSON *cur = arr->child;
            cJSON *found_item = NULL;
            for (; cur != NULL; cur = cur->next) {
                cJSON *ki = cJSON_GetObjectItem(cur, "key_index");
                if (ki != NULL && ki->valueint == sign_index) {
                    found_item = cur;
                    break;
                }
            }
            if (found_item == NULL) {
                found_item = cJSON_CreateObject();
                cJSON_AddNumberToObject(found_item, "profile_id",
                                        (sign_index + 1) / 2);
                cJSON_AddStringToObject(found_item,
                                        (cert_use == KM_CERT_USE_SIGN) ?
                                            "sign_cert" : "enc_cert",
                                        name);
                cJSON_AddStringToObject(found_item,
                                        (cert_use == KM_CERT_USE_SIGN) ?
                                            "enc_cert" : "sign_cert",
                                        "");
                cJSON_AddNumberToObject(found_item, "key_index", sign_index);
                cJSON_AddItemToArray(arr, found_item);
            } else {
                cJSON_ReplaceItemInObject(found_item,
                                          (cert_use == KM_CERT_USE_SIGN) ?
                                              "sign_cert" : "enc_cert",
                                          cJSON_CreateString(name));
            }
        }
    }

    /* 确保 client_cert 键存在，随后序列化写回 */
    if (cJSON_GetObjectItem(root, "client_cert") == NULL)
        cJSON_AddItemToObject(root, "client_cert", cJSON_CreateArray());

    text = cJSON_Print(root);
    if (text == NULL) {
        rc = KM_ERR_FILE;
    } else {
        FILE *fp = fopen(path, "w");
        if (fp == NULL) {
            rc = KM_ERR_FILE;
        } else {
            if (fputs(text, fp) == EOF)
                rc = KM_ERR_FILE;
            fclose(fp);
        }
        free(text);
    }
    cJSON_Delete(root);
    return rc;
}

/* ---------- 公开导入接口 ---------- */

/* 按名称导入根证书（信任锚）：结构合法即可存储；根证书列表更新到 certlist.json */
km_err_t km_cert_import_root_named(const char *name,
                                   const char *cert_pem, size_t len)
{
    uint8_t der[2048];
    size_t der_len = 0;
    km_x509_t cert;
    km_err_t rc;

    if (cert_pem == NULL || len == 0)
        return KM_ERR_BAD_PARAM;
    if (!cert_name_valid(name))
        return KM_ERR_BAD_PARAM;

    if (km_pem_to_der(cert_pem, len, "-----BEGIN CERTIFICATE-----",
                      "-----END CERTIFICATE-----", der, sizeof(der), &der_len) != KM_ERR_OK)
        return KM_ERR_FORMAT;
    if (km_x509_parse(der, der_len, &cert) != KM_ERR_OK)
        return KM_ERR_FORMAT;
    if (!cert.has_pubkey)
        return KM_ERR_CERT_INVALID;

    rc = cert_store_file(name, cert_pem, len);
    if (rc != KM_ERR_OK)
        return rc;
    certlist_update(0, name, 0);

    {
        char detail[300];
        snprintf(detail, sizeof(detail), "root cert imported: %s", name);
        km_auditlog_write(EVT_CERT_IMPORTED, detail);
    }
    km_oplog_write(LOG_LEVEL_INFO, "cert: root certificate '%s' imported (%zu bytes)",
                   name, len);
    return KM_ERR_OK;
}

/* 兼容旧调用：导入根证书（固定写入 root.crt，作为设备证书验签链根） */
km_err_t km_cert_import_root(const char *cert_pem, size_t len)
{
    return km_cert_import_root_named("root.crt", cert_pem, len);
}

/* 链校验公共子函数：读 root.crt → 设备证书验签 + 有效期；通过返回根证书解析结果 */
static km_err_t device_chain_check(const km_x509_t *cert,
                                   km_x509_t *root_out)
{
    km_x509_t root;
    char root_pem[4096];
    uint8_t root_der[2048];
    size_t root_pem_len = 0, root_der_len = 0;
    char path[512];
    const CryptoHAL *hal;
    int64_t now;

    cert_file_path(path, sizeof(path), "root.crt");
    if (read_file_all(path, root_pem, sizeof(root_pem), &root_pem_len) != 0) {
        km_oplog_write(LOG_LEVEL_WARN, "cert: root cert not found, device cert import rejected");
        return KM_ERR_CERT_INVALID;
    }
    if (km_pem_to_der(root_pem, root_pem_len, "-----BEGIN CERTIFICATE-----",
                      "-----END CERTIFICATE-----", root_der, sizeof(root_der), &root_der_len) != KM_ERR_OK ||
        km_x509_parse(root_der, root_der_len, &root) != KM_ERR_OK) {
        return KM_ERR_CERT_INVALID;
    }

    hal = km_hal_get();
    if (hal == NULL || hal->sm2_verify == NULL || !root.has_pubkey)
        return KM_ERR_CERT_INVALID;

    /* 验签链：根证书公钥验证设备证书签名（对 tbsCertificate 签名） */
    if (hal->sm2_verify(root.pubkey, cert->tbs, cert->tbs_len, cert->sig) != 0) {
        km_oplog_write(LOG_LEVEL_WARN, "cert: device cert signature verify failed");
        return KM_ERR_CERT_INVALID;
    }

    /* 有效期检查（以当前时间为准） */
    now = (int64_t)time(NULL);
    if (!km_x509_valid_at(cert, now) || !km_x509_valid_at(&root, now)) {
        km_oplog_write(LOG_LEVEL_WARN, "cert: device cert out of validity period");
        return KM_ERR_CERT_INVALID;
    }

    if (root_out != NULL)
        *root_out = root;
    return KM_ERR_OK;
}

/* 解析 PEM 并返回 DER/证书对象（公共子函数） */
static km_err_t cert_parse_pem(const char *cert_pem, size_t len,
                               uint8_t *der, size_t der_cap, size_t *der_len,
                               km_x509_t *cert)
{
    if (km_pem_to_der(cert_pem, len, "-----BEGIN CERTIFICATE-----",
                      "-----END CERTIFICATE-----", der, der_cap, der_len) != KM_ERR_OK)
        return KM_ERR_FORMAT;
    return km_x509_parse(der, *der_len, cert);
}

/* 按名称导入设备证书：链校验 + 证书公钥匹配内部密钥槽（Q1/B/C） */
km_err_t km_cert_import_dev_named(int cert_use, const char *name,
                                  const char *cert_pem, size_t len,
                                  int *key_index)
{
    uint8_t der[2048];
    size_t der_len = 0;
    km_x509_t cert;
    const CryptoHAL *hal;
    int ki;
    km_err_t rc;
    int key_type;

    if (cert_pem == NULL || len == 0 || key_index == NULL)
        return KM_ERR_BAD_PARAM;
    if (cert_use != KM_CERT_USE_SIGN && cert_use != KM_CERT_USE_ENC)
        return KM_ERR_BAD_PARAM;
    if (!cert_name_valid(name))
        return KM_ERR_BAD_PARAM;

    rc = cert_parse_pem(cert_pem, len, der, sizeof(der), &der_len, &cert);
    if (rc != KM_ERR_OK)
        return rc;
    if (!cert.has_pubkey)
        return KM_ERR_CERT_INVALID;

    /* 根证书验签链 + 有效期 */
    rc = device_chain_check(&cert, NULL);
    if (rc != KM_ERR_OK)
        return rc;

    /* 证书公钥匹配密码卡内部密钥对：签名证书匹配签名槽(1 起步步长 2)，
     * 加密证书匹配加密槽（= 签名槽 + 1）；未匹配说明证书不是本卡签发 → 拒绝 */
    hal = km_hal_get();
    if (hal == NULL || hal->slot_find_pubkey == NULL)
        return KM_ERR_CERT_INVALID;
    key_type = (cert_use == KM_CERT_USE_SIGN) ? KEY_TYPE_SIGN : KEY_TYPE_ENC;
    ki = hal->slot_find_pubkey(key_type, cert.pubkey);
    if (ki < 0) {
        km_oplog_write(LOG_LEVEL_WARN,
                       "cert: device cert pubkey not match internal key slot (use=%d)",
                       cert_use);
        return KM_ERR_CERT_INVALID;
    }

    rc = cert_store_file(name, cert_pem, len);
    if (rc != KM_ERR_OK)
        return rc;
    certlist_update(cert_use, name, ki);

    *key_index = ki;
    {
        char detail[300];
        snprintf(detail, sizeof(detail), "device cert imported: %s (key_index=%d)",
                 name, ki);
        km_auditlog_write(EVT_CERT_IMPORTED, detail);
    }
    km_oplog_write(LOG_LEVEL_INFO,
                   "cert: device certificate '%s' imported, key_index=%d",
                   name, ki);
    return KM_ERR_OK;
}

/* 兼容旧调用：导入设备证书（固定写入 device.crt；保持仅链验证语义，
 * 不要求内部密钥匹配，供既有测试/工具使用） */
km_err_t km_cert_import_device(const char *cert_pem, size_t len)
{
    uint8_t der[2048];
    size_t der_len = 0;
    km_x509_t cert;
    km_err_t rc;

    if (cert_pem == NULL || len == 0)
        return KM_ERR_BAD_PARAM;

    rc = cert_parse_pem(cert_pem, len, der, sizeof(der), &der_len, &cert);
    if (rc != KM_ERR_OK)
        return rc;
    rc = device_chain_check(&cert, NULL);
    if (rc != KM_ERR_OK)
        return rc;

    rc = cert_store_file("device.crt", cert_pem, len);
    if (rc != KM_ERR_OK)
        return rc;

    km_auditlog_write(EVT_CERT_IMPORTED, "device cert imported");
    km_oplog_write(LOG_LEVEL_INFO, "cert: device certificate imported and verified");
    return KM_ERR_OK;
}
