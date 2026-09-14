/* 自研最小 DER TLV 读写与 Base64 辅助（零第三方依赖） */
#include "der.h"
#include <string.h>

/* ---------- DER TLV 读取 ---------- */

/* 读取一个 DER TLV：从 off 处解析 tag+长度+值，推进 off；失败返回 KM_ERR_FORMAT */
km_err_t km_der_read_tlv(const uint8_t *der, size_t len, size_t *off,
                         uint8_t *tag, const uint8_t **val, size_t *vlen)
{
    size_t o;
    size_t l;

    if (der == NULL || off == NULL || tag == NULL || val == NULL || vlen == NULL)
        return KM_ERR_BAD_PARAM;
    o = *off;
    if (o >= len)
        return KM_ERR_FORMAT;

    *tag = der[o++];
    /* 长度字段 */
    if (o >= len)
        return KM_ERR_FORMAT;
    if (der[o] < 0x80) {
        l = der[o++];
    } else {
        int nbytes = der[o] & 0x7F;
        size_t i;
        if (nbytes == 0 || nbytes > (int)sizeof(size_t) || (size_t)o + 1 + (size_t)nbytes > len)
            return KM_ERR_FORMAT;
        o++;
        l = 0;
        for (i = 0; i < (size_t)nbytes; i++)
            l = (l << 8) | der[o + i];
        o += (size_t)nbytes;
    }
    if (o + l > len)
        return KM_ERR_FORMAT;

    *val = der + o;
    *vlen = l;
    *off = o + l;
    return KM_ERR_OK;
}

/* ---------- DER 长度编码 ---------- */

/* 编码 DER 长度字段（短/长格式），返回写入字节数；容量不足返回 0 */
size_t km_der_write_len(uint8_t *buf, size_t cap, size_t vlen)
{
    if (vlen < 0x80) {
        if (cap < 1)
            return 0;
        buf[0] = (uint8_t)vlen;
        return 1;
    }
    /* 长格式：取字节数（大小端） */
    {
        uint8_t tmp[8];
        size_t n = 0;
        size_t v = vlen;
        while (v != 0) {
            tmp[n++] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
        if (cap < 1 + n)
            return 0;
        buf[0] = (uint8_t)(0x80 | n);
        {
            size_t i;
            for (i = 0; i < n; i++)
                buf[1 + i] = tmp[n - 1 - i];
        }
        return 1 + n;
    }
}

/* 编码完整 DER TLV（tag+长度+值），返回总字节数；参数非法或容量不足返回 0 */
size_t km_der_write_tlv(uint8_t *buf, size_t cap, uint8_t tag,
                        const uint8_t *val, size_t vlen)
{
    size_t nlen = km_der_write_len(buf == NULL ? NULL : buf + 1, cap >= 1 ? cap - 1 : 0, vlen);
    size_t need;

    if (vlen != 0 && val == NULL)
        return 0;
    if (cap < 1)
        return 0;
    need = 1 + nlen + vlen;
    if (cap < need || nlen == 0)
        return 0;

    buf[0] = tag;
    /* 重写长度字段（上面用 buf+1 试写） */
    if (nlen == 1) {
        buf[1] = (uint8_t)vlen;
    } else {
        size_t n = nlen;
        size_t v = vlen;
        size_t i;
        buf[1] = (uint8_t)(0x80 | (n - 1));
        for (i = 0; i < n - 1; i++) {
            buf[2 + i] = (uint8_t)(v >> (8 * (n - 2 - i)));
        }
    }
    if (vlen != 0)
        memcpy(buf + 1 + nlen, val, vlen);
    return need;
}

/* ---------- Base64 ---------- */

static const char b64_tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 字符 → 6 位数值；非法字符返回 -1 */
static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Base64 编码（标准表，尾部 '=' 填充），返回输出长度；容量不足返回 0 */
size_t km_base64_encode(const uint8_t *in, size_t in_len,
                        char *out, size_t cap)
{
    size_t i, o = 0;

    if (in == NULL && in_len != 0)
        return 0;
    for (i = 0; i + 2 < in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        if (o + 4 > cap)
            return 0;
        out[o++] = b64_tab[(v >> 18) & 0x3F];
        out[o++] = b64_tab[(v >> 12) & 0x3F];
        out[o++] = b64_tab[(v >> 6) & 0x3F];
        out[o++] = b64_tab[v & 0x3F];
    }
    if (in_len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (o + 4 > cap)
            return 0;
        out[o++] = b64_tab[(v >> 18) & 0x3F];
        out[o++] = b64_tab[(v >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (in_len - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        if (o + 4 > cap)
            return 0;
        out[o++] = b64_tab[(v >> 18) & 0x3F];
        out[o++] = b64_tab[(v >> 12) & 0x3F];
        out[o++] = b64_tab[(v >> 6) & 0x3F];
        out[o++] = '=';
    }
    return o;
}

/* Base64 解码（忽略空白与 '=' 填充），成功返回 0 并输出字节数；非法/溢出返回 -1 */
int km_base64_decode(const char *b64, size_t b64_len,
                     uint8_t *out, size_t cap, size_t *out_len)
{
    size_t i = 0, o = 0;
    uint32_t acc = 0;
    int nbits = 0;

    if (b64 == NULL || (out == NULL && cap != 0) || out_len == NULL)
        return -1;
    for (i = 0; i < b64_len; i++) {
        char c = b64[i];
        int v;
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue; /* 忽略填充与空白 */
        v = b64_val(c);
        if (v < 0)
            return -1;
        acc = (acc << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o >= cap)
                return -1;
            out[o++] = (uint8_t)((acc >> nbits) & 0xFF);
        }
    }
    *out_len = o;
    return 0;
}
