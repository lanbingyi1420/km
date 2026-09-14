#ifndef KM_DER_H
#define KM_DER_H

#include <stddef.h>
#include <stdint.h>
#include "km_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- DER TLV 读写辅助（自研最小实现，用于 PKCS#10 / X.509） ---------- */

/**
 * @brief 顺序读取一个 TLV 单元
 * @param der   DER 数据
 * @param len   数据长度
 * @param off   输入当前偏移 / 输出下一偏移
 * @param tag   输出标签
 * @param val   输出值指针（指向 der 内部）
 * @param vlen  输出值长度
 * @return KM_ERR_OK 成功；KM_ERR_FORMAT 越界/格式错误；KM_ERR_BAD_PARAM 参数错
 */
km_err_t km_der_read_tlv(const uint8_t *der, size_t len, size_t *off,
                         uint8_t *tag, const uint8_t **val, size_t *vlen);

/**
 * @brief 写出 DER 长度字段（自动短/长格式）
 * @return 写入字节数；0 表示缓冲区不足
 */
size_t km_der_write_len(uint8_t *buf, size_t cap, size_t vlen);

/**
 * @brief 写出一个 TLV 单元（tag + len + value）
 * @return 写入字节数；0 表示缓冲区不足/参数错
 */
size_t km_der_write_tlv(uint8_t *buf, size_t cap, uint8_t tag,
                        const uint8_t *val, size_t vlen);

/* ---------- Base64（标准字母表，PEM 使用） ---------- */

/**
 * @brief Base64 解码
 * @return 0 成功；-1 非法字符/缓冲区不足
 */
int km_base64_decode(const char *b64, size_t b64_len,
                     uint8_t *out, size_t cap, size_t *out_len);

/**
 * @brief Base64 编码（含换行/无换行均可，PEM 默认不换行，由调用方排版）
 * @return 输出字符数（不含 '\0'）；0 表示缓冲区不足
 */
size_t km_base64_encode(const uint8_t *in, size_t in_len,
                        char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* KM_DER_H */
