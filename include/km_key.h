#ifndef KM_KEY_H
#define KM_KEY_H

#include <stddef.h>
#include "km_error.h"
#include "km_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 创建指定类型密钥对（SM2）
 * @param type   密钥类型（KEY_TYPE_ROOT / SIGN / ENC）
 * @param key_id 输出密钥标识符（至少 KM_KEY_ID_LEN 字节）
 * @return km_err_t
 */
km_err_t km_key_create(key_type_t type, char key_id[KM_KEY_ID_LEN]);

/**
 * @brief 导出证书请求 (PKCS#10 CSR)
 * @param key_id   密钥标识
 * @param subject  主题 DN（如 "CN=KM-Device,O=Org"）
 * @param csr_pem  输出 PEM 格式 CSR（缓冲区由调用方提供）
 * @param csr_len  输入缓冲区大小 / 输出实际长度
 * @return km_err_t
 */
km_err_t km_key_export_csr(const char *key_id,
                           const char *subject,
                           char *csr_pem,
                           size_t *csr_len);

#ifdef __cplusplus
}
#endif

#endif /* KM_KEY_H */
