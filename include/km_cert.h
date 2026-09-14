#ifndef KM_CERT_H
#define KM_CERT_H

#include <stddef.h>
#include "km_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 导入根证书
 * @param cert_pem PEM 格式证书
 * @param len      长度
 * @return KM_ERR_OK 成功，KM_ERR_CERT_INVALID 证书无效
 */
km_err_t km_cert_import_root(const char *cert_pem, size_t len);

/**
 * @brief 导入设备证书并验证（根证书验签链 + 有效期检查）
 * @param cert_pem PEM 格式设备证书
 * @param len      长度
 * @return KM_ERR_OK 成功，KM_ERR_CERT_INVALID 证书无效
 */
km_err_t km_cert_import_device(const char *cert_pem, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KM_CERT_H */
