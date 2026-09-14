#ifndef KM_CERT_VALIDATOR_H
#define KM_CERT_VALIDATOR_H

#include <stddef.h>
#include <stdint.h>
#include "km_error.h"
#include "km_types.h"

/* 证书用途/类型（与 mgmt_protocol.h 的 KM_CERT_USE_SIGN/ENC 保持一致，
 * 放这里以便 cert_validator 不依赖 comm 层头文件） */
#ifndef KM_CERT_USE_SIGN
#define KM_CERT_USE_SIGN 0x01 /* 设备证书：签名证书 */
#define KM_CERT_USE_ENC  0x02 /* 设备证书：加密证书 */
#endif

/* 证书文件名长度上限（线格式 1B 字段） */
#ifndef KM_CERT_NAME_MAX
#define KM_CERT_NAME_MAX 255
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 证书目录环境变量名（测试可覆盖到临时目录）；
 * Windows 开发机默认相对路径 ./certs，板卡/release 用绝对路径 */
#define KM_CERT_DIR_ENV "KM_CERT_DIR"
#ifdef _WIN32
#define KM_CERT_DEFAULT_DIR "./certs"
#else
#define KM_CERT_DEFAULT_DIR "/opt/km/certs"
#endif

/* 证书列表文件（Q0：纯输出记录，便于外部审计，KM 不读回用于管理） */
#define KM_CERTLIST_FILE "certlist.json"

/* ---------- 解析结果（供实现与测试使用） ---------- */

typedef struct {
    char     subject[256];                 /* 主体 DN（简化格式 "CN=.., O=.."） */
    char     issuer[256];                  /* 签发者 DN */
    uint8_t  pubkey[KM_SM2_PUBKEY_LEN];    /* SM2 公钥 x||y */
    int      has_pubkey;
    int64_t  not_before;                   /* Unix 秒 */
    int64_t  not_after;
    int      has_validity;
    const uint8_t *tbs;                    /* tbsCertificate 原始 DER（用于验签） */
    size_t   tbs_len;
    const uint8_t *sig;                    /* 签名值（不含 BIT STRING 未用位头） */
    size_t   sig_len;
} km_x509_t;

/**
 * @brief 从 PEM 包络提取 DER（对 begin/end 标记之间的 base64 解码）
 * @param begin_marker / end_marker 如 "-----BEGIN CERTIFICATE-----"
 */
km_err_t km_pem_to_der(const char *pem, size_t len,
                       const char *begin_marker, const char *end_marker,
                       uint8_t *der, size_t cap, size_t *der_len);

/** @brief 解析 X.509 证书 DER */
km_err_t km_x509_parse(const uint8_t *der, size_t len, km_x509_t *cert);

/** @brief 有效期检查：now 落在 [not_before, not_after] 返回 1，否则 0（无有效期也返回 0） */
int km_x509_valid_at(const km_x509_t *cert, int64_t now);

/**
 * @brief 按名称导入根证书（管理消息证书项循环的每一项）
 * @param name 文件名，如 "gov-ca-root.pem"（写入 cert_dir()/name，且更新 certlist.json）
 * @param cert_pem / len PEM 内容
 * @return KM_ERR_OK / KM_ERR_FORMAT / KM_ERR_CERT_INVALID / KM_ERR_FILE
 */
km_err_t km_cert_import_root_named(const char *name,
                                   const char *cert_pem, size_t len);

/**
 * @brief 按名称导入设备证书（多证书项之一，含证书类型）
 * @param cert_use  KM_CERT_USE_SIGN(1)=签名证书 / KM_CERT_USE_ENC(2)=加密证书
 * @param name      文件名，如 "server_sign_1.pem"
 * @param cert_pem / len PEM 内容
 * @param key_index 出参：证书公钥匹配到的内部密钥对 key_index
 *                  （签名证书 = 签名槽（1 起步步长 2），加密证书 = 加密槽 = 签名槽 + 1）
 * @return KM_ERR_OK / KM_ERR_FORMAT / KM_ERR_CERT_INVALID（含链验证/有效期/公钥不匹配） /
 *         KM_ERR_FILE
 */
km_err_t km_cert_import_dev_named(int cert_use, const char *name,
                                  const char *cert_pem, size_t len,
                                  int *key_index);

#ifdef __cplusplus
}
#endif

#endif /* KM_CERT_VALIDATOR_H */
