#ifndef KM_ERROR_H
#define KM_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 错误码定义 ---------- */
typedef enum {
    KM_ERR_OK             = 0,
    KM_ERR_INIT_FAIL      = -1,
    KM_ERR_SELFTEST_FAIL  = -2,
    KM_ERR_COMM_FAIL      = -3,
    KM_ERR_CERT_INVALID   = -4,
    KM_ERR_BAD_PARAM      = -5,
    KM_ERR_NO_MEM         = -6,
    KM_ERR_CRYPTO         = -7,
    KM_ERR_KEY_NOT_FOUND  = -8,
    KM_ERR_FILE           = -9,
    KM_ERR_ALREADY_INIT   = -10,
    KM_ERR_NOT_SUPPORTED  = -11,
    KM_ERR_BUF_TOO_SMALL  = -12,
    KM_ERR_FORMAT         = -13,
    KM_ERR_RESERVED       = -14, /* 预留通道消息（协议已定义但尚未启用，区别于未知类型） */
} km_err_t;

/* 返回错误码的字符串描述（线程安全，返回静态字符串） */
const char *km_err_str(km_err_t err);

#ifdef __cplusplus
}
#endif

#endif /* KM_ERROR_H */
