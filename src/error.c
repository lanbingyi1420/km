#include "km_error.h"

/* 返回错误码对应的可读英文描述；未知错误码返回 "unknown error" */
const char *km_err_str(km_err_t err)
{
    switch (err) {
    case KM_ERR_OK:            return "OK";
    case KM_ERR_INIT_FAIL:     return "initialization failed";
    case KM_ERR_SELFTEST_FAIL: return "self test failed";
    case KM_ERR_COMM_FAIL:     return "communication failed";
    case KM_ERR_CERT_INVALID:  return "invalid certificate";
    case KM_ERR_BAD_PARAM:     return "bad parameter";
    case KM_ERR_NO_MEM:        return "out of memory";
    case KM_ERR_CRYPTO:        return "crypto operation failed";
    case KM_ERR_KEY_NOT_FOUND: return "key not found";
    case KM_ERR_FILE:          return "file operation failed";
    case KM_ERR_ALREADY_INIT:  return "already initialized";
    case KM_ERR_NOT_SUPPORTED: return "not supported";
    case KM_ERR_BUF_TOO_SMALL: return "buffer too small";
    case KM_ERR_FORMAT:        return "format error";
    case KM_ERR_RESERVED:      return "reserved channel not enabled";
    default:                   return "unknown error";
    }
}
