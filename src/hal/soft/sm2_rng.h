#ifndef KM_SM2_RNG_H
#define KM_SM2_RNG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 密码学安全随机数
 * - Linux: /dev/urandom
 * - Windows: BCryptGenRandom
 * @return 0 成功，非 0 失败
 */
int sm2_rng_bytes(uint8_t *out, size_t len);

/** 注入自定义随机源（测试用，NULL 恢复系统源） */
void sm2_rng_set_custom(int (*fn)(uint8_t *, size_t));

#ifdef __cplusplus
}
#endif

#endif /* KM_SM2_RNG_H */
