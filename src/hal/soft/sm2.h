#ifndef KM_SM2_H
#define KM_SM2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_PUBKEY_LEN 64  /* x || y */
#define SM2_PRIKEY_LEN 32
#define SM2_SIG_LEN    64  /* r || s */

/**
 * 生成 SM2 密钥对
 * @param pubkey 输出 64B (x||y)
 * @param prikey 输出 32B
 * @return 0 成功，非 0 失败
 */
int sm2_gen_keypair(uint8_t pubkey[SM2_PUBKEY_LEN], uint8_t prikey[SM2_PRIKEY_LEN]);

/**
 * 由私钥计算公钥（测试/验证用）
 * @param prikey 32B 私钥
 * @param pubkey 输出 64B (x||y)
 * @return 0 成功
 */
int sm2_pubkey_from_prikey(const uint8_t prikey[SM2_PRIKEY_LEN],
                           uint8_t pubkey[SM2_PUBKEY_LEN]);

/**
 * SM2 签名（内部计算 ZA，data 为待签名原文）
 * @param prikey 32B 私钥
 * @param data   待签名数据
 * @param data_len 数据长度
 * @param sig    输出 64B (r||s)
 * @return 0 成功
 */
int sm2_sign(const uint8_t prikey[SM2_PRIKEY_LEN], const uint8_t *data,
             size_t data_len, uint8_t sig[SM2_SIG_LEN]);

/**
 * SM2 验签
 * @param pubkey 64B (x||y)
 * @param data   原文
 * @param data_len
 * @param sig    64B (r||s)
 * @return 0 验证通过，非 0 失败
 */
int sm2_verify(const uint8_t pubkey[SM2_PUBKEY_LEN], const uint8_t *data,
               size_t data_len, const uint8_t sig[SM2_SIG_LEN]);

/**
 * SM2 KDF 密钥派生
 * @param z    输入
 * @param zlen 输入长度
 * @param klen 期望输出长度
 * @param out  输出缓冲区（klen 字节）
 */
void sm2_kdf(const uint8_t *z, size_t zlen, size_t klen, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* KM_SM2_H */
