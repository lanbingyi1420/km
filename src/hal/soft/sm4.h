#ifndef KM_SM4_H
#define KM_SM4_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_KEY_LEN   16
#define SM4_BLOCK_LEN 16

void sm4_set_encrypt_key(const uint8_t key[SM4_KEY_LEN], uint32_t rk[32]);
void sm4_set_decrypt_key(const uint8_t key[SM4_KEY_LEN], uint32_t rk[32]);

/* 单分组加解密（in/out 可为同一缓冲区） */
void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[SM4_BLOCK_LEN],
                       uint8_t out[SM4_BLOCK_LEN]);
void sm4_decrypt_block(const uint32_t rk[32], const uint8_t in[SM4_BLOCK_LEN],
                       uint8_t out[SM4_BLOCK_LEN]);

/* ECB 模式：len 必须为 16 的整数倍 */
void sm4_ecb_encrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t *in, uint8_t *out, size_t len);
void sm4_ecb_decrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t *in, uint8_t *out, size_t len);

/* CBC 模式：len 必须为 16 的整数倍 */
void sm4_cbc_encrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t iv[SM4_BLOCK_LEN],
                     const uint8_t *in, uint8_t *out, size_t len);
void sm4_cbc_decrypt(const uint8_t key[SM4_KEY_LEN],
                     const uint8_t iv[SM4_BLOCK_LEN],
                     const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KM_SM4_H */
