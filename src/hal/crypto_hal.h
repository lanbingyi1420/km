#ifndef KM_CRYPTO_HAL_H
#define KM_CRYPTO_HAL_H

#include <stdint.h>
#include <stddef.h>
#include "km_types.h"
#include "km_error.h"
#include "km_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * CryptoHAL：统一密码服务接口（函数指针结构体）
 * 第一阶段由 SoftCryptoProvider 实现，第二阶段替换为 PcieCryptoProvider，
 * 上层业务零改动。
 */
typedef struct {
    int  (*init)(const void *cfg); /* cfg: Provider 私有配置（Soft 传密钥目录） */
    void (*deinit)(void);

    /* SM2：pubkey=64B(x||y)，prikey=32B，sig=64B(r||s)，data 为待签名原文（ZA 值计算在内部完成） */
    int  (*sm2_gen_keypair)(uint8_t *pubkey, uint8_t *prikey);
    int  (*sm2_sign)(const uint8_t *prikey, const uint8_t *data,
                     size_t data_len, uint8_t *sig);
    int  (*sm2_verify)(const uint8_t *pubkey, const uint8_t *data,
                       size_t data_len, const uint8_t *sig);

    /* SM3 */
    int  (*sm3_digest)(const uint8_t *in, size_t len,
                       uint8_t out[KM_SM3_DIGEST_LEN]);

    /* SM4：ECB/CBC 模式，iv 可为 NULL（ECB）；len 必须为 16 的整数倍 */
    int  (*sm4_encrypt)(const uint8_t key[KM_SM4_KEY_LEN],
                        const uint8_t iv[KM_SM4_BLOCK_LEN],
                        const uint8_t *in, uint8_t *out, size_t len);
    int  (*sm4_decrypt)(const uint8_t key[KM_SM4_KEY_LEN],
                        const uint8_t iv[KM_SM4_BLOCK_LEN],
                        const uint8_t *in, uint8_t *out, size_t len);

    /* 算法自检（KAT 已知答案测试） */
    int  (*self_test)(void);

    /* 密钥生命周期管理（保证上层零改动：Soft 加密文件存储 / PCIe 卡内存储） */
    int  (*key_gen_store)(int key_type, char key_id[KM_KEY_ID_LEN]);
    int  (*key_load)(int key_type, const char *key_id,
                     uint8_t *prikey, uint8_t *pubkey);
    int  (*key_exists)(int key_type, const char *key_id);

    /* 密钥槽台账（Q1/B/C 决策：密码卡内部密钥对 key_index 规则）
     * 签名密钥索引从 1 开始、步长 2（1,3,5,…）；加密密钥索引 = 签名索引 + 1（2,4,6,…）。
     * 设备证书导入时以其公钥匹配内部密钥对，得到该证书绑定的 key_index。
     * Soft 实现：虚拟槽台账（key_dir/slot.ledger）；PCIe 实现：卡内槽位。 */
    int  (*slot_gen_store)(int key_type, char key_id[KM_KEY_ID_LEN],
                           int *key_index);       /* 生成密钥并分配槽位 */
    int  (*slot_find_pubkey)(int key_type,
                             const uint8_t *pubkey); /* 按公钥匹配返回 key_index，未匹配返回 -1 */
} CryptoHAL;

/** SoftCryptoProvider 初始化配置 */
typedef struct {
    const char *key_dir;        /* 密钥存储目录（NULL 用默认 /opt/km/keys） */
    const char *master_key_env; /* 主密钥环境变量名（NULL 用 KM_MASTER_KEY） */
} soft_crypto_cfg_t;

/**
 * @brief 初始化 CryptoHAL 并选择 Provider
 * @param provider CRYPTO_PROVIDER_SOFT / CRYPTO_PROVIDER_PCIE
 * @param cfg      Provider 私有配置（Soft: const char* 密钥目录；PCIe: 可为 NULL）
 */
km_err_t km_hal_init(crypto_provider_t provider, const void *cfg);

/** @brief 释放 HAL */
void km_hal_deinit(void);

/** @brief 获取当前 HAL 接口（未初始化返回 NULL） */
const CryptoHAL *km_hal_get(void);

#ifdef __cplusplus
}
#endif

#endif /* KM_CRYPTO_HAL_H */
