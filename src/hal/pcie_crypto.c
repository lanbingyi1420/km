#include "crypto_hal.h"

/* ============================================================
 * PcieCryptoProvider：第二阶段密码卡驱动（第一阶段桩）
 * 密钥由密码卡安全存储、不出卡；仅替换 HAL 接口表即可迁移，上层零改动。
 * ============================================================ */

/* PCIe 实现初始化：加载驱动并打开设备（第二阶段接入，当前桩返回失败） */
static int pcie_init(const void *cfg)
{
    (void)cfg;
    return -1; /* 未支持 */
}

/* PCIe 实现反初始化：关闭设备（桩） */
static void pcie_deinit(void)
{
}

/* PCIe SM2 密钥对生成（桩：密钥不出卡，暂未支持） */
static int pcie_sm2_gen_keypair(uint8_t *pubkey, uint8_t *prikey)
{
    (void)pubkey;
    (void)prikey;
    return -1;
}

/* PCIe SM2 签名（桩：暂未支持） */
static int pcie_sm2_sign(const uint8_t *prikey, const uint8_t *data,
                         size_t data_len, uint8_t *sig)
{
    (void)prikey;
    (void)data;
    (void)data_len;
    (void)sig;
    return -1;
}

/* PCIe SM2 验签（桩：暂未支持） */
static int pcie_sm2_verify(const uint8_t *pubkey, const uint8_t *data,
                           size_t data_len, const uint8_t *sig)
{
    (void)pubkey;
    (void)data;
    (void)data_len;
    (void)sig;
    return -1;
}

/* PCIe SM3 摘要（桩：暂未支持） */
static int pcie_sm3_digest(const uint8_t *in, size_t len,
                           uint8_t out[KM_SM3_DIGEST_LEN])
{
    (void)in;
    (void)len;
    (void)out;
    return -1;
}

/* PCIe SM4-CBC 加密（桩：暂未支持） */
static int pcie_sm4_encrypt(const uint8_t key[KM_SM4_KEY_LEN],
                            const uint8_t iv[KM_SM4_BLOCK_LEN],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    (void)key;
    (void)iv;
    (void)in;
    (void)out;
    (void)len;
    return -1;
}

/* PCIe SM4-CBC 解密（桩：暂未支持） */
static int pcie_sm4_decrypt(const uint8_t key[KM_SM4_KEY_LEN],
                            const uint8_t iv[KM_SM4_BLOCK_LEN],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    (void)key;
    (void)iv;
    (void)in;
    (void)out;
    (void)len;
    return -1;
}

/* PCIe 算法自检（桩：暂未支持） */
static int pcie_self_test(void)
{
    return -1;
}

/* PCIe 密钥生成并存储于卡内（桩：暂未支持） */
static int pcie_key_gen_store(int key_type, char key_id[KM_KEY_ID_LEN])
{
    (void)key_type;
    (void)key_id;
    return -1;
}

/* PCIe 卡内密钥加载（桩：暂未支持） */
static int pcie_key_load(int key_type, const char *key_id,
                         uint8_t *prikey, uint8_t *pubkey)
{
    (void)key_type;
    (void)key_id;
    (void)prikey;
    (void)pubkey;
    return -1;
}

/* PCIe 卡内密钥存在性检查（桩：恒返回不存在） */
static int pcie_key_exists(int key_type, const char *key_id)
{
    (void)key_type;
    (void)key_id;
    return 0;
}

/* PCIe 密钥槽生成（桩：暂未支持，卡内槽位分配后续接入） */
static int pcie_slot_gen_store(int key_type, char key_id[KM_KEY_ID_LEN],
                               int *key_index)
{
    (void)key_type;
    (void)key_id;
    (void)key_index;
    return -1;
}

/* PCIe 按公钥匹配卡内密钥槽（桩：暂未支持） */
static int pcie_slot_find_pubkey(int key_type, const uint8_t *pubkey)
{
    (void)key_type;
    (void)pubkey;
    return -1;
}

const CryptoHAL km_pcie_crypto_hal = {
    .init            = pcie_init,
    .deinit          = pcie_deinit,
    .sm2_gen_keypair = pcie_sm2_gen_keypair,
    .sm2_sign        = pcie_sm2_sign,
    .sm2_verify      = pcie_sm2_verify,
    .sm3_digest      = pcie_sm3_digest,
    .sm4_encrypt     = pcie_sm4_encrypt,
    .sm4_decrypt     = pcie_sm4_decrypt,
    .self_test       = pcie_self_test,
    .key_gen_store   = pcie_key_gen_store,
    .key_load        = pcie_key_load,
    .key_exists      = pcie_key_exists,
    .slot_gen_store  = pcie_slot_gen_store,
    .slot_find_pubkey = pcie_slot_find_pubkey,
};
