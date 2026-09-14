#include "km_test.h"
#include "hal/crypto_hal.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

/* 测试用临时密钥目录（工作区 out/testkeys 下） */
#define TEST_KEY_DIR "out/testkeys"
#define TEST_MASTER  "km-master-key-for-unit-test-0123456789"

static void ensure_clean_dir(void)
{
#ifdef _WIN32
    _mkdir("out");
    _mkdir(TEST_KEY_DIR);
#else
    mkdir("out", 0700);
    mkdir(TEST_KEY_DIR, 0700);
#endif
}

void test_crypto_hal(void)
{
    const CryptoHAL *hal;
    soft_crypto_cfg_t cfg;
    char key_id[KM_KEY_ID_LEN];
    uint8_t pub[KM_SM2_PUBKEY_LEN], pri[KM_SM2_PRIKEY_LEN];
    uint8_t pub2[KM_SM2_PUBKEY_LEN], pri2[KM_SM2_PRIKEY_LEN];
    uint8_t sig[KM_SM2_SIG_LEN];
    const uint8_t msg[] = "HAL interface test";
    uint8_t digest[KM_SM3_DIGEST_LEN];
    uint8_t in[64], enc[64], dec[64];
    size_t i;

#ifdef _WIN32
    _putenv_s("KM_MASTER_KEY", TEST_MASTER);
#else
    setenv("KM_MASTER_KEY", TEST_MASTER, 1);
#endif
    ensure_clean_dir();

    /* 1) HAL 未初始化时返回 NULL */
    KM_TEST_ASSERT(km_hal_get() == NULL);

    /* 2) 初始化 Soft Provider */
    cfg.key_dir = TEST_KEY_DIR;
    cfg.master_key_env = "KM_MASTER_KEY";
    KM_TEST_ASSERT_EQ_INT(km_hal_init(CRYPTO_PROVIDER_SOFT, &cfg), KM_ERR_OK);
    hal = km_hal_get();
    KM_TEST_ASSERT(hal != NULL);
    KM_TEST_ASSERT(hal->self_test != NULL);

    /* 3) 算法接口一致性：SM3 与标准向量一致 */
    KM_TEST_ASSERT_EQ_INT(hal->sm3_digest((const uint8_t *)"abc", 3, digest), 0);
    {
        static const uint8_t exp[32] = {
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
            0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
            0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
            0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
        };
        KM_TEST_ASSERT_MEM_EQ(digest, exp, 32);
    }

    /* 4) SM4 往返 */
    for (i = 0; i < sizeof(in); i++)
        in[i] = (uint8_t)(i + 1);
    {
        uint8_t key[16];
        memset(key, 0x33, sizeof(key));
        KM_TEST_ASSERT_EQ_INT(hal->sm4_encrypt(key, NULL, in, enc, 64), 0);
        KM_TEST_ASSERT_EQ_INT(hal->sm4_decrypt(key, NULL, enc, dec, 64), 0);
        KM_TEST_ASSERT_MEM_EQ(dec, in, 64);
        /* 非 16 字节倍数拒绝 */
        KM_TEST_ASSERT_EQ_INT(hal->sm4_encrypt(key, NULL, in, enc, 17), -1);
    }

    /* 5) 自检通过 */
    KM_TEST_ASSERT_EQ_INT(hal->self_test(), 0);

    /* 6) 密钥生成 + 存储 + 加载往返 */
    KM_TEST_ASSERT_EQ_INT(hal->key_gen_store(KEY_TYPE_SIGN, key_id), 0);
    KM_TEST_ASSERT(key_id[0] != '\0');
    KM_TEST_ASSERT(hal->key_exists(KEY_TYPE_SIGN, key_id) == 1);
    KM_TEST_ASSERT_EQ_INT(hal->key_load(KEY_TYPE_SIGN, key_id, pri, pub), 0);

    /* 7) 加载出的密钥可正常签名验签 */
    KM_TEST_ASSERT_EQ_INT(hal->sm2_sign(pri, msg, sizeof(msg) - 1, sig), 0);
    KM_TEST_ASSERT_EQ_INT(hal->sm2_verify(pub, msg, sizeof(msg) - 1, sig), 0);

    /* 8) 重新加载同一密钥与首次一致（文件持久化正确） */
    KM_TEST_ASSERT_EQ_INT(hal->key_load(KEY_TYPE_SIGN, key_id, pri2, pub2), 0);
    KM_TEST_ASSERT_MEM_EQ(pri, pri2, KM_SM2_PRIKEY_LEN);
    KM_TEST_ASSERT_MEM_EQ(pub, pub2, KM_SM2_PUBKEY_LEN);

    /* 9) 错误类型/不存在密钥 */
    KM_TEST_ASSERT_EQ_INT(hal->key_load(KEY_TYPE_ROOT, key_id, pri, pub), -1);
    KM_TEST_ASSERT(hal->key_exists(KEY_TYPE_ROOT, key_id) == 0);
    KM_TEST_ASSERT_EQ_INT(hal->key_gen_store(99, key_id), -1);

    km_hal_deinit();

    /* 10) PCIe Provider：第一阶段应初始化失败（未支持） */
    KM_TEST_ASSERT_EQ_INT(km_hal_init(CRYPTO_PROVIDER_PCIE, NULL), KM_ERR_INIT_FAIL);
    km_hal_deinit();
}
