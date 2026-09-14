#include "km_test.h"
#include "sm4.h"

/* GB/T 32907-2016 附录 A 标准测试向量 */
static const uint8_t KAT_KEY[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static const uint8_t KAT_PT[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static const uint8_t KAT_CT[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
};

void test_sm4(void)
{
    uint8_t out[64];
    uint8_t back[64];

    /* 单块加密 KAT */
    sm4_ecb_encrypt(KAT_KEY, KAT_PT, out, 16);
    KM_TEST_ASSERT_MEM_EQ(out, KAT_CT, 16);

    /* 单块解密 KAT */
    sm4_ecb_decrypt(KAT_KEY, KAT_CT, out, 16);
    KM_TEST_ASSERT_MEM_EQ(out, KAT_PT, 16);

    /* ECB 多块：相同分组 → 相同密文 */
    {
        uint8_t pt2[32];
        uint8_t ct2[32];
        memcpy(pt2, KAT_PT, 16);
        memcpy(pt2 + 16, KAT_PT, 16);
        sm4_ecb_encrypt(KAT_KEY, pt2, ct2, 32);
        KM_TEST_ASSERT_MEM_EQ(ct2, KAT_CT, 16);
        KM_TEST_ASSERT_MEM_EQ(ct2 + 16, KAT_CT, 16);
        sm4_ecb_decrypt(KAT_KEY, ct2, back, 32);
        KM_TEST_ASSERT_MEM_EQ(back, pt2, 32);
    }

    /* CBC 往返 */
    {
        uint8_t iv[16];
        uint8_t pt[48];
        size_t i;
        for (i = 0; i < 16; i++)
            iv[i] = (uint8_t)(0xa0 + i);
        for (i = 0; i < 48; i++)
            pt[i] = (uint8_t)(i * 3 + 1);
        sm4_cbc_encrypt(KAT_KEY, iv, pt, out, 48);
        sm4_cbc_decrypt(KAT_KEY, iv, out, back, 48);
        KM_TEST_ASSERT_MEM_EQ(back, pt, 48);
        /* 不同 IV 产生不同密文 */
        {
            uint8_t iv2[16] = {0};
            uint8_t out2[48];
            sm4_cbc_encrypt(KAT_KEY, iv2, pt, out2, 48);
            KM_TEST_ASSERT(memcmp(out, out2, 48) != 0);
        }
    }

    /* 块接口往返 */
    {
        uint32_t rk[32];
        sm4_set_encrypt_key(KAT_KEY, rk);
        sm4_encrypt_block(rk, KAT_PT, out);
        KM_TEST_ASSERT_MEM_EQ(out, KAT_CT, 16);
        sm4_set_decrypt_key(KAT_KEY, rk);
        sm4_decrypt_block(rk, KAT_CT, out);
        KM_TEST_ASSERT_MEM_EQ(out, KAT_PT, 16);
    }
}
