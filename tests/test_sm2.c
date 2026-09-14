#include "km_test.h"
#include "sm2.h"

/* GB/T 32918.2-2016（GM/T 0003.5）附录 A 标准示例向量 */
static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len)
{
    size_t n = strlen(hex);
    size_t i;
    (void)len;
    for (i = 0; i < n; i += 2)
        out[i / 2] = (uint8_t)((hex_val(hex[i]) << 4) | hex_val(hex[i + 1]));
}

void test_sm2(void)
{
    /* 标准私钥 d 与公钥 P */
    static const char *D_HEX =
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    static const char *PX_HEX =
        "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020";
    static const char *PY_HEX =
        "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    static const char *R_HEX =
        "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3";
    static const char *S_HEX =
        "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA";

    uint8_t d[SM2_PRIKEY_LEN];
    uint8_t pub[SM2_PUBKEY_LEN];
    uint8_t sig[SM2_SIG_LEN];
    const char *msg = "message digest";

    hex_to_bytes(D_HEX, d, sizeof(d));

    /* 1) 由标准私钥计算公钥，应与标准公钥一致（验证曲线参数与标量乘） */
    KM_TEST_ASSERT_EQ_INT(sm2_pubkey_from_prikey(d, pub), 0);
    {
        uint8_t px[32], py[32];
        hex_to_bytes(PX_HEX, px, sizeof(px));
        hex_to_bytes(PY_HEX, py, sizeof(py));
        KM_TEST_ASSERT_MEM_EQ(pub, px, 32);
        KM_TEST_ASSERT_MEM_EQ(pub + 32, py, 32);
    }

    /* 2) 用标准公钥验证标准签名（验证 ZA 计算与验签算法） */
    hex_to_bytes(PX_HEX, pub, 32);
    hex_to_bytes(PY_HEX, pub + 32, 32);
    hex_to_bytes(R_HEX, sig, 32);
    hex_to_bytes(S_HEX, sig + 32, 32);
    KM_TEST_ASSERT_EQ_INT(sm2_verify(pub, (const uint8_t *)msg, strlen(msg), sig), 0);

    /* 3) 篡改消息 → 验签失败 */
    KM_TEST_ASSERT_EQ_INT(
        sm2_verify(pub, (const uint8_t *)"message digesX", 16, sig), -1);

    /* 4) 随机密钥对：签名 → 验签往返 */
    {
        uint8_t pri[SM2_PRIKEY_LEN];
        uint8_t p2[SM2_PUBKEY_LEN];
        uint8_t s2[SM2_SIG_LEN];
        int i;
        KM_TEST_ASSERT_EQ_INT(sm2_gen_keypair(p2, pri), 0);
        KM_TEST_ASSERT_EQ_INT(sm2_sign(pri, (const uint8_t *)msg, strlen(msg), s2), 0);
        KM_TEST_ASSERT_EQ_INT(sm2_verify(p2, (const uint8_t *)msg, strlen(msg), s2), 0);
        /* 另一条消息验签失败 */
        KM_TEST_ASSERT_EQ_INT(
            sm2_verify(p2, (const uint8_t *)"other message", 13, s2), -1);
        /* 多轮往返（覆盖不同随机 k） */
        for (i = 0; i < 5; i++) {
            KM_TEST_ASSERT_EQ_INT(sm2_gen_keypair(p2, pri), 0);
            KM_TEST_ASSERT_EQ_INT(sm2_sign(pri, (const uint8_t *)msg, strlen(msg), s2), 0);
            KM_TEST_ASSERT_EQ_INT(sm2_verify(p2, (const uint8_t *)msg, strlen(msg), s2), 0);
        }
    }

    /* 5) KDF：长度 48 字节，往返一致性（无标准向量，验证长度行为） */
    {
        uint8_t z[32];
        uint8_t k1[48], k2[48];
        memset(z, 0x5a, sizeof(z));
        sm2_kdf(z, sizeof(z), sizeof(k1), k1);
        sm2_kdf(z, sizeof(z), sizeof(k2), k2);
        KM_TEST_ASSERT_MEM_EQ(k1, k2, sizeof(k1));
        z[0] ^= 0xff;
        sm2_kdf(z, sizeof(z), sizeof(k2), k2);
        KM_TEST_ASSERT(memcmp(k1, k2, sizeof(k1)) != 0);
    }
}
