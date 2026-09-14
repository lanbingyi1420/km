#include "km_test.h"
#include "sm3.h"
#include <ctype.h>

/* GB/T 32905-2016 附录 A 标准测试向量 */
static const char *HEX = "0123456789abcdef";

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t *len)
{
    size_t n = strlen(hex);
    size_t i;
    for (i = 0; i < n; i += 2) {
        out[i / 2] = (uint8_t)((hex_val(hex[i]) << 4) | hex_val(hex[i + 1]));
    }
    *len = n / 2;
}

void test_sm3(void)
{
    uint8_t digest[SM3_DIGEST_LEN];
    uint8_t expected[SM3_DIGEST_LEN];
    size_t elen;
    const char *msg;

    /* 向量 1: 空串 */
    sm3_digest((const uint8_t *)"", 0, digest);
    hex_to_bytes("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
                 expected, &elen);
    KM_TEST_ASSERT_EQ_INT(elen, SM3_DIGEST_LEN);
    KM_TEST_ASSERT_MEM_EQ(digest, expected, SM3_DIGEST_LEN);

    /* 向量 2: "abc" */
    msg = "abc";
    sm3_digest((const uint8_t *)msg, 3, digest);
    hex_to_bytes("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                 expected, &elen);
    KM_TEST_ASSERT_MEM_EQ(digest, expected, SM3_DIGEST_LEN);

    /* 向量 3: "abcd"*16（64 字节） */
    {
        uint8_t msg64[64];
        size_t i;
        for (i = 0; i < 64; i++)
            msg64[i] = (uint8_t)('a' + (i % 4));
        sm3_digest(msg64, sizeof(msg64), digest);
        hex_to_bytes("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                     expected, &elen);
        KM_TEST_ASSERT_MEM_EQ(digest, expected, SM3_DIGEST_LEN);
    }

    /* 分块 update 与一次性 digest 结果一致 */
    {
        uint8_t data[100];
        sm3_ctx_t ctx;
        uint8_t d1[32], d2[32];
        size_t i;
        for (i = 0; i < sizeof(data); i++)
            data[i] = (uint8_t)(i * 7 + 3);
        sm3_digest(data, sizeof(data), d1);
        sm3_init(&ctx);
        sm3_update(&ctx, data, 10);
        sm3_update(&ctx, data + 10, 55);
        sm3_update(&ctx, data + 65, sizeof(data) - 65);
        sm3_final(&ctx, d2);
        KM_TEST_ASSERT_MEM_EQ(d1, d2, 32);
    }
}
