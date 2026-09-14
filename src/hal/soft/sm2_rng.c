#include "sm2_rng.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <stdio.h>
#include <unistd.h>
#endif

static int (*g_custom_rng)(uint8_t *, size_t) = NULL;

/* 注入自定义随机源（用于测试向量复现）；传 NULL 恢复系统默认 */
void sm2_rng_set_custom(int (*fn)(uint8_t *, size_t))
{
    g_custom_rng = fn;
}

/* 获取 len 字节安全随机数（Windows: BCrypt / Linux: /dev/urandom）；成功返回 0 */
int sm2_rng_bytes(uint8_t *out, size_t len)
{
    if (g_custom_rng != NULL)
        return g_custom_rng(out, len);

#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)len,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;
#else
    {
        FILE *fp = fopen("/dev/urandom", "rb");
        size_t got;
        if (fp == NULL)
            return -1;
        got = fread(out, 1, len, fp);
        fclose(fp);
        return (got == len) ? 0 : -1;
    }
#endif
}
