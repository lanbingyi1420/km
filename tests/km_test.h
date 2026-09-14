#ifndef KM_TEST_H
#define KM_TEST_H

#include <stdio.h>
#include <string.h>

/* 轻量断言框架：统计通过/失败用例，返回非 0 退出码供 CTest 判定
 * 计数为全局符号，定义于 test_main.c，避免各翻译单元各自持有副本导致统计失真 */

extern int g_km_test_pass;
extern int g_km_test_fail;

#define KM_TEST_ASSERT(cond)                                                    \
    do {                                                                        \
        if (cond) {                                                             \
            g_km_test_pass++;                                                   \
        } else {                                                                \
            g_km_test_fail++;                                                   \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                                       \
    } while (0)

#define KM_TEST_ASSERT_EQ_INT(actual, expected)                                 \
    do {                                                                        \
        long long _a = (long long)(actual);                                     \
        long long _e = (long long)(expected);                                   \
        if (_a == _e) {                                                         \
            g_km_test_pass++;                                                   \
        } else {                                                                \
            g_km_test_fail++;                                                   \
            fprintf(stderr, "  FAIL %s:%d: %s == %lld, expected %lld\n",        \
                    __FILE__, __LINE__, #actual, _a, _e);                       \
        }                                                                       \
    } while (0)

#define KM_TEST_ASSERT_MEM_EQ(actual, expected, len)                            \
    do {                                                                        \
        const unsigned char *_a = (const unsigned char *)(actual);              \
        const unsigned char *_e = (const unsigned char *)(expected);            \
        size_t _n = (len);                                                      \
        if (memcmp(_a, _e, _n) == 0) {                                          \
            g_km_test_pass++;                                                   \
        } else {                                                                \
            size_t _i;                                                          \
            g_km_test_fail++;                                                   \
            fprintf(stderr, "  FAIL %s:%d: memcmp(%s, %s, %zu)\n",              \
                    __FILE__, __LINE__, #actual, #expected, _n);                \
            for (_i = 0; _i < _n; _i++) {                                       \
                if (_a[_i] != _e[_i]) {                                         \
                    fprintf(stderr, "    first diff at [%zu]: 0x%02x vs 0x%02x\n",\
                            _i, _a[_i], _e[_i]);                                \
                    break;                                                      \
                }                                                               \
            }                                                                   \
        }                                                                       \
    } while (0)

#define KM_TEST_RUN(fn)                                                         \
    do {                                                                        \
        int _before = g_km_test_fail;                                           \
        printf("[test] %s\n", #fn);                                             \
        fn();                                                                   \
        if (g_km_test_fail == _before)                                          \
            printf("  PASS\n");                                                 \
    } while (0)

#define KM_TEST_SUMMARY()                                                       \
    do {                                                                        \
        printf("========================================\n");                   \
        printf("TOTAL: pass=%d fail=%d\n", g_km_test_pass, g_km_test_fail);     \
        return g_km_test_fail == 0 ? 0 : 1;                                     \
    } while (0)

#endif /* KM_TEST_H */
