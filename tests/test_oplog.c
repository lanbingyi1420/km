#include "km_test.h"
#include "km_log.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#define TEST_LOG_DIR "out/testoplog"

static void ensure_dir(void)
{
#ifdef _WIN32
    _mkdir("out");
    _mkdir(TEST_LOG_DIR);
#else
    mkdir("out", 0700);
    mkdir(TEST_LOG_DIR, 0700);
#endif
}

/* 生成当日日志文件名 */
static void daily_path(char *path, size_t cap)
{
    time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    snprintf(path, cap, "%s/oplog-%04d%02d%02d.log",
             TEST_LOG_DIR, tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
}

static long file_size(const char *path)
{
    long sz = -1;
    FILE *fp = fopen(path, "rb");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        sz = ftell(fp);
        fclose(fp);
    }
    return sz;
}

/* 清理测试目录中当日日志及历史轮转文件，保证测试隔离 */
static void clean_logs(const char *path)
{
    char p[384];
    remove(path);
    for (int i = 1; i <= 5; i++) {
        snprintf(p, sizeof(p), "%s.%d", path, i);
        remove(p);
    }
}

void test_oplog(void)
{
    char path[384];
    km_oplog_cfg_t cfg;

    ensure_dir();
    daily_path(path, sizeof(path));

    /* 1) 关闭文件记录：to_file=0 不产生文件，但 console=1 打印后台 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.level = LOG_LEVEL_INFO;
    cfg.console = 1;
    cfg.to_file = 0;
    cfg.file_max = 0;
    cfg.file_count = 5;
    clean_logs(path);
    KM_TEST_ASSERT_EQ_INT(km_log_init2(TEST_LOG_DIR, TEST_LOG_DIR, &cfg), 0);
    km_oplog_write(LOG_LEVEL_INFO, "no file logging");
    KM_TEST_ASSERT_EQ_INT(file_size(path), -1); /* 未创建 */
    km_log_deinit();

    /* 2) 日志级别过滤：level=error 时 info/warn 被丢弃 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.level = LOG_LEVEL_ERROR;
    cfg.to_file = 1;
    cfg.file_count = 5;
    clean_logs(path);
    KM_TEST_ASSERT_EQ_INT(km_log_init2(TEST_LOG_DIR, TEST_LOG_DIR, &cfg), 0);
    km_oplog_write(LOG_LEVEL_INFO, "should be dropped");
    km_oplog_write(LOG_LEVEL_WARN, "should be dropped too");
    km_oplog_write(LOG_LEVEL_ERROR, "kept error");
    {
        char buf[1024];
        size_t rd;
        FILE *fp = fopen(path, "rb");
        KM_TEST_ASSERT(fp != NULL);
        if (fp != NULL) {
            rd = fread(buf, 1, sizeof(buf) - 1, fp);
            fclose(fp);
            buf[rd] = '\0';
            KM_TEST_ASSERT(strstr(buf, "kept error") != NULL);
            KM_TEST_ASSERT(strstr(buf, "should be dropped") == NULL);
        }
    }
    km_log_deinit();

    /* 3) 循环覆盖：file_max 很小 + file_count=N，触发轮转产生 .1 文件 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.level = LOG_LEVEL_INFO;
    cfg.to_file = 1;
    cfg.file_max = 256;   /* 极小的单文件上限，触发轮转 */
    cfg.file_count = 3;
    clean_logs(path);
    KM_TEST_ASSERT_EQ_INT(km_log_init2(TEST_LOG_DIR, TEST_LOG_DIR, &cfg), 0);
    for (int i = 0; i < 60; i++)
        km_oplog_write(LOG_LEVEL_INFO, "rotate line %d with some padding 1234567890", i);
    km_log_deinit();

    /* 轮转后应存在 .1 历史文件 */
    {
        char p1[384];
        snprintf(p1, sizeof(p1), "%s.1", path);
        KM_TEST_ASSERT(file_size(p1) >= 0);
    }
    /* 当前文件不超过（略放宽：<= file_max + 单行上限） */
    KM_TEST_ASSERT(file_size(path) <= (long)cfg.file_max + 512);

    /* 4) DEBUG 级：变参数字符串 + 数据域 hex（独立行、含行号、每行 16 字节） */
    memset(&cfg, 0, sizeof(cfg));
    cfg.level = LOG_LEVEL_DEBUG;
    cfg.to_file = 1;
    cfg.file_count = 5;
    clean_logs(path);
    KM_TEST_ASSERT_EQ_INT(km_log_init2(TEST_LOG_DIR, TEST_LOG_DIR, &cfg), 0);
    km_oplog_write(LOG_LEVEL_INFO, "info still kept");
    km_dbg_write("dbg str %s=%d", "k", 7);
    {
        uint8_t data[20];
        for (int i = 0; i < 20; i++)
            data[i] = (uint8_t)i;
        km_dbg_hex("blob", data, sizeof(data));
        km_dbg_hex("nil", NULL, 0);
    }
    km_log_deinit();
    {
        char buf[4096];
        size_t rd;
        FILE *fp = fopen(path, "rb");
        KM_TEST_ASSERT(fp != NULL);
        if (fp != NULL) {
            rd = fread(buf, 1, sizeof(buf) - 1, fp);
            fclose(fp);
            buf[rd] = '\0';
            KM_TEST_ASSERT(strstr(buf, "[debug]") != NULL);
            KM_TEST_ASSERT(strstr(buf, "info still kept") != NULL);
            KM_TEST_ASSERT(strstr(buf, "dbg str k=7") != NULL);
            /* hex 块头行：tag[长度] */
            KM_TEST_ASSERT(strstr(buf, "::blob[20]:") != NULL);
            /* 数据行：1 基偏移 0001、每行 16 字节、每 8 字节以 " | " 分隔 */
            KM_TEST_ASSERT(strstr(buf,
                "0001: 00 01 02 03 04 05 06 07 | 08 09 0A 0B 0C 0D 0E 0F") != NULL);
            /* 次行：1 基偏移 0017、剩余 4 字节（不足 8 字节，无分隔符） */
            KM_TEST_ASSERT(strstr(buf, "0017: 10 11 12 13") != NULL);
            /* 空数据：仅头行 tag[0]: */
            KM_TEST_ASSERT(strstr(buf, "::nil[0]:") != NULL);
        }
    }

    /* 5) DEBUG 低于 INFO：level=info 时 debug 日志被过滤 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.level = LOG_LEVEL_INFO;
    cfg.to_file = 1;
    cfg.file_count = 5;
    clean_logs(path);
    KM_TEST_ASSERT_EQ_INT(km_log_init2(TEST_LOG_DIR, TEST_LOG_DIR, &cfg), 0);
    km_oplog_write(LOG_LEVEL_INFO, "only info kept");
    km_dbg_write("dropped debug");
    {
        uint8_t data[4] = { 1, 2, 3, 4 };
        km_dbg_hex("blob", data, sizeof(data));
    }
    km_log_deinit();
    {
        char buf[1024];
        size_t rd;
        FILE *fp = fopen(path, "rb");
        KM_TEST_ASSERT(fp != NULL);
        if (fp != NULL) {
            rd = fread(buf, 1, sizeof(buf) - 1, fp);
            fclose(fp);
            buf[rd] = '\0';
            KM_TEST_ASSERT(strstr(buf, "only info kept") != NULL);
            KM_TEST_ASSERT(strstr(buf, "dropped debug") == NULL);
            KM_TEST_ASSERT(strstr(buf, "blob") == NULL);
        }
    }
}
