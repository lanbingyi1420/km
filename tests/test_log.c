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

#define TEST_LOG_DIR "out/testlogs"

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

/* 清理持久化的审计队列，保证测试隔离（每次运行从头开始） */
static void clean_audit(void)
{
    char path[384];
    snprintf(path, sizeof(path), "%s/audit.log", TEST_LOG_DIR);
    remove(path);
}

void test_log(void)
{
    km_audit_entry_t entries[16];
    int count = 0;

    ensure_dir();
    clean_audit();

    /* 1) 初始化日志 */
    KM_TEST_ASSERT_EQ_INT(km_log_init(TEST_LOG_DIR, TEST_LOG_DIR, LOG_LEVEL_INFO), 0);

    /* 2) 运维日志写入，文件存在且符合行格式 */
    km_oplog_write(LOG_LEVEL_INFO, "device init start");
    km_oplog_write(LOG_LEVEL_ERROR, "selftest component=%s result=%d", "sm4", -1);
    {
        char path[384];
        time_t now = time(NULL);
        struct tm tmv;
        FILE *fp;
        char buf[1024];
        size_t rd;
#ifdef _WIN32
        localtime_s(&tmv, &now);
#else
        localtime_r(&now, &tmv);
#endif
        snprintf(path, sizeof(path), "%s/oplog-%04d%02d%02d.log",
                 TEST_LOG_DIR, tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
        fp = fopen(path, "rb");
        KM_TEST_ASSERT(fp != NULL);
        if (fp != NULL) {
            rd = fread(buf, 1, sizeof(buf) - 1, fp);
            fclose(fp);
            buf[rd] = '\0';
            KM_TEST_ASSERT(strstr(buf, "[error]") != NULL);
            KM_TEST_ASSERT(strstr(buf, "selftest") != NULL);
        }
    }

    /* 3) 审计日志：写入 → 待上报 → 确认 */
    km_auditlog_write(EVT_DEVICE_INIT_START, "init begin");
    km_auditlog_write(EVT_KEY_GENERATED, "key_type=sign");
    KM_TEST_ASSERT_EQ_INT(km_auditlog_pending(entries, 16, &count), 0);
    KM_TEST_ASSERT_EQ_INT(count, 2);
    KM_TEST_ASSERT(entries[0].seq < entries[1].seq);
    KM_TEST_ASSERT_EQ_INT((int)entries[0].event_id, EVT_DEVICE_INIT_START);
    KM_TEST_ASSERT(strcmp(entries[1].detail, "key_type=sign") == 0);

    /* 4) 确认第一条：pending 剩 1 条 */
    km_auditlog_ack(entries[0].seq);
    KM_TEST_ASSERT_EQ_INT(km_auditlog_pending(entries, 16, &count), 0);
    KM_TEST_ASSERT_EQ_INT(count, 1);
    KM_TEST_ASSERT_EQ_INT((int)entries[0].seq, 2);

    /* 5) 重启恢复：未确认条目（seq=2）从磁盘恢复 */
    km_log_deinit();
    km_auditlog_write(0, "should-not-appear"); /* 未初始化时忽略 */
    KM_TEST_ASSERT_EQ_INT(km_log_init(TEST_LOG_DIR, TEST_LOG_DIR, LOG_LEVEL_INFO), 0);
    KM_TEST_ASSERT_EQ_INT(km_auditlog_pending(entries, 16, &count), 0);
    KM_TEST_ASSERT_EQ_INT(count, 1);
    KM_TEST_ASSERT_EQ_INT((int)entries[0].event_id, EVT_KEY_GENERATED);

    /* 6) 全部确认后队列为空 */
    km_auditlog_ack(entries[0].seq);
    KM_TEST_ASSERT_EQ_INT(km_auditlog_pending(entries, 16, &count), 0);
    KM_TEST_ASSERT_EQ_INT(count, 0);

    km_log_deinit();
}
