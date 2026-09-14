#include "km_api.h"
#include "km_config.h"
#include "km_env.h"
#include "km_device.h"
#include "comm/km_comm.h"
#include "comm/mgmt_protocol.h"
#include "app/cmd_handler.h"
#include "app/heartbeat.h"
#include "app/msg_dispatch.h"
#include "thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

static km_config_t g_cfg;
static volatile int g_running = 1;

/* 启动入参解析：--conf <path> / --heartbeat <sec> / --selftest <on|off>
 *             / --selftest-interval <sec>
 *             --log-level <info|warn|error> / --log-console <on|off>
 * 兼容：首个非选项参数视为配置文件路径（argv[1] 原有用法） */

/* 扫描命令行取配置文件路径：--conf <path> 或首个非选项位置参数；无则返回 NULL */
static const char *parse_conf_arg(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a == NULL || *a == '\0')
            continue;
        if (strcmp(a, "--conf") == 0) {
            if (i + 1 < argc)
                return argv[i + 1];
            continue;
        }
        if (a[0] != '-')
            return a; /* 兼容：位置参数 */
    }
    return NULL;
}

/* 应用命令行覆盖（km_config_load 后调用，优先级最高）：
 * --heartbeat <sec> / --selftest <on|off> / --selftest-interval <sec>
 * --log-level <debug|info|warn|error> / --log-console <on|off>
 * 解析完成后将日志选项应用到运行中的日志系统并记录汇总日志 */
static void apply_cli_overrides(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a == NULL)
            continue;
        if (strcmp(a, "--selftest") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            g_cfg.selftest_enable = (strcmp(v, "1") == 0 ||
                                     strcmp(v, "on") == 0 ||
                                     strcmp(v, "yes") == 0) ? 1 : 0;
        } else if (strcmp(a, "--heartbeat") == 0 && i + 1 < argc) {
            int iv = atoi(argv[++i]);
            if (iv >= 0 && iv <= 86400)
                g_cfg.heartbeat_interval = iv; /* 0 = 关闭心跳（联调/冒烟用短周期覆盖） */
        } else if (strcmp(a, "--selftest-interval") == 0 && i + 1 < argc) {
            int iv = atoi(argv[++i]);
            if (iv >= 0 && iv <= 86400)
                g_cfg.selftest_interval = iv;
        } else if (strcmp(a, "--log-level") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "debug") == 0)
                g_cfg.log_level = LOG_LEVEL_DEBUG;
            else if (strcmp(v, "warn") == 0)
                g_cfg.log_level = LOG_LEVEL_WARN;
            else if (strcmp(v, "info") == 0)
                g_cfg.log_level = LOG_LEVEL_INFO;
            else /* error / 非法值均按最高级 */
                g_cfg.log_level = LOG_LEVEL_ERROR;
        } else if (strcmp(a, "--log-console") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            g_cfg.log_console = (strcmp(v, "1") == 0 ||
                                 strcmp(v, "on") == 0 ||
                                 strcmp(v, "yes") == 0) ? 1 : 0;
        }
    }

    /* 应用日志相关覆盖（--log-level / --log-console），使过滤立即生效 */
    {
        km_oplog_cfg_t ocfg;
        memset(&ocfg, 0, sizeof(ocfg));
        ocfg.level = g_cfg.log_level;
        ocfg.console = g_cfg.log_console;
        ocfg.to_file = g_cfg.log_to_file;
        ocfg.file_max = g_cfg.log_file_max;
        ocfg.file_count = g_cfg.log_file_count;
        km_oplog_update(&ocfg);
    }
    km_oplog_write(LOG_LEVEL_INFO,
                   "cli overrides: heartbeat_interval=%ds selftest_enable=%d "
                   "selftest_interval=%ds log_level=%d log_console=%d",
                   g_cfg.heartbeat_interval,
                   g_cfg.selftest_enable, g_cfg.selftest_interval,
                   (int)g_cfg.log_level, g_cfg.log_console);
}

/* 定时自检：按设定频率执行；失败停止工作并上报，恢复后继续工作并上报。
 * 由定时线程（多线程模式）或主循环（单线程模式）调用，时间判定基于传入 now。 */
static void run_periodic_selftest(time_t now, time_t *last_st)
{
    km_err_t serr;

    if (!g_cfg.selftest_enable || g_cfg.selftest_interval <= 0)
        return;
    if ((now - *last_st) < g_cfg.selftest_interval)
        return;
    *last_st = now;

    serr = km_selftest_run();
    if (serr == KM_ERR_OK) {
        km_heartbeat_set_run_state(KM_RUN_STATE_BOOT_OK); /* 自检正常/恢复：心跳上报 0x01 */
        km_oplog_write(LOG_LEVEL_INFO, "periodic selftest OK");
        if (!km_cmd_is_working()) {
            km_cmd_set_working(1);
            km_selftest_report(1);
            km_oplog_write(LOG_LEVEL_INFO,
                           "selftest recovered, device resumed working");
        }
    } else {
        km_oplog_write(LOG_LEVEL_ERROR, "periodic selftest failed: %s",
                       km_err_str(serr));
        km_auditlog_write(EVT_SELFTEST_RESULT, "periodic selftest failed");
        if (km_cmd_is_working()) {
            km_cmd_set_working(0);
            km_selftest_report(0);
            km_oplog_write(LOG_LEVEL_WARN,
                           "selftest failed, device stopped working");
        }
    }
}



/* 定时线程：心跳发送/超时判定 + 定时自检与故障门控。
 * 与业务线程解耦：业务堵塞不影响心跳与自检。 */
static void timer_thread_main(void *arg)
{
    time_t last_st = time(NULL);

    (void)arg;
    while (g_running) {
        time_t now = time(NULL);

        /* 心跳：到期发送 + 超时判定（内部按绝对时间，线程安全） */
        km_heartbeat_tick(now);

        /* 定时自检 + 故障门控 */
        run_periodic_selftest(now, &last_st);

        km_thread_sleep_ms(50);
    }
}

/* KM daemon 入口：加载配置→初始化日志→应用 CLI 覆盖→设备初始化→
* 三线程模型：
 *  - 通信线程 km_comm_worker：recv → 收帧队列；发送队列 → send；
 *  - 本线程（主线程）承担业务：收帧队列 → km_msg_handle(最外层分流) → 应答；
 *  - 定时线程 timer_thread_main：心跳 + 自检。
 * 业务处理（证书导入等）即使耗时，也不再影响定时功能。
 * 收帧入口分层（km_msg_handle）：
 *  km_fpga_parse(最外层头检查) → 按 msg_type 分流(管理/预留 fromFPGA/未知)
 *  → km_mng_parse(管理头检查) → km_mng_handle_message(心跳/状态/证书导入) 
  * 退出时逆序反初始化 */
int main(int argc, char **argv)
{
    const char *conf_path;
    km_err_t err;
    km_thread_t comm_t;
    km_thread_t timer_t;
    uint8_t rbuf[KM_MAX_MSG_LEN];


    conf_path = parse_conf_arg(argc, argv);
    err = km_config_load(&g_cfg, conf_path);
    if (err != KM_ERR_OK) {
        fprintf(stderr, "config load failed: %s\n", km_err_str(err));
        return 1;
    }

    /* 先按配置初始化日志，使后续启动信息进入运维日志 */
    {
        km_oplog_cfg_t ocfg;
        memset(&ocfg, 0, sizeof(ocfg));
        ocfg.level = g_cfg.log_level;
        ocfg.console = g_cfg.log_console;
        ocfg.to_file = g_cfg.log_to_file;
        ocfg.file_max = g_cfg.log_file_max;
        ocfg.file_count = g_cfg.log_file_count;
        km_log_init2(g_cfg.oplog_dir, g_cfg.audit_dir, &ocfg);
    }
    
    km_oplog_write(LOG_LEVEL_INFO,
                   "KM daemon v" KM_VERSION_STR " starting, env=%s (%s)",
                   km_env_name(), km_env_desc());
    km_config_dump(&g_cfg);

    /* 命令行覆盖（--selftest / --selftest-interval），日志已初始化 */
    apply_cli_overrides(argc, argv);

    err = km_device_init(&g_cfg);
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "device init failed: %s", km_err_str(err));
        return 1;    }

    km_oplog_write(LOG_LEVEL_INFO,
                   "KM daemon initialized, heartbeat=%ds selftest=%s interval=%ds "
                   "threads=%s",
                   g_cfg.heartbeat_interval,g_cfg.selftest_enable ? "on" : "off", g_cfg.selftest_interval, "3"); 

    /* 线程启动前完成共享状态预热：cmd_handler 内部锁、心跳模块 */
    km_cmd_set_working(1);
    km_heartbeat_init((uint32_t)g_cfg.heartbeat_interval, KM_HEARTBEAT_MAX_LOST);

    if (km_thread_create(&comm_t, km_comm_worker, NULL) != KM_ERR_OK)    {
        km_oplog_write(LOG_LEVEL_ERROR, "thread km_comm_worker create failed");    }
    else    {
        km_oplog_write(LOG_LEVEL_INFO,"thread km_comm_worker create success");    }

    if (km_thread_create(&timer_t, timer_thread_main, NULL) != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "thread create failed");
    } else{
        km_oplog_write(LOG_LEVEL_INFO,"thread timer_thread_main create success");
    }

    /* 业务线程（主线程）循环 */
    while (g_running) {
        size_t rlen = 0;

        if (km_comm_frame_pop(rbuf, sizeof(rbuf), &rlen) == KM_ERR_OK) {
            km_oplog_write(LOG_LEVEL_INFO, "recv frame len=%u", (unsigned)rlen);

            (void)km_msg_handle(rbuf, rlen);
            
        } else {
            km_thread_sleep_ms(5);
        }
    }

    //exit deal
    km_comm_worker_stop();
    km_thread_join(&comm_t);
    km_thread_join(&timer_t);

    km_oplog_write(LOG_LEVEL_INFO, "KM daemon shutting down");
    km_device_deinit();
    return 0;
}
