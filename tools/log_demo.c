/* 各级别日志内容模拟输出（tools/log_demo.c）
 *
 * 目的：经 km_log.h 对外接口逐级别生成运维日志样例，直观展示：
 *   1) 控制台各显示形态：debug / info / warn / error（error 走 stderr）；
 *   2) 落盘行格式：ts [level] {KM_file_func_line}::msg（带调用点定位）；
 *   3) DEBUG 级数据域 hex dump（整块输出，每行 16B、每 8 字节以 | 分隔、1 基偏移）；
 *   4) 管理服务心跳交互消息的 hex 输出（下行问询 / KM 应答 / KM 主动心跳；
 *      KM 上行载荷为 km_heartbeat_payload_t：已运行秒数 4B + 运行状态 1B）；
 *   5) 级别过滤效果：level=info 时 debug 被丢弃。
 *
 * 用法：km_log_demo [输出目录]（默认 out/logdemo）
 * 退出码：0 成功。
 */
#include "km_log.h"
#include "km_types.h"
#include "comm/mgmt_protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#define DEMO_MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define DEMO_MKDIR(p) mkdir((p), 0755)
#endif

static const char *g_dir = "out/logdemo";

/* 当日运维日志文件名（与 src/log/op_log.c 命名一致） */
static void today_path(char *path, size_t cap)
{
    time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    snprintf(path, cap, "%s/oplog-%04d%02d%02d.log",
             g_dir, tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
}

/* 打印当日日志文件内容（即"日志内容"的落盘形态） */
static void dump_oplog(const char *title)
{
    char path[384];
    char line[1024];
    FILE *fp;

    today_path(path, sizeof(path));
    printf("\n---- %s\n     文件：%s\n", title, path);
    fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("  (无文件)\n");
        return;
    }
    while (fgets(line, sizeof(line), fp) != NULL)
        printf("  %s", line);
    fclose(fp);
}

/* 删除当日日志文件：用于下一阶段演示前清空，避免旧记录混入落盘展示 */
static void clean_today_log(void)
{
    char path[384];
    today_path(path, sizeof(path));
    remove(path);
}

/* 模拟"管理服务"下行的管理帧（mgmt_protocol 仅有 KM 主动/应答编码器，
 * 下行方向在演示中按同一线格式手工组帧）：FPGA 头 + 管理头 + TLV + 填充。
 * 整帧 8 字节对齐且不低于 64B，填充字节值 = padding_len，pkt_len = len + padding_len。
 * 组出的帧可被 km_fpga_parse / km_mng_parse 视为合法管理帧。
 * 返回整帧长度，容量不足返回 0。 */
static size_t build_mng_downlink(uint8_t *out, size_t cap,
                                 uint16_t msg_cmd, uint8_t msg_id,
                                 const uint8_t *tlv, size_t tlv_len)
{
    STU_TLV_MNG_HEAD h;
    size_t data_len, total;
    uint8_t padding_len;

    if (out == NULL)
        return 0;

    data_len = sizeof(STU_TLV_MNG_HEAD) + tlv_len;         /* 不含填充 */
    total = (data_len + KM_FRAME_ALIGN - 1) & ~(size_t)(KM_FRAME_ALIGN - 1);
    if (total < KM_FRAME_MIN_LEN)
        total = KM_FRAME_MIN_LEN;
    if (total > cap || total > KM_FRAME_MAX_LEN)
        return 0;
    padding_len = (uint8_t)(total - data_len);

    memset(&h, 0, sizeof(h));
    h.fpga_head.head = KM_FPGA_TLV_HEAD;            /* 0x5a5a */
    h.fpga_head.msg_type = FPGA_MSGTYPE_fromSYSMNG; /* 管理服务->密码管理 */
    h.fpga_head.padding_len = padding_len;
    h.fpga_head.pkt_len = (uint16_t)(KM_MNG_HEAD_LEN + tlv_len + padding_len);
    h.head = KM_MNG_HEAD_MAGIC;                     /* 0x68 */
    h.len = (uint16_t)(KM_MNG_HEAD_LEN + tlv_len);  /* 管理消息长度 */
    h.msg_id = msg_id;
    h.sender = KM_SENDER_MNG;                       /* 发送方：管理服务 */
    h.receiver = KM_SENDER_KM;                      /* 接收方：密码管理模块 */
    h.msg_cmd[0] = (uint8_t)msg_cmd;                /* 2B 小端 */
    h.msg_cmd[1] = (uint8_t)(msg_cmd >> 8);
    memcpy(out, &h, sizeof(h));

    if (tlv_len > 0 && tlv != NULL)
        memcpy(out + sizeof(h), tlv, tlv_len);
    if (padding_len > 0)
        memset(out + data_len, padding_len, padding_len);
    return total;
}

int main(int argc, char **argv)
{
    km_oplog_cfg_t cfg;
    uint8_t frame[24];
    uint8_t hbframe[KM_FRAME_MIN_LEN];
    int i;

    if (argc > 1 && argv[1][0] != '\0')
        g_dir = argv[1];

    DEMO_MKDIR("out");
    DEMO_MKDIR(g_dir);

    /* ① 全级别开启（DEBUG）：控制台 + 文件；展示四种级别与 hex dump */
    printf("==== 各级别日志内容模拟输出（level=debug, console=on, to_file=on）====\n");

    memset(&cfg, 0, sizeof(cfg));
    cfg.level = LOG_LEVEL_DEBUG;
    cfg.console = 1;
    cfg.to_file = 1;
    cfg.file_count = 5;
    km_log_init2(g_dir, g_dir, &cfg);

    printf("\n>> DEBUG 级（km_log_debug / km_dbg_write）\n");
    km_log_debug("simulated debug: heartbeat timer tick, interval=30s");
    km_dbg_write("simulated debug: recv frame len=%u cmd=0x%04x", 64u, 0x0001u);

    printf("\n>> DEBUG 级数据域 hex（km_dbg_hex：整块输出，头行 tag[长度]，每行 16B、8 字节 | 8 字节、1 基偏移）\n");
    for (i = 0; i < (int)sizeof(frame); i++)
        frame[i] = (uint8_t)(i + 1);
    frame[0] = 0x5A; frame[1] = 0x5A;   /* 模拟帧头 magic，便于对照 */
    frame[2] = 0x31; frame[3] = 0x31;
    km_dbg_hex("raw-data", frame, sizeof(frame));

    printf("\n>> 管理服务心跳交互消息 hex（KM 上行载荷 = 运行时间 4B + 运行状态 1B，真实管理帧线格式）\n");
    {
        km_heartbeat_payload_t body;   /* KM -> MG 心跳载荷：单字节对齐结构体 */
        uint8_t tlv[16];
        size_t tlv_len = 0;
        size_t n;

        /* KM 上行载荷：软件已运行 42s、运行状态=完成开机自检(0x01) */
        memset(&body, 0, sizeof(body));
        body.uptime_sec = 42;
        body.run_state = KM_RUN_STATE_BOOT_OK;
        km_tlv_append(tlv, sizeof(tlv), &tlv_len, KM_TLV_TAG_HEARTBEAT,
                      &body, sizeof(body));

        /* ① 管理服务主动问询：下行（fromSYSMNG，sender=MNG），无载荷，msg_id=0x21 */
        n = build_mng_downlink(hbframe, sizeof(hbframe),
                               (uint16_t)SYSMNG_MSG_TYPE_HEARTBEAT, 0x21, NULL, 0);
        km_dbg_write("heartbeat: mgmt query downlink (no payload), msg_id=0x%02x len=%zu",
                     0x21u, n);
        km_dbg_hex("hb-rx", hbframe, n);

        /* ② KM 应答：回显请求 msg_id，载荷 = 运行时间+运行状态结构体 */
        n = sizeof(hbframe);
        if (km_mng_frame_encode_reply(hbframe, &n,
                                      (uint16_t)SYSMNG_MSG_TYPE_HEARTBEAT,
                                      0x21, tlv, tlv_len) == KM_ERR_OK) {
            km_dbg_write("heartbeat: reply, uptime=%us run_state=0x%02x msg_id=0x%02x len=%zu",
                         (unsigned)body.uptime_sec, body.run_state, 0x21u, n);
            km_dbg_hex("hb-tx-reply", hbframe, n);
        }

        /* ③ KM 主动心跳：上行（toSYSMNG），encode 发送前自增 msg_id（首帧=1），同一载荷 */
        km_mng_reset_msg_id();
        n = sizeof(hbframe);
        if (km_mng_frame_encode(hbframe, &n,
                                (uint16_t)SYSMNG_MSG_TYPE_HEARTBEAT,
                                tlv, tlv_len, NULL) == KM_ERR_OK) {
            km_dbg_write("heartbeat: proactive tx, uptime=%us run_state=0x%02x msg_id=0x01 len=%zu",
                         (unsigned)body.uptime_sec, body.run_state, n);
            km_dbg_hex("hb-tx", hbframe, n);
        }
    }

    printf("\n>> INFO 级（km_log_info / KM_OPLOG_RECORD）\n");
    km_log_info("simulated info: device initialized, heartbeat=30s selftest=on");
    KM_OPLOG_RECORD(LOG_LEVEL_INFO, "simulated info: %s",
                    "thread timer_thread_main create success");

    printf("\n>> WARN 级（km_log_warn）\n");
    km_log_warn("simulated warn: selftest failed, device stopped working");

    printf("\n>> ERROR 级（km_log_error，控制台输出到 stderr）\n");
    km_log_error("simulated error: device init failed: %s", "SM2 self-test mismatch");

    km_log_deinit();
    dump_oplog("落盘内容（各条均携带 file/func/line 定位）");

    /* ② 级别过滤：level=info 时 debug 被丢弃 */
    printf("\n==== 级别过滤模拟（level=info：debug 丢弃，info/warn/error 保留）====\n");

    memset(&cfg, 0, sizeof(cfg));
    cfg.level = LOG_LEVEL_INFO;
    cfg.console = 1;
    cfg.to_file = 1;
    cfg.file_count = 5;
    clean_today_log();   /* 清空上一阶段记录，使下方落盘展示仅反映本阶段 */
    km_log_init2(g_dir, g_dir, &cfg);

    km_log_debug("simulated debug: should be DROPPED at level=info");
    km_log_info("simulated info: kept at level=info");
    km_log_warn("simulated warn: kept at level=info");
    km_log_error("simulated error: kept at level=info");

    km_log_deinit();
    dump_oplog("落盘内容（debug 行已被过滤，不在文件中）");

    printf("\n完成：输出目录 %s\n", g_dir);
    return 0;
}
