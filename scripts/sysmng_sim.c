/* sysmng_sim.c — System V 消息队列"管理服务（sysmng）侧"心跳双向联调模拟器
 *（SIM_LINUX 单板模拟联调用，独立实现，仅 POSIX，不依赖项目头文件/源码）
 *
 * 背景：KM 主程序（SIM_LINUX）经 System V 消息队列（默认 key=88，约定见
 * src/comm/sim_comm.h）与管理服务通信，mtype 即接收端通道号：
 *   - KM 上报 / 管理服务接收  -> mtype=1；
 *   - 管理服务下发 / KM 接收   -> mtype=2。
 * 心跳协议（见 src/comm/mgmt_protocol.h / src/app/heartbeat.h）：
 *   - KM 定时主动发送心跳（msg_cmd=0x01，sender=KM=4，receiver=管理服务=0，
 *     帧头 msg_type=toSYSMNG=0x3131），msg_id 自增 1（首帧=1）；
 *     管理服务收到后应回显同 msg_id（sender=管理服务=0，receiver=KM=4，
 *     msg_type=fromSYSMNG=0x1231），KM 以"期望槽匹配"确认存活；
 *   - 管理服务也可主动问询（任意 msg_id 下发心跳），KM 收到不匹配帧会应答并
 *     回显其 msg_id。
 * 本工具模拟管理服务行为并自动校验完整闭环：
 *   rx KM 主动心跳（递增 msg_id + TLV 0x01 心跳信息 5B）-> 自动回显回执；
 *   -q 下周期主动问询 -> 等待 KM 同 msg_id 应答帧，匹配即判定"问询应答 OK"。
 *
 * 用法：sysmng_sim [-k key] [-t sec] [-q qsec] [-n need] [-e|-E] [-v]
 *   -k key   消息队列 key（十进制或 0x 十六进制），默认 88
 *   -t sec   运行总时限（秒），默认 15；到点未满足成功条件按失败退出
 *   -q qsec  管理服务主动心跳问询间隔（秒）；0 = 不问询（默认 3）
 *   -n need  期望收到的 KM 主动心跳最小帧数（默认 1）
 *   -e       收到 KM 主动心跳即回显同 msg_id 回执（默认开启；联调验证用）
 *   -E       不回执（观察 KM 超时告警的对照场景）
 *   -v       兼容保留（心跳交互帧内容现默认按 16 进制逐帧回显）
 *   -h       帮助
 *
 * 成功条件：收到 >= need 帧 KM 主动心跳；且 -q>0 时至少收到 1 次问询应答。
 * 退出码：0 = 成功；1 = 超时/条件不足；2 = 系统调用失败/参数错误。
 * 退出前打印统计表（供脚本解析与人工核对）。
 *
 * 独立于项目源码编译，便于在联调机器单独使用：
 *   cc -Wall -Wextra -O2 sysmng_sim.c -o sysmng_sim
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

/* ---------- 与 sim_comm.h / mgmt_protocol.h 保持一致的线格式约定 ---------- */

#define KM_MNG_CH_MNG_RECV   1L  /* KM 上报方向消息类型（管理服务接收通道） */
#define KM_MNG_CH_KM_RECV    2L  /* KM 接收端通道（管理服务->KM 方向 mtype） */
#define KM_MNG_MSGQ_MODE     0600

#define KM_MNG_HEAD_MAGIC    0x68
#define KM_FRAME_MIN_LEN     64   /* 最短帧长（GMAC 最小传输要求，模拟沿用） */
#define KM_FRAME_ALIGN       8
#define KM_MAX_MSG_LEN       4096

#define FPGA_MSGTYPE_fromSYSMNG 0x1231 /* 管理服务->密码管理（下行） */
#define FPGA_MSGTYPE_toSYSMNG   0x3131 /* 密码管理->管理服务（上行） */

#define KM_SENDER_MNG        0    /* 管理服务 */
#define KM_SENDER_KM         4    /* 密码管理模块 */

#define SYSMNG_MSG_TYPE_HEARTBEAT 0x01

#define TLV_TAG_HB_INFO      0x01 /* 心跳信息 TLV */
#define HB_INFO_LEN          5    /* uptime_sec 4B 小端 + dev_status 1B */
#define FPGA_HEAD_LEN        8
#define MNG_HEAD_LEN         8
#define MNG_TOTAL_HEAD       (FPGA_HEAD_LEN + MNG_HEAD_LEN) /* 16 */

/* 心跳 TLV 内 dev_status 常用取值（km_types.h km_dev_status_t） */
#define DEV_STATUS_BOOTING   0xFF
#define DEV_STATUS_READY     0x01

typedef struct {
    long     mtype;
    uint8_t  mtext[KM_MAX_MSG_LEN];
} sim_msg_t;

/* ---------- 帧视图（构造/解析共用，字节偏移即线格式，主机小端前提） ---------- */

typedef struct {
    uint8_t  magic_ok;      /* 0=帧头非法 */
    uint16_t msg_type;      /* FPGA 帧头 msg_type（方向/通道） */
    uint8_t  padding_len;
    uint16_t pkt_len;
    uint8_t  head_ok;       /* 管理头 0x68 检查 */
    uint16_t mng_len;       /* 管理消息长度（8 + TLV） */
    uint8_t  msg_id;
    uint8_t  sender;
    uint8_t  receiver;
    uint16_t msg_cmd;       /* 2B 小端 */
    uint8_t  hb_uptime[4];  /* TLV 0x01 心跳信息：uptime_sec 小端 */
    uint8_t  hb_dev_status;
    int      hb_info_got;
} frame_view_t;

static void store_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static uint16_t load_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 组一帧管理服务侧心跳（下行 mtype=2）：
 * [5A 5A][msg_type=fromSYSMNG LE][reserve][padding_len][pkt_len LE] 8B
 * [0x68][len LE][msg_id][sender=0][receiver=4][cmd LE]                 8B
 * 无 TLV 载荷；尾部填充至整帧 8 字节对齐且 >= 64B，填充字节值 = padding_len */
static void build_heartbeat_frame(uint8_t *out, size_t *out_len,
                                  uint8_t msg_id)
{
    uint8_t  pad_len;
    uint16_t mng_len, pkt_len;
    size_t   total, data_len;

    mng_len = MNG_HEAD_LEN;                  /* 无 TLV */
    data_len = MNG_TOTAL_HEAD;               /* 16 */
    total = (data_len + KM_FRAME_ALIGN - 1) & ~(size_t)(KM_FRAME_ALIGN - 1);
    if (total < KM_FRAME_MIN_LEN)
        total = KM_FRAME_MIN_LEN;
    pad_len = (uint8_t)(total - data_len);
    pkt_len = (uint16_t)(mng_len + pad_len);

    memset(out, 0, total);
    out[0] = 0x5A; out[1] = 0x5A;                        /* FPGA 帧头 magic */
    store_le16(out + 2, FPGA_MSGTYPE_fromSYSMNG);        /* 管理服务 -> 密码管理 */
    out[4] = 0;                                          /* reserve */
    out[5] = pad_len;
    store_le16(out + 6, pkt_len);
    out[8] = KM_MNG_HEAD_MAGIC;
    store_le16(out + 9, mng_len);
    out[11] = msg_id;
    out[12] = KM_SENDER_MNG;
    out[13] = KM_SENDER_KM;
    store_le16(out + 14, SYSMNG_MSG_TYPE_HEARTBEAT);
    /* 尾部填充：填充字节值 = pad_len */
    memset(out + data_len, pad_len, pad_len);

    *out_len = total;
}

/* 解析 KM 上行帧（mtype=1，整帧即 STU_TLV_MNG_HEAD 视图） */
static void parse_frame(const uint8_t *in, size_t in_len, frame_view_t *v)
{
    const uint8_t *tlv;
    size_t tlv_len, off = 0;

    memset(v, 0, sizeof(*v));
    if (in == NULL || in_len < MNG_TOTAL_HEAD)
        return;
    if (in[0] == 0x5A && in[1] == 0x5A)
        v->magic_ok = 1;
    v->msg_type = load_le16(in + 2);
    v->padding_len = in[5];
    v->pkt_len = load_le16(in + 6);
    if (in[8] == KM_MNG_HEAD_MAGIC)
        v->head_ok = 1;
    v->mng_len = load_le16(in + 9);
    v->msg_id = in[11];
    v->sender = in[12];
    v->receiver = in[13];
    v->msg_cmd = load_le16(in + 14);

    /* 心跳信息 TLV：0x01 + 2B 大端长 + value */
    tlv = in + MNG_TOTAL_HEAD;
    tlv_len = (size_t)v->mng_len - MNG_HEAD_LEN;
    while (tlv_len - off >= 3) {
        uint16_t l = (uint16_t)(((uint16_t)tlv[off + 1] << 8) | tlv[off + 2]);
        if (tlv_len - off - 3 < l)
            break;
        if (tlv[off] == TLV_TAG_HB_INFO && l == HB_INFO_LEN) {
            memcpy(v->hb_uptime, tlv + off + 3, 4);
            v->hb_dev_status = tlv[off + 3 + 4];
            v->hb_info_got = 1;
            break;
        }
        off += 3 + l;
    }
}

static const char *sender_name(uint8_t s)
{
    return s == KM_SENDER_MNG ? "MNG" : s == KM_SENDER_KM ? "KM" : "?";
}

/* ---------- 运行状态 ---------- */

static int g_verbose = 0;
static int g_echo = 1;
static unsigned g_active_hb = 0;   /* 收到 KM 主动心跳帧数 */
static unsigned g_query_ack = 0;   /* 收到 KM 问询应答帧数 */
static unsigned g_query_tx = 0;    /* 发出问询次数 */
static unsigned g_echo_tx = 0;     /* 发出回显回执次数 */
static unsigned g_rx_total = 0;    /* 收到 KM 上行帧总数 */
static long    g_query_last_id = -1; /* 最近一次问询所用 msg_id；-1=无 */
static int     g_query_pending = 0;  /* 有问询等待 KM 应答 */
static long    g_hb_prev_id = -1;    /* 上一个 KM 主动心跳 msg_id（观察递增） */
static int     g_hb_seq_ok = 1;

static long parse_long(const char *s, long lo, long hi)
{
    char *end = NULL;
    long v;

    errno = 0;
    v = strtol(s, &end, 0);
    if (errno != 0 || end == NULL || *end != '\0' || v < lo || v > hi) {
        fprintf(stderr, "invalid number: %s (range %ld..%ld)\n", s, lo, hi);
        exit(2);
    }
    return v;
}

static void print_hex(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        printf("%02X%s", p[i], (i + 1) % 8 == 0 ? "  " : " ");
    printf("\n");
}

static void usage(const char *prog)
{
    printf("usage: %s [-k key] [-t sec] [-q qsec] [-n need] [-e|-E] [-v]\n"
           "\n"
           "  -k key   消息队列 key，默认 88（十进制或 0x 十六进制）\n"
           "  -t sec   运行总时限（秒），默认 15\n"
           "  -q qsec  管理服务主动心跳问询间隔（秒），0=不问询（默认 3）\n"
           "  -n need  期望收到的 KM 主动心跳最小帧数（默认 1）\n"
           "  -e       收到 KM 主动心跳即回显回执（默认开启）\n"
           "  -E       不回执（对照：观察 KM 超时告警）\n"
           "  -v       兼容保留（心跳交互帧内容默认按 16 进制回显）\n"
           "  -h       帮助\n", prog);
}

int main(int argc, char **argv)
{
    long key = 88, wait_sec = 15, q_sec = 3, need = 1;
    int qid, i, rc = 1;
    sim_msg_t msg;
    struct timespec ts;
    time_t t0, deadline;
    unsigned frame_no = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key = parse_long(argv[++i], 1, 0x7fffffffL);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            wait_sec = parse_long(argv[++i], 0, 86400L);
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            q_sec = parse_long(argv[++i], 0, 86400L);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            need = parse_long(argv[++i], 1, 1000000L);
        } else if (strcmp(argv[i], "-e") == 0) {
            g_echo = 1;
        } else if (strcmp(argv[i], "-E") == 0) {
            g_echo = 0;
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    qid = msgget((key_t)key, IPC_CREAT | KM_MNG_MSGQ_MODE);
    if (qid < 0) {
        perror("msgget");
        return 2;
    }
    printf("sysmng_sim: queue key=%ld msgqid=%d | rx mtype=%ld (KM->MNG) "
           "tx mtype=%ld (MNG->KM)\n",
           key, qid, (long)KM_MNG_CH_MNG_RECV, (long)KM_MNG_CH_KM_RECV);
    printf("sysmng_sim: echo=%s query_interval=%lds expect_active_hb=%ld "
           "timeout=%lds\n",
           g_echo ? "on" : "off", q_sec, need, wait_sec);

    ts.tv_sec = 0;
    ts.tv_nsec = 10 * 1000 * 1000; /* 10ms 轮询 */
    t0 = time(NULL);
    deadline = t0 + wait_sec;

    while (1) {
        ssize_t n;
        frame_view_t v;
        time_t now;

        /* 1) 收取 KM 上行帧（mtype=1，非阻塞轮询） */
        n = msgrcv(qid, &msg, sizeof(msg.mtext), KM_MNG_CH_MNG_RECV, IPC_NOWAIT);
        if (n >= 0) {
            frame_no++;
            g_rx_total++;
            parse_frame(msg.mtext, (size_t)n, &v);
            printf("[rx #%u len=%zd] magic=%d head=%d msg_type=0x%04x "
                   "cmd=0x%04x msg_id=%u %s(%u)->%s(%u) tlv_info=%d\n",
                   frame_no, n, v.magic_ok, v.head_ok, v.msg_type,
                   v.msg_cmd, v.msg_id, sender_name(v.sender), v.sender,
                   sender_name(v.receiver), v.receiver, v.hb_info_got);
            if (v.hb_info_got) {
                printf("    hb info: uptime_sec=%lu dev_status=0x%02x%s\n",
                       (unsigned long)load_le32(v.hb_uptime), v.hb_dev_status,
                       v.hb_dev_status == DEV_STATUS_READY ? " (READY)" :
                       v.hb_dev_status == DEV_STATUS_BOOTING ? " (BOOTING)" : "");
            }
            /* 心跳交互帧内容全帧 16 进制回显（收/发各一次，含帧头与填充） */
            printf("    rx hex (%zdB): ", n);
            print_hex(msg.mtext, (size_t)n);

            if (v.magic_ok && v.head_ok && v.sender == KM_SENDER_KM &&
                v.msg_cmd == SYSMNG_MSG_TYPE_HEARTBEAT) {
                if (g_query_pending && (long)v.msg_id == g_query_last_id) {
                    /* 对本机最近一次问询的应答：回显 msg_id 一致 */
                    g_query_ack++;
                    g_query_pending = 0;
                    printf("    => QUERY ACK: KM replied same msg_id %u\n",
                           v.msg_id);
                } else {
                    /* KM 主动心跳上报 */
                    g_active_hb++;
                    if (g_hb_prev_id >= 0 &&
                        (long)v.msg_id != (g_hb_prev_id + 1))
                        g_hb_seq_ok = 0;
                    g_hb_prev_id = v.msg_id;
                    printf("    => KM active heartbeat msg_id=%u\n", v.msg_id);
                    if (g_echo) {
                        size_t olen;
                        build_heartbeat_frame(msg.mtext, &olen, v.msg_id);
                        msg.mtype = KM_MNG_CH_KM_RECV;
                        if (msgsnd(qid, &msg, olen, IPC_NOWAIT) < 0)
                            perror("msgsnd(echo)");
                        else {
                            g_echo_tx++;
                            printf("    => echo reply msg_id=%u sent (mtype=2)\n",
                                   v.msg_id);
                            printf("    tx hex (%zuB): ", olen);
                            print_hex(msg.mtext, olen);
                        }
                    }
                }
            }
        } else if (errno != ENOMSG) {
            if (errno == EIDRM || errno == EINVAL) {
                fprintf(stderr, "message queue removed\n");
                break;
            }
            perror("msgrcv");
            rc = 2;
            break;
        }

        /* 2) 周期主动问询（mtype=2 心跳，msg_id 自高段取避免与 KM 主动冲突） */
        now = time(NULL);
        if (q_sec > 0 && !g_query_pending && (now - t0) >= (time_t)(g_query_tx + 1) * q_sec) {
            size_t olen;
            uint8_t qid8 = (uint8_t)(0x51 + g_query_tx); /* 0x51.. */
            build_heartbeat_frame(msg.mtext, &olen, qid8);
            msg.mtype = KM_MNG_CH_KM_RECV;
            if (msgsnd(qid, &msg, olen, IPC_NOWAIT) < 0) {
                perror("msgsnd(query)");
            } else {
                g_query_last_id = qid8;
                g_query_pending = 1;
                g_query_tx++;
                printf("[tx query #%u] heartbeat msg_id=%u sent (mtype=2), "
                       "wait KM reply with same id\n", g_query_tx, qid8);
                printf("    tx hex (%zuB): ", olen);
                print_hex(msg.mtext, olen);
            }
        }

        /* 3) 持续监听至 deadline（不提前退出：让"持续无 lost"类判定可观察
         *    完整超时窗；成功与否仅由退出码与 summary 表达） */
        if (now >= deadline)
            break;

        nanosleep(&ts, NULL);
    }

    printf("==== sysmng_sim summary ====\n");
    printf("  runtime          : %lds (limit %lds)\n",
           (long)(time(NULL) - t0), wait_sec);
    printf("  rx frames (KM->MNG): %u (active hb: %u, query ack: %u)\n",
           g_rx_total, g_active_hb, g_query_ack);
    printf("  tx frames (MNG->KM): %u (echo: %u, query: %u)\n",
           g_echo_tx + g_query_tx, g_echo_tx, g_query_tx);
    if (g_active_hb >= 2)
        printf("  hb msg_id monotonic: %s\n", g_hb_seq_ok ? "OK" : "MISMATCH");
    printf("  expect active hb   : >= %ld\n", need);

    if (g_active_hb >= (unsigned)need && (q_sec == 0 || g_query_ack >= 1)) {
        printf("result: PASS\n");
        rc = 0;
    } else {
        printf("result: FAIL (missing frames: active_hb=%u need=%ld "
               "query_ack=%u q=%ld)\n",
               g_active_hb, need, g_query_ack, q_sec);
        rc = 1;
    }
    return rc;
}
