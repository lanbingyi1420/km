/* msgq_probe.c — System V 消息队列"管理服务侧"探针（SIM_LINUX 单板联调冒烟用）
 *
 * 打开管理服务通信消息队列（默认 key=88，约定见 sim_comm.h），
 * 接收 KM 上报消息（mtype=1，即 KM 经 sim_comm 投递的帧），打印帧长
 * 与前 16B hex，收满预期帧数后正常退出。
 *
 * 典型用途（scripts/build_linux_sim.sh smoke）：
 *   先启动 km 主程序（heartbeat 周期 2s），本探针作为对端接收心跳帧，
 *   验证 KM 的 System V 消息队列后端 send 链路真实可用。
 *
 * 用法：msgq_probe [-k key] [-w wait_sec] [-n count]
 *   -k  消息队列 key（十进制或 0x 十六进制），默认 88
 *   -w  总等待秒数，默认 5（到点未收满按超时退出）
 *   -n  期望接收帧数，默认 1（收满立即退出）
 *
 * 退出码：0 = 收满预期帧；1 = 超时未收满；2 = 系统调用失败。
 * 独立实现（仅 POSIX，不依赖项目头文件/源码），便于在联调机器单独编译。
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

/* 与 sim_comm.h 保持一致的联调约定 */
#define KM_MNG_CH_MNG_RECV 1L   /* KM 上报方向消息类型（管理服务接收通道） */
#define KM_MNG_MSGQ_MODE   0600 /* 队列访问权限（仅属主） */

#define MAX_TEXT 4096 /* 与 KM_MAX_MSG_LEN 一致 */
#define HEX_BYTES 16

typedef struct {
    long     mtype;
    uint8_t  mtext[MAX_TEXT];
} probe_msg_t;

static volatile sig_atomic_t g_timedout = 0;

static void on_alarm(int sig)
{
    (void)sig;
    g_timedout = 1;
}

static void print_hex(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        printf("%02X%s", p[i], (i + 1) % 8 == 0 ? "  " : " ");
    printf("\n");
}

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

int main(int argc, char **argv)
{
    long key = 88, wait_sec = 5, need = 1;
    int qid, rc = 1;
    probe_msg_t msg;
    long i;
    struct sigaction sa;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key = parse_long(argv[++i], 1, 0x7fffffffL);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            wait_sec = parse_long(argv[++i], 0, 86400L);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            need = parse_long(argv[++i], 1, 1000000L);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("usage: msgq_probe [-k key] [-w wait_sec] [-n count]\n");
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 2;
        }
    }

    qid = msgget((key_t)key, IPC_CREAT | KM_MNG_MSGQ_MODE);
    if (qid < 0) {
        perror("msgget");
        return 2;
    }
    printf("msgq_probe: queue key=%ld msgqid=%d, "
           "wait for mtype=%ld frames\n", key, qid, (long)KM_MNG_CH_MNG_RECV);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
    alarm((unsigned int)wait_sec);

    while (need > 0 && !g_timedout) {
        ssize_t n = msgrcv(qid, &msg, sizeof(msg.mtext),
                           KM_MNG_CH_MNG_RECV, 0);
        if (n < 0) {
            if (errno == EINTR)
                break; /* alarm 到期 */
            perror("msgrcv");
            return 2;
        }
        printf("rx mtype=%ld len=%zd bytes: ", msg.mtype, n);
        print_hex(msg.mtext, (size_t)n < HEX_BYTES ? (size_t)n : HEX_BYTES);
        if (n >= 2 && msg.mtext[0] == 0x5A && msg.mtext[1] == 0x5A)
            printf("  frame magic 5A 5A (FPGA head 0x5a5a) OK\n");
        need--;
    }
    alarm(0);

    if (need <= 0) {
        printf("msgq_probe: received all expected frames\n");
        rc = 0;
    } else {
        printf("msgq_probe: timeout, %ld frame(s) still pending\n", need);
        rc = 1;
    }
    return rc;
}
