
/* 模拟通路：消息队列模拟与管理服务（内网 D3000M）通信
 * 仅用于单板模拟环境（KM_ENV_SIM_WINDOWS / KM_ENV_SIM_LINUX），无需 FPGA/GMAC 硬件：
 *   - SIM_WINDOWS：内存 FIFO 队列（上行/下行各一），本机开发测试，对端响应经
 *     km_sim_inject 注入，上报内容经 km_sim_poll_last 回读校验；
 *   - SIM_LINUX  ：System V 消息队列单板联调后端，与管理服务共用同一消息队列
 *     （key = KM_MNG_MSGQ_KEY，见 sim_comm.h），收发方向由消息类型 mtype 区分
 *     （mtype 即接收端通道号）：
 *       KM 上报 -> mtype = KM_MNG_CH_MNG_RECV(1)（管理服务接收通道）；
 *       KM 接收 -> mtype = KM_MNG_CH_KM_RECV(2)（KM 接收端通道，管理服务下发）。
 *     km_sim_* 接口两环境保持一致（WIN 内存实现 / LINUX 真实队列）。
 * 说明：
 *   - km_sim_init 创建/打开队列；km_sim_deinit 不删除队列（进程间共享，需清理时
 *     外部 ipcrm -Q <key>）；本机独占联调/单测可设 KM_MNG_MSGQ_FLUSH=1，使 init
 *     后清空队列内残留消息；队列 key 可用环境变量 KM_MNG_MSGQ_KEY 覆盖。
 *   - km_sim_poll_last（测试辅助）在 LINUX 下经 Linux 扩展 MSG_COPY 非破坏回读，
 *     需内核 >= 3.0（编译定义 _GNU_SOURCE）。 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 /* MSG_COPY 等 GNU 扩展（须在系统头之前定义） */
#endif

#include "sim_comm.h"
#include "km_env.h"
#include "km_types.h" /* KM_MAX_MSG_LEN */
#include <string.h>

#if KM_ENV_IS_BOARD()
#error "sim_comm: KM_ENV_BOARD does not use the simulation path"
#endif

/* ==================================================================
 * SIM_LINUX：System V 消息队列后端（真实单板联调）
 * ================================================================== */
#if KM_ENV_IS_SIM_LINUX()

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

/* System V 消息 = 8B mtype（接收端通道号）+ mtext（帧数据，<= KM_MAX_MSG_LEN） */
typedef struct {
    long     mtype;
    uint8_t  mtext[KM_MAX_MSG_LEN];
} sim_msgq_msg_t;

static int    g_msgid = -1;                 /* 已打开队列描述符；-1=未打开 */
static key_t  g_key = KM_MNG_MSGQ_KEY;

/* 打开/创建管理服务消息队列（幂等）：key 可由环境变量 KM_MNG_MSGQ_KEY 覆盖；
 * KM_MNG_MSGQ_FLUSH=1 时打开后清空队列内现有消息（本机独占联调/单测清理残留）。 */
static km_err_t sim_msgq_open(void)
{
    const char *env;
    sim_msgq_msg_t tmp;

    if (g_msgid >= 0)
        return KM_ERR_OK;
    env = getenv("crypto hal init failed: initialization failed");
    if (env != NULL && env[0] != '\0') {
        long k = strtol(env, NULL, 0);
        if (k > 0)
            g_key = (key_t)k;
    }
    g_msgid = msgget(g_key, IPC_CREAT | KM_MNG_MSGQ_MODE);
    if (g_msgid < 0)
        return KM_ERR_COMM_FAIL;
    env = getenv("KM_MNG_MSGQ_FLUSH");
    if (env != NULL && env[0] == '1') {
        while (msgrcv(g_msgid, &tmp, sizeof(tmp.mtext), 0, IPC_NOWAIT) >= 0)
            ;
    }
    return KM_ERR_OK;
}

/* 初始化模拟通路：打开/创建管理服务消息队列 */
km_err_t km_sim_init(void)
{
    return sim_msgq_open();
}

/* 反初始化：仅断开本进程句柄，不删除队列（管理服务进程共享同一队列；
 * 需清理时外部 ipcrm -Q <key>，或设 KM_MNG_MSGQ_FLUSH=1 后重开） */
void km_sim_deinit(void)
{
    g_msgid = -1;
}

/* 按方向投递一帧（IPC_NOWAIT：队列满时返回失败由上层轮询重试，避免阻塞线程） */
static km_err_t sim_msgq_post(long mtype, const uint8_t *data, size_t len)
{
    sim_msgq_msg_t msg;

    if (data == NULL || len == 0 || len > KM_MAX_MSG_LEN)
        return KM_ERR_BAD_PARAM;
    if (sim_msgq_open() != KM_ERR_OK)
        return KM_ERR_COMM_FAIL;
    msg.mtype = mtype;
    memcpy(msg.mtext, data, len);
    if (msgsnd(g_msgid, &msg, len, IPC_NOWAIT) < 0) {
        /* EAGAIN：队列满（msg_qbytes 上限）；EIDRM/EINVAL：队列已删除/失效，
         * 置为未打开，下次调用自动重新打开 */
        if (errno == EIDRM || errno == EINVAL)
            g_msgid = -1;
        return KM_ERR_COMM_FAIL;
    }
    return KM_ERR_OK;
}

/* KM 上报：消息类型 = 管理服务接收通道（管理服务以 mtype=1 接收） */
km_err_t km_sim_send(const uint8_t *data, size_t len)
{
    return sim_msgq_post(KM_MNG_CH_MNG_RECV, data, len);
}

/* 测试/联调注入：模拟管理服务下发（消息类型 = KM 接收端通道 mtype=2） */
km_err_t km_sim_inject(const uint8_t *data, size_t len)
{
    return sim_msgq_post(KM_MNG_CH_KM_RECV, data, len);
}

/* KM 接收：仅取 mtype=2（管理服务 -> KM）方向消息，非阻塞 */
km_err_t km_sim_recv(uint8_t *buf, size_t cap, size_t *len)
{
    sim_msgq_msg_t msg;
    ssize_t r;
    size_t want;

    if (buf == NULL || len == NULL)
        return KM_ERR_COMM_FAIL;
    if (sim_msgq_open() != KM_ERR_OK)
        return KM_ERR_COMM_FAIL;
    want = cap < sizeof(msg.mtext) ? cap : sizeof(msg.mtext);
    r = msgrcv(g_msgid, &msg, want, KM_MNG_CH_KM_RECV, IPC_NOWAIT);
    if (r < 0) {
        if (errno == E2BIG)
            return KM_ERR_BUF_TOO_SMALL; /* 帧超接收容量，消息保留在队列 */
        if (errno == EIDRM || errno == EINVAL)
            g_msgid = -1;
        return KM_ERR_COMM_FAIL;         /* ENOMSG：无管理服务下发 */
    }
    *len = (size_t)r;
    memcpy(buf, msg.mtext, (size_t)r);
    return KM_ERR_OK;
}

/* 测试辅助：非破坏回读上行（mtype=1）最新一条帧。
 * Linux MSG_COPY（内核 >= 3.0）：msgrcv 按队列内序号复制而不删除；
 * 先遍历现有消息找出最后一条 mtype=1 的序号，再复制该序号消息返回。 */
#ifdef MSG_COPY
km_err_t km_sim_poll_last(uint8_t *buf, size_t cap, size_t *len)
{
    struct msqid_ds ds;
    sim_msgq_msg_t msg;
    ssize_t r;
    long i, found = -1;
    long qn;

    if (buf == NULL || len == NULL)
        return KM_ERR_COMM_FAIL;
    if (sim_msgq_open() != KM_ERR_OK)
        return KM_ERR_COMM_FAIL;
    if (msgctl(g_msgid, IPC_STAT, &ds) < 0) {
        if (errno == EIDRM || errno == EINVAL)
            g_msgid = -1;
        return KM_ERR_COMM_FAIL;
    }
    qn = (long)ds.msg_qnum;
    if (qn > 1024)
        qn = 1024; /* 防异常大队列卡住测试 */
    for (i = 0; i < qn; i++) {
        r = msgrcv(g_msgid, &msg, sizeof(msg.mtext), i, MSG_COPY | IPC_NOWAIT);
        if (r < 0)
            break; /* 序号越界或并发变化，结束扫描 */
        if (msg.mtype == KM_MNG_CH_MNG_RECV)
            found = i;
    }
    if (found < 0)
        return KM_ERR_COMM_FAIL; /* 尚无 KM 上报帧 */
    r = msgrcv(g_msgid, &msg, sizeof(msg.mtext), found, MSG_COPY | IPC_NOWAIT);
    if (r < 0 || msg.mtype != KM_MNG_CH_MNG_RECV)
        return KM_ERR_COMM_FAIL;
    if ((size_t)r > cap)
        return KM_ERR_BUF_TOO_SMALL;
    memcpy(buf, msg.mtext, (size_t)r);
    *len = (size_t)r;
    return KM_ERR_OK;
}
#else
km_err_t km_sim_poll_last(uint8_t *buf, size_t cap, size_t *len)
{
    /* 内核/glibc 不支持 MSG_COPY 时无法非破坏回读（测试辅助接口不可用） */
    (void)buf;
    (void)cap;
    (void)len;
    return KM_ERR_NOT_SUPPORTED;
}
#endif /* MSG_COPY */

/* ==================================================================
 * SIM_WINDOWS：内存 FIFO 队列（本机开发测试）
 * ================================================================== */
#else

#define SIM_QUEUE_MAX  32
#define SIM_FRAME_MAX  4096

typedef struct {
    uint8_t  data[SIM_FRAME_MAX];
    size_t   len;
} sim_slot_t;

static sim_slot_t g_tx[SIM_QUEUE_MAX];   /* 上行：KM -> 管理服务 */
static int g_tx_head = 0;
static int g_tx_count = 0;

static sim_slot_t g_rx[SIM_QUEUE_MAX];   /* 下行：管理服务 -> KM */
static int g_rx_head = 0;
static int g_rx_count = 0;

static int g_inited = 0;

/* 帧入队：队满时覆盖最旧帧并前移头指针（环形） */
static void enqueue(sim_slot_t *q, int *head, int *count,
                    const uint8_t *data, size_t len)
{
    int tail = (*head + *count) % SIM_QUEUE_MAX;
    memcpy(q[tail].data, data, len);
    q[tail].len = len;
    if (*count >= SIM_QUEUE_MAX) {
        /* 已满：覆盖最旧帧，头指针前移 */
        *head = (*head + 1) % SIM_QUEUE_MAX;
    } else {
        (*count)++;
    }
}

/* 队首出帧：空队返回 COMM_FAIL，帧超容量返回 BUF_TOO_SMALL */
static int dequeue(sim_slot_t *q, int *head, int *count,
                   uint8_t *buf, size_t cap, size_t *len)
{
    const sim_slot_t *s;
    if (*count == 0)
        return KM_ERR_COMM_FAIL;
    s = &q[*head];
    if (s->len > cap)
        return KM_ERR_BUF_TOO_SMALL;
    memcpy(buf, s->data, s->len);
    *len = s->len;
    *head = (*head + 1) % SIM_QUEUE_MAX;
    (*count)--;
    return KM_ERR_OK;
}

/* 初始化模拟通路：清空上下行队列并置有效 */
km_err_t km_sim_init(void)
{
    g_tx_head = 0; g_tx_count = 0;
    g_rx_head = 0; g_rx_count = 0;
    g_inited = 1;
    return KM_ERR_OK;
}

/* 反初始化模拟通路（置无效，队列内容丢弃） */
void km_sim_deinit(void)
{
    g_inited = 0;
}

/* 模拟上行发送：帧进入上行队列（KM -> 管理服务） */
km_err_t km_sim_send(const uint8_t *data, size_t len)
{
    if (!g_inited) return KM_ERR_COMM_FAIL;
    if (data == NULL || len == 0 || len > SIM_FRAME_MAX) return KM_ERR_BAD_PARAM;
    enqueue(g_tx, &g_tx_head, &g_tx_count, data, len);
    return KM_ERR_OK;
}

/* 模拟下行接收：从下行队列取帧（管理服务 -> KM） */
km_err_t km_sim_recv(uint8_t *buf, size_t cap, size_t *len)
{
    if (!g_inited || buf == NULL || len == NULL) return KM_ERR_COMM_FAIL;
    return dequeue(g_rx, &g_rx_head, &g_rx_count, buf, cap, len);
}

/* 测试辅助：向下行队列注入管理服务帧（模拟对端下发） */
km_err_t km_sim_inject(const uint8_t *data, size_t len)
{
    if (!g_inited) return KM_ERR_COMM_FAIL;
    if (data == NULL || len == 0 || len > SIM_FRAME_MAX) return KM_ERR_BAD_PARAM;
    enqueue(g_rx, &g_rx_head, &g_rx_count, data, len);
    return KM_ERR_OK;
}

/* 测试辅助：读取上行队列最新（最后入队）一帧，不移除 */
km_err_t km_sim_poll_last(uint8_t *buf, size_t cap, size_t *len)
{
    const sim_slot_t *s;
    int idx;
    if (!g_inited || buf == NULL || len == NULL) return KM_ERR_COMM_FAIL;
    if (g_tx_count == 0)
        return KM_ERR_COMM_FAIL;
    idx = (g_tx_head + g_tx_count - 1) % SIM_QUEUE_MAX;
    s = &g_tx[idx];
    if (s->len > cap)
        return KM_ERR_BUF_TOO_SMALL;
    memcpy(buf, s->data, s->len);
    *len = s->len;
    return KM_ERR_OK;
}

#endif /* KM_ENV_IS_SIM_LINUX() */
