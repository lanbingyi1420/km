/* 管理通路统一抽象层
 * 按编译环境 KM_ENV 分别处理（见 km_env.h）：
 *   - BOARD：正式通路 GMAC + FPGA，仅允许 COMM_PATH_FORMAL；
 *   - SIM（WIN/LINUX）：模拟通路消息队列，仅允许 COMM_PATH_SIMULATION。
 * 运行时 g_path 保留用于查询，但仅能取环境允许的通路。 */

#include "km_comm.h"
#include "km_env.h"
#include "km_log.h"
#include "km_types.h"
#include "msg_queue.h"

#if KM_ENV_IS_BOARD()
#include "gmac_comm.h"
#include "fpga_comm.h"
#else
#include "sim_comm.h"
#endif

#if KM_ENV_IS_BOARD()
#define KM_ENV_DEFAULT_PATH COMM_PATH_FORMAL
#else
#define KM_ENV_DEFAULT_PATH COMM_PATH_SIMULATION
#endif

static km_comm_path_t g_path = KM_ENV_DEFAULT_PATH;
static int g_inited = 0;

#define KM_RX_QUEUE_CAP 16 /* 收帧队列槽位数（业务慢时丢帧告警） */
#define KM_TX_QUEUE_CAP 16 /* 发送队列槽位数 */
#define KM_QUEUE_SLOT_LEN KM_MAX_MSG_LEN

static km_msg_queue_t g_rx_q;
static km_msg_queue_t g_tx_q;
static int g_q_inited = 0;
static volatile int g_worker_stop = 0;
static volatile int g_worker_running = 0; /* 通信线程运行标志：未运行时 send_async 退化为同步发送 */

/* 初始化管理通路：环境约束（BOARD=正式通路，SIM=模拟通路），
 * 与 KM_ENV 不符的通路返回 NOT_SUPPORTED；重复调用返回 ALREADY_INIT */
km_err_t km_comm_init(km_comm_path_t path, gmac_mode_t gmac_mode)
{
    km_err_t err;

    /* 环境约束优先：与 KM_ENV 不符的通路始终拒绝（即使已初始化） */
    if (path != KM_ENV_DEFAULT_PATH)
        return KM_ERR_NOT_SUPPORTED;
    if (g_inited)
        return KM_ERR_ALREADY_INIT;
    g_path = path;

#if KM_ENV_IS_BOARD()
    /* 正式隔离架构环境：GMAC 通道 + FPGA */
    err = km_gmac_init(gmac_mode, NULL);
    if (err != KM_ERR_OK)
        return err;
    err = km_fpga_init();
#else
    /* 单板模拟环境：与管理服务通信（WIN 内存队列 / LINUX System V 消息队列） */
    (void)gmac_mode;
    err = km_sim_init();
#endif

    if (err != KM_ERR_OK)
        return err;
    if (km_msg_queue_init(&g_rx_q, KM_RX_QUEUE_CAP, KM_QUEUE_SLOT_LEN) != KM_ERR_OK ||
        km_msg_queue_init(&g_tx_q, KM_TX_QUEUE_CAP, KM_QUEUE_SLOT_LEN) != KM_ERR_OK) {
        km_msg_queue_deinit(&g_rx_q);
        km_msg_queue_deinit(&g_tx_q);
        return KM_ERR_COMM_FAIL;
    }
    g_worker_stop = 0;
    g_q_inited = 1;
    g_inited = 1;
    return KM_ERR_OK;
}

/* 反初始化管理通路（按环境释放底层通道） */
void km_comm_deinit(void)
{
    if (!g_inited)
        return;
    if (g_q_inited) {
        km_msg_queue_deinit(&g_rx_q);
        km_msg_queue_deinit(&g_tx_q);
        g_q_inited = 0;
    }
#if KM_ENV_IS_BOARD()
    km_fpga_deinit();
    km_gmac_deinit();
#else
    km_sim_deinit();
#endif
    g_inited = 0;
}

/* 返回当前生效的管理通路类型（始终为环境允许的通路） */
km_comm_path_t km_comm_path(void)
{
    return g_path;
}

/* 发送数据到管理服务 */
km_err_t km_comm_send(const uint8_t *data, size_t len)
{
    if (!g_inited)
        return KM_ERR_COMM_FAIL;
#if KM_ENV_IS_BOARD()
    /* 正式通路：经 GMAC 原始通道下发，由 FPGA 转发给内网 D3000M 管理服务 */
    return km_gmac_send(data, len);
#else
    return km_sim_send(data, len);
#endif
}

/* 从管理通路接收一帧数据（阻塞语义由底层实现决定） */
km_err_t km_comm_recv(uint8_t *buf, size_t cap, size_t *len)
{
    if (!g_inited)
        return KM_ERR_COMM_FAIL;
#if KM_ENV_IS_BOARD()
    return km_gmac_recv(buf, cap, len);
#else
    return km_sim_recv(buf, cap, len);
#endif
}

/* 异步发送：入发送队列由通信线程 km_comm_send；
 * 通信线程未启动/未启用/未初始化时退化为同步发送（测试与启动阶段行为一致） */
km_err_t km_comm_send_async(const uint8_t *data, size_t len)
{
    if (g_q_inited && g_worker_running) {
        int r = km_msg_queue_push(&g_tx_q, data, len);

        if (r == 0)
            return KM_ERR_BAD_PARAM;
        if (r < 0)
            km_oplog_write(LOG_LEVEL_WARN, "comm: tx queue full, frame dropped");
        return KM_ERR_OK;
    }
    return km_comm_send(data, len);
}

void km_comm_worker(void *arg)
{
    uint8_t rbuf[KM_MAX_MSG_LEN];
    uint8_t tbuf[KM_MAX_MSG_LEN];

    (void)arg;
    g_worker_running = 1;
    while (!g_worker_stop) {
        size_t rlen = 0;

        /* 收帧：底层非阻塞 recv → 入收帧队列 */
        if (km_comm_recv(rbuf, sizeof(rbuf), &rlen) == KM_ERR_OK) {
            if (km_msg_queue_push(&g_rx_q, rbuf, rlen) < 0)
                km_oplog_write(LOG_LEVEL_WARN, "comm: rx queue full, frame dropped");
        }
        /* 发送：发送队列 → 底层发送 */
        if (km_msg_queue_pop(&g_tx_q, tbuf, sizeof(tbuf), &rlen) == 1)
            km_comm_send(tbuf, rlen);

        km_thread_sleep_ms(2);
    }
    g_worker_running = 0;
}

km_err_t km_comm_frame_pop(uint8_t *buf, size_t cap, size_t *len)
{
    if (!g_q_inited)
        return KM_ERR_COMM_FAIL;
    if (km_msg_queue_pop(&g_rx_q, buf, cap, len) == 1)
        return KM_ERR_OK;
    return KM_ERR_COMM_FAIL;
}

void km_comm_worker_stop(void)
{
    g_worker_stop = 1;
}
