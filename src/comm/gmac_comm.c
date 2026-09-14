/* GmacComm：GMAC 通道
 * 正式隔离架构环境（KM_ENV_BOARD）下作为正式通路的底层承载；
 * 单板模拟环境（KM_ENV_SIM_*）下仅用于协议自测（km_gmac_inject 注入）。
 * 第一阶段为 loopback 回环桩（内存 FIFO 模拟收发）；
 * 真实 AF_PACKET 实现（raw 模式）预留，接入后 BOARD 默认配置切 GMAC_MODE_RAW。
 */

#include "gmac_comm.h"
#include "km_env.h"
#include <string.h>

#define GMAC_QUEUE_MAX 16
#define GMAC_FRAME_MAX KM_MAX_MSG_LEN

typedef struct {
    uint8_t  data[GMAC_FRAME_MAX];
    size_t   len;
} gmac_slot_t;

static gmac_slot_t g_rx[GMAC_QUEUE_MAX];
static int g_rx_head = 0;
static int g_rx_count = 0;
static int g_inited = 0;

/* GMAC 初始化：仅支持回环模式（第一阶段桩，真实 AF_PACKET 预留）；成功返回 OK */
km_err_t km_gmac_init(gmac_mode_t mode, const char *ifname)
{
    (void)ifname;
    if (mode != GMAC_MODE_LOOPBACK)
        return KM_ERR_NOT_SUPPORTED; /* 第一阶段仅支持回环桩 */
    g_rx_head = 0;
    g_rx_count = 0;
    g_inited = 1;
    return KM_ERR_OK;
}

/* GMAC 反初始化（桩：置无效） */
void km_gmac_deinit(void)
{
    g_inited = 0;
}

/* GMAC 发送（回环桩：仅校验参数，帧不真正发出） */
km_err_t km_gmac_send(const uint8_t *data, size_t len)
{
    if (!g_inited)
        return KM_ERR_COMM_FAIL;
    if (data == NULL || len == 0 || len > GMAC_FRAME_MAX)
        return KM_ERR_BAD_PARAM;
    return KM_ERR_OK;
}

/* GMAC 接收（回环桩：从注入队列取帧，空队返回 COMM_FAIL） */
km_err_t km_gmac_recv(uint8_t *buf, size_t cap, size_t *len)
{
    if (!g_inited || buf == NULL || len == NULL)
        return KM_ERR_COMM_FAIL;
    if (g_rx_count == 0)
        return KM_ERR_COMM_FAIL;

    {
        const gmac_slot_t *s = &g_rx[g_rx_head];
        if (s->len > cap)
            return KM_ERR_BUF_TOO_SMALL;
        memcpy(buf, s->data, s->len);
        *len = s->len;
        g_rx_head = (g_rx_head + 1) % GMAC_QUEUE_MAX;
        g_rx_count--;
        return KM_ERR_OK;
    }
}

/* 测试辅助：向接收队列注入一帧（模拟对端下发，队满返回 COMM_FAIL） */
km_err_t km_gmac_inject(const uint8_t *data, size_t len)
{
    int tail;

    if (!g_inited)
        return KM_ERR_COMM_FAIL;
    if (data == NULL || len == 0 || len > GMAC_FRAME_MAX)
        return KM_ERR_BAD_PARAM;
    if (g_rx_count >= GMAC_QUEUE_MAX)
        return KM_ERR_COMM_FAIL;

    tail = (g_rx_head + g_rx_count) % GMAC_QUEUE_MAX;
    memcpy(g_rx[tail].data, data, len);
    g_rx[tail].len = len;
    g_rx_count++;
    return KM_ERR_OK;
}
