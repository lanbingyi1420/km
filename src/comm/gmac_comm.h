#ifndef KM_GMAC_COMM_H
#define KM_GMAC_COMM_H

#include <stdint.h>
#include <stddef.h>
#include "km_error.h"
#include "km_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * GMAC 通信层
 * 第一阶段：loopback 回环桩（内存管道），便于协议与指令处理全链路测试；
 * 第二阶段：raw 模式基于 AF_PACKET 原始套接字（预留）。
 */

km_err_t km_gmac_init(gmac_mode_t mode, const char *ifname);
void     km_gmac_deinit(void);

/** @brief 发送一帧（len <= KM_FRAME_MAX_LEN） */
km_err_t km_gmac_send(const uint8_t *data, size_t len);

/**
 * @brief 接收一帧（非阻塞；超时由调用方控制）
 * @return KM_ERR_OK 收到数据并填充 len；KM_ERR_COMM_FAIL 无数据/失败
 */
km_err_t km_gmac_recv(uint8_t *buf, size_t cap, size_t *len);

/** @brief 向接收队列注入一帧（回环桩专用：模拟 D3000M 下发消息） */
km_err_t km_gmac_inject(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KM_GMAC_COMM_H */
