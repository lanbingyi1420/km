#ifndef KM_COMM_H
#define KM_COMM_H

#include <stdint.h>
#include <stddef.h>
#include "km_error.h"
#include "km_config.h"
#include "thread.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 管理通路统一抽象层
 *
 * 通路选择与编译环境 KM_ENV 绑定（见 km_env.h），不再支持运行时自由切换：
 *   - KM_ENV_BOARD（正式隔离架构）  -> COMM_PATH_FORMAL 正式通路：
 *         MgmtProtocol 帧 -> GmacComm(GMAC) -> FpgaComm -> 内网 D3000M 管理服务。
 *   - KM_ENV_SIM_WINDOWS / KM_ENV_SIM_LINUX（单板模拟） -> COMM_PATH_SIMULATION 模拟通路：
 *         消息队列模拟与管理服务通信，无需 FPGA/GMAC 硬件；
 *         Windows 为内存队列（本机自测），Linux 为 System V 消息队列联调后端
 *         （key 默认 88，KM_MSGQ_KEY 可覆盖，约定见 sim_comm.h）。
 * 传入与环境不符的通路返回 KM_ERR_NOT_SUPPORTED。
 */

/**
 * @brief 初始化管理通路
 * @param path 通路类型（必须与编译环境 KM_ENV 一致，否则 KM_ERR_NOT_SUPPORTED）
 * @param gmac_mode GMAC 模式（正式环境使用；loopback 回环桩 / raw 预留；模拟环境忽略）
 */
km_err_t km_comm_init(km_comm_path_t path, gmac_mode_t gmac_mode);

/** @brief 释放管理通路 */
void km_comm_deinit(void);

/** @brief 获取当前通路类型 */
km_comm_path_t km_comm_path(void);

/**
 * @brief 发送一帧（len <= KM_MAX_MSG_LEN）
 * 正式通路经 GMAC 下发；模拟通路投递到模拟消息队列（模拟对端可 km_sim_inject 应答）。
 */
km_err_t km_comm_send(const uint8_t *data, size_t len);

/**
 * @brief 接收一帧（非阻塞）
 * @return KM_ERR_OK 收到数据并填充 len；KM_ERR_COMM_FAIL 无数据
 */
km_err_t km_comm_recv(uint8_t *buf, size_t cap, size_t *len);

/**
 * @brief 异步发送：投递到发送队列，由通信线程 km_comm_send；
 *        线程未启用或队列未初始化时退化为同步 km_comm_send。
 *        用于业务线程/定时线程发送，避免多线程直写底层通道。
 */
km_err_t km_comm_send_async(const uint8_t *data, size_t len);

/**
 * @brief 通信线程入口（三线程模型的通信线程）：
 *        循环 recv → 收帧队列；发送队列 → km_comm_send。由 main 创建。
 */
void km_comm_worker(void *arg);

/** @brief 停止通信线程（设置停止标志，join 前调用） */
void km_comm_worker_stop(void);

/**
 * @brief 业务线程取一帧（收帧队列非阻塞）
 * @return KM_ERR_OK 有帧；KM_ERR_COMM_FAIL 暂无帧
 */
km_err_t km_comm_frame_pop(uint8_t *buf, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* KM_COMM_H */
