#ifndef KM_SIM_COMM_H
#define KM_SIM_COMM_H

#include <stdint.h>
#include <stddef.h>
#include "km_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 模拟通路：与管理服务（内网 D3000M）通信，用于单板模拟环境测试。
 * 按编译环境（KM_ENV）选择后端（见 km_env.h）：
 *   - SIM_WINDOWS：两个内存 FIFO 队列模拟上行（KM -> 管理服务）与下行（管理服务 -> KM），
 *                  本机开发/单测自环（对端响应经 km_sim_inject 注入，km_sim_poll_last 回读校验）；
 *   - SIM_LINUX  ：真实 System V 消息队列联调后端，可与独立进程
 *                  （scripts/msgq_probe.c / sysmng_sim.c，或真实 sysmng）跨进程通信。
 * 接口 km_sim_* 对上层（km_comm）保持稳定，不随后端变化。
 */

/* ---------- SIM_LINUX 真实联调约定（System V 消息队列） ----------
 * 与 scripts/msgq_probe.c / scripts/sysmng_sim.c 保持一致的线格式约定：
 *   - 队列 key 默认 KM_MNG_MSGQ_KEY_DEFAULT，可用环境变量 KM_MSGQ_KEY 覆盖
 *     （build.sh 的 --msgq-key / MSGQ_KEY 为同一来源）；
 *   - mtype 即接收端通道号：KM 上报 -> mtype=1（管理服务接收），
 *     管理服务下发 -> mtype=2（KM 接收）；
 *   - 消息载荷 mtext = 完整管理帧（FPGA 帧头 8B 起，含尾部填充，长度 <= KM_MAX_MSG_LEN）；
 *   - 环境变量 KM_MNG_MSGQ_FLUSH=1（km_tests 由 CMake 预设，主程序不设）：
 *     初始化时排空队列遗留帧，保证单测队列状态可控。
 */
#define KM_MNG_CH_MNG_RECV      1L  /* KM 上报方向消息类型（管理服务接收通道） */
#define KM_MNG_CH_KM_RECV       2L  /* KM 接收端通道（管理服务->KM 方向 mtype） */
#define KM_MNG_MSGQ_KEY_DEFAULT 88  /* 消息队列默认 key */
#define KM_MNG_MSGQ_MODE        0600 /* 队列访问权限（仅属主） */

km_err_t km_sim_init(void);
void     km_sim_deinit(void);

/** @brief 发送一帧上行帧（KM -> 管理服务）。
 *  SIM_WINDOWS 入内存上行队列；SIM_LINUX 投递到 System V 队列（mtype=1），
 *  队列满时投递失败返回 KM_ERR_COMM_FAIL（对端未及时消费不阻塞 KM）。 */
km_err_t km_sim_send(const uint8_t *data, size_t len);

/** @brief 接收一帧下行帧（管理服务 -> KM；非阻塞）。
 *  SIM_WINDOWS 从内存下行队列取；SIM_LINUX 从 System V 队列收（mtype=2），
 *  无下行帧返回 KM_ERR_COMM_FAIL。 */
km_err_t km_sim_recv(uint8_t *buf, size_t cap, size_t *len);

/** @brief 模拟管理服务向下行方向注入一帧。
 *  SIM_WINDOWS 入内存下行队列；SIM_LINUX 向 System V 队列发 mtype=2 下行帧
 *  （等效对端下发，供测试/联调构造下行场景；真实下行与注入共用同一下行通道）。 */
km_err_t km_sim_inject(const uint8_t *data, size_t len);

/** @brief 取走上行方向最新一帧（测试/联调校验 KM 上报内容）；无数据返回 KM_ERR_COMM_FAIL。
 *  仅单测/调试使用：SIM_WINDOWS 为内存 peek（不移除）；
 *  SIM_LINUX 下真实对端本会消费上行帧，进程内回读即 msgrcv(mtype=1) 取走
 *  （单测无对端竞争，语义等价；联调时请由对端校验）。 */
km_err_t km_sim_poll_last(uint8_t *buf, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* KM_SIM_COMM_H */
