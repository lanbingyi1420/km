#ifndef KM_HEARTBEAT_H
#define KM_HEARTBEAT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "km_error.h"
#include "comm/mgmt_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 心跳超时判定阈值（周期倍数）：interval*max_lost 未收到对端心跳判为一次丢失；
 * 连续丢失达到 max_lost 次触发告警日志 + 审计。 */
#define KM_HEARTBEAT_MAX_LOST 3

/* 心跳运行统计（读取加锁，任意线程可调用 km_heartbeat_get_stat 查询） */
typedef struct {
    uint32_t interval;    /* 心跳周期（秒）；0=关闭 */
    uint32_t max_lost;    /* 超时/告警阈值（周期倍数） */
    uint32_t tx_count;    /* 累计主动发送次数 */
    uint32_t rx_count;    /* 累计收到对端心跳次数（含问询与对主动心跳的回复） */
    uint32_t lost_count;  /* 当前连续丢失次数 */
    time_t   last_tx;     /* 最近主动发送时间 */
    time_t   last_rx;     /* 最近收到对端心跳时间 */
    uint8_t  tx_msg_id;   /* 最近一次主动发送所用的 msg_id（期望槽匹配依据） */
    uint8_t  pending;     /* 期望槽：1=存在未确认的主动发送（等待对端同 id 回复） */
} km_heartbeat_stat_t;

/**
 * @brief 初始化心跳模块（线程启动前调用一次；可重复调用以改参数）
 * @param interval 心跳周期（秒）；0 表示关闭心跳发送与超时判定
 * @param max_lost 超时/告警阈值；0 使用默认 KM_HEARTBEAT_MAX_LOST
 */
km_err_t km_heartbeat_init(uint32_t interval, uint32_t max_lost);

/**
 * @brief 设置软件运行状态（写入心跳上行载荷 run_state 字段，取值见 km_run_state_t）。
 *        设备初始化（自检成功/失败）与运行期故障切换时调用，线程安全。
 * @param state km_run_state_t 取值（0x01 正常 / 0xE0~0xE2 自检故障 / 0xFF 软件启动）
 */
void km_heartbeat_set_run_state(uint8_t state);

/** @brief 查询当前软件运行状态（km_run_state_t 取值）。 */
uint8_t km_heartbeat_get_run_state(void);

/**
 * @brief 定时线程节拍：到期主动发送心跳；超时未收到对端心跳则计数/告警。
 *        内部按传入 now 做绝对时间判定（幂等，线程安全）。
 */
void km_heartbeat_tick(time_t now);

/**
 * @brief 业务线程收到 MSG_HEARTBEAT_REQ 时调用（心跳收发的完整处理收敛于此）：
 *        - 任何方向的心跳均视为对端存活（记录 last_rx、清零连续丢失）；
 *        - sender==MNG 时按 msg_id 判定帧的性质：
 *            * 与期望槽匹配（本模块有未确认的主动发送且 msg_id 一致）→ 是对本机
 *              主动心跳的回复：确认存活、清空期望槽，不答复；
 *            * msg_id 比本机最近一次主动发送"新" → 管理服务主动问询：应答并回显其
 *              msg_id（走 encode_reply，不自增/不登记期望）；挂起的期望槽保持，
 *              等待同 id 回复或超时清除；
 *            * msg_id 不新于最近已发 id → 对历史心跳的迟到回执/重复回显：只记存活，
 *              不答复（防止对端回显本机应答形成无限回声乒乓）；
 *        - sender==KM（回环/对端回传）→ 只记存活不回，避免乒乓。
 * @param frame   整帧首指针（即 STU_TLV_MNG_HEAD 视图起点，含 FPGA 头 8B + 管理头 8B）
 * @param mng_len 管理消息长度（头内 len 字段 = 8 + TLV，km_mng_parse 已校验）
 */
km_err_t km_heartbeat_handle(const uint8_t *frame, uint16_t mng_len);

/** @brief 获取心跳运行统计 */
void km_heartbeat_get_stat(km_heartbeat_stat_t *st);

#ifdef __cplusplus
}
#endif

#endif /* KM_HEARTBEAT_H */
