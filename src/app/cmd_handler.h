#ifndef KM_CMD_HANDLER_H
#define KM_CMD_HANDLER_H

#include <stddef.h>
#include <stdint.h>
#include "km_error.h"
#include "comm/mgmt_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 管理消息子处理入口：分发已解析的管理消息（心跳/状态/证书导入）并编码应答。
 * 仅处理 km_mng_parse 检查通过的管理消息；最外层收帧/分流（km_msg_handle）
 * 在 app/msg_dispatch.c，本函数由其在识别管理通道后调用。
 * @param frame   整帧首指针（即 STU_TLV_MNG_HEAD 视图起点，含 FPGA 头 8B + 管理头 8B）
 * @param mng_len 管理消息长度（头内 len 字段 = 8 + TLV，km_mng_parse 已校验）
 * @return KM_ERR_OK 处理完成（含不应答/应答帧）；错误码表示处理失败
 */
km_err_t km_mng_handle_message(const uint8_t *frame, uint16_t mng_len);

/**
 * @brief 设置设备工作状态
 * @param working 1=正常工作；0=自检失败停止工作。
 * 停止工作后，业务类消息（证书导入等）被拒绝并返回自检失败错误码，
 * 心跳/状态查询仍正常应答（状态应答反馈故障状态）。
 * 线程安全：定时线程（自检结果）与业务线程（读取）并发访问。
 */
void km_cmd_set_working(int working);

/**
 * @brief 查询设备工作状态（线程安全）
 * @return 1=正常工作；0=自检失败停止工作
 */
int km_cmd_is_working(void);

#ifdef __cplusplus
}
#endif

#endif /* KM_CMD_HANDLER_H */
