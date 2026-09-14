#ifndef KM_MSG_DISPATCH_H
#define KM_MSG_DISPATCH_H

#include <stddef.h>
#include <stdint.h>
#include "km_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 应用层唯一收帧入口：最外层 FPGA 头检查后按 msg_type(FPGA_MSGTYPE) 分流。
 *   - 管理通道（toSYSMNG / fromSYSMNG）
 *       → km_mng_parse 管理头检查 → km_mng_handle_message（心跳/状态/证书导入）
 *   - 预留通道（FPGA_MSGTYPE_fromFPGA，FPGA 算法自检回复，未启用）
 *       → 记说明日志，返回 KM_ERR_RESERVED（区别于未知类型）
 *   - 未知类型 → 记告警日志，返回 KM_ERR_NOT_SUPPORTED
 * @param frame 收到的帧数据（MgmtProtocol 编码，帧头统一 FPGA 帧头 8B）
 * @param len   长度
 * @return km_err_t
 */
km_err_t km_msg_handle(const uint8_t *frame, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KM_MSG_DISPATCH_H */
