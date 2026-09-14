/* ============================================================
 * MsgDispatch：应用层唯一收帧入口（最外层分流）
 * 收帧 -> km_fpga_parse(最外层头检查) -> 按 msg_type(FPGA_MSGTYPE) 分流：
 *   管理通道(fromSYSMNG: 管理服务下行 / toSYSMNG: 密码管理上行)
 *     -> km_mng_parse(管理头检查) -> km_mng_handle_message(管理子处理)
 *   预留通道(FPGA 算法自检回复：FPGA_MSGTYPE_fromFPGA)
 *     -> 记说明日志，返回 KM_ERR_RESERVED（协议已定义、尚未启用，区别于未知类型）
 *   未知类型
 *     -> 记告警日志，返回 KM_ERR_NOT_SUPPORTED
 * 协议层 km_frame_dispatch 保留为纯协议版本（供测试与无应用日志场景）。
 * ============================================================ */

#include "km_api.h"
#include "comm/mgmt_protocol.h"
#include "cmd_handler.h"
#include "km_log.h"

km_err_t km_msg_handle(const uint8_t *frame, size_t len)
{
    const STU_TLV_FPGA_HEAD *head = NULL;
    uint16_t mng_len = 0;
    km_err_t err;

    if (frame == NULL || len == 0)
        return KM_ERR_BAD_PARAM;

    /* 最外层：FPGA 帧头检查（magic/长度/对齐/pkt_len/padding/CRC） */
    err = km_fpga_parse(frame, len, &head);
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_WARN, "msg: fpga parse failed: %s", km_err_str(err));
        return err;
    }

    /* 非管理通道：区分"预留算法自检"与"未知类型" */
    if (!km_fpga_is_mng_type(head)) {
        if (head->msg_type == FPGA_MSGTYPE_fromFPGA) {
            /* 预留通道：FPGA 算法自检回复帧（载荷 = 算法自检结果）。
             * 当前 FPGA 自检为同步请求-应答（km_fpga_selftest_comm），尚未异步化，
             * 此通道未启用；单独记说明日志并返回 KM_ERR_RESERVED，
             * 与未知类型（KM_ERR_NOT_SUPPORTED + 告警）区分，便于未来挂载子处理。 */
            km_oplog_write(LOG_LEVEL_INFO,
                           "msg: reserved channel from FPGA algcheck (not enabled)");
            return KM_ERR_RESERVED;
        }
        km_oplog_write(LOG_LEVEL_WARN, "msg: unknown fpga msg_type 0x%04x",
                       (unsigned)head->msg_type);
        return KM_ERR_NOT_SUPPORTED;
    }

    /* 管理通道：管理头检查（0x68/len/sender/receiver/msg_cmd/TLV 边界） */
    err = km_mng_parse(frame, len, NULL, &mng_len);
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_WARN, "msg: mng parse failed: %s", km_err_str(err));
        return err;
    }
    /* 管理子处理：心跳/状态/证书导入，内部组帧并异步发送应答 */
    return km_mng_handle_message(frame, mng_len);
}
