#ifndef KM_FPGA_COMM_H
#define KM_FPGA_COMM_H

#include <stdint.h>
#include <stddef.h>
#include "km_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** FPGA 通信层（基于 GmacComm 明通通道），第一阶段提供桩 */

km_err_t km_fpga_init(void);
void     km_fpga_deinit(void);

/** @brief FPGA 算法自检：发送自检命令并校验响应（第一阶段桩返回 OK）
 * 命名带 _comm 后缀以区分设备级公共 API km_fpga_selftest() */
km_err_t km_fpga_selftest_comm(void);

/** @brief 经 FPGA 明通通道上报一帧数据（第一阶段桩） */
km_err_t km_fpga_report(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KM_FPGA_COMM_H */
