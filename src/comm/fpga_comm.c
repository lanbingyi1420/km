#include "fpga_comm.h"

/* FpgaComm 桩：第一阶段无 FPGA 硬件，返回占位结果 */

/* FPGA 初始化（第一阶段桩：直接返回成功） */
km_err_t km_fpga_init(void)
{
    return KM_ERR_OK;
}

/* FPGA 反初始化（第一阶段桩：空操作） */
void km_fpga_deinit(void)
{
}

/* FPGA 通信自检（第一阶段桩：模拟通过） */
km_err_t km_fpga_selftest_comm(void)
{
    /* 第一阶段：模拟 FPGA 自检通过 */
    return KM_ERR_OK;
}

/* 上报数据到 FPGA（第一阶段桩：丢弃数据返回成功） */
km_err_t km_fpga_report(const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;
    return KM_ERR_OK;
}
