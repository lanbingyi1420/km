#ifndef KM_DEVICE_H
#define KM_DEVICE_H

#include "km_error.h"
#include "km_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 设备完整初始化流程（配置加载与日志初始化由调用方完成）
 * 调用方需先 km_config_load() + km_log_init2()；本函数执行其余链节：
 * 初始化通信层 → 初始化 CryptoHAL → 密码卡算法自检 → FPGA 算法自检
 * → 上报初始化完成状态。由 daemon main 传入与运行一致的配置，
 * 避免内部按默认路径重载配置/重初始化日志，覆盖调用方设置。
 * @param cfg 运行配置（不可为 NULL）
 * @return KM_ERR_OK 成功，其他错误码
 */
km_err_t km_device_init(const km_config_t *cfg);

/**
 * @brief 密码卡算法自检（SM2/SM3/SM4 已知答案测试）
 * @return KM_ERR_OK 通过，KM_ERR_SELFTEST_FAIL 失败
 */
km_err_t km_crypto_selftest(void);

/**
 * @brief FPGA 算法自检
 * @return KM_ERR_OK 通过，KM_ERR_SELFTEST_FAIL 失败
 */
km_err_t km_fpga_selftest(void);

/**
 * @brief 向 D3000M 上报设备初始化完成状态
 * @param ok 是否初始化成功
 * @return KM_ERR_OK 成功
 */
km_err_t km_report_init_status(int ok);

/**
 * @brief 执行一次完整周期自检（密码卡算法自检 + FPGA 自检）
 * 供定时自检调度使用；任一环节失败即返回对应错误码。
 * @return KM_ERR_OK 全部通过，KM_ERR_SELFTEST_FAIL 等错误码
 */
km_err_t km_selftest_run(void);

/**
 * @brief 向 D3000M 上报定时自检结果（MSG_SELFTEST_RSP）
 * @param ok 1=自检正常 0=自检故障
 * @return KM_ERR_OK 成功
 */
km_err_t km_selftest_report(int ok);

/**
 * @brief 设备退出清理
 */
void km_device_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* KM_DEVICE_H */
