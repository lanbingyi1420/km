#ifndef KM_ENV_H
#define KM_ENV_H

#ifdef __cplusplus
extern "C" {
#endif

/* ================= 运行环境宏体系 =================
 * 通过编译期宏 KM_ENV 区分目标环境，所有相关结构定义、消息通道处理、
 * 默认配置等均据此分别处理（见 CMakeLists.txt 的 KM_ENV 构建选项）：
 *
 *   KM_ENV_BOARD        正式隔离架构环境（板卡/隔离架构）
 *                       通道：正式通路 MgmtProtocol + GMAC + FPGA
 *
 *   KM_ENV_SIM_WINDOWS  单板模拟环境：Windows 开发测试
 *                       通道：模拟通路（内存消息队列，本机自测）
 *
 *   KM_ENV_SIM_LINUX    单板模拟环境：Linux 单板联调测试
 *                       通道：模拟通路（System V 消息队列联调后端，key 默认 88，
 *                       环境变量 KM_MSGQ_KEY 可覆盖；约定见 comm/sim_comm.h，
 *                       与独立对端 msgq_probe / sysmng_sim 联调）
 *
 * 帧头全局唯一（统一 FPGA 帧头，8B）：
 *   STU_TLV_FPGA_HEAD（0x5a5a 2B | msg_type 2B(FPGA_MSGTYPE) | reserve | padding_len | pkt_len 2B）
 *   + STU_TLV_MNG_HEAD（管理头 8B）；三环境帧格式一致，KM_ENV 仅区分通信通路，
 *   不再区分帧头版本（SMLT 9B/正式 8B 通路已移除，见 mgmt_protocol.h）。
 *
 * 构建示例：
 *   -DKM_ENV=KM_ENV_SIM_WINDOWS（默认）
 *   -DKM_ENV=KM_ENV_SIM_LINUX
 *   -DKM_ENV=KM_ENV_BOARD
 * 也可直接写数值（0 / 1 / 2）。
 */

#define KM_ENV_BOARD       0 /* 正式隔离架构环境 */
#define KM_ENV_SIM_WINDOWS 1 /* 单板模拟环境：Windows 开发测试 */
#define KM_ENV_SIM_LINUX   2 /* 单板模拟环境：Linux 单板联调测试 */

#ifndef KM_ENV
#define KM_ENV KM_ENV_SIM_WINDOWS
#endif

/* 派生判断宏（供结构定义 / 通道处理 / 默认配置按环境分支） */
#define KM_ENV_IS_BOARD()       ((KM_ENV) == KM_ENV_BOARD)
#define KM_ENV_IS_SIM()         ((KM_ENV) != KM_ENV_BOARD)
#define KM_ENV_IS_SIM_WINDOWS() ((KM_ENV) == KM_ENV_SIM_WINDOWS)
#define KM_ENV_IS_SIM_LINUX()   ((KM_ENV) == KM_ENV_SIM_LINUX)

#if (KM_ENV != KM_ENV_BOARD) && (KM_ENV != KM_ENV_SIM_WINDOWS) && \
    (KM_ENV != KM_ENV_SIM_LINUX)
#error "KM_ENV value invalid: must be KM_ENV_BOARD / KM_ENV_SIM_WINDOWS / KM_ENV_SIM_LINUX"
#endif

/** @brief 返回当前环境名称（"board" / "sim_windows" / "sim_linux"，供日志/打印） */
const char *km_env_name(void);

/** @brief 返回当前环境描述（一行的说明文字） */
const char *km_env_desc(void);

#ifdef __cplusplus
}
#endif

#endif /* KM_ENV_H */
