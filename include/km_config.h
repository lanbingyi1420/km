#ifndef KM_CONFIG_H
#define KM_CONFIG_H

#include <stddef.h>
#include "km_types.h"
#include "km_error.h"
#include "km_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 密码服务 Provider 类型 */
typedef enum {
    CRYPTO_PROVIDER_SOFT = 0,
    CRYPTO_PROVIDER_PCIE = 1,
} crypto_provider_t;

/** GMAC 通信模式 */
typedef enum {
    GMAC_MODE_LOOPBACK = 0,
    GMAC_MODE_RAW      = 1,
} gmac_mode_t;

/** 管理通路类型 */
typedef enum {
    COMM_PATH_FORMAL    = 0, /* 正式通路：MgmtProtocol + GMAC + FPGA 转发内网 D3000M 管理服务 */
    COMM_PATH_SIMULATION = 1, /* 模拟通路：消息队列模拟与管理服务通信（单板模拟环境测试） */
} km_comm_path_t;

/** 全局配置 */
typedef struct {
    int              heartbeat_interval; /* 心跳周期（秒） */
    int              selftest_enable;    /* 是否开启定时自检：1=开启 0=关闭（默认 1） */
    int              selftest_interval;  /* 定时自检周期（秒），0=不周期自检（默认 3600） */
    log_level_t      log_level;
    char             oplog_dir[256];
    char             audit_dir[256];
    char             key_dir[256];
    char             cert_dir[256];
    crypto_provider_t provider;
    char             master_key_env[64];
    gmac_mode_t      gmac_mode;

    /* 管理通路选择 */
    km_comm_path_t   comm_path;

    /* 运维日志配置 */
    int              log_console;   /* 是否打印到后台（stdout/stderr），1=是 */
    int              log_to_file;   /* 是否记录到文件，1=是 */
    long             log_file_max;  /* 单个日志文件最大字节数（0=不限制） */
    int              log_file_count; /* 保留的历史日志文件数（循环覆盖，>=1） */

    int              initialized;
} km_config_t;

/**
 * @brief 加载配置文件（默认 /etc/km/km.conf，可经环境变量 KM_CONF 指定；
 *        路径字段可经同名环境变量覆盖，便于本机测试）
 * @param cfg 输出配置
 * @param conf_path 配置文件路径（NULL 使用默认）
 * @return km_err_t
 */
km_err_t km_config_load(km_config_t *cfg, const char *conf_path);

/** @brief 打印当前配置（调试用） */
void km_config_dump(const km_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* KM_CONFIG_H */
