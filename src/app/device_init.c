/* 设备初始化链（配置加载与日志初始化由调用方 daemon main 负责）：
 * 1. 初始化通信层(GmacComm+FpgaComm) → 2. 初始化 CryptoHAL
 * → 3. 密码卡算法自检 → 4. FPGA 算法自检 → 5. 上报初始化完成状态
 */

#include <stdio.h>
#include <string.h>
#include "km_api.h"
#include "km_config.h"
#include "hal/crypto_hal.h"
#include "comm/km_comm.h"
#include "comm/mgmt_protocol.h"
#include "comm/fpga_comm.h"
#include "app/heartbeat.h"

static int g_init_state = 0; /* 0 未初始化，1 已初始化 */

/* 密码卡算法自检：调用 HAL self_test（SM2/SM3/SM4 KAT），结果写入审计日志 */
km_err_t km_crypto_selftest(void)
{
    const CryptoHAL *hal = km_hal_get();
    km_err_t err;
    char detail[64];

    if (hal == NULL || hal->self_test == NULL)
        return KM_ERR_INIT_FAIL;

    err = (hal->self_test() == 0) ? KM_ERR_OK : KM_ERR_SELFTEST_FAIL;
    if (err != KM_ERR_OK)
        km_heartbeat_set_run_state(KM_RUN_STATE_CARD_FAIL); /* 密码卡自检失败（随心跳上报） */
    snprintf(detail, sizeof(detail), "component=sm2,sm3,sm4 result=%s",
             err == KM_ERR_OK ? "ok" : "fail");
    km_auditlog_write(EVT_SELFTEST_RESULT, detail);
    return err;
}

/* FPGA 算法自检：调用 FPGA 通信自检并写入审计日志 */
km_err_t km_fpga_selftest(void)
{
    km_err_t err;
    char detail[64];

    err = km_fpga_selftest_comm();
    if (err != KM_ERR_OK)
        km_heartbeat_set_run_state(KM_RUN_STATE_FPGA_FAIL); /* FPGA 算法自检失败（随心跳上报） */
    snprintf(detail, sizeof(detail), "component=fpga result=%s",
             err == KM_ERR_OK ? "ok" : "fail");
    km_auditlog_write(EVT_SELFTEST_RESULT, detail);
    return err;
}

/* 上报初始化完成状态（SYSMNG_MSG_TYPE_STATUS_REQ，TLV 0x01 状态字节）到管理服务 */
km_err_t km_report_init_status(int ok)
{
    uint8_t buf[KM_MAX_MSG_LEN];
    size_t len = sizeof(buf);
    uint8_t tlv[8];
    size_t tlv_len = 0;
    uint8_t status = (uint8_t)(ok ? 1 : 0);
    km_err_t err;

    if (km_tlv_append(tlv, sizeof(tlv), &tlv_len, 0x01, &status, 1) == KM_ERR_OK) {
        /* 组帧（FPGA 头 + 管理头 + TLV），帧头恒为统一 FPGA 版本（msg_type=toSYSMNG）。
         * msg_id 发送前自动自增；本上报按用户语义不登记期望（主动类型目前仅心跳），
         * 对端是否回执不影响 KM 状态机，故 tx_msg_id 置 NULL 忽略。 */
        err = km_mng_frame_encode(buf, &len,
                                  SYSMNG_MSG_TYPE_STATUS_REQ, tlv, tlv_len, NULL);
        if (err != KM_ERR_OK)
            return KM_ERR_COMM_FAIL;
        return km_comm_send(buf, len);
    }
    return KM_ERR_BUF_TOO_SMALL;
}

/* 定时自检：依次执行密码卡算法自检与 FPGA 自检；任一失败立即返回 */
km_err_t km_selftest_run(void)
{
    km_err_t err;

    /* 密码卡算法自检（SM2/SM3/SM4 KAT 与签名验签往返） */
    err = km_crypto_selftest();
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "periodic selftest: crypto failed: %s",
                       km_err_str(err));
        return err;
    }
    /* FPGA 算法自检 */
    err = km_fpga_selftest();
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "periodic selftest: fpga failed: %s",
                       km_err_str(err));
        return err;
    }
    return KM_ERR_OK;
}

/* 上报自检结果（SYSMNG_MSG_TYPE_SELFTEST_RSP，TLV 0x01 状态字节，1=正常 0=故障）。
 * 定时线程调用，经异步发送（投递发送队列由通信线程发送）。 */
km_err_t km_selftest_report(int ok)
{
    uint8_t buf[KM_MAX_MSG_LEN];
    size_t len = sizeof(buf);
    uint8_t tlv[8];
    size_t tlv_len = 0;
    uint8_t status = (uint8_t)(ok ? 1 : 0);
    km_err_t err;

    if (km_tlv_append(tlv, sizeof(tlv), &tlv_len, 0x01, &status, 1) == KM_ERR_OK) {
        /* 组帧（FPGA 头 + 管理头 + TLV），帧头恒为统一 FPGA 版本（msg_type=toSYSMNG）。
         * msg_id 发送前自动自增；按用户语义不登记期望（主动类型目前仅心跳），
         * 收到 sender=MNG 的 SELFTEST_RSP 由 cmd_handler default 分支丢弃。 */
        err = km_mng_frame_encode(buf, &len,
                                  SYSMNG_MSG_TYPE_SELFTEST_RSP, tlv, tlv_len, NULL);
        if (err != KM_ERR_OK)
            return KM_ERR_COMM_FAIL;
        return km_comm_send_async(buf, len);
    }
    return KM_ERR_BUF_TOO_SMALL;
}

/* 设备初始化链；配置/日志由调用方预先就绪，此处使用传入 cfg，避免
 * 二次 config_load/log_init2 以默认值覆盖 daemon main 的 --conf 设置
 * （曾导致启动后运行时日志落到默认目录/级别而被静默丢弃）。 */
km_err_t km_device_init(const km_config_t *cfg)
{
    km_err_t err;
    soft_crypto_cfg_t soft_cfg;

    if (cfg == NULL)
        return KM_ERR_BAD_PARAM;
    if (g_init_state)
        return KM_ERR_ALREADY_INIT;

    km_auditlog_write(EVT_DEVICE_INIT_START, "device init start");
    /* 软件启动：自检通过前心跳上报 0xFF；失败码由各自检函数在失败时更新 */
    km_heartbeat_set_run_state(KM_RUN_STATE_STARTING);

    /* 1. 初始化通信层（正式通路 GMAC+FPGA / 模拟通路消息队列） */
    err = km_comm_init(cfg->comm_path, cfg->gmac_mode);
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "comm path init failed: %d", (int)err);
        km_auditlog_write(EVT_DEVICE_INIT_FAIL, "comm path init failed");
        return err;
    }
    km_oplog_write(LOG_LEVEL_INFO, "comm path=%s initialized",
                   cfg->comm_path == COMM_PATH_SIMULATION ? "simulation" : "formal");

    /* 2. 初始化 CryptoHAL */
    memset(&soft_cfg, 0, sizeof(soft_cfg));
    soft_cfg.key_dir = cfg->key_dir;
    soft_cfg.master_key_env = cfg->master_key_env;
    err = km_hal_init(cfg->provider, &soft_cfg);
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "crypto hal init failed: %s",
                       km_err_str(err));
        km_auditlog_write(EVT_DEVICE_INIT_FAIL, "crypto hal init failed");
        return err;
    }
    km_oplog_write(LOG_LEVEL_INFO, "crypto provider=%s initialized",
                   cfg->provider == CRYPTO_PROVIDER_PCIE ? "pcie" : "soft");

    /* 3. 密码卡算法自检 */
    err = km_crypto_selftest();
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "crypto selftest failed");
        km_auditlog_write(EVT_DEVICE_INIT_FAIL, "crypto selftest failed");
        return err;
    }
    km_oplog_write(LOG_LEVEL_INFO, "crypto selftest OK");

    /* 4. FPGA 算法自检 */
    err = km_fpga_selftest();
    if (err != KM_ERR_OK) {
        km_oplog_write(LOG_LEVEL_ERROR, "fpga selftest failed");
        km_auditlog_write(EVT_DEVICE_INIT_FAIL, "fpga selftest failed");
        return err;
    }
    km_oplog_write(LOG_LEVEL_INFO, "fpga selftest OK");

    /* 5. 上报初始化完成状态（并通过心跳上报运行正常 0x01） */
    km_heartbeat_set_run_state(KM_RUN_STATE_BOOT_OK);
    km_report_init_status(1);
    km_auditlog_write(EVT_DEVICE_INIT_OK, "device init ok");
    km_oplog_write(LOG_LEVEL_INFO, "device init completed");

    g_init_state = 1;
    return KM_ERR_OK;
}

/* 设备反初始化：按 HAL→通信→日志 顺序释放资源（幂等） */
void km_device_deinit(void)
{
    if (!g_init_state)
        return;
    km_hal_deinit();
    km_comm_deinit();
    km_log_deinit();
    g_init_state = 0;
}
