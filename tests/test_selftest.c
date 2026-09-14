#include "km_test.h"
#include "km_api.h"
#include "hal/crypto_hal.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#define TEST_MASTER "km-master-key-for-unit-test-0123456789"

static void ensure_dir(const char *d)
{
#ifdef _WIN32
    _mkdir(d);
#else
    mkdir(d, 0700);
#endif
}

void test_selftest(void)
{
    km_oplog_cfg_t ocfg;
    soft_crypto_cfg_t cfg;
    km_err_t rc;

#ifdef _WIN32
    _putenv_s("KM_MASTER_KEY", TEST_MASTER);
#else
    setenv("KM_MASTER_KEY", TEST_MASTER, 1);
#endif
    ensure_dir("out");

    /* 日志初始化（console 开、不落文件，保证 auditlog 可用且不污染工作区） */
    memset(&ocfg, 0, sizeof(ocfg));
    ocfg.level = LOG_LEVEL_ERROR;
    ocfg.console = 1;
    ocfg.to_file = 0;
    KM_TEST_ASSERT_EQ_INT(km_log_init2("out/oplog_selftest", "out/audit_selftest", &ocfg), KM_ERR_OK);

    /* FPGA 自检（桩）：应直接通过 */
    KM_TEST_ASSERT_EQ_INT(km_fpga_selftest(), KM_ERR_OK);

    /* CryptoHAL（SOFT）初始化 */
    cfg.key_dir = "out/testkeys";
    cfg.master_key_env = "KM_MASTER_KEY";
    KM_TEST_ASSERT_EQ_INT(km_hal_init(CRYPTO_PROVIDER_SOFT, &cfg), KM_ERR_OK);

    /* 密码卡算法自检：SM2/SM3/SM4 KAT 与签名验签往返应全部通过 */
    rc = km_crypto_selftest();
    KM_TEST_ASSERT_EQ_INT(rc, KM_ERR_OK);

    /* 周期自检执行器：密码卡算法自检 + FPGA 自检全链路应通过 */
    KM_TEST_ASSERT_EQ_INT(km_selftest_run(), KM_ERR_OK);

    /* 未初始化 HAL 时自检应报初始化失败 */
    km_hal_deinit();
    KM_TEST_ASSERT_EQ_INT(km_crypto_selftest(), KM_ERR_INIT_FAIL);

    km_log_deinit();
}
