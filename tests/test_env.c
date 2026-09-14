/* 环境宏体系测试：验证 KM_ENV 取值、派生宏一致性、默认通路与编译环境匹配。
 * 帧头三环境一致（统一 FPGA 帧头 8B），不再存在"默认帧头版本"随 KM_ENV 切换的问题。 */

#include "km_test.h"
#include "km_env.h"
#include "km_config.h"
#include "comm/mgmt_protocol.h"
#include <string.h>

void test_env(void)
{
    /* 1) KM_ENV 取值合法（头文件 #error 已保证）且派生宏互斥一致 */
    KM_TEST_ASSERT(KM_ENV == KM_ENV_BOARD ||
                   KM_ENV == KM_ENV_SIM_WINDOWS ||
                   KM_ENV == KM_ENV_SIM_LINUX);

#if KM_ENV_IS_BOARD()
    KM_TEST_ASSERT(!KM_ENV_IS_SIM());
    KM_TEST_ASSERT(!KM_ENV_IS_SIM_WINDOWS());
    KM_TEST_ASSERT(!KM_ENV_IS_SIM_LINUX());
#else
    KM_TEST_ASSERT(KM_ENV_IS_SIM());
    KM_TEST_ASSERT(KM_ENV_IS_SIM_WINDOWS() ^ KM_ENV_IS_SIM_LINUX());
#endif

    /* 2) 环境名称与描述非空 */
    KM_TEST_ASSERT(km_env_name() != NULL && km_env_name()[0] != '\0');
    KM_TEST_ASSERT(km_env_desc() != NULL && km_env_desc()[0] != '\0');

    /* 3) 帧头尺寸恒定：FPGA 帧头 8B + 管理头 8B（唯一帧格式，_Static_assert 已校验） */
    KM_TEST_ASSERT_EQ_INT((int)sizeof(STU_TLV_FPGA_HEAD), 8);
    KM_TEST_ASSERT_EQ_INT((int)sizeof(STU_TLV_MNG_HEAD), 16);
    KM_TEST_ASSERT_EQ_INT((int)KM_FPGA_HEAD_LEN, 8);
    KM_TEST_ASSERT_EQ_INT((int)KM_MNG_HEAD_LEN, 8);

    /* 4) 配置默认通路与环境匹配 */
    {
        km_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        KM_TEST_ASSERT_EQ_INT(km_config_load(&cfg, NULL), KM_ERR_OK);
#if KM_ENV_IS_BOARD()
        KM_TEST_ASSERT_EQ_INT((int)cfg.comm_path, (int)COMM_PATH_FORMAL);
#else
        KM_TEST_ASSERT_EQ_INT((int)cfg.comm_path, (int)COMM_PATH_SIMULATION);
#endif
    }
}
