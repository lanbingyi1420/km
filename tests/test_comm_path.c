/* 管理通路测试：按编译环境 KM_ENV 分别验证（见 km_env.h）
 *  - BOARD（正式隔离架构）：仅正式通路可用，模拟通路被拒绝；
 *  - SIM（WIN/LINUX 单板模拟）：仅模拟通路可用，正式通路被拒绝。
 * 帧头三环境一致（统一 FPGA 帧头 8B），KM_ENV 仅区分通信通路。 */

#include "km_test.h"
#include "km_api.h"
#include "km_env.h"
#include "comm/km_comm.h"
#include "comm/sim_comm.h"
#include "comm/gmac_comm.h"
#include "comm/mgmt_protocol.h"
#include <string.h>

/* 管理消息捕获回调（仅模拟通路分支需要）：按线格式从整帧读管理头（frame 为整帧首） */
#if !KM_ENV_IS_BOARD()
typedef struct {
    uint16_t msg_cmd; /* 2B 小端 */
    uint8_t  sender;
} path_mng_capture;

static km_err_t path_mng_handler(const uint8_t *frame, uint16_t mng_len, void *ctx)
{
    STU_TLV_MNG_HEAD mh;
    path_mng_capture *out = (path_mng_capture *)ctx;

    (void)mng_len;
    if (out != NULL) {
        memcpy(&mh, frame, sizeof(mh));
        out->msg_cmd = (uint16_t)((uint16_t)mh.msg_cmd[0] | ((uint16_t)mh.msg_cmd[1] << 8));
        out->sender = mh.sender;
    }
    return KM_ERR_OK;
}
#endif /* !KM_ENV_IS_BOARD */

void test_comm_path(void)
{
    uint8_t payload[64];
    uint8_t out[4096];
    size_t len;

#if KM_ENV_IS_BOARD()
    /* ---------- 正式隔离架构环境：仅正式通路可用 ---------- */
    KM_TEST_ASSERT_EQ_INT(km_comm_init(COMM_PATH_FORMAL, GMAC_MODE_LOOPBACK), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)km_comm_path(), (int)COMM_PATH_FORMAL);
    /* 模拟通路与环境不符，拒绝 */
    KM_TEST_ASSERT_EQ_INT(km_comm_init(COMM_PATH_SIMULATION, GMAC_MODE_LOOPBACK),
                          KM_ERR_NOT_SUPPORTED);

    memset(payload, 0x11, sizeof(payload));
    KM_TEST_ASSERT_EQ_INT(km_comm_send(payload, sizeof(payload)), KM_ERR_OK);

    /* 无注入时下行为空 */
    len = 0;
    KM_TEST_ASSERT_EQ_INT(km_comm_recv(out, sizeof(out), &len), KM_ERR_COMM_FAIL);

    /* 注入下行帧（模拟 D3000M 下发）后可收到 */
    memset(payload, 0x44, 12);
    KM_TEST_ASSERT_EQ_INT(km_gmac_inject(payload, 12), KM_ERR_OK);
    len = 0;
    KM_TEST_ASSERT_EQ_INT(km_comm_recv(out, sizeof(out), &len), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)len, 12);
    KM_TEST_ASSERT_MEM_EQ(out, payload, 12);

    km_comm_deinit();

    /* 自检结果上报：经正式通路下发（帧头为统一 FPGA 帧头 8B） */
    KM_TEST_ASSERT_EQ_INT(km_comm_init(COMM_PATH_FORMAL, GMAC_MODE_LOOPBACK), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT(km_selftest_report(1), KM_ERR_OK);
    km_comm_deinit();

#else
    /* ---------- 单板模拟环境（WIN/LINUX）：仅模拟通路可用 ---------- */
    KM_TEST_ASSERT_EQ_INT(km_comm_init(COMM_PATH_SIMULATION, GMAC_MODE_LOOPBACK), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)km_comm_path(), (int)COMM_PATH_SIMULATION);
    /* 正式通路与环境不符，拒绝 */
    KM_TEST_ASSERT_EQ_INT(km_comm_init(COMM_PATH_FORMAL, GMAC_MODE_LOOPBACK),
                          KM_ERR_NOT_SUPPORTED);

    /* KM 上报 -> 上行队列（管理服务可读到） */
    memset(payload, 0x22, sizeof(payload));
    KM_TEST_ASSERT_EQ_INT(km_comm_send(payload, sizeof(payload)), KM_ERR_OK);
    len = 0;
    KM_TEST_ASSERT_EQ_INT(km_sim_poll_last(out, sizeof(out), &len), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)len, (int)sizeof(payload));
    KM_TEST_ASSERT_MEM_EQ(out, payload, sizeof(payload));

    /* 定时自检结果上报：应编码 SYSMNG_MSG_TYPE_SELFTEST_RSP 帧并进入上行队列 */
    KM_TEST_ASSERT_EQ_INT(km_selftest_report(1), KM_ERR_OK);
    len = 0;
    KM_TEST_ASSERT_EQ_INT(km_sim_poll_last(out, sizeof(out), &len), KM_ERR_OK);
    {
        path_mng_capture cap;
        memset(&cap, 0, sizeof(cap));
    /* 分层分发：外层 FPGA 头 + 管理子处理，回调按线格式捕获管理消息 */
    KM_TEST_ASSERT_EQ_INT(km_frame_dispatch(out, len, path_mng_handler, &cap), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)cap.msg_cmd, (int)SYSMNG_MSG_TYPE_SELFTEST_RSP);
    /* KM 编码发出（sender=KM） */
    KM_TEST_ASSERT_EQ_INT((int)cap.sender, (int)KM_SENDER_KM);
    }

    /* 管理服务主动下发 -> 下行队列 -> KM 接收 */
    memset(payload, 0x33, 8);
    KM_TEST_ASSERT_EQ_INT(km_sim_inject(payload, 8), KM_ERR_OK);
    len = 0;
    KM_TEST_ASSERT_EQ_INT(km_comm_recv(out, sizeof(out), &len), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)len, 8);
    KM_TEST_ASSERT_MEM_EQ(out, payload, 8);

    km_comm_deinit();
#endif

    /* 未初始化时收发均失败 */
    KM_TEST_ASSERT_EQ_INT(km_comm_send(payload, 4), KM_ERR_COMM_FAIL);
    KM_TEST_ASSERT_EQ_INT(km_comm_recv(out, sizeof(out), &len), KM_ERR_COMM_FAIL);

    /* 配置解析默认通路与环境一致 */
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
