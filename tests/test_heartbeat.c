/* 心跳模块测试：发送节拍/应答/方向区分/超时判定/统计/参数校验
 * 注意：测试环境不初始化日志与通信，心跳内部发送失败仅记日志不影响统计。
 * 入口形态：(frame, mng_len)，frame 为整帧首（STU_TLV_MNG_HEAD 视图）。 */
#include "km_test.h"
#include "km_api.h"
#include "km_types.h"
#include "app/heartbeat.h"
#include "comm/mgmt_protocol.h"

#include <string.h>
#include <stddef.h>

/* 构造心跳管理帧（整帧首视图）：只填管理头必要字段，mng_len=8（KM_MNG_HEAD_LEN）
 * msg_cmd 按 2B 小端写入；msg_id 可指定（模拟对端回执本机主动发送的 id） */
static void build_heartbeat_frame(uint8_t *out, uint8_t sender,
                                  uint16_t msg_cmd, uint8_t msg_id)
{
    STU_TLV_MNG_HEAD mh;

    memset(&mh, 0, sizeof(mh));
    mh.fpga_head.head = KM_FPGA_TLV_HEAD; /* 0x5a5a */
    mh.fpga_head.msg_type = FPGA_MSGTYPE_fromSYSMNG; /* 管理服务下行 */
    mh.head = KM_MNG_HEAD_MAGIC;
    mh.len = KM_MNG_HEAD_LEN; /* 无 TLV */
    mh.msg_id = msg_id;
    mh.sender = sender;
    mh.receiver = (sender == KM_SENDER_MNG) ? KM_SENDER_KM : KM_SENDER_MNG;
    mh.msg_cmd[0] = (uint8_t)msg_cmd;
    mh.msg_cmd[1] = (uint8_t)(msg_cmd >> 8);
    memcpy(out, &mh, sizeof(mh));
}

static void test_heartbeat_immediate_send(void)
{
    km_heartbeat_stat_t st;

    memset(&st, 0, sizeof(st));
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_init(2, 3), KM_ERR_OK);
    km_mng_reset_msg_id();

    /* 首次 tick 立即发送：期望槽登记（pending=1、tx_msg_id=1） */
    km_heartbeat_tick(1000);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 1);
    KM_TEST_ASSERT_EQ_INT((int)st.last_tx, 1000);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 1);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_msg_id, 1);

    /* 未到期不重复发送 */
    km_heartbeat_tick(1001);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 1);

    /* 到期（+2s）再发一次：msg_id 自增 2 */
    km_heartbeat_tick(1002);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 2);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 1);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_msg_id, 2);
}

static void test_heartbeat_handle(void)
{
    uint8_t frame[sizeof(STU_TLV_MNG_HEAD)];
    km_heartbeat_stat_t st;

    km_heartbeat_init(2, 3);
    km_mng_reset_msg_id();

    /* 管理服务问询（sender=MNG，无挂起期望）：记存活 + 应答回显其 msg_id */
    build_heartbeat_frame(frame, KM_SENDER_MNG, SYSMNG_MSG_TYPE_HEARTBEAT, 0);
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(frame, KM_MNG_HEAD_LEN), KM_ERR_OK);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.rx_count, 1);
    KM_TEST_ASSERT_EQ_INT((int)st.lost_count, 0);
    KM_TEST_ASSERT_EQ_INT((int)(st.last_rx != 0), 1);
    /* 问询应答走 encode_reply：不消耗主动计数、不登记期望 */
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 0);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 0);

    /* 对端回传（sender=KM）：只记存活不回（防回环乒乓） */
    build_heartbeat_frame(frame, KM_SENDER_KM, SYSMNG_MSG_TYPE_HEARTBEAT, 0);
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(frame, KM_MNG_HEAD_LEN), KM_ERR_OK);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.rx_count, 2);
}

/* 期望槽匹配语义：本机主动心跳 → 对端回显同 id → 确认存活、清槽、不答复；
 * 收到不匹配（或对端主动问询）心跳 → 应答回显，挂起期望不被清除 */
static void test_heartbeat_reply_match(void)
{
    uint8_t frame[sizeof(STU_TLV_MNG_HEAD)];
    km_heartbeat_stat_t st;

    km_heartbeat_init(2, 3);
    km_mng_reset_msg_id();

    km_heartbeat_tick(1000); /* 主动发送 id=1，登记期望 */
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_msg_id, 1);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 1);

    /* 对端回执同 id（期望匹配）→ 确认存活：清槽、不答复、不增加主动发送 */
    build_heartbeat_frame(frame, KM_SENDER_MNG, SYSMNG_MSG_TYPE_HEARTBEAT, 1);
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(frame, KM_MNG_HEAD_LEN), KM_ERR_OK);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 0);
    KM_TEST_ASSERT_EQ_INT((int)st.lost_count, 0);
    KM_TEST_ASSERT_EQ_INT((int)st.rx_count, 1);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 1);

    /* 超时窗内（无挂起期望）不再判丢 */
    km_heartbeat_tick(1001);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.lost_count, 0);

    km_heartbeat_tick(1002); /* 第二拍：主动发送 id=2，再次登记 */
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 2);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_msg_id, 2);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 1);

    /* 收到不匹配 id=7（视为管理服务问询）→ 应答回显 7，挂起期望保持 */
    build_heartbeat_frame(frame, KM_SENDER_MNG, SYSMNG_MSG_TYPE_HEARTBEAT, 7);
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(frame, KM_MNG_HEAD_LEN), KM_ERR_OK);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 1);  /* 期望未被清除 */
    KM_TEST_ASSERT_EQ_INT((int)st.tx_msg_id, 2);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 2); /* 问询应答不消耗主动计数 */
    KM_TEST_ASSERT_EQ_INT((int)st.rx_count, 2);

    /* 随后同 id 回执到达 → 匹配清槽 */
    build_heartbeat_frame(frame, KM_SENDER_MNG, SYSMNG_MSG_TYPE_HEARTBEAT, 2);
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(frame, KM_MNG_HEAD_LEN), KM_ERR_OK);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 0);
    KM_TEST_ASSERT_EQ_INT((int)st.rx_count, 3);
}

static void test_heartbeat_timeout(void)
{
    uint8_t frame[sizeof(STU_TLV_MNG_HEAD)];
    km_heartbeat_stat_t st;

    km_heartbeat_init(2, 3);
    km_mng_reset_msg_id();

    km_heartbeat_tick(1000); /* 首次发送，last_tx=1000，期望槽 id=1 */
    km_heartbeat_tick(1001); /* 未到下一发送周期（1s<2s），超时窗未到（<1000+6） */
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 1);
    KM_TEST_ASSERT_EQ_INT((int)st.lost_count, 0);

    km_heartbeat_tick(1006); /* 1006-1000=6 >= 2*3：超时判丢一次（同时推进新一轮 id=2） */
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.lost_count, 1);

    /* 收到对端同 id 回执（当前期望槽 id=2）→ 匹配清槽并清零 */
    build_heartbeat_frame(frame, KM_SENDER_MNG, SYSMNG_MSG_TYPE_HEARTBEAT, 2);
    km_heartbeat_handle(frame, KM_MNG_HEAD_LEN);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.lost_count, 0);
    KM_TEST_ASSERT_EQ_INT((int)st.pending, 0);
}

static void test_heartbeat_disabled(void)
{
    km_heartbeat_stat_t st;

    km_heartbeat_init(0, 3); /* interval=0：关闭心跳 */
    km_heartbeat_tick(1000);
    km_heartbeat_get_stat(&st);
    KM_TEST_ASSERT_EQ_INT((int)st.tx_count, 0);
    KM_TEST_ASSERT_EQ_INT((int)st.lost_count, 0);
}

static void test_heartbeat_bad_param(void)
{
    uint8_t frame[sizeof(STU_TLV_MNG_HEAD)];

    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(NULL, 0), KM_ERR_BAD_PARAM);
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(frame, 7), KM_ERR_BAD_PARAM); /* mng_len < 8 */

    /* 非心跳命令 */
    build_heartbeat_frame(frame, KM_SENDER_MNG, 0xFF, 0);
    KM_TEST_ASSERT_EQ_INT(km_heartbeat_handle(frame, KM_MNG_HEAD_LEN), KM_ERR_BAD_PARAM);
}

/* 心跳上行载荷（km_heartbeat_payload_t）：单字节对齐 5B 定长线格式，
 * 内容 = 4B 已运行秒数 + 1B 运行状态；运行状态可设置/查询（写入上行载荷）。 */
static void test_heartbeat_payload(void)
{
    km_heartbeat_payload_t body;
    uint8_t tlv[16];
    const uint8_t *val = NULL;
    size_t tlv_len = 0, off = 0, vlen = 0;
    uint8_t tag = 0;

    /* 结构体布局：pack(1)，字段偏移与总长固定（对端按此解析） */
    KM_TEST_ASSERT_EQ_INT((int)sizeof(km_heartbeat_payload_t), 5);
    KM_TEST_ASSERT_EQ_INT((int)offsetof(km_heartbeat_payload_t, uptime_sec), 0);
    KM_TEST_ASSERT_EQ_INT((int)offsetof(km_heartbeat_payload_t, run_state), 4);

    /* 运行状态枚举取值（协议约定，收发两端一致） */
    KM_TEST_ASSERT_EQ_INT((int)KM_RUN_STATE_STARTING, 0xFF);
    KM_TEST_ASSERT_EQ_INT((int)KM_RUN_STATE_BOOT_OK, 0x01);
    KM_TEST_ASSERT_EQ_INT((int)KM_RUN_STATE_RNG_FAIL, 0xE0);
    KM_TEST_ASSERT_EQ_INT((int)KM_RUN_STATE_FPGA_FAIL, 0xE1);
    KM_TEST_ASSERT_EQ_INT((int)KM_RUN_STATE_CARD_FAIL, 0xE2);

    /* 运行状态设置/查询（随心跳上行载荷上报） */
    km_heartbeat_init(2, 3);
    km_heartbeat_set_run_state(KM_RUN_STATE_STARTING);
    KM_TEST_ASSERT_EQ_INT((int)km_heartbeat_get_run_state(), (int)KM_RUN_STATE_STARTING);
    km_heartbeat_set_run_state(KM_RUN_STATE_CARD_FAIL);
    KM_TEST_ASSERT_EQ_INT((int)km_heartbeat_get_run_state(), (int)KM_RUN_STATE_CARD_FAIL);
    km_heartbeat_set_run_state(KM_RUN_STATE_BOOT_OK);
    KM_TEST_ASSERT_EQ_INT((int)km_heartbeat_get_run_state(), (int)KM_RUN_STATE_BOOT_OK);

    /* 载荷 TLV 编解码往返：tag=0x01、value 恰为 5B、字段按小端写入线格式 */
    memset(&body, 0, sizeof(body));
    body.uptime_sec = 0x01020304u;  /* 小端线格式字节序：04 03 02 01 */
    body.run_state = KM_RUN_STATE_FPGA_FAIL;
    KM_TEST_ASSERT_EQ_INT(km_tlv_append(tlv, sizeof(tlv), &tlv_len,
                                        KM_TLV_TAG_HEARTBEAT, &body, sizeof(body)),
                          KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)tlv_len, 3 + 5);
    KM_TEST_ASSERT_EQ_INT(km_tlv_next(tlv, tlv_len, &off, &tag, &val, &vlen), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)tag, (int)KM_TLV_TAG_HEARTBEAT);
    KM_TEST_ASSERT_EQ_INT((int)vlen, 5);
    KM_TEST_ASSERT_EQ_INT((int)val[0], 0x04);
    KM_TEST_ASSERT_EQ_INT((int)val[1], 0x03);
    KM_TEST_ASSERT_EQ_INT((int)val[2], 0x02);
    KM_TEST_ASSERT_EQ_INT((int)val[3], 0x01);
    KM_TEST_ASSERT_EQ_INT((int)val[4], (int)KM_RUN_STATE_FPGA_FAIL);
}

void test_heartbeat(void)
{
    test_heartbeat_immediate_send();
    test_heartbeat_handle();
    test_heartbeat_reply_match();
    test_heartbeat_timeout();
    test_heartbeat_disabled();
    test_heartbeat_bad_param();
    test_heartbeat_payload();
}
