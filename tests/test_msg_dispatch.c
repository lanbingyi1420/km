#include "km_test.h"
#include "app/msg_dispatch.h"
#include "comm/mgmt_protocol.h"
#include <string.h>

/* 应用层收帧入口（km_msg_handle）分流测试：
 *   管理通道(SYSMNG_MSG_TYPE_HEARTBEAT)        → KM_ERR_OK（内部经 km_mng_parse + 管理子处理）
 *   预留通道(FPGA_MSGTYPE_fromFPGA)           → KM_ERR_RESERVED（区别于未知类型）
 *   未知 msg_type                              → KM_ERR_NOT_SUPPORTED
 *   参数/格式错误                              → KM_ERR_BAD_PARAM / KM_ERR_FORMAT
 * 帧头统一 FPGA 帧头 8B：msg_type@2-3（2B 小端篡改点） */
void test_msg_dispatch(void)
{
    uint8_t buf[KM_MAX_MSG_LEN];
    size_t len;

    /* 1) 管理通道正常流转：编码 SYSMNG_MSG_TYPE_HEARTBEAT（sender=KM，心跳只记存活不应答） */
    len = sizeof(buf);
    KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len,
                                              SYSMNG_MSG_TYPE_HEARTBEAT, NULL, 0, NULL), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT(km_msg_handle(buf, len), KM_ERR_OK);

    /* 1.5) 管理通道：管理头损坏 → mng_parse 拒绝，返回 KM_ERR_FORMAT */
    {
        size_t mng_off = KM_FPGA_HEAD_LEN; /* 管理头起点：0x68@8 */
        buf[mng_off] ^= 0xff; /* 0x68 magic */
        KM_TEST_ASSERT_EQ_INT(km_msg_handle(buf, len), KM_ERR_FORMAT);
        buf[mng_off] ^= 0xff;
    }

    /* 2) 预留通道：篡改 msg_type@2-3 为 FPGA_MSGTYPE_fromFPGA（FPGA 算法自检回复）
     *    → KM_ERR_RESERVED（区别于未知类型的 KM_ERR_NOT_SUPPORTED） */
    {
        size_t flen = sizeof(buf);
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &flen,
                                                  SYSMNG_MSG_TYPE_STATUS_REQ, NULL, 0, NULL),
                              KM_ERR_OK);
        buf[2] = (uint8_t)FPGA_MSGTYPE_fromFPGA;
        buf[3] = (uint8_t)(FPGA_MSGTYPE_fromFPGA >> 8);
        KM_TEST_ASSERT_EQ_INT(km_msg_handle(buf, flen), KM_ERR_RESERVED);
    }

    /* 3) 未知 msg_type → KM_ERR_NOT_SUPPORTED */
    {
        size_t flen = sizeof(buf);
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &flen,
                                                  SYSMNG_MSG_TYPE_STATUS_REQ, NULL, 0, NULL),
                              KM_ERR_OK);
        buf[2] = 0xff;
        buf[3] = 0xff;
        KM_TEST_ASSERT_EQ_INT(km_msg_handle(buf, flen), KM_ERR_NOT_SUPPORTED);
    }

    /* 4) 参数校验 */
    KM_TEST_ASSERT_EQ_INT(km_msg_handle(NULL, 0), KM_ERR_BAD_PARAM);
    KM_TEST_ASSERT_EQ_INT(km_msg_handle(buf, 0), KM_ERR_BAD_PARAM);

    /* 5) 最外层格式错误（长度未 8 字节对齐 / 过短）→ fpga_parse 拒绝 */
    len = sizeof(buf);
    KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len,
                                              SYSMNG_MSG_TYPE_STATUS_REQ, NULL, 0, NULL),
                          KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT(km_msg_handle(buf, len - 1), KM_ERR_FORMAT);
    KM_TEST_ASSERT_EQ_INT(km_msg_handle(buf, 7), KM_ERR_FORMAT);
}
