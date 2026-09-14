#include "km_test.h"
#include "comm/mgmt_protocol.h"
#include "comm/gmac_comm.h"
#include <string.h>

/* 管理消息捕获回调：按线格式从整帧读管理头，把 TLV 拷到 ctx（结构捕获） */
typedef struct {
    uint8_t  msg_id;    /* 管理消息 id（帧内偏移 11） */
    uint8_t  sender;
    uint8_t  receiver;
    uint16_t msg_cmd;   /* 2B 小端 */
    uint8_t tlv[512];
    size_t  tlv_len;
} test_mng_capture;

static km_err_t test_mng_handler(const uint8_t *frame, uint16_t mng_len, void *ctx)
{
    STU_TLV_MNG_HEAD mh;
    test_mng_capture *out = (test_mng_capture *)ctx;

    if (out != NULL) {
        memcpy(&mh, frame, sizeof(mh));
        out->msg_id = mh.msg_id;
        out->sender = mh.sender;
        out->receiver = mh.receiver;
        out->msg_cmd = (uint16_t)((uint16_t)mh.msg_cmd[0] | ((uint16_t)mh.msg_cmd[1] << 8));
        out->tlv_len = mng_len - KM_MNG_HEAD_LEN;
        memcpy(out->tlv, frame + sizeof(STU_TLV_MNG_HEAD), out->tlv_len);
    }
    return KM_ERR_OK;
}

void test_mgmt_protocol(void)
{
    uint8_t buf[KM_MAX_MSG_LEN];
    uint8_t tlv_buf[512];
    size_t tlv_len = 0;
    size_t len;
    size_t off;
    uint8_t tag;
    const uint8_t *val;
    size_t vlen;
    const STU_TLV_FPGA_HEAD *head = NULL;
    test_mng_capture cap;

    /* 1) 构造带 TLV 的请求帧并编码 → 校验填充规则（帧头统一 FPGA 帧头 8B） */
    {
        static const uint8_t body[] = {0xde, 0xad, 0xbe, 0xef};

        KM_TEST_ASSERT_EQ_INT(
            km_tlv_append(tlv_buf, sizeof(tlv_buf), &tlv_len, 0x01, body, sizeof(body)), 0);
        KM_TEST_ASSERT_EQ_INT(
            km_tlv_append(tlv_buf, sizeof(tlv_buf), &tlv_len, 0x02, "CN=KM", 5), 0);

        len = sizeof(buf);
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len,
                                                  SYSMNG_MSG_TYPE_STATUS_REQ, tlv_buf, tlv_len, NULL),
                              KM_ERR_OK);
        /* 填充要求：整帧（含 CRC）8 字节对齐且 >= 64B */
        KM_TEST_ASSERT(len >= KM_FRAME_MIN_LEN);
        KM_TEST_ASSERT(len % KM_FRAME_ALIGN == 0);
        KM_TEST_ASSERT(len > KM_FPGA_HEAD_LEN + KM_MNG_HEAD_LEN + KM_FRAME_CRC_LEN);
        /* FPGA 帧头(8B)：padding_len@5，pkt_len@6-7(小端) = 管理消息 + 填充 */
        KM_TEST_ASSERT_EQ_INT(
            (int)buf[5],
            (int)(len - (KM_FPGA_HEAD_LEN + KM_MNG_HEAD_LEN + tlv_len + KM_FRAME_CRC_LEN)));
        KM_TEST_ASSERT_EQ_INT(
            (int)(buf[6] | ((int)buf[7] << 8)),
            (int)(KM_MNG_HEAD_LEN + tlv_len + buf[5])); /* len 含 0x68 头 = 8 + tlv */
        {
            size_t k;
            for (k = KM_FPGA_HEAD_LEN + KM_MNG_HEAD_LEN + tlv_len;
                 k < len - KM_FRAME_CRC_LEN; k++)
                KM_TEST_ASSERT_EQ_INT((int)buf[k], (int)buf[5]); /* 填充字节值 = padding_len */
        }

        /* 最外层：km_fpga_parse 仅解析 FPGA 头，输出零拷贝视图 */
        KM_TEST_ASSERT_EQ_INT(km_fpga_parse(buf, len, &head), KM_ERR_OK);
        KM_TEST_ASSERT(head != NULL);
        KM_TEST_ASSERT_EQ_INT((int)head->msg_type, (int)FPGA_MSGTYPE_toSYSMNG);
        KM_TEST_ASSERT_EQ_INT((int)buf[5], (int)(len - (KM_FPGA_HEAD_LEN + KM_MNG_HEAD_LEN
                                                        + tlv_len + KM_FRAME_CRC_LEN)));
        KM_TEST_ASSERT_EQ_INT((int)(buf[6] | ((int)buf[7] << 8)),
                              (int)(KM_MNG_HEAD_LEN + tlv_len + buf[5])); /* = 8 + tlv + pad */

        /* 分层分发：管理类型 → 管理子处理 → 回调(frame,mng_len) 按线格式读字段 */
        memset(&cap, 0, sizeof(cap));
        KM_TEST_ASSERT_EQ_INT(km_frame_dispatch(buf, len, test_mng_handler, &cap), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)cap.msg_cmd, (int)SYSMNG_MSG_TYPE_STATUS_REQ);
        KM_TEST_ASSERT_EQ_INT((int)cap.sender, (int)KM_SENDER_KM);
        KM_TEST_ASSERT_EQ_INT((int)cap.receiver, (int)KM_SENDER_MNG);
        KM_TEST_ASSERT_EQ_INT((int)cap.tlv_len, (int)tlv_len);
        KM_TEST_ASSERT_MEM_EQ(cap.tlv, tlv_buf, tlv_len);
    }

    /* 1.5) 非管理通道分流：预留/未知类型 → 协议层统一 NOT_SUPPORTED */
    {
        size_t flen = sizeof(buf);

        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &flen,
                                                  SYSMNG_MSG_TYPE_STATUS_REQ, tlv_buf, tlv_len, NULL),
                              KM_ERR_OK);
        /* 篡改 msg_type（@2-3 小端，FPGA 帧头 8B）为 FPGA->KM 算法自检回复类型 */
        buf[2] = (uint8_t)FPGA_MSGTYPE_fromFPGA;
        buf[3] = (uint8_t)(FPGA_MSGTYPE_fromFPGA >> 8);
        KM_TEST_ASSERT_EQ_INT(km_frame_dispatch(buf, flen, test_mng_handler, &cap),
                              KM_ERR_NOT_SUPPORTED);
        /* 未知类型同样 NOT_SUPPORTED */
        buf[2] = 0xff;
        buf[3] = 0xff;
        KM_TEST_ASSERT_EQ_INT(km_frame_dispatch(buf, flen, test_mng_handler, &cap),
                              KM_ERR_NOT_SUPPORTED);
    }

    /* 2) TLV 顺序解析 */
    off = 0;
    KM_TEST_ASSERT_EQ_INT(km_tlv_next(tlv_buf, tlv_len, &off, &tag, &val, &vlen), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)tag, 0x01);
    KM_TEST_ASSERT_EQ_INT((int)vlen, 4);
    KM_TEST_ASSERT_MEM_EQ(val, (const uint8_t *)"\xde\xad\xbe\xef", 4);
    KM_TEST_ASSERT_EQ_INT(km_tlv_next(tlv_buf, tlv_len, &off, &tag, &val, &vlen), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT((int)tag, 0x02);
    KM_TEST_ASSERT_EQ_INT((int)vlen, 5);
    KM_TEST_ASSERT_MEM_EQ(val, "CN=KM", 5);
    /* 越界 → 格式错误 */
    KM_TEST_ASSERT_EQ_INT(km_tlv_next(tlv_buf, tlv_len, &off, &tag, &val, &vlen), KM_ERR_FORMAT);

    /* 2.5) msg_id 语义：主动发送自动自增（1..255 后回绕 0）；应答回显且不消耗计数器 */
    {
        uint8_t id1 = 0, id2 = 0, id3 = 0;
        size_t l1 = sizeof(buf), l2 = sizeof(buf), l3 = sizeof(buf);
        size_t mng_off = KM_FPGA_HEAD_LEN; /* 管理头起点 @8 */

        km_mng_reset_msg_id();
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &l1, SYSMNG_MSG_TYPE_HEARTBEAT,
                                                  NULL, 0, &id1), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)id1, 1);
        /* 帧内偏移：msg_id@11、sender@12、receiver@13、msg_cmd@14-15（小端） */
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 3], 1);              /* msg_id=1 */
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 4], (int)KM_SENDER_KM);
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 5], (int)KM_SENDER_MNG);
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 6], 0x01);           /* cmd 低字节 */
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 7], 0x00);           /* cmd 高字节 */

        /* 连续主动发送：自增 1 → 2 */
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &l2, SYSMNG_MSG_TYPE_HEARTBEAT,
                                                  NULL, 0, &id2), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)id2, 2);

        /* 应答回显请求 id=0xAB：帧内 msg_id=0xAB，且不消耗自增计数器 */
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode_reply(buf, &l3,
                                                        SYSMNG_MSG_TYPE_HEARTBEAT,
                                                        0xAB, NULL, 0), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 3], 0xAB);
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &l3, SYSMNG_MSG_TYPE_HEARTBEAT,
                                                  NULL, 0, &id3), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)id3, 3); /* reply 未消耗：2 的下一个仍是 3 */

        /* 2B 小端命令写入：0x0123 → 字节 [0x23, 0x01]（低字节在前） */
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &l1, 0x0123, NULL, 0, NULL),
                              KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 6], 0x23);
        KM_TEST_ASSERT_EQ_INT((int)buf[mng_off + 7], 0x01);
        /* 分发读取同一命令值 */
        memset(&cap, 0, sizeof(cap));
        KM_TEST_ASSERT_EQ_INT(km_frame_dispatch(buf, l1, test_mng_handler, &cap), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)cap.msg_cmd, 0x0123);

        /* 回绕：连续发送 256 次 id=1..255、0，再下一次回到 1 */
        km_mng_reset_msg_id();
        {
            int i;
            for (i = 0; i < 256; i++) {
                uint8_t id = 0;
                KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &l1,
                                                          SYSMNG_MSG_TYPE_HEARTBEAT,
                                                          NULL, 0, &id), KM_ERR_OK);
                if (i < 255)
                    KM_TEST_ASSERT_EQ_INT((int)id, i + 1); /* 第 256 次 = 0 */
            }
            id1 = 0;
            KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &l1,
                                                      SYSMNG_MSG_TYPE_HEARTBEAT,
                                                      NULL, 0, &id1), KM_ERR_OK);
            KM_TEST_ASSERT_EQ_INT((int)id1, 1);
        }
        km_mng_reset_msg_id();
    }

    /* 3) 异常输入 */
    {
        size_t len2 = sizeof(buf);
        size_t mng_off = KM_FPGA_HEAD_LEN; /* 管理头起点：0x68@8 */

        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len2,
                                                  SYSMNG_MSG_TYPE_STATUS_REQ, tlv_buf, tlv_len, NULL),
                              KM_ERR_OK);

#if KM_FRAME_CRC_ENABLE
        /* 篡改 payload → CRC 失败 */
        buf[len2 - KM_FRAME_CRC_LEN - 1] ^= 0xff;
        KM_TEST_ASSERT_EQ_INT(km_fpga_parse(buf, len2, &head), KM_ERR_FORMAT);
        buf[len2 - KM_FRAME_CRC_LEN - 1] ^= 0xff;
#endif

        /* 篡改填充区最后一个字节 → 填充内容校验失败（外层） */
        {
            size_t pad_last = len2 - KM_FRAME_CRC_LEN - 1; /* 填充区非空：64B 对齐保证 */
            buf[pad_last] ^= 0xff;
            KM_TEST_ASSERT_EQ_INT(km_fpga_parse(buf, len2, &head), KM_ERR_FORMAT);
            buf[pad_last] ^= 0xff;
        }

        /* 篡改管理头 0x68 magic → 最外层通过、管理子处理拒绝 */
        KM_TEST_ASSERT_EQ_INT(km_fpga_parse(buf, len2, &head), KM_ERR_OK);
        buf[mng_off] ^= 0xff;
        KM_TEST_ASSERT_EQ_INT(km_frame_dispatch(buf, len2, test_mng_handler, &cap),
                              KM_ERR_FORMAT);
        buf[mng_off] ^= 0xff;

        /* 篡改 msg_cmd 为 0（2B 小端，低字节@14）→ 管理子处理拒绝 */
        {
            size_t cmd_off = mng_off + 6; /* msg_cmd@14-15 */
            buf[cmd_off] = 0;
            buf[cmd_off + 1] = 0;
            KM_TEST_ASSERT_EQ_INT(km_frame_dispatch(buf, len2, test_mng_handler, &cap),
                                  KM_ERR_FORMAT);
            /* 恢复：重新编码 */
            len2 = sizeof(buf);
            KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len2,
                                                      SYSMNG_MSG_TYPE_STATUS_REQ,
                                                      tlv_buf, tlv_len, NULL), KM_ERR_OK);
        }

        /* magic 错误 */
        buf[0] ^= 0xff;
        KM_TEST_ASSERT_EQ_INT(km_fpga_parse(buf, len2, &head), KM_ERR_FORMAT);
        buf[0] ^= 0xff;
        /* 长度不足 */
        KM_TEST_ASSERT_EQ_INT(km_fpga_parse(buf, 7, &head), KM_ERR_FORMAT);
        /* 长度未 8 字节对齐 */
        KM_TEST_ASSERT_EQ_INT(km_fpga_parse(buf, len2 - 1, &head), KM_ERR_FORMAT);
        /* 空指针 */
        KM_TEST_ASSERT_EQ_INT(km_fpga_parse(NULL, 0, &head), KM_ERR_BAD_PARAM);
        KM_TEST_ASSERT_EQ_INT(km_mng_parse(NULL, 0, NULL, NULL), KM_ERR_BAD_PARAM);
    }

    /* 4) GmacComm 回环桩：注入 → 接收 */
    len = sizeof(buf);
    KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len,
                                              SYSMNG_MSG_TYPE_STATUS_REQ, tlv_buf, tlv_len, NULL),
                          KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT(km_gmac_init(GMAC_MODE_LOOPBACK, NULL), KM_ERR_OK);
    KM_TEST_ASSERT_EQ_INT(km_gmac_inject(buf, len), KM_ERR_OK);
    {
        uint8_t rbuf[KM_MAX_MSG_LEN];
        size_t rlen = 0;
        KM_TEST_ASSERT_EQ_INT(km_gmac_recv(rbuf, sizeof(rbuf), &rlen), KM_ERR_OK);
        KM_TEST_ASSERT_EQ_INT((int)rlen, (int)len);
        KM_TEST_ASSERT_MEM_EQ(rbuf, buf, len);
    }
    /* 无数据时返回 COMM_FAIL */
    {
        uint8_t rbuf[64];
        size_t rlen = 0;
        KM_TEST_ASSERT_EQ_INT(km_gmac_recv(rbuf, sizeof(rbuf), &rlen), KM_ERR_COMM_FAIL);
    }
    /* raw 模式第一阶段不支持 */
    KM_TEST_ASSERT_EQ_INT(km_gmac_init(GMAC_MODE_RAW, "eth0"), KM_ERR_NOT_SUPPORTED);
    km_gmac_deinit();

    /* 5) 帧缓冲区过小 / 非法命令 */
    {
        size_t small = 16;
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &small,
                                                  SYSMNG_MSG_TYPE_STATUS_REQ, tlv_buf, tlv_len, NULL),
                              KM_ERR_BUF_TOO_SMALL);
        /* 非法命令：>= 0xFFFF（上限 2B 值域 1..0xFFFE） */
        len = sizeof(buf);
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len,
                                                  SYSMNG_MSG_TYPE_MAX,
                                                  tlv_buf, tlv_len, NULL),
                              KM_ERR_BAD_PARAM);
        /* msg_cmd 0 */
        len = sizeof(buf);
        KM_TEST_ASSERT_EQ_INT(km_mng_frame_encode(buf, &len, 0, tlv_buf, tlv_len, NULL),
                              KM_ERR_BAD_PARAM);
    }
}
