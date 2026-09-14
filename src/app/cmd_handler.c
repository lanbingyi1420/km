/* ============================================================
 * CmdHandler：管理消息子处理（心跳/状态/证书导入）
 * 仅处理已通过 km_mng_parse 管理头检查的消息（frame + mng_len）：
 *   收帧 -> km_fpga_parse -> 按 msg_type 分流 -> km_mng_parse -> km_mng_handle_message
 *      (本模块分发，frame 为整帧首 = STU_TLV_MNG_HEAD 视图) -> 编码应答 -> 发送
 * 最外层收帧/分流职责在 app/msg_dispatch.c 的 km_msg_handle。
 * 承载约定：frame 指向帧首，TLV = frame + sizeof(STU_TLV_MNG_HEAD)(17)，
 *   TLV 长度 = mng_len - KM_MNG_HEAD_LEN(8)；不再使用 km_mng_msg_t。
 * 期望语义：本模块收到的管理消息按"对方发起"应答（encode_reply 回显请求 msg_id）；
 *   KM 主动发送类型（目前仅心跳）的期望跟踪收敛在 heartbeat 模块，
 *   业务消息不登记期望（对端是否回执不影响 KM 状态机）。
 * ============================================================ */

#include "km_api.h"
#include "comm/km_comm.h"
#include "comm/mgmt_protocol.h"
#include "km_cert.h"
#include "km_log.h"
#include "core/cert_validator.h"
#include "heartbeat.h"
#include "thread.h"

#include <string.h>

/* 应答帧 TLV 约定：
 *   0x01 状态字节（心跳/状态应答）
 *   0x02 结果码 int32（证书导入应答，0 = 成功） */

/* 设备工作状态：1=正常；0=定时自检失败停止工作（业务消息被拒绝）。
 * 由定时线程（自检结果）写入、业务线程读取，经 g_work_lock 保护。
 * 锁初始化须在启动线程前完成（main 预热调用 km_cmd_set_working）。 */
static int g_working = 1;
static km_mutex_t g_work_lock;
static int g_work_lock_inited = 0;

static void ensure_work_lock(void)
{
    if (!g_work_lock_inited) {
        km_mutex_init(&g_work_lock);
        g_work_lock_inited = 1;
    }
}

/* 设置设备工作状态：1=正常；0=自检失败停止工作（业务消息被拒绝） */
void km_cmd_set_working(int working)
{
    ensure_work_lock();
    km_mutex_lock(&g_work_lock);
    g_working = (working != 0) ? 1 : 0;
    km_mutex_unlock(&g_work_lock);
}

/* 查询设备工作状态（线程安全） */
int km_cmd_is_working(void)
{
    int w;

    ensure_work_lock();
    km_mutex_lock(&g_work_lock);
    w = g_working;
    km_mutex_unlock(&g_work_lock);
    return w;
}

/* 组帧并异步发送应答（投递发送队列由通信线程发送；线程未启用时同步发送）。
 * 应答语义：回显请求帧 msg_id（encode_reply，不自增/不登记期望）。 */
static km_err_t reply_frame(uint16_t msg_cmd, uint8_t req_msg_id,
                            const uint8_t *tlv, size_t tlv_len)
{
    uint8_t buf[KM_MAX_MSG_LEN];
    size_t len = sizeof(buf);

    if (km_mng_frame_encode_reply(buf, &len, msg_cmd, req_msg_id,
                                  tlv, tlv_len) != KM_ERR_OK)
        return KM_ERR_COMM_FAIL;
    return km_comm_send_async(buf, len);
}

/* 构造 TLV 0x01 状态字节应答帧 */
static km_err_t reply_status(uint16_t msg_cmd, uint8_t req_msg_id, uint8_t status)
{
    uint8_t tlv[8];
    size_t tlv_len = 0;

    if (km_tlv_append(tlv, sizeof(tlv), &tlv_len, 0x01, &status, 1) != KM_ERR_OK)
        return KM_ERR_BUF_TOO_SMALL;
    return reply_frame(msg_cmd, req_msg_id, tlv, tlv_len);
}

/* 构造 TLV 0x02 结果码 int32 应答帧 */
static km_err_t reply_result(uint16_t msg_cmd, uint8_t req_msg_id, km_err_t rc)
{
    int32_t code = (int32_t)rc;
    uint8_t tlv[8];
    size_t tlv_len = 0;

    if (km_tlv_append(tlv, sizeof(tlv), &tlv_len, 0x02, &code, sizeof(code)) != KM_ERR_OK)
        return KM_ERR_BUF_TOO_SMALL;
    return reply_frame(msg_cmd, req_msg_id, tlv, tlv_len);
}

/* ---------- 证书导入（新线格式，子功能独立函数） ----------
 * 线格式见 mgmt_protocol.h：
 *   SET_CACERT（根证书导入）：data 区 = 证书项循环，每项：
 *     [名称长度:1B][名称 xxx.pem][内容长度:2B 小端][内容 PEM]
 *   SET_DEVCERT（设备证书导入）：data 区 = [证书类型:1B(1=签名 2=加密)]
 *     后接证书项循环（每项同上）。
 * 证书保存至 ./certs/ 并更新 certlist.json；设备证书导入同时匹配内部密钥
 * 槽 key_index（签名=1 起步步长 2，加密=签名+1）。 */

/* 读 2 字节小端（证书内容长度字段） */
static uint16_t cert_load_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* 从 data 区 offset 处解析一个证书项：
 * 成功返回 KM_ERR_OK 并推进 *off；无更多项返回 1（结束）；格式错返回负错误码 */
static int cert_item_next(const uint8_t *data, size_t data_len, size_t *off,
                          char *name, size_t name_cap, size_t *name_len,
                          const uint8_t **pem, size_t *pem_len)
{
    size_t o = *off;
    size_t nl;

    if (o >= data_len)
        return 1; /* 无更多证书项 */

    if (data_len - o < 3) {
        km_oplog_write(LOG_LEVEL_WARN, "cmd: cert item too short at off %u",
                       (unsigned)o);
        return -KM_ERR_FORMAT;
    }
    nl = data[o];
    if (nl == 0 || nl > KM_CERT_NAME_MAX) {
        km_oplog_write(LOG_LEVEL_WARN, "cmd: cert name len %u invalid", (unsigned)nl);
        return -KM_ERR_FORMAT;
    }
    if (data_len - o < 1 + nl + 2) {
        km_oplog_write(LOG_LEVEL_WARN, "cmd: cert item truncated (name %u)", (unsigned)nl);
        return -KM_ERR_FORMAT;
    }
    if (nl >= name_cap) {
        km_oplog_write(LOG_LEVEL_WARN, "cmd: cert name buffer too small");
        return -KM_ERR_FORMAT;
    }

    memcpy(name, data + o + 1, nl);
    name[nl] = '\0';

    *pem_len = cert_load_le16(data + o + 1 + nl);
    if (*pem_len == 0 || data_len - o < 1 + nl + 2 + *pem_len) {
        km_oplog_write(LOG_LEVEL_WARN, "cmd: cert pem len %u invalid",
                       (unsigned)*pem_len);
        return -KM_ERR_FORMAT;
    }
    *pem = data + o + 1 + nl + 2;

    *name_len = nl;
    *off = o + 1 + nl + 2 + *pem_len;
    return 0;
}

/* 导入一个证书项（根证书或设备证书单条），返回导入错误码 */
static km_err_t cert_import_one(uint16_t msg_cmd, int cert_use,
                                const char *name,
                                const char *pem, size_t pem_len)
{
    km_err_t err;
    int key_index = -1;

    if (msg_cmd == SYSMNG_MSG_TYPE_SET_CACERT) {
        err = km_cert_import_root_named(name, pem, pem_len);
    } else {
        err = km_cert_import_dev_named(cert_use, name, pem, pem_len,
                                       &key_index);
    }
    if (err != KM_ERR_OK)
        km_oplog_write(LOG_LEVEL_WARN,
                       "cmd: cert import '%s' failed: %s", name, km_err_str(err));
    return err;
}

/* SET_CACERT / SET_DEVCERT 证书导入公共处理（证书项循环 + 应答）。
 * frame 为整帧首（STU_TLV_MNG_HEAD 视图），从管理头读 msg_cmd；
 * TLV 载荷 = frame + sizeof(STU_TLV_MNG_HEAD)，长度 = mng_len - KM_MNG_HEAD_LEN */
static km_err_t handle_cert_import(const uint8_t *frame, uint16_t mng_len)
{
    STU_TLV_MNG_HEAD mh;
    const uint8_t *tlv;
    size_t tlv_len;
    size_t off = 0;
    uint16_t msg_cmd;
    uint8_t req_msg_id;
    int rc;
    int cert_use = 0;
    int item_cnt = 0;

    memcpy(&mh, frame, sizeof(mh));
    msg_cmd = (uint16_t)((uint16_t)mh.msg_cmd[0] | ((uint16_t)mh.msg_cmd[1] << 8));
    req_msg_id = mh.msg_id;
    tlv = frame + sizeof(STU_TLV_MNG_HEAD);
    tlv_len = mng_len - KM_MNG_HEAD_LEN;

    /* SET_DEVCERT 首位为证书类型 1B：1=签名证书 2=加密证书 */
    if (msg_cmd == SYSMNG_MSG_TYPE_SET_DEVCERT) {
        if (tlv_len < 1) {
            km_oplog_write(LOG_LEVEL_WARN, "cmd: dev cert import missing type byte");
            return reply_result(msg_cmd, req_msg_id, KM_ERR_FORMAT);
        }
        cert_use = tlv[0];
        if (cert_use != KM_CERT_USE_SIGN && cert_use != KM_CERT_USE_ENC) {
            km_oplog_write(LOG_LEVEL_WARN, "cmd: dev cert bad use 0x%02x", cert_use);
            return reply_result(msg_cmd, req_msg_id, KM_ERR_FORMAT);
        }
        off = 1;
    }

    for (;;) {
        char name[KM_CERT_NAME_MAX + 1];
        size_t name_len = 0;
        const uint8_t *pem = NULL;
        size_t pem_len = 0;
        km_err_t err;

        rc = cert_item_next(tlv, tlv_len, &off,
                            name, sizeof(name), &name_len,
                            &pem, &pem_len);
        if (rc == 1)
            break; /* 所有证书项处理完毕 */
        if (rc != 0)
            return reply_result(msg_cmd, req_msg_id, KM_ERR_FORMAT);

        err = cert_import_one(msg_cmd, cert_use,
                              name, (const char *)pem, pem_len);
        if (err != KM_ERR_OK)
            return reply_result(msg_cmd, req_msg_id, err);
        item_cnt++;
    }

    if (item_cnt == 0) {
        km_oplog_write(LOG_LEVEL_WARN, "cmd: cert import with zero cert item");
        return reply_result(msg_cmd, req_msg_id, KM_ERR_FORMAT);
    }

    km_oplog_write(LOG_LEVEL_INFO, "cmd: cert import ok type=0x%04x items=%d",
                   msg_cmd, item_cnt);
    return reply_result(msg_cmd, req_msg_id, KM_ERR_OK);
}

/* 管理消息子处理入口：由 msg_dispatch 在 km_mng_parse 检查管理头后调用；
 * frame 为整帧首（STU_TLV_MNG_HEAD 视图），mng_len 为管理消息长度（8+TLV）；
 * 收到的管理消息视为"对方发起"：心跳走 heartbeat 模块（内部按 msg_id 判回复/问询），
 * 其余命令应答回显请求 msg_id（encode_reply）；业务在自检失败时被拒 */
km_err_t km_mng_handle_message(const uint8_t *frame, uint16_t mng_len)
{
    STU_TLV_MNG_HEAD mh;
    uint16_t msg_cmd;
    uint8_t req_msg_id;

    if (frame == NULL || mng_len < KM_MNG_HEAD_LEN)
        return KM_ERR_BAD_PARAM;

    memcpy(&mh, frame, sizeof(mh)); /* frame 已过 km_mng_parse 校验，安全 */
    msg_cmd = (uint16_t)((uint16_t)mh.msg_cmd[0] | ((uint16_t)mh.msg_cmd[1] << 8));
    req_msg_id = mh.msg_id;

    switch (msg_cmd) {
    case SYSMNG_MSG_TYPE_HEARTBEAT:
        /* 心跳收发/应答/超时统计收敛于 heartbeat 模块：
         * 期望槽匹配（本机主动心跳的回复）→ 确认存活不答复；
         * 不匹配 → 视为管理服务问询，应答并回显其 msg_id。 */
        return km_heartbeat_handle(frame, mng_len);

    case SYSMNG_MSG_TYPE_STATUS_REQ:
        /* 状态应答（回显请求 msg_id）：1=正常，0=自检失败停止工作 */
        return reply_status(SYSMNG_MSG_TYPE_STATUS_REQ, req_msg_id,
                            (uint8_t)(km_cmd_is_working() ? 1 : 0));

    case SYSMNG_MSG_TYPE_SET_CACERT:
    case SYSMNG_MSG_TYPE_SET_DEVCERT:
        /* 自检失败停止工作：拒绝业务消息 */
        if (!km_cmd_is_working()) {
            km_oplog_write(LOG_LEVEL_WARN,
                           "cmd: device stopped (selftest failed), reject msg 0x%04x",
                           msg_cmd);
            return reply_result(msg_cmd, req_msg_id, KM_ERR_SELFTEST_FAIL);
        }
        return handle_cert_import(frame, mng_len);

    default:
        km_oplog_write(LOG_LEVEL_WARN, "cmd: unknown msg type 0x%04x", msg_cmd);
        return KM_ERR_OK;
    }
}
