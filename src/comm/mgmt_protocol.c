/* 管理协议分层编解码（不使用 km_frame_t / km_fpga_info_t / km_mng_msg_t）
 * 接收路径：
 *   [最外层 km_fpga_parse]    仅 FPGA 头：识别 magic、总长范围与对齐、
 *                             pkt_len/padding_len 一致性、填充内容、CRC32（宏控）
 *   [外层分发 km_frame_dispatch] 按 msg_type(FPGA_MSGTYPE) 分流到子处理
 *   [管理子处理 km_mng_parse] 检查管理头：0x68、len、sender/receiver、msg_cmd、TLV 边界
 * 发送路径：
 *   [km_mng_frame_encode]     组帧：FPGA 头 + 管理头 + TLV + 填充 [+ CRC32]
 *
 * 帧格式（统一 FPGA 帧头 8B，全局唯一；SMLT 9B/正式 8B 通路已移除）：
 *   [FPGA 头: head(2B, 0x5a5a) | msg_type(2B 小端, FPGA_MSGTYPE)
 *             | reserve(1B) | padding_len(1B) | pkt_len(2B 小端)]
 *   [管理头: 0x68(1B) | len(2B 小端 含0x68头及data) | msg_id(1B) | sender(1B) | receiver(1B)
 *             | msg_cmd(2B 小端)]
 *   [TLV 数据][padding(字节值 = padding_len)][crc32:4B，宏控]
 * 填充规则：整帧 8 字节对齐、最短 64B、最长 4096B（管理通道上限）；
 *   len = 管理消息长度（含 0x68 头及 data = 8 + TLV）；pkt_len = len + padding_len。
 * TLV 单元：[tag:1B][len:2B BE][value]
 *
 * 管理消息 id（msg_id，帧内偏移 11）：
 *   主动发送（km_mng_frame_encode）发送前自增 1（uint8 0~255 回绕，首帧=1）；
 *   应答（km_mng_frame_encode_reply）回显请求帧 msg_id，不消耗计数器。
 *   并发约束：自增计数器为模块级状态，主动发送须由单写者（如定时线程）调用；
 *   应答路径（业务/心跳处理线程）仅走 encode_reply，不触碰计数器。
 *
 * 头部读写统一通过 STU_TLV_* 结构体（pack(1) + memcpy 到局部结构体），
 * 不直接强转输入帧指针（避免 strict-aliasing UB），前提：主机小端。
 */

#include "mgmt_protocol.h"
#include "km_env.h"
#include "km_log.h"
#include <string.h>

/* 写 2 字节大端（TLV 长度字段） */
static void store_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* 读 2 字节大端 */
static uint16_t load_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* 写 2 字节小端（管理头 msg_cmd 字段） */
static void store_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

/* 读 2 字节小端 */
static uint16_t load_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* 主动发送 msg_id 计数器：发送前自增（0 起，1..255 后回绕到 0），单写者访问 */
static uint8_t g_tx_msg_id = 0;

void km_mng_reset_msg_id(void)
{
    g_tx_msg_id = 0;
}

/* 最外层：仅检查 FPGA 帧头（不解析管理头/子类型头）
 * 校验项：帧头 magic(0x5a5a)、总长范围(64~4096)/8 字节对齐、
 *         pkt_len/padding_len 一致性、填充内容、CRC32（宏控）
 * 校验通过后输出指向帧内 FPGA 头视图（head，零拷贝，仅 in 有效期内有效） */
km_err_t km_fpga_parse(const uint8_t *in, size_t in_len,
                       const STU_TLV_FPGA_HEAD **head)
{
    size_t payload_off, payload_len, pad_start;
    STU_TLV_FPGA_HEAD fh;
    uint16_t magic;
    size_t i;

    if (in == NULL)
        return KM_ERR_BAD_PARAM;

    /* GMAC 传输约束：最短 64B、最长 4096B、整帧 8 字节对齐 */
    if (in_len < KM_FRAME_MIN_LEN || in_len > KM_FRAME_MAX_LEN)
        return KM_ERR_FORMAT;
    if (in_len % KM_FRAME_ALIGN != 0)
        return KM_ERR_FORMAT;

    /* 帧头 magic：head 字段 2B 小端 = 0x5a5a（线格式 0x5A 0x5A）；其余一律拒绝 */
    memcpy(&magic, in, 2);
    if (magic != KM_FPGA_TLV_HEAD)
        return KM_ERR_FORMAT;

    memcpy(&fh, in, sizeof(fh));
    payload_off = sizeof(STU_TLV_FPGA_HEAD); /* 8 */
    payload_len = in_len - payload_off - fh.padding_len - KM_FRAME_CRC_LEN;

    /* pkt_len = 载荷区（管理头+TLV）+ padding；即 pkt_len + 帧头 + CRC = 整帧长 */
    if ((size_t)fh.pkt_len != payload_len + fh.padding_len)
        return KM_ERR_FORMAT;
    if (fh.padding_len > 0 && fh.padding_len > (in_len - payload_off))
        return KM_ERR_FORMAT;

    /* CRC32 校验（宏控，收发两端须一致） */
#if KM_FRAME_CRC_ENABLE
    {
        uint32_t crc_calc, crc_recv;
        const uint8_t *p = in + in_len - KM_FRAME_CRC_LEN;
        crc_calc = km_crc32(0xFFFFFFFFu, in, in_len - KM_FRAME_CRC_LEN);
        crc_recv = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                   ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        if (crc_calc != crc_recv)
            return KM_ERR_FORMAT;
    }
#endif

    /* 填充内容校验：填充字节值 == padding_len */
    pad_start = payload_off + payload_len;
    for (i = pad_start; i < in_len - KM_FRAME_CRC_LEN; i++) {
        if (in[i] != fh.padding_len)
            return KM_ERR_FORMAT;
    }

    if (head != NULL)
        *head = (const STU_TLV_FPGA_HEAD *)(const void *)in;
    return KM_ERR_OK;
}

/* 管理子处理：检查管理头并输出管理消息视图（零拷贝指向帧首）。
 * 帧整体即 STU_TLV_MNG_HEAD（16B 定长头）视图；TLV 起点 = frame + sizeof(STU_TLV_MNG_HEAD)。 */
km_err_t km_mng_parse(const uint8_t *in, size_t in_len,
                      const STU_TLV_MNG_HEAD **mng, uint16_t *mng_len)
{
    STU_TLV_MNG_HEAD mh;
    size_t payload_len;

    if (in == NULL || mng_len == NULL)
        return KM_ERR_BAD_PARAM;

    /* 须在 km_fpga_parse 通过后调用：帧内字段按 FPGA 帧布局直接读取（至少帧头+管理头） */
    if (in_len < sizeof(STU_TLV_MNG_HEAD))
        return KM_ERR_FORMAT;

    memcpy(&mh, in, sizeof(mh));
    if (mh.head != KM_MNG_HEAD_MAGIC)
        return KM_ERR_FORMAT;
    if (mh.len < KM_MNG_HEAD_LEN)
        return KM_ERR_FORMAT;

    /* 管理头 len = 8 + TLV，须与载荷区长度一致（载荷区不含填充/CRC） */
    payload_len = in_len - sizeof(STU_TLV_FPGA_HEAD) - mh.fpga_head.padding_len
                  - KM_FRAME_CRC_LEN;
    if ((size_t)mh.len != payload_len)
        return KM_ERR_FORMAT;

    /* sender/receiver 允许双向：管理服务(KM_SENDER_MNG=0) 与 KM(KM_SENDER_KM=4) 互发 */
    if (mh.sender != KM_SENDER_MNG && mh.sender != KM_SENDER_KM)
        return KM_ERR_FORMAT;
    if (mh.receiver != KM_SENDER_MNG && mh.receiver != KM_SENDER_KM)
        return KM_ERR_FORMAT;
    {
        /* msg_cmd 2B 小端读取；msg_id 任意 0~255 均合法，匹配语义由调用方负责 */
        uint16_t cmd = load_le16(mh.msg_cmd);
        if (cmd == 0 || cmd >= (uint16_t)SYSMNG_MSG_TYPE_MAX)
            return KM_ERR_FORMAT;
    }

    if (mng != NULL)
        *mng = (const STU_TLV_MNG_HEAD *)(const void *)in;
    *mng_len = mh.len;
    return KM_ERR_OK;
}

/* 判断 fpga_parse 结果是否为管理通道消息：
 * msg_type（FPGA_MSGTYPE）：toSYSMNG（密码管理->管理服务）上行 /
 * fromSYSMNG（管理服务->密码管理）下行。
 * 协议层分发与应用层收帧入口（msg_dispatch）共用，保证"管理通道"定义只维护一处。 */
int km_fpga_is_mng_type(const STU_TLV_FPGA_HEAD *head)
{
    STU_TLV_FPGA_HEAD fh;

    if (head == NULL)
        return 0;
    memcpy(&fh, head, sizeof(fh)); /* head 可能指向非对齐输入帧，memcpy 读取 */
    return (fh.msg_type == FPGA_MSGTYPE_toSYSMNG ||
            fh.msg_type == FPGA_MSGTYPE_fromSYSMNG);
}

/* 协议层分发：fpga_parse 后按 msg_type（FPGA_MSGTYPE）分流到子处理。
 * 管理通道 → km_mng_parse 检查管理头后回调 handler(frame, mng_len, ctx)；
 * 其余（含预留的 fromFPGA 算法自检回复与未知类型）→ KM_ERR_NOT_SUPPORTED（协议层无子解析器）。
 * 注意：本函数不区分"预留类型"与"未知类型"——应用层收帧入口（msg_dispatch）
 * 须自行区分：预留通道（msg_type=FPGA_MSGTYPE_fromFPGA）返回 KM_ERR_RESERVED 并记录说明日志，
 * 未知类型返回 KM_ERR_NOT_SUPPORTED。 */
km_err_t km_frame_dispatch(const uint8_t *in, size_t in_len,
                           km_mng_handler_t handler, void *ctx)
{
    const STU_TLV_FPGA_HEAD *head = NULL;
    uint16_t mng_len = 0;
    km_err_t err;

    err = km_fpga_parse(in, in_len, &head);
    if (err != KM_ERR_OK)
        return err;

    if (!km_fpga_is_mng_type(head))
        return KM_ERR_NOT_SUPPORTED; /* 非管理通道：预留 fromFPGA / 未知类型 */

    err = km_mng_parse(in, in_len, NULL, &mng_len);
    if (err != KM_ERR_OK)
        return err;
    if (handler != NULL)
        return handler(in, mng_len, ctx);
    return KM_ERR_OK;
}

/* 组管理帧核心：FPGA 头 + 管理头（msg_id 显式给定）+ TLV + 填充 [+ CRC32]；
 * 帧头恒为统一 FPGA 版本：head=0x5a5a、msg_type=toSYSMNG（密码管理->管理服务）；
 * sender=KM、receiver=管理服务；msg_cmd 按 2B 小端写入；
 * 整帧 8 字节对齐且不低于 64B，尾部填充字节值 = padding_len；
 * *out_len 入为容量出为总长。
 * 头部用局部 STU_TLV_MNG_HEAD 填充后 memcpy 到输出（字段偏移由编译器保证）。 */
static km_err_t mng_frame_build(uint8_t *out, size_t *out_len,
                                uint16_t msg_cmd, uint8_t msg_id,
                                const uint8_t *tlv, size_t tlv_len)
{
    size_t data_len, total;
    uint8_t padding_len;
    uint16_t mng_len, pkt_len;
    STU_TLV_MNG_HEAD h;
    uint8_t *p;

    if (out == NULL || out_len == NULL)
        return KM_ERR_BAD_PARAM;
    if (msg_cmd == 0 || msg_cmd >= (uint16_t)SYSMNG_MSG_TYPE_MAX)
        return KM_ERR_BAD_PARAM;
    if (tlv_len > KM_TLV_VALUE_MAX)
        return KM_ERR_BUF_TOO_SMALL;

    mng_len = (uint16_t)(KM_MNG_HEAD_LEN + tlv_len); /* 含 0x68 头及 data */
    data_len = sizeof(STU_TLV_MNG_HEAD) + tlv_len;   /* 不含填充与 CRC */

    /* 整帧（含 CRC32）8 字节对齐，且不低于最短帧长 */
    total = data_len + KM_FRAME_CRC_LEN;
    total = (total + KM_FRAME_ALIGN - 1) & ~(size_t)(KM_FRAME_ALIGN - 1);
    if (total < KM_FRAME_MIN_LEN)
        total = KM_FRAME_MIN_LEN;
    if (total > KM_FRAME_MAX_LEN)
        return KM_ERR_BUF_TOO_SMALL;
    if (total > *out_len)
        return KM_ERR_BUF_TOO_SMALL;

    padding_len = (uint8_t)(total - data_len - KM_FRAME_CRC_LEN);
    pkt_len = (uint16_t)(mng_len + padding_len); /* 报文长度含填充 */

    memset(&h, 0, sizeof(h));
    h.fpga_head.head = KM_FPGA_TLV_HEAD;           /* 0x5a5a */
    h.fpga_head.msg_type = FPGA_MSGTYPE_toSYSMNG;  /* 密码管理->管理服务 */
    h.fpga_head.padding_len = padding_len;
    h.fpga_head.pkt_len = pkt_len;
    h.head = KM_MNG_HEAD_MAGIC;
    h.len = mng_len;
    h.msg_id = msg_id;
    h.sender = KM_SENDER_KM;    /* 发送方：密码管理模块 */
    h.receiver = KM_SENDER_MNG; /* 接收方：管理服务 */
    store_le16(h.msg_cmd, msg_cmd);
    memcpy(out, &h, sizeof(h));

    p = out + sizeof(STU_TLV_MNG_HEAD);
    if (tlv_len > 0 && tlv != NULL) {
        memcpy(p, tlv, tlv_len);
        p += tlv_len;
    }

    /* 尾部填充：填充字节值 = padding_len */
    if (padding_len > 0)
        memset(p, padding_len, padding_len);
    p += padding_len;

#if KM_FRAME_CRC_ENABLE
    {
        uint32_t crc = km_crc32(0xFFFFFFFFu, out, (size_t)(p - out));
        p[0] = (uint8_t)(crc >> 24);
        p[1] = (uint8_t)(crc >> 16);
        p[2] = (uint8_t)(crc >> 8);
        p[3] = (uint8_t)crc;
        p += 4;
    }
#endif

    *out_len = total;
    return KM_ERR_OK;
}

/* KM 主动发送：msg_id 发送前自动自增 1（uint8 0~255 回绕），本次 id 经 tx_msg_id 输出。
 * 注意：自增计数器为模块级状态，须由单写者（定时线程/启动期）调用；
 * 应答路径请走 km_mng_frame_encode_reply（回显，不触碰计数器）。 */
km_err_t km_mng_frame_encode(uint8_t *out, size_t *out_len,
                             uint16_t msg_cmd,
                             const uint8_t *tlv, size_t tlv_len,
                             uint8_t *tx_msg_id)
{
    uint8_t id;

    if (out == NULL || out_len == NULL)
        return KM_ERR_BAD_PARAM;
    if (msg_cmd == 0 || msg_cmd >= (uint16_t)SYSMNG_MSG_TYPE_MAX)
        return KM_ERR_BAD_PARAM;

    g_tx_msg_id = (uint8_t)(g_tx_msg_id + 1); /* 发送前自增，0~255 回绕 */
    id = g_tx_msg_id;
    if (tx_msg_id != NULL)
        *tx_msg_id = id;

    return mng_frame_build(out, out_len, msg_cmd, id, tlv, tlv_len);
}

/* 应答对方发起的管理消息：msg_id 回显请求帧 id，不自增、不登记。 */
km_err_t km_mng_frame_encode_reply(uint8_t *out, size_t *out_len,
                                   uint16_t msg_cmd, uint8_t req_msg_id,
                                   const uint8_t *tlv, size_t tlv_len)
{
    if (out == NULL || out_len == NULL)
        return KM_ERR_BAD_PARAM;
    if (msg_cmd == 0 || msg_cmd >= (uint16_t)SYSMNG_MSG_TYPE_MAX)
        return KM_ERR_BAD_PARAM;

    return mng_frame_build(out, out_len, msg_cmd, req_msg_id, tlv, tlv_len);
}

/* 向 TLV 缓冲区末尾追加一个 TLV 单元（tag + 2B 大端长度 + 值） */
km_err_t km_tlv_append(uint8_t *buf, size_t cap, size_t *len,
                       uint8_t tag, const void *value, size_t vlen)
{
    size_t need;

    if (buf == NULL || len == NULL)
        return KM_ERR_BAD_PARAM;
    if (vlen > KM_TLV_VALUE_MAX)
        return KM_ERR_BUF_TOO_SMALL;

    need = 3 + vlen;
    if (*len + need > cap)
        return KM_ERR_BUF_TOO_SMALL;

    buf[*len] = tag;
    store_be16(buf + *len + 1, (uint16_t)vlen);
    if (vlen > 0 && value != NULL)
        memcpy(buf + *len + 3, value, vlen);
    *len += need;
    return KM_ERR_OK;
}

/* 顺序遍历 TLV 块：从 offset 处取出下一个单元并推进 offset（可用于迭代） */
km_err_t km_tlv_next(const uint8_t *tlv, size_t tlv_len, size_t *offset,
                     uint8_t *tag, const uint8_t **value, size_t *vlen)
{
    size_t o;
    uint16_t l;

    if (tlv == NULL || offset == NULL)
        return KM_ERR_BAD_PARAM;
    o = *offset;
    if (o >= tlv_len)
        return KM_ERR_FORMAT;
    if (tlv_len - o < 3)
        return KM_ERR_FORMAT;

    l = load_be16(tlv + o + 1);
    if (tlv_len - o - 3 < l)
        return KM_ERR_FORMAT;

    if (tag)   *tag = tlv[o];
    if (value) *value = tlv + o + 3;
    if (vlen)  *vlen = l;
    *offset = o + 3 + l;
    return KM_ERR_OK;
}
