#ifndef KM_MGMT_PROTOCOL_H
#define KM_MGMT_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "km_error.h"
#include "km_types.h"
#include "km_env.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 管理帧格式（FPGA 头 + 管理头 + TLV + 填充 + CRC32） ----------
 * 帧头全局唯一（统一 FPGA 帧头 STU_TLV_FPGA_HEAD，8B）：
 *   [FPGA 头: head(2B, 0x5a5a) | msg_type(2B 小端, FPGA_MSGTYPE 方向/通道)
 *             | reserve(1B) | padding_len(1B) | pkt_len(2B 小端)] = 8B
 *   [管理头: 0x68(1B) | len(2B 小端 含0x68头及data) | msg_id(1B) | sender(1B) | receiver(1B)
 *             | msg_cmd(2B 小端)] = 8B
 *   [TLV 数据][padding][crc32:4B]
 */

#define KM_MNG_HEAD_MAGIC     0x68        /* 管理类消息头 */
#define KM_MNG_HEAD_LEN       8           /* 管理头长（0x68|len|msg_id|sender|receiver|msg_cmd 2B） */

/* 统一 FPGA 帧头 magic：head 字段取值（2B 小端，线格式字节 0x5A 0x5A）；
 * 帧头长度 KM_FPGA_HEAD_LEN 定义于 STU_TLV_FPGA_HEAD 结构体之后（= sizeof）。 */
#define KM_FPGA_TLV_HEAD      0x5a5a

/* CRC32 校验开关：1=编解码均计算/校验；0=跳过（默认）。
 * 注意：收发两端宏配置必须一致，且编码端只在启用时追加 4B CRC 尾。 */
#define KM_FRAME_CRC_ENABLE   0
#if KM_FRAME_CRC_ENABLE
#define KM_FRAME_CRC_LEN      4
#else
#define KM_FRAME_CRC_LEN      0
#endif
#define KM_FRAME_ALIGN        8     /* 整帧 8 字节对齐 */
#define KM_FRAME_MIN_LEN      64    /* 最短帧长（GMAC 最小传输要求） */
#define KM_FRAME_MAX_LEN      4096 /* 最长帧长（管理通道上限 4096B，含帧头） */
#define KM_TLV_TAG_MAX        0xFF
#define KM_TLV_VALUE_MAX      4000 /* 单个 TLV value 上限 */
#define KM_MNG_DATA_MAX       4000 /* 管理消息 TLV 数据总长上限 */

/* 管理消息 sender/receiver 取值 */
#define KM_SENDER_MNG  0   /* 管理服务 */
#define KM_SENDER_KM   4   /* 密码管理模块 */

/* 证书数据域（SET_CACERT / SET_DEVCERT，位于管理头 data 区，即 TLV 载荷内），
 * 线格式采用"证书项循环"，一条消息可携带多个证书：
 *   SET_CACERT（根证书导入）：
 *     data 区 = 证书项循环，每项：
 *       [名称长度:1B][名称 xxx.pem][内容长度:2B 小端][内容 PEM]
 *   SET_DEVCERT（设备证书导入）：在证书项循环前多 1B 证书类型：
 *     [证书类型:1B（1=签名证书 2=加密证书）]
 *     data 区 = 证书项循环，每项同上。
 * 名称与证书内容均写入 ./certs/，并更新 certlist.json（输出记录）。
 * 设备证书导入时校验公钥与密码卡内部密钥对匹配，记录 key_index：
 *   签名证书 key_index = k（从 1 起，步长 2）；加密证书 key_index = 签名 key_index + 1。 */
#define KM_CERT_TYPE_PEM       0x01  /* 证书内容类型：PEM（当前仅支持；DER 预留） */
#define KM_CERT_USE_SIGN       0x01  /* 设备证书用途：签名证书 */
#define KM_CERT_USE_ENC        0x02  /* 设备证书用途：加密证书 */
#define KM_CERT_NAME_MAX       255   /* 证书文件名长度上限（1B 字段） */


/* ---------- 接收/发送分层（不使用 km_frame_t / km_fpga_info_t / km_mng_msg_t） ----------
 * 接收路径分层：
 *   ① km_fpga_parse  最外层：仅检查 FPGA 头（magic、总长/对齐、pkt_len、padding、CRC），
 *                    输出指向帧内头的零拷贝视图（STU_TLV_FPGA_HEAD）
 *   ② km_msg_handle  应用层唯一收帧入口（src/app/msg_dispatch.c）：km_fpga_parse 后
 *                    按 msg_type(FPGA_MSGTYPE) 分流——管理通道→km_mng_parse→km_mng_handle_message；
 *                    预留 fromFPGA→KM_ERR_RESERVED（记说明日志）；未知类型→KM_ERR_NOT_SUPPORTED（记告警）
 *   （协议层 km_frame_dispatch 为同逻辑的纯协议版本，供测试与无应用日志场景使用）
 *   ③ km_mng_parse   管理子处理：检查管理头（0x68、len、sender/receiver、msg_cmd、TLV 边界），
 *                    输出指向帧首的 STU_TLV_MNG_HEAD 视图与管理消息长度
 * 发送路径：km_mng_frame_encode 直接组帧（FPGA 头 + 管理头 + TLV + 填充 + CRC）
 * 约定：任何管理帧整体即 1 条 STU_TLV_MNG_HEAD（16B 定长头，帧首即其视图起点）+ 变长 TLV + 填充；
 *       TLV 起点 = frame + sizeof(STU_TLV_MNG_HEAD)（16），TLV 长度 = 管理消息长度 - KM_MNG_HEAD_LEN（8）；
 *       派生量（载荷偏移/长度等）一律由头内 len/pkt_len/padding_len 字段自描述，不再设镜像结构。 */


/* FPGA 报文头结构体（pack(1)：结构体即线格式，主机小端前提，sizeof == 8B）。
 * head 固定 KM_FPGA_TLV_HEAD(0x5a5a)；msg_type 取 FPGA_MSGTYPE，接收分流按该字段。 */
#pragma pack(push, 1)
typedef struct struct_tlv_FPGA_head {
    uint16_t head;                  //固定FPGA报文头，0x5a5a
    uint16_t msg_type;              //消息类型（FPGA_MSGTYPE 取值，方向/通道）
    uint8_t reserve;                //保留字节
    uint8_t padding_len;            //填充长度（填充字节值 = padding_len）
    uint16_t pkt_len;               //报文总长度，含头及padding及校验码（若有）
}STU_TLV_FPGA_HEAD;                 /* 8B */
#pragma pack(pop)
#define KM_FPGA_HEAD_LEN sizeof(STU_TLV_FPGA_HEAD) /* == 8（见下 static assert） */
_Static_assert(sizeof(STU_TLV_FPGA_HEAD) == 8,
               "STU_TLV_FPGA_HEAD size mismatch with wire format");

/* FPGA 消息类型（msg_type 字段取值，2B 小端；标识帧方向/收发通道） */
typedef enum {
    FPGA_MSGTYPE_toSYSMNG = 0x3131,     //KM->SYSMNG
    FPGA_MSGTYPE_fromSYSMNG = 0x1231,   //SYSMNG->KM
    FPGA_MSGTYPE_toFPGA = 0x3a24,       //KM->FPGA
    FPGA_MSGTYPE_fromFPGA = 0xa324,     //FPGA->KM
}FPGA_MSGTYPE;

/* 管理消息头结构：结构体即线格式（pack(1) + 固定宽度字段），
 * sizeof(STU_TLV_MNG_HEAD) == 帧头总长（FPGA 头 8B + 管理头 8B），data 紧随其后。
 * 前提：主机小端（x86/x64），字段顺序与线格式严格一致。
 * 命令枚举（msg_cmd 2B 小端取值）见 km_types.h 的 sysmng_msg_type_t。 */

#pragma pack(push, 1)
typedef struct struct_tlv_mng {
    STU_TLV_FPGA_HEAD fpga_head;  /* FPGA 帧头 */
    uint8_t  head;      /* 管理类消息头，0x68 */
    uint16_t len;       /* 管理消息长度（含0x68头及data = 8 + TLV 长度） */
    uint8_t  msg_id;    /* 管理消息id：KM 主动发送自增1（0~255 回绕）；应答回显请求 id */
    uint8_t  sender;    /* 发送方：管理服务 0，KM 4 */
    uint8_t  receiver;  /* 接收方：管理服务 0，KM 4 */
    uint8_t  msg_cmd[2];   /* 管理消息命令（sysmng_msg_type_t 值，2B 小端） */
    uint8_t  data[0];   /* TLV 数据（pack 后偏移即线格式 TLV 起始） */
} STU_TLV_MNG_HEAD;                 /* 8 + 8 = 16B */
#pragma pack(pop)
_Static_assert(sizeof(STU_TLV_MNG_HEAD) == KM_FPGA_HEAD_LEN + KM_MNG_HEAD_LEN,
               "STU_TLV_MNG_HEAD size mismatch with wire format");

/* 管理消息处理回调：分发入口完成 fpga_parse/mng_parse 校验后调用。
 * frame 指向整帧首（即 STU_TLV_MNG_HEAD 视图起点，含 FPGA 头 8B + 管理头 8B）；
 * mng_len = 管理消息长度（头内 len 字段 = 8 + TLV，mng_parse 已校验与帧载荷一致）。
 * 字段读取沿用 STU_TLV_*_HEAD memcpy 到局部结构体（pack(1)，frame 可能非对齐）。 */
typedef km_err_t (*km_mng_handler_t)(const uint8_t *frame, uint16_t mng_len, void *ctx);


/**
 * @brief 最外层解析：仅检查 FPGA 帧头（magic 0x5a5a、总长范围 64~4096 / 8 字节对齐、
 * pkt_len/padding_len 一致性、填充内容；CRC32 由 KM_FRAME_CRC_ENABLE 控制）。
 * 不解析任何管理头/子类型头——子类型头检查在各子处理中进行。
 * @param in     输入帧数据
 * @param in_len 输入长度
 * @param head   输出：指向帧内 FPGA 头视图的零拷贝指针（仅在 in 有效期内有效；可传 NULL 纯校验）
 * @return km_err_t
 */
km_err_t km_fpga_parse(const uint8_t *in, size_t in_len,
                       const STU_TLV_FPGA_HEAD **head);

/**
 * @brief 判断帧的 msg_type（FPGA_MSGTYPE）是否为管理通道（km_fpga_parse 输出的 head 视图）。
 * 管理通道 = SYSMNG 双向：fromSYSMNG（管理服务->密码管理，下行）/ toSYSMNG（密码管理->管理服务，上行）。
 * 协议层分发与应用层收帧入口（msg_dispatch）共用此定义。
 * @param head km_fpga_parse 输出的帧头视图
 * @return 1=管理通道，0=其他（含预留 fromFPGA 算法自检 / 未知类型）
 */
int km_fpga_is_mng_type(const STU_TLV_FPGA_HEAD *head);

/**
 * @brief 协议层分发：km_fpga_parse 后按 msg_type（FPGA_MSGTYPE）分流到子处理。
 * 管理通道 → 内部再调 km_mng_parse 检查管理头后回调 handler(frame, mng_len, ctx)；
 * 其余（含预留 fromFPGA 算法自检 / 未知类型）→ 返回 KM_ERR_NOT_SUPPORTED（协议层无子解析器）。
 * 注意：协议层不区分"预留/未知"，区分由应用层收帧入口 msg_dispatch 负责
 * （预留→KM_ERR_RESERVED 记说明日志；未知→KM_ERR_NOT_SUPPORTED 记告警）。
 * @param in      输入帧数据
 * @param in_len  输入长度
 * @param handler 管理消息处理回调（可为 NULL，此时仅做协议校验）
 * @param ctx     透传上下文
 * @return km_err_t
 */
km_err_t km_frame_dispatch(const uint8_t *in, size_t in_len,
                           km_mng_handler_t handler, void *ctx);

/**
 * @brief 管理子处理：检查管理头（0x68 magic、len、sender/receiver、msg_cmd 范围、
 * len/帧长/padding 一致性），输出指向帧首的 STU_TLV_MNG_HEAD 视图与管理消息长度。
 * 须在 km_fpga_parse 成功之后调用（帧头已校验，帧内字段可直接按 FPGA 帧布局读取）。
 * msg_cmd 按 2B 小端读取，校验 0 与 >= SYSMNG_MSG_TYPE_MAX（0xFFFF）为非法；
 * msg_id 任意取值（0~255）均合法，匹配语义由调用方按命令/方向决定。
 * @param in      输入帧数据
 * @param in_len  输入长度
 * @param mng     输出：指向帧首的管理消息视图（零拷贝；可传 NULL）
 * @param mng_len 输出：管理消息长度（= 头内 len 字段 = 8 + TLV）
 * @return km_err_t
 */
km_err_t km_mng_parse(const uint8_t *in, size_t in_len,
                      const STU_TLV_MNG_HEAD **mng, uint16_t *mng_len);

/**
 * @brief 组管理帧并编码（FPGA 头 + 管理头 + TLV + 填充 [+ CRC32]）——KM 主动发送。
 * 帧头恒为统一 FPGA 版本（head=0x5a5a，8B）；msg_type=toSYSMNG（密码管理->管理服务）、
 * sender=KM(4)、receiver=管理服务(0)。
 * 管理头 msg_id：发送前自动自增 1（0~255 回绕，首帧=1），本次取值经 tx_msg_id 输出
 * （可为 NULL）；发送方可登记该 id 作为期望，待对端同 cmd 回显时校验确认。
 * 整帧（含 CRC32）8 字节对齐且不低于 64B：尾部自动填充，填充字节值 = padding_len，
 * padding_len 写入帧头；pkt_len = len + padding_len。
 * @param msg_cmd   管理消息命令（sysmng_msg_type_t 值，2B 小端写入；0 与 >=0xFFFF 拒绝）
 * @param tlv       TLV 载荷（可 NULL）
 * @param tlv_len   TLV 载荷长度
 * @param tx_msg_id 输出：本次分配的管理消息 id（可传 NULL 忽略）
 * @param out       输出编码缓冲区
 * @param out_len   输入缓冲区大小 / 输出实际长度
 * @return km_err_t
 */
km_err_t km_mng_frame_encode(uint8_t *out, size_t *out_len,
                             uint16_t msg_cmd,
                             const uint8_t *tlv, size_t tlv_len,
                             uint8_t *tx_msg_id);

/**
 * @brief 组管理帧并编码（同 km_mng_frame_encode）——应答对方发起的管理消息。
 * 与 encode 的唯一区别：msg_id 回显请求帧的 msg_id（req_msg_id），
 * 不触碰主动发送的自增计数器、不登记期望。
 * @param msg_cmd    管理消息命令（同被应答请求的 cmd，2B 小端写入）
 * @param req_msg_id 被应答请求帧的 msg_id（回显）
 * @param tlv        TLV 载荷（可 NULL）
 * @param tlv_len    TLV 载荷长度
 * @param out        输出编码缓冲区
 * @param out_len    输入缓冲区大小 / 输出实际长度
 * @return km_err_t
 */
km_err_t km_mng_frame_encode_reply(uint8_t *out, size_t *out_len,
                                   uint16_t msg_cmd, uint8_t req_msg_id,
                                   const uint8_t *tlv, size_t tlv_len);

/**
 * @brief 复位主动发送的 msg_id 自增计数器（下次 encode 从 1 重新开始）。
 * 仅供测试与进程级重新初始化场景使用；运行期主动发送须保持单调（0~255 回绕）。
 */
void km_mng_reset_msg_id(void);

/** @brief 计算 CRC32（多段调用支持） */
uint32_t km_crc32(uint32_t crc, const uint8_t *data, size_t len);

/* ---------- TLV 单元辅助 ---------- */

/**
 * @brief 向 TLV 列表追加一个单元 [tag:1B][len:2B BE][value]
 * @param buf   目标缓冲区
 * @param cap   缓冲区容量
 * @param len   输入当前长度 / 输出新长度
 * @param tag   标签
 * @param value 值
 * @param vlen  值长度
 */
km_err_t km_tlv_append(uint8_t *buf, size_t cap, size_t *len,
                       uint8_t tag, const void *value, size_t vlen);

/**
 * @brief 顺序解析 TLV 单元
 * @param tlv    TLV 列表
 * @param tlv_len TLV 列表长度
 * @param offset 输入当前偏移 / 输出下一偏移
 * @param tag    输出标签
 * @param value  输出值指针（指向 tlv 内部）
 * @param vlen   输出值长度
 * @return KM_ERR_OK 成功；KM_ERR_FORMAT 结束或格式错误
 */
km_err_t km_tlv_next(const uint8_t *tlv, size_t tlv_len, size_t *offset,
                     uint8_t *tag, const uint8_t **value, size_t *vlen);

#ifdef __cplusplus
}
#endif

#endif /* KM_MGMT_PROTOCOL_H */
