#ifndef KM_TYPES_H
#define KM_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 版本号 ---------- */
#define KM_VERSION_MAJOR 0
#define KM_VERSION_MINOR 1
#define KM_VERSION_PATCH 0

#define KM_VERSION_STR "0.1.0"

/* ---------- 公共常量 ---------- */
#define KM_KEY_ID_LEN       32      /* 密钥标识长度 */
#define KM_MAX_MSG_LEN      4096    /* 管理消息最大长度 */
#define KM_DEFAULT_HEARTBEAT_SEC 30 /* 默认心跳周期（秒） */
#define KM_SM2_PUBKEY_LEN   64      /* SM2 公钥长度 (x||y) */
#define KM_SM2_PRIKEY_LEN   32      /* SM2 私钥长度 */
#define KM_SM2_SIG_LEN      64      /* SM2 签名长度 (r||s) */
#define KM_SM3_DIGEST_LEN   32      /* SM3 摘要长度 */
#define KM_SM4_KEY_LEN      16      /* SM4 密钥长度 */
#define KM_SM4_BLOCK_LEN    16      /* SM4 分组长度 */

/* ---------- 管理消息类型（线格式取值，管理头 msg_cmd 字段 2B 小端） ----------
 * 请求/应答不再用独立类型区分，方向由管理消息头的 sender/receiver 表达。
 * 应用层 switch/case 使用枚举常量；改值必须收发两端（管理服务/FPGA）同步。
 */
typedef enum {
    SYSMNG_MSG_TYPE_UNKNOWN          = 0x00, /* 无效命令 */
    SYSMNG_MSG_TYPE_HEARTBEAT        = 0x01, /* 心跳（双向） */
    SYSMNG_MSG_TYPE_SET_CACERT       = 0x02, /* 根证书导入 */
    SYSMNG_MSG_TYPE_SET_DEVCERT      = 0x03, /* 设备证书导入 */
    SYSMNG_MSG_TYPE_STATUS_REQ       = 0x04, /* 状态查询/上报 */
    SYSMNG_MSG_TYPE_SELFTEST_RSP     = 0x05, /* 定时自检结果上报（KM 主动上报：1=正常 0=故障） */
    SYSMNG_MSG_TYPE_AUDIT_LOG_REPORT = 0x06, /* 审计日志上报 */
    SYSMNG_MSG_TYPE_MAX              = 0xFFFF, /* 命令范围上限（线格式 2B 小端：拒绝 0 与 >=0xFFFF） */
} sysmng_msg_type_t;

/* ---------- 心跳上报载荷（KM 上行发给管理服务，SYSMNG_MSG_TYPE_HEARTBEAT 的 TLV 0x01 值） ----------
 * 与对端共享的线格式结构体：单字节对齐（pack(1)），字段顺序/宽度固定，主机小端。
 * 内容可扩展：新增字段一律追加到结构体尾部，收发两端同步升级（当前共 5B）。
 *   +0  uptime_sec : 4B 小端  软件已运行时间（单位：秒）
 *   +4  run_state  : 1B       软件运行状态（km_run_state_t）
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t uptime_sec;  /* 软件已运行时间（秒，小端） */
    uint8_t  run_state;   /* 软件运行状态，取值见 km_run_state_t */
} km_heartbeat_payload_t;
#pragma pack(pop)

/* 软件运行状态（心跳载荷 run_state 字段取值）：0x01=运行正常，0xE0 段=自检故障，可扩展 */
typedef enum {
    KM_RUN_STATE_BOOT_OK   = 0x01, /* 完成开机自检（运行正常） */
    KM_RUN_STATE_RNG_FAIL  = 0xE0, /* 随机数自检失败 */
    KM_RUN_STATE_FPGA_FAIL = 0xE1, /* FPGA 算法自检失败 */
    KM_RUN_STATE_CARD_FAIL = 0xE2, /* 密码卡自检失败 */
    KM_RUN_STATE_STARTING  = 0xFF, /* 软件启动 */
} km_run_state_t;

/* 心跳上行载荷 TLV 标签：value = km_heartbeat_payload_t */
#define KM_TLV_TAG_HEARTBEAT 0x01
/* 心跳上行载荷当前字节数（= sizeof(km_heartbeat_payload_t)，供对端/测试校验） */
#define KM_HEARTBEAT_PAYLOAD_LEN ((uint16_t)sizeof(km_heartbeat_payload_t))

/* 载荷为单字节对齐的定长线格式：字段偏移与总长必须固定（对端按此解析） */
_Static_assert(sizeof(km_heartbeat_payload_t) == 5, "heartbeat payload must be 5B");
_Static_assert(offsetof(km_heartbeat_payload_t, uptime_sec) == 0, "uptime_sec @0");
_Static_assert(offsetof(km_heartbeat_payload_t, run_state) == 4, "run_state @4");

/* ---------- 审计事件类型 ---------- */
typedef enum {
    EVT_DEVICE_INIT_START = 1,
    EVT_DEVICE_INIT_OK,
    EVT_DEVICE_INIT_FAIL,
    EVT_KEY_GENERATED,
    EVT_CERT_IMPORTED,
    EVT_SELFTEST_RESULT,
    EVT_HEARTBEAT_LOST,   /* 心跳链路丢失告警（连续丢失达到阈值） */
} km_audit_event_t;

/* ---------- 密钥类型 ---------- */
typedef enum {
    KEY_TYPE_ROOT = 0,
    KEY_TYPE_SIGN = 1,
    KEY_TYPE_ENC  = 2,
} key_type_t;

#ifdef __cplusplus
}
#endif

#endif /* KM_TYPES_H */
