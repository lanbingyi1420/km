# KM 密钥管理软件 · API 规范（第一阶段）

> 目标平台：E2000Q（ARM64）+ Linux；Windows（MinGW/MSVC）可编译、可单测。
> 语言：C11（C99 兼容子集），零第三方依赖（SM2/SM3/SM4 为自研实现）。

## 1. 公共头与错误码

公共接口统一由 `include/km_api.h` 聚合导出，头文件按模块拆分：

| 头文件 | 内容 |
|---|---|
| `km_types.h` | 基础类型：`key_type_t`、管理消息类型、心跳载荷 `km_heartbeat_payload_t` 与运行状态 `km_run_state_t`、审计事件枚举、版本、常量 |
| `km_error.h` | 错误码 `km_err_t` 与 `km_err_str()` |
| `km_device.h` | 设备初始化 / 自检 / 状态上报 |
| `km_key.h` | 密钥创建 / CSR 导出 |
| `km_cert.h` | 根证书 / 设备证书导入 |
| `km_log.h` | 运维日志 / 审计日志 |
| `km_config.h` | 配置结构体与加载接口（内部使用） |

错误码约定（节选）：

| 码 | 值 | 含义 |
|---|---|---|
| `KM_ERR_OK` | 0 | 成功 |
| `KM_ERR_INIT_FAIL` | -1 | 初始化失败 |
| `KM_ERR_SELFTEST_FAIL` | -2 | 自检失败 |
| `KM_ERR_COMM_FAIL` | -3 | 通信失败 |
| `KM_ERR_CERT_INVALID` | -4 | 证书非法 / 验签失败 |
| `KM_ERR_BAD_PARAM` | -5 | 参数错误 |
| `KM_ERR_CRYPTO` | -7 | 密码运算失败 |
| `KM_ERR_KEY_NOT_FOUND` | -8 | 密钥不存在 |
| `KM_ERR_FILE` | -9 | 文件读写失败 |
| `KM_ERR_ALREADY_INIT` | -10 | 重复初始化 |
| `KM_ERR_NOT_SUPPORTED` | -11 | 不支持（未知 msg_type 等） |
| `KM_ERR_BUF_TOO_SMALL` | -12 | 缓冲区不足 |
| `KM_ERR_FORMAT` | -13 | 数据格式错误（PEM/DER/帧） |
| `KM_ERR_RESERVED` | -14 | 预留通道消息（协议已定义未启用） |

## 2. 设备初始化

```c
km_err_t km_device_init(const char *conf_path);   // 七步启动链
void     km_device_deinit(void);
km_err_t km_crypto_selftest(void);                // 密码卡 KAT 自检
km_err_t km_fpga_selftest(void);                  // FPGA 自检（桩）
void     km_report_init_status(km_err_t rc);      // 上报初始化状态（审计）
```

启动链：加载配置 → 初始化日志 → 初始化通信层（`km_comm_init`）→ 初始化 CryptoHAL → 算法自检 → FPGA 自检 → 状态上报。

## 3. 密钥管理

```c
typedef enum { KEY_TYPE_ROOT = 0, KEY_TYPE_SIGN = 1, KEY_TYPE_ENC = 2 } key_type_t;

km_err_t km_key_create(key_type_t type, char key_id[KM_KEY_ID_LEN]);   // 生成并加密落盘
km_err_t km_key_export_csr(const char *key_id, const char *subject,
                           char *csr_pem, size_t *csr_len);            // PKCS#10 DER + SM2 签名 → PEM
```

- `subject` 格式：`"CN=设备名,O=组织"`，支持 `CN/O/C/ST/L/OU`。
- CSR 编码：`CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm(sm2signWithSM3), signatureValue }`，签名对象为 `certificationRequestInfo` 完整 DER，公钥算法标识 `id-ecPublicKey` + 参数 `sm2p256v1(1.2.156.10197.1.301)`。

## 4. 证书导入与验证

```c
km_err_t km_cert_import_root(const char *cert_pem, size_t len);   // 信任锚：结构合法即存
km_err_t km_cert_import_device(const char *cert_pem, size_t len); // 验签链 + 有效期检查后存储
```

- 存储：`KM_CERT_DIR`（默认 `/opt/km/certs`）下 `root.crt` / `device.crt`（PEM 原文）。
- 解析（内部接口 `core/cert_validator.h`）：PEM 提取 → 最小 DER X.509 解析（subject/issuer/有效期/公钥）→ 有效期边界 → 根证书公钥验证设备证书 `tbsCertificate` 的 SM2 签名。

## 5. 日志系统

```c
typedef enum { LOG_LEVEL_DEBUG = 0, LOG_LEVEL_INFO = 1,
               LOG_LEVEL_WARN = 2, LOG_LEVEL_ERROR = 3 } log_level_t;

km_err_t km_log_init2(const char *oplog_dir, const char *audit_dir,
                      const km_oplog_cfg_t *cfg);   // cfg 可空（默认全开）
void     km_log_deinit(void);

/* 运维日志：底层 *_loc 函数携带调用点位置（文件/函数/行号），对外以宏提供 */
void km_oplog_write_loc(log_level_t lv, const char *file, const char *func,
                        int line, const char *fmt, ...);
void km_dbg_write_loc(const char *file, const char *func, int line,
                      const char *fmt, ...);
void km_dbg_hex_loc(const char *file, const char *func, int line,
                    const char *tag, const void *data, size_t len);

/* 对外宏：展开处自动填充 __FILE__ / __FUNCTION__ / __LINE__（参考 log.h 实现方式） */
#define KM_OPLOG_RECORD(level, fmt, ...)  /* 记录指定级别运维日志，携带调用点定位 */
#define km_oplog_write(level, fmt, ...)               // 等价于 KM_OPLOG_RECORD
#define km_log_debug/info/warn/error(fmt, ...)        // 分级便捷宏
#define km_dbg_write(fmt, ...)                        // DEBUG 级变参数字符串
#define km_dbg_hex(tag, data, len)                    // DEBUG 级数据域 hex

void     km_auditlog_write(km_audit_event_t ev, const char *detail); // 审计日志
void     km_auditlog_deinit(void);
```

运维日志的对外提供方式与 `log.h` 一致：**底层函数带 `file/func/line` 定位参数，对外以宏形式
暴露**，宏在调用点自动注入 `__FILE__/__FUNCTION__/__LINE__`，因此每条记录都携带定位信息。
日志行（文件记录与控制台后台打印一致）形如：

```
2026-09-11_14:20:28 [debug] {KM_log_demo.c_main_94}::heartbeat timer tick, interval=30s.
```

- 行首为时间戳 `YYYY-MM-DD_hh:mm:ss`，随后 `[level]`（debug/info/warn/error）
- `{KM_<file>_<func>_<line>}`：`file` 为调用点源文件基名，`func` 为函数名，`line` 为行号
- `::` 之后为日志正文（msg）

错误级别走 stderr，其余走 stdout；msg 中的换行/控制字符会被替换为空格，防止破坏行格式。

日志级别严重度递增（DEBUG < INFO < WARN < ERROR），低于配置级别的日志被丢弃；级别可由
配置文件 `log_level=debug|info|warn|error` 或命令行 `--log-level` 设置。

`km_dbg_hex` 将指定数据域按十六进制**整块**输出：
头行为 `<时间戳> [debug] {KM_<file>_<func>_<line>}::<tag>[<字节数>]:`，
其后每行 **16 字节**、每 8 字节以 ` | ` 分隔，行首为 **1 基**起始偏移（`%04d`，首行 `0001`），形如：

```
2026-09-11_14:20:28 [debug] {KM_log_demo.c_main_94}::hb-rx[32]:
0001: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
0017: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
```

运维日志配置 `km_oplog_cfg_t { level, console, to_file, file_max, file_count }`：
- `console`：是否打印后台；`to_file`：是否记录文件；`file_max`：单文件最大字节数；`file_count`：循环覆盖轮转份数（`.1`~`.N`）。
- 审计日志：内存环形缓冲 + 磁盘 append-only 队列（`[seq][ts][event_id][detail][crc32]`），上报成功推进水位。

## 6. 通信层

### MgmtProtocol 分层帧（不使用 km_frame_t / km_fpga_info_t / km_mng_msg_t）

帧格式（帧头全局唯一，统一 FPGA 帧头版本，8B + 8B）：
```
[FPGA 头 STU_TLV_FPGA_HEAD: 0x5a5a(2B) | msg_type:2B 小端(FPGA_MSGTYPE) | reserve:1B | padding_len:1B | pkt_len:2B 小端]  = 8B
[管理头: 0x68:1B | len:2B 小端 | msg_id:1B | sender:1B | receiver:1B | msg_cmd:2B 小端]                                  = 8B
[TLV 列表][padding(值 = padding_len)][crc32:4B，KM_FRAME_CRC_ENABLE 控制]
TLV: [tag:1B][len:2B BE][value]
```
- 帧内偏移（相对整帧首）：FPGA 头 8B：`head`@0-1、`msg_type`@2-3、`reserve`@4、`padding_len`@5、`pkt_len`@6-7；管理头起点@8：`0x68`@8、`len`@9-10、`msg_id`@11、`sender`@12、`receiver`@13、`msg_cmd`@14-15（小端低字节在前）；TLV 起点 = 16。
- 管理消息 id（`msg_id`）：1B，取值 0~255（0 非哨兵）。**KM 主动发送**（`km_mng_frame_encode`）发送前自动自增 1 并回绕（0→1→…→255→0，首帧=1），发送方可经 `tx_msg_id` 输出参数取得本次 id 以登记期望（如心跳）；**应答**（`km_mng_frame_encode_reply`）回显请求帧 `msg_id`，不自增、不登记。
- 线格式结构即线格式本身（pack(1)，小端）：整帧 = 1 条 `STU_TLV_MNG_HEAD`（16B 定长头，含内嵌 FPGA 头）+ 变长 TLV + 填充；
  TLV 起点 = `frame + sizeof(STU_TLV_MNG_HEAD)`（16），TLV 长度 = 管理消息长度 − `KM_MNG_HEAD_LEN`（8）；
  派生量（载荷偏移/长度）均由头内 `len`/`pkt_len`/`padding_len` 字段自描述，不再设镜像结构。
- 最外层 `km_fpga_parse` 仅检查 FPGA 头：识别 magic（0x5a5a）、总长/对齐、pkt_len/padding_len 一致性、填充内容、CRC（宏控），输出指向帧内头的零拷贝视图 `const STU_TLV_FPGA_HEAD *`。
- 应用层唯一收帧入口 `km_msg_handle`（`app/msg_dispatch.h`）按 `msg_type`（`FPGA_MSGTYPE`）分流：
  管理通道（`km_fpga_is_mng_type`：`FPGA_MSGTYPE_toSYSMNG` 0x3131 上行 / `FPGA_MSGTYPE_fromSYSMNG` 0x1231 下行）→ 管理子处理；
  预留通道（`FPGA_MSGTYPE_fromFPGA` 0xa324，FPGA 算法自检回复，未启用）→ `KM_ERR_RESERVED` + 说明日志；
  未知类型（其它 `msg_type`）→ `KM_ERR_NOT_SUPPORTED` + 告警日志。预留与未知**不同处理**，便于未来挂载 FPGA 自检异步化子处理。
- 协议层 `km_frame_dispatch` 为同逻辑的纯协议版本（管理通道 → 管理子处理 + 回调；其余统一 `KM_ERR_NOT_SUPPORTED`，供测试与无应用日志场景，不区分预留/未知）。
- 管理子处理 `km_mng_parse` 检查管理头：0x68、len、sender/receiver、msg_cmd（2B 小端，拒绝 0 与 ≥0xFFFF）、TLV 边界，输出指向帧首的管理消息视图 `const STU_TLV_MNG_HEAD *` 与管理消息长度（头内 len 字段，TLV 零拷贝定位）。
- 发送 `km_mng_frame_encode`（主动，自动自增 msg_id）/ `km_mng_frame_encode_reply`（应答，回显 msg_id）组帧：FPGA 头 + 管理头 + TLV + 填充 [+ CRC]，帧头恒为统一 FPGA 版本（head=0x5a5a、msg_type=toSYSMNG）。
- CRC32 开关 `KM_FRAME_CRC_ENABLE`（默认 0 关闭）：1=编解码均计算/校验；0=跳过且不追加 CRC 尾。

```c
/* 线格式结构（pack(1)，主机小端） */
#pragma pack(push, 1)
typedef struct struct_tlv_FPGA_head {
    uint16_t head;          /* 0x5a5a（2B 小端，线格式字节 0x5A 0x5A） */
    uint16_t msg_type;      /* FPGA_MSGTYPE：0x3131 toSYSMNG / 0x1231 fromSYSMNG / 0x3a24 toFPGA / 0xa324 fromFPGA */
    uint8_t reserve;
    uint8_t padding_len;    /* 填充长度（填充字节值 = padding_len） */
    uint16_t pkt_len;       /* 报文总长（len + padding_len，不含 FPGA 头） */
} STU_TLV_FPGA_HEAD;        /* 8B */

typedef struct struct_tlv_mng {
    STU_TLV_FPGA_HEAD fpga_head; /* FPGA 帧头 */
    uint8_t  head;        /* 0x68 */
    uint16_t len;         /* 管理消息长度（= 8 + TLV） */
    uint8_t  msg_id;      /* 管理消息 id：主动发送自增（0~255 回绕）；应答回显请求 id */
    uint8_t  sender;      /* 0=管理服务 4=KM */
    uint8_t  receiver;
    uint8_t  msg_cmd[2];  /* sysmng_msg_type_t 值（2B 小端：低字节在前） */
    uint8_t  data[0];     /* TLV 起点（pack 后偏移即线格式） */
} STU_TLV_MNG_HEAD;       /* 8 + 8 = 16B */
#pragma pack(pop)
/* sizeof(STU_TLV_FPGA_HEAD)==8，sizeof(STU_TLV_MNG_HEAD)==16（_Static_assert 校验） */

/* 管理消息处理回调：分发入口完成 fpga_parse/mng_parse 校验后调用。
 * frame 指向整帧首（即 STU_TLV_MNG_HEAD 视图起点）；mng_len = 管理消息长度（8 + TLV）。
 * 字段读取沿用 memcpy 到局部 STU_TLV_*_HEAD（frame 可能非对齐），TLV = frame + 16、长度 = mng_len - 8。 */
typedef km_err_t (*km_mng_handler_t)(const uint8_t *frame, uint16_t mng_len, void *ctx);

km_err_t km_fpga_parse(const uint8_t *in, size_t in_len,
                       const STU_TLV_FPGA_HEAD **head);   /* head 可 NULL（纯校验） */
int      km_fpga_is_mng_type(const STU_TLV_FPGA_HEAD *head); /* 1=管理通道（toSYSMNG/fromSYSMNG） */
km_err_t km_frame_dispatch(const uint8_t *in, size_t in_len,
                           km_mng_handler_t handler, void *ctx);
km_err_t km_mng_parse(const uint8_t *in, size_t in_len,
                      const STU_TLV_MNG_HEAD **mng, uint16_t *mng_len);
km_err_t km_mng_frame_encode(uint8_t *out, size_t *out_len,
                             uint16_t msg_cmd,
                             const uint8_t *tlv, size_t tlv_len,
                             uint8_t *tx_msg_id);   /* 可 NULL；输出本次自动分配 msg_id */
km_err_t km_mng_frame_encode_reply(uint8_t *out, size_t *out_len,
                                   uint16_t msg_cmd, uint8_t req_msg_id,
                                   const uint8_t *tlv, size_t tlv_len); /* 回显，不自增 */
void     km_mng_reset_msg_id(void);                 /* 复位自增计数器（测试/进程复位用） */
km_err_t km_tlv_append(uint8_t *buf, size_t cap, size_t *off,
                       uint8_t tag, const void *v, size_t n);
km_err_t km_tlv_next(const uint8_t *tlv, size_t tlv_len, size_t *off,
                     uint8_t *tag, const uint8_t **v, size_t *n);
```

消息类型（`km_types.h` 的 `sysmng_msg_type_t`，线格式 2B 小端，合法 1..0xFFFE）：
`HEARTBEAT 0x01`（双向）、`SET_CACERT 0x02`、`SET_DEVCERT 0x03`、`STATUS_REQ 0x04`（查询/上报）、`SELFTEST_RSP 0x05`（KM 定时自检上报）、`AUDIT_LOG_REPORT 0x06`；上限 `SYSMNG_MSG_TYPE_MAX = 0xFFFF`。

收帧入口与指令分发：

```c
km_err_t km_msg_handle(const uint8_t *frame, size_t len);      // app/msg_dispatch.h：总入口，最外层分流（管理/预留/未知）
km_err_t km_mng_handle_message(const uint8_t *frame, uint16_t mng_len); // app/cmd_handler.h：管理子处理（心跳/状态/证书导入）
```

- 职责划分：总入口只做 fpga_parse + 按 msg_type 分流；管理消息子处理收敛于 cmd_handler（不再承载最外层收帧）。
- 管理子处理/心跳回调统一收"整帧首指针 + 管理消息长度"（`(frame, mng_len)`），从 `STU_TLV_MNG_HEAD` 线格式读 `msg_cmd`（2B 小端）/`msg_id`/`sender/receiver`，TLV 由帧首偏移与 `mng_len` 推导。
- 期望语义：收到的管理消息按命令方向判定——"对方发起"的命令（STATUS_REQ/SET_CACERT/SET_DEVCERT 等）一律应答并**回显请求 msg_id**（`km_mng_frame_encode_reply`）；"本机主动"的类型（目前仅心跳）对端回复时做期望 id 鉴定（见心跳模块）。
- 错误码：预留通道（`FPGA_MSGTYPE_fromFPGA` 0xa324）→ `KM_ERR_RESERVED`（-14，记说明日志）；
  未知 msg_type → `KM_ERR_NOT_SUPPORTED`（-11，记告警日志）；两者**不同处理**。

应答 TLV：`0x01` 心跳上行载荷 `km_heartbeat_payload_t`（见心跳模块；`STATUS_REQ` 的 `0x01` 为状态字节）、`0x02` 结果码 int32（证书导入，0=成功）。

### 统一通信抽象（`comm/km_comm.h`）

```c
km_err_t km_comm_init(km_comm_path_t path, int gmac_mode);
void     km_comm_deinit(void);
km_err_t km_comm_send(const uint8_t *data, size_t len);
km_err_t km_comm_recv(uint8_t *buf, size_t cap, size_t *len); // 非阻塞
km_comm_path_t km_comm_path(void);

/* 多线程扩展 */
km_err_t km_comm_send_async(const uint8_t *data, size_t len); // 入发送队列；未启用线程时退化为同步 send
void     km_comm_worker(void *arg);                          // 通信线程：recv→收帧队列；发送队列→send
void     km_comm_worker_stop(void);
km_err_t km_comm_frame_pop(uint8_t *buf, size_t cap, size_t *len); // 业务线程取一帧（非阻塞）
```

- 正式通路 `COMM_PATH_FORMAL`：自定义协议 + GMAC 经 FPGA 转发给 D3000M。
- 模拟通路 `COMM_PATH_SIMULATION`：内存消息队列（`sim_comm`），供单板模拟环境测试。
- 切换方式：`km.conf` 的 `comm_path` 或环境变量 `COMM_PATH`（`formal` / `simulation`）。
- 收帧/发送队列：线程安全定长槽位环形队列（`comm/msg_queue.h`），满时覆盖最旧帧并告警日志；
  底层通道只被通信线程访问，避免多线程直写竞争。

### 心跳模块（`app/heartbeat.h`，收发完整闭环）

```c
km_err_t km_heartbeat_init(uint32_t interval, uint32_t max_lost); // interval=0 关闭心跳
void     km_heartbeat_tick(time_t now);     // 定时线程节拍：到期发送 + 超时判定（绝对时间）
km_err_t km_heartbeat_handle(const uint8_t *frame, uint16_t mng_len); // 收到心跳：按方向处理
void     km_heartbeat_get_stat(km_heartbeat_stat_t *st);
void     km_heartbeat_set_run_state(uint8_t state); // 设置软件运行状态（写入上行载荷 run_state）
uint8_t  km_heartbeat_get_run_state(void);          // 查询当前软件运行状态
```

**心跳上行载荷（KM → MG，`SYSMNG_MSG_TYPE_HEARTBEAT` 的 TLV `0x01` 值）**：
单字节对齐（`pack(1)`）定长结构体，即线格式，主机小端，当前共 **5B**：

```c
#pragma pack(push, 1)
typedef struct {
    uint32_t uptime_sec;  /* +0  软件已运行时间（秒，小端） */
    uint8_t  run_state;   /* +4  软件运行状态（km_run_state_t） */
} km_heartbeat_payload_t; /* sizeof == 5 */
#pragma pack(pop)
```

运行状态 `run_state`（`km_run_state_t`）：`0x01` 完成开机自检（运行正常）、`0xE0` 随机数自检失败、
`0xE1` FPGA 算法自检失败、`0xE2` 密码卡自检失败、`0xFF` 软件启动。**结构体内容与状态取值均可扩展**
（新增字段一律追加到结构体尾部、新增状态码避开已用值，收发两端同步升级）。

- 载荷填充：`uptime_sec` = 当前时间 − 模块初始化时刻；`run_state` 默认 `0xFF`（软件启动），
  由设备初始化链更新——自检通过 `0x01`、密码卡/FPGA 自检失败分别 `0xE2`/`0xE1`（定时自检失败/恢复同样更新）。
- 发送与应答收敛于此模块（原 main 循环与 cmd_handler 散点逻辑移除）。
- **msg_id 期望槽（唯一"本机主动"类型）**：定时节拍主动发送心跳时，`km_mng_frame_encode` 自动自增并登记期望（`pending` + `tx_msg_id`）；
  收到 `sender==MNG` 的心跳先按 msg_id 判定帧性质：
  - **匹配期望**（有未确认的主动发送且 msg_id 一致）→ 是管理服务对本机主动心跳的回复：确认存活、清空期望槽、**不答复**；
  - **不匹配** → 是管理服务主动问询：应答并**回显其 msg_id**（走 encode_reply，不自增、不登记），挂起期望保持，等待同 id 回复或超时清除。
- `sender==KM`（回环/回传）→ 只记存活，防乒乓。
- 任何方向收到心跳均记录 `last_rx` 并清零连续丢失（对端问询本身即存活证据）。
- 超时判定：`interval × max_lost` 内挂起期望未被确认判丢一次；连续丢失达 `max_lost` 次（默认 3）触发告警日志 + 审计 `EVT_HEARTBEAT_LOST`（不上报管理服务）。


```
                     ┌──────────────────────────────────────────┐
                     │             KM daemon                    │
  GMAC/FPGA/SIM ───▶ │  通信线程: recv → 收帧队列；发送队列 → send │
                     │  ┌──────────────────────────────────────┐ │
                     │  │ 业务线程(主线程): 收帧队列 → km_msg_handle(分流) → 应答 │ │
                     │  └──────────────────────────────────────┘ │
                     │  定时线程: 心跳发送/超时 + 定时自检/故障门控    │
                     └──────────────────────────────────────────┘
```

- 业务处理（证书导入等）慢/阻塞**不再影响**定时功能（心跳发送/自检）。
- 平台线程抽象：`src/thread.h/.c`（Windows CRITICAL_SECTION + _beginthreadex / POSIX pthread + nanosleep）。
- 并发安全：`g_working` 收敛于 cmd_handler（`km_cmd_set_working`/`km_cmd_is_working`，互斥保护）；
  运维/审计日志写文件加互斥（业务/定时/通信线程并发写）。

## 7. 密钥文件容器（SoftCrypto 私有格式）

```
[magic:4B "KMKF"][version:1B][key_type:1B][key_id:32B][iv:16B][ciphertext:N][sm3_checksum:32B]
```

- 算法：SM4-CBC 加密；会话密钥由主密钥（`KM_MASTER_KEY` 环境变量注入，不落盘）经 SM3 派生。
- 目录权限 700、文件权限 600（Windows 降级）。

## 8. 配置项（`config/km.conf`）

```ini
[km]
conf_dir=/etc/km
key_dir=/etc/km/keys
provider=soft
heartbeat=30
log_level=info

[oplog]
log_console=1
log_to_file=1
log_file_max=1048576
log_file_count=5

[comm]
comm_path=formal        # formal | simulation
```

环境变量覆盖：`KM_CONF`、`KM_MASTER_KEY`、`COMM_PATH`、`LOG_CONSOLE`、`LOG_TO_FILE`、`LOG_FILE_MAX`、`LOG_FILE_COUNT`。

## 9. 目录结构（工程）

```
include/   公共 API 头
src/app/   device_init.c / cmd_handler.c / heartbeat.c / msg_dispatch.c
src/core/  crypto_engine / key_manager / cert_validator / der（DER/Base64 工具）
src/hal/   crypto_hal 调度 + soft_crypto（纯软 Provider）+ pcie_crypto 桩 + soft/{sm2,sm3,sm4,...}
src/comm/  km_comm（统一抽象）/ gmac_comm / fpga_comm / mgmt_protocol / sim_comm / msg_queue
src/log/   op_log / audit_log
src/       thread.c（平台线程/互斥抽象）
tests/     km_test.h 断言框架 + 各模块单测（CTest 驱动）
docs/      本文件
```

## 10. 当前状态与待办

- 已实现并通过单测：SM3/SM4 KAT、日志（含轮转）、统一通信（formal 注入 / simulation 回环）、MgmtProtocol、密钥容器、证书解析/根证书导入、设备初始化与自检框架、指令分发。
- **待办**：SM2 大数/曲线运算（当前为占位实现，补齐后 `test_sm2`、`test_crypto_hal`、设备证书验签链将自动转绿）；PKCS#10 CSR 依赖 SM2 签名，补齐后即可导出。
