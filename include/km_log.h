#ifndef KM_LOG_H
#define KM_LOG_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include "km_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 日志级别（严重度递增）：低于当前配置级别的日志被丢弃。
 * DEBUG 为最详细级别，用于调试跟踪（含数据域 hex dump），默认不输出。 */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
} log_level_t;

/** 运维日志选项（参考开源 syslog 实现） */
typedef struct {
    log_level_t level;        /* 日志级别：低于该级别的日志被丢弃 */
    int         console;      /* 是否同时打印到后台（stdout/stderr） */
    int         to_file;      /* 是否记录到文件 */
    long        file_max;     /* 单个日志文件最大字节数（0=不限制；超过后轮转） */
    int         file_count;   /* 保留的历史日志文件数（循环覆盖，>=1） */
} km_oplog_cfg_t;

/**
 * @brief 初始化日志系统
 * @param oplog_dir  运维日志目录（NULL 使用默认）
 * @param audit_dir  审计日志目录（NULL 使用默认）
 * @param level      日志级别（等价于 km_oplog_cfg_t{level=level, console=0, to_file=1}）
 */
int km_log_init(const char *oplog_dir, const char *audit_dir, log_level_t level);

/**
 * @brief 以完整选项初始化日志系统（oplog 与 audit 均需目录）
 * @param oplog_dir  运维日志目录
 * @param audit_dir  审计日志目录
 * @param ocfg       运维日志选项（NULL 使用默认：level=ERROR,console=1,to_file=1,file_max=0,file_count=5）
 */
int km_log_init2(const char *oplog_dir, const char *audit_dir, const km_oplog_cfg_t *ocfg);

/**
 * @brief 运行时更新运维日志选项（级别/后台打印/文件记录等，不重启审计日志）
 * @param ocfg 新的运维日志选项（不可为 NULL）
 * @return 0 成功
 */
int km_oplog_update(const km_oplog_cfg_t *ocfg);

/* ---------- 运维日志对外接口（参考开源 log.h 实现方式） ----------
 * 底层函数携带调用点位置（文件/函数/行号），对外以宏形式提供：
 * 宏在展开处自动填充 __FILE__/__FUNCTION__/__LINE__，日志记录携带定位信息。 */

/**
 * @brief 记录运维日志（文件 + 可选的打印到后台）
 *        行格式：YYYY-MM-DD_hh:mm:ss [level] {KM_file_func_line}::msg
 * @param level 日志级别
 * @param file  调用点源文件（由宏自动填充）
 * @param func  调用点函数名（由宏自动填充）
 * @param line  调用点行号（由宏自动填充）
 * @param fmt   格式化字符串
 */
void km_oplog_write_loc(log_level_t level, const char *file, const char *func,
                        int line, const char *fmt, ...);

/**
 * @brief 记录一条 DEBUG 级运维日志（可变参数字符串，带调用点位置）
 */
void km_dbg_write_loc(const char *file, const char *func, int line,
                      const char *fmt, ...);

/**
 * @brief 以 DEBUG 级输出指定数据域的十六进制 dump（带调用点位置）
 *        整块输出：头行 <tag>[<len>]:，其后每行 16 字节、每 8 字节以 " | " 分隔，
 *        行首为 1 基起始偏移
 * @param tag  数据域标签（可为 NULL）
 * @param data 数据首地址（NULL 或 len=0 时仅输出头行 <tag>[0]:）
 * @param len  数据长度（字节）
 */
void km_dbg_hex_loc(const char *file, const char *func, int line,
                    const char *tag, const void *data, size_t len);

/* 记录一条带调用点位置的运维日志 */
#define KM_OPLOG_RECORD(level, fmt, ...) \
        km_oplog_write_loc(level, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

/* 通用运维日志宏：调用方指定级别 */
#define km_oplog_write(level, fmt, ...) KM_OPLOG_RECORD(level, fmt, ##__VA_ARGS__)

/* 分级便捷宏 */
#define km_log_debug(fmt, ...) KM_OPLOG_RECORD(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define km_log_info(fmt, ...)  KM_OPLOG_RECORD(LOG_LEVEL_INFO,  fmt, ##__VA_ARGS__)
#define km_log_warn(fmt, ...)  KM_OPLOG_RECORD(LOG_LEVEL_WARN,  fmt, ##__VA_ARGS__)
#define km_log_error(fmt, ...) KM_OPLOG_RECORD(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

/* DEBUG 级日志宏（等价于 km_log_debug） */
#define km_dbg_write(fmt, ...) \
        km_dbg_write_loc(__FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

/* DEBUG 级十六进制 dump 宏
 * 输出形态：一整块（头行 + 数据行），头行为 <tag>[<字节数>]:，
 * 其后每行 16 字节、每 8 字节以 " | " 分隔，行首为 1 基起始偏移，形如：
 *   {KM_xxx.c_main_94}::hb-rx[32]:
 *   0001: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
 *   0017: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
 */
#define km_dbg_hex(tag, data, len) \
        km_dbg_hex_loc(__FILE__, __FUNCTION__, __LINE__, tag, data, len)

/**
 * @brief 初始化审计日志队列（由 km_log_init 内部调用）
 * @param dir 审计目录（NULL 使用默认）
 * @return 0 成功
 */
int km_auditlog_init(const char *dir);

/**
 * @brief 记录审计日志（本地持久化队列 + 上报 D3000M）
 * @param event_id 审计事件类型（km_audit_event_t）
 * @param detail   事件详情（可为 NULL）
 */
void km_auditlog_write(uint32_t event_id, const char *detail);

/** @brief 关闭审计日志（关闭文件、清空队列状态） */
void km_auditlog_deinit(void);

/* ---------- 上报队列接口（供通信层上报后确认） ---------- */

typedef struct {
    uint64_t seq;        /* 队列序号 */
    uint64_t ts;         /* 事件时间戳（Unix 秒） */
    uint32_t event_id;   /* 审计事件类型 */
    char     detail[256];
} km_audit_entry_t;

/**
 * @brief 获取待上报的审计条目（内存队列，最多 max 条）
 * @return 0 成功，count 为实际条数
 */
int km_auditlog_pending(km_audit_entry_t *entries, int max, int *count);

/**
 * @brief 确认上报成功（推进水位，清理已确认条目）
 * @param up_to_seq 已成功上报的最大 seq
 */
void km_auditlog_ack(uint64_t up_to_seq);

/** @brief 刷新并关闭日志系统 */
void km_log_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* KM_LOG_H */
