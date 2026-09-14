/* 运维日志：行式文本文件（参考开源 syslog 实现）
 * 存储：<oplog_dir>/oplog-YYYYMMDD.log
 * 每行：YYYY-MM-DD_hh:mm:ss [level] {KM_file_func_line}::msg
 * hex dump 为一整块（头行 + 数据行，每行 16 字节、每 8 字节以 " | " 分隔、1 基偏移）：
 *   2026-09-11_14:20:28 [debug] {KM_log_demo.c_main_94}::hb-rx[32]:
 *   0001: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
 *   0017: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
 * 对外接口参考 log.h 方式：底层 *_loc 函数携带调用点位置（文件/函数/行号），
 * 对外以宏（KM_OPLOG_RECORD / km_oplog_write / km_log_* / km_dbg_*）自动填充定位。
 * 特性（可配置）：
 *   - 日志级别过滤
 *   - 是否打印到后台（stdout/stderr）
 *   - 是否记录到文件
 *   - 单文件最大字节数（超过后轮转 .1/.2/.../.N）
 *   - 保留文件数（循环覆盖）
 */

#include "km_log.h"
#include "thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#define DEFAULT_OPLOG_DIR "/var/log/km/operational"

static char g_oplog_dir[256];
static log_level_t g_level = LOG_LEVEL_ERROR; /* 默认最高级：仅记录 error */
static int g_console = 1;      /* 默认开启后台打印 */
static int g_to_file = 1;      /* 记录到文件 */
static long g_file_max = 0;    /* 单文件最大字节数（0=不限制） */
static int g_file_count = 5;   /* 保留文件数（循环覆盖） */
static int g_inited = 0;

/* 写文件段互斥：多线程（业务/定时/通信）并发写日志 */
static km_mutex_t g_lock;

/* 创建日志目录（Windows: _mkdir / Linux: mkdir 0755，已存在不报错） */
static void mkdir_log_dir(const char *path)
{
#ifdef _WIN32
    _mkdir(path);
#else
    mkdir(path, 0755);
#endif
}

/* 行内转义：将换行/回车等控制字符替换为空格，防止破坏“一行一条”的记录格式 */
static void escape_line(const char *in, char *out, size_t cap)
{
    size_t i, o = 0;
    for (i = 0; in[i] != '\0' && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        out[o++] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
    }
    out[o] = '\0';
}

/* 取源文件基名（兼容 '/' 与 '\\' 分隔），用于记录中的 file 字段 */
static const char *file_basename(const char *file)
{
    const char *p;
    const char *q;

    if (file == NULL || file[0] == '\0')
        return "";
    p = strrchr(file, '/');
    q = strrchr(file, '\\');
    if (q != NULL && (p == NULL || q > p))
        p = q;
    return (p != NULL) ? p + 1 : file;
}

/* 日志级别枚举转字符串（debug/info/warn/error） */
static const char *level_str(log_level_t level)
{
    switch (level) {
    case LOG_LEVEL_DEBUG: return "debug";
    case LOG_LEVEL_WARN:  return "warn";
    case LOG_LEVEL_ERROR: return "error";
    default:              return "info";
    }
}

/* 生成当日日志文件路径 */
static void daily_path(char *path, size_t cap, const struct tm *tmv)
{
    snprintf(path, cap, "%s/oplog-%04d%02d%02d.log",
             g_oplog_dir, tmv->tm_year + 1900, tmv->tm_mon + 1, tmv->tm_mday);
}

/* 轮转：当前文件超过 file_max 时，将 .N-1 -> .N 依次后移，当前文件 -> .1（循环覆盖） */
static void rotate_if_needed(const char *path)
{
    long size = 0;
    long fsz;
    int i;
    char cur[384];
    char next[384];

    if (g_file_max <= 0 || g_file_count < 1)
        return;

    {
        FILE *fp = fopen(path, "rb");
        if (fp != NULL) {
            fseek(fp, 0, SEEK_END);
            fsz = ftell(fp);
            fclose(fp);
            size = (fsz < 0) ? 0 : fsz;
        }
    }
    if (size < g_file_max)
        return;

    /* 先删除最旧的一个，实现循环覆盖 */
    snprintf(cur, sizeof(cur), "%s.%d", path, g_file_count - 1);
    remove(cur);

    /* 逆序后移 */
    for (i = g_file_count - 2; i >= 1; i--) {
        snprintf(cur, sizeof(cur), "%s.%d", path, i);
        snprintf(next, sizeof(next), "%s.%d", path, i + 1);
        rename(cur, next);
    }

    /* 当前文件 -> .1 */
    snprintf(next, sizeof(next), "%s.%d", path, 1);
    rename(path, next);
}

/* 输出一条日志（msg 可含换行，如一整块 hex dump），带调用点定位。
 * 行格式：<ts> [<level>] {KM_<file>_<func>_<line>}::<msg>
 * 未初始化或低于当前级别时丢弃；文件与控制台后台打印同一格式。 */
static void write_record(log_level_t level, const char *file, const char *func,
                         int line, const char *msg)
{
    char path[384];
    char ts[40];
    time_t now;
    struct tm tmv;
    FILE *fp;
    const char *base = file_basename(file);
    const char *fn = (func != NULL) ? func : "";

    if (!g_inited || level < g_level)
        return;

    time(&now);
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    strftime(ts, sizeof(ts), "%Y-%m-%d_%H:%M:%S", &tmv);

    km_mutex_lock(&g_lock);

    if (g_to_file) {
        daily_path(path, sizeof(path), &tmv);
        rotate_if_needed(path);

        fp = fopen(path, "ab");
        if (fp != NULL) {
            fprintf(fp, "%s [%s] {KM_%s_%s_%d}::%s\n",
                    ts, level_str(level), base, fn, line, msg);
            fflush(fp);
            fclose(fp);
        }
    }

    /* 打印到后台（错误 -> stderr，其余 -> stdout），与文件行同一格式 */
    if (g_console) {
        if (level == LOG_LEVEL_ERROR)
            fprintf(stderr, "%s [%s] {KM_%s_%s_%d}::%s\n",
                    ts, level_str(level), base, fn, line, msg);
        else
            printf("%s [%s] {KM_%s_%s_%d}::%s\n",
                   ts, level_str(level), base, fn, line, msg);
    }

    km_mutex_unlock(&g_lock);
}

/* 简易初始化：指定级别、写文件、保留 5 份；其余选项用默认（后台打印=开） */
int km_log_init(const char *oplog_dir, const char *audit_dir, log_level_t level)
{
    km_oplog_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.level = level;
    cfg.to_file = 1;
    cfg.file_count = 5;
    return km_log_init2(oplog_dir, audit_dir, &cfg);
}

/* 完整初始化日志系统：设置目录与全部选项并创建目录，同时初始化审计日志 */
int km_log_init2(const char *oplog_dir, const char *audit_dir, const km_oplog_cfg_t *ocfg)
{
    if (oplog_dir != NULL && oplog_dir[0] != '\0') {
        strncpy(g_oplog_dir, oplog_dir, sizeof(g_oplog_dir) - 1);
        g_oplog_dir[sizeof(g_oplog_dir) - 1] = '\0';
    } else {
        strncpy(g_oplog_dir, DEFAULT_OPLOG_DIR, sizeof(g_oplog_dir) - 1);
    }

    /* 默认选项：最高级（仅 error）+ 开启后台打印 + 写文件 */
    g_level = LOG_LEVEL_ERROR;
    g_console = 1;
    g_to_file = 1;
    g_file_max = 0;
    g_file_count = 5;

    if (ocfg != NULL) {
        g_level = ocfg->level;
        g_console = ocfg->console;
        g_to_file = ocfg->to_file;
        g_file_max = (ocfg->file_max > 0) ? ocfg->file_max : 0;
        g_file_count = (ocfg->file_count >= 1) ? ocfg->file_count : 1;
    }

    mkdir_log_dir(g_oplog_dir);
    km_mutex_init(&g_lock);
    g_inited = 1;
    km_auditlog_init(audit_dir);
    return 0;
}

/* 运行时更新运维日志选项（级别/后台打印/文件记录/轮转参数，不重启审计）；失败返回 -1 */
int km_oplog_update(const km_oplog_cfg_t *ocfg)
{
    if (ocfg == NULL)
        return -1;

    km_mutex_lock(&g_lock);
    g_level = ocfg->level;
    g_console = ocfg->console;
    g_to_file = ocfg->to_file;
    g_file_max = (ocfg->file_max > 0) ? ocfg->file_max : 0;
    g_file_count = (ocfg->file_count >= 1) ? ocfg->file_count : 1;
    km_mutex_unlock(&g_lock);
    return 0;
}

/* 运维日志变参核心（带调用点定位）：格式化并转义后交由 write_record 输出 */
static void oplog_writev_loc(log_level_t level, const char *file, const char *func,
                             int line, const char *fmt, va_list ap)
{
    char msg[512];
    char escaped[1200];

    vsnprintf(msg, sizeof(msg), fmt, ap);
    escape_line(msg, escaped, sizeof(escaped));
    write_record(level, file, func, line, escaped);
}

/* 运维日志底层接口：调用点定位由 KM_OPLOG_RECORD / km_oplog_write 宏自动填充 */
void km_oplog_write_loc(log_level_t level, const char *file, const char *func,
                        int line, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    oplog_writev_loc(level, file, func, line, fmt, ap);
    va_end(ap);
}

/* DEBUG 级日志底层接口（可变参数字符串），供调试跟踪使用 */
void km_dbg_write_loc(const char *file, const char *func, int line,
                      const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    oplog_writev_loc(LOG_LEVEL_DEBUG, file, func, line, fmt, ap);
    va_end(ap);
}

/* DEBUG 级十六进制 dump 底层接口：整块输出（头行 tag[长度] + 数据行）。
 * 数据行每行 16 字节、每 8 字节以 " | " 分隔，行首为 1 基起始偏移（%04d）：
 *   {KM_file_func_line}::tag[32]:
 *   0001: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
 *   0017: 5A 5A 31 31 05 06 07 08 | 09 0A 0B 0C 0D 0E 0F 10
 * data 为 NULL 或 len=0 时仅输出头行 tag[0]: */
void km_dbg_hex_loc(const char *file, const char *func, int line,
                    const char *tag, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    char tagbuf[128];
    char buf[4096];
    size_t o;
    size_t off;
    int w;

    escape_line((tag != NULL) ? tag : "-", tagbuf, sizeof(tagbuf));

    /* 头行：<tag>[<len>]: */
    o = (size_t)snprintf(buf, sizeof(buf), "%s[%zu]:", tagbuf, len);
    if (o >= sizeof(buf))
        o = sizeof(buf) - 1;

    for (off = 0; off < len; off += 16) {
        size_t n = len - off;
        size_t i;

        if (n > 16)
            n = 16;
        if (o + 64 >= sizeof(buf))
            break;   /* 缓冲区不足：截断 dump */

        w = snprintf(buf + o, sizeof(buf) - o, "\n%04u:", (unsigned)(off + 1));
        if (w < 0)
            break;
        o += (size_t)w;

        /* 前 8 字节 */
        for (i = 0; i < n && i < 8 && o + 4 < sizeof(buf); i++) {
            w = snprintf(buf + o, sizeof(buf) - o, " %02X", p[off + i]);
            if (w < 0)
                break;
            o += (size_t)w;
        }
        /* 后 8 字节（本行超过 8 字节时以 " | " 分隔） */
        if (n > 8 && o + 4 < sizeof(buf)) {
            w = snprintf(buf + o, sizeof(buf) - o, " |");
            if (w < 0)
                break;
            o += (size_t)w;
            for (i = 8; i < n && o + 4 < sizeof(buf); i++) {
                w = snprintf(buf + o, sizeof(buf) - o, " %02X", p[off + i]);
                if (w < 0)
                    break;
                o += (size_t)w;
            }
        }
    }
    buf[(o < sizeof(buf)) ? o : sizeof(buf) - 1] = '\0';

    write_record(LOG_LEVEL_DEBUG, file, func, line, buf);
}

/* 反初始化日志系统并关闭审计日志 */
void km_log_deinit(void)
{
    g_inited = 0;
    km_auditlog_deinit();
    km_mutex_destroy(&g_lock);
}
