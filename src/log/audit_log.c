/* 审计日志：内存环形缓冲 + 磁盘持久化队列
 * 磁盘文件 <audit_dir>/audit.log：
 *   [header: magic 8B "KMAUDIT1"][watermark_seq: 8B LE]
 *   [entry: seq 8B | ts 8B | event_id 4B | detail_len 2B | detail | crc32 4B]
 * 上报成功后 ack 推进 watermark（重写 header），重启后 > watermark 的条目
 * 重新加载入内存队列继续上报（失败重传）。
 */

#include "km_log.h"
#include "comm/mgmt_protocol.h"
#include "thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#define AUDIT_MAGIC       "KMAUDIT1"
#define AUDIT_HEADER_LEN  16
#define AUDIT_DETAIL_MAX  255
#define AUDIT_RING_SIZE   512
#define AUDIT_ENTRY_MAX   (8 + 8 + 4 + 2 + AUDIT_DETAIL_MAX + 4)
#define DEFAULT_AUDIT_DIR "/var/log/km/audit"

typedef struct {
    uint64_t seq;
    uint64_t ts;
    uint32_t event_id;
    char     detail[AUDIT_DETAIL_MAX + 1];
} ring_entry_t;

static char     g_audit_dir[256];
static FILE    *g_file = NULL;
static uint64_t g_next_seq = 1;
static uint64_t g_watermark = 0;
static int      g_inited = 0;

static ring_entry_t g_ring[AUDIT_RING_SIZE];
static int g_ring_head = 0;   /* 环形缓冲读指针 */
static int g_ring_count = 0;  /* 队列内条目数 */

/* 全状态互斥：多线程（业务/定时）并发写审计、上报方并发取/确认 */
static km_mutex_t g_lock;
static int        g_lock_inited = 0;

/* 创建审计日志目录（Windows: _mkdir / Linux: mkdir 0755，已存在不报错） */
static void mkdir_audit_dir(const char *path)
{
#ifdef _WIN32
    _mkdir(path);
#else
    mkdir(path, 0755);
#endif
}

/* ---------- 小端读写 ---------- */

/* 64 位值按小端写入 8 字节 */
static void put_le64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* 32 位值按小端写入 4 字节 */
static void put_le32(uint8_t *p, uint32_t v)
{
    int i;
    for (i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* 16 位值按小端写入 2 字节 */
static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

/* 从 8 字节小端读出 64 位值 */
static uint64_t get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* 计算条目 CRC32（zlib 多项式，初始 0xFFFFFFFF） */
static uint32_t entry_crc(const uint8_t *data, size_t len)
{
    return km_crc32(0xFFFFFFFFu, data, len);
}

/* ---------- 磁盘持久化 ---------- */

/* 将条目序列化追加到 audit.log 末尾（seq|ts|event|len|detail|crc）；失败返回 -1 */
static int append_entry(const ring_entry_t *e)
{
    uint8_t buf[AUDIT_ENTRY_MAX];
    uint8_t *p = buf;
    uint16_t dlen = (uint16_t)strlen(e->detail);
    uint32_t crc;

    put_le64(p, e->seq); p += 8;
    put_le64(p, e->ts);  p += 8;
    put_le32(p, e->event_id); p += 4;
    put_le16(p, dlen); p += 2;
    memcpy(p, e->detail, dlen); p += dlen;
    crc = entry_crc(buf, (size_t)(p - buf));
    put_le32(p, crc); p += 4;

    if (g_file == NULL)
        return -1;
    /* r+b 模式：显式定位到末尾再追加 */
    if (fseek(g_file, 0, SEEK_END) != 0)
        return -1;
    if (fwrite(buf, 1, (size_t)(p - buf), g_file) != (size_t)(p - buf))
        return -1;
    fflush(g_file);
    return 0;
}

/* 将已确认上报水位 seq 回写文件头（偏移 8 处） */
static void write_watermark(uint64_t seq)
{
    uint8_t buf[8];
    if (g_file == NULL)
        return;
    put_le64(buf, seq);
    /* 注意：文件以 r+b 打开（非 a+），否则 fseek 后写入仍会被追加到末尾 */
    if (fseek(g_file, 8, SEEK_SET) != 0)
        return;
    fwrite(buf, 1, 8, g_file);
    fflush(g_file);
}

/* 打开/新建 audit.log，读取水位，将未确认（>watermark）条目恢复入内存队列；失败返回 -1 */
static int open_and_recover(void)
{
    char path[384];
    uint8_t header[AUDIT_HEADER_LEN];
    uint8_t *entry_buf = NULL;
    size_t entry_cap = AUDIT_ENTRY_MAX;
    FILE *fp;

    snprintf(path, sizeof(path), "%s/audit.log", g_audit_dir);
    fp = fopen(path, "r+b");   /* 读写模式：watermark 需回写 header，append 模式不行 */
    if (fp == NULL)
        fp = fopen(path, "w+b"); /* 不存在则新建 */
    if (fp == NULL)
        return -1;

    /* 初始化 header 若不存在 */
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        uint8_t h[AUDIT_HEADER_LEN];
        memcpy(h, AUDIT_MAGIC, 8);
        put_le64(h + 8, 0);
        fwrite(h, 1, AUDIT_HEADER_LEN, fp);
        fflush(fp);
    } else {
        fseek(fp, 0, SEEK_SET);
        if (fread(header, 1, AUDIT_HEADER_LEN, fp) == AUDIT_HEADER_LEN &&
            memcmp(header, AUDIT_MAGIC, 8) == 0) {
            g_watermark = get_le64(header + 8);
        } else {
            fclose(fp);
            return -1;
        }
    }
    g_file = fp;

    /* 扫描条目恢复未上报记录 */
    entry_buf = (uint8_t *)malloc(entry_cap);
    if (entry_buf == NULL)
        return -1;

    fseek(g_file, AUDIT_HEADER_LEN, SEEK_SET);
    for (;;) {
        ring_entry_t e;
        size_t fixed = 8 + 8 + 4 + 2;
        uint16_t dlen;
        uint32_t crc;
        size_t total;

        if (fread(entry_buf, 1, fixed, g_file) != fixed)
            break;
        e.seq = get_le64(entry_buf);
        e.ts  = get_le64(entry_buf + 8);
        e.event_id = (uint32_t)(entry_buf[16] | (entry_buf[17] << 8) |
                                (entry_buf[18] << 16) | (entry_buf[19] << 24));
        dlen = (uint16_t)(entry_buf[20] | (entry_buf[21] << 8));
        if (dlen > AUDIT_DETAIL_MAX)
            break;
        total = fixed + dlen + 4;
        if (fread(entry_buf + fixed, 1, total - fixed, g_file) != total - fixed)
            break;
        crc = (uint32_t)(entry_buf[fixed + dlen] |
                         (entry_buf[fixed + dlen + 1] << 8) |
                         (entry_buf[fixed + dlen + 2] << 16) |
                         (entry_buf[fixed + dlen + 3] << 24));
        if (entry_crc(entry_buf, fixed + dlen) != crc)
            break;

        if (e.seq > g_watermark && g_ring_count < AUDIT_RING_SIZE) {
            memset(&e.detail, 0, sizeof(e.detail));
            memcpy(e.detail, entry_buf + fixed, dlen);
            e.detail[dlen] = '\0';
            /* 写入环形尾部 */
            {
                int tail = (g_ring_head + g_ring_count) % AUDIT_RING_SIZE;
                g_ring[tail] = e;
                g_ring_count++;
            }
        }
        if (e.seq >= g_next_seq)
            g_next_seq = e.seq + 1;
    }

    free(entry_buf);
    return 0;
}

/* ---------- 对外接口 ---------- */

/* 初始化审计日志：清旧状态、设置目录并恢复未上报条目；支持重复初始化 */
int km_auditlog_init(const char *dir)
{
    /* 支持重复初始化（如测试中重启恢复场景）：先清理旧状态 */
    if (!g_lock_inited) {
        km_mutex_init(&g_lock);
        g_lock_inited = 1;
    }
    km_mutex_lock(&g_lock);
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    g_ring_head = 0;
    g_ring_count = 0;
    g_next_seq = 1;
    g_watermark = 0;

    if (dir != NULL && dir[0] != '\0') {
        strncpy(g_audit_dir, dir, sizeof(g_audit_dir) - 1);
        g_audit_dir[sizeof(g_audit_dir) - 1] = '\0';
    } else {
        strncpy(g_audit_dir, DEFAULT_AUDIT_DIR, sizeof(g_audit_dir) - 1);
    }
    mkdir_audit_dir(g_audit_dir);
    g_inited = 1;
    {
        int rc = open_and_recover();
        km_mutex_unlock(&g_lock);
        return rc;
    }
}

/* 反初始化审计日志：关闭文件并置无效 */
void km_auditlog_deinit(void)
{
    if (g_lock_inited)
        km_mutex_lock(&g_lock);
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    g_inited = 0;
    if (g_lock_inited) {
        km_mutex_unlock(&g_lock);
        km_mutex_destroy(&g_lock);
        g_lock_inited = 0;
    }
}

/* 记录一条审计事件：分配 seq 落盘并入内存环形缓冲（满时覆盖最旧未上报条目） */
void km_auditlog_write(uint32_t event_id, const char *detail)
{
    ring_entry_t e;
    int tail;

    if (!g_inited)
        return;

    km_mutex_lock(&g_lock);
    memset(&e, 0, sizeof(e));
    e.seq = g_next_seq++;
    e.ts = (uint64_t)time(NULL);
    e.event_id = event_id;
    if (detail != NULL) {
        strncpy(e.detail, detail, AUDIT_DETAIL_MAX);
        e.detail[AUDIT_DETAIL_MAX] = '\0';
    }

    append_entry(&e);

    /* 入内存环形缓冲 */
    if (g_ring_count < AUDIT_RING_SIZE) {
        tail = (g_ring_head + g_ring_count) % AUDIT_RING_SIZE;
        g_ring[tail] = e;
        g_ring_count++;
    } else {
        /* 队列满：覆盖最旧未上报条目 */
        g_ring[g_ring_head] = e;
        g_ring_head = (g_ring_head + 1) % AUDIT_RING_SIZE;
    }
    km_mutex_unlock(&g_lock);
}

/* 取未上报条目快照（最多 max 条，按 seq 升序）；成功返回 0 */
int km_auditlog_pending(km_audit_entry_t *entries, int max, int *count)
{
    int n = 0;
    int i;

    if (entries == NULL || max <= 0 || count == NULL)
        return -1;

    km_mutex_lock(&g_lock);
    for (i = 0; i < g_ring_count && n < max; i++) {
        const ring_entry_t *src = &g_ring[(g_ring_head + i) % AUDIT_RING_SIZE];
        entries[n].seq = src->seq;
        entries[n].ts = src->ts;
        entries[n].event_id = src->event_id;
        strncpy(entries[n].detail, src->detail, sizeof(entries[n].detail) - 1);
        entries[n].detail[sizeof(entries[n].detail) - 1] = '\0';
        n++;
    }
    *count = n;
    km_mutex_unlock(&g_lock);
    return 0;
}

/* 确认上报至 up_to_seq：出队 ≤ 该 seq 的条目并回写水位（失败重传依据） */
void km_auditlog_ack(uint64_t up_to_seq)
{
    int removed = 0;

    km_mutex_lock(&g_lock);
    while (g_ring_count > 0) {
        const ring_entry_t *first = &g_ring[g_ring_head];
        if (first->seq > up_to_seq)
            break;
        g_ring_head = (g_ring_head + 1) % AUDIT_RING_SIZE;
        g_ring_count--;
        removed++;
    }
    (void)removed;

    if (up_to_seq > g_watermark) {
        g_watermark = up_to_seq;
        write_watermark(g_watermark);
    }
    km_mutex_unlock(&g_lock);
}
