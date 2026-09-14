#include "heartbeat.h"

#include <string.h>

#include "km_types.h"
#include "km_log.h"
#include "comm/km_comm.h"
#include "thread.h"

/* ---------- 内部状态（全部经 g_lock 保护） ---------- */

static km_mutex_t  g_lock;
static int         g_lock_inited = 0;
static uint32_t    g_interval = 0;   /* 心跳周期（秒） */
static uint32_t    g_max_lost = KM_HEARTBEAT_MAX_LOST;
static uint32_t    g_tx_count = 0;
static uint32_t    g_rx_count = 0;
static uint32_t    g_lost_count = 0;
static time_t      g_last_tx = 0;
static time_t      g_last_rx = 0;
static int         g_pending = 0;    /* 有未确认的主动发送（期望槽挂起） */
static time_t      g_pending_since = 0; /* 期望槽起算点（周期重发不重置） */
static uint8_t     g_tx_msg_id = 0;  /* 最近一次主动发送所用 msg_id（期望匹配依据） */
static uint8_t     g_run_state = KM_RUN_STATE_STARTING; /* 软件运行状态（随心跳上报） */
static time_t      g_start_time = 0; /* 软件启动时刻（用于计算已运行秒数） */

static void ensure_lock(void)
{
    if (!g_lock_inited) {
        km_mutex_init(&g_lock);
        g_lock_inited = 1;
    }
}


/* 组心跳上行载荷 TLV（tag=0x01）：value = km_heartbeat_payload_t
 * （软件已运行秒数 4B + 软件运行状态 1B，单字节对齐线格式）。 */
static void heartbeat_fill_tlv(uint8_t *tlv, size_t cap, size_t *tlv_len)
{
    km_heartbeat_payload_t body;
    time_t now = time(NULL);
    time_t start;
    uint8_t state;

    ensure_lock();
    km_mutex_lock(&g_lock);
    start = g_start_time;
    state = g_run_state;
    km_mutex_unlock(&g_lock);

    memset(&body, 0, sizeof(body));
    if (start != 0 && now > start)
        body.uptime_sec = (uint32_t)(now - start);
    body.run_state = state;

    *tlv_len = 0;
    if (km_tlv_append(tlv, cap, tlv_len, KM_TLV_TAG_HEARTBEAT,
                      &body, sizeof(body)) != KM_ERR_OK)
        *tlv_len = 0;
}

/* 主动发送心跳：encode 自动自增 msg_id，本次 id 经 tx_msg_id 输出（供登记期望）。
 * 仅在定时线程节拍（tick）中调用——单写者，保证 msg_id 计数器单调。
 * 组帧成功即返回 OK 并登记期望（发送链路失败仅记日志，best-effort，
 * 与"对端存活靠接收心跳确认"的状态机一致：链路中断时由超时窗口告警）。 */
static km_err_t heartbeat_send(uint8_t *tx_msg_id)
{
    uint8_t buf[KM_MAX_MSG_LEN];
    size_t len = sizeof(buf);
    uint8_t tlv[16];  /* TLV 头 3B + 载荷 5B（预留扩展） */
    size_t tlv_len = 0;
    km_err_t e;

    heartbeat_fill_tlv(tlv, sizeof(tlv), &tlv_len);
    e = km_mng_frame_encode(buf, &len, SYSMNG_MSG_TYPE_HEARTBEAT,
                            tlv, tlv_len, tx_msg_id);
    if (e != KM_ERR_OK)
        return e;
    e = km_comm_send_async(buf, len);
    if (e != KM_ERR_OK)
        km_oplog_write(LOG_LEVEL_WARN, "heartbeat: send failed rc=%s",
                       km_err_str(e));
    return KM_ERR_OK;
}

/* 应答管理服务主动问询（sender=MNG）：msg_id 回显请求帧 id，不自增、不登记期望 */
static km_err_t heartbeat_reply(uint8_t req_msg_id)
{
    uint8_t buf[KM_MAX_MSG_LEN];
    size_t len = sizeof(buf);
    uint8_t tlv[16];  /* TLV 头 3B + 载荷 5B（预留扩展） */
    size_t tlv_len = 0;

    heartbeat_fill_tlv(tlv, sizeof(tlv), &tlv_len);
    if (km_mng_frame_encode_reply(buf, &len, SYSMNG_MSG_TYPE_HEARTBEAT,
                                  req_msg_id, tlv, tlv_len) != KM_ERR_OK)
        return KM_ERR_BUF_TOO_SMALL;
    return km_comm_send_async(buf, len);
}

/* ---------- 公开接口 ---------- */

km_err_t km_heartbeat_init(uint32_t interval, uint32_t max_lost)
{
    ensure_lock();
    km_mutex_lock(&g_lock);
    g_interval = interval;
    g_max_lost = (max_lost == 0) ? KM_HEARTBEAT_MAX_LOST : max_lost;
    g_tx_count = 0;
    g_rx_count = 0;
    g_lost_count = 0;
    g_last_tx = 0;
    g_last_rx = 0;
    g_pending = 0;
    g_pending_since = 0;
    g_tx_msg_id = 0;
    if (g_start_time == 0)
        g_start_time = time(NULL); /* 软件启动时刻：进程内仅记录一次（重初始化不改写已运行时长） */
    km_mutex_unlock(&g_lock);
    return KM_ERR_OK;
}

void km_heartbeat_set_run_state(uint8_t state)
{
    ensure_lock();
    km_mutex_lock(&g_lock);
    g_run_state = state;
    km_mutex_unlock(&g_lock);
}

uint8_t km_heartbeat_get_run_state(void)
{
    uint8_t state;

    ensure_lock();
    km_mutex_lock(&g_lock);
    state = g_run_state;
    km_mutex_unlock(&g_lock);
    return state;
}

void km_heartbeat_tick(time_t now)
{
    int due = 0;
    int lost = 0;

    ensure_lock();
    if (now <= 0)
        now = time(NULL);
    if (g_interval == 0)
        return; /* 心跳关闭 */

    km_mutex_lock(&g_lock);
    if (g_last_tx == 0 || (now - g_last_tx) >= (time_t)g_interval)
        due = 1;
    /* 超时基准为"期望槽起算点"（g_pending_since，首次挂起时刻）而非"上次主动发送"：
     * 主动心跳每周期都会重发并刷新 g_last_tx，若以它计时则对端静默时永不判丢；
     * 起算点只在期望槽从无到有时确立，周期重发不重置（对端回复/问询经 handle 清 lost
     * 计数并清槽，起算点随之由下次发送重建）。 */
    if (g_pending && g_pending_since != 0 &&
        (now - g_pending_since) >= (time_t)g_interval * (time_t)g_max_lost) {
        lost = 1;
        g_pending = 0;
        g_lost_count++;
    }
    km_mutex_unlock(&g_lock);

    if (lost) {
        km_oplog_write(LOG_LEVEL_WARN,
                       "heartbeat: no reply within %us (consecutive lost #%u)",
                       g_interval * g_max_lost, g_lost_count);
        if (g_lost_count >= g_max_lost) {
            km_oplog_write(LOG_LEVEL_ERROR,
                           "heartbeat: link lost (%u consecutive misses)", g_lost_count);
            km_auditlog_write(EVT_HEARTBEAT_LOST, "heartbeat link lost");
        }
    }

    if (due) {
        uint8_t tx_msg_id = 0;
        km_err_t e = heartbeat_send(&tx_msg_id);

        /* 统计照常推进（组帧失败仅记日志，避免链路异常阻断状态机） */
        km_mutex_lock(&g_lock);
        if (g_pending == 0)
            g_pending_since = now; /* 期望槽首次挂起：记录超时计时起点 */
        g_last_tx = now;
        g_pending = 1;
        g_tx_count++;
        if (e == KM_ERR_OK)
            g_tx_msg_id = tx_msg_id; /* 登记期望槽：等待对端回显同 id 确认 */
        km_mutex_unlock(&g_lock);
        if (e != KM_ERR_OK)
            km_oplog_write(LOG_LEVEL_WARN, "heartbeat: frame build failed rc=%s",
                           km_err_str(e));
    }
}

km_err_t km_heartbeat_handle(const uint8_t *frame, uint16_t mng_len)
{
    STU_TLV_MNG_HEAD mh;
    uint16_t cmd;
    int is_reply_match = 0; /* 本帧是本机主动心跳的回复（期望槽匹配） */
    int is_query = 0;       /* 本帧是管理服务主动问询（应答回显其 msg_id） */
    km_err_t e = KM_ERR_OK;

    if (frame == NULL || mng_len < KM_MNG_HEAD_LEN)
        return KM_ERR_BAD_PARAM;

    memcpy(&mh, frame, sizeof(mh)); /* frame 已过 km_mng_parse 校验，安全 */
    cmd = (uint16_t)((uint16_t)mh.msg_cmd[0] | ((uint16_t)mh.msg_cmd[1] << 8));
    if (cmd != SYSMNG_MSG_TYPE_HEARTBEAT)
        return KM_ERR_BAD_PARAM;

    /* 任何方向的心跳均视为对端存活（MNG 问询/回执、KM 回环均清连续丢失） */
    ensure_lock();
    km_mutex_lock(&g_lock);
    g_last_rx = time(NULL);
    g_rx_count++;
    g_lost_count = 0;
    if (mh.sender == KM_SENDER_MNG) {
        if (g_pending && mh.msg_id == g_tx_msg_id) {
            /* 期望槽匹配：管理服务回显本机主动心跳 msg_id → 确认存活、清槽，不答复 */
            is_reply_match = 1;
            g_pending = 0;
        } else if ((uint8_t)(mh.msg_id - g_tx_msg_id) < 0x80u) {
            /* msg_id 比本机最近一次主动发送"新"（环内 ≤127）→ 管理服务主动问询。
             * 低于/等于最近已发 id 的 MNG 心跳视作对历史心跳的迟到回执（回环/重复回显），
             * 不答复——否则对端回显本机应答会形成无限回声乒乓。 */
            is_query = 1;
        }
    }
    km_mutex_unlock(&g_lock);

    /* sender==MNG 且判定为问询 → 应答回显其 msg_id（不自增/不登记期望）；
     * 回环方向（sender=KM）或迟到回执只记存活，避免乒乓。应答失败仅记日志（存活已确认）。 */
    if (is_query) {
        e = heartbeat_reply(mh.msg_id);
        if (e != KM_ERR_OK)
            km_oplog_write(LOG_LEVEL_WARN, "heartbeat: reply send failed rc=%s",
                           km_err_str(e));
    }
    return KM_ERR_OK;
}

void km_heartbeat_get_stat(km_heartbeat_stat_t *st)
{
    if (st == NULL)
        return;
    ensure_lock();
    km_mutex_lock(&g_lock);
    st->interval = g_interval;
    st->max_lost = g_max_lost;
    st->tx_count = g_tx_count;
    st->rx_count = g_rx_count;
    st->lost_count = g_lost_count;
    st->last_tx = g_last_tx;
    st->last_rx = g_last_rx;
    st->tx_msg_id = g_tx_msg_id;
    st->pending = (uint8_t)g_pending;
    km_mutex_unlock(&g_lock);
}
