#ifndef KM_MSG_QUEUE_H
#define KM_MSG_QUEUE_H

#include <stddef.h>
#include <stdint.h>

#include "km_error.h"
#include "thread.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 线程安全定长槽位环形队列：
 * - push：满则覆盖最旧一帧（返回 -1 表示丢过帧），单帧长度须 <= slot_len；
 * - pop：非阻塞，空返回 0；
 * 用于通信线程与业务线程/定时线程之间的帧交换。 */

typedef struct {
    km_mutex_t lock;
    uint8_t   *slots;      /* cap * slot_len 缓冲 */
    uint16_t  *lens;       /* 每槽实际长度 */
    size_t     slot_len;
    size_t     cap;
    size_t     head;       /* 读位置 */
    size_t     count;      /* 当前帧数 */
} km_msg_queue_t;

km_err_t km_msg_queue_init(km_msg_queue_t *q, size_t cap, size_t slot_len);
void km_msg_queue_deinit(km_msg_queue_t *q);

/* @return 1 入队成功；-1 入队成功但覆盖最旧一帧（丢帧）；0 参数非法 */
int km_msg_queue_push(km_msg_queue_t *q, const uint8_t *data, size_t len);

/* @return 1 出队成功（len 为实际长度）；0 队列空或参数非法 */
int km_msg_queue_pop(km_msg_queue_t *q, uint8_t *buf, size_t cap, size_t *len);

size_t km_msg_queue_count(km_msg_queue_t *q);

#ifdef __cplusplus
}
#endif

#endif /* KM_MSG_QUEUE_H */
