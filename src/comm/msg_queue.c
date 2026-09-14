#include "msg_queue.h"

#include <stdlib.h>
#include <string.h>

km_err_t km_msg_queue_init(km_msg_queue_t *q, size_t cap, size_t slot_len)
{
    if (q == NULL || cap == 0 || slot_len == 0)
        return KM_ERR_BAD_PARAM;

    memset(q, 0, sizeof(*q));
    q->slots = (uint8_t *)malloc(cap * slot_len);
    q->lens  = (uint16_t *)malloc(cap * sizeof(uint16_t));
    if (q->slots == NULL || q->lens == NULL) {
        free(q->slots);
        free(q->lens);
        q->slots = NULL;
        q->lens = NULL;
        return KM_ERR_COMM_FAIL;
    }
    q->slot_len = slot_len;
    q->cap = cap;
    q->head = 0;
    q->count = 0;
    km_mutex_init(&q->lock);
    return KM_ERR_OK;
}

void km_msg_queue_deinit(km_msg_queue_t *q)
{
    if (q == NULL)
        return;
    km_mutex_destroy(&q->lock);
    free(q->slots);
    free(q->lens);
    memset(q, 0, sizeof(*q));
}

int km_msg_queue_push(km_msg_queue_t *q, const uint8_t *data, size_t len)
{
    size_t tail;
    int dropped = 0;

    if (q == NULL || data == NULL || len == 0 || len > q->slot_len)
        return 0;

    km_mutex_lock(&q->lock);
    tail = (q->head + q->count) % q->cap;
    memcpy(q->slots + tail * q->slot_len, data, len);
    q->lens[tail] = (uint16_t)len;
    if (q->count == q->cap) {
        dropped = 1;
        q->head = (q->head + 1) % q->cap;
    } else {
        q->count++;
    }
    km_mutex_unlock(&q->lock);
    return dropped ? -1 : 1;
}

int km_msg_queue_pop(km_msg_queue_t *q, uint8_t *buf, size_t cap, size_t *len)
{
    size_t n;

    if (q == NULL || buf == NULL || len == NULL)
        return 0;

    km_mutex_lock(&q->lock);
    if (q->count == 0) {
        km_mutex_unlock(&q->lock);
        return 0;
    }
    n = q->lens[q->head];
    if (n > cap)
        n = cap;
    memcpy(buf, q->slots + q->head * q->slot_len, n);
    *len = n;
    q->head = (q->head + 1) % q->cap;
    q->count--;
    km_mutex_unlock(&q->lock);
    return 1;
}

size_t km_msg_queue_count(km_msg_queue_t *q)
{
    size_t c;

    if (q == NULL)
        return 0;
    km_mutex_lock(&q->lock);
    c = q->count;
    km_mutex_unlock(&q->lock);
    return c;
}
