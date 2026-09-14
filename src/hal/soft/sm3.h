#ifndef KM_SM3_H
#define KM_SM3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_LEN 32

typedef struct {
    uint32_t state[8];
    uint64_t total_bits;
    uint8_t  buffer[64];
    size_t   buf_len;
} sm3_ctx_t;

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const uint8_t *in, size_t len);
void sm3_final(sm3_ctx_t *ctx, uint8_t out[SM3_DIGEST_LEN]);

void sm3_digest(const uint8_t *in, size_t len, uint8_t out[SM3_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* KM_SM3_H */
