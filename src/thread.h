#ifndef KM_THREAD_H
#define KM_THREAD_H

#include <stddef.h>
#include "km_error.h"

#ifdef __cplusplus
extern "C" {
#endif



#ifdef _WIN32
#include <windows.h>
#include <process.h>
typedef CRITICAL_SECTION km_mutex_t;
typedef HANDLE           km_thread_t;
#else
#include <pthread.h>
typedef pthread_mutex_t km_mutex_t;
typedef pthread_t        km_thread_t;
#endif

km_err_t km_mutex_init(km_mutex_t *m);
void km_mutex_lock(km_mutex_t *m);
void km_mutex_unlock(km_mutex_t *m);
void km_mutex_destroy(km_mutex_t *m);

void km_thread_sleep_ms(unsigned ms);

typedef void (*km_thread_fn_t)(void *arg);

km_err_t km_thread_create(km_thread_t *t, km_thread_fn_t fn, void *arg);
void km_thread_join(km_thread_t *t);

#ifdef __cplusplus
}
#endif

#endif /* KM_THREAD_H */
