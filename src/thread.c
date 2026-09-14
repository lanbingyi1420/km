#include "thread.h"

#include <stdlib.h>
#include <time.h>

/* ---------- 互斥锁 ---------- */

km_err_t km_mutex_init(km_mutex_t *m)
{
    if (m == NULL)
        return KM_ERR_BAD_PARAM;
#ifdef _WIN32
    InitializeCriticalSection(m);
#else
    if (pthread_mutex_init(m, NULL) != 0)
        return KM_ERR_COMM_FAIL;
#endif
    return KM_ERR_OK;
}

void km_mutex_lock(km_mutex_t *m)
{
    if (m == NULL)
        return;
#ifdef _WIN32
    EnterCriticalSection(m);
#else
    pthread_mutex_lock(m);
#endif
}

void km_mutex_unlock(km_mutex_t *m)
{
    if (m == NULL)
        return;
#ifdef _WIN32
    LeaveCriticalSection(m);
#else
    pthread_mutex_unlock(m);
#endif
}

void km_mutex_destroy(km_mutex_t *m)
{
    if (m == NULL)
        return;
#ifdef _WIN32
    DeleteCriticalSection(m);
#else
    pthread_mutex_destroy(m);
#endif
}

/* ---------- 睡眠 ---------- */

void km_thread_sleep_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    nanosleep(&ts, NULL);
#endif
}

/* ---------- 线程 ---------- */


typedef struct {
    km_thread_fn_t fn;
    void *arg;
} km_thread_arg_t;

#ifdef _WIN32
static unsigned __stdcall km_win_thread_wrap(void *p)
{
    km_thread_arg_t *a = (km_thread_arg_t *)p;

    a->fn(a->arg);
    free(a);
    return 0;
}
#else
static void *km_posix_thread_wrap(void *p)
{
    km_thread_arg_t *a = (km_thread_arg_t *)p;

    a->fn(a->arg);
    free(a);
    return NULL;
}
#endif

km_err_t km_thread_create(km_thread_t *t, km_thread_fn_t fn, void *arg)
{
    km_thread_arg_t *a;

    if (t == NULL || fn == NULL)
        return KM_ERR_BAD_PARAM;
    a = (km_thread_arg_t *)malloc(sizeof(*a));
    if (a == NULL)
        return KM_ERR_COMM_FAIL;
    a->fn = fn;
    a->arg = arg;
#ifdef _WIN32
    {
        unsigned tid;
        HANDLE h = (HANDLE)_beginthreadex(NULL, 0, km_win_thread_wrap, a, 0, &tid);

        if (h == NULL || h == INVALID_HANDLE_VALUE) {
            free(a);
            return KM_ERR_COMM_FAIL;
        }
        *t = h;
    }
#else
    if (pthread_create(t, NULL, km_posix_thread_wrap, a) != 0) {
        free(a);
        return KM_ERR_COMM_FAIL;
    }
#endif
    return KM_ERR_OK;
}

void km_thread_join(km_thread_t *t)
{
    if (t == NULL)
        return;
#ifdef _WIN32
    if (*t != NULL && *t != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(*t, INFINITE);
        CloseHandle(*t);
        *t = NULL;
    }
#else
    pthread_join(*t, NULL);
#endif
}

