#include "km_test.h"

int g_km_test_pass = 0;
int g_km_test_fail = 0;

/* 各测试模块用例入口 */
void test_sm3(void);
void test_sm4(void);
void test_sm2(void);
void test_crypto_hal(void);
void test_selftest(void);
void test_cert_import(void);
void test_mgmt_protocol(void);
void test_log(void);
void test_comm_path(void);
void test_env(void);
void test_oplog(void);
void test_heartbeat(void);
void test_msg_dispatch(void);

int main(void)
{
    KM_TEST_RUN(test_sm3);
    KM_TEST_RUN(test_sm4);
    KM_TEST_RUN(test_sm2);
    KM_TEST_RUN(test_crypto_hal);
    KM_TEST_RUN(test_log);
    KM_TEST_RUN(test_oplog);
    KM_TEST_RUN(test_comm_path);
    KM_TEST_RUN(test_env);
    KM_TEST_RUN(test_selftest);
    KM_TEST_RUN(test_cert_import);
    KM_TEST_RUN(test_mgmt_protocol);
    KM_TEST_RUN(test_heartbeat);
    KM_TEST_RUN(test_msg_dispatch);
    KM_TEST_SUMMARY();
    return 0;
}
