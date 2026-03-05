/* SPDX-License-Identifier: Apache-2.0 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include "sm2_implicit_cert.h"
#include "sm2_revocation.h"
#include "sm2_auth.h"
#include "sm2_crypto.h"
#include "sm2_pki_service.h"
#include "sm2_pki_client.h"

extern int g_tests_run;
extern int g_tests_passed;
extern int g_tests_failed;

extern sm2_private_key_t g_ca_priv;
extern sm2_ec_point_t g_ca_pub;
extern int g_ca_initialized;

#define TEST_ASSERT(condition, msg)                                            \
    do                                                                         \
    {                                                                          \
        if (!(condition))                                                      \
        {                                                                      \
            printf("\033[31m[FAIL] %s: %s\033[0m\n", __func__, msg);           \
            g_tests_failed++;                                                  \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TEST_PASS()                                                            \
    do                                                                         \
    {                                                                          \
        printf("\033[32m[PASS] %s\033[0m\n", __func__);                        \
        g_tests_passed++;                                                      \
    } while (0)

#define RUN_TEST(test_func)                                                    \
    do                                                                         \
    {                                                                          \
        g_tests_run++;                                                         \
        test_func();                                                           \
    } while (0)

double now_ms_highres(void);
double calc_p95_ms(double *samples, size_t count);
double calc_median_value(double *samples, size_t count);

void test_setup_ca(void);

void run_test_ecqv_suite(void);
void run_test_cuckoo_suite(void);
void run_test_revoke_suite(void);
void run_test_sync_suite(void);
void run_test_auth_suite(void);
void run_test_pki_suite(void);

#endif
