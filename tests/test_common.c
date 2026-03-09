/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

int g_tests_run = 0;
int g_tests_passed = 0;
int g_tests_failed = 0;

sm2_private_key_t g_ca_priv;
sm2_ec_point_t g_ca_pub;
int g_ca_initialized = 0;

static int cmp_double_asc(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db)
        return -1;
    if (da > db)
        return 1;
    return 0;
}

double now_ms_highres(void)
{
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int initialized = 0;
    LARGE_INTEGER counter;
    if (!initialized)
    {
        QueryPerformanceFrequency(&freq);
        initialized = 1;
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

double calc_p95_ms(double *samples, size_t count)
{
    if (!samples || count == 0)
        return 0.0;
    qsort(samples, count, sizeof(double), cmp_double_asc);
    size_t idx = (count * 95 + 99) / 100;
    if (idx == 0)
        idx = 1;
    if (idx > count)
        idx = count;
    return samples[idx - 1];
}

double calc_median_value(double *samples, size_t count)
{
    if (!samples || count == 0)
        return 0.0;
    qsort(samples, count, sizeof(double), cmp_double_asc);
    if ((count & 1U) != 0U)
        return samples[count / 2];
    return (samples[(count / 2) - 1] + samples[count / 2]) / 2.0;
}

uint64_t test_now_unix(void)
{
    time_t now = time(NULL);
    if (now < 0)
        return 0;
    return (uint64_t)now;
}

uint64_t test_cert_now(const sm2_implicit_cert_t *cert)
{
    if (cert && cert->valid_from != 0)
        return cert->valid_from;
    return test_now_unix();
}

uint64_t test_cert_pair_now(
    const sm2_implicit_cert_t *cert_a, const sm2_implicit_cert_t *cert_b)
{
    uint64_t now_a = test_cert_now(cert_a);
    uint64_t now_b = test_cert_now(cert_b);
    return now_a > now_b ? now_a : now_b;
}

int test_benchmarks_enabled(void)
{
    const char *flag = getenv("TINYPKI_RUN_BENCHMARKS");
    return flag && flag[0] != '\0' && strcmp(flag, "0") != 0;
}

int test_generate_sm2_keypair(
    sm2_private_key_t *private_key, sm2_ec_point_t *public_key)
{
    return sm2_auth_generate_ephemeral_keypair(private_key, public_key)
        == SM2_IC_SUCCESS;
}

void test_setup_ca(void)
{
    TEST_ASSERT(
        test_generate_sm2_keypair(&g_ca_priv, &g_ca_pub), "CA Keypair Failed");
    g_ca_initialized = 1;
}

int run_named_test_suite(const char *title, void (*run_suite)(void))
{
    if (!run_suite)
        return -1;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("--- %s ---\n", title ? title : "TinyPKI Test Suite");
    run_suite();
    printf("\nSummary: %d Run, %d Passed, %d Failed.\n", g_tests_run,
        g_tests_passed, g_tests_failed);
    return g_tests_failed == 0 ? 0 : -1;
}
