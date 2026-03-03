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
