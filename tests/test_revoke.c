/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

typedef struct
{
    int should_fail;
    sm2_rev_status_t fixed_status;
    int call_count;
} mock_ocsp_state_t;

typedef struct
{
    int pattern[16]; /* 1=success, 0=fail */
    size_t pattern_len;
    size_t idx;
    int call_count;
} jitter_ocsp_state_t;

static sm2_ic_error_t mock_ocsp_query(void *user_ctx, uint64_t serial_number,
    uint32_t timeout_ms, sm2_ocsp_response_t *response)
{
    (void)serial_number;
    (void)timeout_ms;
    mock_ocsp_state_t *st = (mock_ocsp_state_t *)user_ctx;
    st->call_count++;
    if (st->should_fail)
        return SM2_IC_ERR_CRYPTO;

    response->serial_number = serial_number;
    response->status = st->fixed_status;
    response->this_update = 1000;
    response->next_update = 2000;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t jitter_ocsp_query(void *user_ctx, uint64_t serial_number,
    uint32_t timeout_ms, sm2_ocsp_response_t *response)
{
    (void)timeout_ms;
    jitter_ocsp_state_t *st = (jitter_ocsp_state_t *)user_ctx;
    if (!st || !response || st->pattern_len == 0)
        return SM2_IC_ERR_PARAM;
    int ok = st->pattern[st->idx % st->pattern_len];
    st->idx++;
    st->call_count++;
    if (!ok)
        return SM2_IC_ERR_CRYPTO;

    response->serial_number = serial_number;
    response->status = SM2_REV_STATUS_GOOD;
    response->this_update = 1000;
    response->next_update = 1001; /* force minimal cache window */
    return SM2_IC_SUCCESS;
}

static void test_revocation_delta_and_cuckoo()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 64, 300, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");

    sm2_crl_delta_item_t delta_items[] = { { 1001, true }, { 1002, true } };
    sm2_crl_delta_t d1 = { 0, 1, delta_items, 2 };
    TEST_ASSERT(
        sm2_revocation_apply_crl_delta(&ctx, &d1, 120) == SM2_IC_SUCCESS,
        "Apply Delta 1");
    TEST_ASSERT(sm2_revocation_crl_version(&ctx) == 1, "Version 1");
    TEST_ASSERT(sm2_revocation_local_count(&ctx) == 2, "Local Count 2");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 1001, 130, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Revoked");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "1001 Revoked");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER, "Source Local");

    TEST_ASSERT(sm2_revocation_query(&ctx, 2000, 130, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Good");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "2000 Good");

    sm2_crl_delta_item_t delta_items2[] = { { 1001, false } };
    sm2_crl_delta_t d2 = { 1, 2, delta_items2, 1 };
    TEST_ASSERT(
        sm2_revocation_apply_crl_delta(&ctx, &d2, 140) == SM2_IC_SUCCESS,
        "Apply Delta 2");
    TEST_ASSERT(sm2_revocation_crl_version(&ctx) == 2, "Version 2");

    TEST_ASSERT(sm2_revocation_query(&ctx, 1001, 145, &status, &source)
            == SM2_IC_SUCCESS,
        "Query 1001 Removed");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "1001 Good After Remove");

    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_ttl_expire()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 32, 10, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");

    sm2_crl_delta_item_t items[] = { { 3333, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 105) == SM2_IC_SUCCESS,
        "Apply Delta");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 3333, 110, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Before TTL");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Revoked Before TTL");

    TEST_ASSERT(sm2_revocation_query(&ctx, 3333, 116, &status, &source)
            == SM2_IC_SUCCESS,
        "Query After TTL");
    TEST_ASSERT(status == SM2_REV_STATUS_UNKNOWN, "Unknown After TTL");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER_STALE, "Stale Source");

    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_online_ocsp_and_cache()
{
    sm2_revocation_ctx_t ctx;
    mock_ocsp_state_t state;
    memset(&state, 0, sizeof(state));
    state.fixed_status = SM2_REV_STATUS_REVOKED;

    TEST_ASSERT(sm2_revocation_init(&ctx, 32, 120, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(
        sm2_revocation_set_online(&ctx, true) == SM2_IC_SUCCESS, "Set Online");

    sm2_ocsp_client_cfg_t ocsp_cfg;
    memset(&ocsp_cfg, 0, sizeof(ocsp_cfg));
    ocsp_cfg.query_fn = mock_ocsp_query;
    ocsp_cfg.user_ctx = &state;
    ocsp_cfg.timeout_ms = 100;
    ocsp_cfg.retry_count = 2;
    ocsp_cfg.cache_capacity = 16;
    TEST_ASSERT(sm2_revocation_config_ocsp(&ctx, &ocsp_cfg) == SM2_IC_SUCCESS,
        "Config OCSP");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 7777, 200, &status, &source)
            == SM2_IC_SUCCESS,
        "Online OCSP Query");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "OCSP Revoked");
    TEST_ASSERT(source == SM2_REV_SOURCE_OCSP, "Source OCSP");

    state.should_fail = 1;
    TEST_ASSERT(sm2_revocation_query(&ctx, 7777, 300, &status, &source)
            == SM2_IC_SUCCESS,
        "Cache Query");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Cache Revoked");
    TEST_ASSERT(source == SM2_REV_SOURCE_OCSP_CACHE, "Source Cache");

    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_online_fallback_to_local()
{
    sm2_revocation_ctx_t ctx;
    mock_ocsp_state_t state;
    memset(&state, 0, sizeof(state));
    state.should_fail = 1;

    TEST_ASSERT(sm2_revocation_init(&ctx, 32, 300, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(
        sm2_revocation_set_online(&ctx, true) == SM2_IC_SUCCESS, "Set Online");

    sm2_ocsp_client_cfg_t ocsp_cfg;
    memset(&ocsp_cfg, 0, sizeof(ocsp_cfg));
    ocsp_cfg.query_fn = mock_ocsp_query;
    ocsp_cfg.user_ctx = &state;
    ocsp_cfg.timeout_ms = 100;
    ocsp_cfg.retry_count = 1;
    ocsp_cfg.cache_capacity = 8;
    TEST_ASSERT(sm2_revocation_config_ocsp(&ctx, &ocsp_cfg) == SM2_IC_SUCCESS,
        "Config OCSP");

    sm2_crl_delta_item_t items[] = { { 9001, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 150) == SM2_IC_SUCCESS,
        "Apply Delta");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 9001, 200, &status, &source)
            == SM2_IC_SUCCESS,
        "Fallback Query");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Fallback Revoked");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER, "Source Local Fallback");

    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_ocsp_latency_sla()
{
    sm2_revocation_ctx_t ctx;
    mock_ocsp_state_t state;
    memset(&state, 0, sizeof(state));
    state.fixed_status = SM2_REV_STATUS_GOOD;

    TEST_ASSERT(sm2_revocation_init(&ctx, 32, 300, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(
        sm2_revocation_set_online(&ctx, true) == SM2_IC_SUCCESS, "Set Online");

    sm2_ocsp_client_cfg_t ocsp_cfg;
    memset(&ocsp_cfg, 0, sizeof(ocsp_cfg));
    ocsp_cfg.query_fn = mock_ocsp_query;
    ocsp_cfg.user_ctx = &state;
    ocsp_cfg.timeout_ms = 100;
    ocsp_cfg.retry_count = 1;
    ocsp_cfg.cache_capacity = 128;
    TEST_ASSERT(sm2_revocation_config_ocsp(&ctx, &ocsp_cfg) == SM2_IC_SUCCESS,
        "Config OCSP");

    const int rounds = 2000;
    clock_t start = clock();
    for (int i = 0; i < rounds; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        uint64_t serial = (uint64_t)(500000
            + i); /* avoid cache hits by using unique serials */
        TEST_ASSERT(
            sm2_revocation_query(&ctx, serial, 1000 + i, &status, &source)
                == SM2_IC_SUCCESS,
            "OCSP Query");
        TEST_ASSERT(source == SM2_REV_SOURCE_OCSP, "OCSP Source");
        TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "OCSP Good");
    }
    double avg_ms
        = ((double)(clock() - start)) / CLOCKS_PER_SEC * 1000.0 / rounds;
    printf("   [OCSP-SLA] avg=%.4f ms (N=%d)\n", avg_ms, rounds);

    /* SLA target for current mock-linked prototype path */
    TEST_ASSERT(avg_ms <= 5.0, "OCSP Avg Latency > 5ms");
    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_false_positive_rate()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 4096, 3600, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");

    enum
    {
        revoked_n = 2000
    };
    sm2_crl_delta_item_t *items = (sm2_crl_delta_item_t *)calloc(
        revoked_n, sizeof(sm2_crl_delta_item_t));
    TEST_ASSERT(items != NULL, "Alloc Delta Items");

    for (int i = 0; i < revoked_n; i++)
    {
        items[i].serial_number = (uint64_t)(100000 + i);
        items[i].revoked = true;
    }
    sm2_crl_delta_t d = { 0, 1, items, revoked_n };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 110) == SM2_IC_SUCCESS,
        "Apply Large Delta");

    enum
    {
        query_n = 50000
    };
    int false_positive = 0;
    for (int i = 0; i < query_n; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        uint64_t serial
            = (uint64_t)(500000 + i); /* disjoint from revoked range */
        TEST_ASSERT(sm2_revocation_query(&ctx, serial, 200, &status, &source)
                == SM2_IC_SUCCESS,
            "Query Non Member");
        if (status == SM2_REV_STATUS_REVOKED)
            false_positive++;
    }

    double fpr = (double)false_positive / (double)query_n;
    printf("   [CF-FPR] fp=%d/%d (%.6f)\n", false_positive, query_n, fpr);
    TEST_ASSERT(fpr <= 0.01, "False Positive Rate > 1%");

    free(items);
    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_network_jitter_sequence()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 64, 300, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(
        sm2_revocation_set_online(&ctx, true) == SM2_IC_SUCCESS, "Set Online");

    jitter_ocsp_state_t state;
    memset(&state, 0, sizeof(state));
    int pattern[] = { 1, 0, 0, 1, 0, 1 };
    memcpy(state.pattern, pattern, sizeof(pattern));
    state.pattern_len = sizeof(pattern) / sizeof(pattern[0]);

    sm2_ocsp_client_cfg_t ocsp_cfg;
    memset(&ocsp_cfg, 0, sizeof(ocsp_cfg));
    ocsp_cfg.query_fn = jitter_ocsp_query;
    ocsp_cfg.user_ctx = &state;
    ocsp_cfg.timeout_ms = 100;
    ocsp_cfg.retry_count = 1;
    ocsp_cfg.cache_capacity = 0; /* disable cache to expose jitter behavior */
    TEST_ASSERT(sm2_revocation_config_ocsp(&ctx, &ocsp_cfg) == SM2_IC_SUCCESS,
        "Config OCSP");

    sm2_crl_delta_item_t items[] = { { 9100, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 120) == SM2_IC_SUCCESS,
        "Apply Delta");

    for (int i = 0; i < 10; i++)
    {
        if (i == 3)
            TEST_ASSERT(
                sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
                "Disconnect");
        if (i == 6)
            TEST_ASSERT(sm2_revocation_set_online(&ctx, true) == SM2_IC_SUCCESS,
                "Reconnect");

        sm2_rev_status_t status;
        sm2_rev_source_t source;
        TEST_ASSERT(sm2_revocation_query(&ctx, 9100, 130 + i, &status, &source)
                == SM2_IC_SUCCESS,
            "Jitter Query");

        if (i >= 3 && i < 6)
        {
            TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER,
                "Offline Must Use Local");
            TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Offline Revoked");
            continue;
        }
        if (source == SM2_REV_SOURCE_OCSP)
        {
            TEST_ASSERT(
                status == SM2_REV_STATUS_GOOD, "Online Success Uses OCSP");
        }
        else
        {
            TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER,
                "Online Failure Fallback Local");
            TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Fallback Revoked");
        }
    }

    TEST_ASSERT(state.call_count >= 6, "Jitter Sequence Call Count");
    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_false_positive_rate_constrained()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 64, 3600, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");
    TEST_ASSERT(
        sm2_revocation_config_local_filter(&ctx, 12, 4, 500) == SM2_IC_SUCCESS,
        "Constrained Filter Config");

    enum
    {
        revoked_n = 300
    };
    sm2_crl_delta_item_t *items = (sm2_crl_delta_item_t *)calloc(
        revoked_n, sizeof(sm2_crl_delta_item_t));
    TEST_ASSERT(items != NULL, "Alloc Delta Items");
    for (int i = 0; i < revoked_n; i++)
    {
        items[i].serial_number = (uint64_t)(700000 + i);
        items[i].revoked = true;
    }
    sm2_crl_delta_t d = { 0, 1, items, revoked_n };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 110) == SM2_IC_SUCCESS,
        "Apply Constrained Delta");

    enum
    {
        query_n = 50000
    };
    int false_positive = 0;
    for (int i = 0; i < query_n; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        uint64_t serial = (uint64_t)(900000 + i);
        TEST_ASSERT(sm2_revocation_query(&ctx, serial, 200, &status, &source)
                == SM2_IC_SUCCESS,
            "Constrained Query");
        if (status == SM2_REV_STATUS_REVOKED)
            false_positive++;
    }

    double fpr = (double)false_positive / (double)query_n;
    printf("   [CF-FPR-CONSTRAINED] fp=%d/%d (%.6f)\n", false_positive, query_n,
        fpr);
    TEST_ASSERT(false_positive > 0, "Constrained FP Should Be Observable");
    TEST_ASSERT(fpr <= 0.05, "Constrained FPR > 5%");

    free(items);
    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

void run_test_revoke_suite(void)
{
    RUN_TEST(test_revocation_delta_and_cuckoo);
    RUN_TEST(test_revocation_ttl_expire);
    RUN_TEST(test_revocation_online_ocsp_and_cache);
    RUN_TEST(test_revocation_online_fallback_to_local);
    RUN_TEST(test_revocation_network_jitter_sequence);
    RUN_TEST(test_revocation_ocsp_latency_sla);
    RUN_TEST(test_revocation_false_positive_rate);
    RUN_TEST(test_revocation_false_positive_rate_constrained);
}
