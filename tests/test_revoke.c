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
typedef struct
{
    int fail_mode;
    int call_count;
} expiry_ocsp_state_t;

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

static sm2_ic_error_t expiry_ocsp_query(void *user_ctx, uint64_t serial_number,
    uint32_t timeout_ms, sm2_ocsp_response_t *response)
{
    (void)timeout_ms;
    expiry_ocsp_state_t *st = (expiry_ocsp_state_t *)user_ctx;
    if (!st || !response)
        return SM2_IC_ERR_PARAM;

    st->call_count++;
    if (st->fail_mode)
        return SM2_IC_ERR_CRYPTO;

    response->serial_number = serial_number;
    response->status = SM2_REV_STATUS_GOOD;
    response->this_update = 1000;
    if (serial_number == 100)
        response->next_update = 2500;
    else if (serial_number == 200)
        response->next_update = 1200;
    else
        response->next_update = 3000;
    return SM2_IC_SUCCESS;
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

static void test_revocation_ocsp_cache_eviction_policy()
{
    sm2_revocation_ctx_t ctx;
    expiry_ocsp_state_t state;
    memset(&state, 0, sizeof(state));

    TEST_ASSERT(sm2_revocation_init(&ctx, 16, 300, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(
        sm2_revocation_set_online(&ctx, true) == SM2_IC_SUCCESS, "Set Online");

    sm2_ocsp_client_cfg_t ocsp_cfg;
    memset(&ocsp_cfg, 0, sizeof(ocsp_cfg));
    ocsp_cfg.query_fn = expiry_ocsp_query;
    ocsp_cfg.user_ctx = &state;
    ocsp_cfg.timeout_ms = 100;
    ocsp_cfg.retry_count = 1;
    ocsp_cfg.cache_capacity = 2;
    TEST_ASSERT(sm2_revocation_config_ocsp(&ctx, &ocsp_cfg) == SM2_IC_SUCCESS,
        "Config OCSP");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 100, 110, &status, &source)
            == SM2_IC_SUCCESS,
        "Prime Cache Serial 100");
    TEST_ASSERT(sm2_revocation_query(&ctx, 200, 111, &status, &source)
            == SM2_IC_SUCCESS,
        "Prime Cache Serial 200");
    TEST_ASSERT(sm2_revocation_query(&ctx, 300, 112, &status, &source)
            == SM2_IC_SUCCESS,
        "Trigger Eviction");

    state.fail_mode = 1;
    TEST_ASSERT(sm2_revocation_query(&ctx, 100, 113, &status, &source)
            == SM2_IC_SUCCESS,
        "Serial 100 Should Remain Cached");
    TEST_ASSERT(source == SM2_REV_SOURCE_OCSP_CACHE, "Cache Keeps Newer Entry");

    TEST_ASSERT(sm2_revocation_query(&ctx, 200, 113, &status, &source)
            == SM2_IC_SUCCESS,
        "Serial 200 Should Fall Back");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER,
        "Evicted Entry Falls Back Local");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Fallback Good");

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

static void test_revocation_cleanup_idempotent_and_param_defense()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 32, 300, 100) == SM2_IC_SUCCESS,
        "Revocation Init");

    sm2_revocation_cleanup(&ctx);
    sm2_revocation_cleanup(&ctx);

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(NULL, 1, 100, &status, &source)
            == SM2_IC_ERR_PARAM,
        "Query NULL Ctx");
    TEST_ASSERT(
        sm2_revocation_query(&ctx, 1, 100, NULL, &source) == SM2_IC_ERR_PARAM,
        "Query NULL Status");
    TEST_ASSERT(
        sm2_revocation_query(&ctx, 1, 100, &status, NULL) == SM2_IC_ERR_PARAM,
        "Query NULL Source");
    TEST_ASSERT(sm2_revocation_config_ocsp(&ctx, NULL) == SM2_IC_ERR_PARAM,
        "Config OCSP NULL");
    TEST_ASSERT(
        sm2_revocation_config_local_filter(&ctx, 0, 4, 1) == SM2_IC_ERR_PARAM,
        "Config Filter Invalid");

    TEST_PASS();
}

void run_test_cuckoo_suite(void);
void run_test_sync_suite(void);

void run_test_revoke_suite(void)
{
    run_test_cuckoo_suite();
    RUN_TEST(test_revocation_online_ocsp_and_cache);
    RUN_TEST(test_revocation_ocsp_cache_eviction_policy);
    RUN_TEST(test_revocation_online_fallback_to_local);
    RUN_TEST(test_revocation_network_jitter_sequence);
    RUN_TEST(test_revocation_ocsp_latency_sla);
    RUN_TEST(test_revocation_cleanup_idempotent_and_param_defense);
    run_test_sync_suite();
}
