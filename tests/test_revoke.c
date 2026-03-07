/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

typedef struct
{
    sm2_rev_status_t status;
    uint64_t last_serial;
    int call_count;
} mock_merkle_query_state_t;

static sm2_ic_error_t mock_merkle_query(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status)
{
    (void)now_ts;
    if (!cert || !user_ctx || !status)
        return SM2_IC_ERR_PARAM;

    mock_merkle_query_state_t *st = (mock_merkle_query_state_t *)user_ctx;
    st->call_count++;
    st->last_serial = cert->serial_number;
    *status = st->status;
    return SM2_IC_SUCCESS;
}

static void test_revocation_merkle_query_callback_priority(void)
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 32, 120, 100) == SM2_IC_SUCCESS,
        "Revocation Init");

    sm2_crl_delta_item_t items[] = { { 7777, true } };
    sm2_crl_delta_t delta = { 0, 1, items, 1 };
    TEST_ASSERT(
        sm2_revocation_apply_crl_delta(&ctx, &delta, 110) == SM2_IC_SUCCESS,
        "Apply Delta");

    mock_merkle_query_state_t merkle_state;
    memset(&merkle_state, 0, sizeof(merkle_state));
    merkle_state.status = SM2_REV_STATUS_GOOD;

    TEST_ASSERT(
        sm2_revocation_set_merkle_query(&ctx, mock_merkle_query, &merkle_state)
            == SM2_IC_SUCCESS,
        "Set Merkle Callback");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 7777, 120, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Merkle Callback");
    TEST_ASSERT(source == SM2_REV_SOURCE_MERKLE_NODE, "Source Merkle Node");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Merkle Callback Override");
    TEST_ASSERT(merkle_state.call_count == 1, "Merkle Callback Call Count");
    TEST_ASSERT(merkle_state.last_serial == 7777, "Merkle Callback Serial");

    TEST_ASSERT(
        sm2_revocation_set_merkle_query(&ctx, NULL, NULL) == SM2_IC_SUCCESS,
        "Clear Merkle Callback");
    status = SM2_REV_STATUS_GOOD;
    source = SM2_REV_SOURCE_MERKLE_NODE;
    TEST_ASSERT(sm2_revocation_query(&ctx, 7777, 120, &status, &source)
            == SM2_IC_ERR_VERIFY,
        "Query Without Callback Must Reject");
    TEST_ASSERT(source == SM2_REV_SOURCE_NONE, "Source None After Reject");
    TEST_ASSERT(
        status == SM2_REV_STATUS_UNKNOWN, "Status Unknown After Reject");

    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_cleanup_idempotent_and_param_defense(void)
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
    TEST_ASSERT(sm2_revocation_set_merkle_query(NULL, mock_merkle_query, &ctx)
            == SM2_IC_ERR_PARAM,
        "Set Merkle Callback NULL Ctx");

    TEST_PASS();
}

void run_test_merkle_suite(void);

void run_test_revoke_suite(void)
{
    RUN_TEST(test_revocation_merkle_query_callback_priority);
    RUN_TEST(test_revocation_cleanup_idempotent_and_param_defense);
    run_test_merkle_suite();
}
