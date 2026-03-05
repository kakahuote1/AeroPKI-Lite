/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

typedef struct
{
    uint8_t key;
    int sign_count;
    int verify_count;
} mock_sync_sig_state_t;

static sm2_ic_error_t mock_sync_sign(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    mock_sync_sig_state_t *st = (mock_sync_sig_state_t *)user_ctx;

    uint8_t *buf = (uint8_t *)calloc(data_len + 1, 1);
    if (!buf)
        return SM2_IC_ERR_MEMORY;
    buf[0] = st->key;
    memcpy(buf + 1, data, data_len);

    uint8_t digest[SM3_DIGEST_LENGTH];
    sm2_ic_error_t ret = sm2_ic_sm3_hash(buf, data_len + 1, digest);
    free(buf);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*signature_len < SM3_DIGEST_LENGTH)
        return SM2_IC_ERR_MEMORY;
    memcpy(signature, digest, SM3_DIGEST_LENGTH);
    *signature_len = SM3_DIGEST_LENGTH;
    st->sign_count++;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t mock_sync_verify(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    if (!user_ctx || !data || !signature)
        return SM2_IC_ERR_PARAM;
    if (signature_len != SM3_DIGEST_LENGTH)
        return SM2_IC_ERR_VERIFY;

    mock_sync_sig_state_t *st = (mock_sync_sig_state_t *)user_ctx;

    uint8_t *buf = (uint8_t *)calloc(data_len + 1, 1);
    if (!buf)
        return SM2_IC_ERR_MEMORY;
    buf[0] = st->key;
    memcpy(buf + 1, data, data_len);

    uint8_t digest[SM3_DIGEST_LENGTH];
    sm2_ic_error_t ret = sm2_ic_sm3_hash(buf, data_len + 1, digest);
    free(buf);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    st->verify_count++;
    if (memcmp(digest, signature, SM3_DIGEST_LENGTH) != 0)
        return SM2_IC_ERR_VERIFY;
    return SM2_IC_SUCCESS;
}

static void test_revocation_sync_delta_roundtrip()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x5A;

    TEST_ASSERT(
        sm2_revocation_init(&a, 64, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 64, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Sync Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Sync Identity B");

    sm2_crl_delta_item_t items[] = { { 880001, true }, { 880002, true } };
    sm2_crl_delta_t d = { 0, 1, items, 2 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&a, &d, 120) == SM2_IC_SUCCESS,
        "Apply Delta A");

    sm2_rev_sync_hello_t hb;
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 130, &hb) == SM2_IC_SUCCESS, "Hello B");

    sm2_rev_sync_plan_t plan;
    TEST_ASSERT(sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS,
        "Plan A->B");
    TEST_ASSERT(plan.action == SM2_REV_SYNC_ACTION_DELTA
            || plan.action == SM2_REV_SYNC_ACTION_FULL,
        "Plan Must Export");

    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 131, 1001, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export Delta");
    TEST_ASSERT(pkt.item_count >= 1, "Packet Has Items");

    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 132, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply Delta");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&b, 880001, 133, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Synced Serial");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Synced Revoked");

    sm2_revocation_sync_packet_cleanup(&pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_param_mismatch_full_snapshot()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x6B;

    TEST_ASSERT(
        sm2_revocation_init(&a, 128, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 128, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity B");

    TEST_ASSERT(
        sm2_revocation_config_local_filter(&b, 12, 4, 500) == SM2_IC_SUCCESS,
        "B Filter Params");

    sm2_crl_delta_item_t items[] = { { 990001, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&a, &d, 120) == SM2_IC_SUCCESS,
        "Apply A");

    sm2_rev_sync_hello_t hb;
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 130, &hb) == SM2_IC_SUCCESS, "Hello B");

    sm2_rev_sync_plan_t plan;
    TEST_ASSERT(
        sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS, "Plan");
    TEST_ASSERT(!plan.compatible_params, "Params Mismatch");
    TEST_ASSERT(plan.action == SM2_REV_SYNC_ACTION_FULL, "Full Snapshot Plan");

    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 131, 2001, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export Full");
    TEST_ASSERT(pkt.full_snapshot, "Packet Full Snapshot");

    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 132, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply Full Snapshot");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&b, 990001, 133, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Full Sync");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Full Sync Revoked");

    sm2_revocation_sync_packet_cleanup(&pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_security_replay_and_tamper()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x39;

    TEST_ASSERT(
        sm2_revocation_init(&a, 64, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 64, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity B");

    sm2_crl_delta_item_t items[] = { { 777001, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&a, &d, 120) == SM2_IC_SUCCESS,
        "Apply A Delta");

    sm2_rev_sync_hello_t hb;
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 130, &hb) == SM2_IC_SUCCESS, "Hello B");
    sm2_rev_sync_plan_t plan;
    TEST_ASSERT(
        sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS, "Plan");

    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 131, 3001, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export");

    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 132, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply 1");

    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 133, mock_sync_verify, &sig_state)
            == SM2_IC_ERR_VERIFY,
        "Replay Reject");

    pkt.signature[0] ^= 0xFF;
    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 134, mock_sync_verify, &sig_state)
            == SM2_IC_ERR_VERIFY,
        "Tamper Reject");

    sm2_revocation_sync_packet_cleanup(&pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_end_to_end_auth_block()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x44;

    TEST_ASSERT(
        sm2_revocation_init(&a, 64, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 64, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity B");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"SYNC_AUTH", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Req");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue Cert");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon Keys");

    sm2_crl_delta_item_t items[] = { { cert_res.cert.serial_number, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&a, &d, 120) == SM2_IC_SUCCESS,
        "Apply A Delta");

    sm2_rev_sync_hello_t hb;
    sm2_rev_sync_plan_t plan;
    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 130, &hb) == SM2_IC_SUCCESS, "Hello B");
    TEST_ASSERT(sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS,
        "Plan A->B");
    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 131, 4001, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export");
    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 132, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply");

    const uint8_t msg[] = "SYNC_AUTH_MESSAGE";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign");

    sm2_auth_trust_store_t trust;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust) == SM2_IC_SUCCESS, "Trust Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust Add");

    sm2_auth_request_t request
        = { &cert_res.cert, &user_pub, msg, sizeof(msg) - 1, &sig };
    TEST_ASSERT(sm2_auth_authenticate_request(&request, &trust, &b, 133, NULL)
            == SM2_IC_ERR_VERIFY,
        "Synced Revoke Block");

    sm2_revocation_sync_packet_cleanup(&pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static size_t sync_packet_estimated_size(const sm2_rev_sync_packet_t *pkt)
{
    if (!pkt)
        return 0;
    return (size_t)(1 + pkt->node_id_len + 8 + 8 + 8 + 8 + 8 + 1
        + SM2_REV_SYNC_DIGEST_LEN + SM2_REV_SYNC_DIGEST_LEN + 8 + 1 + 8
        + pkt->item_count * 9);
}

static void test_revocation_sync_bidirectional_merge_converge()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x71;

    TEST_ASSERT(
        sm2_revocation_init(&a, 64, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 64, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 2048)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 2048)
            == SM2_IC_SUCCESS,
        "Identity B");

    sm2_crl_delta_item_t a_items[] = { { 710001, true } };
    sm2_crl_delta_t a_d = { 0, 1, a_items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&a, &a_d, 120) == SM2_IC_SUCCESS,
        "A Local Delta");

    sm2_crl_delta_item_t b_items[] = { { 720001, true } };
    sm2_crl_delta_t b_d = { 0, 1, b_items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&b, &b_d, 120) == SM2_IC_SUCCESS,
        "B Local Delta");

    sm2_rev_sync_hello_t hb;
    sm2_rev_sync_plan_t plan_a2b;
    sm2_rev_sync_packet_t pkt_a2b;
    memset(&pkt_a2b, 0, sizeof(pkt_a2b));
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 130, &hb) == SM2_IC_SUCCESS, "Hello B");
    TEST_ASSERT(sm2_revocation_sync_plan(&a, &hb, &plan_a2b) == SM2_IC_SUCCESS,
        "Plan A->B");
    TEST_ASSERT(plan_a2b.action == SM2_REV_SYNC_ACTION_DELTA,
        "A->B Should Delta Reconcile");
    TEST_ASSERT(plan_a2b.candidate_bucket_count > 0, "Candidate Buckets");
    TEST_ASSERT(sm2_revocation_sync_export_delta(&a, &plan_a2b, 131, 5001,
                    mock_sync_sign, &sig_state, &pkt_a2b)
            == SM2_IC_SUCCESS,
        "Export A->B");
    TEST_ASSERT(sm2_revocation_sync_apply(
                    &b, &pkt_a2b, 132, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply A->B");

    sm2_rev_sync_hello_t ha;
    sm2_rev_sync_plan_t plan_b2a;
    sm2_rev_sync_packet_t pkt_b2a;
    memset(&pkt_b2a, 0, sizeof(pkt_b2a));
    TEST_ASSERT(
        sm2_revocation_sync_hello(&a, 133, &ha) == SM2_IC_SUCCESS, "Hello A");
    TEST_ASSERT(sm2_revocation_sync_plan(&b, &ha, &plan_b2a) == SM2_IC_SUCCESS,
        "Plan B->A");
    TEST_ASSERT(sm2_revocation_sync_export_delta(&b, &plan_b2a, 134, 5002,
                    mock_sync_sign, &sig_state, &pkt_b2a)
            == SM2_IC_SUCCESS,
        "Export B->A");
    TEST_ASSERT(sm2_revocation_sync_apply(
                    &a, &pkt_b2a, 135, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply B->A");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&a, 710001, 136, &status, &source)
            == SM2_IC_SUCCESS,
        "A Query 710001");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "A Has 710001");
    TEST_ASSERT(sm2_revocation_query(&a, 720001, 136, &status, &source)
            == SM2_IC_SUCCESS,
        "A Query 720001");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "A Has 720001");
    TEST_ASSERT(sm2_revocation_query(&b, 710001, 136, &status, &source)
            == SM2_IC_SUCCESS,
        "B Query 710001");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "B Has 710001");
    TEST_ASSERT(sm2_revocation_query(&b, 720001, 136, &status, &source)
            == SM2_IC_SUCCESS,
        "B Query 720001");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "B Has 720001");

    sm2_revocation_sync_packet_cleanup(&pkt_b2a);
    sm2_revocation_sync_packet_cleanup(&pkt_a2b);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_ttl_stale_refresh()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x19;

    TEST_ASSERT(
        sm2_revocation_init(&a, 64, 120, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 64, 10, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity B");

    sm2_crl_delta_item_t items[] = { { 730001, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&a, &d, 110) == SM2_IC_SUCCESS,
        "A Local Delta");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&b, 730001, 200, &status, &source)
            == SM2_IC_SUCCESS,
        "B Query Stale");
    TEST_ASSERT(status == SM2_REV_STATUS_UNKNOWN, "B Stale Unknown");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER_STALE, "B Source Stale");

    sm2_rev_sync_hello_t hb;
    sm2_rev_sync_plan_t plan;
    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 201, &hb) == SM2_IC_SUCCESS, "Hello B");
    TEST_ASSERT(sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS,
        "Plan A->B");
    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 202, 6001, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export");
    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 203, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply");

    TEST_ASSERT(sm2_revocation_query(&b, 730001, 204, &status, &source)
            == SM2_IC_SUCCESS,
        "B Query Refreshed");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "B Refreshed Revoked");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER, "B Source Local");

    sm2_revocation_sync_packet_cleanup(&pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_fragment_and_rate_limit()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x55;

    TEST_ASSERT(
        sm2_revocation_init(&a, 128, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 128, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 2048)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 2048)
            == SM2_IC_SUCCESS,
        "Identity B");
    TEST_ASSERT(sm2_revocation_config_sync_limits(&a, 2, 5) == SM2_IC_SUCCESS,
        "Config Sync Limits");

    for (int i = 0; i < 4; i++)
    {
        sm2_crl_delta_item_t it = { (uint64_t)(740001 + i), true };
        sm2_crl_delta_t d = { (uint64_t)i, (uint64_t)(i + 1), &it, 1 };
        TEST_ASSERT(
            sm2_revocation_apply_crl_delta(&a, &d, 120 + i) == SM2_IC_SUCCESS,
            "A Local Delta");
    }

    sm2_rev_sync_hello_t hb;
    sm2_rev_sync_plan_t plan;
    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 130, &hb) == SM2_IC_SUCCESS, "Hello B");
    TEST_ASSERT(sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS,
        "Plan A->B");

    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 200, 7001, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export Frag1");
    TEST_ASSERT(pkt.has_more, "Packet Should Be Fragmented");
    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 201, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply Frag1");

    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 202, 7002, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_ERR_VERIFY,
        "Rate Limit Reject");

    uint64_t cursor = pkt.next_from_version;
    size_t frag_count = 1;
    while (pkt.has_more)
    {
        sm2_rev_sync_plan_t part_plan;
        memset(&part_plan, 0, sizeof(part_plan));
        part_plan.action = SM2_REV_SYNC_ACTION_DELTA;
        part_plan.from_version = cursor;
        part_plan.to_version = sm2_revocation_crl_version(&a);

        TEST_ASSERT(sm2_revocation_sync_export_delta(&a, &part_plan,
                        205 + (uint64_t)frag_count * 5, 7002 + frag_count,
                        mock_sync_sign, &sig_state, &pkt)
                == SM2_IC_SUCCESS,
            "Export Next Frag");
        TEST_ASSERT(
            sm2_revocation_sync_apply(&b, &pkt, 206 + (uint64_t)frag_count * 5,
                mock_sync_verify, &sig_state)
                == SM2_IC_SUCCESS,
            "Apply Next Frag");

        cursor = pkt.next_from_version;
        frag_count++;
        TEST_ASSERT(frag_count <= 4, "Fragment Count Overflow");
    }

    for (int i = 0; i < 4; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        TEST_ASSERT(sm2_revocation_query(
                        &b, (uint64_t)(740001 + i), 260, &status, &source)
                == SM2_IC_SUCCESS,
            "B Query Synced");
        TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "B Synced Revoked");
    }

    sm2_revocation_sync_packet_cleanup(&pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_metrics_rounds_bandwidth()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x33;

    TEST_ASSERT(
        sm2_revocation_init(&a, 256, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 256, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 4096)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 4096)
            == SM2_IC_SUCCESS,
        "Identity B");
    TEST_ASSERT(sm2_revocation_config_sync_limits(&a, 2, 0) == SM2_IC_SUCCESS,
        "Config Sync Limits");

    for (int i = 0; i < 6; i++)
    {
        sm2_crl_delta_item_t it = { (uint64_t)(750001 + i), true };
        sm2_crl_delta_t d = { (uint64_t)i, (uint64_t)(i + 1), &it, 1 };
        TEST_ASSERT(
            sm2_revocation_apply_crl_delta(&a, &d, 120 + i) == SM2_IC_SUCCESS,
            "A Local Delta");
    }

    size_t rounds = 0;
    size_t bytes_sent = 0;
    uint64_t now_ts = 300;

    while (rounds < 5)
    {
        sm2_rev_sync_hello_t hb;
        sm2_rev_sync_plan_t plan;
        sm2_rev_sync_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));

        TEST_ASSERT(
            sm2_revocation_sync_hello(&b, now_ts, &hb) == SM2_IC_SUCCESS,
            "Hello B");
        TEST_ASSERT(sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS,
            "Plan A->B");

        if (plan.action == SM2_REV_SYNC_ACTION_NONE)
            break;

        TEST_ASSERT(sm2_revocation_sync_export_delta(&a, &plan, now_ts + 1,
                        8000 + rounds, mock_sync_sign, &sig_state, &pkt)
                == SM2_IC_SUCCESS,
            "Export Round");

        bytes_sent += sync_packet_estimated_size(&pkt);

        TEST_ASSERT(sm2_revocation_sync_apply(
                        &b, &pkt, now_ts + 2, mock_sync_verify, &sig_state)
                == SM2_IC_SUCCESS,
            "Apply Round");

        rounds++;
        if (!pkt.has_more)
            break;

        sm2_revocation_sync_packet_cleanup(&pkt);
        now_ts += 10;
    }

    for (int i = 0; i < 6; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        TEST_ASSERT(sm2_revocation_query(
                        &b, (uint64_t)(750001 + i), 500, &status, &source)
                == SM2_IC_SUCCESS,
            "B Query Metric");
        TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "B Metric Revoked");
    }

    printf("   [SYNC-METRIC] rounds=%zu, bytes=%zu\n", rounds, bytes_sent);
    TEST_ASSERT(rounds <= 3, "Converge Rounds > 3");
    TEST_ASSERT(bytes_sent > 0, "Bandwidth Metric Invalid");

    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_bandwidth_reduction_vs_full()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x2A;

    TEST_ASSERT(
        sm2_revocation_init(&a, 256, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 256, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 4096)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 4096)
            == SM2_IC_SUCCESS,
        "Identity B");

    for (int i = 0; i < 10; i++)
    {
        sm2_crl_delta_item_t it = { (uint64_t)(760001 + i), true };
        sm2_crl_delta_t d = { (uint64_t)i, (uint64_t)(i + 1), &it, 1 };
        TEST_ASSERT(
            sm2_revocation_apply_crl_delta(&a, &d, 120 + i) == SM2_IC_SUCCESS,
            "A Local Delta");
    }

    sm2_rev_sync_hello_t hb_delta;
    memset(&hb_delta, 0, sizeof(hb_delta));
    hb_delta.sync_epoch = 1;
    hb_delta.crl_version = 8;
    memcpy(hb_delta.filter_param_hash, a.filter_param_hash,
        SM2_REV_SYNC_DIGEST_LEN);

    sm2_rev_sync_plan_t delta_plan;
    TEST_ASSERT(
        sm2_revocation_sync_plan(&a, &hb_delta, &delta_plan) == SM2_IC_SUCCESS,
        "Delta Plan");
    TEST_ASSERT(delta_plan.action == SM2_REV_SYNC_ACTION_DELTA, "Need Delta");

    sm2_rev_sync_packet_t delta_pkt;
    memset(&delta_pkt, 0, sizeof(delta_pkt));
    TEST_ASSERT(sm2_revocation_sync_export_delta(&a, &delta_plan, 200, 9001,
                    mock_sync_sign, &sig_state, &delta_pkt)
            == SM2_IC_SUCCESS,
        "Export Delta");
    size_t delta_bytes = sync_packet_estimated_size(&delta_pkt);

    sm2_rev_sync_hello_t hb_full;
    memset(&hb_full, 0, sizeof(hb_full));
    hb_full.sync_epoch = 1;
    hb_full.crl_version = 8;
    memset(hb_full.filter_param_hash, 0xFF, SM2_REV_SYNC_DIGEST_LEN);

    sm2_rev_sync_plan_t full_plan;
    TEST_ASSERT(
        sm2_revocation_sync_plan(&a, &hb_full, &full_plan) == SM2_IC_SUCCESS,
        "Full Plan");
    TEST_ASSERT(full_plan.action == SM2_REV_SYNC_ACTION_FULL, "Need Full");

    sm2_rev_sync_packet_t full_pkt;
    memset(&full_pkt, 0, sizeof(full_pkt));
    TEST_ASSERT(sm2_revocation_sync_export_delta(&a, &full_plan, 210, 9002,
                    mock_sync_sign, &sig_state, &full_pkt)
            == SM2_IC_SUCCESS,
        "Export Full");
    size_t full_bytes = sync_packet_estimated_size(&full_pkt);

    double ratio = full_bytes == 0 ? 1.0 : ((double)delta_bytes / full_bytes);
    printf("   [SYNC-BW] delta=%zu, full=%zu, ratio=%.4f\n", delta_bytes,
        full_bytes, ratio);

    TEST_ASSERT(full_bytes > 0, "Full Bytes Invalid");
    TEST_ASSERT(delta_bytes < full_bytes, "Delta Not Smaller Than Full");
    TEST_ASSERT(ratio <= 0.70, "Bandwidth Reduction < 30%");

    sm2_revocation_sync_packet_cleanup(&full_pkt);
    sm2_revocation_sync_packet_cleanup(&delta_pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_constrained_fpr_after_sync()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x6D;

    TEST_ASSERT(
        sm2_revocation_init(&a, 512, 3600, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 512, 3600, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(
        sm2_revocation_config_local_filter(&a, 12, 4, 500) == SM2_IC_SUCCESS,
        "A Constrained Filter");
    TEST_ASSERT(
        sm2_revocation_config_local_filter(&b, 12, 4, 500) == SM2_IC_SUCCESS,
        "B Constrained Filter");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 4096)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &b, (const uint8_t *)"NODE_B", 6, 1, 4096)
            == SM2_IC_SUCCESS,
        "Identity B");

    enum
    {
        revoked_n = 300
    };
    sm2_crl_delta_item_t *items = (sm2_crl_delta_item_t *)calloc(
        revoked_n, sizeof(sm2_crl_delta_item_t));
    TEST_ASSERT(items != NULL, "Alloc Delta Items");
    for (int i = 0; i < revoked_n; i++)
    {
        items[i].serial_number = (uint64_t)(770000 + i);
        items[i].revoked = true;
    }
    sm2_crl_delta_t d = { 0, 1, items, revoked_n };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&a, &d, 120) == SM2_IC_SUCCESS,
        "Apply A Delta");

    sm2_rev_sync_hello_t hb;
    sm2_rev_sync_plan_t plan;
    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 130, &hb) == SM2_IC_SUCCESS, "Hello B");
    TEST_ASSERT(
        sm2_revocation_sync_plan(&a, &hb, &plan) == SM2_IC_SUCCESS, "Plan");
    TEST_ASSERT(sm2_revocation_sync_export_delta(
                    &a, &plan, 131, 9101, mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export");
    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 132, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply");

    enum
    {
        query_n = 50000
    };
    int false_positive = 0;
    for (int i = 0; i < query_n; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        uint64_t serial = (uint64_t)(990000 + i);
        TEST_ASSERT(sm2_revocation_query(&b, serial, 200, &status, &source)
                == SM2_IC_SUCCESS,
            "Constrained Query");
        if (status == SM2_REV_STATUS_REVOKED)
            false_positive++;
    }

    double fpr = (double)false_positive / (double)query_n;
    printf("   [SYNC-FPR-CONSTRAINED] fp=%d/%d (%.6f)\n", false_positive,
        query_n, fpr);

    TEST_ASSERT(fpr <= 0.05, "Constrained Sync FPR > 5%");

    sm2_revocation_sync_packet_cleanup(&pkt);
    free(items);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_log_ring_window_stability()
{
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    mock_sync_sig_state_t sig_state;
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x7C;

    TEST_ASSERT(
        sm2_revocation_init(&a, 256, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(
        sm2_revocation_init(&b, 256, 300, 100) == SM2_IC_SUCCESS, "Init B");
    TEST_ASSERT(
        sm2_revocation_set_sync_identity(&a, (const uint8_t *)"NODE_A", 6, 1, 8)
            == SM2_IC_SUCCESS,
        "Identity A");
    TEST_ASSERT(
        sm2_revocation_set_sync_identity(&b, (const uint8_t *)"NODE_B", 6, 1, 8)
            == SM2_IC_SUCCESS,
        "Identity B");

    for (int i = 0; i < 40; i++)
    {
        sm2_crl_delta_item_t it = { (uint64_t)(780000 + i + 1), true };
        sm2_crl_delta_t d = { (uint64_t)i, (uint64_t)(i + 1), &it, 1 };
        TEST_ASSERT(
            sm2_revocation_apply_crl_delta(&a, &d, 110 + i) == SM2_IC_SUCCESS,
            "Append Delta");
    }

    for (int i = 0; i < 32; i++)
    {
        sm2_crl_delta_item_t it = { (uint64_t)(780000 + i + 1), true };
        sm2_crl_delta_t d = { (uint64_t)i, (uint64_t)(i + 1), &it, 1 };
        TEST_ASSERT(
            sm2_revocation_apply_crl_delta(&b, &d, 110 + i) == SM2_IC_SUCCESS,
            "Warmup B Base");
    }

    sm2_rev_sync_hello_t hb_recent;
    TEST_ASSERT(
        sm2_revocation_sync_hello(&b, 299, &hb_recent) == SM2_IC_SUCCESS,
        "Hello Recent B");
    TEST_ASSERT(hb_recent.crl_version == 32, "B Base Version");

    sm2_rev_sync_plan_t plan_recent;
    TEST_ASSERT(sm2_revocation_sync_plan(&a, &hb_recent, &plan_recent)
            == SM2_IC_SUCCESS,
        "Plan Recent");
    TEST_ASSERT(plan_recent.action == SM2_REV_SYNC_ACTION_DELTA,
        "Recent Version Should Delta");

    sm2_rev_sync_hello_t hb_old;
    memset(&hb_old, 0, sizeof(hb_old));
    hb_old.sync_epoch = 1;
    hb_old.crl_version = 10;
    memcpy(
        hb_old.filter_param_hash, a.filter_param_hash, SM2_REV_SYNC_DIGEST_LEN);

    sm2_rev_sync_plan_t plan_old;
    TEST_ASSERT(
        sm2_revocation_sync_plan(&a, &hb_old, &plan_old) == SM2_IC_SUCCESS,
        "Plan Old");
    TEST_ASSERT(
        plan_old.action == SM2_REV_SYNC_ACTION_FULL, "Old Version Should Full");

    sm2_rev_sync_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    TEST_ASSERT(sm2_revocation_sync_export_delta(&a, &plan_recent, 300, 10001,
                    mock_sync_sign, &sig_state, &pkt)
            == SM2_IC_SUCCESS,
        "Export Recent Delta");
    TEST_ASSERT(
        sm2_revocation_sync_apply(&b, &pkt, 301, mock_sync_verify, &sig_state)
            == SM2_IC_SUCCESS,
        "Apply Recent Delta");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&b, 780040, 302, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Synced Tail");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Tail Revoked");

    sm2_revocation_sync_packet_cleanup(&pkt);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

static void test_revocation_sync_adaptive_bucket_summary()
{
    sm2_revocation_ctx_t a;
    TEST_ASSERT(
        sm2_revocation_init(&a, 4096, 300, 100) == SM2_IC_SUCCESS, "Init A");
    TEST_ASSERT(sm2_revocation_set_sync_identity(
                    &a, (const uint8_t *)"NODE_A", 6, 1, 1024)
            == SM2_IC_SUCCESS,
        "Identity A");

    sm2_rev_sync_hello_t hello_default;
    TEST_ASSERT(
        sm2_revocation_sync_hello(&a, 120, &hello_default) == SM2_IC_SUCCESS,
        "Hello Default");
    TEST_ASSERT(hello_default.bucket_count > 32, "Need Large Bucket Count");

    TEST_ASSERT(sm2_revocation_config_sync_limits(&a, 64, 0) == SM2_IC_SUCCESS,
        "Config Wide Budget");
    sm2_rev_sync_hello_t hello_wide;
    TEST_ASSERT(
        sm2_revocation_sync_hello(&a, 121, &hello_wide) == SM2_IC_SUCCESS,
        "Hello Wide");
    TEST_ASSERT(
        hello_wide.bucket_summary_count > 32, "Adaptive Summary Should Expand");

    TEST_ASSERT(sm2_revocation_config_sync_limits(&a, 4, 0) == SM2_IC_SUCCESS,
        "Config Tight Budget");
    sm2_rev_sync_hello_t hello_tight;
    TEST_ASSERT(
        sm2_revocation_sync_hello(&a, 122, &hello_tight) == SM2_IC_SUCCESS,
        "Hello Tight");

    TEST_ASSERT(hello_tight.bucket_summary_count <= 32,
        "Tight Budget Should Shrink Summary");

    sm2_revocation_cleanup(&a);
    TEST_PASS();
}

void run_test_sync_suite(void)
{
    RUN_TEST(test_revocation_sync_delta_roundtrip);
    RUN_TEST(test_revocation_sync_param_mismatch_full_snapshot);
    RUN_TEST(test_revocation_sync_security_replay_and_tamper);
    RUN_TEST(test_revocation_sync_end_to_end_auth_block);
    RUN_TEST(test_revocation_sync_bidirectional_merge_converge);
    RUN_TEST(test_revocation_sync_ttl_stale_refresh);
    RUN_TEST(test_revocation_sync_fragment_and_rate_limit);
    RUN_TEST(test_revocation_sync_metrics_rounds_bandwidth);
    RUN_TEST(test_revocation_sync_bandwidth_reduction_vs_full);
    RUN_TEST(test_revocation_sync_constrained_fpr_after_sync);
    RUN_TEST(test_revocation_sync_log_ring_window_stability);
    RUN_TEST(test_revocation_sync_adaptive_bucket_summary);
}
