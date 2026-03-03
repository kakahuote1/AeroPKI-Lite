/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

static void test_auth_precompute_pool()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_PRECOMP", 12,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    sm2_auth_precompute_pool_t pool;
    TEST_ASSERT(
        sm2_auth_precompute_pool_init(&pool, &user_priv, 256) == SM2_IC_SUCCESS,
        "Pool Init");
    TEST_ASSERT(sm2_auth_precompute_pool_fill(&pool, 256) == SM2_IC_SUCCESS,
        "Pool Fill");
    TEST_ASSERT(
        sm2_auth_precompute_pool_available(&pool) == 256, "Pool Available");

    const uint8_t msg[] = "PRECOMPUTE_SIGN_MESSAGE";
    sm2_auth_signature_t sig;
    TEST_ASSERT(sm2_auth_sign_with_pool(&pool, msg, sizeof(msg) - 1, &sig)
            == SM2_IC_SUCCESS,
        "Sign Pool");
    TEST_ASSERT(sm2_auth_verify_signature(&user_pub, msg, sizeof(msg) - 1, &sig)
            == SM2_IC_SUCCESS,
        "Verify Sig");

    const int rounds = 200;
    clock_t start_pool = clock();
    for (int i = 0; i < rounds; i++)
    {
        uint8_t m[32];
        memset(m, (uint8_t)i, sizeof(m));
        TEST_ASSERT(sm2_auth_sign_with_pool(&pool, m, sizeof(m), &sig)
                == SM2_IC_SUCCESS,
            "Loop Sign Pool");
    }
    double avg_pool_ms
        = ((double)(clock() - start_pool)) / CLOCKS_PER_SEC * 1000.0 / rounds;

    clock_t start_plain = clock();
    for (int i = 0; i < rounds; i++)
    {
        uint8_t m[32];
        memset(m, (uint8_t)i, sizeof(m));
        TEST_ASSERT(
            sm2_auth_sign(&user_priv, m, sizeof(m), &sig) == SM2_IC_SUCCESS,
            "Loop Sign Plain");
    }
    double avg_plain_ms
        = ((double)(clock() - start_plain)) / CLOCKS_PER_SEC * 1000.0 / rounds;
    printf("   [AUTH-PRECOMP] pool=%.4f ms, plain=%.4f ms\n", avg_pool_ms,
        avg_plain_ms);

    TEST_ASSERT(avg_pool_ms <= avg_plain_ms * 1.5, "Pool Sign Too Slow");
    sm2_auth_precompute_pool_cleanup(&pool);
    TEST_PASS();
}

static void test_auth_batch_verify()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_BATCH", 10,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    const size_t n = 256;
    sm2_auth_signature_t *sigs
        = (sm2_auth_signature_t *)calloc(n, sizeof(sm2_auth_signature_t));
    uint8_t *msgs = (uint8_t *)calloc(n * 16, sizeof(uint8_t));
    sm2_auth_verify_item_t *items
        = (sm2_auth_verify_item_t *)calloc(n, sizeof(sm2_auth_verify_item_t));
    TEST_ASSERT(sigs && msgs && items, "Alloc Batch Buffers");

    for (size_t i = 0; i < n; i++)
    {
        memset(msgs + i * 16, (int)i, 16);
        TEST_ASSERT(sm2_auth_sign(&user_priv, msgs + i * 16, 16, &sigs[i])
                == SM2_IC_SUCCESS,
            "Sign");
        items[i].public_key = &user_pub;
        items[i].message = msgs + i * 16;
        items[i].message_len = 16;
        items[i].signature = &sigs[i];
    }

    size_t valid_count = 0;
    clock_t start_batch = clock();
    TEST_ASSERT(sm2_auth_batch_verify(items, n, &valid_count) == SM2_IC_SUCCESS,
        "Batch Verify");
    double batch_ms
        = ((double)(clock() - start_batch)) / CLOCKS_PER_SEC * 1000.0;
    TEST_ASSERT(valid_count == n, "Batch Valid Count");

    clock_t start_single = clock();
    size_t single_ok = 0;
    for (size_t i = 0; i < n; i++)
    {
        if (sm2_auth_verify_signature(&user_pub, msgs + i * 16, 16, &sigs[i])
            == SM2_IC_SUCCESS)
            single_ok++;
    }
    double single_ms
        = ((double)(clock() - start_single)) / CLOCKS_PER_SEC * 1000.0;
    printf(
        "   [AUTH-BATCH] batch=%.4f ms, single=%.4f ms\n", batch_ms, single_ms);
    TEST_ASSERT(single_ok == n, "Single Verify Count");
    TEST_ASSERT(batch_ms <= single_ms * 1.5, "Batch Verify Too Slow");

    /* tamper one signature and ensure batch detects */
    sigs[0].der[0] ^= 0xFF;
    TEST_ASSERT(
        sm2_auth_batch_verify(items, n, &valid_count) == SM2_IC_ERR_VERIFY,
        "Batch Tamper Detect");

    free(items);
    free(msgs);
    free(sigs);
    TEST_PASS();
}

static void test_auth_cleanup_idempotent_and_param_defense()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_auth_precompute_pool_t pool;
    TEST_ASSERT(
        sm2_auth_precompute_pool_init(&pool, &g_ca_priv, 8) == SM2_IC_SUCCESS,
        "Pool Init");
    TEST_ASSERT(
        sm2_auth_precompute_pool_fill(&pool, 4) == SM2_IC_SUCCESS, "Pool Fill");

    sm2_auth_precompute_pool_cleanup(&pool);
    TEST_ASSERT(pool.slots == NULL, "Cleanup Reset Slots");
    TEST_ASSERT(pool.native_sign_key == NULL, "Cleanup Reset Native");
    TEST_ASSERT(pool.available == 0, "Cleanup Reset Available");

    sm2_auth_precompute_pool_cleanup(&pool);
    TEST_ASSERT(pool.slots == NULL, "Cleanup Idempotent Slots");
    TEST_ASSERT(pool.native_sign_key == NULL, "Cleanup Idempotent Native");

    TEST_ASSERT(
        sm2_auth_precompute_pool_init(NULL, &g_ca_priv, 8) == SM2_IC_ERR_PARAM,
        "Pool Init NULL");
    TEST_ASSERT(sm2_auth_precompute_pool_fill(NULL, 1) == SM2_IC_ERR_PARAM,
        "Pool Fill NULL");
    TEST_ASSERT(
        sm2_auth_sign(NULL, (const uint8_t *)"A", 1, NULL) == SM2_IC_ERR_PARAM,
        "Sign NULL");
    TEST_ASSERT(sm2_auth_verify_signature(NULL, (const uint8_t *)"A", 1, NULL)
            == SM2_IC_ERR_PARAM,
        "Verify NULL");

    TEST_PASS();
}

static void test_auth_cross_domain_unified()
{
    sm2_private_key_t ca1_priv, ca2_priv;
    sm2_ec_point_t ca1_pub, ca2_pub;
    TEST_ASSERT(
        sm2_ic_generate_random(ca1_priv.d, 32) == SM2_IC_SUCCESS, "CA1 Rand");
    TEST_ASSERT(
        sm2_ic_generate_random(ca2_priv.d, 32) == SM2_IC_SUCCESS, "CA2 Rand");
    TEST_ASSERT(
        sm2_ic_sm2_point_mult(&ca1_pub, ca1_priv.d, 32, NULL) == SM2_IC_SUCCESS,
        "CA1 Pub");
    TEST_ASSERT(
        sm2_ic_sm2_point_mult(&ca2_pub, ca2_priv.d, 32, NULL) == SM2_IC_SUCCESS,
        "CA2 Pub");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"CROSS_DOMAIN", 12,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_res, &req, (uint8_t *)"CA2", 3, &ca2_priv, &ca2_pub)
            == SM2_IC_SUCCESS,
        "Issue by CA2");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &ca2_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    sm2_auth_trust_store_t store;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&store) == SM2_IC_SUCCESS, "Store Init");
    TEST_ASSERT(sm2_auth_trust_store_add_ca(&store, &ca1_pub) == SM2_IC_SUCCESS,
        "Add CA1");
    TEST_ASSERT(sm2_auth_trust_store_add_ca(&store, &ca2_pub) == SM2_IC_SUCCESS,
        "Add CA2");

    size_t matched = 0;
    TEST_ASSERT(sm2_auth_verify_cert_with_store(
                    &cert_res.cert, &user_pub, &store, &matched)
            == SM2_IC_SUCCESS,
        "Store Verify");
    TEST_ASSERT(matched == 1, "Matched CA2 Index");

    const uint8_t msg[] = "UNIFIED_AUTH_MSG";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign");

    sm2_auth_request_t request;
    request.cert = &cert_res.cert;
    request.public_key = &user_pub;
    request.message = msg;
    request.message_len = sizeof(msg) - 1;
    request.signature = &sig;
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &store, NULL, 0, &matched)
            == SM2_IC_SUCCESS,
        "Unified Auth");

    TEST_PASS();
}

static void test_auth_mutual_and_session_key()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req_a, req_b;
    sm2_private_key_t temp_a, temp_b;
    sm2_ic_cert_result_t cert_a, cert_b;
    sm2_private_key_t priv_a, priv_b;
    sm2_ec_point_t pub_a, pub_b;

    TEST_ASSERT(sm2_ic_create_cert_request(&req_a, (uint8_t *)"DEV_A", 5,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_a)
            == SM2_IC_SUCCESS,
        "Req A");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_b, (uint8_t *)"DEV_B", 5,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_b)
            == SM2_IC_SUCCESS,
        "Req B");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_a, &req_a, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue A");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_b, &req_b, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue B");
    TEST_ASSERT(
        sm2_ic_reconstruct_keys(&priv_a, &pub_a, &cert_a, &temp_a, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon A");
    TEST_ASSERT(
        sm2_ic_reconstruct_keys(&priv_b, &pub_b, &cert_b, &temp_b, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon B");

    const uint8_t msg_a[] = "HELLO_FROM_A";
    const uint8_t msg_b[] = "HELLO_FROM_B";
    sm2_auth_signature_t sig_a, sig_b;
    TEST_ASSERT(sm2_auth_sign(&priv_a, msg_a, sizeof(msg_a) - 1, &sig_a)
            == SM2_IC_SUCCESS,
        "Sign A");
    TEST_ASSERT(sm2_auth_sign(&priv_b, msg_b, sizeof(msg_b) - 1, &sig_b)
            == SM2_IC_SUCCESS,
        "Sign B");

    sm2_auth_trust_store_t trust_a, trust_b;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust_a) == SM2_IC_SUCCESS, "Trust A Init");
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust_b) == SM2_IC_SUCCESS, "Trust B Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust_a, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust A Add");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust_b, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust B Add");

    sm2_auth_request_t a_to_b
        = { &cert_a.cert, &pub_a, msg_a, sizeof(msg_a) - 1, &sig_a };
    sm2_auth_request_t b_to_a
        = { &cert_b.cert, &pub_b, msg_b, sizeof(msg_b) - 1, &sig_b };

    uint8_t sk_a[16], sk_b[16];
    TEST_ASSERT(
        sm2_auth_mutual_auth_and_key_agreement(&a_to_b, &priv_a, &trust_b, NULL,
            &b_to_a, &priv_b, &trust_a, NULL, 1000, sk_a, sk_b, sizeof(sk_a))
            == SM2_IC_SUCCESS,
        "Mutual Auth");
    TEST_ASSERT(memcmp(sk_a, sk_b, sizeof(sk_a)) == 0, "Session Key Equal");

    TEST_PASS();
}

static void test_auth_session_sm4_protect()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req_a, req_b;
    sm2_private_key_t temp_a, temp_b;
    sm2_ic_cert_result_t cert_a, cert_b;
    sm2_private_key_t priv_a, priv_b;
    sm2_ec_point_t pub_a, pub_b;

    TEST_ASSERT(sm2_ic_create_cert_request(&req_a, (uint8_t *)"SM4_A", 5,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_a)
            == SM2_IC_SUCCESS,
        "Req A");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_b, (uint8_t *)"SM4_B", 5,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_b)
            == SM2_IC_SUCCESS,
        "Req B");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_a, &req_a, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue A");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_b, &req_b, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue B");
    TEST_ASSERT(
        sm2_ic_reconstruct_keys(&priv_a, &pub_a, &cert_a, &temp_a, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon A");
    TEST_ASSERT(
        sm2_ic_reconstruct_keys(&priv_b, &pub_b, &cert_b, &temp_b, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon B");

    const uint8_t msg_a[] = "SM4_HELLO_A";
    const uint8_t msg_b[] = "SM4_HELLO_B";
    sm2_auth_signature_t sig_a, sig_b;
    TEST_ASSERT(sm2_auth_sign(&priv_a, msg_a, sizeof(msg_a) - 1, &sig_a)
            == SM2_IC_SUCCESS,
        "Sign A");
    TEST_ASSERT(sm2_auth_sign(&priv_b, msg_b, sizeof(msg_b) - 1, &sig_b)
            == SM2_IC_SUCCESS,
        "Sign B");

    sm2_auth_trust_store_t trust_a, trust_b;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust_a) == SM2_IC_SUCCESS, "Trust A Init");
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust_b) == SM2_IC_SUCCESS, "Trust B Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust_a, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust A Add");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust_b, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust B Add");

    sm2_auth_request_t a_to_b
        = { &cert_a.cert, &pub_a, msg_a, sizeof(msg_a) - 1, &sig_a };
    sm2_auth_request_t b_to_a
        = { &cert_b.cert, &pub_b, msg_b, sizeof(msg_b) - 1, &sig_b };

    uint8_t sk_a[16], sk_b[16];
    TEST_ASSERT(
        sm2_auth_mutual_auth_and_key_agreement(&a_to_b, &priv_a, &trust_b, NULL,
            &b_to_a, &priv_b, &trust_a, NULL, 1000, sk_a, sk_b, sizeof(sk_a))
            == SM2_IC_SUCCESS,
        "Mutual Auth");
    TEST_ASSERT(memcmp(sk_a, sk_b, sizeof(sk_a)) == 0, "Session Key Equal");

    uint8_t iv[16];
    for (size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (uint8_t)i;

    const uint8_t plain[] = "PHASE3_SM4_PROTECTED_PAYLOAD";
    uint8_t cipher[sizeof(plain)];
    size_t cipher_len = sizeof(cipher);
    TEST_ASSERT(sm2_auth_sm4_encrypt(
                    sk_a, iv, plain, sizeof(plain) - 1, cipher, &cipher_len)
            == SM2_IC_SUCCESS,
        "SM4 Encrypt");
    TEST_ASSERT(cipher_len == sizeof(plain) - 1, "Cipher Len");
    TEST_ASSERT(memcmp(cipher, plain, sizeof(plain) - 1) != 0, "Cipher Diff");

    uint8_t recovered[sizeof(plain)];
    size_t recovered_len = sizeof(recovered);
    TEST_ASSERT(sm2_auth_sm4_decrypt(
                    sk_b, iv, cipher, cipher_len, recovered, &recovered_len)
            == SM2_IC_SUCCESS,
        "SM4 Decrypt");
    TEST_ASSERT(recovered_len == sizeof(plain) - 1, "Recover Len");
    TEST_ASSERT(
        memcmp(recovered, plain, sizeof(plain) - 1) == 0, "Recover Plain");

    TEST_PASS();
}

static void test_auth_phase3_perf_targets()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_PERF", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    enum
    {
        perf_rounds = 5,
        sample_count = 64,
        burst_ops = 8,
        total_ops = sample_count * burst_ops
    };
    sm2_auth_signature_t sig;
    uint8_t msg[32];
    double tp_gain_samples[perf_rounds];
    double p95_pool_samples[perf_rounds];
    double p95_plain_samples[perf_rounds];
    double p95_reduction_samples[perf_rounds];

    for (int r = 0; r < perf_rounds; r++)
    {
        sm2_auth_precompute_pool_t pool;
        TEST_ASSERT(sm2_auth_precompute_pool_init(&pool, &user_priv, total_ops)
                == SM2_IC_SUCCESS,
            "Pool Init");
        TEST_ASSERT(
            sm2_auth_precompute_pool_fill(&pool, total_ops) == SM2_IC_SUCCESS,
            "Pool Fill");

        double tp_pool_start = now_ms_highres();
        for (int i = 0; i < total_ops; i++)
        {
            memset(msg, (uint8_t)(i & 0xFF), sizeof(msg));
            TEST_ASSERT(sm2_auth_sign_with_pool(&pool, msg, sizeof(msg), &sig)
                    == SM2_IC_SUCCESS,
                "TP Pool Sign");
        }
        double tp_pool_ms = now_ms_highres() - tp_pool_start;
        sm2_auth_precompute_pool_cleanup(&pool);

        double tp_plain_start = now_ms_highres();
        for (int i = 0; i < total_ops; i++)
        {
            memset(msg, (uint8_t)(i & 0xFF), sizeof(msg));
            TEST_ASSERT(sm2_auth_sign(&user_priv, msg, sizeof(msg), &sig)
                    == SM2_IC_SUCCESS,
                "TP Plain Sign");
        }
        TEST_ASSERT(sm2_auth_verify_signature(&user_pub, msg, sizeof(msg), &sig)
                == SM2_IC_SUCCESS,
            "TP Verify");
        double tp_plain_ms = now_ms_highres() - tp_plain_start;
        TEST_ASSERT(tp_pool_ms > 0.0, "Pool Time Zero");
        tp_gain_samples[r] = tp_plain_ms / tp_pool_ms;

        TEST_ASSERT(sm2_auth_precompute_pool_init(&pool, &user_priv, total_ops)
                == SM2_IC_SUCCESS,
            "Pool2 Init");
        TEST_ASSERT(
            sm2_auth_precompute_pool_fill(&pool, total_ops) == SM2_IC_SUCCESS,
            "Pool2 Fill");

        double pool_lat[sample_count];
        double plain_lat[sample_count];
        for (int s = 0; s < sample_count; s++)
        {
            double t0 = now_ms_highres();
            for (int j = 0; j < burst_ops; j++)
            {
                memset(msg, (uint8_t)((s * burst_ops + j) & 0xFF), sizeof(msg));
                TEST_ASSERT(
                    sm2_auth_sign_with_pool(&pool, msg, sizeof(msg), &sig)
                        == SM2_IC_SUCCESS,
                    "P95 Pool Sign");
            }
            pool_lat[s] = (now_ms_highres() - t0) / burst_ops;
        }
        sm2_auth_precompute_pool_cleanup(&pool);

        for (int s = 0; s < sample_count; s++)
        {
            double t0 = now_ms_highres();
            for (int j = 0; j < burst_ops; j++)
            {
                memset(msg, (uint8_t)((s * burst_ops + j) & 0xFF), sizeof(msg));
                TEST_ASSERT(sm2_auth_sign(&user_priv, msg, sizeof(msg), &sig)
                        == SM2_IC_SUCCESS,
                    "P95 Plain Sign");
            }
            plain_lat[s] = (now_ms_highres() - t0) / burst_ops;
        }

        p95_pool_samples[r] = calc_p95_ms(pool_lat, sample_count);
        p95_plain_samples[r] = calc_p95_ms(plain_lat, sample_count);
        TEST_ASSERT(p95_plain_samples[r] > 0.0, "P95 Plain Zero");
        p95_reduction_samples[r] = (p95_plain_samples[r] - p95_pool_samples[r])
            / p95_plain_samples[r];
    }

    double throughput_gain = calc_median_value(tp_gain_samples, perf_rounds);
    double p95_pool = calc_median_value(p95_pool_samples, perf_rounds);
    double p95_plain = calc_median_value(p95_plain_samples, perf_rounds);
    double p95_reduction
        = calc_median_value(p95_reduction_samples, perf_rounds);

    printf("   [P3-PERF-MEDIAN] rounds=%d, tp_gain=%.4fx, p95_pool=%.4f ms, "
           "p95_plain=%.4f ms, p95_reduction=%.4f%%\n",
        perf_rounds, throughput_gain, p95_pool, p95_plain,
        p95_reduction * 100.0);

    TEST_ASSERT(throughput_gain >= 2.0, "Phase3 Throughput Gain < 2x");
    TEST_ASSERT(p95_reduction >= 0.30, "Phase3 P95 Reduction < 30%");
    TEST_PASS();
}

static void test_auth_with_revocation_block()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"REVOKE_AUTH", 11,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    sm2_auth_trust_store_t trust;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust) == SM2_IC_SUCCESS, "Trust Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust Add");

    sm2_revocation_ctx_t rev_ctx;
    TEST_ASSERT(sm2_revocation_init(&rev_ctx, 32, 300, 100) == SM2_IC_SUCCESS,
        "Rev Init");
    sm2_crl_delta_item_t items[] = { { cert_res.cert.serial_number, true } };
    sm2_crl_delta_t delta = { 0, 1, items, 1 };
    TEST_ASSERT(
        sm2_revocation_apply_crl_delta(&rev_ctx, &delta, 120) == SM2_IC_SUCCESS,
        "Apply Delta");

    const uint8_t msg[] = "AUTH_WITH_REVOCATION";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign");
    sm2_auth_request_t request
        = { &cert_res.cert, &user_pub, msg, sizeof(msg) - 1, &sig };
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, &rev_ctx, 130, NULL)
            == SM2_IC_ERR_VERIFY,
        "Revocation Block");

    sm2_revocation_cleanup(&rev_ctx);
    TEST_PASS();
}

void run_test_auth_suite(void)
{
    RUN_TEST(test_auth_precompute_pool);
    RUN_TEST(test_auth_batch_verify);
    RUN_TEST(test_auth_cleanup_idempotent_and_param_defense);
    RUN_TEST(test_auth_cross_domain_unified);
    RUN_TEST(test_auth_mutual_and_session_key);
    RUN_TEST(test_auth_session_sm4_protect);
    RUN_TEST(test_auth_phase3_perf_targets);
    RUN_TEST(test_auth_with_revocation_block);
}
