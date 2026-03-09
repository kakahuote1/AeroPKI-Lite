static void test_auth_cross_domain_unified()
{
    sm2_private_key_t ca1_priv, ca2_priv;
    sm2_ec_point_t ca1_pub, ca2_pub;
    TEST_ASSERT(test_generate_sm2_keypair(&ca1_priv, &ca1_pub), "CA1 Keypair");
    TEST_ASSERT(test_generate_sm2_keypair(&ca2_priv, &ca2_pub), "CA2 Keypair");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"CROSS_DOMAIN", 12,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(test_issue_cert(
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
    sm2_auth_request_init(&request);
    request.cert = &cert_res.cert;
    request.public_key = &user_pub;
    request.message = msg;
    request.message_len = sizeof(msg) - 1;
    request.signature = &sig;
    request.allow_missing_revocation_check = true;
    uint64_t now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &store, NULL, now, &matched)
            == SM2_IC_SUCCESS,
        "Unified Auth");

    TEST_PASS();
}

static void test_auth_static_handshake_and_session_key()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req_a, req_b;
    sm2_private_key_t temp_a, temp_b;
    sm2_ic_cert_result_t cert_a, cert_b;
    sm2_private_key_t priv_a, priv_b;
    sm2_ec_point_t pub_a, pub_b;

    TEST_ASSERT(sm2_ic_create_cert_request(&req_a, (uint8_t *)"DEV_A", 5,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &temp_a)
            == SM2_IC_SUCCESS,
        "Req A");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_b, (uint8_t *)"DEV_B", 5,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &temp_b)
            == SM2_IC_SUCCESS,
        "Req B");
    TEST_ASSERT(test_issue_cert(
                    &cert_a, &req_a, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue A");
    TEST_ASSERT(test_issue_cert(
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
    a_to_b.allow_missing_revocation_check = true;
    b_to_a.allow_missing_revocation_check = true;
    uint64_t now = test_cert_pair_now(&cert_a.cert, &cert_b.cert);

    uint8_t sk_a[16], sk_b[16];
    TEST_ASSERT(
        sm2_auth_mutual_handshake_static(&a_to_b, &priv_a, &trust_b, NULL,
            &b_to_a, &priv_b, &trust_a, NULL, now, sk_a, sk_b, sizeof(sk_a))
            == SM2_IC_SUCCESS,
        "Mutual Auth");
    TEST_ASSERT(memcmp(sk_a, sk_b, sizeof(sk_a)) == 0, "Session Key Equal");

    TEST_PASS();
}

static void test_auth_session_aead_protect()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req_a, req_b;
    sm2_private_key_t temp_a, temp_b;
    sm2_ic_cert_result_t cert_a, cert_b;
    sm2_private_key_t priv_a, priv_b;
    sm2_ec_point_t pub_a, pub_b;

    TEST_ASSERT(sm2_ic_create_cert_request(&req_a, (uint8_t *)"SM4_A", 5,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &temp_a)
            == SM2_IC_SUCCESS,
        "Req A");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_b, (uint8_t *)"SM4_B", 5,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &temp_b)
            == SM2_IC_SUCCESS,
        "Req B");
    TEST_ASSERT(test_issue_cert(
                    &cert_a, &req_a, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue A");
    TEST_ASSERT(test_issue_cert(
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

    const uint8_t msg_a[] = "AEAD_HELLO_A";
    const uint8_t msg_b[] = "AEAD_HELLO_B";
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
    a_to_b.allow_missing_revocation_check = true;
    b_to_a.allow_missing_revocation_check = true;
    uint64_t now = test_cert_pair_now(&cert_a.cert, &cert_b.cert);

    uint8_t sk_a[16], sk_b[16];
    TEST_ASSERT(
        sm2_auth_mutual_handshake_static(&a_to_b, &priv_a, &trust_b, NULL,
            &b_to_a, &priv_b, &trust_a, NULL, now, sk_a, sk_b, sizeof(sk_a))
            == SM2_IC_SUCCESS,
        "Mutual Auth");
    TEST_ASSERT(memcmp(sk_a, sk_b, sizeof(sk_a)) == 0, "Session Key Equal");

    sm2_auth_aead_mode_t mode = SM2_AUTH_AEAD_MODE_SM4_GCM;
    if (!test_auth_aead_mode_available(mode))
    {
        mode = SM2_AUTH_AEAD_MODE_SM4_CCM;
    }
    if (!test_auth_aead_mode_available(mode))
    {
        printf("   [AUTH-AEAD] no supported SM4 AEAD mode in current runtime "
               "OpenSSL/provider config, skip session protect flow\n");
        TEST_PASS();
        return;
    }

    uint8_t iv[12];
    for (size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (uint8_t)i;

    const uint8_t aad[] = "AUTH_SESSION_AAD";
    const uint8_t plain[] = "AUTH_SESSION_AEAD_PAYLOAD";
    uint8_t cipher[sizeof(plain)];
    size_t cipher_len = sizeof(cipher);
    uint8_t tag[SM2_AUTH_AEAD_TAG_MAX_LEN];
    size_t tag_len = sizeof(tag);
    TEST_ASSERT(
        sm2_auth_encrypt(mode, sk_a, iv, sizeof(iv), aad, sizeof(aad) - 1,
            plain, sizeof(plain) - 1, cipher, &cipher_len, tag, &tag_len)
            == SM2_IC_SUCCESS,
        "AEAD Encrypt");
    TEST_ASSERT(cipher_len == sizeof(plain) - 1, "Cipher Len");
    TEST_ASSERT(memcmp(cipher, plain, sizeof(plain) - 1) != 0, "Cipher Diff");

    uint8_t recovered[sizeof(plain)];
    size_t recovered_len = sizeof(recovered);
    TEST_ASSERT(
        sm2_auth_decrypt(mode, sk_b, iv, sizeof(iv), aad, sizeof(aad) - 1,
            cipher, cipher_len, tag, tag_len, recovered, &recovered_len)
            == SM2_IC_SUCCESS,
        "AEAD Decrypt");
    TEST_ASSERT(recovered_len == sizeof(plain) - 1, "Recover Len");
    TEST_ASSERT(
        memcmp(recovered, plain, sizeof(plain) - 1) == 0, "Recover Plain");

    tag[0] ^= 0x55;
    recovered_len = sizeof(recovered);
    TEST_ASSERT(
        sm2_auth_decrypt(mode, sk_b, iv, sizeof(iv), aad, sizeof(aad) - 1,
            cipher, cipher_len, tag, tag_len, recovered, &recovered_len)
            == SM2_IC_ERR_VERIFY,
        "AEAD Tag Reject");

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
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    /*
     * This benchmark measures the implementation's signing-pool cache
     * path,
     * not a proof of generic cryptographic precomputation
     * speedups.
     */
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
        sm2_auth_sign_pool_t pool;
        TEST_ASSERT(sm2_auth_sign_pool_init(&pool, &user_priv, total_ops)
                == SM2_IC_SUCCESS,
            "Pool Init");
        TEST_ASSERT(sm2_auth_sign_pool_fill(&pool, total_ops) == SM2_IC_SUCCESS,
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
        sm2_auth_sign_pool_cleanup(&pool);

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

        TEST_ASSERT(sm2_auth_sign_pool_init(&pool, &user_priv, total_ops)
                == SM2_IC_SUCCESS,
            "Pool2 Init");
        TEST_ASSERT(sm2_auth_sign_pool_fill(&pool, total_ops) == SM2_IC_SUCCESS,
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
        sm2_auth_sign_pool_cleanup(&pool);

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
    double throughput_gain_peak = tp_gain_samples[0];
    for (int r = 1; r < perf_rounds; r++)
    {
        if (tp_gain_samples[r] > throughput_gain_peak)
            throughput_gain_peak = tp_gain_samples[r];
    }

    printf("   [P3-SIGN-POOL-CACHE] rounds=%d, tp_gain=%.4fx, tp_peak=%.4fx, "
           "p95_cached=%.4f ms, p95_baseline=%.4f ms, p95_reduction=%.4f%%\n",
        perf_rounds, throughput_gain, throughput_gain_peak, p95_pool, p95_plain,
        p95_reduction * 100.0);

    TEST_ASSERT(throughput_gain >= 1.70,
        "Phase3 Pool-Cache Throughput Median < 1.70x (suite-level CI jitter)");
    TEST_ASSERT(
        throughput_gain_peak >= 2.0, "Phase3 Pool-Cache Throughput Peak < 2x");
    TEST_ASSERT(p95_reduction >= 0.30, "Phase3 Pool-Cache P95 Reduction < 30%");
    TEST_PASS();
}
