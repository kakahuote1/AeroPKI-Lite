static void test_phase8_merkle_hook_and_service_binding()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P8_MERKLE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P8_NODE";
    const uint8_t aux_identity[] = "P8_NODE_AUX";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");
    TEST_ASSERT(sm2_pki_identity_register(service, aux_identity,
                    sizeof(aux_identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Aux Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_private_key_t temp_aux;
    sm2_ic_cert_result_t cert_res;
    sm2_ic_cert_result_t aux_cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    TEST_ASSERT(
        pki_issue_identity_cert(service, aux_identity, sizeof(aux_identity) - 1,
            SM2_KU_DIGITAL_SIGNATURE, &aux_cert_res, &temp_aux),
        "Issue Aux Cert");
    uint64_t auth_now = test_cert_now(&cert_res.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P8_MERKLE_AUTH";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(signer, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Signer Sign");
    const sm2_implicit_cert_t *signer_cert = NULL;
    const sm2_ec_point_t *signer_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(signer, &signer_cert, &signer_pub),
        "Get Signer Material");

    sm2_pki_verify_request_t auth_req = { .cert = signer_cert,
        .public_key = signer_pub,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig };

    sm2_pki_client_ctx_t *verifier_merkle = NULL;
    TEST_ASSERT(sm2_pki_client_create(&verifier_merkle, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Verifier Merkle Init");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier_merkle, &auth_req, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Verify Without Revocation Hook Must Reject");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_res.cert.serial_number, auth_now + 100)
            == SM2_PKI_SUCCESS,
        "Revoke Serial");
    TEST_ASSERT(sm2_pki_service_revoke(
                    service, aux_cert_res.cert.serial_number, auth_now + 101)
            == SM2_PKI_SUCCESS,
        "Revoke Aux Serial");
    sm2_rev_epoch_dir_t *dir = NULL;
    size_t expected_cache_levels = 0;
    TEST_ASSERT(sm2_pki_service_export_epoch_dir(service, 88, 6,
                    auth_now > 100 ? auth_now - 100 : 0, auth_now + 1000, &dir)
            == SM2_PKI_SUCCESS,
        "Build Epoch Directory");
    expected_cache_levels = sm2_rev_epoch_dir_tree_level_count(dir) > 1
        ? sm2_rev_epoch_dir_tree_level_count(dir) - 1
        : 0;
    if (expected_cache_levels > 6)
        expected_cache_levels = 6;
    TEST_ASSERT(
        sm2_rev_epoch_dir_cache_level_count(dir) == expected_cache_levels,
        "Epoch Directory Cache Levels");
    TEST_ASSERT(sm2_rev_epoch_dir_patch_version(dir) == 0,
        "Epoch Directory Patch Version");

    pki_merkle_verify_ctx_t verify_ctx = { .ca_pub = &ca_pub };
    sm2_rev_lookup_ctx_t query_ctx;
    memset(&query_ctx, 0, sizeof(query_ctx));
    query_ctx.directory = dir;
    query_ctx.verify_fn = pki_merkle_verify_cb;
    query_ctx.verify_user_ctx = &verify_ctx;

    TEST_ASSERT(sm2_pki_client_set_revocation_query(
                    verifier_merkle, sm2_rev_epoch_lookup_cb, &query_ctx)
            == SM2_PKI_SUCCESS,
        "Set Merkle Revocation Hook");

    TEST_ASSERT(
        sm2_pki_verify(verifier_merkle, &auth_req, auth_now + 200, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Merkle Hook Blocks Revoked");

    TEST_ASSERT(sm2_pki_client_set_revocation_query(verifier_merkle, NULL, NULL)
            == SM2_PKI_SUCCESS,
        "Clear Merkle Hook");
    TEST_ASSERT(
        sm2_pki_verify(verifier_merkle, &auth_req, auth_now + 200, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Clear Hook Keeps Reject Without Query Path");

    sm2_pki_client_ctx_t *verifier_service_bound = NULL;
    TEST_ASSERT(sm2_pki_client_create(&verifier_service_bound, &ca_pub, service)
            == SM2_PKI_SUCCESS,
        "Verifier Service Bind Init");
    TEST_ASSERT(sm2_pki_verify(
                    verifier_service_bound, &auth_req, auth_now + 200, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Service Revocation Binding");

    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_pki_client_destroy(&verifier_service_bound);
    sm2_pki_client_destroy(&verifier_merkle);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase9_epoch_lookup_unknown_query_override_behavior()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P9_MERKLE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");
    const uint8_t identity[] = "P9_NODE";
    const uint8_t aux_identity_1[] = "P9_NODE_AUX1";
    const uint8_t aux_identity_2[] = "P9_NODE_AUX2";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");
    TEST_ASSERT(sm2_pki_identity_register(service, aux_identity_1,
                    sizeof(aux_identity_1) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Aux1 Identity Register");
    TEST_ASSERT(sm2_pki_identity_register(service, aux_identity_2,
                    sizeof(aux_identity_2) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Aux2 Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_private_key_t temp_aux_1;
    sm2_private_key_t temp_aux_2;
    sm2_ic_cert_result_t cert_res;
    sm2_ic_cert_result_t aux_cert_res_1;
    sm2_ic_cert_result_t aux_cert_res_2;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    TEST_ASSERT(pki_issue_identity_cert(service, aux_identity_1,
                    sizeof(aux_identity_1) - 1, SM2_KU_DIGITAL_SIGNATURE,
                    &aux_cert_res_1, &temp_aux_1),
        "Issue Aux1 Cert");
    TEST_ASSERT(pki_issue_identity_cert(service, aux_identity_2,
                    sizeof(aux_identity_2) - 1, SM2_KU_DIGITAL_SIGNATURE,
                    &aux_cert_res_2, &temp_aux_2),
        "Issue Aux2 Cert");
    uint64_t auth_now = test_cert_now(&cert_res.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P9_PATCH_FIRST_FALLBACK";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(signer, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Signer Sign");
    const sm2_implicit_cert_t *signer_cert = NULL;
    const sm2_ec_point_t *signer_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(signer, &signer_cert, &signer_pub),
        "Get Signer Material");

    sm2_pki_verify_request_t auth_req = { .cert = signer_cert,
        .public_key = signer_pub,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig };

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, aux_cert_res_1.cert.serial_number, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke Aux1 Cert");
    TEST_ASSERT(sm2_pki_service_revoke(
                    service, aux_cert_res_2.cert.serial_number, auth_now + 11)
            == SM2_PKI_SUCCESS,
        "Revoke Aux2 Cert");

    sm2_rev_epoch_dir_t *dir = NULL;
    size_t expected_cache_levels = 0;
    TEST_ASSERT(sm2_pki_service_export_epoch_dir(service, 91, 6,
                    auth_now > 100 ? auth_now - 100 : 0, auth_now + 2000, &dir)
            == SM2_PKI_SUCCESS,
        "Build Epoch Directory");
    expected_cache_levels = sm2_rev_epoch_dir_tree_level_count(dir) > 1
        ? sm2_rev_epoch_dir_tree_level_count(dir) - 1
        : 0;
    if (expected_cache_levels > 6)
        expected_cache_levels = 6;
    TEST_ASSERT(
        sm2_rev_epoch_dir_cache_level_count(dir) == expected_cache_levels,
        "Epoch Directory Cache Levels");
    TEST_ASSERT(sm2_rev_epoch_dir_patch_version(dir) == 0,
        "Epoch Directory Patch Version");

    pki_merkle_verify_ctx_t verify_ctx = { .ca_pub = &ca_pub };
    sm2_rev_lookup_ctx_t query_ctx;
    memset(&query_ctx, 0, sizeof(query_ctx));
    query_ctx.directory = dir;
    query_ctx.verify_fn = pki_merkle_verify_cb;
    query_ctx.verify_user_ctx = &verify_ctx;

    size_t matched = 0;

    sm2_pki_client_ctx_t *verifier_explicit_query = NULL;
    TEST_ASSERT(sm2_pki_client_create(&verifier_explicit_query, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Verifier Explicit Query Init");
    TEST_ASSERT(sm2_pki_client_set_revocation_query(verifier_explicit_query,
                    sm2_rev_epoch_lookup_cb, &query_ctx)
            == SM2_PKI_SUCCESS,
        "Set Epoch Lookup Hook");
    TEST_ASSERT(sm2_pki_verify(verifier_explicit_query, &auth_req,
                    auth_now + 100, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Epoch Lookup Unknown With Explicit Query Must Reject");

    sm2_pki_client_ctx_t *verifier_service_bound = NULL;
    TEST_ASSERT(sm2_pki_client_create(&verifier_service_bound, &ca_pub, service)
            == SM2_PKI_SUCCESS,
        "Verifier Service Bound Init");
    TEST_ASSERT(sm2_pki_client_set_revocation_query(
                    verifier_service_bound, sm2_rev_epoch_lookup_cb, &query_ctx)
            == SM2_PKI_SUCCESS,
        "Set Epoch Lookup Hook Replaces Service Binding");
    TEST_ASSERT(sm2_pki_verify(
                    verifier_service_bound, &auth_req, auth_now + 100, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Epoch Lookup Unknown After Query Override Must Reject");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_res.cert.serial_number, auth_now + 200)
            == SM2_PKI_SUCCESS,
        "Revoke Cert");
    TEST_ASSERT(sm2_pki_verify(
                    verifier_service_bound, &auth_req, auth_now + 300, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Query Override Must Not Re-enable Service Binding");

    sm2_pki_client_destroy(&verifier_service_bound);
    sm2_pki_client_destroy(&verifier_explicit_query);
    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}
static void test_phase93_crypto_direct_api_min_coverage()
{
    if (!g_ca_initialized)
        test_setup_ca();

    uint8_t rnd[32];
    TEST_ASSERT(
        sm2_pki_random(rnd, sizeof(rnd)) == SM2_PKI_SUCCESS, "PKI Random");
    bool any_nonzero = false;
    for (size_t i = 0; i < sizeof(rnd); i++)
    {
        if (rnd[i] != 0)
        {
            any_nonzero = true;
            break;
        }
    }
    TEST_ASSERT(any_nonzero, "PKI Random NonZero");

    const uint8_t msg[] = "PKI_DIRECT_API";
    uint8_t d1[SM3_DIGEST_LENGTH];
    uint8_t d2[SM3_DIGEST_LENGTH];
    TEST_ASSERT(sm2_pki_sm3_hash(msg, sizeof(msg) - 1, d1) == SM2_PKI_SUCCESS,
        "PKI SM3 Hash");
    TEST_ASSERT(sm2_ic_sm3_hash(msg, sizeof(msg) - 1, d2) == SM2_IC_SUCCESS,
        "IC SM3 Hash");
    TEST_ASSERT(memcmp(d1, d2, sizeof(d1)) == 0, "SM3 Hash Match");

    sm2_ic_cert_request_t req_a, req_b;
    sm2_private_key_t temp_a, temp_b;
    sm2_ic_cert_result_t cert_a, cert_b;
    sm2_private_key_t priv_a, priv_b;
    sm2_ec_point_t pub_a, pub_b;

    TEST_ASSERT(sm2_ic_create_cert_request(&req_a, (uint8_t *)"PKI_DIR_A", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_a)
            == SM2_IC_SUCCESS,
        "Create Req A");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_b, (uint8_t *)"PKI_DIR_B", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_b)
            == SM2_IC_SUCCESS,
        "Create Req B");
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

    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_crypto_sign(&priv_a, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Crypto Sign");
    TEST_ASSERT(sm2_crypto_verify(&pub_a, msg, sizeof(msg) - 1, &sig)
            == SM2_PKI_SUCCESS,
        "Crypto Verify");

    uint8_t tampered[sizeof(msg)];
    memcpy(tampered, msg, sizeof(msg));
    tampered[0] ^= 0x01;
    TEST_ASSERT(sm2_crypto_verify(&pub_a, tampered, sizeof(msg) - 1, &sig)
            == SM2_PKI_ERR_VERIFY,
        "Crypto Verify Tamper Reject");

    uint8_t sk_a[16], sk_b[16];
    TEST_ASSERT(
        sm2_auth_derive_session_key_static(&priv_a, &pub_b, sk_a, sizeof(sk_a))
            == SM2_IC_SUCCESS,
        "Direct Derive A");
    TEST_ASSERT(
        sm2_auth_derive_session_key_static(&priv_b, &pub_a, sk_b, sizeof(sk_b))
            == SM2_IC_SUCCESS,
        "Direct Derive B");
    TEST_ASSERT(memcmp(sk_a, sk_b, sizeof(sk_a)) == 0, "Derived Key Equal");

    uint8_t iv[12];
    TEST_ASSERT(
        sm2_pki_random(iv, sizeof(iv)) == SM2_PKI_SUCCESS, "AEAD IV Random");
    uint8_t cipher[sizeof(msg)];
    size_t cipher_len = sizeof(msg) - 1;
    uint8_t tag[SM2_AUTH_AEAD_TAG_MAX_LEN];
    size_t tag_len = sizeof(tag);
    int gcm_available = test_pki_sm4_gcm_available();
    sm2_pki_error_t aead_ret
        = sm2_pki_aead_encrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_a, iv, sizeof(iv),
            NULL, 0, msg, sizeof(msg) - 1, cipher, &cipher_len, tag, &tag_len);
    if (!gcm_available)
    {
        TEST_ASSERT(aead_ret == SM2_PKI_ERR_CRYPTO,
            "Unsupported GCM Must Return Crypto Err");
        printf("   [PKI-AEAD] SM4-GCM unsupported in current runtime "
               "OpenSSL/provider config, skip AEAD wrapper checks\n");
    }
    else
    {
        TEST_ASSERT(aead_ret == SM2_PKI_SUCCESS, "PKI AEAD Encrypt");

        uint8_t recover[sizeof(msg)];
        size_t recover_len = sizeof(recover);
        TEST_ASSERT(sm2_pki_aead_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b, iv,
                        sizeof(iv), NULL, 0, cipher, cipher_len, tag, tag_len,
                        recover, &recover_len)
                == SM2_PKI_SUCCESS,
            "PKI AEAD Decrypt");
        TEST_ASSERT(recover_len == sizeof(msg) - 1, "PKI AEAD Recover Len");
        TEST_ASSERT(memcmp(recover, msg, sizeof(msg) - 1) == 0,
            "PKI AEAD Recover Plain");

        tag[0] ^= 0x33;
        recover_len = sizeof(recover);
        TEST_ASSERT(sm2_pki_aead_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b, iv,
                        sizeof(iv), NULL, 0, cipher, cipher_len, tag, tag_len,
                        recover, &recover_len)
                == SM2_PKI_ERR_VERIFY,
            "PKI AEAD Tag Reject");
    }

    TEST_PASS();
}
static void test_phase11_merkle_freshness_e2e_gate()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P11_MERKLE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P11_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    uint64_t auth_now = test_cert_now(&cert_res.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P11_MERKLE_FRESH";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(signer, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Signer Sign");
    const sm2_implicit_cert_t *signer_cert = NULL;
    const sm2_ec_point_t *signer_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(signer, &signer_cert, &signer_pub),
        "Get Signer Material");

    sm2_pki_verify_request_t auth_req = { .cert = signer_cert,
        .public_key = signer_pub,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig };

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now) == SM2_PKI_SUCCESS,
        "Refresh Root");
    sm2_rev_root_record_t root_record;
    memset(&root_record, 0, sizeof(root_record));
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_record)
            == SM2_PKI_SUCCESS,
        "Get Root Record");

    pki_merkle_verify_ctx_t verify_ctx = { .ca_pub = &ca_pub };
    pki_merkle_root_query_ctx_t query_ctx;
    memset(&query_ctx, 0, sizeof(query_ctx));
    query_ctx.service = service;
    query_ctx.root_record = &root_record;
    query_ctx.verify_fn = pki_merkle_verify_cb;
    query_ctx.verify_user_ctx = &verify_ctx;

    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(sm2_pki_client_set_revocation_query(
                    verifier, pki_merkle_root_query_cb, &query_ctx)
            == SM2_PKI_SUCCESS,
        "Set Merkle Hook");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &auth_req, auth_now + 100, &matched)
            == SM2_PKI_SUCCESS,
        "Fresh Proof Allows Auth");
    TEST_ASSERT(sm2_pki_verify(verifier, &auth_req, auth_now + 400, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Expired Proof Blocks Auth");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}
