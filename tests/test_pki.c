/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static void test_x509_real_baseline_size()
{
    if (!g_ca_initialized)
        test_setup_ca();

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    TEST_ASSERT(kctx != NULL, "RSA Keygen Ctx");
    TEST_ASSERT(EVP_PKEY_keygen_init(kctx) == 1, "RSA Keygen Init");
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) == 1, "RSA Bits");
    TEST_ASSERT(EVP_PKEY_keygen(kctx, &pkey) == 1, "RSA Keygen");

    X509 *cert = X509_new();
    TEST_ASSERT(cert != NULL, "X509 New");
    TEST_ASSERT(X509_set_version(cert, 2) == 1, "Set Version");
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    TEST_ASSERT(
        X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL, "NotBefore");
    TEST_ASSERT(X509_gmtime_adj(X509_get_notAfter(cert), 31536000L) != NULL,
        "NotAfter");
    TEST_ASSERT(X509_set_pubkey(cert, pkey) == 1, "Set PubKey");

    X509_NAME *name = X509_get_subject_name(cert);
    TEST_ASSERT(name != NULL, "Get Subject");
    TEST_ASSERT(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                    (const unsigned char *)"BASELINE", -1, -1, 0)
            == 1,
        "Set CN");
    TEST_ASSERT(X509_set_issuer_name(cert, name) == 1, "Set Issuer");
    TEST_ASSERT(X509_sign(cert, pkey, EVP_sha256()) > 0, "X509 Sign");

    int x509_der_len = i2d_X509(cert, NULL);
    TEST_ASSERT(x509_der_len > 0, "X509 DER Len");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    uint8_t buf[1024];
    size_t implicit_len = sizeof(buf);
    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"DER_BASE", 8,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "IC Req");
    TEST_ASSERT(sm2_ic_ca_generate_cert(
                    &res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "IC Issue");
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &implicit_len, &res.cert)
            == SM2_IC_SUCCESS,
        "IC Encode");

    double ratio = (double)implicit_len / (double)x509_der_len;
    printf("   [X509-BASELINE] implicit=%zu, x509_der=%d, ratio=%.4f%%\n",
        implicit_len, x509_der_len, ratio * 100.0);
    TEST_ASSERT(ratio <= 0.30, "Implicit/X509 Ratio > 30%");

    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    TEST_PASS();
}

static void test_phase4_service_client_flow()
{
    sm2_pki_service_ctx_t service;
    const uint8_t issuer[] = "PHASE4_CA";
    TEST_ASSERT(sm2_pki_service_init(
                    &service, issuer, sizeof(issuer) - 1, 64, 300, 1000)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "AIRCRAFT_A";
    TEST_ASSERT(sm2_pki_identity_register(&service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(sm2_pki_cert_request(
                    &service, identity, sizeof(identity) - 1, &req, &temp_priv)
            == SM2_PKI_SUCCESS,
        "Cert Request");
    TEST_ASSERT(
        sm2_pki_cert_issue(&service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(&service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t client;
    TEST_ASSERT(sm2_pki_client_init(&client, &ca_pub, &service.rev_ctx)
            == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(&client, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Cert");
    TEST_ASSERT(
        sm2_pki_client_enable_precompute(&client, 64, 32) == SM2_PKI_SUCCESS,
        "Enable Precompute");

    const uint8_t msg[] = "PHASE4_FLOW_MESSAGE";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(&client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "PKI Sign");

    sm2_auth_request_t request
        = { &client.cert, &client.public_key, msg, sizeof(msg) - 1, &sig };
    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(&client, &request, 1010, &matched) == SM2_PKI_SUCCESS,
        "PKI Verify");
    TEST_ASSERT(matched == 0, "Matched Default CA");

    sm2_auth_verify_item_t item
        = { &client.public_key, msg, sizeof(msg) - 1, &sig };
    size_t valid_count = 0;
    TEST_ASSERT(sm2_pki_batch_verify(&item, 1, &valid_count) == SM2_PKI_SUCCESS,
        "PKI Batch Verify");
    TEST_ASSERT(valid_count == 1, "Batch Valid 1");

    uint8_t session_key[16];
    TEST_ASSERT(sm2_pki_key_agreement(&client, &client.public_key, session_key,
                    sizeof(session_key))
            == SM2_PKI_SUCCESS,
        "Key Agreement");

    uint8_t iv[16];
    for (size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (uint8_t)(0xA0 + i);
    const uint8_t plain[] = "PHASE4_ENCRYPT";
    uint8_t cipher[sizeof(plain)];
    uint8_t recover[sizeof(plain)];
    size_t cipher_len = sizeof(cipher);
    size_t recover_len = sizeof(recover);
    TEST_ASSERT(sm2_pki_encrypt(session_key, iv, plain, sizeof(plain) - 1,
                    cipher, &cipher_len)
            == SM2_PKI_SUCCESS,
        "Encrypt");
    TEST_ASSERT(sm2_pki_decrypt(
                    session_key, iv, cipher, cipher_len, recover, &recover_len)
            == SM2_PKI_SUCCESS,
        "Decrypt");
    TEST_ASSERT(recover_len == sizeof(plain) - 1, "Recover Len");
    TEST_ASSERT(
        memcmp(recover, plain, sizeof(plain) - 1) == 0, "Recover Plain");

    sm2_pki_client_cleanup(&client);
    sm2_pki_service_cleanup(&service);
    TEST_PASS();
}

static void test_phase4_revocation_ocsp_and_cross_domain()
{
    sm2_pki_service_ctx_t svc_a;
    sm2_pki_service_ctx_t svc_b;
    const uint8_t issuer_a[] = "CA_A";
    const uint8_t issuer_b[] = "CA_B";
    TEST_ASSERT(sm2_pki_service_init(
                    &svc_a, issuer_a, sizeof(issuer_a) - 1, 64, 300, 2000)
            == SM2_PKI_SUCCESS,
        "SvcA Init");
    TEST_ASSERT(sm2_pki_service_init(
                    &svc_b, issuer_b, sizeof(issuer_b) - 1, 64, 300, 2000)
            == SM2_PKI_SUCCESS,
        "SvcB Init");

    const uint8_t id_b[] = "NODE_B";
    TEST_ASSERT(sm2_pki_identity_register(
                    &svc_b, id_b, sizeof(id_b) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Register B");

    sm2_ic_cert_request_t req_b;
    sm2_private_key_t temp_b;
    sm2_ic_cert_result_t cert_b;
    TEST_ASSERT(
        sm2_pki_cert_request(&svc_b, id_b, sizeof(id_b) - 1, &req_b, &temp_b)
            == SM2_PKI_SUCCESS,
        "Req B");
    TEST_ASSERT(sm2_pki_cert_issue(&svc_b, &req_b, &cert_b) == SM2_PKI_SUCCESS,
        "Issue B");

    sm2_ocsp_client_cfg_t ocsp_cfg;
    TEST_ASSERT(sm2_pki_service_build_ocsp_cfg(&svc_b, 100, 2, 0, &ocsp_cfg)
            == SM2_PKI_SUCCESS,
        "Build OCSP CFG");
    TEST_ASSERT(
        sm2_revocation_config_ocsp(&svc_b.rev_ctx, &ocsp_cfg) == SM2_IC_SUCCESS,
        "Config OCSP");
    TEST_ASSERT(
        sm2_revocation_set_online(&svc_b.rev_ctx, true) == SM2_IC_SUCCESS,
        "Set Online");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_pki_revoke_check(
                    &svc_b, cert_b.cert.serial_number, 2010, &status, &source)
            == SM2_PKI_SUCCESS,
        "Revoke Check Good");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Initial Good");
    TEST_ASSERT(source == SM2_REV_SOURCE_OCSP, "Source OCSP");

    sm2_ec_point_t ca_b_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(&svc_b, &ca_b_pub) == SM2_PKI_SUCCESS,
        "Get CA_B");

    sm2_pki_client_ctx_t client_b;
    TEST_ASSERT(sm2_pki_client_init(&client_b, &ca_b_pub, &svc_b.rev_ctx)
            == SM2_PKI_SUCCESS,
        "ClientB Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(&client_b, &cert_b, &temp_b, &ca_b_pub)
            == SM2_PKI_SUCCESS,
        "ClientB Import");

    sm2_ec_point_t ca_a_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(&svc_a, &ca_a_pub) == SM2_PKI_SUCCESS,
        "Get CA_A");
    sm2_pki_client_ctx_t verifier;
    TEST_ASSERT(sm2_pki_client_init(&verifier, &ca_a_pub, &svc_b.rev_ctx)
            == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(
        sm2_pki_client_add_trusted_ca(&verifier, &ca_b_pub) == SM2_PKI_SUCCESS,
        "Add Cross Domain CA");

    const uint8_t msg[] = "CROSS_DOMAIN_AUTH";
    sm2_auth_signature_t sig_b;
    TEST_ASSERT(sm2_pki_sign(&client_b, msg, sizeof(msg) - 1, &sig_b)
            == SM2_PKI_SUCCESS,
        "Sign B");
    sm2_auth_request_t req_auth = { &client_b.cert, &client_b.public_key, msg,
        sizeof(msg) - 1, &sig_b };

    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(&verifier, &req_auth, 2020, &matched) == SM2_PKI_SUCCESS,
        "Cross Verify");
    TEST_ASSERT(matched == 1, "Matched CA_B");

    TEST_ASSERT(
        sm2_pki_service_revoke_cert(&svc_b, cert_b.cert.serial_number, 2030)
            == SM2_PKI_SUCCESS,
        "Revoke B Cert");
    TEST_ASSERT(
        sm2_revocation_set_online(&svc_b.rev_ctx, false) == SM2_IC_SUCCESS,
        "Set Offline After Revoke");
    TEST_ASSERT(sm2_pki_revoke_check(
                    &svc_b, cert_b.cert.serial_number, 2040, &status, &source)
            == SM2_PKI_SUCCESS,
        "Revoke Check Revoked");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Status Revoked");

    TEST_ASSERT(sm2_pki_verify(&verifier, &req_auth, 2050, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Verify Blocked After Revoke");

    sm2_pki_client_cleanup(&verifier);
    sm2_pki_client_cleanup(&client_b);
    sm2_pki_service_cleanup(&svc_b);
    sm2_pki_service_cleanup(&svc_a);
    TEST_PASS();
}

static void test_phase4_pki_controls_and_param_defense()
{
    sm2_pki_service_ctx_t service;
    const uint8_t issuer[] = "CTRL_CA";
    TEST_ASSERT(sm2_pki_service_init(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, 3000)
            == SM2_PKI_SUCCESS,
        "Service Init");

    TEST_ASSERT(sm2_pki_service_set_cert_field_mask(NULL, SM2_IC_FIELD_MASK_ALL)
            == SM2_PKI_ERR_PARAM,
        "Set Mask NULL Ctx");
    TEST_ASSERT(sm2_pki_service_set_cert_field_mask(&service, 0xFFFF)
            == SM2_PKI_ERR_PARAM,
        "Set Mask Invalid");
    TEST_ASSERT(
        sm2_pki_service_set_cert_field_mask(&service, 0) == SM2_PKI_SUCCESS,
        "Set Mask Zero");

    const uint8_t identity[] = "CTRL_NODE";
    TEST_ASSERT(sm2_pki_identity_register(&service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(sm2_pki_cert_request(
                    &service, identity, sizeof(identity) - 1, &req, &temp_priv)
            == SM2_PKI_SUCCESS,
        "Cert Request");
    TEST_ASSERT(
        sm2_pki_cert_issue(&service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    TEST_ASSERT(cert_res.cert.field_mask == 0, "Issued Mask Zero");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(&service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t client;
    TEST_ASSERT(sm2_pki_client_init(&client, &ca_pub, &service.rev_ctx)
            == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_add_trusted_ca(&client, NULL) == SM2_PKI_ERR_PARAM,
        "Add Trusted NULL");

    TEST_ASSERT(
        sm2_pki_client_enable_precompute(&client, 32, 16) == SM2_PKI_ERR_PARAM,
        "Enable Precompute Without Keys");

    TEST_ASSERT(
        sm2_pki_client_import_cert(&client, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Cert");
    TEST_ASSERT(
        sm2_pki_client_enable_precompute(&client, 0, 0) == SM2_PKI_ERR_PARAM,
        "Enable Precompute Zero Capacity");
    TEST_ASSERT(
        sm2_pki_client_enable_precompute(&client, 32, 16) == SM2_PKI_SUCCESS,
        "Enable Precompute");

    sm2_pki_client_disable_precompute(&client);
    TEST_ASSERT(!client.precompute_enabled, "Disable Precompute");
    sm2_pki_client_disable_precompute(&client);
    TEST_ASSERT(!client.precompute_enabled, "Disable Precompute Idempotent");

    const uint8_t msg[] = "CTRL_SIGN";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(&client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Sign After Disable");

    size_t valid_count = 0;
    TEST_ASSERT(
        sm2_pki_batch_verify(NULL, 1, &valid_count) == SM2_PKI_ERR_PARAM,
        "Batch Verify NULL Items");

    uint8_t session_key[16];
    TEST_ASSERT(
        sm2_pki_key_agreement(&client, NULL, session_key, sizeof(session_key))
            == SM2_PKI_ERR_PARAM,
        "Key Agreement NULL Peer");

    uint8_t iv[16] = { 0 };
    TEST_ASSERT(sm2_pki_encrypt(
                    session_key, iv, msg, sizeof(msg) - 1, NULL, &valid_count)
            == SM2_PKI_ERR_PARAM,
        "Encrypt NULL Ciphertext");

    sm2_pki_client_cleanup(&client);
    sm2_pki_service_cleanup(&service);
    TEST_PASS();
}

void run_test_pki_suite(void)
{
    RUN_TEST(test_phase4_service_client_flow);
    RUN_TEST(test_phase4_revocation_ocsp_and_cross_domain);
    RUN_TEST(test_phase4_pki_controls_and_param_defense);
    RUN_TEST(test_x509_real_baseline_size);
}
