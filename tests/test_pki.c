/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
typedef struct
{
    const sm2_private_key_t *ca_priv;
    const sm2_ec_point_t *ca_pub;
} pki_merkle_sig_ctx_t;

static sm2_ic_error_t pki_merkle_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    pki_merkle_sig_ctx_t *ctx = (pki_merkle_sig_ctx_t *)user_ctx;
    if (!ctx->ca_priv)
        return SM2_IC_ERR_PARAM;

    sm2_auth_signature_t sig;
    sm2_ic_error_t ret = sm2_auth_sign(ctx->ca_priv, data, data_len, &sig);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*signature_len < sig.der_len)
        return SM2_IC_ERR_MEMORY;

    memcpy(signature, sig.der, sig.der_len);
    *signature_len = sig.der_len;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t pki_merkle_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    if (!user_ctx || !data || !signature)
        return SM2_IC_ERR_PARAM;

    pki_merkle_sig_ctx_t *ctx = (pki_merkle_sig_ctx_t *)user_ctx;
    if (!ctx->ca_pub)
        return SM2_IC_ERR_PARAM;
    if (signature_len == 0 || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
        return SM2_IC_ERR_VERIFY;

    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;

    return sm2_auth_verify_signature(ctx->ca_pub, data, data_len, &sig);
}

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
    sm2_pki_client_cleanup(&client);
    sm2_pki_service_cleanup(&service);
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

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_pki_revoke_check(
                    &svc_b, cert_b.cert.serial_number, 2010, &status, &source)
            == SM2_PKI_SUCCESS,
        "Revoke Check Good");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Initial Good");
    TEST_ASSERT(source == SM2_REV_SOURCE_MERKLE_NODE, "Source Merkle");

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
    sm2_auth_request_t req_auth = { .cert = &client_b.cert,
        .public_key = &client_b.public_key,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig_b,
        .revocation_query_fn = NULL,
        .revocation_query_user_ctx = NULL };

    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(&verifier, &req_auth, 2020, &matched) == SM2_PKI_SUCCESS,
        "Cross Verify");
    TEST_ASSERT(matched == 1, "Matched CA_B");

    TEST_ASSERT(
        sm2_pki_service_revoke_cert(&svc_b, cert_b.cert.serial_number, 2030)
            == SM2_PKI_SUCCESS,
        "Revoke B Cert");
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
    sm2_pki_client_cleanup(&client);
    sm2_pki_service_cleanup(&service);
    sm2_pki_service_cleanup(&service);
    TEST_PASS();
}

static void test_phase8_merkle_revocation_hook_and_legacy_fallback()
{
    sm2_pki_service_ctx_t service;
    const uint8_t issuer[] = "P8_MERKLE_CA";
    TEST_ASSERT(sm2_pki_service_init(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, 1000)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P8_NODE";
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

    sm2_pki_client_ctx_t signer;
    TEST_ASSERT(sm2_pki_client_init(&signer, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(&signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P8_MERKLE_AUTH";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(&signer, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Signer Sign");

    sm2_auth_request_t auth_req = { .cert = &signer.cert,
        .public_key = &signer.public_key,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig,
        .revocation_query_fn = NULL,
        .revocation_query_user_ctx = NULL };

    sm2_pki_client_ctx_t verifier_merkle;
    TEST_ASSERT(
        sm2_pki_client_init(&verifier_merkle, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Merkle Init");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(&verifier_merkle, &auth_req, 1100, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Verify Without Revocation Hook Must Reject");

    TEST_ASSERT(
        sm2_pki_service_revoke_cert(&service, cert_res.cert.serial_number, 1200)
            == SM2_PKI_SUCCESS,
        "Revoke Serial");
    uint64_t revoked[] = { cert_res.cert.serial_number, 990001, 990002 };
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));
    TEST_ASSERT(sm2_revocation_merkle_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030607ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build");

    pki_merkle_sig_ctx_t sig_ctx
        = { &service.ca_private_key, &service.ca_public_key };
    sm2_rev_merkle_epoch_directory_t dir;
    memset(&dir, 0, sizeof(dir));
    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(&tree, 88, 6, 1000,
                    2000, pki_merkle_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    sm2_rev_merkle_query_ctx_t query_ctx;
    memset(&query_ctx, 0, sizeof(query_ctx));
    query_ctx.directory = &dir;
    query_ctx.verify_fn = pki_merkle_verify_cb;
    query_ctx.verify_user_ctx = &sig_ctx;

    TEST_ASSERT(sm2_pki_client_set_revocation_query(&verifier_merkle,
                    sm2_revocation_merkle_query_patch_first_cb, &query_ctx)
            == SM2_PKI_SUCCESS,
        "Set Merkle Revocation Hook");

    TEST_ASSERT(sm2_pki_verify(&verifier_merkle, &auth_req, 1300, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Merkle Hook Blocks Revoked");

    TEST_ASSERT(
        sm2_pki_client_set_revocation_query(&verifier_merkle, NULL, NULL)
            == SM2_PKI_SUCCESS,
        "Clear Merkle Hook");
    TEST_ASSERT(sm2_pki_verify(&verifier_merkle, &auth_req, 1300, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Clear Hook Keeps Reject Without Query Path");

    sm2_pki_client_ctx_t verifier_legacy;
    TEST_ASSERT(sm2_pki_client_init(&verifier_legacy, &ca_pub, &service.rev_ctx)
            == SM2_PKI_SUCCESS,
        "Verifier Legacy Init");
    TEST_ASSERT(sm2_pki_verify(&verifier_legacy, &auth_req, 1300, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Legacy Revocation Fallback");

    sm2_revocation_merkle_epoch_directory_cleanup(&dir);
    sm2_revocation_merkle_cleanup(&tree);
    sm2_pki_client_cleanup(&verifier_legacy);
    sm2_pki_client_cleanup(&verifier_merkle);
    sm2_pki_client_cleanup(&signer);
    sm2_pki_service_cleanup(&service);
    TEST_PASS();
}

static void test_phase9_patch_first_unknown_fallback_behavior()
{
    sm2_pki_service_ctx_t service;
    const uint8_t issuer[] = "P9_MERKLE_CA";
    TEST_ASSERT(sm2_pki_service_init(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, 1000)
            == SM2_PKI_SUCCESS,
        "Service Init");
    const uint8_t identity[] = "P9_NODE";
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

    sm2_pki_client_ctx_t signer;
    TEST_ASSERT(sm2_pki_client_init(&signer, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(&signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P9_PATCH_FIRST_FALLBACK";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(&signer, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Signer Sign");

    sm2_auth_request_t auth_req = { .cert = &signer.cert,
        .public_key = &signer.public_key,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig,
        .revocation_query_fn = NULL,
        .revocation_query_user_ctx = NULL };

    uint64_t revoked[] = { 990001, 990002, 990003 };
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));
    TEST_ASSERT(sm2_revocation_merkle_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030702ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build");

    pki_merkle_sig_ctx_t sig_ctx
        = { &service.ca_private_key, &service.ca_public_key };
    sm2_rev_merkle_epoch_directory_t dir;
    memset(&dir, 0, sizeof(dir));
    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(&tree, 91, 6, 1000,
                    3000, pki_merkle_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    sm2_rev_merkle_query_ctx_t query_ctx;
    memset(&query_ctx, 0, sizeof(query_ctx));
    query_ctx.directory = &dir;
    query_ctx.verify_fn = pki_merkle_verify_cb;
    query_ctx.verify_user_ctx = &sig_ctx;

    size_t matched = 0;

    sm2_pki_client_ctx_t verifier_no_fallback;
    TEST_ASSERT(sm2_pki_client_init(&verifier_no_fallback, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Verifier No Fallback Init");
    TEST_ASSERT(sm2_pki_client_set_revocation_query(&verifier_no_fallback,
                    sm2_revocation_merkle_query_patch_first_cb, &query_ctx)
            == SM2_PKI_SUCCESS,
        "Set Patch-First Hook No Fallback");
    TEST_ASSERT(sm2_pki_verify(&verifier_no_fallback, &auth_req, 1200, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Patch-First Unknown Without Fallback Must Reject");

    sm2_pki_client_ctx_t verifier_with_fallback;
    TEST_ASSERT(
        sm2_pki_client_init(&verifier_with_fallback, &ca_pub, &service.rev_ctx)
            == SM2_PKI_SUCCESS,
        "Verifier With Fallback Init");
    TEST_ASSERT(sm2_pki_client_set_revocation_query(&verifier_with_fallback,
                    sm2_revocation_merkle_query_patch_first_cb, &query_ctx)
            == SM2_PKI_SUCCESS,
        "Set Patch-First Hook With Fallback");
    TEST_ASSERT(
        sm2_pki_verify(&verifier_with_fallback, &auth_req, 1200, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Patch-First Unknown Must Reject In Merkle-Only Mode");

    TEST_ASSERT(
        sm2_pki_service_revoke_cert(&service, cert_res.cert.serial_number, 1300)
            == SM2_PKI_SUCCESS,
        "Revoke Cert");
    TEST_ASSERT(
        sm2_pki_verify(&verifier_with_fallback, &auth_req, 1400, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Patch-First Unknown With Fallback Must Block Revoked Cert");

    sm2_pki_client_cleanup(&verifier_with_fallback);
    sm2_pki_client_cleanup(&verifier_no_fallback);
    sm2_revocation_merkle_epoch_directory_cleanup(&dir);
    sm2_revocation_merkle_cleanup(&tree);
    sm2_pki_client_cleanup(&signer);
    sm2_pki_service_cleanup(&service);
    TEST_PASS();
}
static void test_phase7_service_ca_key_range_check()
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    BIGNUM *order = BN_new();
    BIGNUM *upper_bound = BN_new();

    TEST_ASSERT(group != NULL && order != NULL && upper_bound != NULL,
        "Alloc SM2 Range Objects");
    TEST_ASSERT(
        EC_GROUP_get_order(group, order, NULL) == 1, "Read Curve Order");
    TEST_ASSERT(BN_copy(upper_bound, order) != NULL, "Copy Order");
    TEST_ASSERT(BN_sub_word(upper_bound, 2), "Order Minus Two");

    for (size_t i = 0; i < 16; i++)
    {
        sm2_pki_service_ctx_t service;
        const uint8_t issuer[] = "P7_CA";
        TEST_ASSERT(sm2_pki_service_init(&service, issuer, sizeof(issuer) - 1,
                        16, 300, (uint64_t)(5000 + i))
                == SM2_PKI_SUCCESS,
            "Service Init");

        BIGNUM *d = BN_bin2bn(service.ca_private_key.d, SM2_KEY_LEN, NULL);
        TEST_ASSERT(d != NULL, "CA Private To BN");
        TEST_ASSERT(!BN_is_zero(d) && !BN_is_negative(d), "CA Private > 0");
        TEST_ASSERT(BN_cmp(d, upper_bound) <= 0, "CA Private <= n-2");

        BN_clear_free(d);
        sm2_pki_service_cleanup(&service);
    }

    BN_free(upper_bound);
    BN_free(order);
    EC_GROUP_free(group);
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
    TEST_ASSERT(sm2_auth_derive_session_key(&priv_a, &pub_b, sk_a, sizeof(sk_a))
            == SM2_IC_SUCCESS,
        "Direct Derive A");
    TEST_ASSERT(sm2_auth_derive_session_key(&priv_b, &pub_a, sk_b, sizeof(sk_b))
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
    sm2_pki_error_t aead_ret = sm2_pki_sm4_aead_encrypt(
        SM2_AUTH_AEAD_MODE_SM4_GCM, sk_a, iv, sizeof(iv), NULL, 0, msg,
        sizeof(msg) - 1, cipher, &cipher_len, tag, &tag_len);
    if (aead_ret == SM2_PKI_ERR_CRYPTO)
    {
        printf("   [PKI-AEAD] SM4-GCM unavailable in current OpenSSL build, "
               "skip AEAD wrapper checks\n");
    }
    else
    {
        TEST_ASSERT(aead_ret == SM2_PKI_SUCCESS, "PKI AEAD Encrypt");

        uint8_t recover[sizeof(msg)];
        size_t recover_len = sizeof(recover);
        TEST_ASSERT(sm2_pki_sm4_aead_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b,
                        iv, sizeof(iv), NULL, 0, cipher, cipher_len, tag,
                        tag_len, recover, &recover_len)
                == SM2_PKI_SUCCESS,
            "PKI AEAD Decrypt");
        TEST_ASSERT(recover_len == sizeof(msg) - 1, "PKI AEAD Recover Len");
        TEST_ASSERT(memcmp(recover, msg, sizeof(msg) - 1) == 0,
            "PKI AEAD Recover Plain");

        tag[0] ^= 0x33;
        recover_len = sizeof(recover);
        TEST_ASSERT(sm2_pki_sm4_aead_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b,
                        iv, sizeof(iv), NULL, 0, cipher, cipher_len, tag,
                        tag_len, recover, &recover_len)
                == SM2_PKI_ERR_VERIFY,
            "PKI AEAD Tag Reject");
    }

    TEST_PASS();
}
void run_test_pki_suite(void)
{
    RUN_TEST(test_phase4_service_client_flow);
    RUN_TEST(test_phase4_revocation_ocsp_and_cross_domain);
    RUN_TEST(test_phase4_pki_controls_and_param_defense);
    RUN_TEST(test_phase8_merkle_revocation_hook_and_legacy_fallback);
    RUN_TEST(test_phase9_patch_first_unknown_fallback_behavior);
    RUN_TEST(test_x509_real_baseline_size);
    RUN_TEST(test_phase7_service_ca_key_range_check);
    RUN_TEST(test_phase93_crypto_direct_api_min_coverage);
}
