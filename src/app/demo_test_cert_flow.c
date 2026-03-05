/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Demo Test 1:
 * End-to-end certificate issuance -> sign/verify -> revocation block.
 */

#include <stdio.h>
#include <string.h>
#include "sm2_pki_service.h"
#include "sm2_pki_client.h"

static int check_pki(sm2_pki_error_t err, const char *step)
{
    if (err != SM2_PKI_SUCCESS)
    {
        printf("[FAIL] %s, err=%d\n", step, (int)err);
        return 0;
    }
    printf("[OK]   %s\n", step);
    return 1;
}

int main(void)
{
    sm2_pki_service_ctx_t svc;
    sm2_pki_client_ctx_t cli;
    sm2_pki_error_t err = SM2_PKI_SUCCESS;

    const uint8_t issuer[] = "ROOT_CA";
    const uint8_t dev_id[] = "NODE_01";
    const uint8_t msg[] = "DEMO_CERT_FLOW_MESSAGE";

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_ec_point_t ca_pub;
    sm2_auth_signature_t sig;
    size_t matched_idx = 0;
    sm2_auth_request_t auth_req;

    sm2_rev_status_t rev_status = SM2_REV_STATUS_UNKNOWN;
    sm2_rev_source_t rev_source = SM2_REV_SOURCE_NONE;

    memset(&svc, 0, sizeof(svc));
    memset(&cli, 0, sizeof(cli));
    memset(&req, 0, sizeof(req));
    memset(&temp_priv, 0, sizeof(temp_priv));
    memset(&cert_res, 0, sizeof(cert_res));
    memset(&ca_pub, 0, sizeof(ca_pub));
    memset(&sig, 0, sizeof(sig));
    memset(&auth_req, 0, sizeof(auth_req));

    /* 1) Initialize in-memory CA/RA service */
    err = sm2_pki_service_init(&svc, issuer, sizeof(issuer) - 1, 64, 300, 1000);
    if (!check_pki(err, "Service Init"))
        goto cleanup;

    /* 2) Register identity and create certificate request */
    err = sm2_pki_identity_register(
        &svc, dev_id, sizeof(dev_id) - 1, SM2_KU_DIGITAL_SIGNATURE);
    if (!check_pki(err, "Identity Register"))
        goto cleanup;

    err = sm2_pki_cert_request(
        &svc, dev_id, sizeof(dev_id) - 1, &req, &temp_priv);
    if (!check_pki(err, "Cert Request"))
        goto cleanup;

    /* 3) Issue implicit certificate from CA */
    err = sm2_pki_cert_issue(&svc, &req, &cert_res);
    if (!check_pki(err, "Cert Issue"))
        goto cleanup;

    err = sm2_pki_service_get_ca_public_key(&svc, &ca_pub);
    if (!check_pki(err, "Get CA Public Key"))
        goto cleanup;

    /* 4) Initialize client and reconstruct identity keys */
    err = sm2_pki_client_init(&cli, &ca_pub, &svc.rev_ctx);
    if (!check_pki(err, "Client Init"))
        goto cleanup;

    err = sm2_pki_client_import_cert(&cli, &cert_res, &temp_priv, &ca_pub);
    if (!check_pki(err, "Import Cert"))
        goto cleanup;

    /* 5) Sign and verify (before revocation should pass) */
    err = sm2_pki_sign(&cli, msg, sizeof(msg) - 1, &sig);
    if (!check_pki(err, "Sign Message"))
        goto cleanup;

    auth_req.cert = &cli.cert;
    auth_req.public_key = &cli.public_key;
    auth_req.message = msg;
    auth_req.message_len = sizeof(msg) - 1;
    auth_req.signature = &sig;

    err = sm2_pki_verify(&cli, &auth_req, 1010, &matched_idx);
    if (!check_pki(err, "Verify Before Revoke"))
        goto cleanup;
    printf("[INFO] matched_ca_index=%zu\n", matched_idx);

    /* 6) Revoke certificate and confirm revocation state */
    err = sm2_pki_service_revoke_cert(&svc, cert_res.cert.serial_number, 1015);
    if (!check_pki(err, "Revoke Cert"))
        goto cleanup;

    err = sm2_pki_revoke_check(
        &svc, cert_res.cert.serial_number, 1016, &rev_status, &rev_source);
    if (!check_pki(err, "Revoke Check"))
        goto cleanup;
    printf("[INFO] revoke_status=%d, source=%d\n", (int)rev_status,
        (int)rev_source);

    if (rev_status != SM2_REV_STATUS_REVOKED)
    {
        printf("[FAIL] Revoke status is not REVOKED\n");
        goto cleanup;
    }

    /* 7) Verify after revocation should be rejected */
    err = sm2_pki_verify(&cli, &auth_req, 1017, &matched_idx);
    if (err == SM2_PKI_SUCCESS)
    {
        printf("[FAIL] Verify After Revoke unexpectedly succeeded\n");
        goto cleanup;
    }
    printf(
        "[OK]   Verify After Revoke blocked as expected, err=%d\n", (int)err);

    printf("[PASS] demo_test_cert_flow\n");
    sm2_pki_client_cleanup(&cli);
    sm2_pki_service_cleanup(&svc);
    return 0;

cleanup:
    sm2_pki_client_cleanup(&cli);
    sm2_pki_service_cleanup(&svc);
    return 1;
}
