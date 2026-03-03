/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_service.h
 * @brief In-memory CA/RA service APIs for registration, issuance and
 * revocation.
 */

#ifndef SM2_PKI_SERVICE_H
#define SM2_PKI_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sm2_crypto.h"
#include "sm2_revocation.h"
#include "sm2_implicit_cert.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_PKI_MAX_IDENTITIES 256
#define SM2_PKI_MAX_ID_LEN 64
#define SM2_PKI_MAX_ISSUER_LEN 64

    typedef struct
    {
        bool used;
        uint8_t identity[SM2_PKI_MAX_ID_LEN];
        size_t identity_len;
        uint8_t key_usage;
        uint64_t issued_serial;
        bool revoked;
    } sm2_pki_identity_entry_t;

    typedef struct
    {
        bool initialized;
        uint8_t issuer_id[SM2_PKI_MAX_ISSUER_LEN];
        size_t issuer_id_len;
        sm2_ic_issue_ctx_t issue_ctx;

        sm2_private_key_t ca_private_key;
        sm2_ec_point_t ca_public_key;

        sm2_pki_identity_entry_t identities[SM2_PKI_MAX_IDENTITIES];
        size_t identity_count;

        sm2_revocation_ctx_t rev_ctx;
    } sm2_pki_service_ctx_t;

    sm2_pki_error_t sm2_pki_service_init(sm2_pki_service_ctx_t *ctx,
        const uint8_t *issuer_id, size_t issuer_id_len,
        size_t expected_revoked_items, uint64_t filter_ttl_sec,
        uint64_t now_ts);

    void sm2_pki_service_cleanup(sm2_pki_service_ctx_t *ctx);

    sm2_pki_error_t sm2_pki_service_get_ca_public_key(
        const sm2_pki_service_ctx_t *ctx, sm2_ec_point_t *ca_public_key);

    sm2_pki_error_t sm2_pki_service_set_cert_field_mask(
        sm2_pki_service_ctx_t *ctx, uint16_t field_mask);

    /* Unified API names required by Phase4-S05. */
    sm2_pki_error_t sm2_pki_identity_register(sm2_pki_service_ctx_t *ctx,
        const uint8_t *identity, size_t identity_len, uint8_t key_usage);

    sm2_pki_error_t sm2_pki_cert_request(sm2_pki_service_ctx_t *ctx,
        const uint8_t *identity, size_t identity_len,
        sm2_ic_cert_request_t *request, sm2_private_key_t *temp_private_key);

    sm2_pki_error_t sm2_pki_cert_issue(sm2_pki_service_ctx_t *ctx,
        const sm2_ic_cert_request_t *request, sm2_ic_cert_result_t *result);

    sm2_pki_error_t sm2_pki_service_revoke_cert(
        sm2_pki_service_ctx_t *ctx, uint64_t serial_number, uint64_t now_ts);

    sm2_pki_error_t sm2_pki_revoke_check(sm2_pki_service_ctx_t *ctx,
        uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
        sm2_rev_source_t *source);

    sm2_pki_error_t sm2_pki_service_build_ocsp_cfg(sm2_pki_service_ctx_t *ctx,
        uint32_t timeout_ms, uint8_t retry_count, size_t cache_capacity,
        sm2_ocsp_client_cfg_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_SERVICE_H */
