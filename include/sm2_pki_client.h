/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_client.h
 * @brief PKI client library interfaces for
 * parse/encode/reconstruct/sign/verify.
 */

#ifndef SM2_PKI_CLIENT_H
#define SM2_PKI_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sm2_crypto.h"
#include "sm2_pki_service.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        bool initialized;
        sm2_implicit_cert_t cert;
        sm2_private_key_t private_key;
        sm2_ec_point_t public_key;
        bool has_identity_keys;

        sm2_auth_trust_store_t trust_store;
        sm2_revocation_ctx_t *rev_ctx;
        sm2_auth_revocation_query_fn revocation_query_fn;
        void *revocation_query_user_ctx;

        sm2_auth_precompute_pool_t precompute_pool;
        bool precompute_enabled;
    } sm2_pki_client_ctx_t;

    sm2_pki_error_t sm2_pki_client_init(sm2_pki_client_ctx_t *ctx,
        const sm2_ec_point_t *default_ca_public_key,
        sm2_revocation_ctx_t *rev_ctx);

    void sm2_pki_client_cleanup(sm2_pki_client_ctx_t *ctx);

    sm2_pki_error_t sm2_pki_client_add_trusted_ca(
        sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t *ca_public_key);

    sm2_pki_error_t sm2_pki_client_set_revocation_query(
        sm2_pki_client_ctx_t *ctx, sm2_auth_revocation_query_fn query_fn,
        void *user_ctx);

    sm2_pki_error_t sm2_pki_client_import_cert(sm2_pki_client_ctx_t *ctx,
        const sm2_ic_cert_result_t *cert_result,
        const sm2_private_key_t *temp_private_key,
        const sm2_ec_point_t *ca_public_key);

    sm2_pki_error_t sm2_pki_client_enable_precompute(
        sm2_pki_client_ctx_t *ctx, size_t capacity, size_t target_available);

    void sm2_pki_client_disable_precompute(sm2_pki_client_ctx_t *ctx);

    /* Unified API names required by Phase4-S05. */
    sm2_pki_error_t sm2_pki_sign(sm2_pki_client_ctx_t *ctx,
        const uint8_t *message, size_t message_len,
        sm2_auth_signature_t *signature);

    sm2_pki_error_t sm2_pki_verify(sm2_pki_client_ctx_t *ctx,
        const sm2_auth_request_t *request, uint64_t now_ts,
        size_t *matched_ca_index);

    sm2_pki_error_t sm2_pki_batch_verify(const sm2_auth_verify_item_t *items,
        size_t item_count, size_t *valid_count);

    sm2_pki_error_t sm2_pki_key_agreement(sm2_pki_client_ctx_t *ctx,
        const sm2_ec_point_t *peer_public_key, uint8_t *session_key,
        size_t session_key_len);

    sm2_pki_error_t sm2_pki_encrypt(const uint8_t key[16], const uint8_t iv[16],
        const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext,
        size_t *ciphertext_len);

    sm2_pki_error_t sm2_pki_decrypt(const uint8_t key[16], const uint8_t iv[16],
        const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext,
        size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_CLIENT_H */
