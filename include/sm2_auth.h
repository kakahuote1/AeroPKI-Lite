/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_auth.h
 * @brief High-throughput unified authentication based on SM2 implicit
 * certificates.
 */

#ifndef SM2_AUTH_H
#define SM2_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sm2_implicit_cert.h"
#include "sm2_revocation.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_AUTH_MAX_SIG_DER_LEN 96
#define SM2_AUTH_MAX_CA_STORE 16

    typedef struct
    {
        uint8_t der[SM2_AUTH_MAX_SIG_DER_LEN];
        size_t der_len;
    } sm2_auth_signature_t;

    typedef struct
    {
        uint8_t kinv[SM2_KEY_LEN];
        uint8_t r[SM2_KEY_LEN];
        bool used;
    } sm2_auth_precomp_slot_t;

    typedef struct
    {
        sm2_private_key_t signing_key;
        sm2_auth_precomp_slot_t *slots;
        size_t capacity;
        size_t available;
        size_t next_slot;
        void *native_sign_key; /* Internal OpenSSL key cache. */
    } sm2_auth_precompute_pool_t;

    typedef struct
    {
        sm2_ec_point_t ca_pub_keys[SM2_AUTH_MAX_CA_STORE];
        size_t count;
    } sm2_auth_trust_store_t;

    typedef struct
    {
        const sm2_implicit_cert_t *cert;
        const sm2_ec_point_t *public_key;
        const uint8_t *message;
        size_t message_len;
        const sm2_auth_signature_t *signature;
    } sm2_auth_request_t;

    typedef struct
    {
        const sm2_ec_point_t *public_key;
        const uint8_t *message;
        size_t message_len;
        const sm2_auth_signature_t *signature;
    } sm2_auth_verify_item_t;

    sm2_ic_error_t sm2_auth_precompute_pool_init(
        sm2_auth_precompute_pool_t *pool, const sm2_private_key_t *signing_key,
        size_t capacity);
    void sm2_auth_precompute_pool_cleanup(sm2_auth_precompute_pool_t *pool);
    sm2_ic_error_t sm2_auth_precompute_pool_fill(
        sm2_auth_precompute_pool_t *pool, size_t target_available);
    size_t sm2_auth_precompute_pool_available(
        const sm2_auth_precompute_pool_t *pool);

    sm2_ic_error_t sm2_auth_sign(const sm2_private_key_t *signing_key,
        const uint8_t *message, size_t message_len,
        sm2_auth_signature_t *signature);
    sm2_ic_error_t sm2_auth_sign_with_pool(sm2_auth_precompute_pool_t *pool,
        const uint8_t *message, size_t message_len,
        sm2_auth_signature_t *signature);
    sm2_ic_error_t sm2_auth_verify_signature(const sm2_ec_point_t *public_key,
        const uint8_t *message, size_t message_len,
        const sm2_auth_signature_t *signature);

    sm2_ic_error_t sm2_auth_batch_verify(const sm2_auth_verify_item_t *items,
        size_t item_count, size_t *valid_count);

    sm2_ic_error_t sm2_auth_trust_store_init(sm2_auth_trust_store_t *store);
    sm2_ic_error_t sm2_auth_trust_store_add_ca(
        sm2_auth_trust_store_t *store, const sm2_ec_point_t *ca_public_key);

    sm2_ic_error_t sm2_auth_verify_cert_with_store(
        const sm2_implicit_cert_t *cert, const sm2_ec_point_t *public_key,
        const sm2_auth_trust_store_t *store, size_t *matched_ca_index);

    sm2_ic_error_t sm2_auth_authenticate_request(
        const sm2_auth_request_t *request, const sm2_auth_trust_store_t *store,
        sm2_revocation_ctx_t *rev_ctx, uint64_t now_ts,
        size_t *matched_ca_index);

    sm2_ic_error_t sm2_auth_derive_session_key(
        const sm2_private_key_t *local_private_key,
        const sm2_ec_point_t *peer_public_key, uint8_t *session_key,
        size_t session_key_len);

    sm2_ic_error_t sm2_auth_mutual_auth_and_key_agreement(
        const sm2_auth_request_t *a_to_b,
        const sm2_private_key_t *a_private_key,
        const sm2_auth_trust_store_t *b_trust_store,
        sm2_revocation_ctx_t *b_rev_ctx, const sm2_auth_request_t *b_to_a,
        const sm2_private_key_t *b_private_key,
        const sm2_auth_trust_store_t *a_trust_store,
        sm2_revocation_ctx_t *a_rev_ctx, uint64_t now_ts,
        uint8_t *session_key_a, uint8_t *session_key_b, size_t session_key_len);

    sm2_ic_error_t sm2_auth_sm4_encrypt(const uint8_t key[16],
        const uint8_t iv[16], const uint8_t *plaintext, size_t plaintext_len,
        uint8_t *ciphertext, size_t *ciphertext_len);

    sm2_ic_error_t sm2_auth_sm4_decrypt(const uint8_t key[16],
        const uint8_t iv[16], const uint8_t *ciphertext, size_t ciphertext_len,
        uint8_t *plaintext, size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* SM2_AUTH_H */
