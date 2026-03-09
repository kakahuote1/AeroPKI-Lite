/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_client.c
 * @brief PKI client library implementation.
 */

#include "pki_internal.h"
#include "sm2_secure_mem.h"
#include <stdlib.h>
#include <string.h>

static sm2_pki_client_state_t *pki_client_state(sm2_pki_client_ctx_t *ctx)
{
    return ctx;
}

static const sm2_pki_client_state_t *pki_client_state_const(
    const sm2_pki_client_ctx_t *ctx)
{
    return ctx;
}

static sm2_ic_error_t pki_client_revocation_bridge(
    const sm2_implicit_cert_t *cert, uint64_t now_ts, void *user_ctx,
    sm2_rev_status_t *status)
{
    if (!cert || !user_ctx || !status)
        return SM2_IC_ERR_PARAM;

    sm2_pki_service_state_t *service = (sm2_pki_service_state_t *)user_ctx;
    sm2_rev_source_t source = SM2_REV_SOURCE_NONE;
    return sm2_pki_service_query_revocation_binding(
        service, cert->serial_number, now_ts, status, &source);
}

static void pki_client_release_bound_service(sm2_pki_client_state_t *state)
{
    if (!state || !state->revocation_service)
        return;

    sm2_pki_service_release_revocation_binding(state->revocation_service);
    state->revocation_service = NULL;
}

static sm2_pki_error_t pki_client_require_local_key_agreement(
    const sm2_pki_client_ctx_t *ctx)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys)
        return SM2_PKI_ERR_PARAM;
    if ((state->cert.field_mask & SM2_IC_FIELD_KEY_USAGE) == 0
        || (state->cert.key_usage & SM2_KU_KEY_AGREEMENT) == 0)
    {
        return SM2_PKI_ERR_VERIFY;
    }
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_create(sm2_pki_client_ctx_t **ctx,
    const sm2_ec_point_t *default_ca_public_key,
    sm2_pki_service_ctx_t *revocation_service)
{
    if (!ctx)
        return SM2_PKI_ERR_PARAM;
    *ctx = NULL;

    sm2_pki_client_state_t *state
        = (sm2_pki_client_state_t *)calloc(1, sizeof(*state));
    if (!state)
        return SM2_PKI_ERR_MEMORY;

    sm2_ic_error_t ret = sm2_auth_trust_store_init(&state->trust_store);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_pki_client_destroy(&state);
        return sm2_pki_error_from_ic(ret);
    }

    if (default_ca_public_key)
    {
        ret = sm2_auth_trust_store_add_ca(
            &state->trust_store, default_ca_public_key);
        if (ret != SM2_IC_SUCCESS)
        {
            sm2_pki_client_destroy(&state);
            return sm2_pki_error_from_ic(ret);
        }
    }

    state->initialized = true;
    *ctx = state;
    if (revocation_service)
    {
        sm2_pki_error_t bind_ret
            = sm2_pki_client_bind_revocation(state, revocation_service);
        if (bind_ret != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(ctx);
            return bind_ret;
        }
    }
    return SM2_PKI_SUCCESS;
}

void sm2_pki_client_destroy(sm2_pki_client_ctx_t **ctx)
{
    if (!ctx || !*ctx)
        return;
    sm2_pki_client_state_t *state = *ctx;
    sm2_pki_client_disable_sign_pool(state);
    if (state)
    {
        pki_client_release_bound_service(state);
        sm2_secure_memzero(state, sizeof(*state));
        free(state);
    }
    *ctx = NULL;
}

sm2_pki_error_t sm2_pki_client_add_trusted_ca(
    sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t *ca_public_key)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !ca_public_key)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(
        sm2_auth_trust_store_add_ca(&state->trust_store, ca_public_key));
}

sm2_pki_error_t sm2_pki_client_get_cert(
    const sm2_pki_client_ctx_t *ctx, const sm2_implicit_cert_t **cert)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || !cert)
        return SM2_PKI_ERR_PARAM;
    *cert = &state->cert;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_get_public_key(
    const sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t **public_key)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || !public_key)
        return SM2_PKI_ERR_PARAM;
    *public_key = &state->public_key;
    return SM2_PKI_SUCCESS;
}

bool sm2_pki_client_is_sign_pool_enabled(const sm2_pki_client_ctx_t *ctx)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    return ctx && ctx->initialized && state && state->sign_pool_enabled;
}

sm2_pki_error_t sm2_pki_client_bind_revocation(
    sm2_pki_client_ctx_t *ctx, sm2_pki_service_ctx_t *service)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    sm2_pki_service_state_t *bound_service = NULL;
    if (!ctx || !ctx->initialized || !state || !service)
        return SM2_PKI_ERR_PARAM;

    if (state->revocation_service
        && state->revocation_query_fn == pki_client_revocation_bridge)
    {
        if (state->revocation_service == service)
            return SM2_PKI_SUCCESS;
        pki_client_release_bound_service(state);
    }

    sm2_pki_error_t ret
        = sm2_pki_service_acquire_revocation_binding(service, &bound_service);
    if (ret != SM2_PKI_SUCCESS)
        return ret;

    state->revocation_service = bound_service;
    state->revocation_query_fn = pki_client_revocation_bridge;
    state->revocation_query_user_ctx = bound_service;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_set_revocation_query(sm2_pki_client_ctx_t *ctx,
    sm2_auth_revocation_query_fn query_fn, void *user_ctx)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state)
        return SM2_PKI_ERR_PARAM;
    if (state->revocation_query_fn == pki_client_revocation_bridge)
        pki_client_release_bound_service(state);
    state->revocation_query_fn = query_fn;
    state->revocation_query_user_ctx = user_ctx;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_import_cert(sm2_pki_client_ctx_t *ctx,
    const sm2_ic_cert_result_t *cert_result,
    const sm2_private_key_t *temp_private_key,
    const sm2_ec_point_t *ca_public_key)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    sm2_private_key_t imported_private_key;
    sm2_ec_point_t imported_public_key;
    if (!ctx || !ctx->initialized || !state || !cert_result || !temp_private_key
        || !ca_public_key)
    {
        return SM2_PKI_ERR_PARAM;
    }

    memset(&imported_private_key, 0, sizeof(imported_private_key));
    memset(&imported_public_key, 0, sizeof(imported_public_key));

    sm2_ic_error_t ret = sm2_ic_reconstruct_keys(&imported_private_key,
        &imported_public_key, cert_result, temp_private_key, ca_public_key);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    ret = sm2_ic_verify_cert(
        &cert_result->cert, &imported_public_key, ca_public_key);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_secure_memzero(
            imported_private_key.d, sizeof(imported_private_key.d));
        return sm2_pki_error_from_ic(ret);
    }

    sm2_secure_memzero(state->private_key.d, sizeof(state->private_key.d));
    state->private_key = imported_private_key;
    state->public_key = imported_public_key;
    state->cert = cert_result->cert;
    state->has_identity_keys = true;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_enable_sign_pool(
    sm2_pki_client_ctx_t *ctx, size_t capacity, size_t target_available)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || capacity == 0)
    {
        return SM2_PKI_ERR_PARAM;
    }

    sm2_pki_client_disable_sign_pool(ctx);

    sm2_ic_error_t ret = sm2_auth_sign_pool_init(
        &state->sign_pool, &state->private_key, capacity);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    ret = sm2_auth_sign_pool_fill(&state->sign_pool, target_available);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_auth_sign_pool_cleanup(&state->sign_pool);
        return sm2_pki_error_from_ic(ret);
    }

    state->sign_pool_enabled = true;
    return SM2_PKI_SUCCESS;
}

void sm2_pki_client_disable_sign_pool(sm2_pki_client_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (state && state->sign_pool_enabled)
    {
        sm2_auth_sign_pool_cleanup(&state->sign_pool);
        state->sign_pool_enabled = false;
    }
}

sm2_pki_error_t sm2_pki_sign(sm2_pki_client_ctx_t *ctx, const uint8_t *message,
    size_t message_len, sm2_auth_signature_t *signature)
{
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (!ctx || !ctx->initialized || !state || !state->has_identity_keys
        || !message || !signature)
    {
        return SM2_PKI_ERR_PARAM;
    }
    sm2_ic_error_t ret = SM2_IC_SUCCESS;
    if (state->sign_pool_enabled
        && sm2_auth_sign_pool_available(&state->sign_pool) > 0)
    {
        ret = sm2_auth_sign_with_pool(
            &state->sign_pool, message, message_len, signature);
    }
    else
    {
        ret = sm2_auth_sign(
            &state->private_key, message, message_len, signature);
    }
    return sm2_pki_error_from_ic(ret);
}

sm2_pki_error_t sm2_pki_verify(sm2_pki_client_ctx_t *ctx,
    const sm2_pki_verify_request_t *request, uint64_t now_ts,
    size_t *matched_ca_index)
{
    const sm2_pki_client_state_t *state = pki_client_state_const(ctx);
    if (!ctx || !ctx->initialized || !state || !request)
        return SM2_PKI_ERR_PARAM;
    if (!state->revocation_query_fn)
        return SM2_PKI_ERR_VERIFY;

    sm2_auth_request_t req;
    sm2_auth_request_init(&req);
    req.cert = request->cert;
    req.public_key = request->public_key;
    req.message = request->message;
    req.message_len = request->message_len;
    req.signature = request->signature;
    req.revocation_query_fn = state->revocation_query_fn;
    req.revocation_query_user_ctx = state->revocation_query_user_ctx;
    req.revocation_policy = SM2_AUTH_REVOCATION_POLICY_PREFER_CALLBACK;
    req.lightweight_mode = true;

    return sm2_pki_error_from_ic(sm2_auth_authenticate_request(
        &req, &state->trust_store, NULL, now_ts, matched_ca_index));
}

sm2_pki_error_t sm2_pki_batch_verify(
    const sm2_auth_verify_item_t *items, size_t item_count, size_t *valid_count)
{
    return sm2_pki_error_from_ic(
        sm2_auth_batch_verify(items, item_count, valid_count));
}

sm2_pki_error_t sm2_pki_generate_ephemeral_keypair(
    sm2_private_key_t *ephemeral_private_key,
    sm2_ec_point_t *ephemeral_public_key)
{
    return sm2_pki_error_from_ic(sm2_auth_generate_ephemeral_keypair(
        ephemeral_private_key, ephemeral_public_key));
}

sm2_pki_error_t sm2_pki_key_agreement(sm2_pki_client_ctx_t *ctx,
    const sm2_private_key_t *local_ephemeral_private_key,
    const sm2_ec_point_t *peer_public_key,
    const sm2_ec_point_t *peer_ephemeral_public_key, const uint8_t *transcript,
    size_t transcript_len, uint8_t *session_key, size_t session_key_len)
{
    sm2_pki_error_t policy_ret = pki_client_require_local_key_agreement(ctx);
    sm2_pki_client_state_t *state = pki_client_state(ctx);
    if (policy_ret != SM2_PKI_SUCCESS)
        return policy_ret;
    return sm2_pki_error_from_ic(sm2_auth_derive_session_key(
        &state->private_key, local_ephemeral_private_key, peer_public_key,
        peer_ephemeral_public_key, transcript, transcript_len, session_key,
        session_key_len));
}

sm2_pki_error_t sm2_pki_encrypt(sm2_pki_aead_mode_t mode, const uint8_t key[16],
    const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext,
    size_t *ciphertext_len, uint8_t *tag, size_t *tag_len)
{
    return sm2_pki_aead_encrypt(mode, key, iv, iv_len, aad, aad_len, plaintext,
        plaintext_len, ciphertext, ciphertext_len, tag, tag_len);
}

sm2_pki_error_t sm2_pki_decrypt(sm2_pki_aead_mode_t mode, const uint8_t key[16],
    const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag,
    size_t tag_len, uint8_t *plaintext, size_t *plaintext_len)
{
    return sm2_pki_aead_decrypt(mode, key, iv, iv_len, aad, aad_len, ciphertext,
        ciphertext_len, tag, tag_len, plaintext, plaintext_len);
}
