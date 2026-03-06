/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_client.c
 * @brief PKI client library implementation.
 */

#include "sm2_pki_client.h"
#include "sm2_secure_mem.h"
#include <string.h>

sm2_pki_error_t sm2_pki_client_init(sm2_pki_client_ctx_t *ctx,
    const sm2_ec_point_t *default_ca_public_key, sm2_revocation_ctx_t *rev_ctx)
{
    if (!ctx)
        return SM2_PKI_ERR_PARAM;
    memset(ctx, 0, sizeof(*ctx));

    sm2_ic_error_t ret = sm2_auth_trust_store_init(&ctx->trust_store);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    if (default_ca_public_key)
    {
        ret = sm2_auth_trust_store_add_ca(
            &ctx->trust_store, default_ca_public_key);
        if (ret != SM2_IC_SUCCESS)
            return sm2_pki_error_from_ic(ret);
    }

    ctx->rev_ctx = rev_ctx;
    ctx->initialized = true;
    return SM2_PKI_SUCCESS;
}

void sm2_pki_client_cleanup(sm2_pki_client_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_disable_precompute(ctx);
    sm2_secure_memzero(ctx, sizeof(*ctx));
}

sm2_pki_error_t sm2_pki_client_add_trusted_ca(
    sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t *ca_public_key)
{
    if (!ctx || !ctx->initialized || !ca_public_key)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(
        sm2_auth_trust_store_add_ca(&ctx->trust_store, ca_public_key));
}

sm2_pki_error_t sm2_pki_client_import_cert(sm2_pki_client_ctx_t *ctx,
    const sm2_ic_cert_result_t *cert_result,
    const sm2_private_key_t *temp_private_key,
    const sm2_ec_point_t *ca_public_key)
{
    if (!ctx || !ctx->initialized || !cert_result || !temp_private_key
        || !ca_public_key)
    {
        return SM2_PKI_ERR_PARAM;
    }

    sm2_ic_error_t ret = sm2_ic_reconstruct_keys(&ctx->private_key,
        &ctx->public_key, cert_result, temp_private_key, ca_public_key);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    ctx->cert = cert_result->cert;
    ctx->has_identity_keys = true;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_client_enable_precompute(
    sm2_pki_client_ctx_t *ctx, size_t capacity, size_t target_available)
{
    if (!ctx || !ctx->initialized || !ctx->has_identity_keys || capacity == 0)
    {
        return SM2_PKI_ERR_PARAM;
    }

    sm2_pki_client_disable_precompute(ctx);

    sm2_ic_error_t ret = sm2_auth_precompute_pool_init(
        &ctx->precompute_pool, &ctx->private_key, capacity);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    ret = sm2_auth_precompute_pool_fill(
        &ctx->precompute_pool, target_available);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_auth_precompute_pool_cleanup(&ctx->precompute_pool);
        return sm2_pki_error_from_ic(ret);
    }

    ctx->precompute_enabled = true;
    return SM2_PKI_SUCCESS;
}

void sm2_pki_client_disable_precompute(sm2_pki_client_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->precompute_enabled)
    {
        sm2_auth_precompute_pool_cleanup(&ctx->precompute_pool);
        ctx->precompute_enabled = false;
    }
}

sm2_pki_error_t sm2_pki_sign(sm2_pki_client_ctx_t *ctx, const uint8_t *message,
    size_t message_len, sm2_auth_signature_t *signature)
{
    if (!ctx || !ctx->initialized || !ctx->has_identity_keys || !message
        || !signature)
    {
        return SM2_PKI_ERR_PARAM;
    }
    sm2_ic_error_t ret = SM2_IC_SUCCESS;
    if (ctx->precompute_enabled
        && sm2_auth_precompute_pool_available(&ctx->precompute_pool) > 0)
    {
        ret = sm2_auth_sign_with_pool(
            &ctx->precompute_pool, message, message_len, signature);
    }
    else
    {
        ret = sm2_auth_sign(&ctx->private_key, message, message_len, signature);
    }
    return sm2_pki_error_from_ic(ret);
}

sm2_pki_error_t sm2_pki_verify(sm2_pki_client_ctx_t *ctx,
    const sm2_auth_request_t *request, uint64_t now_ts,
    size_t *matched_ca_index)
{
    if (!ctx || !ctx->initialized || !request)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(sm2_auth_authenticate_request(
        request, &ctx->trust_store, ctx->rev_ctx, now_ts, matched_ca_index));
}

sm2_pki_error_t sm2_pki_batch_verify(
    const sm2_auth_verify_item_t *items, size_t item_count, size_t *valid_count)
{
    return sm2_pki_error_from_ic(
        sm2_auth_batch_verify(items, item_count, valid_count));
}

sm2_pki_error_t sm2_pki_key_agreement(sm2_pki_client_ctx_t *ctx,
    const sm2_ec_point_t *peer_public_key, uint8_t *session_key,
    size_t session_key_len)
{
    if (!ctx || !ctx->initialized || !ctx->has_identity_keys)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(sm2_auth_derive_session_key(
        &ctx->private_key, peer_public_key, session_key, session_key_len));
}

sm2_pki_error_t sm2_pki_encrypt(const uint8_t key[16], const uint8_t iv[16],
    const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext,
    size_t *ciphertext_len)
{
    return sm2_pki_sm4_encrypt(
        key, iv, plaintext, plaintext_len, ciphertext, ciphertext_len);
}

sm2_pki_error_t sm2_pki_decrypt(const uint8_t key[16], const uint8_t iv[16],
    const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext,
    size_t *plaintext_len)
{
    return sm2_pki_sm4_decrypt(
        key, iv, ciphertext, ciphertext_len, plaintext, plaintext_len);
}
