/* SPDX-License-Identifier: Apache-2.0 */

#include "test_revoke_helpers.h"

sm2_ic_error_t mock_redirect_verify(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    if (!user_ctx || !data || data_len == 0 || !signature || signature_len != 1)
        return SM2_IC_ERR_VERIFY;

    mock_redirect_verify_ctx_t *ctx = (mock_redirect_verify_ctx_t *)user_ctx;
    ctx->called = true;
    return signature[0] == ctx->expect_tag ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t revoke_merkle_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    revoke_merkle_sig_ctx_t *ctx = (revoke_merkle_sig_ctx_t *)user_ctx;
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

sm2_ic_error_t revoke_merkle_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    if (!user_ctx || !data || !signature)
        return SM2_IC_ERR_PARAM;

    revoke_merkle_sig_ctx_t *ctx = (revoke_merkle_sig_ctx_t *)user_ctx;
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

sm2_ic_error_t mock_merkle_query(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status)
{
    (void)now_ts;
    if (!cert || !user_ctx || !status)
        return SM2_IC_ERR_PARAM;

    mock_merkle_query_state_t *st = (mock_merkle_query_state_t *)user_ctx;
    st->call_count++;
    st->last_serial = cert->serial_number;
    *status = st->status;
    return SM2_IC_SUCCESS;
}
