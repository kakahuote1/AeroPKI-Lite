/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_service.c
 * @brief In-memory CA/RA service implementation.
 */

#include "sm2_pki_service.h"
#include "sm2_auth.h"
#include "sm2_secure_mem.h"
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static sm2_pki_identity_entry_t *service_find_identity(
    sm2_pki_service_ctx_t *ctx, const uint8_t *identity, size_t identity_len)
{
    if (!ctx || !identity)
        return NULL;
    for (size_t i = 0; i < SM2_PKI_MAX_IDENTITIES; i++)
    {
        sm2_pki_identity_entry_t *e = &ctx->identities[i];
        if (!e->used)
            continue;
        if (e->identity_len == identity_len
            && memcmp(e->identity, identity, identity_len) == 0)
        {
            return e;
        }
    }
    return NULL;
}

static sm2_pki_identity_entry_t *service_find_by_serial(
    sm2_pki_service_ctx_t *ctx, uint64_t serial_number)
{
    if (!ctx)
        return NULL;
    for (size_t i = 0; i < SM2_PKI_MAX_IDENTITIES; i++)
    {
        sm2_pki_identity_entry_t *e = &ctx->identities[i];
        if (!e->used)
            continue;
        if (e->issued_serial == serial_number)
            return e;
    }
    return NULL;
}

static sm2_pki_identity_entry_t *service_alloc_identity(
    sm2_pki_service_ctx_t *ctx)
{
    if (!ctx)
        return NULL;
    for (size_t i = 0; i < SM2_PKI_MAX_IDENTITIES; i++)
    {
        if (!ctx->identities[i].used)
            return &ctx->identities[i];
    }
    return NULL;
}

static sm2_ic_error_t service_merkle_sign_cb(void *user_ctx,
    const uint8_t *data, size_t data_len, uint8_t *signature,
    size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    sm2_pki_service_ctx_t *ctx = (sm2_pki_service_ctx_t *)user_ctx;
    sm2_auth_signature_t sig;
    sm2_ic_error_t ret
        = sm2_auth_sign(&ctx->ca_private_key, data, data_len, &sig);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*signature_len < sig.der_len)
        return SM2_IC_ERR_MEMORY;

    memcpy(signature, sig.der, sig.der_len);
    *signature_len = sig.der_len;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t service_merkle_verify_cb(void *user_ctx,
    const uint8_t *data, size_t data_len, const uint8_t *signature,
    size_t signature_len)
{
    if (!user_ctx || !data || !signature || signature_len == 0
        || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_pki_service_ctx_t *ctx = (sm2_pki_service_ctx_t *)user_ctx;
    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;

    return sm2_auth_verify_signature(&ctx->ca_public_key, data, data_len, &sig);
}

static sm2_ic_error_t service_merkle_query(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status)
{
    if (!cert || !user_ctx || !status)
        return SM2_IC_ERR_PARAM;

    sm2_pki_service_ctx_t *ctx = (sm2_pki_service_ctx_t *)user_ctx;
    sm2_rev_merkle_tree_t tree;
    sm2_rev_merkle_root_record_t root_record;
    sm2_rev_merkle_membership_proof_t member_proof;
    sm2_rev_merkle_non_membership_proof_t non_member_proof;
    memset(&tree, 0, sizeof(tree));
    memset(&root_record, 0, sizeof(root_record));
    memset(&member_proof, 0, sizeof(member_proof));
    memset(&non_member_proof, 0, sizeof(non_member_proof));

    uint64_t root_version
        = ctx->rev_ctx.crl_version == 0 ? 1 : ctx->rev_ctx.crl_version;
    sm2_ic_error_t ret = sm2_revocation_merkle_build(&tree,
        ctx->rev_ctx.revoked_serials, ctx->rev_ctx.revoked_count, root_version);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint64_t ttl = ctx->rev_ctx.root_valid_ttl_sec;
    if (ttl == 0)
        ttl = 300;
    uint64_t valid_from = now_ts > ttl ? now_ts - ttl : 0;
    uint64_t valid_until = now_ts;
    if (ttl <= UINT64_MAX - valid_until)
        valid_until += ttl;
    else
        valid_until = UINT64_MAX;

    ret = sm2_revocation_merkle_sign_root(&tree, valid_from, valid_until,
        service_merkle_sign_cb, ctx, &root_record);
    if (ret != SM2_IC_SUCCESS)
        goto cleanup;

    ret = sm2_revocation_merkle_prove_member(
        &tree, cert->serial_number, &member_proof);
    if (ret == SM2_IC_SUCCESS)
    {
        ret = sm2_revocation_merkle_verify_member_with_root(
            &root_record, now_ts, &member_proof, service_merkle_verify_cb, ctx);
        if (ret == SM2_IC_SUCCESS)
            *status = SM2_REV_STATUS_REVOKED;
        goto cleanup;
    }

    if (ret != SM2_IC_ERR_VERIFY)
        goto cleanup;

    ret = sm2_revocation_merkle_prove_non_member(
        &tree, cert->serial_number, &non_member_proof);
    if (ret != SM2_IC_SUCCESS)
        goto cleanup;

    ret = sm2_revocation_merkle_verify_non_member_with_root(
        &root_record, now_ts, &non_member_proof, service_merkle_verify_cb, ctx);
    if (ret == SM2_IC_SUCCESS)
        *status = SM2_REV_STATUS_GOOD;

cleanup:
    sm2_revocation_merkle_cleanup(&tree);
    return ret;
}
static bool service_private_key_in_valid_range(
    const sm2_private_key_t *private_key)
{
    if (!private_key)
        return false;

    bool valid = false;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    BIGNUM *order = BN_new();
    BIGNUM *upper_bound = BN_new();
    BIGNUM *d_bn = BN_bin2bn(private_key->d, SM2_KEY_LEN, NULL);

    if (!group || !order || !upper_bound || !d_bn)
        goto cleanup;
    if (EC_GROUP_get_order(group, order, NULL) != 1)
        goto cleanup;
    if (BN_copy(upper_bound, order) == NULL)
        goto cleanup;
    if (!BN_sub_word(upper_bound, 2))
        goto cleanup;

    if (!BN_is_zero(d_bn) && !BN_is_negative(d_bn)
        && BN_cmp(d_bn, upper_bound) <= 0)
    {
        valid = true;
    }

cleanup:
    BN_clear_free(d_bn);
    BN_free(upper_bound);
    BN_free(order);
    EC_GROUP_free(group);
    return valid;
}

static sm2_pki_error_t service_generate_ca_private_key(
    sm2_private_key_t *private_key)
{
    if (!private_key)
        return SM2_PKI_ERR_PARAM;

    for (size_t attempt = 0; attempt < 64; attempt++)
    {
        if (sm2_ic_generate_random(private_key->d, SM2_KEY_LEN)
            != SM2_IC_SUCCESS)
        {
            return SM2_PKI_ERR_CRYPTO;
        }
        if (service_private_key_in_valid_range(private_key))
            return SM2_PKI_SUCCESS;
    }

    sm2_secure_memzero(private_key->d, SM2_KEY_LEN);
    return SM2_PKI_ERR_CRYPTO;
}
sm2_pki_error_t sm2_pki_service_init(sm2_pki_service_ctx_t *ctx,
    const uint8_t *issuer_id, size_t issuer_id_len,
    size_t expected_revoked_items, uint64_t filter_ttl_sec, uint64_t now_ts)
{
    if (!ctx || !issuer_id || issuer_id_len == 0
        || issuer_id_len > SM2_PKI_MAX_ISSUER_LEN)
    {
        return SM2_PKI_ERR_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));

    sm2_pki_error_t key_ret
        = service_generate_ca_private_key(&ctx->ca_private_key);
    if (key_ret != SM2_PKI_SUCCESS)
    {
        sm2_secure_memzero(ctx, sizeof(*ctx));
        return key_ret;
    }

    if (sm2_ic_sm2_point_mult(
            &ctx->ca_public_key, ctx->ca_private_key.d, SM2_KEY_LEN, NULL)
        != SM2_IC_SUCCESS)
    {
        sm2_secure_memzero(ctx, sizeof(*ctx));
        return SM2_PKI_ERR_CRYPTO;
    }
    if (sm2_revocation_init(
            &ctx->rev_ctx, expected_revoked_items, filter_ttl_sec, now_ts)
        != SM2_IC_SUCCESS)
    {
        sm2_revocation_cleanup(&ctx->rev_ctx);
        sm2_secure_memzero(ctx, sizeof(*ctx));
        return SM2_PKI_ERR_CRYPTO;
    }

    if (sm2_revocation_set_merkle_query(
            &ctx->rev_ctx, service_merkle_query, ctx)
        != SM2_IC_SUCCESS)
    {
        sm2_revocation_cleanup(&ctx->rev_ctx);
        sm2_secure_memzero(ctx, sizeof(*ctx));
        return SM2_PKI_ERR_CRYPTO;
    }

    memcpy(ctx->issuer_id, issuer_id, issuer_id_len);
    ctx->issuer_id_len = issuer_id_len;
    sm2_ic_issue_ctx_init(&ctx->issue_ctx);
    ctx->initialized = true;
    return SM2_PKI_SUCCESS;
}
void sm2_pki_service_cleanup(sm2_pki_service_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_revocation_cleanup(&ctx->rev_ctx);
    sm2_secure_memzero(ctx, sizeof(*ctx));
}

sm2_pki_error_t sm2_pki_service_get_ca_public_key(
    const sm2_pki_service_ctx_t *ctx, sm2_ec_point_t *ca_public_key)
{
    if (!ctx || !ca_public_key || !ctx->initialized)
        return SM2_PKI_ERR_PARAM;
    *ca_public_key = ctx->ca_public_key;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_set_cert_field_mask(
    sm2_pki_service_ctx_t *ctx, uint16_t field_mask)
{
    if (!ctx || !ctx->initialized)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(
        sm2_ic_issue_ctx_set_field_mask(&ctx->issue_ctx, field_mask));
}

sm2_pki_error_t sm2_pki_identity_register(sm2_pki_service_ctx_t *ctx,
    const uint8_t *identity, size_t identity_len, uint8_t key_usage)
{
    if (!ctx || !ctx->initialized || !identity || identity_len == 0
        || identity_len > SM2_PKI_MAX_ID_LEN)
    {
        return SM2_PKI_ERR_PARAM;
    }
    if (service_find_identity(ctx, identity, identity_len))
        return SM2_PKI_ERR_CONFLICT;

    sm2_pki_identity_entry_t *slot = service_alloc_identity(ctx);
    if (!slot)
        return SM2_PKI_ERR_MEMORY;

    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->identity, identity, identity_len);
    slot->identity_len = identity_len;
    slot->key_usage = key_usage;
    ctx->identity_count++;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_cert_request(sm2_pki_service_ctx_t *ctx,
    const uint8_t *identity, size_t identity_len,
    sm2_ic_cert_request_t *request, sm2_private_key_t *temp_private_key)
{
    if (!ctx || !ctx->initialized || !identity || !request || !temp_private_key)
    {
        return SM2_PKI_ERR_PARAM;
    }
    sm2_pki_identity_entry_t *entry
        = service_find_identity(ctx, identity, identity_len);
    if (!entry)
        return SM2_PKI_ERR_NOT_FOUND;

    sm2_ic_error_t ret = sm2_ic_create_cert_request(
        request, identity, identity_len, entry->key_usage, temp_private_key);
    return sm2_pki_error_from_ic(ret);
}

sm2_pki_error_t sm2_pki_cert_issue(sm2_pki_service_ctx_t *ctx,
    const sm2_ic_cert_request_t *request, sm2_ic_cert_result_t *result)
{
    if (!ctx || !ctx->initialized || !request || !result)
        return SM2_PKI_ERR_PARAM;

    sm2_pki_identity_entry_t *entry = service_find_identity(
        ctx, request->subject_id, request->subject_id_len);
    if (!entry)
        return SM2_PKI_ERR_NOT_FOUND;

    sm2_ic_error_t ret = sm2_ic_ca_generate_cert_with_ctx(result, request,
        ctx->issuer_id, ctx->issuer_id_len, &ctx->ca_private_key,
        &ctx->ca_public_key, &ctx->issue_ctx);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    entry->issued_serial = result->cert.serial_number;
    entry->revoked = false;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_service_revoke_cert(
    sm2_pki_service_ctx_t *ctx, uint64_t serial_number, uint64_t now_ts)
{
    if (!ctx || !ctx->initialized || serial_number == 0)
        return SM2_PKI_ERR_PARAM;
    sm2_pki_identity_entry_t *entry
        = service_find_by_serial(ctx, serial_number);
    if (!entry)
        return SM2_PKI_ERR_NOT_FOUND;

    sm2_crl_delta_item_t item;
    item.serial_number = serial_number;
    item.revoked = true;

    sm2_crl_delta_t delta;
    delta.base_version = sm2_revocation_crl_version(&ctx->rev_ctx);
    delta.new_version = delta.base_version + 1;
    delta.items = &item;
    delta.item_count = 1;

    sm2_ic_error_t ret
        = sm2_revocation_apply_crl_delta(&ctx->rev_ctx, &delta, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return sm2_pki_error_from_ic(ret);

    entry->revoked = true;
    return SM2_PKI_SUCCESS;
}

sm2_pki_error_t sm2_pki_revoke_check(sm2_pki_service_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    if (!ctx || !ctx->initialized)
        return SM2_PKI_ERR_PARAM;
    return sm2_pki_error_from_ic(sm2_revocation_query(
        &ctx->rev_ctx, serial_number, now_ts, status, source));
}
