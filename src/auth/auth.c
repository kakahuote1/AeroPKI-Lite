/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_auth.c
 * @brief High-throughput unified authentication based on SM2 implicit certs.
 */

#include "sm2_auth.h"
#include "sm2_secure_mem.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/obj_mac.h>

typedef struct
{
    bool used;
    uint8_t key_raw[SM2_KEY_LEN * 2];
    EVP_PKEY *pkey;
} verify_key_cache_t;

static EVP_PKEY *utils_pkey_from_public(const sm2_ec_point_t *public_key)
{
    if (!public_key)
        return NULL;

    uint8_t pub_buf[65];
    pub_buf[0] = 0x04;
    memcpy(pub_buf + 1, public_key->x, SM2_KEY_LEN);
    memcpy(pub_buf + 1 + SM2_KEY_LEN, public_key->y, SM2_KEY_LEN);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pkey = NULL;

    if (!pctx || !bld)
        goto cleanup;
    if (!OSSL_PARAM_BLD_push_utf8_string(
            bld, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0))
        goto cleanup;
    if (!OSSL_PARAM_BLD_push_octet_string(
            bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, sizeof(pub_buf)))
        goto cleanup;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params)
        goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) <= 0)
        goto cleanup;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        pkey = NULL;
        goto cleanup;
    }

cleanup:
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    sm2_secure_memzero(pub_buf, sizeof(pub_buf));
    return pkey;
}
static EVP_PKEY *utils_pkey_from_private(const sm2_private_key_t *private_key)
{
    if (!private_key)
        return NULL;

    sm2_ec_point_t pub;
    if (sm2_ic_sm2_point_mult(&pub, private_key->d, SM2_KEY_LEN, NULL)
        != SM2_IC_SUCCESS)
    {
        return NULL;
    }

    uint8_t pub_buf[65];
    pub_buf[0] = 0x04;
    memcpy(pub_buf + 1, pub.x, SM2_KEY_LEN);
    memcpy(pub_buf + 1 + SM2_KEY_LEN, pub.y, SM2_KEY_LEN);

    BIGNUM *d_bn = BN_bin2bn(private_key->d, SM2_KEY_LEN, NULL);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pkey = NULL;

    if (!d_bn || !pctx || !bld)
        goto cleanup;
    if (!OSSL_PARAM_BLD_push_utf8_string(
            bld, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0))
        goto cleanup;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d_bn))
        goto cleanup;
    if (!OSSL_PARAM_BLD_push_octet_string(
            bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, sizeof(pub_buf)))
        goto cleanup;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params)
        goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) <= 0)
        goto cleanup;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
    {
        pkey = NULL;
        goto cleanup;
    }

cleanup:
    BN_clear_free(d_bn);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    sm2_secure_memzero(pub_buf, sizeof(pub_buf));
    sm2_secure_memzero(&pub, sizeof(pub));
    return pkey;
}
static sm2_ic_error_t utils_sign_with_pkey(EVP_PKEY *pkey,
    const uint8_t *message, size_t message_len, sm2_auth_signature_t *signature)
{
    if (!pkey || !message || !signature)
        return SM2_IC_ERR_PARAM;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx)
        return SM2_IC_ERR_MEMORY;

    size_t sig_len = sizeof(signature->der);
    int ok = EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey);
    if (ok == 1)
        ok = EVP_DigestSign(
            mctx, signature->der, &sig_len, message, message_len);
    EVP_MD_CTX_free(mctx);

    if (ok != 1)
        return SM2_IC_ERR_CRYPTO;
    if (sig_len > SM2_AUTH_MAX_SIG_DER_LEN)
        return SM2_IC_ERR_MEMORY;
    signature->der_len = sig_len;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t utils_verify_with_pkey(EVP_PKEY *pkey,
    const uint8_t *message, size_t message_len,
    const sm2_auth_signature_t *signature)
{
    if (!pkey || !message || !signature || signature->der_len == 0)
        return SM2_IC_ERR_PARAM;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx)
        return SM2_IC_ERR_MEMORY;

    int ok = EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey);
    if (ok == 1)
    {
        ok = EVP_DigestVerify(
            mctx, signature->der, signature->der_len, message, message_len);
    }
    EVP_MD_CTX_free(mctx);
    return ok == 1 ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
}

static sm2_ic_error_t utils_kdf_sm3(
    const uint8_t *z, size_t z_len, uint8_t *out, size_t out_len)
{
    if (!z || !out || out_len == 0)
        return SM2_IC_ERR_PARAM;

    if (z_len > SIZE_MAX - 4)
        return SM2_IC_ERR_PARAM;

    uint32_t counter = 1;
    size_t offset = 0;
    size_t in_len = z_len + 4;
    uint8_t *in_buf = (uint8_t *)malloc(in_len);
    if (!in_buf)
        return SM2_IC_ERR_MEMORY;

    while (offset < out_len)
    {
        memcpy(in_buf, z, z_len);
        in_buf[z_len + 0] = (uint8_t)(counter >> 24);
        in_buf[z_len + 1] = (uint8_t)(counter >> 16);
        in_buf[z_len + 2] = (uint8_t)(counter >> 8);
        in_buf[z_len + 3] = (uint8_t)(counter);

        uint8_t block[SM3_DIGEST_LENGTH];
        sm2_ic_error_t ret = sm2_ic_sm3_hash(in_buf, z_len + 4, block);
        if (ret != SM2_IC_SUCCESS)
        {
            sm2_secure_memzero(in_buf, in_len);
            free(in_buf);
            return ret;
        }

        size_t n = (out_len - offset < SM3_DIGEST_LENGTH) ? (out_len - offset)
                                                          : SM3_DIGEST_LENGTH;
        memcpy(out + offset, block, n);
        offset += n;
        counter++;
    }

    sm2_secure_memzero(in_buf, in_len);
    free(in_buf);
    return SM2_IC_SUCCESS;
}

static bool utils_private_key_is_zero(const sm2_private_key_t *private_key)
{
    if (!private_key)
        return true;
    for (size_t i = 0; i < SM2_KEY_LEN; i++)
    {
        if (private_key->d[i] != 0)
            return false;
    }
    return true;
}

static sm2_ic_error_t utils_ecdh_shared_xy(
    const sm2_private_key_t *local_private_key,
    const sm2_ec_point_t *peer_public_key, uint8_t shared_xy[64])
{
    if (!local_private_key || !peer_public_key || !shared_xy)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = SM2_IC_ERR_CRYPTO;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    BN_CTX *bn_ctx = NULL;
    BIGNUM *d = NULL;
    EC_POINT *peer = NULL;
    EC_POINT *shared = NULL;
    uint8_t pub_buf[65];
    uint8_t shared_buf[65];

    memset(pub_buf, 0, sizeof(pub_buf));
    memset(shared_buf, 0, sizeof(shared_buf));
    memset(shared_xy, 0, 64);

    if (!group)
        return SM2_IC_ERR_CRYPTO;

    bn_ctx = BN_CTX_new();
    d = BN_bin2bn(local_private_key->d, SM2_KEY_LEN, NULL);
    peer = EC_POINT_new(group);
    shared = EC_POINT_new(group);
    if (!bn_ctx || !d || !peer || !shared)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto cleanup;
    }

    pub_buf[0] = 0x04;
    memcpy(pub_buf + 1, peer_public_key->x, SM2_KEY_LEN);
    memcpy(pub_buf + 1 + SM2_KEY_LEN, peer_public_key->y, SM2_KEY_LEN);

    if (EC_POINT_oct2point(group, peer, pub_buf, sizeof(pub_buf), bn_ctx) != 1
        || EC_POINT_mul(group, shared, NULL, peer, d, bn_ctx) != 1)
    {
        ret = SM2_IC_ERR_CRYPTO;
        goto cleanup;
    }

    if (EC_POINT_point2oct(group, shared, POINT_CONVERSION_UNCOMPRESSED,
            shared_buf, sizeof(shared_buf), bn_ctx)
        != sizeof(shared_buf))
    {
        ret = SM2_IC_ERR_CRYPTO;
        goto cleanup;
    }

    memcpy(shared_xy, shared_buf + 1, 64);
    ret = SM2_IC_SUCCESS;

cleanup:
    sm2_secure_memzero(shared_buf, sizeof(shared_buf));
    sm2_secure_memzero(pub_buf, sizeof(pub_buf));
    EC_POINT_free(shared);
    EC_POINT_free(peer);
    BN_clear_free(d);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

static sm2_ic_error_t utils_validate_keypair(
    const sm2_private_key_t *private_key, const sm2_ec_point_t *public_key)
{
    if (!private_key || !public_key)
        return SM2_IC_ERR_PARAM;

    sm2_ec_point_t derived;
    sm2_ic_error_t ret
        = sm2_ic_sm2_point_mult(&derived, private_key->d, SM2_KEY_LEN, NULL);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (memcmp(&derived, public_key, sizeof(derived)) != 0)
        return SM2_IC_ERR_VERIFY;
    return SM2_IC_SUCCESS;
}

static const EVP_CIPHER *utils_sm4_aead_cipher(sm2_auth_aead_mode_t mode)
{
    switch (mode)
    {
        case SM2_AUTH_AEAD_MODE_SM4_GCM:
            return EVP_get_cipherbyname("SM4-GCM");
        case SM2_AUTH_AEAD_MODE_SM4_CCM:
            return EVP_get_cipherbyname("SM4-CCM");
        default:
            return NULL;
    }
}

static bool utils_size_to_int(size_t value, int *out)
{
    if (!out || value > (size_t)INT_MAX)
        return false;
    *out = (int)value;
    return true;
}
static sm2_ic_error_t utils_sm4_crypt_ctr(int encrypt, const uint8_t key[16],
    const uint8_t iv[16], const uint8_t *input, size_t input_len,
    uint8_t *output, size_t *output_len)
{
    if (!key || !iv || !input || !output || !output_len)
        return SM2_IC_ERR_PARAM;
    if (*output_len < input_len)
        return SM2_IC_ERR_MEMORY;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return SM2_IC_ERR_CRYPTO;

    int len = 0;
    int total = 0;
    int ok = 1;
    if (encrypt)
    {
        ok = EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv);
        if (ok == 1)
            ok = EVP_EncryptUpdate(ctx, output, &len, input, (int)input_len);
        total = len;
        if (ok == 1)
            ok = EVP_EncryptFinal_ex(ctx, output + total, &len);
        total += len;
    }
    else
    {
        ok = EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv);
        if (ok == 1)
            ok = EVP_DecryptUpdate(ctx, output, &len, input, (int)input_len);
        total = len;
        if (ok == 1)
            ok = EVP_DecryptFinal_ex(ctx, output + total, &len);
        total += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1)
        return SM2_IC_ERR_CRYPTO;
    *output_len = (size_t)total;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_precompute_pool_init(sm2_auth_precompute_pool_t *pool,
    const sm2_private_key_t *signing_key, size_t capacity)
{
    if (!pool || !signing_key || capacity == 0)
        return SM2_IC_ERR_PARAM;
    memset(pool, 0, sizeof(*pool));
    pool->slots = (sm2_auth_precomp_slot_t *)calloc(
        capacity, sizeof(sm2_auth_precomp_slot_t));
    if (!pool->slots)
        return SM2_IC_ERR_MEMORY;

    pool->signing_key = *signing_key;
    pool->capacity = capacity;
    pool->available = 0;
    pool->next_slot = 0;
    pool->native_sign_key = (void *)utils_pkey_from_private(&pool->signing_key);
    if (!pool->native_sign_key)
    {
        free(pool->slots);
        sm2_secure_memzero(pool, sizeof(*pool));
        return SM2_IC_ERR_CRYPTO;
    }
    return SM2_IC_SUCCESS;
}

void sm2_auth_precompute_pool_cleanup(sm2_auth_precompute_pool_t *pool)
{
    if (!pool)
        return;
    if (pool->native_sign_key)
    {
        EVP_PKEY_free((EVP_PKEY *)pool->native_sign_key);
    }
    free(pool->slots);
    sm2_secure_memzero(pool, sizeof(*pool));
}

size_t sm2_auth_precompute_pool_available(
    const sm2_auth_precompute_pool_t *pool)
{
    return pool ? pool->available : 0;
}

sm2_ic_error_t sm2_auth_precompute_pool_fill(
    sm2_auth_precompute_pool_t *pool, size_t target_available)
{
    if (!pool || !pool->slots)
        return SM2_IC_ERR_PARAM;
    if (!pool->native_sign_key)
        return SM2_IC_ERR_PARAM;
    if (target_available > pool->capacity)
        target_available = pool->capacity;
    if (pool->available >= target_available)
        return SM2_IC_SUCCESS;

    size_t cap = pool->capacity;
    size_t target = target_available;

    /* EVP does not expose ECDSA (kinv,r) precomputation.
     * We keep a
     * lightweight token pool to represent
     * message-independent prepared
     * signing capacity.
     */
    for (size_t i = 0; i < cap && pool->available < target; i++)
    {
        if (pool->slots[i].used)
            continue;
        pool->slots[i].used = true;
        pool->available++;
    }
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_sign(const sm2_private_key_t *signing_key,
    const uint8_t *message, size_t message_len, sm2_auth_signature_t *signature)
{
    if (!signing_key || !message || !signature)
        return SM2_IC_ERR_PARAM;
    memset(signature, 0, sizeof(*signature));

    EVP_PKEY *pkey = utils_pkey_from_private(signing_key);
    if (!pkey)
        return SM2_IC_ERR_CRYPTO;
    sm2_ic_error_t ret
        = utils_sign_with_pkey(pkey, message, message_len, signature);
    EVP_PKEY_free(pkey);
    return ret;
}

sm2_ic_error_t sm2_auth_sign_with_pool(sm2_auth_precompute_pool_t *pool,
    const uint8_t *message, size_t message_len, sm2_auth_signature_t *signature)
{
    if (!pool || !message || !signature)
        return SM2_IC_ERR_PARAM;
    if (!pool->native_sign_key)
        return SM2_IC_ERR_PARAM;
    memset(signature, 0, sizeof(*signature));

    size_t consumed_idx = pool->capacity;
    for (size_t n = 0; n < pool->capacity; n++)
    {
        size_t i = (pool->next_slot + n) % pool->capacity;
        if (!pool->slots[i].used)
            continue;
        consumed_idx = i;
        break;
    }
    if (consumed_idx != pool->capacity)
    {
        pool->slots[consumed_idx].used = false;
        if (pool->available > 0)
            pool->available--;
        pool->next_slot = (consumed_idx + 1) % pool->capacity;
    }

    return utils_sign_with_pkey(
        (EVP_PKEY *)pool->native_sign_key, message, message_len, signature);
}

sm2_ic_error_t sm2_auth_verify_signature(const sm2_ec_point_t *public_key,
    const uint8_t *message, size_t message_len,
    const sm2_auth_signature_t *signature)
{
    if (!public_key || !message || !signature || signature->der_len == 0)
        return SM2_IC_ERR_PARAM;

    EVP_PKEY *pkey = utils_pkey_from_public(public_key);
    if (!pkey)
        return SM2_IC_ERR_CRYPTO;
    sm2_ic_error_t ret
        = utils_verify_with_pkey(pkey, message, message_len, signature);
    EVP_PKEY_free(pkey);
    return ret;
}

sm2_ic_error_t sm2_auth_batch_verify(
    const sm2_auth_verify_item_t *items, size_t item_count, size_t *valid_count)
{
    if (!items || item_count == 0)
        return SM2_IC_ERR_PARAM;
    if (valid_count)
        *valid_count = 0;

    verify_key_cache_t cache[8];
    memset(cache, 0, sizeof(cache));

    size_t ok_count = 0;
    for (size_t i = 0; i < item_count; i++)
    {
        if (!items[i].public_key || !items[i].signature || !items[i].message)
            return SM2_IC_ERR_PARAM;

        uint8_t raw[SM2_KEY_LEN * 2];
        memcpy(raw, items[i].public_key->x, SM2_KEY_LEN);
        memcpy(raw + SM2_KEY_LEN, items[i].public_key->y, SM2_KEY_LEN);

        EVP_PKEY *key = NULL;
        for (size_t k = 0; k < sizeof(cache) / sizeof(cache[0]); k++)
        {
            if (cache[k].used
                && memcmp(cache[k].key_raw, raw, sizeof(raw)) == 0)
            {
                key = cache[k].pkey;
                break;
            }
        }
        if (!key)
        {
            key = utils_pkey_from_public(items[i].public_key);
            if (!key)
            {
                for (size_t k = 0; k < sizeof(cache) / sizeof(cache[0]); k++)
                {
                    if (cache[k].used)
                        EVP_PKEY_free(cache[k].pkey);
                }
                return SM2_IC_ERR_CRYPTO;
            }

            size_t pos = 0;
            bool placed = false;
            for (; pos < sizeof(cache) / sizeof(cache[0]); pos++)
            {
                if (!cache[pos].used)
                {
                    placed = true;
                    break;
                }
            }
            if (!placed)
                pos = 0;
            if (cache[pos].used)
                EVP_PKEY_free(cache[pos].pkey);
            cache[pos].used = true;
            memcpy(cache[pos].key_raw, raw, sizeof(raw));
            cache[pos].pkey = key;
        }

        sm2_ic_error_t ret = utils_verify_with_pkey(
            key, items[i].message, items[i].message_len, items[i].signature);
        if (ret == SM2_IC_SUCCESS)
            ok_count++;
    }

    for (size_t k = 0; k < sizeof(cache) / sizeof(cache[0]); k++)
    {
        if (cache[k].used)
            EVP_PKEY_free(cache[k].pkey);
    }

    if (ok_count == item_count)
    {
        if (valid_count)
            *valid_count = ok_count;
        return SM2_IC_SUCCESS;
    }

    /* Fallback: strict single verification for per-item truth */
    size_t strict_ok = 0;
    for (size_t i = 0; i < item_count; i++)
    {
        if (sm2_auth_verify_signature(items[i].public_key, items[i].message,
                items[i].message_len, items[i].signature)
            == SM2_IC_SUCCESS)
        {
            strict_ok++;
        }
    }
    if (valid_count)
        *valid_count = strict_ok;
    return SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_auth_trust_store_init(sm2_auth_trust_store_t *store)
{
    if (!store)
        return SM2_IC_ERR_PARAM;
    memset(store, 0, sizeof(*store));
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_trust_store_add_ca(
    sm2_auth_trust_store_t *store, const sm2_ec_point_t *ca_public_key)
{
    if (!store || !ca_public_key)
        return SM2_IC_ERR_PARAM;
    if (store->count >= SM2_AUTH_MAX_CA_STORE)
        return SM2_IC_ERR_MEMORY;
    store->ca_pub_keys[store->count++] = *ca_public_key;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_verify_cert_with_store(const sm2_implicit_cert_t *cert,
    const sm2_ec_point_t *public_key, const sm2_auth_trust_store_t *store,
    size_t *matched_ca_index)
{
    if (!cert || !public_key || !store || store->count == 0)
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < store->count; i++)
    {
        if (sm2_ic_verify_cert(cert, public_key, &store->ca_pub_keys[i])
            == SM2_IC_SUCCESS)
        {
            if (matched_ca_index)
                *matched_ca_index = i;
            return SM2_IC_SUCCESS;
        }
    }
    return SM2_IC_ERR_VERIFY;
}

#define SM2_AUTH_UNIX_TS_MIN 1000000000ULL

static sm2_ic_error_t auth_check_cert_policy(
    const sm2_implicit_cert_t *cert, uint64_t now_ts)
{
    if (!cert)
        return SM2_IC_ERR_PARAM;

    if ((cert->field_mask & SM2_IC_FIELD_KEY_USAGE) != 0
        && (cert->key_usage & SM2_KU_DIGITAL_SIGNATURE) == 0)
    {
        return SM2_IC_ERR_VERIFY;
    }

    bool has_valid_from = (cert->field_mask & SM2_IC_FIELD_VALID_FROM) != 0;
    bool has_valid_duration
        = (cert->field_mask & SM2_IC_FIELD_VALID_DURATION) != 0;

    if (has_valid_from != has_valid_duration)
        return SM2_IC_ERR_VERIFY;

    if (has_valid_from && has_valid_duration)
    {
        bool mixed_timescale = now_ts < SM2_AUTH_UNIX_TS_MIN
            && cert->valid_from >= SM2_AUTH_UNIX_TS_MIN;
        if (!mixed_timescale)
        {
            if (now_ts < cert->valid_from)
                return SM2_IC_ERR_VERIFY;

            uint64_t valid_to = cert->valid_from;
            if (cert->valid_duration <= UINT64_MAX - valid_to)
                valid_to += cert->valid_duration;
            else
                valid_to = UINT64_MAX;

            if (now_ts > valid_to)
                return SM2_IC_ERR_VERIFY;
        }
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_authenticate_request(const sm2_auth_request_t *request,
    const sm2_auth_trust_store_t *store, sm2_revocation_ctx_t *rev_ctx,
    uint64_t now_ts, size_t *matched_ca_index)
{
    if (!request || !request->cert || !request->public_key
        || !request->signature || !request->message)
    {
        return SM2_IC_ERR_PARAM;
    }

    if (request->revocation_policy != SM2_AUTH_REVOCATION_POLICY_PREFER_CALLBACK
        && request->revocation_policy
            != SM2_AUTH_REVOCATION_POLICY_STRICT_CROSS_CHECK)
    {
        return SM2_IC_ERR_PARAM;
    }

    if (request->lightweight_mode
        && request->revocation_policy
            == SM2_AUTH_REVOCATION_POLICY_STRICT_CROSS_CHECK)
    {
        return SM2_IC_ERR_PARAM;
    }

    if (request->lightweight_mode && !request->revocation_query_fn)
        return SM2_IC_ERR_VERIFY;

    sm2_ic_error_t ret = sm2_auth_verify_cert_with_store(
        request->cert, request->public_key, store, matched_ca_index);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = auth_check_cert_policy(request->cert, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (request->revocation_query_fn)
    {
        sm2_rev_status_t status = SM2_REV_STATUS_UNKNOWN;
        ret = request->revocation_query_fn(
            request->cert, now_ts, request->revocation_query_user_ctx, &status);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        if (!request->lightweight_mode && status == SM2_REV_STATUS_GOOD
            && request->revocation_policy
                == SM2_AUTH_REVOCATION_POLICY_STRICT_CROSS_CHECK)
        {
            sm2_rev_status_t local_status = SM2_REV_STATUS_UNKNOWN;
            sm2_rev_source_t local_source = SM2_REV_SOURCE_NONE;
            if (!rev_ctx)
                return SM2_IC_ERR_VERIFY;
            ret = sm2_revocation_query(rev_ctx, request->cert->serial_number,
                now_ts, &local_status, &local_source);
            (void)local_source;
            if (ret != SM2_IC_SUCCESS)
                return ret;
            if (local_status != SM2_REV_STATUS_GOOD)
                return SM2_IC_ERR_VERIFY;
        }

        if (!request->lightweight_mode && status == SM2_REV_STATUS_UNKNOWN
            && rev_ctx)
        {
            sm2_rev_source_t source = SM2_REV_SOURCE_NONE;
            ret = sm2_revocation_query(rev_ctx, request->cert->serial_number,
                now_ts, &status, &source);
            (void)source;
            if (ret != SM2_IC_SUCCESS)
                return ret;
        }

        if (status != SM2_REV_STATUS_GOOD)
            return SM2_IC_ERR_VERIFY;
    }
    else if (!request->lightweight_mode && rev_ctx)
    {
        sm2_rev_status_t status = SM2_REV_STATUS_UNKNOWN;
        sm2_rev_source_t source = SM2_REV_SOURCE_NONE;
        ret = sm2_revocation_query(
            rev_ctx, request->cert->serial_number, now_ts, &status, &source);
        (void)source;
        if (ret != SM2_IC_SUCCESS)
            return ret;
        if (status != SM2_REV_STATUS_GOOD)
            return SM2_IC_ERR_VERIFY;
    }
    else if (request->lightweight_mode)
    {
        return SM2_IC_ERR_VERIFY;
    }

    return sm2_auth_verify_signature(request->public_key, request->message,
        request->message_len, request->signature);
}

sm2_ic_error_t sm2_auth_derive_session_key(
    const sm2_private_key_t *local_private_key,
    const sm2_ec_point_t *peer_public_key, uint8_t *session_key,
    size_t session_key_len)
{
    if (!local_private_key || !peer_public_key || !session_key
        || session_key_len == 0)
    {
        return SM2_IC_ERR_PARAM;
    }

    uint8_t shared_xy[64];
    sm2_ic_error_t ret
        = utils_ecdh_shared_xy(local_private_key, peer_public_key, shared_xy);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = utils_kdf_sm3(
        shared_xy, sizeof(shared_xy), session_key, session_key_len);
    sm2_secure_memzero(shared_xy, sizeof(shared_xy));
    return ret;
}
sm2_ic_error_t sm2_auth_mutual_auth_and_key_agreement(
    const sm2_auth_request_t *a_to_b, const sm2_private_key_t *a_private_key,
    const sm2_auth_trust_store_t *b_trust_store,
    sm2_revocation_ctx_t *b_rev_ctx, const sm2_auth_request_t *b_to_a,
    const sm2_private_key_t *b_private_key,
    const sm2_auth_trust_store_t *a_trust_store,
    sm2_revocation_ctx_t *a_rev_ctx, uint64_t now_ts, uint8_t *session_key_a,
    uint8_t *session_key_b, size_t session_key_len)
{
    if (!a_to_b || !b_to_a || !a_private_key || !b_private_key || !a_trust_store
        || !b_trust_store || !session_key_a || !session_key_b
        || session_key_len == 0)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_ic_error_t ret = sm2_auth_authenticate_request(
        a_to_b, b_trust_store, b_rev_ctx, now_ts, NULL);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_auth_authenticate_request(
        b_to_a, a_trust_store, a_rev_ctx, now_ts, NULL);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_auth_derive_session_key(
        a_private_key, b_to_a->public_key, session_key_a, session_key_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    ret = sm2_auth_derive_session_key(
        b_private_key, a_to_b->public_key, session_key_b, session_key_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (memcmp(session_key_a, session_key_b, session_key_len) != 0)
        return SM2_IC_ERR_VERIFY;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_generate_ephemeral_keypair(
    sm2_private_key_t *ephemeral_private_key,
    sm2_ec_point_t *ephemeral_public_key)
{
    if (!ephemeral_private_key || !ephemeral_public_key)
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < 32; i++)
    {
        sm2_ic_error_t ret
            = sm2_ic_generate_random(ephemeral_private_key->d, SM2_KEY_LEN);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        if (utils_private_key_is_zero(ephemeral_private_key))
            continue;
        ret = sm2_ic_sm2_point_mult(
            ephemeral_public_key, ephemeral_private_key->d, SM2_KEY_LEN, NULL);
        if (ret == SM2_IC_SUCCESS)
            return SM2_IC_SUCCESS;
    }

    return SM2_IC_ERR_CRYPTO;
}

sm2_ic_error_t sm2_auth_derive_session_key_ephemeral(
    const sm2_private_key_t *local_private_key,
    const sm2_private_key_t *local_ephemeral_private_key,
    const sm2_ec_point_t *peer_public_key,
    const sm2_ec_point_t *peer_ephemeral_public_key, const uint8_t *transcript,
    size_t transcript_len, uint8_t *session_key, size_t session_key_len)
{
    if (!local_private_key || !local_ephemeral_private_key || !peer_public_key
        || !peer_ephemeral_public_key || !session_key || session_key_len == 0)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (transcript_len > 0 && !transcript)
        return SM2_IC_ERR_PARAM;

    uint8_t shared_ee[64];
    uint8_t shared_mix_a[64];
    uint8_t shared_mix_b[64];
    sm2_ic_error_t ret = utils_ecdh_shared_xy(
        local_ephemeral_private_key, peer_ephemeral_public_key, shared_ee);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = utils_ecdh_shared_xy(
        local_private_key, peer_ephemeral_public_key, shared_mix_a);
    if (ret != SM2_IC_SUCCESS)
        goto cleanup;

    ret = utils_ecdh_shared_xy(
        local_ephemeral_private_key, peer_public_key, shared_mix_b);
    if (ret != SM2_IC_SUCCESS)
        goto cleanup;

    const uint8_t *mix_first = shared_mix_a;
    const uint8_t *mix_second = shared_mix_b;
    if (memcmp(shared_mix_a, shared_mix_b, sizeof(shared_mix_a)) > 0)
    {
        mix_first = shared_mix_b;
        mix_second = shared_mix_a;
    }

    if (transcript_len > SIZE_MAX
            - (sizeof(shared_ee) + sizeof(shared_mix_a) + sizeof(shared_mix_b)))
    {
        ret = SM2_IC_ERR_PARAM;
        goto cleanup;
    }

    size_t kdf_in_len = sizeof(shared_ee) + sizeof(shared_mix_a)
        + sizeof(shared_mix_b) + transcript_len;
    uint8_t *kdf_in = (uint8_t *)malloc(kdf_in_len);
    if (!kdf_in)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto cleanup;
    }

    size_t off = 0;
    memcpy(kdf_in + off, shared_ee, sizeof(shared_ee));
    off += sizeof(shared_ee);
    memcpy(kdf_in + off, mix_first, sizeof(shared_mix_a));
    off += sizeof(shared_mix_a);
    memcpy(kdf_in + off, mix_second, sizeof(shared_mix_b));
    off += sizeof(shared_mix_b);
    if (transcript_len > 0)
        memcpy(kdf_in + off, transcript, transcript_len);

    ret = utils_kdf_sm3(kdf_in, kdf_in_len, session_key, session_key_len);
    sm2_secure_memzero(kdf_in, kdf_in_len);
    free(kdf_in);

cleanup:
    sm2_secure_memzero(shared_mix_b, sizeof(shared_mix_b));
    sm2_secure_memzero(shared_mix_a, sizeof(shared_mix_a));
    sm2_secure_memzero(shared_ee, sizeof(shared_ee));
    return ret;
}

sm2_ic_error_t sm2_auth_mutual_auth_and_key_agreement_v2(
    const sm2_auth_request_t *a_to_b, const sm2_private_key_t *a_private_key,
    const sm2_private_key_t *a_ephemeral_private_key,
    const sm2_ec_point_t *a_ephemeral_public_key,
    const sm2_auth_trust_store_t *b_trust_store,
    sm2_revocation_ctx_t *b_rev_ctx, const sm2_auth_request_t *b_to_a,
    const sm2_private_key_t *b_private_key,
    const sm2_private_key_t *b_ephemeral_private_key,
    const sm2_ec_point_t *b_ephemeral_public_key,
    const sm2_auth_trust_store_t *a_trust_store,
    sm2_revocation_ctx_t *a_rev_ctx, uint64_t now_ts, const uint8_t *transcript,
    size_t transcript_len, uint8_t *session_key_a, uint8_t *session_key_b,
    size_t session_key_len)
{
    if (!a_to_b || !b_to_a || !a_private_key || !a_ephemeral_private_key
        || !a_ephemeral_public_key || !b_private_key || !b_ephemeral_private_key
        || !b_ephemeral_public_key || !a_trust_store || !b_trust_store
        || !session_key_a || !session_key_b || session_key_len == 0)
    {
        return SM2_IC_ERR_PARAM;
    }

    if (transcript_len > 0 && !transcript)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = utils_validate_keypair(
        a_ephemeral_private_key, a_ephemeral_public_key);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    ret = utils_validate_keypair(
        b_ephemeral_private_key, b_ephemeral_public_key);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_auth_authenticate_request(
        a_to_b, b_trust_store, b_rev_ctx, now_ts, NULL);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_auth_authenticate_request(
        b_to_a, a_trust_store, a_rev_ctx, now_ts, NULL);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_auth_derive_session_key_ephemeral(a_private_key,
        a_ephemeral_private_key, b_to_a->public_key, b_ephemeral_public_key,
        transcript, transcript_len, session_key_a, session_key_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_auth_derive_session_key_ephemeral(b_private_key,
        b_ephemeral_private_key, a_to_b->public_key, a_ephemeral_public_key,
        transcript, transcript_len, session_key_b, session_key_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (memcmp(session_key_a, session_key_b, session_key_len) != 0)
        return SM2_IC_ERR_VERIFY;

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_sm4_aead_encrypt(sm2_auth_aead_mode_t mode,
    const uint8_t key[16], const uint8_t *iv, size_t iv_len, const uint8_t *aad,
    size_t aad_len, const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len, uint8_t *tag, size_t *tag_len)
{
    if (!key || !iv || iv_len == 0 || !ciphertext || !ciphertext_len || !tag
        || !tag_len)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (plaintext_len > 0 && !plaintext)
        return SM2_IC_ERR_PARAM;
    if (aad_len > 0 && !aad)
        return SM2_IC_ERR_PARAM;
    if (*ciphertext_len < plaintext_len)
        return SM2_IC_ERR_MEMORY;

    size_t actual_tag_len = (*tag_len == 0) ? 16 : *tag_len;
    if (actual_tag_len < 8 || actual_tag_len > SM2_AUTH_AEAD_TAG_MAX_LEN)
        return SM2_IC_ERR_PARAM;

    int iv_len_i = 0;
    int aad_len_i = 0;
    int plaintext_len_i = 0;
    if (!utils_size_to_int(iv_len, &iv_len_i)
        || !utils_size_to_int(aad_len, &aad_len_i)
        || !utils_size_to_int(plaintext_len, &plaintext_len_i))
    {
        return SM2_IC_ERR_PARAM;
    }

    const EVP_CIPHER *cipher = utils_sm4_aead_cipher(mode);
    if (!cipher)
        return SM2_IC_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return SM2_IC_ERR_CRYPTO;

    int ok = 1;
    int len = 0;
    int total = 0;

    if (mode == SM2_AUTH_AEAD_MODE_SM4_GCM)
    {
        ok = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len_i, NULL);
        if (ok == 1)
            ok = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        if (ok == 1 && aad_len_i > 0)
            ok = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len_i);
        if (ok == 1 && plaintext_len_i > 0)
            ok = EVP_EncryptUpdate(
                ctx, ciphertext, &len, plaintext, plaintext_len_i);
        total = len;
        if (ok == 1)
            ok = EVP_EncryptFinal_ex(ctx, ciphertext + total, &len);
        total += len;
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_GET_TAG, (int)actual_tag_len, tag);
    }
    else
    {
        ok = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len_i, NULL);
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_AEAD_SET_TAG, (int)actual_tag_len, NULL);
        if (ok == 1)
            ok = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        if (ok == 1)
            ok = EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len_i);
        if (ok == 1 && aad_len_i > 0)
            ok = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len_i);
        if (ok == 1 && plaintext_len_i > 0)
            ok = EVP_EncryptUpdate(
                ctx, ciphertext, &len, plaintext, plaintext_len_i);
        total = len;
        if (ok == 1)
            ok = EVP_EncryptFinal_ex(ctx, ciphertext + total, &len);
        total += len;
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_AEAD_GET_TAG, (int)actual_tag_len, tag);
    }

    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1)
        return SM2_IC_ERR_CRYPTO;

    *ciphertext_len = (size_t)total;
    *tag_len = actual_tag_len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_auth_sm4_aead_decrypt(sm2_auth_aead_mode_t mode,
    const uint8_t key[16], const uint8_t *iv, size_t iv_len, const uint8_t *aad,
    size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag, size_t tag_len, uint8_t *plaintext,
    size_t *plaintext_len)
{
    if (!key || !iv || iv_len == 0 || !ciphertext || !tag || !plaintext
        || !plaintext_len)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (aad_len > 0 && !aad)
        return SM2_IC_ERR_PARAM;
    if (tag_len < 8 || tag_len > SM2_AUTH_AEAD_TAG_MAX_LEN)
        return SM2_IC_ERR_PARAM;
    if (*plaintext_len < ciphertext_len)
        return SM2_IC_ERR_MEMORY;

    int iv_len_i = 0;
    int aad_len_i = 0;
    int ciphertext_len_i = 0;
    if (!utils_size_to_int(iv_len, &iv_len_i)
        || !utils_size_to_int(aad_len, &aad_len_i)
        || !utils_size_to_int(ciphertext_len, &ciphertext_len_i))
    {
        return SM2_IC_ERR_PARAM;
    }

    const EVP_CIPHER *cipher = utils_sm4_aead_cipher(mode);
    if (!cipher)
        return SM2_IC_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return SM2_IC_ERR_CRYPTO;

    int ok = 1;
    int len = 0;
    int total = 0;

    if (mode == SM2_AUTH_AEAD_MODE_SM4_GCM)
    {
        ok = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len_i, NULL);
        if (ok == 1)
            ok = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        if (ok == 1 && aad_len_i > 0)
            ok = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len_i);
        if (ok == 1 && ciphertext_len_i > 0)
            ok = EVP_DecryptUpdate(
                ctx, plaintext, &len, ciphertext, ciphertext_len_i);
        total = len;
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)tag);
        if (ok == 1)
            ok = EVP_DecryptFinal_ex(ctx, plaintext + total, &len);
        total += len;
    }
    else
    {
        ok = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len_i, NULL);
        if (ok == 1)
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, (void *)tag);
        if (ok == 1)
            ok = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        if (ok == 1)
            ok = EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len_i);
        if (ok == 1 && aad_len_i > 0)
            ok = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len_i);
        if (ok == 1 && ciphertext_len_i > 0)
            ok = EVP_DecryptUpdate(
                ctx, plaintext, &len, ciphertext, ciphertext_len_i);
        total = len;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1)
        return SM2_IC_ERR_VERIFY;

    *plaintext_len = (size_t)total;
    return SM2_IC_SUCCESS;
}
sm2_ic_error_t sm2_auth_sm4_encrypt(const uint8_t key[16], const uint8_t iv[16],
    const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext,
    size_t *ciphertext_len)
{
    return utils_sm4_crypt_ctr(
        1, key, iv, plaintext, plaintext_len, ciphertext, ciphertext_len);
}

sm2_ic_error_t sm2_auth_sm4_decrypt(const uint8_t key[16], const uint8_t iv[16],
    const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext,
    size_t *plaintext_len)
{
    return utils_sm4_crypt_ctr(
        0, key, iv, ciphertext, ciphertext_len, plaintext, plaintext_len);
}
