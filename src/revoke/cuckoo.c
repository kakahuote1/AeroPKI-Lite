/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file cuckoo.c
 * @brief Cuckoo filter engine and shared hash/utilities for revocation module.
 */

#include "revoke_internal.h"
#include <stdlib.h>
#include <string.h>

static uint64_t utils_mix_u64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static void utils_u64_to_be(uint64_t v, uint8_t out[8])
{
    for (int i = 0; i < 8; i++)
        out[7 - i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}

static uint64_t utils_hash_u64_sm3_tag(uint64_t v, uint8_t tag)
{
    uint8_t in[9];
    uint8_t out[SM3_DIGEST_LENGTH];
    in[0] = tag;
    for (int i = 0; i < 8; i++)
        in[8 - i] = (uint8_t)((v >> (i * 8)) & 0xFF);
    if (sm2_ic_sm3_hash(in, sizeof(in), out) != SM2_IC_SUCCESS)
        return utils_mix_u64(v);

    uint64_t h = 0;
    for (int i = 0; i < 8; i++)
        h = (h << 8) | out[i];
    return h;
}

static size_t utils_next_pow2(size_t v)
{
    size_t p = 1;
    while (p < v)
        p <<= 1;
    return p;
}

static void utils_xor_digest(uint8_t out[SM2_REV_SYNC_DIGEST_LEN],
    const uint8_t in[SM2_REV_SYNC_DIGEST_LEN])
{
    for (size_t i = 0; i < SM2_REV_SYNC_DIGEST_LEN; i++)
        out[i] ^= in[i];
}

static sm2_ic_error_t utils_calc_filter_param_hash(uint8_t fp_bits,
    size_t bucket_size, size_t bucket_count,
    uint8_t out[SM2_REV_SYNC_DIGEST_LEN])
{
    uint8_t buf[1 + 8 + 8];
    uint8_t bs[8];
    uint8_t bc[8];
    buf[0] = fp_bits;
    utils_u64_to_be((uint64_t)bucket_size, bs);
    utils_u64_to_be((uint64_t)bucket_count, bc);
    memcpy(buf + 1, bs, sizeof(bs));
    memcpy(buf + 1 + sizeof(bs), bc, sizeof(bc));
    return sm2_ic_sm3_hash(buf, sizeof(buf), out);
}

static sm2_ic_error_t utils_refresh_filter_param_hash(sm2_revocation_ctx_t *ctx)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;
    return utils_calc_filter_param_hash(ctx->filter.fp_bits,
        ctx->filter.bucket_size, ctx->filter.bucket_count,
        ctx->filter_param_hash);
}

static sm2_ic_error_t utils_calc_set_digest(
    const sm2_revocation_ctx_t *ctx, uint8_t out[SM2_REV_SYNC_DIGEST_LEN])
{
    if (!ctx || !out)
        return SM2_IC_ERR_PARAM;

    uint8_t acc[SM2_REV_SYNC_DIGEST_LEN];
    memset(acc, 0, sizeof(acc));

    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        uint8_t in[9];
        uint8_t digest[SM2_REV_SYNC_DIGEST_LEN];
        in[0] = 1;
        utils_u64_to_be(ctx->revoked_serials[i], in + 1);
        if (sm2_ic_sm3_hash(in, sizeof(in), digest) != SM2_IC_SUCCESS)
            return SM2_IC_ERR_CRYPTO;
        utils_xor_digest(acc, digest);
    }

    uint8_t meta[16 + SM2_REV_SYNC_DIGEST_LEN];
    utils_u64_to_be(ctx->crl_version, meta);
    utils_u64_to_be((uint64_t)ctx->revoked_count, meta + 8);
    memcpy(meta + 16, acc, sizeof(acc));

    return sm2_ic_sm3_hash(meta, sizeof(meta), out);
}

static uint32_t cuckoo_fp(const sm2_cuckoo_filter_t *f, uint64_t serial)
{
    if (!f || f->fp_bits == 0 || f->fp_bits > 32)
        return 1;
    uint64_t h = utils_hash_u64_sm3_tag(serial, 0xA1);
    uint32_t mask
        = (f->fp_bits == 32) ? 0xFFFFFFFFU : ((1U << f->fp_bits) - 1U);
    uint32_t fp = (uint32_t)(h & mask);
    return fp == 0 ? 1 : fp;
}

static size_t cuckoo_index1(const sm2_cuckoo_filter_t *f, uint64_t serial)
{
    return (size_t)(utils_hash_u64_sm3_tag(serial, 0xB2)
        & (uint64_t)(f->bucket_count - 1));
}

static size_t cuckoo_index2(
    const sm2_cuckoo_filter_t *f, size_t i1, uint32_t fp)
{
    uint64_t h = utils_hash_u64_sm3_tag((uint64_t)fp, 0xC3);
    return (size_t)((i1 ^ (size_t)h) & (f->bucket_count - 1));
}

static uint32_t *cuckoo_bucket_slot(
    const sm2_cuckoo_filter_t *f, size_t bucket, size_t slot)
{
    return &f->fingerprints[bucket * f->bucket_size + slot];
}

static bool cuckoo_contains(const sm2_cuckoo_filter_t *f, uint64_t serial)
{
    uint32_t fp = cuckoo_fp(f, serial);
    size_t i1 = cuckoo_index1(f, serial);
    size_t i2 = cuckoo_index2(f, i1, fp);

    for (size_t s = 0; s < f->bucket_size; s++)
    {
        if (*cuckoo_bucket_slot(f, i1, s) == fp)
            return true;
        if (*cuckoo_bucket_slot(f, i2, s) == fp)
            return true;
    }
    return false;
}

static bool cuckoo_delete(sm2_cuckoo_filter_t *f, uint64_t serial)
{
    uint32_t fp = cuckoo_fp(f, serial);
    size_t i1 = cuckoo_index1(f, serial);
    size_t i2 = cuckoo_index2(f, i1, fp);

    for (size_t s = 0; s < f->bucket_size; s++)
    {
        uint32_t *a = cuckoo_bucket_slot(f, i1, s);
        if (*a == fp)
        {
            *a = 0;
            return true;
        }
        uint32_t *b = cuckoo_bucket_slot(f, i2, s);
        if (*b == fp)
        {
            *b = 0;
            return true;
        }
    }
    return false;
}

static sm2_ic_error_t cuckoo_insert(sm2_cuckoo_filter_t *f, uint64_t serial)
{
    uint32_t fp = cuckoo_fp(f, serial);
    size_t i1 = cuckoo_index1(f, serial);
    size_t i2 = cuckoo_index2(f, i1, fp);

    for (size_t s = 0; s < f->bucket_size; s++)
    {
        uint32_t *a = cuckoo_bucket_slot(f, i1, s);
        if (*a == 0)
        {
            *a = fp;
            return SM2_IC_SUCCESS;
        }
        uint32_t *b = cuckoo_bucket_slot(f, i2, s);
        if (*b == 0)
        {
            *b = fp;
            return SM2_IC_SUCCESS;
        }
    }

    size_t idx = (utils_hash_u64_sm3_tag(serial, 0xD4) & 1U) ? i1 : i2;
    uint32_t cur_fp = fp;

    for (size_t kick = 0; kick < f->max_kicks; kick++)
    {
        size_t slot = (size_t)(utils_hash_u64_sm3_tag(
                                   ((uint64_t)cur_fp << 32) | kick, 0xE5)
            % f->bucket_size);
        uint32_t *target = cuckoo_bucket_slot(f, idx, slot);
        uint32_t victim = *target;
        *target = cur_fp;
        cur_fp = victim;

        idx = cuckoo_index2(f, idx, cur_fp);
        for (size_t s = 0; s < f->bucket_size; s++)
        {
            uint32_t *cand = cuckoo_bucket_slot(f, idx, s);
            if (*cand == 0)
            {
                *cand = cur_fp;
                return SM2_IC_SUCCESS;
            }
        }
    }
    return SM2_IC_ERR_MEMORY;
}

static sm2_ic_error_t cuckoo_reset(sm2_cuckoo_filter_t *f, size_t bucket_count,
    size_t bucket_size, size_t max_kicks, uint8_t fp_bits)
{
    if (!f || bucket_count == 0 || bucket_size == 0)
        return SM2_IC_ERR_PARAM;
    if (fp_bits == 0 || fp_bits > 32)
        return SM2_IC_ERR_PARAM;

    uint32_t *new_mem
        = (uint32_t *)calloc(bucket_count * bucket_size, sizeof(uint32_t));
    if (!new_mem)
        return SM2_IC_ERR_MEMORY;

    free(f->fingerprints);
    f->fingerprints = new_mem;
    f->bucket_count = bucket_count;
    f->bucket_size = bucket_size;
    f->max_kicks = max_kicks;
    f->fp_bits = fp_bits;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t rebuild_filter(sm2_revocation_ctx_t *ctx)
{
    size_t min_buckets = utils_next_pow2((ctx->revoked_count / 3) + 64);
    if (min_buckets < 64)
        min_buckets = 64;

    sm2_ic_error_t ret = cuckoo_reset(&ctx->filter, min_buckets,
        ctx->filter.bucket_size, ctx->filter.max_kicks, ctx->filter.fp_bits);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        ret = cuckoo_insert(&ctx->filter, ctx->revoked_serials[i]);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    return utils_refresh_filter_param_hash(ctx);
}

void sm2_rev_internal_u64_to_be(uint64_t v, uint8_t out[8])
{
    utils_u64_to_be(v, out);
}

uint64_t sm2_rev_internal_hash_u64_sm3_tag(uint64_t v, uint8_t tag)
{
    return utils_hash_u64_sm3_tag(v, tag);
}

size_t sm2_rev_internal_next_pow2(size_t v)
{
    return utils_next_pow2(v);
}

sm2_ic_error_t sm2_rev_internal_refresh_filter_param_hash(
    sm2_revocation_ctx_t *ctx)
{
    return utils_refresh_filter_param_hash(ctx);
}

sm2_ic_error_t sm2_rev_internal_calc_set_digest(
    const sm2_revocation_ctx_t *ctx, uint8_t out[SM2_REV_SYNC_DIGEST_LEN])
{
    return utils_calc_set_digest(ctx, out);
}

uint32_t sm2_rev_internal_cuckoo_fp(
    const sm2_cuckoo_filter_t *f, uint64_t serial)
{
    return cuckoo_fp(f, serial);
}

size_t sm2_rev_internal_cuckoo_index1(
    const sm2_cuckoo_filter_t *f, uint64_t serial)
{
    return cuckoo_index1(f, serial);
}

size_t sm2_rev_internal_cuckoo_index2(
    const sm2_cuckoo_filter_t *f, size_t i1, uint32_t fp)
{
    return cuckoo_index2(f, i1, fp);
}

uint32_t *sm2_rev_internal_cuckoo_bucket_slot(
    const sm2_cuckoo_filter_t *f, size_t bucket, size_t slot)
{
    return cuckoo_bucket_slot(f, bucket, slot);
}

bool sm2_rev_internal_cuckoo_contains(
    const sm2_cuckoo_filter_t *f, uint64_t serial)
{
    return cuckoo_contains(f, serial);
}

bool sm2_rev_internal_cuckoo_delete(sm2_cuckoo_filter_t *f, uint64_t serial)
{
    return cuckoo_delete(f, serial);
}

sm2_ic_error_t sm2_rev_internal_cuckoo_insert(
    sm2_cuckoo_filter_t *f, uint64_t serial)
{
    return cuckoo_insert(f, serial);
}

sm2_ic_error_t sm2_rev_internal_cuckoo_reset(sm2_cuckoo_filter_t *f,
    size_t bucket_count, size_t bucket_size, size_t max_kicks, uint8_t fp_bits)
{
    return cuckoo_reset(f, bucket_count, bucket_size, max_kicks, fp_bits);
}

sm2_ic_error_t sm2_rev_internal_rebuild_filter(sm2_revocation_ctx_t *ctx)
{
    return rebuild_filter(ctx);
}
