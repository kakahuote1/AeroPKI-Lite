/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_revocation.c
 * @brief Online/offline revocation manager based on OCSP + incremental CRL +
 * Cuckoo Filter.
 */

#include "sm2_revocation.h"
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

static sm2_ic_error_t local_list_add(sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        if (ctx->revoked_serials[i] == serial)
            return SM2_IC_SUCCESS;
    }

    if (ctx->revoked_count == ctx->revoked_capacity)
    {
        size_t new_cap
            = ctx->revoked_capacity == 0 ? 64 : ctx->revoked_capacity * 2;
        uint64_t *new_mem = (uint64_t *)realloc(
            ctx->revoked_serials, new_cap * sizeof(uint64_t));
        if (!new_mem)
            return SM2_IC_ERR_MEMORY;
        ctx->revoked_serials = new_mem;
        ctx->revoked_capacity = new_cap;
    }

    ctx->revoked_serials[ctx->revoked_count++] = serial;
    return SM2_IC_SUCCESS;
}

static void local_list_remove(sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        if (ctx->revoked_serials[i] == serial)
        {
            ctx->revoked_serials[i]
                = ctx->revoked_serials[ctx->revoked_count - 1];
            ctx->revoked_count--;
            return;
        }
    }
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
    return SM2_IC_SUCCESS;
}

static sm2_ocsp_cache_entry_t *cache_find(
    sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    for (size_t i = 0; i < ctx->ocsp_cache_capacity; i++)
    {
        if (ctx->ocsp_cache[i].used
            && ctx->ocsp_cache[i].serial_number == serial)
        {
            return &ctx->ocsp_cache[i];
        }
    }
    return NULL;
}

static sm2_ocsp_cache_entry_t *cache_pick_slot(sm2_revocation_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->ocsp_cache_capacity; i++)
    {
        if (!ctx->ocsp_cache[i].used)
            return &ctx->ocsp_cache[i];
    }
    return &ctx->ocsp_cache[0];
}

static void cache_put(sm2_revocation_ctx_t *ctx, uint64_t serial,
    sm2_rev_status_t status, uint64_t expires_at)
{
    if (!ctx->ocsp_cache || ctx->ocsp_cache_capacity == 0)
        return;

    sm2_ocsp_cache_entry_t *e = cache_find(ctx, serial);
    if (!e)
        e = cache_pick_slot(ctx);
    if (!e)
        return;

    e->used = true;
    e->serial_number = serial;
    e->status = status;
    e->expires_at = expires_at;
}

sm2_ic_error_t sm2_revocation_init(sm2_revocation_ctx_t *ctx,
    size_t expected_revoked_items, uint64_t filter_ttl_sec, uint64_t now_ts)
{
    if (!ctx || filter_ttl_sec == 0)
        return SM2_IC_ERR_PARAM;
    memset(ctx, 0, sizeof(*ctx));

    size_t bucket_count = utils_next_pow2((expected_revoked_items / 3) + 64);
    if (bucket_count < 64)
        bucket_count = 64;

    sm2_ic_error_t ret = cuckoo_reset(&ctx->filter, bucket_count, 4, 500, 32);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ctx->filter_ttl_sec = filter_ttl_sec;
    ctx->filter_expire_at = now_ts + filter_ttl_sec;
    ctx->crl_version = 0;
    ctx->online_mode = false;
    return SM2_IC_SUCCESS;
}

void sm2_revocation_cleanup(sm2_revocation_ctx_t *ctx)
{
    if (!ctx)
        return;
    free(ctx->filter.fingerprints);
    free(ctx->revoked_serials);
    free(ctx->ocsp_cache);
    memset(ctx, 0, sizeof(*ctx));
}

sm2_ic_error_t sm2_revocation_set_online(
    sm2_revocation_ctx_t *ctx, bool online_mode)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;
    ctx->online_mode = online_mode;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_config_ocsp(
    sm2_revocation_ctx_t *ctx, const sm2_ocsp_client_cfg_t *cfg)
{
    if (!ctx || !cfg)
        return SM2_IC_ERR_PARAM;

    ctx->ocsp_cfg = *cfg;
    if (ctx->ocsp_cfg.cache_capacity == 0)
    {
        free(ctx->ocsp_cache);
        ctx->ocsp_cache = NULL;
        ctx->ocsp_cache_capacity = 0;
        return SM2_IC_SUCCESS;
    }

    sm2_ocsp_cache_entry_t *new_cache = (sm2_ocsp_cache_entry_t *)calloc(
        cfg->cache_capacity, sizeof(sm2_ocsp_cache_entry_t));
    if (!new_cache)
        return SM2_IC_ERR_MEMORY;

    free(ctx->ocsp_cache);
    ctx->ocsp_cache = new_cache;
    ctx->ocsp_cache_capacity = cfg->cache_capacity;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_config_local_filter(sm2_revocation_ctx_t *ctx,
    uint8_t fp_bits, size_t bucket_size, size_t max_kicks)
{
    if (!ctx || fp_bits == 0 || fp_bits > 32 || bucket_size == 0
        || max_kicks == 0)
    {
        return SM2_IC_ERR_PARAM;
    }

    ctx->filter.fp_bits = fp_bits;
    ctx->filter.bucket_size = bucket_size;
    ctx->filter.max_kicks = max_kicks;
    return rebuild_filter(ctx);
}

sm2_ic_error_t sm2_revocation_apply_crl_delta(
    sm2_revocation_ctx_t *ctx, const sm2_crl_delta_t *delta, uint64_t now_ts)
{
    if (!ctx || !delta)
        return SM2_IC_ERR_PARAM;
    if (delta->base_version != ctx->crl_version)
        return SM2_IC_ERR_VERIFY;
    if (delta->new_version <= delta->base_version)
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < delta->item_count; i++)
    {
        const sm2_crl_delta_item_t *it = &delta->items[i];
        if (it->revoked)
        {
            sm2_ic_error_t ret = local_list_add(ctx, it->serial_number);
            if (ret != SM2_IC_SUCCESS)
                return ret;

            ret = cuckoo_insert(&ctx->filter, it->serial_number);
            if (ret != SM2_IC_SUCCESS)
            {
                ret = rebuild_filter(ctx);
                if (ret != SM2_IC_SUCCESS)
                    return ret;
            }
        }
        else
        {
            local_list_remove(ctx, it->serial_number);
            if (!cuckoo_delete(&ctx->filter, it->serial_number))
            {
                sm2_ic_error_t ret = rebuild_filter(ctx);
                if (ret != SM2_IC_SUCCESS)
                    return ret;
            }
        }
    }

    ctx->crl_version = delta->new_version;
    ctx->filter_expire_at = now_ts + ctx->filter_ttl_sec;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t query_online_ocsp(sm2_revocation_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    if (!ctx->ocsp_cfg.query_fn)
        return SM2_IC_ERR_PARAM;

    sm2_ocsp_cache_entry_t *cached = cache_find(ctx, serial_number);
    if (cached && cached->expires_at >= now_ts)
    {
        *status = cached->status;
        *source = SM2_REV_SOURCE_OCSP_CACHE;
        return SM2_IC_SUCCESS;
    }

    sm2_ocsp_response_t resp;
    memset(&resp, 0, sizeof(resp));
    sm2_ic_error_t ret = SM2_IC_ERR_CRYPTO;

    uint8_t tries
        = ctx->ocsp_cfg.retry_count == 0 ? 1 : ctx->ocsp_cfg.retry_count;
    for (uint8_t i = 0; i < tries; i++)
    {
        ret = ctx->ocsp_cfg.query_fn(ctx->ocsp_cfg.user_ctx, serial_number,
            ctx->ocsp_cfg.timeout_ms, &resp);
        if (ret == SM2_IC_SUCCESS)
            break;
    }

    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint64_t expires_at
        = resp.next_update > now_ts ? resp.next_update : (now_ts + 30);
    cache_put(ctx, serial_number, resp.status, expires_at);
    *status = resp.status;
    *source = SM2_REV_SOURCE_OCSP;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t query_local_filter(sm2_revocation_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    if (ctx->filter_expire_at < now_ts)
    {
        *status = SM2_REV_STATUS_UNKNOWN;
        *source = SM2_REV_SOURCE_LOCAL_FILTER_STALE;
        return SM2_IC_SUCCESS;
    }

    *status = cuckoo_contains(&ctx->filter, serial_number)
        ? SM2_REV_STATUS_REVOKED
        : SM2_REV_STATUS_GOOD;
    *source = SM2_REV_SOURCE_LOCAL_FILTER;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_query(sm2_revocation_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    if (!ctx || !status || !source)
        return SM2_IC_ERR_PARAM;

    *status = SM2_REV_STATUS_UNKNOWN;
    *source = SM2_REV_SOURCE_NONE;

    if (ctx->online_mode && ctx->ocsp_cfg.query_fn)
    {
        sm2_ic_error_t ret
            = query_online_ocsp(ctx, serial_number, now_ts, status, source);
        if (ret == SM2_IC_SUCCESS)
            return SM2_IC_SUCCESS;
    }

    return query_local_filter(ctx, serial_number, now_ts, status, source);
}

size_t sm2_revocation_local_count(const sm2_revocation_ctx_t *ctx)
{
    return ctx ? ctx->revoked_count : 0;
}

uint64_t sm2_revocation_crl_version(const sm2_revocation_ctx_t *ctx)
{
    return ctx ? ctx->crl_version : 0;
}
