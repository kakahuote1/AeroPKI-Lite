/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke.c
 * @brief Revocation state management and OCSP/CRL query path.
 */

#include "revoke_internal.h"
#include "sm2_secure_mem.h"
#include <stdlib.h>
#include <string.h>

#define utils_next_pow2 sm2_rev_internal_next_pow2
#define utils_refresh_filter_param_hash                                        \
    sm2_rev_internal_refresh_filter_param_hash
#define cuckoo_reset sm2_rev_internal_cuckoo_reset
#define cuckoo_insert sm2_rev_internal_cuckoo_insert
#define cuckoo_delete sm2_rev_internal_cuckoo_delete
#define cuckoo_contains sm2_rev_internal_cuckoo_contains
#define rebuild_filter sm2_rev_internal_rebuild_filter
#define sync_log_append sm2_rev_internal_sync_log_append

static sm2_ic_error_t local_list_reserve(
    sm2_revocation_ctx_t *ctx, size_t target_count)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;
    if (target_count <= ctx->revoked_capacity)
        return SM2_IC_SUCCESS;

    size_t new_cap = (ctx->revoked_capacity == 0) ? 64 : ctx->revoked_capacity;
    while (new_cap < target_count)
    {
        if (new_cap > (SIZE_MAX / 2))
            return SM2_IC_ERR_MEMORY;
        new_cap *= 2;
    }
    if (new_cap > (SIZE_MAX / sizeof(uint64_t)))
        return SM2_IC_ERR_MEMORY;

    uint64_t *new_mem = (uint64_t *)malloc(new_cap * sizeof(uint64_t));
    if (!new_mem)
        return SM2_IC_ERR_MEMORY;

    if (ctx->revoked_serials)
    {
        if (ctx->revoked_count > 0)
        {
            memcpy(new_mem, ctx->revoked_serials,
                ctx->revoked_count * sizeof(uint64_t));
        }
        sm2_secure_memzero(
            ctx->revoked_serials, ctx->revoked_capacity * sizeof(uint64_t));
        free(ctx->revoked_serials);
    }

    ctx->revoked_serials = new_mem;
    ctx->revoked_capacity = new_cap;
    return SM2_IC_SUCCESS;
}
static sm2_ic_error_t local_list_add(sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    if (cuckoo_contains(&ctx->filter, serial))
    {
        for (size_t i = 0; i < ctx->revoked_count; i++)
        {
            if (ctx->revoked_serials[i] == serial)
                return SM2_IC_SUCCESS;
        }
    }

    sm2_ic_error_t ret = local_list_reserve(ctx, ctx->revoked_count + 1);
    if (ret != SM2_IC_SUCCESS)
        return ret;

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

sm2_ic_error_t sm2_rev_internal_local_list_add(
    sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    return local_list_add(ctx, serial);
}

void sm2_rev_internal_local_list_remove(
    sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    local_list_remove(ctx, serial);
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
    if (!ctx || !ctx->ocsp_cache || ctx->ocsp_cache_capacity == 0)
        return NULL;

    sm2_ocsp_cache_entry_t *victim = &ctx->ocsp_cache[0];
    for (size_t i = 0; i < ctx->ocsp_cache_capacity; i++)
    {
        sm2_ocsp_cache_entry_t *entry = &ctx->ocsp_cache[i];
        if (!entry->used)
            return entry;
        if (!victim->used || entry->expires_at < victim->expires_at)
            victim = entry;
    }
    return victim;
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

    ctx->sync_epoch = 1;
    ctx->sync_log_window = 2048;
    ctx->sync_log_head = 0;
    ctx->last_sync_ts = 0;
    ctx->last_sync_nonce = 0;
    ctx->sync_max_items_per_packet = 256;
    ctx->sync_min_export_interval_sec = 0;

    return utils_refresh_filter_param_hash(ctx);
}

void sm2_revocation_cleanup(sm2_revocation_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->filter.fingerprints)
    {
        sm2_secure_memzero(ctx->filter.fingerprints,
            ctx->filter.bucket_count * ctx->filter.bucket_size
                * sizeof(uint32_t));
    }
    if (ctx->revoked_serials && ctx->revoked_capacity > 0)
    {
        sm2_secure_memzero(
            ctx->revoked_serials, ctx->revoked_capacity * sizeof(uint64_t));
    }
    if (ctx->ocsp_cache && ctx->ocsp_cache_capacity > 0)
    {
        sm2_secure_memzero(ctx->ocsp_cache,
            ctx->ocsp_cache_capacity * sizeof(sm2_ocsp_cache_entry_t));
    }
    if (ctx->sync_log && ctx->sync_log_capacity > 0)
    {
        sm2_secure_memzero(ctx->sync_log,
            ctx->sync_log_capacity * sizeof(sm2_rev_sync_log_entry_t));
    }

    free(ctx->filter.fingerprints);
    free(ctx->revoked_serials);
    free(ctx->ocsp_cache);
    free(ctx->sync_log);
    sm2_secure_memzero(ctx, sizeof(*ctx));
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
        if (ctx->ocsp_cache && ctx->ocsp_cache_capacity > 0)
        {
            sm2_secure_memzero(ctx->ocsp_cache,
                ctx->ocsp_cache_capacity * sizeof(sm2_ocsp_cache_entry_t));
        }
        free(ctx->ocsp_cache);
        ctx->ocsp_cache = NULL;
        ctx->ocsp_cache_capacity = 0;
        return SM2_IC_SUCCESS;
    }

    sm2_ocsp_cache_entry_t *new_cache = (sm2_ocsp_cache_entry_t *)calloc(
        cfg->cache_capacity, sizeof(sm2_ocsp_cache_entry_t));
    if (!new_cache)
        return SM2_IC_ERR_MEMORY;

    if (ctx->ocsp_cache && ctx->ocsp_cache_capacity > 0)
    {
        sm2_secure_memzero(ctx->ocsp_cache,
            ctx->ocsp_cache_capacity * sizeof(sm2_ocsp_cache_entry_t));
    }
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

        sm2_ic_error_t log_ret = sync_log_append(ctx, delta->base_version,
            delta->new_version, now_ts, it->serial_number, it->revoked);
        if (log_ret != SM2_IC_SUCCESS)
            return log_ret;
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
