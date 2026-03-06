/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sync.c
 * @brief Offline revocation synchronization protocol and ring-log management.
 */

#include "revoke_internal.h"
#include <stdlib.h>
#include <string.h>

#define utils_u64_to_be sm2_rev_internal_u64_to_be
#define utils_calc_set_digest sm2_rev_internal_calc_set_digest
#define utils_refresh_filter_param_hash                                        \
    sm2_rev_internal_refresh_filter_param_hash
#define cuckoo_bucket_slot sm2_rev_internal_cuckoo_bucket_slot
#define cuckoo_index1 sm2_rev_internal_cuckoo_index1
#define cuckoo_index2 sm2_rev_internal_cuckoo_index2
#define cuckoo_fp sm2_rev_internal_cuckoo_fp
#define cuckoo_insert sm2_rev_internal_cuckoo_insert
#define cuckoo_delete sm2_rev_internal_cuckoo_delete
#define cuckoo_reset sm2_rev_internal_cuckoo_reset
#define rebuild_filter sm2_rev_internal_rebuild_filter
#define local_list_add sm2_rev_internal_local_list_add
#define local_list_remove sm2_rev_internal_local_list_remove

#define SM2_REV_SYNC_LOG_FLAG_REVOKED 0x01U

static const sm2_rev_sync_log_entry_t *sync_log_get_const(
    const sm2_revocation_ctx_t *ctx, size_t logical_index)
{
    if (!ctx || !ctx->sync_log || logical_index >= ctx->sync_log_count
        || ctx->sync_log_capacity == 0)
    {
        return NULL;
    }
    size_t physical
        = (ctx->sync_log_head + logical_index) % ctx->sync_log_capacity;
    return &ctx->sync_log[physical];
}

static sm2_rev_sync_log_entry_t *sync_log_get_mutable(
    sm2_revocation_ctx_t *ctx, size_t logical_index)
{
    if (!ctx || !ctx->sync_log || logical_index >= ctx->sync_log_count
        || ctx->sync_log_capacity == 0)
    {
        return NULL;
    }
    size_t physical
        = (ctx->sync_log_head + logical_index) % ctx->sync_log_capacity;
    return &ctx->sync_log[physical];
}

static bool sync_log_decode_new_version(const sm2_revocation_ctx_t *ctx,
    const sm2_rev_sync_log_entry_t *entry, uint64_t *out_new_version)
{
    if (!ctx || !entry || !out_new_version)
        return false;
    if (ctx->sync_log_base_new_version
        > UINT64_MAX - (uint64_t)entry->new_version_offset)
    {
        return false;
    }
    *out_new_version
        = ctx->sync_log_base_new_version + (uint64_t)entry->new_version_offset;
    return true;
}

static bool sync_log_decode_timestamp(const sm2_revocation_ctx_t *ctx,
    const sm2_rev_sync_log_entry_t *entry, uint64_t *out_timestamp)
{
    if (!ctx || !entry || !out_timestamp)
        return false;
    if (ctx->sync_log_base_timestamp
        > UINT64_MAX - (uint64_t)entry->timestamp_offset)
    {
        return false;
    }
    *out_timestamp
        = ctx->sync_log_base_timestamp + (uint64_t)entry->timestamp_offset;
    return true;
}

static bool sync_log_entry_revoked(const sm2_rev_sync_log_entry_t *entry)
{
    return entry && ((entry->flags & SM2_REV_SYNC_LOG_FLAG_REVOKED) != 0);
}

static sm2_ic_error_t sync_log_reserve_ordered(
    sm2_revocation_ctx_t *ctx, size_t new_cap)
{
    if (!ctx || new_cap == 0)
        return SM2_IC_ERR_PARAM;

    sm2_rev_sync_log_entry_t *new_mem = (sm2_rev_sync_log_entry_t *)calloc(
        new_cap, sizeof(sm2_rev_sync_log_entry_t));
    if (!new_mem)
        return SM2_IC_ERR_MEMORY;

    for (size_t i = 0; i < ctx->sync_log_count; i++)
    {
        const sm2_rev_sync_log_entry_t *src = sync_log_get_const(ctx, i);
        if (src)
            new_mem[i] = *src;
    }

    free(ctx->sync_log);
    ctx->sync_log = new_mem;
    ctx->sync_log_capacity = new_cap;
    ctx->sync_log_head = 0;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t sync_log_rebase_to_oldest(sm2_revocation_ctx_t *ctx)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;
    if (ctx->sync_log_count == 0 || !ctx->sync_log)
        return SM2_IC_SUCCESS;

    const sm2_rev_sync_log_entry_t *oldest = sync_log_get_const(ctx, 0);
    if (!oldest)
        return SM2_IC_ERR_VERIFY;

    uint64_t rebase_new = 0;
    uint64_t rebase_ts = 0;
    if (!sync_log_decode_new_version(ctx, oldest, &rebase_new)
        || !sync_log_decode_timestamp(ctx, oldest, &rebase_ts))
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint64_t old_base_new = ctx->sync_log_base_new_version;
    uint64_t old_base_ts = ctx->sync_log_base_timestamp;

    ctx->sync_log_base_new_version = rebase_new;
    ctx->sync_log_base_timestamp = rebase_ts;

    for (size_t i = 0; i < ctx->sync_log_count; i++)
    {
        sm2_rev_sync_log_entry_t *entry = sync_log_get_mutable(ctx, i);
        if (!entry)
            return SM2_IC_ERR_VERIFY;

        if (old_base_new > UINT64_MAX - (uint64_t)entry->new_version_offset
            || old_base_ts > UINT64_MAX - (uint64_t)entry->timestamp_offset)
        {
            return SM2_IC_ERR_VERIFY;
        }

        uint64_t abs_new = old_base_new + (uint64_t)entry->new_version_offset;
        uint64_t abs_ts = old_base_ts + (uint64_t)entry->timestamp_offset;

        if (abs_new < ctx->sync_log_base_new_version
            || abs_ts < ctx->sync_log_base_timestamp)
        {
            return SM2_IC_ERR_VERIFY;
        }

        uint64_t v_off = abs_new - ctx->sync_log_base_new_version;
        uint64_t ts_off = abs_ts - ctx->sync_log_base_timestamp;
        if (v_off > UINT16_MAX || ts_off > UINT32_MAX)
            return SM2_IC_ERR_VERIFY;

        entry->new_version_offset = (uint16_t)v_off;
        entry->timestamp_offset = (uint32_t)ts_off;
    }

    return SM2_IC_SUCCESS;
}

static void sync_log_drop_oldest(sm2_revocation_ctx_t *ctx)
{
    if (!ctx || ctx->sync_log_count == 0 || ctx->sync_log_capacity == 0)
        return;

    const sm2_rev_sync_log_entry_t *oldest = sync_log_get_const(ctx, 0);
    uint64_t dropped_new = ctx->crl_version;
    if (oldest)
    {
        if (!sync_log_decode_new_version(ctx, oldest, &dropped_new))
            dropped_new = ctx->crl_version;
    }

    if (ctx->sync_log_oldest_base_version < dropped_new)
        ctx->sync_log_oldest_base_version = dropped_new;

    ctx->sync_log_head = (ctx->sync_log_head + 1) % ctx->sync_log_capacity;
    ctx->sync_log_count--;

    if (ctx->sync_log_count == 0)
    {
        ctx->sync_log_head = 0;
        ctx->sync_log_base_new_version = 0;
        ctx->sync_log_base_timestamp = 0;
        ctx->sync_log_oldest_base_version = 0;
    }
}

static bool sync_log_can_encode(
    const sm2_revocation_ctx_t *ctx, uint64_t new_version, uint64_t now_ts)
{
    if (!ctx)
        return false;
    if (new_version < ctx->sync_log_base_new_version
        || now_ts < ctx->sync_log_base_timestamp)
    {
        return false;
    }

    uint64_t v_off = new_version - ctx->sync_log_base_new_version;
    uint64_t ts_off = now_ts - ctx->sync_log_base_timestamp;
    return v_off <= UINT16_MAX && ts_off <= UINT32_MAX;
}

static sm2_ic_error_t sync_log_prepare_for_encode(sm2_revocation_ctx_t *ctx,
    uint64_t base_version, uint64_t new_version, uint64_t now_ts)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    if (ctx->sync_log_count == 0)
    {
        ctx->sync_log_base_new_version = new_version;
        ctx->sync_log_base_timestamp = now_ts;
        ctx->sync_log_oldest_base_version = base_version;
        return SM2_IC_SUCCESS;
    }

    if (sync_log_can_encode(ctx, new_version, now_ts))
        return SM2_IC_SUCCESS;

    while (ctx->sync_log_count > 0)
    {
        sm2_ic_error_t ret = sync_log_rebase_to_oldest(ctx);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        if (sync_log_can_encode(ctx, new_version, now_ts))
            return SM2_IC_SUCCESS;

        sync_log_drop_oldest(ctx);
    }

    ctx->sync_log_base_new_version = new_version;
    ctx->sync_log_base_timestamp = now_ts;
    ctx->sync_log_oldest_base_version = base_version;
    return SM2_IC_SUCCESS;
}

static void sync_log_write_entry(sm2_revocation_ctx_t *ctx,
    sm2_rev_sync_log_entry_t *dst, uint64_t new_version, uint64_t now_ts,
    uint64_t serial_number, bool revoked)
{
    uint64_t v_off = new_version - ctx->sync_log_base_new_version;
    uint64_t ts_off = now_ts - ctx->sync_log_base_timestamp;

    dst->serial_number = serial_number;
    dst->new_version_offset = (uint16_t)v_off;
    dst->timestamp_offset = (uint32_t)ts_off;
    dst->flags = revoked ? SM2_REV_SYNC_LOG_FLAG_REVOKED : 0;
    dst->reserved = 0;
}

static sm2_ic_error_t sync_log_append(sm2_revocation_ctx_t *ctx,
    uint64_t base_version, uint64_t new_version, uint64_t now_ts,
    uint64_t serial_number, bool revoked)
{
    if (!ctx || ctx->sync_log_window == 0)
        return SM2_IC_SUCCESS;

    size_t target_cap = ctx->sync_log_window;
    if (ctx->sync_log_capacity == 0)
    {
        size_t init_cap = target_cap < 128 ? target_cap : 128;
        if (init_cap == 0)
            init_cap = 1;
        sm2_ic_error_t ret = sync_log_reserve_ordered(ctx, init_cap);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    if (ctx->sync_log_count == ctx->sync_log_capacity
        && ctx->sync_log_capacity < target_cap)
    {
        size_t grow = ctx->sync_log_capacity * 2;
        if (grow > target_cap)
            grow = target_cap;
        if (grow == ctx->sync_log_capacity)
            grow = ctx->sync_log_capacity + 1;
        sm2_ic_error_t ret = sync_log_reserve_ordered(ctx, grow);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    if (ctx->sync_log_count >= ctx->sync_log_window)
        sync_log_drop_oldest(ctx);

    sm2_ic_error_t ret
        = sync_log_prepare_for_encode(ctx, base_version, new_version, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (ctx->sync_log_count >= ctx->sync_log_capacity)
        return SM2_IC_ERR_MEMORY;

    size_t write_idx
        = (ctx->sync_log_head + ctx->sync_log_count) % ctx->sync_log_capacity;
    sm2_rev_sync_log_entry_t *dst = &ctx->sync_log[write_idx];
    sync_log_write_entry(ctx, dst, new_version, now_ts, serial_number, revoked);
    ctx->sync_log_count++;
    return SM2_IC_SUCCESS;
}

static bool sync_log_has_base(
    const sm2_revocation_ctx_t *ctx, uint64_t base_version)
{
    if (!ctx)
        return false;
    if (base_version == ctx->crl_version)
        return true;
    if (ctx->sync_log_count == 0)
        return false;

    uint64_t oldest_base = ctx->sync_log_oldest_base_version;
    if (oldest_base > ctx->crl_version)
        oldest_base = ctx->crl_version;

    return base_version >= oldest_base && base_version <= ctx->crl_version;
}
static sm2_ic_error_t sync_reset_local_state(
    sm2_revocation_ctx_t *ctx, uint64_t now_ts)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    ctx->revoked_count = 0;
    ctx->crl_version = 0;
    ctx->sync_log_count = 0;
    ctx->sync_log_head = 0;
    ctx->sync_log_base_new_version = 0;
    ctx->sync_log_base_timestamp = 0;
    ctx->sync_log_oldest_base_version = 0;

    size_t bucket_count = ctx->filter.bucket_count;
    if (bucket_count < 64)
        bucket_count = 64;
    sm2_ic_error_t ret = cuckoo_reset(&ctx->filter, bucket_count,
        ctx->filter.bucket_size == 0 ? 4 : ctx->filter.bucket_size,
        ctx->filter.max_kicks == 0 ? 500 : ctx->filter.max_kicks,
        ctx->filter.fp_bits == 0 ? 32 : ctx->filter.fp_bits);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (ctx->ocsp_cache && ctx->ocsp_cache_capacity > 0)
    {
        memset(ctx->ocsp_cache, 0,
            ctx->ocsp_cache_capacity * sizeof(sm2_ocsp_cache_entry_t));
    }

    ctx->filter_expire_at = now_ts + ctx->filter_ttl_sec;
    return utils_refresh_filter_param_hash(ctx);
}

static bool sync_plan_add_candidate_bucket(
    sm2_rev_sync_plan_t *plan, size_t bucket_idx)
{
    if (!plan)
        return false;
    for (size_t i = 0; i < plan->candidate_bucket_count; i++)
    {
        if (plan->candidate_buckets[i] == bucket_idx)
            return true;
    }
    if (plan->candidate_bucket_count >= SM2_REV_SYNC_BUCKET_CANDIDATE_MAX)
        return false;
    plan->candidate_buckets[plan->candidate_bucket_count++] = bucket_idx;
    return true;
}

static void sync_collect_bucket_summary(const sm2_cuckoo_filter_t *f,
    size_t bucket_index, sm2_rev_bucket_summary_t *out)
{
    if (!f || !out || bucket_index >= f->bucket_count)
        return;

    out->bucket_index = bucket_index;
    out->nonzero_count = 0;
    out->xor_fp = 0;
    out->sum_fp = 0;

    for (size_t s = 0; s < f->bucket_size; s++)
    {
        uint32_t fp = *cuckoo_bucket_slot(f, bucket_index, s);
        if (fp == 0)
            continue;
        out->nonzero_count++;
        out->xor_fp ^= fp;
        out->sum_fp += fp;
    }
}

static size_t sync_calc_summary_count(const sm2_revocation_ctx_t *ctx)
{
    if (!ctx || ctx->filter.bucket_count == 0)
        return 0;

    size_t target = 0;
    if (ctx->filter.bucket_count <= 32)
    {
        target = ctx->filter.bucket_count;
    }
    else
    {
        size_t budget = ctx->sync_max_items_per_packet;
        if (budget <= 4)
            target = 32;
        else if (budget <= 8)
            target = 48;
        else if (budget <= 16)
            target = 64;
        else if (budget <= 32)
            target = 96;
        else
            target = SM2_REV_SYNC_BUCKET_SUMMARY_MAX;
    }

    if (target > ctx->filter.bucket_count)
        target = ctx->filter.bucket_count;
    if (target > SM2_REV_SYNC_BUCKET_SUMMARY_MAX)
        target = SM2_REV_SYNC_BUCKET_SUMMARY_MAX;
    if (target == 0)
        target = 1;
    return target;
}

static void sync_fill_hello_bucket_summaries(
    const sm2_revocation_ctx_t *ctx, sm2_rev_sync_hello_t *hello)
{
    if (!ctx || !hello || ctx->filter.bucket_count == 0)
        return;

    size_t count = sync_calc_summary_count(ctx);
    hello->bucket_summary_count = count;
    for (size_t i = 0; i < count; i++)
    {
        size_t idx = (i * ctx->filter.bucket_count) / count;
        sync_collect_bucket_summary(
            &ctx->filter, idx, &hello->bucket_summaries[i]);
    }
}
static void sync_mark_candidates_from_hello(const sm2_revocation_ctx_t *ctx,
    const sm2_rev_sync_hello_t *peer_hello, sm2_rev_sync_plan_t *plan)
{
    if (!ctx || !peer_hello || !plan)
        return;

    for (size_t i = 0; i < peer_hello->bucket_summary_count; i++)
    {
        const sm2_rev_bucket_summary_t *peer = &peer_hello->bucket_summaries[i];
        if (peer->bucket_index >= ctx->filter.bucket_count)
            continue;

        sm2_rev_bucket_summary_t local;
        memset(&local, 0, sizeof(local));
        sync_collect_bucket_summary(&ctx->filter, peer->bucket_index, &local);

        if (local.nonzero_count != peer->nonzero_count
            || local.xor_fp != peer->xor_fp || local.sum_fp != peer->sum_fp)
        {
            sync_plan_add_candidate_bucket(plan, peer->bucket_index);
        }
    }
}

static void sync_mark_candidates_from_serial(
    const sm2_revocation_ctx_t *ctx, uint64_t serial, sm2_rev_sync_plan_t *plan)
{
    if (!ctx || !plan || ctx->filter.bucket_count == 0)
        return;

    size_t i1 = cuckoo_index1(&ctx->filter, serial);
    uint32_t fp = cuckoo_fp(&ctx->filter, serial);
    size_t i2 = cuckoo_index2(&ctx->filter, i1, fp);
    sync_plan_add_candidate_bucket(plan, i1);
    sync_plan_add_candidate_bucket(plan, i2);
}

typedef struct
{
    uint64_t serial_number;
    bool revoked;
    uint64_t version;
    uint64_t timestamp;
} sync_delta_merge_item_t;

static sm2_ic_error_t sync_collect_items_from_log(
    const sm2_revocation_ctx_t *ctx, uint64_t from_version, bool full_snapshot,
    size_t max_items, sm2_crl_delta_item_t **items, size_t *item_count,
    uint64_t *to_version, bool *has_more, uint64_t *next_from_version)
{
    if (!ctx || !items || !item_count || !to_version || !has_more
        || !next_from_version)
    {
        return SM2_IC_ERR_PARAM;
    }

    *items = NULL;
    *item_count = 0;
    *to_version = from_version;
    *has_more = false;
    *next_from_version = from_version;

    if (max_items == 0)
    {
        max_items = ctx->sync_max_items_per_packet == 0
            ? 256
            : ctx->sync_max_items_per_packet;
    }

    if (full_snapshot)
    {
        if (ctx->revoked_count == 0)
        {
            *to_version = ctx->crl_version;
            *next_from_version = ctx->crl_version;
            return SM2_IC_SUCCESS;
        }

        sm2_crl_delta_item_t *buf = (sm2_crl_delta_item_t *)calloc(
            ctx->revoked_count, sizeof(sm2_crl_delta_item_t));
        if (!buf)
            return SM2_IC_ERR_MEMORY;

        for (size_t i = 0; i < ctx->revoked_count; i++)
        {
            buf[i].serial_number = ctx->revoked_serials[i];
            buf[i].revoked = true;
        }
        *items = buf;
        *item_count = ctx->revoked_count;
        *to_version = ctx->crl_version;
        *next_from_version = ctx->crl_version;
        return SM2_IC_SUCCESS;
    }

    if (ctx->sync_log_count == 0)
        return SM2_IC_SUCCESS;

    size_t start = ctx->sync_log_count;
    for (size_t i = 0; i < ctx->sync_log_count; i++)
    {
        const sm2_rev_sync_log_entry_t *entry = sync_log_get_const(ctx, i);
        uint64_t entry_new = 0;
        if (!entry || !sync_log_decode_new_version(ctx, entry, &entry_new))
            return SM2_IC_ERR_VERIFY;

        if (entry_new > from_version)
        {
            start = i;
            break;
        }
    }
    if (start >= ctx->sync_log_count)
        return SM2_IC_SUCCESS;

    size_t end = start;
    size_t raw_count = 0;
    uint64_t window_to_version = from_version;

    while (end < ctx->sync_log_count)
    {
        const sm2_rev_sync_log_entry_t *entry = sync_log_get_const(ctx, end);
        uint64_t entry_new = 0;
        if (!entry || !sync_log_decode_new_version(ctx, entry, &entry_new))
            return SM2_IC_ERR_VERIFY;

        if (entry_new <= from_version)
        {
            end++;
            continue;
        }

        if (raw_count < max_items)
        {
            raw_count++;
            window_to_version = entry_new;
            end++;
            continue;
        }

        if (entry_new == window_to_version)
        {
            raw_count++;
            end++;
            continue;
        }

        break;
    }

    if (raw_count == 0)
        return SM2_IC_SUCCESS;

    for (size_t i = end; i < ctx->sync_log_count; i++)
    {
        const sm2_rev_sync_log_entry_t *entry = sync_log_get_const(ctx, i);
        uint64_t entry_new = 0;
        if (!entry || !sync_log_decode_new_version(ctx, entry, &entry_new))
            return SM2_IC_ERR_VERIFY;

        if (entry_new > window_to_version)
        {
            *has_more = true;
            break;
        }
    }

    *to_version = window_to_version;
    *next_from_version = window_to_version;

    sync_delta_merge_item_t *merged = (sync_delta_merge_item_t *)calloc(
        raw_count, sizeof(sync_delta_merge_item_t));
    if (!merged)
        return SM2_IC_ERR_MEMORY;

    size_t merged_n = 0;
    for (size_t i = start; i < end; i++)
    {
        const sm2_rev_sync_log_entry_t *entry = sync_log_get_const(ctx, i);
        uint64_t entry_new = 0;
        uint64_t entry_ts = 0;
        if (!entry || !sync_log_decode_new_version(ctx, entry, &entry_new)
            || !sync_log_decode_timestamp(ctx, entry, &entry_ts))
        {
            free(merged);
            return SM2_IC_ERR_VERIFY;
        }

        if (entry_new <= from_version)
            continue;

        bool entry_revoked = sync_log_entry_revoked(entry);
        size_t hit = merged_n;
        for (size_t j = 0; j < merged_n; j++)
        {
            if (merged[j].serial_number == entry->serial_number)
            {
                hit = j;
                break;
            }
        }

        if (hit == merged_n)
        {
            merged[merged_n].serial_number = entry->serial_number;
            merged[merged_n].revoked = entry_revoked;
            merged[merged_n].version = entry_new;
            merged[merged_n].timestamp = entry_ts;
            merged_n++;
            continue;
        }

        sync_delta_merge_item_t *m = &merged[hit];
        if (entry_new > m->version)
        {
            m->version = entry_new;
            m->timestamp = entry_ts;
            m->revoked = entry_revoked;
        }
        else if (entry_new == m->version && entry_ts > m->timestamp)
        {
            m->timestamp = entry_ts;
            m->revoked = entry_revoked;
        }

        if (entry_revoked || m->revoked)
            m->revoked = true;
    }

    if (merged_n == 0)
    {
        free(merged);
        return SM2_IC_SUCCESS;
    }

    sm2_crl_delta_item_t *buf = (sm2_crl_delta_item_t *)calloc(
        merged_n, sizeof(sm2_crl_delta_item_t));
    if (!buf)
    {
        free(merged);
        return SM2_IC_ERR_MEMORY;
    }

    for (size_t i = 0; i < merged_n; i++)
    {
        buf[i].serial_number = merged[i].serial_number;
        buf[i].revoked = merged[i].revoked;
    }

    free(merged);
    *items = buf;
    *item_count = merged_n;
    return SM2_IC_SUCCESS;
}
static sm2_ic_error_t sync_calc_payload_digest(uint64_t from_version,
    uint64_t to_version, bool full_snapshot, const sm2_crl_delta_item_t *items,
    size_t item_count, uint8_t out[SM2_REV_SYNC_DIGEST_LEN])
{
    if (!out)
        return SM2_IC_ERR_PARAM;

    size_t buf_len = 8 + 8 + 1 + 8 + item_count * 9;
    uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
    if (!buf)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    utils_u64_to_be(from_version, buf + off);
    off += 8;
    utils_u64_to_be(to_version, buf + off);
    off += 8;
    buf[off++] = full_snapshot ? 1 : 0;
    utils_u64_to_be((uint64_t)item_count, buf + off);
    off += 8;

    for (size_t i = 0; i < item_count; i++)
    {
        utils_u64_to_be(items[i].serial_number, buf + off);
        off += 8;
        buf[off++] = items[i].revoked ? 1 : 0;
    }

    sm2_ic_error_t ret = sm2_ic_sm3_hash(buf, buf_len, out);
    free(buf);
    return ret;
}

static sm2_ic_error_t sync_serialize_packet_for_auth(
    const sm2_rev_sync_packet_t *packet, uint8_t **out, size_t *out_len)
{
    if (!packet || !out || !out_len)
        return SM2_IC_ERR_PARAM;

    size_t need = 1 + packet->node_id_len + 8 + 8 + 8 + 8 + 8 + 1
        + SM2_REV_SYNC_DIGEST_LEN + SM2_REV_SYNC_DIGEST_LEN + 8 + 1 + 8
        + packet->item_count * 9;

    uint8_t *buf = (uint8_t *)calloc(need, 1);
    if (!buf)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    buf[off++] = (uint8_t)packet->node_id_len;
    if (packet->node_id_len > 0)
    {
        memcpy(buf + off, packet->node_id, packet->node_id_len);
        off += packet->node_id_len;
    }

    utils_u64_to_be(packet->sync_epoch, buf + off);
    off += 8;
    utils_u64_to_be(packet->from_version, buf + off);
    off += 8;
    utils_u64_to_be(packet->to_version, buf + off);
    off += 8;
    utils_u64_to_be(packet->generated_ts, buf + off);
    off += 8;
    utils_u64_to_be(packet->nonce, buf + off);
    off += 8;
    buf[off++] = packet->full_snapshot ? 1 : 0;

    memcpy(buf + off, packet->filter_param_hash, SM2_REV_SYNC_DIGEST_LEN);
    off += SM2_REV_SYNC_DIGEST_LEN;
    memcpy(buf + off, packet->payload_digest, SM2_REV_SYNC_DIGEST_LEN);
    off += SM2_REV_SYNC_DIGEST_LEN;

    utils_u64_to_be((uint64_t)packet->item_count, buf + off);
    off += 8;
    buf[off++] = packet->has_more ? 1 : 0;
    utils_u64_to_be(packet->next_from_version, buf + off);
    off += 8;

    for (size_t i = 0; i < packet->item_count; i++)
    {
        utils_u64_to_be(packet->items[i].serial_number, buf + off);
        off += 8;
        buf[off++] = packet->items[i].revoked ? 1 : 0;
    }

    *out = buf;
    *out_len = need;
    return SM2_IC_SUCCESS;
}

const sm2_rev_sync_log_entry_t *sm2_rev_internal_sync_log_get(
    const sm2_revocation_ctx_t *ctx, size_t logical_index)
{
    return sync_log_get_const(ctx, logical_index);
}

sm2_ic_error_t sm2_rev_internal_sync_log_append(sm2_revocation_ctx_t *ctx,
    uint64_t base_version, uint64_t new_version, uint64_t now_ts,
    uint64_t serial_number, bool revoked)
{
    return sync_log_append(
        ctx, base_version, new_version, now_ts, serial_number, revoked);
}

bool sm2_rev_internal_sync_log_has_base(
    const sm2_revocation_ctx_t *ctx, uint64_t base_version)
{
    return sync_log_has_base(ctx, base_version);
}

sm2_ic_error_t sm2_rev_internal_sync_reset_local_state(
    sm2_revocation_ctx_t *ctx, uint64_t now_ts)
{
    return sync_reset_local_state(ctx, now_ts);
}

sm2_ic_error_t sm2_revocation_set_sync_identity(sm2_revocation_ctx_t *ctx,
    const uint8_t *node_id, size_t node_id_len, uint64_t sync_epoch,
    size_t sync_log_window)
{
    if (!ctx || !node_id || node_id_len == 0
        || node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    memcpy(ctx->node_id, node_id, node_id_len);
    ctx->node_id_len = node_id_len;
    ctx->sync_epoch = sync_epoch == 0 ? 1 : sync_epoch;
    ctx->sync_log_window = sync_log_window == 0 ? 2048 : sync_log_window;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_config_sync_limits(sm2_revocation_ctx_t *ctx,
    size_t max_items_per_packet, uint64_t min_export_interval_sec)
{
    if (!ctx || max_items_per_packet == 0)
        return SM2_IC_ERR_PARAM;

    ctx->sync_max_items_per_packet = max_items_per_packet;
    ctx->sync_min_export_interval_sec = min_export_interval_sec;
    return SM2_IC_SUCCESS;
}
sm2_ic_error_t sm2_revocation_sync_hello(const sm2_revocation_ctx_t *ctx,
    uint64_t now_ts, sm2_rev_sync_hello_t *hello)
{
    if (!ctx || !hello)
        return SM2_IC_ERR_PARAM;

    memset(hello, 0, sizeof(*hello));
    memcpy(hello->node_id, ctx->node_id, ctx->node_id_len);
    hello->node_id_len = ctx->node_id_len;
    hello->sync_epoch = ctx->sync_epoch;
    hello->last_sync_ts = ctx->last_sync_ts == 0 ? now_ts : ctx->last_sync_ts;
    hello->crl_version = ctx->crl_version;
    hello->filter_ttl_sec = ctx->filter_ttl_sec;
    hello->filter_expire_at = ctx->filter_expire_at;
    hello->fp_bits = ctx->filter.fp_bits;
    hello->bucket_size = ctx->filter.bucket_size;
    hello->bucket_count = ctx->filter.bucket_count;
    memcpy(hello->filter_param_hash, ctx->filter_param_hash,
        SM2_REV_SYNC_DIGEST_LEN);
    sync_fill_hello_bucket_summaries(ctx, hello);

    return utils_calc_set_digest(ctx, hello->set_digest);
}

sm2_ic_error_t sm2_revocation_sync_plan(const sm2_revocation_ctx_t *ctx,
    const sm2_rev_sync_hello_t *peer_hello, sm2_rev_sync_plan_t *plan)
{
    if (!ctx || !peer_hello || !plan)
        return SM2_IC_ERR_PARAM;

    memset(plan, 0, sizeof(*plan));
    plan->action = SM2_REV_SYNC_ACTION_NONE;

    bool same_params = memcmp(peer_hello->filter_param_hash,
                           ctx->filter_param_hash, SM2_REV_SYNC_DIGEST_LEN)
        == 0;
    plan->compatible_params = same_params;

    if (same_params)
        sync_mark_candidates_from_hello(ctx, peer_hello, plan);

    if (!same_params || peer_hello->sync_epoch != ctx->sync_epoch)
    {
        plan->action = SM2_REV_SYNC_ACTION_FULL;
        plan->from_version = 0;
        plan->to_version = ctx->crl_version;
        plan->full_snapshot = true;
        return SM2_IC_SUCCESS;
    }

    if (ctx->crl_version == peer_hello->crl_version)
    {
        uint8_t local_digest[SM2_REV_SYNC_DIGEST_LEN];
        sm2_ic_error_t ret = utils_calc_set_digest(ctx, local_digest);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        if (memcmp(local_digest, peer_hello->set_digest, sizeof(local_digest))
            == 0)
        {
            return SM2_IC_SUCCESS;
        }

        if (ctx->crl_version > 0
            && sync_log_has_base(ctx, ctx->crl_version - 1))
        {
            plan->action = SM2_REV_SYNC_ACTION_DELTA;
            plan->from_version = ctx->crl_version - 1;
            plan->to_version = ctx->crl_version;
            plan->full_snapshot = false;

            for (size_t i = 0; i < ctx->sync_log_count; i++)
            {
                const sm2_rev_sync_log_entry_t *entry
                    = sync_log_get_const(ctx, i);
                uint64_t entry_new = 0;
                if (!entry
                    || !sync_log_decode_new_version(ctx, entry, &entry_new))
                    return SM2_IC_ERR_VERIFY;

                if (entry_new > plan->from_version)
                {
                    sync_mark_candidates_from_serial(
                        ctx, entry->serial_number, plan);
                }
            }
        }
        else
        {
            plan->action = SM2_REV_SYNC_ACTION_FULL;
            plan->from_version = 0;
            plan->to_version = ctx->crl_version;
            plan->full_snapshot = true;
        }
        return SM2_IC_SUCCESS;
    }

    if (ctx->crl_version < peer_hello->crl_version)
    {
        plan->action = SM2_REV_SYNC_ACTION_NONE;
        return SM2_IC_SUCCESS;
    }

    if (sync_log_has_base(ctx, peer_hello->crl_version))
    {
        plan->action = SM2_REV_SYNC_ACTION_DELTA;
        plan->from_version = peer_hello->crl_version;
        plan->to_version = ctx->crl_version;
        plan->full_snapshot = false;

        for (size_t i = 0; i < ctx->sync_log_count; i++)
        {
            const sm2_rev_sync_log_entry_t *entry = sync_log_get_const(ctx, i);
            uint64_t entry_new = 0;
            if (!entry || !sync_log_decode_new_version(ctx, entry, &entry_new))
                return SM2_IC_ERR_VERIFY;

            if (entry_new > plan->from_version)
            {
                sync_mark_candidates_from_serial(
                    ctx, entry->serial_number, plan);
            }
        }
    }
    else
    {
        plan->action = SM2_REV_SYNC_ACTION_FULL;
        plan->from_version = 0;
        plan->to_version = ctx->crl_version;
        plan->full_snapshot = true;
    }

    return SM2_IC_SUCCESS;
}
sm2_ic_error_t sm2_revocation_sync_export_delta(sm2_revocation_ctx_t *ctx,
    const sm2_rev_sync_plan_t *plan, uint64_t now_ts, uint64_t nonce,
    sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_sync_packet_t *packet)
{
    if (!ctx || !plan || !packet || !sign_fn)
        return SM2_IC_ERR_PARAM;
    if (plan->action != SM2_REV_SYNC_ACTION_DELTA
        && plan->action != SM2_REV_SYNC_ACTION_FULL)
    {
        return SM2_IC_ERR_PARAM;
    }

    if (ctx->sync_min_export_interval_sec > 0 && ctx->last_sync_ts > 0
        && now_ts < ctx->last_sync_ts + ctx->sync_min_export_interval_sec)
    {
        return SM2_IC_ERR_VERIFY;
    }

    sm2_revocation_sync_packet_cleanup(packet);

    packet->node_id_len = ctx->node_id_len;
    memcpy(packet->node_id, ctx->node_id, ctx->node_id_len);
    packet->sync_epoch = ctx->sync_epoch;
    packet->from_version = plan->from_version;
    packet->to_version = plan->to_version;
    packet->generated_ts = now_ts;
    packet->nonce = nonce;
    packet->full_snapshot = plan->full_snapshot;
    memcpy(packet->filter_param_hash, ctx->filter_param_hash,
        SM2_REV_SYNC_DIGEST_LEN);

    bool has_more = false;
    uint64_t next_from_version = plan->from_version;
    uint64_t real_to_version = plan->to_version;
    sm2_ic_error_t ret = sync_collect_items_from_log(ctx, plan->from_version,
        plan->full_snapshot, ctx->sync_max_items_per_packet, &packet->items,
        &packet->item_count, &real_to_version, &has_more, &next_from_version);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_revocation_sync_packet_cleanup(packet);
        return ret;
    }
    packet->item_capacity = packet->item_count;
    packet->to_version = real_to_version;
    packet->has_more = has_more;
    packet->next_from_version = next_from_version;

    ret = sync_calc_payload_digest(packet->from_version, packet->to_version,
        packet->full_snapshot, packet->items, packet->item_count,
        packet->payload_digest);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_revocation_sync_packet_cleanup(packet);
        return ret;
    }

    uint8_t *auth_buf = NULL;
    size_t auth_len = 0;
    ret = sync_serialize_packet_for_auth(packet, &auth_buf, &auth_len);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_revocation_sync_packet_cleanup(packet);
        return ret;
    }

    size_t sig_len = sizeof(packet->signature);
    ret = sign_fn(
        sign_user_ctx, auth_buf, auth_len, packet->signature, &sig_len);
    free(auth_buf);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_revocation_sync_packet_cleanup(packet);
        return ret;
    }

    if (sig_len == 0 || sig_len > sizeof(packet->signature))
    {
        sm2_revocation_sync_packet_cleanup(packet);
        return SM2_IC_ERR_VERIFY;
    }
    packet->signature_len = sig_len;

    ctx->last_sync_ts = now_ts;
    ctx->last_sync_nonce = nonce;
    return SM2_IC_SUCCESS;
}
static sm2_ic_error_t sync_apply_items_reconcile(sm2_revocation_ctx_t *ctx,
    const sm2_crl_delta_item_t *items, size_t item_count, uint64_t version,
    uint64_t now_ts)
{
    if (!ctx || (!items && item_count != 0))
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < item_count; i++)
    {
        const sm2_crl_delta_item_t *it = &items[i];
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

        uint64_t base_version = version == 0 ? 0 : (version - 1);
        sm2_ic_error_t log_ret = sync_log_append(
            ctx, base_version, version, now_ts, it->serial_number, it->revoked);
        if (log_ret != SM2_IC_SUCCESS)
            return log_ret;
    }

    if (version > ctx->crl_version)
        ctx->crl_version = version;
    ctx->filter_expire_at = now_ts + ctx->filter_ttl_sec;
    return SM2_IC_SUCCESS;
}
sm2_ic_error_t sm2_revocation_sync_apply(sm2_revocation_ctx_t *ctx,
    const sm2_rev_sync_packet_t *packet, uint64_t now_ts,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    if (!ctx || !packet || !verify_fn)
        return SM2_IC_ERR_PARAM;
    if (packet->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN)
        return SM2_IC_ERR_PARAM;

    if (packet->generated_ts < ctx->last_sync_ts)
        return SM2_IC_ERR_VERIFY;
    if (packet->generated_ts == ctx->last_sync_ts
        && packet->nonce == ctx->last_sync_nonce)
    {
        return SM2_IC_ERR_VERIFY;
    }

    if (packet->has_more && packet->next_from_version < packet->from_version)
        return SM2_IC_ERR_VERIFY;

    if (!packet->full_snapshot
        && memcmp(packet->filter_param_hash, ctx->filter_param_hash,
               SM2_REV_SYNC_DIGEST_LEN)
            != 0)
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint8_t expected_payload[SM2_REV_SYNC_DIGEST_LEN];
    sm2_ic_error_t ret = sync_calc_payload_digest(packet->from_version,
        packet->to_version, packet->full_snapshot, packet->items,
        packet->item_count, expected_payload);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (memcmp(
            expected_payload, packet->payload_digest, SM2_REV_SYNC_DIGEST_LEN)
        != 0)
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint8_t *auth_buf = NULL;
    size_t auth_len = 0;
    ret = sync_serialize_packet_for_auth(packet, &auth_buf, &auth_len);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = verify_fn(verify_user_ctx, auth_buf, auth_len, packet->signature,
        packet->signature_len);
    free(auth_buf);
    if (ret != SM2_IC_SUCCESS)
        return SM2_IC_ERR_VERIFY;

    if (packet->full_snapshot)
    {
        bool compatible = memcmp(packet->filter_param_hash,
                              ctx->filter_param_hash, SM2_REV_SYNC_DIGEST_LEN)
            == 0;
        if (compatible && packet->to_version == ctx->crl_version)
        {
            ret = sync_apply_items_reconcile(ctx, packet->items,
                packet->item_count, packet->to_version, now_ts);
            if (ret != SM2_IC_SUCCESS)
                return ret;
        }
        else
        {
            ret = sync_reset_local_state(ctx, now_ts);
            if (ret != SM2_IC_SUCCESS)
                return ret;

            sm2_crl_delta_t delta;
            delta.base_version = 0;
            delta.new_version = packet->to_version;
            delta.items = packet->items;
            delta.item_count = packet->item_count;

            ret = sm2_revocation_apply_crl_delta(ctx, &delta, now_ts);
            if (ret != SM2_IC_SUCCESS)
                return ret;
        }
    }
    else
    {
        if (packet->from_version == ctx->crl_version)
        {
            sm2_crl_delta_t delta;
            delta.base_version = packet->from_version;
            delta.new_version = packet->to_version;
            delta.items = packet->items;
            delta.item_count = packet->item_count;

            ret = sm2_revocation_apply_crl_delta(ctx, &delta, now_ts);
            if (ret != SM2_IC_SUCCESS)
                return ret;
        }
        else if (packet->to_version == ctx->crl_version
            && packet->from_version < ctx->crl_version)
        {
            ret = sync_apply_items_reconcile(ctx, packet->items,
                packet->item_count, packet->to_version, now_ts);
            if (ret != SM2_IC_SUCCESS)
                return ret;
        }
        else
        {
            return SM2_IC_ERR_VERIFY;
        }
    }

    ctx->last_sync_ts = packet->generated_ts;
    ctx->last_sync_nonce = packet->nonce;
    return SM2_IC_SUCCESS;
}
void sm2_revocation_sync_packet_cleanup(sm2_rev_sync_packet_t *packet)
{
    if (!packet)
        return;
    free(packet->items);
    memset(packet, 0, sizeof(*packet));
}
