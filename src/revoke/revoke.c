/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke.c
 * @brief Revocation state management for Merkle-only query path.
 */

#include "sm2_revocation.h"
#include "sm2_secure_mem.h"

#include <stdlib.h>
#include <string.h>

static sm2_rev_congestion_signal_t calc_congestion_signal(
    const sm2_revocation_ctx_t *ctx)
{
    if (!ctx)
        return SM2_REV_CONGESTION_NORMAL;

    size_t busy = ctx->congestion_busy_threshold;
    size_t overload = ctx->congestion_overload_threshold;
    if (busy == 0)
        busy = 64;
    if (overload <= busy)
        overload = busy + 1;

    if (ctx->query_inflight >= overload)
        return SM2_REV_CONGESTION_OVERLOAD;
    if (ctx->query_inflight >= busy)
        return SM2_REV_CONGESTION_BUSY;
    return SM2_REV_CONGESTION_NORMAL;
}

static uint32_t route_effective_weight(
    const sm2_rev_route_node_t *node, bool include_overload)
{
    if (!node || !node->enabled || node->node_id_len == 0
        || node->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN
        || node->base_weight == 0)
    {
        return 0;
    }

    if (!include_overload
        && node->congestion_signal == SM2_REV_CONGESTION_OVERLOAD)
    {
        return 0;
    }

    uint32_t weight = node->base_weight;
    if (node->congestion_signal == SM2_REV_CONGESTION_BUSY)
    {
        weight = (weight + 1U) / 2U;
    }
    else if (node->congestion_signal == SM2_REV_CONGESTION_OVERLOAD)
    {
        weight = (weight + 7U) / 8U;
    }

    return weight == 0 ? 1U : weight;
}

static sm2_ic_error_t local_list_reserve(
    sm2_revocation_ctx_t *ctx, size_t target_count)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;
    if (target_count <= ctx->revoked_capacity)
        return SM2_IC_SUCCESS;

    size_t new_cap = ctx->revoked_capacity == 0 ? 64 : ctx->revoked_capacity;
    while (new_cap < target_count)
    {
        if (new_cap > SIZE_MAX / 2)
            return SM2_IC_ERR_MEMORY;
        new_cap *= 2;
    }

    uint64_t *new_list
        = (uint64_t *)realloc(ctx->revoked_serials, new_cap * sizeof(uint64_t));
    if (!new_list)
        return SM2_IC_ERR_MEMORY;

    ctx->revoked_serials = new_list;
    ctx->revoked_capacity = new_cap;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t local_list_add(sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        if (ctx->revoked_serials[i] == serial)
            return SM2_IC_SUCCESS;
    }

    sm2_ic_error_t ret = local_list_reserve(ctx, ctx->revoked_count + 1);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ctx->revoked_serials[ctx->revoked_count++] = serial;
    return SM2_IC_SUCCESS;
}

static void local_list_remove(sm2_revocation_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return;

    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        if (ctx->revoked_serials[i] == serial)
        {
            if (i + 1 < ctx->revoked_count)
            {
                memmove(&ctx->revoked_serials[i], &ctx->revoked_serials[i + 1],
                    (ctx->revoked_count - i - 1) * sizeof(uint64_t));
            }
            ctx->revoked_count--;
            return;
        }
    }
}

static sm2_ic_error_t query_merkle_callback(sm2_revocation_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    if (!ctx || !ctx->merkle_query_fn || !status || !source)
        return SM2_IC_ERR_PARAM;

    sm2_implicit_cert_t cert;
    memset(&cert, 0, sizeof(cert));
    cert.serial_number = serial_number;

    sm2_ic_error_t ret = ctx->merkle_query_fn(
        &cert, now_ts, ctx->merkle_query_user_ctx, status);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*status != SM2_REV_STATUS_GOOD && *status != SM2_REV_STATUS_REVOKED
        && *status != SM2_REV_STATUS_UNKNOWN)
    {
        return SM2_IC_ERR_VERIFY;
    }

    *source = SM2_REV_SOURCE_MERKLE_NODE;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_init(sm2_revocation_ctx_t *ctx,
    size_t expected_revoked_items, uint64_t filter_ttl_sec, uint64_t now_ts)
{
    if (!ctx || filter_ttl_sec == 0)
        return SM2_IC_ERR_PARAM;

    memset(ctx, 0, sizeof(*ctx));
    ctx->root_valid_ttl_sec = filter_ttl_sec;
    ctx->root_valid_until = now_ts + filter_ttl_sec;

    ctx->query_inflight = 0;
    ctx->congestion_busy_threshold = 64;
    ctx->congestion_overload_threshold = 128;
    ctx->congestion_signal = SM2_REV_CONGESTION_NORMAL;
    ctx->clock_skew_tolerance_sec = 300;

    if (expected_revoked_items > 0)
    {
        sm2_ic_error_t ret = local_list_reserve(ctx, expected_revoked_items);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    return SM2_IC_SUCCESS;
}

void sm2_revocation_cleanup(sm2_revocation_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->revoked_serials && ctx->revoked_capacity > 0)
    {
        sm2_secure_memzero(
            ctx->revoked_serials, ctx->revoked_capacity * sizeof(uint64_t));
    }

    free(ctx->revoked_serials);
    sm2_secure_memzero(ctx, sizeof(*ctx));
}

sm2_ic_error_t sm2_revocation_set_merkle_query(
    sm2_revocation_ctx_t *ctx, sm2_rev_merkle_query_fn query_fn, void *user_ctx)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    ctx->merkle_query_fn = query_fn;
    ctx->merkle_query_user_ctx = user_ctx;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_apply_crl_delta(
    sm2_revocation_ctx_t *ctx, const sm2_crl_delta_t *delta, uint64_t now_ts)
{
    if (!ctx || !delta)
        return SM2_IC_ERR_PARAM;
    if (delta->item_count > 0 && !delta->items)
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
        }
        else
        {
            local_list_remove(ctx, it->serial_number);
        }
    }

    ctx->crl_version = delta->new_version;
    ctx->root_valid_until = now_ts + ctx->root_valid_ttl_sec;
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

    if (!ctx->merkle_query_fn)
        return SM2_IC_ERR_VERIFY;

    return query_merkle_callback(ctx, serial_number, now_ts, status, source);
}

size_t sm2_revocation_local_count(const sm2_revocation_ctx_t *ctx)
{
    return ctx ? ctx->revoked_count : 0;
}

uint64_t sm2_revocation_crl_version(const sm2_revocation_ctx_t *ctx)
{
    return ctx ? ctx->crl_version : 0;
}

sm2_ic_error_t sm2_revocation_set_congestion_thresholds(
    sm2_revocation_ctx_t *ctx, size_t busy_threshold, size_t overload_threshold)
{
    if (!ctx || busy_threshold == 0 || overload_threshold <= busy_threshold)
        return SM2_IC_ERR_PARAM;

    ctx->congestion_busy_threshold = busy_threshold;
    ctx->congestion_overload_threshold = overload_threshold;
    ctx->congestion_signal = calc_congestion_signal(ctx);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_set_query_inflight(
    sm2_revocation_ctx_t *ctx, size_t query_inflight)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    ctx->query_inflight = query_inflight;
    ctx->congestion_signal = calc_congestion_signal(ctx);
    return SM2_IC_SUCCESS;
}

sm2_rev_congestion_signal_t sm2_revocation_get_congestion_signal(
    const sm2_revocation_ctx_t *ctx)
{
    return calc_congestion_signal(ctx);
}

sm2_ic_error_t sm2_revocation_set_clock_skew_tolerance(
    sm2_revocation_ctx_t *ctx, uint64_t tolerance_sec)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    ctx->clock_skew_tolerance_sec = tolerance_sec;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_route_select_node(
    const sm2_rev_route_node_t *nodes, size_t node_count, uint64_t now_ts,
    uint64_t random_nonce, size_t *selected_index)
{
    if (!nodes || node_count == 0 || !selected_index)
        return SM2_IC_ERR_PARAM;

    bool has_non_overload = false;
    for (size_t i = 0; i < node_count; i++)
    {
        const sm2_rev_route_node_t *node = &nodes[i];
        if (node->next_retry_ts > now_ts)
            continue;
        if (route_effective_weight(node, true) == 0)
            continue;
        if (node->congestion_signal != SM2_REV_CONGESTION_OVERLOAD)
            has_non_overload = true;
    }

    uint64_t total_weight = 0;
    for (size_t i = 0; i < node_count; i++)
    {
        const sm2_rev_route_node_t *node = &nodes[i];
        if (node->next_retry_ts > now_ts)
            continue;

        uint32_t w = route_effective_weight(node, !has_non_overload);
        if (w == 0)
            continue;

        if (total_weight > UINT64_MAX - (uint64_t)w)
            total_weight = UINT64_MAX;
        else
            total_weight += (uint64_t)w;
    }

    if (total_weight == 0)
        return SM2_IC_ERR_VERIFY;

    uint64_t ticket = random_nonce % total_weight;
    for (size_t i = 0; i < node_count; i++)
    {
        const sm2_rev_route_node_t *node = &nodes[i];
        if (node->next_retry_ts > now_ts)
            continue;

        uint32_t w = route_effective_weight(node, !has_non_overload);
        if (w == 0)
            continue;

        if (ticket < (uint64_t)w)
        {
            *selected_index = i;
            return SM2_IC_SUCCESS;
        }
        ticket -= (uint64_t)w;
    }

    return SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_revocation_route_feedback(sm2_rev_route_node_t *node,
    bool success, uint64_t now_ts, uint64_t base_backoff_sec,
    uint64_t max_backoff_sec)
{
    if (!node || base_backoff_sec == 0 || max_backoff_sec < base_backoff_sec)
        return SM2_IC_ERR_PARAM;

    if (success)
    {
        node->fail_streak = 0;
        node->next_retry_ts = now_ts;
        return SM2_IC_SUCCESS;
    }

    if (node->fail_streak < UINT32_MAX)
        node->fail_streak++;

    uint32_t shift = node->fail_streak == 0 ? 0U : (node->fail_streak - 1U);
    if (shift > 30U)
        shift = 30U;

    uint64_t backoff = base_backoff_sec;
    if (shift > 0)
    {
        if (backoff > (UINT64_MAX >> shift))
            backoff = UINT64_MAX;
        else
            backoff <<= shift;
    }

    if (backoff > max_backoff_sec)
        backoff = max_backoff_sec;

    if (now_ts > UINT64_MAX - backoff)
        node->next_retry_ts = UINT64_MAX;
    else
        node->next_retry_ts = now_ts + backoff;

    return SM2_IC_SUCCESS;
}

static bool quorum_vote_node_id_equal(
    const sm2_rev_quorum_vote_t *a, const sm2_rev_quorum_vote_t *b)
{
    if (!a || !b)
        return false;
    if (a->node_id_len != b->node_id_len)
        return false;
    if (a->node_id_len == 0 || a->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN)
        return false;

    return memcmp(a->node_id, b->node_id, a->node_id_len) == 0;
}

sm2_ic_error_t sm2_revocation_trust_matrix_evaluate(
    const sm2_rev_trust_matrix_input_t *input,
    sm2_rev_trust_matrix_result_t *result)
{
    if (!input || !result)
        return SM2_IC_ERR_PARAM;

    memset(result, 0, sizeof(*result));

    bool version_monotonic = input->remote_version >= input->local_version;
    bool skew_ok = false;
    uint64_t abs_skew = 0;
    if (input->clock_skew_sec >= 0)
        abs_skew = (uint64_t)input->clock_skew_sec;
    else
        abs_skew = (uint64_t)(-(input->clock_skew_sec + 1)) + 1U;

    skew_ok = abs_skew <= input->clock_tolerance_sec;

    result->hop_pass[SM2_REV_TRUST_HOP_CA_TO_NODE]
        = input->ca_to_node_ok && version_monotonic;
    result->hop_pass[SM2_REV_TRUST_HOP_NODE_SYNC] = input->node_sync_ok;
    result->hop_pass[SM2_REV_TRUST_HOP_NODE_RESPONSE] = input->node_response_ok;
    result->hop_pass[SM2_REV_TRUST_HOP_DEVICE_VERIFY] = input->device_verify_ok;
    result->hop_pass[SM2_REV_TRUST_HOP_FALLBACK_PATH] = input->fallback_ok;
    result->hop_pass[SM2_REV_TRUST_HOP_TIME_WINDOW] = skew_ok;

    for (size_t i = 0; i < SM2_REV_TRUST_HOP_COUNT; i++)
    {
        if (!result->hop_pass[i])
            result->fail_mask |= (uint32_t)(1U << i);
    }

    result->overall_pass = result->fail_mask == 0;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_quorum_evaluate(
    const sm2_rev_quorum_vote_t *votes, size_t vote_count, size_t threshold,
    sm2_rev_quorum_result_t *result)
{
    if (!votes || vote_count == 0 || threshold == 0 || !result)
        return SM2_IC_ERR_PARAM;
    if (vote_count > SM2_REV_QUORUM_MAX_VOTES)
        return SM2_IC_ERR_PARAM;

    memset(result, 0, sizeof(*result));
    result->threshold = threshold;
    result->decided_status = SM2_REV_STATUS_UNKNOWN;

    bool *accepted = (bool *)calloc(vote_count, sizeof(bool));
    if (!accepted)
        return SM2_IC_ERR_MEMORY;

    bool has_selected_version = false;
    uint64_t selected_version = 0;

    for (size_t i = 0; i < vote_count; i++)
    {
        const sm2_rev_quorum_vote_t *v = &votes[i];
        if (!v->proof_valid || v->node_id_len == 0
            || v->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN)
        {
            continue;
        }

        bool dup = false;
        for (size_t j = 0; j < i; j++)
        {
            if (!accepted[j])
                continue;
            if (quorum_vote_node_id_equal(v, &votes[j]))
            {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;

        accepted[i] = true;
        result->unique_node_count++;

        if (!has_selected_version || v->root_version > selected_version)
        {
            selected_version = v->root_version;
            has_selected_version = true;
        }
    }

    if (!has_selected_version)
    {
        free(accepted);
        return SM2_IC_SUCCESS;
    }

    result->selected_root_version = selected_version;

    bool hash_set = false;
    for (size_t i = 0; i < vote_count; i++)
    {
        if (!accepted[i])
            continue;

        const sm2_rev_quorum_vote_t *v = &votes[i];
        if (v->root_version != selected_version)
        {
            result->stale_vote_count++;
            continue;
        }

        result->valid_vote_count++;
        if (!hash_set)
        {
            memcpy(result->selected_root_hash, v->root_hash,
                SM2_REV_SYNC_DIGEST_LEN);
            hash_set = true;
        }
        else if (memcmp(result->selected_root_hash, v->root_hash,
                     SM2_REV_SYNC_DIGEST_LEN)
            != 0)
        {
            result->conflict_vote_count++;
        }
    }

    if (result->conflict_vote_count > 0)
    {
        free(accepted);
        return SM2_IC_ERR_VERIFY;
    }

    for (size_t i = 0; i < vote_count; i++)
    {
        if (!accepted[i])
            continue;

        const sm2_rev_quorum_vote_t *v = &votes[i];
        if (v->root_version != selected_version)
            continue;

        if (v->status == SM2_REV_STATUS_REVOKED)
            result->revoked_votes++;
        else if (v->status == SM2_REV_STATUS_GOOD)
            result->good_votes++;
        else
            result->unknown_votes++;
    }

    result->quorum_met = result->valid_vote_count >= threshold;
    if (result->revoked_votes >= threshold)
        result->decided_status = SM2_REV_STATUS_REVOKED;
    else if (result->good_votes >= threshold)
        result->decided_status = SM2_REV_STATUS_GOOD;

    free(accepted);
    return SM2_IC_SUCCESS;
}
