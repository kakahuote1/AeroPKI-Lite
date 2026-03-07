/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle_k_anon.c
 * @brief k-Anonymity query builder, cluster policy, risk estimator and
 *        patch-first query callback.
 */

#include "merkle_internal.h"
sm2_ic_error_t merkle_prng_next(
    uint64_t seed, uint64_t *counter, uint64_t *out_value)
{
    if (!counter || !out_value)
        return SM2_IC_ERR_PARAM;

    uint8_t buf[16];
    merkle_u64_to_be(seed, buf);
    merkle_u64_to_be(*counter, buf + 8);
    (*counter)++;

    uint8_t hash[SM2_REV_MERKLE_HASH_LEN];
    sm2_ic_error_t ret = sm2_ic_sm3_hash(buf, sizeof(buf), hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    uint64_t result = 0;
    for (int i = 0; i < 8; i++)
        result = (result << 8) | (uint64_t)hash[i];

    *out_value = result;
    return SM2_IC_SUCCESS;
}

bool merkle_k_anon_contains(
    const uint64_t *serials, size_t count, uint64_t serial)
{
    for (size_t i = 0; i < count; i++)
    {
        if (serials[i] == serial)
            return true;
    }
    return false;
}

#define MERKLE_K_ANON_DEFAULT_SCAN_FACTOR 16U
#define MERKLE_K_ANON_DEFAULT_WEIGHT_K 40U
#define MERKLE_K_ANON_DEFAULT_WEIGHT_SPAN 45U
#define MERKLE_K_ANON_DEFAULT_WEIGHT_NEAREST 15U

typedef struct
{
    uint64_t serial;
    uint8_t used;
} merkle_u64_hash_slot_t;

void merkle_k_anon_set_default_weights(sm2_rev_merkle_k_anon_query_t *query)
{
    query->risk_weight_k = MERKLE_K_ANON_DEFAULT_WEIGHT_K;
    query->risk_weight_span = MERKLE_K_ANON_DEFAULT_WEIGHT_SPAN;
    query->risk_weight_nearest = MERKLE_K_ANON_DEFAULT_WEIGHT_NEAREST;
}

void merkle_k_anon_apply_policy_weights(sm2_rev_merkle_k_anon_query_t *query,
    const sm2_rev_merkle_k_anon_policy_t *policy)
{
    if (!query)
        return;

    merkle_k_anon_set_default_weights(query);
    if (!policy)
        return;

    uint32_t sum = (uint32_t)policy->risk_weight_k
        + (uint32_t)policy->risk_weight_span
        + (uint32_t)policy->risk_weight_nearest;
    if (sum == 0)
        return;

    query->risk_weight_k = policy->risk_weight_k;
    query->risk_weight_span = policy->risk_weight_span;
    query->risk_weight_nearest = policy->risk_weight_nearest;
}

size_t merkle_k_anon_resolve_scan_limit(
    size_t decoy_count, size_t k, const sm2_rev_merkle_k_anon_policy_t *policy)
{
    size_t limit = k * MERKLE_K_ANON_DEFAULT_SCAN_FACTOR;
    if (policy && policy->candidate_scan_limit > 0)
        limit = policy->candidate_scan_limit;

    if (limit < k)
        limit = k;
    if (limit > decoy_count)
        limit = decoy_count;

    return limit;
}

uint64_t merkle_hash_mix64(uint64_t v)
{
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    v *= 0xc4ceb9fe1a85ec53ULL;
    v ^= v >> 33;
    return v;
}

sm2_ic_error_t merkle_u64_hash_insert(merkle_u64_hash_slot_t *slots,
    size_t slot_count, uint64_t serial, bool *inserted)
{
    if (!slots || slot_count == 0 || !inserted)
        return SM2_IC_ERR_PARAM;

    size_t mask = slot_count - 1;
    size_t idx = (size_t)(merkle_hash_mix64(serial) & (uint64_t)mask);

    for (size_t i = 0; i < slot_count; i++)
    {
        merkle_u64_hash_slot_t *slot = &slots[idx];
        if (!slot->used)
        {
            slot->used = 1;
            slot->serial = serial;
            *inserted = true;
            return SM2_IC_SUCCESS;
        }
        if (slot->serial == serial)
        {
            *inserted = false;
            return SM2_IC_SUCCESS;
        }
        idx = (idx + 1) & mask;
    }

    return SM2_IC_ERR_MEMORY;
}
sm2_ic_error_t sm2_revocation_merkle_build_k_anon_query(uint64_t real_serial,
    const uint64_t *decoy_serials, size_t decoy_count, size_t k,
    uint64_t shuffle_seed, sm2_rev_merkle_k_anon_query_t *query)
{
    if (!query || k == 0 || k > SM2_REV_MERKLE_K_ANON_MAX)
        return SM2_IC_ERR_PARAM;
    if (k > 1 && (!decoy_serials || decoy_count == 0))
        return SM2_IC_ERR_PARAM;

    memset(query, 0, sizeof(*query));
    merkle_k_anon_set_default_weights(query);
    query->serials[0] = real_serial;
    query->serial_count = 1;

    for (size_t i = 0; i < decoy_count && query->serial_count < k; i++)
    {
        uint64_t candidate = decoy_serials[i];

        if (candidate == real_serial)
            continue;
        if (merkle_k_anon_contains(
                query->serials, query->serial_count, candidate))
        {
            continue;
        }

        query->serials[query->serial_count++] = candidate;
    }

    if (query->serial_count != k)
        return SM2_IC_ERR_PARAM;

    uint64_t prng_seed = shuffle_seed ^ real_serial ^ (uint64_t)k;
    uint64_t prng_counter = 0;
    for (size_t i = k - 1; i > 0; i--)
    {
        uint64_t rnd = 0;
        sm2_ic_error_t ret = merkle_prng_next(prng_seed, &prng_counter, &rnd);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        size_t j = (size_t)(rnd % (i + 1));
        uint64_t tmp = query->serials[i];
        query->serials[i] = query->serials[j];
        query->serials[j] = tmp;
    }

    for (size_t i = 0; i < k; i++)
    {
        if (query->serials[i] == real_serial)
        {
            query->real_index = i;
            return SM2_IC_SUCCESS;
        }
    }

    return SM2_IC_ERR_VERIFY;
}

typedef struct
{
    uint64_t serial;
    uint64_t distance;
    uint64_t random_key;
    size_t rank_distance;
    size_t rank_random;
    uint64_t score;
    bool selected;
} merkle_k_anon_candidate_t;

uint64_t merkle_u64_distance(uint64_t a, uint64_t b)
{
    return (a >= b) ? (a - b) : (b - a);
}

sm2_ic_error_t sm2_revocation_merkle_build_k_anon_query_with_policy(
    uint64_t real_serial, const uint64_t *decoy_serials, size_t decoy_count,
    size_t k, uint64_t shuffle_seed,
    const sm2_rev_merkle_k_anon_policy_t *policy,
    sm2_rev_merkle_k_anon_query_t *query)
{
    if (!policy)
    {
        return sm2_revocation_merkle_build_k_anon_query(
            real_serial, decoy_serials, decoy_count, k, shuffle_seed, query);
    }

    if (!query || k == 0 || k > SM2_REV_MERKLE_K_ANON_MAX)
        return SM2_IC_ERR_PARAM;
    if (policy->cluster_level > 100)
        return SM2_IC_ERR_PARAM;
    if (k > 1 && (!decoy_serials || decoy_count == 0))
        return SM2_IC_ERR_PARAM;

    memset(query, 0, sizeof(*query));
    merkle_k_anon_apply_policy_weights(query, policy);
    query->serials[0] = real_serial;
    query->serial_count = 1;

    if (k == 1)
    {
        query->real_index = 0;
        return SM2_IC_SUCCESS;
    }

    size_t scan_limit
        = merkle_k_anon_resolve_scan_limit(decoy_count, k, policy);
    if (scan_limit < (k - 1U))
        scan_limit = k - 1U;

    merkle_k_anon_candidate_t *candidates = (merkle_k_anon_candidate_t *)calloc(
        scan_limit, sizeof(merkle_k_anon_candidate_t));
    if (!candidates)
        return SM2_IC_ERR_MEMORY;

    size_t slot_count = multiproof_next_pow2(scan_limit * 4U);
    if (slot_count < 16U)
        slot_count = 16U;
    if (slot_count > (SIZE_MAX / sizeof(merkle_u64_hash_slot_t)))
    {
        free(candidates);
        return SM2_IC_ERR_MEMORY;
    }

    merkle_u64_hash_slot_t *hash_slots = (merkle_u64_hash_slot_t *)calloc(
        slot_count, sizeof(merkle_u64_hash_slot_t));
    if (!hash_slots)
    {
        free(candidates);
        return SM2_IC_ERR_MEMORY;
    }

    bool inserted = false;
    sm2_ic_error_t ret = merkle_u64_hash_insert(
        hash_slots, slot_count, real_serial, &inserted);
    if (ret != SM2_IC_SUCCESS)
    {
        free(hash_slots);
        free(candidates);
        return ret;
    }

    size_t unique_count = 0;
    uint64_t prng_seed = shuffle_seed ^ real_serial ^ ((uint64_t)k << 32);
    uint64_t prng_counter = 0;

    for (size_t i = 0; i < decoy_count && unique_count < scan_limit; i++)
    {
        uint64_t candidate = decoy_serials[i];

        ret = merkle_u64_hash_insert(
            hash_slots, slot_count, candidate, &inserted);
        if (ret != SM2_IC_SUCCESS)
        {
            free(hash_slots);
            free(candidates);
            return ret;
        }
        if (!inserted || candidate == real_serial)
            continue;

        candidates[unique_count].serial = candidate;
        candidates[unique_count].distance
            = merkle_u64_distance(candidate, real_serial);
        uint64_t rnd = 0;
        ret = merkle_prng_next(prng_seed, &prng_counter, &rnd);
        if (ret != SM2_IC_SUCCESS)
        {
            free(hash_slots);
            free(candidates);
            return ret;
        }

        candidates[unique_count].random_key = rnd;
        unique_count++;
    }

    free(hash_slots);

    if (unique_count < (k - 1U))
    {
        free(candidates);
        return SM2_IC_ERR_PARAM;
    }

    uint8_t cluster_level = policy->cluster_level;
    for (size_t i = 0; i < unique_count; i++)
    {
        size_t dist_rank = 0;
        size_t rand_rank = 0;
        for (size_t j = 0; j < unique_count; j++)
        {
            if (candidates[j].distance < candidates[i].distance
                || (candidates[j].distance == candidates[i].distance
                    && candidates[j].serial < candidates[i].serial))
            {
                dist_rank++;
            }

            if (candidates[j].random_key < candidates[i].random_key
                || (candidates[j].random_key == candidates[i].random_key
                    && candidates[j].serial < candidates[i].serial))
            {
                rand_rank++;
            }
        }

        candidates[i].rank_distance = dist_rank;
        candidates[i].rank_random = rand_rank;
        candidates[i].score = (uint64_t)cluster_level * (uint64_t)dist_rank
            + (uint64_t)(100U - cluster_level) * (uint64_t)rand_rank;
    }

    while (query->serial_count < k)
    {
        size_t best = SIZE_MAX;

        for (size_t i = 0; i < unique_count; i++)
        {
            if (candidates[i].selected)
                continue;

            if (best == SIZE_MAX)
            {
                best = i;
                continue;
            }

            bool better = false;
            if (candidates[i].score < candidates[best].score)
            {
                better = true;
            }
            else if (candidates[i].score == candidates[best].score)
            {
                if (candidates[i].distance < candidates[best].distance)
                {
                    better = true;
                }
                else if (candidates[i].distance == candidates[best].distance)
                {
                    if (candidates[i].random_key < candidates[best].random_key)
                    {
                        better = true;
                    }
                    else if (candidates[i].random_key
                            == candidates[best].random_key
                        && candidates[i].serial < candidates[best].serial)
                    {
                        better = true;
                    }
                }
            }

            if (better)
                best = i;
        }

        if (best == SIZE_MAX)
        {
            free(candidates);
            return SM2_IC_ERR_VERIFY;
        }

        candidates[best].selected = true;
        query->serials[query->serial_count++] = candidates[best].serial;
    }

    free(candidates);

    prng_seed = shuffle_seed ^ real_serial ^ (uint64_t)k;
    prng_counter = 0;
    for (size_t i = k - 1; i > 0; i--)
    {
        uint64_t rnd = 0;
        ret = merkle_prng_next(prng_seed, &prng_counter, &rnd);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        size_t j = (size_t)(rnd % (i + 1));
        uint64_t tmp = query->serials[i];
        query->serials[i] = query->serials[j];
        query->serials[j] = tmp;
    }

    for (size_t i = 0; i < k; i++)
    {
        if (query->serials[i] == real_serial)
        {
            query->real_index = i;
            return SM2_IC_SUCCESS;
        }
    }

    return SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_revocation_merkle_estimate_k_anon_risk(
    const sm2_rev_merkle_k_anon_query_t *query, uint64_t real_serial,
    double *risk_score, uint64_t *span)
{
    if (!query)
        return SM2_IC_ERR_PARAM;
    if (!risk_score && !span)
        return SM2_IC_ERR_PARAM;
    if (query->serial_count == 0
        || query->serial_count > SM2_REV_MERKLE_K_ANON_MAX)
    {
        return SM2_IC_ERR_PARAM;
    }

    size_t real_hits = 0;
    uint64_t min_serial = query->serials[0];
    uint64_t max_serial = query->serials[0];
    uint64_t nearest = UINT64_MAX;

    for (size_t i = 0; i < query->serial_count; i++)
    {
        uint64_t v = query->serials[i];

        if (v < min_serial)
            min_serial = v;
        if (v > max_serial)
            max_serial = v;

        if (v == real_serial)
        {
            real_hits++;
            continue;
        }

        uint64_t d = merkle_u64_distance(v, real_serial);
        if (d < nearest)
            nearest = d;
    }

    if (real_hits != 1)
        return SM2_IC_ERR_VERIFY;

    uint64_t serial_span = max_serial - min_serial;
    if (span)
        *span = serial_span;

    if (risk_score)
    {
        double k_component = 1.0 / (double)query->serial_count;
        double span_component = (double)(query->serial_count - 1U)
            / ((double)serial_span + (double)(query->serial_count - 1U));
        double nearest_component
            = (nearest == UINT64_MAX) ? 0.0 : (1.0 / ((double)nearest + 1.0));

        double wk = (double)query->risk_weight_k;
        double ws = (double)query->risk_weight_span;
        double wn = (double)query->risk_weight_nearest;
        double wsum = wk + ws + wn;
        if (wsum <= 0.0)
        {
            wk = MERKLE_K_ANON_DEFAULT_WEIGHT_K;
            ws = MERKLE_K_ANON_DEFAULT_WEIGHT_SPAN;
            wn = MERKLE_K_ANON_DEFAULT_WEIGHT_NEAREST;
            wsum = wk + ws + wn;
        }

        double risk
            = (wk * k_component + ws * span_component + wn * nearest_component)
            / wsum;
        if (risk < 0.0)
            risk = 0.0;
        if (risk > 1.0)
            risk = 1.0;
        *risk_score = risk;
    }

    return SM2_IC_SUCCESS;
}
sm2_ic_error_t sm2_revocation_merkle_export_k_anon_serials(
    const sm2_rev_merkle_k_anon_query_t *query, uint64_t *serials,
    size_t *serial_count)
{
    if (!query || !serial_count)
        return SM2_IC_ERR_PARAM;
    if (query->serial_count == 0
        || query->serial_count > SM2_REV_MERKLE_K_ANON_MAX)
    {
        return SM2_IC_ERR_PARAM;
    }

    if (!serials || *serial_count < query->serial_count)
    {
        *serial_count = query->serial_count;
        return SM2_IC_ERR_MEMORY;
    }

    memcpy(serials, query->serials, query->serial_count * sizeof(uint64_t));
    *serial_count = query->serial_count;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_revocation_merkle_query_patch_first_cb(
    const sm2_implicit_cert_t *cert, uint64_t now_ts, void *user_ctx,
    sm2_rev_status_t *status)
{
    if (!cert || !status || !user_ctx)
        return SM2_IC_ERR_PARAM;

    sm2_rev_merkle_query_ctx_t *ctx = (sm2_rev_merkle_query_ctx_t *)user_ctx;
    if (!ctx->directory || !ctx->verify_fn)
        return SM2_IC_ERR_PARAM;

    return sm2_revocation_merkle_epoch_query_patch_first(ctx->directory, now_ts,
        cert->serial_number, ctx->verify_fn, ctx->verify_user_ctx, status);
}
