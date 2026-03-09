/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke_bft.c
 * @brief Revocation BFT quorum and trust evaluation helpers.
 */

#include "sm2_revocation.h"
#include "revoke_internal.h"

#include <stdlib.h>
#include <string.h>

sm2_ic_error_t sm2_rev_bft_check(const sm2_rev_bft_quorum_input_t *input,
    sm2_rev_bft_quorum_result_t *result)
{
    if (!input || !result || !input->votes || !input->trust_inputs
        || input->threshold == 0)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_ic_error_t ret
        = sm2_rev_internal_validate_vote_count(input->vote_count);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (input->patch && (!input->local_root_hash || !input->patch_ca_verified))
        return SM2_IC_ERR_VERIFY;

    memset(result, 0, sizeof(*result));

    if (input->patch)
    {
        ret = sm2_rev_sync_verify_patch_link(input->patch, input->local_version,
            input->local_root_hash, input->now_ts, input->skew_tolerance_sec);
        if (ret != SM2_IC_SUCCESS)
            return ret;
        result->patch_verified = true;
    }

    if (input->vote_count > SIZE_MAX / sizeof(sm2_rev_quorum_vote_t))
        return SM2_IC_ERR_MEMORY;

    sm2_rev_quorum_vote_t *trusted_votes = (sm2_rev_quorum_vote_t *)calloc(
        input->vote_count, sizeof(sm2_rev_quorum_vote_t));
    if (!trusted_votes)
        return SM2_IC_ERR_MEMORY;

    size_t trusted_count = 0;
    for (size_t i = 0; i < input->vote_count; i++)
    {
        sm2_rev_trust_matrix_result_t trust_result;
        sm2_ic_error_t ret
            = sm2_rev_trust_evaluate(&input->trust_inputs[i], &trust_result);
        if (ret != SM2_IC_SUCCESS)
        {
            free(trusted_votes);
            return ret;
        }

        if (!trust_result.overall_pass)
        {
            result->rejected_vote_count++;
            continue;
        }

        trusted_votes[trusted_count++] = input->votes[i];
    }

    result->trusted_vote_count = trusted_count;
    result->live_honest_node_assumed = trusted_count > 0;
    if (trusted_count == 0)
    {
        free(trusted_votes);
        return SM2_IC_SUCCESS;
    }

    ret = sm2_rev_quorum_check(
        trusted_votes, trusted_count, input->threshold, &result->quorum_result);
    free(trusted_votes);

    result->quorum_evaluated = true;
    result->quorum_met = result->quorum_result.quorum_met;
    result->fork_detected = result->quorum_result.conflict_vote_count > 0;
    if (ret == SM2_IC_ERR_VERIFY && result->fork_detected)
        return SM2_IC_ERR_VERIFY;
    return ret;
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

sm2_ic_error_t sm2_rev_trust_evaluate(const sm2_rev_trust_matrix_input_t *input,
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

sm2_ic_error_t sm2_rev_quorum_check(const sm2_rev_quorum_vote_t *votes,
    size_t vote_count, size_t threshold, sm2_rev_quorum_result_t *result)
{
    if (!votes || threshold == 0 || !result)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret = sm2_rev_internal_validate_vote_count(vote_count);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    memset(result, 0, sizeof(*result));
    result->threshold = threshold;
    result->decided_status = SM2_REV_STATUS_UNKNOWN;

    if (vote_count > SIZE_MAX / sizeof(bool))
        return SM2_IC_ERR_MEMORY;

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
