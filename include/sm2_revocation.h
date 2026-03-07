/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_revocation.h
 * @brief Revocation management interfaces (Merkle-only path).
 */

#ifndef SM2_REVOCATION_H
#define SM2_REVOCATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "sm2_implicit_cert.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        SM2_REV_STATUS_GOOD = 0,
        SM2_REV_STATUS_REVOKED = 1,
        SM2_REV_STATUS_UNKNOWN = 2
    } sm2_rev_status_t;

    typedef enum
    {
        SM2_REV_SOURCE_NONE = 0,
        SM2_REV_SOURCE_MERKLE_NODE = 1
    } sm2_rev_source_t;

    typedef enum
    {
        SM2_REV_CONGESTION_NORMAL = 0x00,
        SM2_REV_CONGESTION_BUSY = 0x01,
        SM2_REV_CONGESTION_OVERLOAD = 0x02
    } sm2_rev_congestion_signal_t;

#define SM2_REV_TRUST_HOP_COUNT 6

    typedef enum
    {
        SM2_REV_TRUST_HOP_CA_TO_NODE = 0,
        SM2_REV_TRUST_HOP_NODE_SYNC = 1,
        SM2_REV_TRUST_HOP_NODE_RESPONSE = 2,
        SM2_REV_TRUST_HOP_DEVICE_VERIFY = 3,
        SM2_REV_TRUST_HOP_FALLBACK_PATH = 4,
        SM2_REV_TRUST_HOP_TIME_WINDOW = 5
    } sm2_rev_trust_hop_t;
    typedef sm2_ic_error_t (*sm2_rev_merkle_query_fn)(
        const sm2_implicit_cert_t *cert, uint64_t now_ts, void *user_ctx,
        sm2_rev_status_t *status);

    typedef struct
    {
        uint64_t serial_number;
        bool revoked;
    } sm2_crl_delta_item_t;

    typedef struct
    {
        uint64_t base_version;
        uint64_t new_version;
        const sm2_crl_delta_item_t *items;
        size_t item_count;
    } sm2_crl_delta_t;
#define SM2_REV_SYNC_NODE_ID_MAX_LEN 32
#define SM2_REV_SYNC_DIGEST_LEN 32
#define SM2_REV_SYNC_MAX_SIG_LEN 128
#define SM2_REV_MERKLE_HASH_LEN 32
#define SM2_REV_MERKLE_MAX_DEPTH 64
#define SM2_REV_MERKLE_MULTI_MAX_QUERIES 64
#define SM2_REV_MERKLE_EPOCH_MAX_CACHE_LEVELS 16
#define SM2_REV_MERKLE_K_ANON_MAX 32
#define SM2_REV_QUORUM_MAX_VOTES 256
    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint32_t base_weight;
        sm2_rev_congestion_signal_t congestion_signal;
        uint32_t fail_streak;
        uint64_t next_retry_ts;
        bool enabled;
    } sm2_rev_route_node_t;

    typedef struct
    {
        bool ca_to_node_ok;
        bool node_sync_ok;
        bool node_response_ok;
        bool device_verify_ok;
        bool fallback_ok;
        uint64_t local_version;
        uint64_t remote_version;
        int64_t clock_skew_sec;
        uint64_t clock_tolerance_sec;
    } sm2_rev_trust_matrix_input_t;

    typedef struct
    {
        bool hop_pass[SM2_REV_TRUST_HOP_COUNT];
        bool overall_pass;
        uint32_t fail_mask;
    } sm2_rev_trust_matrix_result_t;

    typedef struct
    {
        uint64_t root_version;
        size_t leaf_count;
        uint64_t *serials;
        size_t level_count;
        size_t level_offsets[SM2_REV_MERKLE_MAX_DEPTH];
        size_t level_sizes[SM2_REV_MERKLE_MAX_DEPTH];
        uint8_t *node_hashes;
        size_t node_hashes_len;
        uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    } sm2_rev_merkle_tree_t;

    typedef struct
    {
        uint64_t serial_number;
        size_t leaf_index;
        size_t leaf_count;
        size_t sibling_count;
        uint8_t sibling_hashes[SM2_REV_MERKLE_MAX_DEPTH]
                              [SM2_REV_MERKLE_HASH_LEN];
        uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH];
    } sm2_rev_merkle_membership_proof_t;

    typedef struct
    {
        uint64_t target_serial;
        size_t leaf_count;
        bool has_left_neighbor;
        bool has_right_neighbor;
        sm2_rev_merkle_membership_proof_t left_proof;
        sm2_rev_merkle_membership_proof_t right_proof;
    } sm2_rev_merkle_non_membership_proof_t;

    typedef struct
    {
        uint64_t root_version;
        uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
        uint64_t valid_from;
        uint64_t valid_until;
        uint8_t signature[SM2_REV_SYNC_MAX_SIG_LEN];
        size_t signature_len;
    } sm2_rev_merkle_root_record_t;

    typedef struct
    {
        uint64_t serial_number;
        size_t leaf_index;
        size_t leaf_count;
        size_t sibling_count;
        uint16_t sibling_ref[SM2_REV_MERKLE_MAX_DEPTH];
        uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH];
    } sm2_rev_merkle_multiproof_item_t;

    typedef struct
    {
        size_t query_count;
        sm2_rev_merkle_multiproof_item_t *items;
        size_t unique_hash_count;
        uint8_t (*unique_hashes)[SM2_REV_MERKLE_HASH_LEN];
    } sm2_rev_merkle_multiproof_t;

    typedef struct
    {
        sm2_rev_merkle_membership_proof_t proof;
        size_t omitted_top_levels;
    } sm2_rev_merkle_cached_member_proof_t;

    typedef struct
    {
        uint64_t epoch_id;
        sm2_rev_merkle_root_record_t root_record;
        size_t tree_level_count;
        size_t cache_level_count;
        size_t cached_level_indices[SM2_REV_MERKLE_MAX_DEPTH];
        size_t cached_level_sizes[SM2_REV_MERKLE_MAX_DEPTH];
        size_t cached_level_offsets[SM2_REV_MERKLE_MAX_DEPTH];
        size_t cached_hash_count;
        uint8_t (*cached_hashes)[SM2_REV_MERKLE_HASH_LEN];
        uint64_t patch_version;
        sm2_crl_delta_item_t *patch_items;
        size_t patch_item_count;
        uint8_t directory_signature[SM2_REV_SYNC_MAX_SIG_LEN];
        size_t directory_signature_len;
    } sm2_rev_merkle_epoch_directory_t;

    typedef struct
    {
        uint64_t serials[SM2_REV_MERKLE_K_ANON_MAX];
        size_t serial_count;
        size_t real_index;
        uint8_t risk_weight_k;
        uint8_t risk_weight_span;
        uint8_t risk_weight_nearest;
    } sm2_rev_merkle_k_anon_query_t;

    typedef struct
    {
        uint8_t cluster_level; /* 0=random, 100=nearest clustering */
        uint8_t risk_weight_k; /* 0 -> default 40 */
        uint8_t risk_weight_span; /* 0 -> default 45 */
        uint8_t risk_weight_nearest; /* 0 -> default 15 */
        uint16_t candidate_scan_limit; /* 0 -> default 16*k */
    } sm2_rev_merkle_k_anon_policy_t;

    typedef struct
    {
        const sm2_rev_merkle_epoch_directory_t *directory;
        sm2_ic_error_t (*verify_fn)(void *user_ctx, const uint8_t *data,
            size_t data_len, const uint8_t *signature, size_t signature_len);
        void *verify_user_ctx;
    } sm2_rev_merkle_query_ctx_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t root_version;
        uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN];
        sm2_rev_status_t status;
        bool proof_valid;
    } sm2_rev_quorum_vote_t;

    typedef struct
    {
        uint64_t selected_root_version;
        uint8_t selected_root_hash[SM2_REV_SYNC_DIGEST_LEN];
        size_t unique_node_count;
        size_t valid_vote_count;
        size_t stale_vote_count;
        size_t conflict_vote_count;
        size_t good_votes;
        size_t revoked_votes;
        size_t unknown_votes;
        size_t threshold;
        bool quorum_met;
        sm2_rev_status_t decided_status;
    } sm2_rev_quorum_result_t;

    typedef sm2_ic_error_t (*sm2_rev_sync_sign_fn)(void *user_ctx,
        const uint8_t *data, size_t data_len, uint8_t *signature,
        size_t *signature_len);

    typedef sm2_ic_error_t (*sm2_rev_sync_verify_fn)(void *user_ctx,
        const uint8_t *data, size_t data_len, const uint8_t *signature,
        size_t signature_len);
    typedef struct
    {
        uint64_t *revoked_serials;
        size_t revoked_count;
        size_t revoked_capacity;

        sm2_rev_merkle_query_fn merkle_query_fn;
        void *merkle_query_user_ctx;

        uint64_t crl_version;
        uint64_t root_valid_ttl_sec;
        uint64_t root_valid_until;

        size_t query_inflight;
        size_t congestion_busy_threshold;
        size_t congestion_overload_threshold;
        sm2_rev_congestion_signal_t congestion_signal;
        uint64_t clock_skew_tolerance_sec;
    } sm2_revocation_ctx_t;

    sm2_ic_error_t sm2_revocation_init(sm2_revocation_ctx_t *ctx,
        size_t expected_revoked_items, uint64_t filter_ttl_sec,
        uint64_t now_ts);
    void sm2_revocation_cleanup(sm2_revocation_ctx_t *ctx);

    sm2_ic_error_t sm2_revocation_set_merkle_query(sm2_revocation_ctx_t *ctx,
        sm2_rev_merkle_query_fn query_fn, void *user_ctx);

    sm2_ic_error_t sm2_revocation_apply_crl_delta(sm2_revocation_ctx_t *ctx,
        const sm2_crl_delta_t *delta, uint64_t now_ts);

    sm2_ic_error_t sm2_revocation_query(sm2_revocation_ctx_t *ctx,
        uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
        sm2_rev_source_t *source);

    size_t sm2_revocation_local_count(const sm2_revocation_ctx_t *ctx);
    uint64_t sm2_revocation_crl_version(const sm2_revocation_ctx_t *ctx);

    sm2_ic_error_t sm2_revocation_set_congestion_thresholds(
        sm2_revocation_ctx_t *ctx, size_t busy_threshold,
        size_t overload_threshold);
    sm2_ic_error_t sm2_revocation_set_query_inflight(
        sm2_revocation_ctx_t *ctx, size_t query_inflight);
    sm2_rev_congestion_signal_t sm2_revocation_get_congestion_signal(
        const sm2_revocation_ctx_t *ctx);

    sm2_ic_error_t sm2_revocation_set_clock_skew_tolerance(
        sm2_revocation_ctx_t *ctx, uint64_t tolerance_sec);

    sm2_ic_error_t sm2_revocation_route_select_node(
        const sm2_rev_route_node_t *nodes, size_t node_count, uint64_t now_ts,
        uint64_t random_nonce, size_t *selected_index);
    sm2_ic_error_t sm2_revocation_route_feedback(sm2_rev_route_node_t *node,
        bool success, uint64_t now_ts, uint64_t base_backoff_sec,
        uint64_t max_backoff_sec);

    sm2_ic_error_t sm2_revocation_trust_matrix_evaluate(
        const sm2_rev_trust_matrix_input_t *input,
        sm2_rev_trust_matrix_result_t *result);

    sm2_ic_error_t sm2_revocation_quorum_evaluate(
        const sm2_rev_quorum_vote_t *votes, size_t vote_count, size_t threshold,
        sm2_rev_quorum_result_t *result);

    sm2_ic_error_t sm2_revocation_merkle_build(sm2_rev_merkle_tree_t *tree,
        const uint64_t *revoked_serials, size_t revoked_count,
        uint64_t root_version);
    void sm2_revocation_merkle_cleanup(sm2_rev_merkle_tree_t *tree);

    sm2_ic_error_t sm2_revocation_merkle_prove_member(
        const sm2_rev_merkle_tree_t *tree, uint64_t serial_number,
        sm2_rev_merkle_membership_proof_t *proof);
    sm2_ic_error_t sm2_revocation_merkle_verify_member(
        const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
        const sm2_rev_merkle_membership_proof_t *proof);

    sm2_ic_error_t sm2_revocation_merkle_prove_non_member(
        const sm2_rev_merkle_tree_t *tree, uint64_t serial_number,
        sm2_rev_merkle_non_membership_proof_t *proof);
    sm2_ic_error_t sm2_revocation_merkle_verify_non_member(
        const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
        const sm2_rev_merkle_non_membership_proof_t *proof);

    sm2_ic_error_t sm2_revocation_merkle_cbor_encode_member_proof(
        const sm2_rev_merkle_membership_proof_t *proof, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_revocation_merkle_cbor_decode_member_proof(
        sm2_rev_merkle_membership_proof_t *proof, const uint8_t *input,
        size_t input_len);

    sm2_ic_error_t sm2_revocation_merkle_cbor_encode_non_member_proof(
        const sm2_rev_merkle_non_membership_proof_t *proof, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_revocation_merkle_cbor_decode_non_member_proof(
        sm2_rev_merkle_non_membership_proof_t *proof, const uint8_t *input,
        size_t input_len);

    sm2_ic_error_t sm2_revocation_merkle_sign_root(
        const sm2_rev_merkle_tree_t *tree, uint64_t valid_from,
        uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
        sm2_rev_merkle_root_record_t *root_record);
    sm2_ic_error_t sm2_revocation_merkle_verify_root_record(
        const sm2_rev_merkle_root_record_t *root_record, uint64_t now_ts,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

    sm2_ic_error_t sm2_revocation_merkle_verify_member_with_root(
        const sm2_rev_merkle_root_record_t *root_record, uint64_t now_ts,
        const sm2_rev_merkle_membership_proof_t *proof,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);
    sm2_ic_error_t sm2_revocation_merkle_verify_non_member_with_root(
        const sm2_rev_merkle_root_record_t *root_record, uint64_t now_ts,
        const sm2_rev_merkle_non_membership_proof_t *proof,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

    sm2_ic_error_t sm2_revocation_merkle_cbor_encode_root_record(
        const sm2_rev_merkle_root_record_t *root_record, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_revocation_merkle_cbor_decode_root_record(
        sm2_rev_merkle_root_record_t *root_record, const uint8_t *input,
        size_t input_len);

    void sm2_revocation_merkle_multiproof_cleanup(
        sm2_rev_merkle_multiproof_t *proof);
    sm2_ic_error_t sm2_revocation_merkle_build_multiproof(
        const sm2_rev_merkle_tree_t *tree, const uint64_t *serial_numbers,
        size_t serial_count, sm2_rev_merkle_multiproof_t *proof);
    sm2_ic_error_t sm2_revocation_merkle_verify_multiproof(
        const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
        const sm2_rev_merkle_multiproof_t *proof);
    sm2_ic_error_t sm2_revocation_merkle_verify_multiproof_with_root(
        const sm2_rev_merkle_root_record_t *root_record, uint64_t now_ts,
        const sm2_rev_merkle_multiproof_t *proof,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);
    sm2_ic_error_t sm2_revocation_merkle_cbor_encode_multiproof(
        const sm2_rev_merkle_multiproof_t *proof, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_revocation_merkle_cbor_decode_multiproof(
        sm2_rev_merkle_multiproof_t *proof, const uint8_t *input,
        size_t input_len);

    void sm2_revocation_merkle_epoch_directory_cleanup(
        sm2_rev_merkle_epoch_directory_t *directory);
    sm2_ic_error_t sm2_revocation_merkle_build_epoch_directory(
        const sm2_rev_merkle_tree_t *tree, uint64_t epoch_id,
        size_t cache_top_levels, uint64_t valid_from, uint64_t valid_until,
        sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
        sm2_rev_merkle_epoch_directory_t *directory);
    sm2_ic_error_t sm2_revocation_merkle_verify_epoch_directory(
        const sm2_rev_merkle_epoch_directory_t *directory, uint64_t now_ts,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);
    sm2_ic_error_t sm2_revocation_merkle_epoch_apply_hot_patch(
        sm2_rev_merkle_epoch_directory_t *directory, uint64_t patch_version,
        const sm2_crl_delta_item_t *items, size_t item_count,
        sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx);

    sm2_ic_error_t sm2_revocation_merkle_prove_member_cached(
        const sm2_rev_merkle_tree_t *tree, uint64_t serial_number,
        size_t cache_top_levels, sm2_rev_merkle_cached_member_proof_t *proof);
    sm2_ic_error_t sm2_revocation_merkle_verify_member_cached(
        const sm2_rev_merkle_epoch_directory_t *directory, uint64_t now_ts,
        const sm2_rev_merkle_cached_member_proof_t *proof,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

    sm2_ic_error_t sm2_revocation_merkle_epoch_query_patch_first(
        const sm2_rev_merkle_epoch_directory_t *directory, uint64_t now_ts,
        uint64_t serial_number, sm2_rev_sync_verify_fn verify_fn,
        void *verify_user_ctx, sm2_rev_status_t *status);

    sm2_ic_error_t sm2_revocation_merkle_epoch_switch(
        sm2_rev_merkle_epoch_directory_t *local_directory,
        const sm2_rev_merkle_epoch_directory_t *incoming_directory,
        uint64_t now_ts, sm2_rev_sync_verify_fn verify_fn,
        void *verify_user_ctx);

    sm2_ic_error_t sm2_revocation_merkle_build_k_anon_query(
        uint64_t real_serial, const uint64_t *decoy_serials, size_t decoy_count,
        size_t k, uint64_t shuffle_seed, sm2_rev_merkle_k_anon_query_t *query);
    sm2_ic_error_t sm2_revocation_merkle_build_k_anon_query_with_policy(
        uint64_t real_serial, const uint64_t *decoy_serials, size_t decoy_count,
        size_t k, uint64_t shuffle_seed,
        const sm2_rev_merkle_k_anon_policy_t *policy,
        sm2_rev_merkle_k_anon_query_t *query);
    sm2_ic_error_t sm2_revocation_merkle_export_k_anon_serials(
        const sm2_rev_merkle_k_anon_query_t *query, uint64_t *serials,
        size_t *serial_count);
    sm2_ic_error_t sm2_revocation_merkle_estimate_k_anon_risk(
        const sm2_rev_merkle_k_anon_query_t *query, uint64_t real_serial,
        double *risk_score, uint64_t *span);

    sm2_ic_error_t sm2_revocation_merkle_query_patch_first_cb(
        const sm2_implicit_cert_t *cert, uint64_t now_ts, void *user_ctx,
        sm2_rev_status_t *status);

    sm2_ic_error_t sm2_revocation_merkle_cbor_encode_epoch_directory(
        const sm2_rev_merkle_epoch_directory_t *directory, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_revocation_merkle_cbor_decode_epoch_directory(
        sm2_rev_merkle_epoch_directory_t *directory, const uint8_t *input,
        size_t input_len);

    sm2_ic_error_t sm2_revocation_merkle_cbor_encode_cached_member_proof(
        const sm2_rev_merkle_cached_member_proof_t *proof, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_revocation_merkle_cbor_decode_cached_member_proof(
        sm2_rev_merkle_cached_member_proof_t *proof, const uint8_t *input,
        size_t input_len);
#ifdef __cplusplus
}
#endif

#endif /* SM2_REVOCATION_H */
