/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2ECQV_REVOKE_H
#define SM2ECQV_REVOKE_H

#include "../sm2_revocation.h"

typedef sm2_revocation_ctx_t SM2_REV_CTX;
typedef sm2_rev_status_t SM2_REV_STATUS;
typedef sm2_rev_source_t SM2_REV_SOURCE;
typedef sm2_crl_delta_item_t SM2_REV_CRL_DELTA_ITEM;
typedef sm2_crl_delta_t SM2_REV_CRL_DELTA;
typedef sm2_rev_congestion_signal_t SM2_REV_CONGESTION_SIGNAL;
typedef sm2_rev_route_node_t SM2_REV_ROUTE_NODE;
typedef sm2_rev_trust_hop_t SM2_REV_TRUST_HOP;
typedef sm2_rev_trust_matrix_input_t SM2_REV_TRUST_MATRIX_INPUT;
typedef sm2_rev_trust_matrix_result_t SM2_REV_TRUST_MATRIX_RESULT;
typedef sm2_rev_quorum_vote_t SM2_REV_QUORUM_VOTE;
typedef sm2_rev_quorum_result_t SM2_REV_QUORUM_RESULT;
typedef sm2_rev_merkle_tree_t SM2_REV_MERKLE_TREE;
typedef sm2_rev_merkle_membership_proof_t SM2_REV_MERKLE_MEMBER_PROOF;
typedef sm2_rev_merkle_non_membership_proof_t SM2_REV_MERKLE_NON_MEMBER_PROOF;
typedef sm2_rev_merkle_root_record_t SM2_REV_MERKLE_ROOT_RECORD;
typedef sm2_rev_merkle_multiproof_item_t SM2_REV_MERKLE_MULTIPROOF_ITEM;
typedef sm2_rev_merkle_multiproof_t SM2_REV_MERKLE_MULTIPROOF;
typedef sm2_rev_merkle_cached_member_proof_t SM2_REV_MERKLE_CACHED_MEMBER_PROOF;
typedef sm2_rev_merkle_epoch_directory_t SM2_REV_MERKLE_EPOCH_DIRECTORY;
typedef sm2_rev_merkle_k_anon_query_t SM2_REV_MERKLE_K_ANON_QUERY;
typedef sm2_rev_merkle_k_anon_policy_t SM2_REV_MERKLE_K_ANON_POLICY;
typedef sm2_rev_merkle_query_ctx_t SM2_REV_MERKLE_QUERY_CTX;
typedef sm2_ic_error_t SM2_REV_ERROR;

#define SM2_REV_SUCCESS SM2_IC_SUCCESS

#define SM2_REV_SIGNAL_NORMAL SM2_REV_CONGESTION_NORMAL
#define SM2_REV_SIGNAL_BUSY SM2_REV_CONGESTION_BUSY
#define SM2_REV_SIGNAL_OVERLOAD SM2_REV_CONGESTION_OVERLOAD

#define SM2_REV_init sm2_revocation_init
#define SM2_REV_cleanup sm2_revocation_cleanup
#define SM2_REV_set_merkle_query sm2_revocation_set_merkle_query
#define SM2_REV_apply_crl_delta sm2_revocation_apply_crl_delta
#define SM2_REV_query sm2_revocation_query
#define SM2_REV_local_count sm2_revocation_local_count
#define SM2_REV_crl_version sm2_revocation_crl_version
#define SM2_REV_set_congestion_thresholds                                      \
    sm2_revocation_set_congestion_thresholds
#define SM2_REV_set_query_inflight sm2_revocation_set_query_inflight
#define SM2_REV_get_congestion_signal sm2_revocation_get_congestion_signal
#define SM2_REV_set_clock_skew_tolerance sm2_revocation_set_clock_skew_tolerance
#define SM2_REV_route_select_node sm2_revocation_route_select_node
#define SM2_REV_route_feedback sm2_revocation_route_feedback
#define SM2_REV_trust_matrix_evaluate sm2_revocation_trust_matrix_evaluate
#define SM2_REV_quorum_evaluate sm2_revocation_quorum_evaluate

#define SM2_REV_merkle_build sm2_revocation_merkle_build
#define SM2_REV_merkle_cleanup sm2_revocation_merkle_cleanup
#define SM2_REV_merkle_prove_member sm2_revocation_merkle_prove_member
#define SM2_REV_merkle_verify_member sm2_revocation_merkle_verify_member
#define SM2_REV_merkle_prove_non_member sm2_revocation_merkle_prove_non_member
#define SM2_REV_merkle_verify_non_member sm2_revocation_merkle_verify_non_member
#define SM2_REV_merkle_cbor_encode_member_proof                                \
    sm2_revocation_merkle_cbor_encode_member_proof
#define SM2_REV_merkle_cbor_decode_member_proof                                \
    sm2_revocation_merkle_cbor_decode_member_proof
#define SM2_REV_merkle_cbor_encode_non_member_proof                            \
    sm2_revocation_merkle_cbor_encode_non_member_proof
#define SM2_REV_merkle_cbor_decode_non_member_proof                            \
    sm2_revocation_merkle_cbor_decode_non_member_proof
#define SM2_REV_merkle_sign_root sm2_revocation_merkle_sign_root
#define SM2_REV_merkle_verify_root_record                                      \
    sm2_revocation_merkle_verify_root_record
#define SM2_REV_merkle_verify_member_with_root                                 \
    sm2_revocation_merkle_verify_member_with_root
#define SM2_REV_merkle_verify_non_member_with_root                             \
    sm2_revocation_merkle_verify_non_member_with_root
#define SM2_REV_merkle_cbor_encode_root_record                                 \
    sm2_revocation_merkle_cbor_encode_root_record
#define SM2_REV_merkle_cbor_decode_root_record                                 \
    sm2_revocation_merkle_cbor_decode_root_record

#define SM2_REV_merkle_multiproof_cleanup                                      \
    sm2_revocation_merkle_multiproof_cleanup
#define SM2_REV_merkle_build_multiproof sm2_revocation_merkle_build_multiproof
#define SM2_REV_merkle_verify_multiproof sm2_revocation_merkle_verify_multiproof
#define SM2_REV_merkle_verify_multiproof_with_root                             \
    sm2_revocation_merkle_verify_multiproof_with_root
#define SM2_REV_merkle_cbor_encode_multiproof                                  \
    sm2_revocation_merkle_cbor_encode_multiproof
#define SM2_REV_merkle_cbor_decode_multiproof                                  \
    sm2_revocation_merkle_cbor_decode_multiproof

#define SM2_REV_merkle_epoch_directory_cleanup                                 \
    sm2_revocation_merkle_epoch_directory_cleanup
#define SM2_REV_merkle_build_epoch_directory                                   \
    sm2_revocation_merkle_build_epoch_directory
#define SM2_REV_merkle_verify_epoch_directory                                  \
    sm2_revocation_merkle_verify_epoch_directory
#define SM2_REV_merkle_epoch_apply_hot_patch                                   \
    sm2_revocation_merkle_epoch_apply_hot_patch
#define SM2_REV_merkle_prove_member_cached                                     \
    sm2_revocation_merkle_prove_member_cached
#define SM2_REV_merkle_verify_member_cached                                    \
    sm2_revocation_merkle_verify_member_cached
#define SM2_REV_merkle_cbor_encode_epoch_directory                             \
    sm2_revocation_merkle_cbor_encode_epoch_directory
#define SM2_REV_merkle_cbor_decode_epoch_directory                             \
    sm2_revocation_merkle_cbor_decode_epoch_directory
#define SM2_REV_merkle_cbor_encode_cached_member_proof                         \
    sm2_revocation_merkle_cbor_encode_cached_member_proof
#define SM2_REV_merkle_cbor_decode_cached_member_proof                         \
    sm2_revocation_merkle_cbor_decode_cached_member_proof

#define SM2_REV_merkle_epoch_query_patch_first                                 \
    sm2_revocation_merkle_epoch_query_patch_first
#define SM2_REV_merkle_epoch_switch sm2_revocation_merkle_epoch_switch
#define SM2_REV_merkle_build_k_anon_query                                      \
    sm2_revocation_merkle_build_k_anon_query
#define SM2_REV_merkle_build_k_anon_query_with_policy                          \
    sm2_revocation_merkle_build_k_anon_query_with_policy
#define SM2_REV_merkle_export_k_anon_serials                                   \
    sm2_revocation_merkle_export_k_anon_serials
#define SM2_REV_merkle_estimate_k_anon_risk                                    \
    sm2_revocation_merkle_estimate_k_anon_risk
#define SM2_REV_merkle_query_patch_first_cb                                    \
    sm2_revocation_merkle_query_patch_first_cb

#endif
