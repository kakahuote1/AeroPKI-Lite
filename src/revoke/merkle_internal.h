/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file merkle_internal.h
 * @brief Internal shared declarations for Merkle accumulator sub-modules.
 *
 * This header is included by merkle.c, merkle_cbor.c, merkle_epoch.c
 * and merkle_k_anon.c.  It is NOT part of the public API.
 */

#ifndef SM2_MERKLE_INTERNAL_H
#define SM2_MERKLE_INTERNAL_H

#include "sm2_revocation.h"
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ---- hash primitives (domain-separated SM3) ---- */
    void merkle_u64_to_be(uint64_t v, uint8_t out[8]);

    sm2_ic_error_t merkle_hash_leaf(
        uint64_t serial_number, uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN]);

    sm2_ic_error_t merkle_hash_parent(
        const uint8_t left[SM2_REV_MERKLE_HASH_LEN],
        const uint8_t right[SM2_REV_MERKLE_HASH_LEN],
        uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN]);

    sm2_ic_error_t merkle_hash_empty(uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN]);

    /* ---- tree layout & search ---- */
    sm2_ic_error_t merkle_calc_layout(sm2_rev_merkle_tree_t *tree,
        size_t leaf_count, size_t *out_total_nodes);

    bool merkle_find_serial(
        const sm2_rev_merkle_tree_t *tree, uint64_t serial, size_t *pos);

    /* ---- sort comparators ---- */
    int merkle_cmp_u64(const void *a, const void *b);
    int merkle_cmp_delta_item(const void *a, const void *b);

    /* ---- CBOR primitives ---- */
    sm2_ic_error_t cbor_put_type_value(uint8_t major, uint64_t value,
        uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_type_value(const uint8_t *in, size_t in_len,
        size_t *offset, uint8_t *major, uint64_t *value);

    sm2_ic_error_t cbor_put_bytes(const uint8_t *data, size_t data_len,
        uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_bytes(const uint8_t *in, size_t in_len,
        size_t *offset, uint8_t *out, size_t out_len, size_t *actual_len);

    sm2_ic_error_t cbor_put_bool(
        bool value, uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_bool(
        const uint8_t *in, size_t in_len, size_t *offset, bool *value);

    sm2_ic_error_t cbor_put_null(uint8_t *out, size_t out_cap, size_t *offset);

    sm2_ic_error_t cbor_get_null(
        const uint8_t *in, size_t in_len, size_t *offset);

    sm2_ic_error_t cbor_get_bytes_alloc(const uint8_t *in, size_t in_len,
        size_t *offset, uint8_t **out, size_t *out_len);

    /* ---- CBOR member proof inner encode/decode ---- */
    sm2_ic_error_t cbor_encode_member_proof_inner(
        const sm2_rev_merkle_membership_proof_t *proof, uint8_t *output,
        size_t output_cap, size_t *offset);

    sm2_ic_error_t cbor_decode_member_proof_inner(
        sm2_rev_merkle_membership_proof_t *proof, const uint8_t *input,
        size_t input_len, size_t *offset);

    /* ---- multiproof helpers ---- */
    sm2_ic_error_t multiproof_reserve_unique_hashes(
        sm2_rev_merkle_multiproof_t *proof, size_t *capacity, size_t required,
        size_t hard_limit);

    sm2_ic_error_t multiproof_find_or_add_hash(
        sm2_rev_merkle_multiproof_t *proof,
        const uint8_t hash[SM2_REV_MERKLE_HASH_LEN], size_t *capacity,
        size_t hard_limit, uint16_t *out_ref);

    sm2_ic_error_t multiproof_expand_member(
        const sm2_rev_merkle_multiproof_t *proof,
        const sm2_rev_merkle_multiproof_item_t *item,
        sm2_rev_merkle_membership_proof_t *member);

    size_t multiproof_next_pow2(size_t v);

    /* ---- epoch directory auth ---- */
    sm2_ic_error_t merkle_serialize_root_for_auth(
        const sm2_rev_merkle_root_record_t *root_record, uint8_t *output,
        size_t output_cap, size_t *output_len);

    sm2_ic_error_t merkle_epoch_serialize_for_auth(
        const sm2_rev_merkle_epoch_directory_t *directory, uint8_t *output,
        size_t output_cap, size_t *output_len);

    sm2_ic_error_t merkle_calc_patch_digest(const sm2_crl_delta_item_t *items,
        size_t item_count, uint8_t out_digest[SM2_REV_MERKLE_HASH_LEN]);

    bool merkle_epoch_patch_lookup(
        const sm2_rev_merkle_epoch_directory_t *directory, uint64_t serial,
        bool *revoked);

    bool merkle_epoch_get_cached_hash(
        const sm2_rev_merkle_epoch_directory_t *directory, size_t level_index,
        size_t node_index, uint8_t out_hash[SM2_REV_MERKLE_HASH_LEN]);

    sm2_ic_error_t merkle_epoch_directory_clone(
        sm2_rev_merkle_epoch_directory_t *dst,
        const sm2_rev_merkle_epoch_directory_t *src);

    size_t merkle_expected_sibling_count(size_t leaf_count);

    /* ---- SM3-based PRNG for k-anonymity ---- */
    sm2_ic_error_t merkle_prng_next(
        uint64_t seed, uint64_t *counter, uint64_t *out_value);

#ifdef __cplusplus
}
#endif

#endif /* SM2_MERKLE_INTERNAL_H */
