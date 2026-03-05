/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2_REVOKE_INTERNAL_H
#define SM2_REVOKE_INTERNAL_H

#include "sm2_revocation.h"

#ifdef __cplusplus
extern "C"
{
#endif

    void sm2_rev_internal_u64_to_be(uint64_t v, uint8_t out[8]);
    uint64_t sm2_rev_internal_hash_u64_sm3_tag(uint64_t v, uint8_t tag);
    size_t sm2_rev_internal_next_pow2(size_t v);

    sm2_ic_error_t sm2_rev_internal_refresh_filter_param_hash(
        sm2_revocation_ctx_t *ctx);
    sm2_ic_error_t sm2_rev_internal_calc_set_digest(
        const sm2_revocation_ctx_t *ctx, uint8_t out[SM2_REV_SYNC_DIGEST_LEN]);

    uint32_t sm2_rev_internal_cuckoo_fp(
        const sm2_cuckoo_filter_t *f, uint64_t serial);
    size_t sm2_rev_internal_cuckoo_index1(
        const sm2_cuckoo_filter_t *f, uint64_t serial);
    size_t sm2_rev_internal_cuckoo_index2(
        const sm2_cuckoo_filter_t *f, size_t i1, uint32_t fp);
    uint32_t *sm2_rev_internal_cuckoo_bucket_slot(
        const sm2_cuckoo_filter_t *f, size_t bucket, size_t slot);
    bool sm2_rev_internal_cuckoo_contains(
        const sm2_cuckoo_filter_t *f, uint64_t serial);
    bool sm2_rev_internal_cuckoo_delete(
        sm2_cuckoo_filter_t *f, uint64_t serial);
    sm2_ic_error_t sm2_rev_internal_cuckoo_insert(
        sm2_cuckoo_filter_t *f, uint64_t serial);
    sm2_ic_error_t sm2_rev_internal_cuckoo_reset(sm2_cuckoo_filter_t *f,
        size_t bucket_count, size_t bucket_size, size_t max_kicks,
        uint8_t fp_bits);

    sm2_ic_error_t sm2_rev_internal_rebuild_filter(sm2_revocation_ctx_t *ctx);

    sm2_ic_error_t sm2_rev_internal_local_list_add(
        sm2_revocation_ctx_t *ctx, uint64_t serial);
    void sm2_rev_internal_local_list_remove(
        sm2_revocation_ctx_t *ctx, uint64_t serial);

    const sm2_rev_sync_log_entry_t *sm2_rev_internal_sync_log_get(
        const sm2_revocation_ctx_t *ctx, size_t logical_index);
    sm2_ic_error_t sm2_rev_internal_sync_log_append(sm2_revocation_ctx_t *ctx,
        uint64_t base_version, uint64_t new_version, uint64_t now_ts,
        uint64_t serial_number, bool revoked);
    bool sm2_rev_internal_sync_log_has_base(
        const sm2_revocation_ctx_t *ctx, uint64_t base_version);
    sm2_ic_error_t sm2_rev_internal_sync_reset_local_state(
        sm2_revocation_ctx_t *ctx, uint64_t now_ts);

#ifdef __cplusplus
}
#endif

#endif /* SM2_REVOKE_INTERNAL_H */
