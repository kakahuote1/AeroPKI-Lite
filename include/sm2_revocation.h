/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_revocation.h
 * @brief Online/Offline certificate revocation management for SM2 implicit
 * certs.
 */

#ifndef SM2_REVOCATION_H
#define SM2_REVOCATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
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
        SM2_REV_SOURCE_OCSP = 1,
        SM2_REV_SOURCE_OCSP_CACHE = 2,
        SM2_REV_SOURCE_LOCAL_FILTER = 3,
        SM2_REV_SOURCE_LOCAL_FILTER_STALE = 4
    } sm2_rev_source_t;

    typedef struct
    {
        uint64_t serial_number;
        sm2_rev_status_t status;
        uint64_t this_update;
        uint64_t next_update;
    } sm2_ocsp_response_t;

    typedef sm2_ic_error_t (*sm2_ocsp_query_fn)(void *user_ctx,
        uint64_t serial_number, uint32_t timeout_ms,
        sm2_ocsp_response_t *response);

    typedef struct
    {
        sm2_ocsp_query_fn query_fn;
        void *user_ctx;
        uint32_t timeout_ms;
        uint8_t retry_count;
        size_t cache_capacity;
    } sm2_ocsp_client_cfg_t;

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

    typedef struct
    {
        uint64_t serial_number;
        sm2_rev_status_t status;
        uint64_t expires_at;
        bool used;
    } sm2_ocsp_cache_entry_t;

    typedef struct
    {
        uint32_t *fingerprints;
        size_t bucket_count;
        size_t bucket_size;
        size_t max_kicks;
        uint8_t fp_bits;
    } sm2_cuckoo_filter_t;

#define SM2_REV_SYNC_NODE_ID_MAX_LEN 32
#define SM2_REV_SYNC_DIGEST_LEN 32
#define SM2_REV_SYNC_MAX_SIG_LEN 128
#define SM2_REV_SYNC_BUCKET_SUMMARY_MAX 128
#define SM2_REV_SYNC_BUCKET_CANDIDATE_MAX 64

    typedef struct
    {
        size_t bucket_index;
        uint32_t nonzero_count;
        uint32_t xor_fp;
        uint64_t sum_fp;
    } sm2_rev_bucket_summary_t;

    typedef struct
    {
        uint64_t base_version;
        uint64_t new_version;
        uint64_t timestamp;
        uint64_t serial_number;
        bool revoked;
    } sm2_rev_sync_log_entry_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t sync_epoch;
        uint64_t last_sync_ts;
        uint64_t crl_version;
        uint64_t filter_ttl_sec;
        uint64_t filter_expire_at;
        uint8_t fp_bits;
        size_t bucket_size;
        size_t bucket_count;
        uint8_t set_digest[SM2_REV_SYNC_DIGEST_LEN];
        uint8_t filter_param_hash[SM2_REV_SYNC_DIGEST_LEN];
        size_t bucket_summary_count;
        sm2_rev_bucket_summary_t
            bucket_summaries[SM2_REV_SYNC_BUCKET_SUMMARY_MAX];
    } sm2_rev_sync_hello_t;

    typedef enum
    {
        SM2_REV_SYNC_ACTION_NONE = 0,
        SM2_REV_SYNC_ACTION_DELTA = 1,
        SM2_REV_SYNC_ACTION_FULL = 2
    } sm2_rev_sync_action_t;

    typedef struct
    {
        sm2_rev_sync_action_t action;
        bool compatible_params;
        uint64_t from_version;
        uint64_t to_version;
        bool full_snapshot;
        size_t candidate_bucket_count;
        size_t candidate_buckets[SM2_REV_SYNC_BUCKET_CANDIDATE_MAX];
    } sm2_rev_sync_plan_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t sync_epoch;
        uint64_t from_version;
        uint64_t to_version;
        uint64_t generated_ts;
        uint64_t nonce;
        bool full_snapshot;

        uint8_t filter_param_hash[SM2_REV_SYNC_DIGEST_LEN];
        uint8_t payload_digest[SM2_REV_SYNC_DIGEST_LEN];

        sm2_crl_delta_item_t *items;
        size_t item_count;
        size_t item_capacity;
        bool has_more;
        uint64_t next_from_version;

        uint8_t signature[SM2_REV_SYNC_MAX_SIG_LEN];
        size_t signature_len;
    } sm2_rev_sync_packet_t;

    typedef sm2_ic_error_t (*sm2_rev_sync_sign_fn)(void *user_ctx,
        const uint8_t *data, size_t data_len, uint8_t *signature,
        size_t *signature_len);

    typedef sm2_ic_error_t (*sm2_rev_sync_verify_fn)(void *user_ctx,
        const uint8_t *data, size_t data_len, const uint8_t *signature,
        size_t signature_len);

    typedef struct
    {
        sm2_cuckoo_filter_t filter;
        uint64_t *revoked_serials;
        size_t revoked_count;
        size_t revoked_capacity;

        sm2_ocsp_cache_entry_t *ocsp_cache;
        size_t ocsp_cache_capacity;
        sm2_ocsp_client_cfg_t ocsp_cfg;

        uint64_t crl_version;
        uint64_t filter_ttl_sec;
        uint64_t filter_expire_at;
        bool online_mode;

        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t sync_epoch;
        uint64_t last_sync_ts;
        uint64_t last_sync_nonce;
        uint8_t filter_param_hash[SM2_REV_SYNC_DIGEST_LEN];

        sm2_rev_sync_log_entry_t *sync_log;
        size_t sync_log_count;
        size_t sync_log_capacity;
        size_t sync_log_head;
        size_t sync_log_window;
        size_t sync_max_items_per_packet;
        uint64_t sync_min_export_interval_sec;
    } sm2_revocation_ctx_t;

    sm2_ic_error_t sm2_revocation_init(sm2_revocation_ctx_t *ctx,
        size_t expected_revoked_items, uint64_t filter_ttl_sec,
        uint64_t now_ts);
    void sm2_revocation_cleanup(sm2_revocation_ctx_t *ctx);

    sm2_ic_error_t sm2_revocation_set_online(
        sm2_revocation_ctx_t *ctx, bool online_mode);
    sm2_ic_error_t sm2_revocation_config_ocsp(
        sm2_revocation_ctx_t *ctx, const sm2_ocsp_client_cfg_t *cfg);
    sm2_ic_error_t sm2_revocation_config_local_filter(sm2_revocation_ctx_t *ctx,
        uint8_t fp_bits, size_t bucket_size, size_t max_kicks);

    sm2_ic_error_t sm2_revocation_apply_crl_delta(sm2_revocation_ctx_t *ctx,
        const sm2_crl_delta_t *delta, uint64_t now_ts);

    sm2_ic_error_t sm2_revocation_query(sm2_revocation_ctx_t *ctx,
        uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
        sm2_rev_source_t *source);

    size_t sm2_revocation_local_count(const sm2_revocation_ctx_t *ctx);
    uint64_t sm2_revocation_crl_version(const sm2_revocation_ctx_t *ctx);

    sm2_ic_error_t sm2_revocation_set_sync_identity(sm2_revocation_ctx_t *ctx,
        const uint8_t *node_id, size_t node_id_len, uint64_t sync_epoch,
        size_t sync_log_window);
    sm2_ic_error_t sm2_revocation_config_sync_limits(sm2_revocation_ctx_t *ctx,
        size_t max_items_per_packet, uint64_t min_export_interval_sec);

    sm2_ic_error_t sm2_revocation_sync_hello(const sm2_revocation_ctx_t *ctx,
        uint64_t now_ts, sm2_rev_sync_hello_t *hello);

    sm2_ic_error_t sm2_revocation_sync_plan(const sm2_revocation_ctx_t *ctx,
        const sm2_rev_sync_hello_t *peer_hello, sm2_rev_sync_plan_t *plan);

    sm2_ic_error_t sm2_revocation_sync_export_delta(sm2_revocation_ctx_t *ctx,
        const sm2_rev_sync_plan_t *plan, uint64_t now_ts, uint64_t nonce,
        sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
        sm2_rev_sync_packet_t *packet);

    sm2_ic_error_t sm2_revocation_sync_apply(sm2_revocation_ctx_t *ctx,
        const sm2_rev_sync_packet_t *packet, uint64_t now_ts,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

    void sm2_revocation_sync_packet_cleanup(sm2_rev_sync_packet_t *packet);

#ifdef __cplusplus
}
#endif

#endif /* SM2_REVOCATION_H */
