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

#ifdef __cplusplus
}
#endif

#endif /* SM2_REVOCATION_H */
