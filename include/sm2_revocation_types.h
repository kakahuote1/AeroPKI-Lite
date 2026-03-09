/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_revocation_types.h
 * @brief Thin shared revocation types for public cross-module APIs.
 */

#ifndef SM2_REVOCATION_TYPES_H
#define SM2_REVOCATION_TYPES_H

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
        SM2_REV_SOURCE_MERKLE_NODE = 1,
        SM2_REV_SOURCE_LOCAL_STATE = 2
    } sm2_rev_source_t;

    typedef struct sm2_rev_ctx_st sm2_rev_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* SM2_REVOCATION_TYPES_H */
