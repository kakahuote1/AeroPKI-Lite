/* SPDX-License-Identifier: Apache-2.0 */

#ifndef TEST_REVOKE_HELPERS_H
#define TEST_REVOKE_HELPERS_H

#include "test_common.h"

typedef struct
{
    sm2_rev_status_t status;
    uint64_t last_serial;
    int call_count;
} mock_merkle_query_state_t;

typedef struct
{
    uint8_t expect_tag;
    bool called;
} mock_redirect_verify_ctx_t;

typedef struct
{
    const sm2_private_key_t *ca_priv;
    const sm2_ec_point_t *ca_pub;
} revoke_merkle_sig_ctx_t;

sm2_ic_error_t mock_redirect_verify(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len);
sm2_ic_error_t revoke_merkle_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len);
sm2_ic_error_t revoke_merkle_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len);
sm2_ic_error_t mock_merkle_query(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status);

#endif
