/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2ECQV_ECQV_H
#define SM2ECQV_ECQV_H

#include "../sm2_implicit_cert.h"

/* New namespace aliases (OpenSSL-style uppercase prefix). */
typedef sm2_ec_point_t SM2_ECQV_POINT;
typedef sm2_private_key_t SM2_ECQV_PRIVATE_KEY;
typedef sm2_implicit_cert_t SM2_ECQV_CERT;
typedef sm2_ic_cert_result_t SM2_ECQV_CERT_RESULT;
typedef sm2_ic_cert_request_t SM2_ECQV_CERT_REQUEST;
typedef sm2_ic_issue_ctx_t SM2_ECQV_ISSUE_CTX;
typedef sm2_ic_error_t SM2_ECQV_ERROR;

#define SM2_ECQV_SUCCESS SM2_IC_SUCCESS

#define SM2_ECQV_generate_random sm2_ic_generate_random
#define SM2_ECQV_sm3_hash sm2_ic_sm3_hash
#define SM2_ECQV_sm2_point_mult sm2_ic_sm2_point_mult

#define SM2_ECQV_issue_ctx_init sm2_ic_issue_ctx_init
#define SM2_ECQV_issue_ctx_set_field_mask sm2_ic_issue_ctx_set_field_mask
#define SM2_ECQV_issue_ctx_get_field_mask sm2_ic_issue_ctx_get_field_mask

#define SM2_ECQV_create_cert_request sm2_ic_create_cert_request
#define SM2_ECQV_ca_generate_cert_with_ctx sm2_ic_ca_generate_cert_with_ctx
#define SM2_ECQV_ca_generate_cert sm2_ic_ca_generate_cert
#define SM2_ECQV_reconstruct_keys sm2_ic_reconstruct_keys
#define SM2_ECQV_verify_cert sm2_ic_verify_cert

#define SM2_ECQV_cbor_encode_cert sm2_ic_cbor_encode_cert
#define SM2_ECQV_cbor_decode_cert sm2_ic_cbor_decode_cert

#endif
