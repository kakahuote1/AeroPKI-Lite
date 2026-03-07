/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2ECQV_AUTH_H
#define SM2ECQV_AUTH_H

#include "../sm2_auth.h"

typedef sm2_auth_signature_t SM2_AUTH_SIGNATURE;
typedef sm2_auth_request_t SM2_AUTH_REQUEST;
typedef sm2_auth_verify_item_t SM2_AUTH_VERIFY_ITEM;
typedef sm2_auth_trust_store_t SM2_AUTH_TRUST_STORE;
typedef sm2_auth_precompute_pool_t SM2_AUTH_PRECOMPUTE_POOL;
typedef sm2_auth_revocation_query_fn SM2_AUTH_REVOCATION_QUERY_FN;
typedef sm2_auth_revocation_policy_t SM2_AUTH_REVOCATION_POLICY;
typedef sm2_auth_aead_mode_t SM2_AUTH_AEAD_MODE;
typedef sm2_ic_error_t SM2_AUTH_ERROR;

#define SM2_AUTH_SUCCESS SM2_IC_SUCCESS

#define SM2_AUTH_sign sm2_auth_sign
#define SM2_AUTH_verify_signature sm2_auth_verify_signature
#define SM2_AUTH_batch_verify sm2_auth_batch_verify
#define SM2_AUTH_verify_cert_with_store sm2_auth_verify_cert_with_store
#define SM2_AUTH_authenticate_request sm2_auth_authenticate_request
#define SM2_AUTH_trust_store_init sm2_auth_trust_store_init
#define SM2_AUTH_trust_store_add_ca sm2_auth_trust_store_add_ca
#define SM2_AUTH_precompute_pool_init sm2_auth_precompute_pool_init
#define SM2_AUTH_precompute_pool_fill sm2_auth_precompute_pool_fill
#define SM2_AUTH_precompute_pool_available sm2_auth_precompute_pool_available
#define SM2_AUTH_precompute_pool_cleanup sm2_auth_precompute_pool_cleanup
#define SM2_AUTH_sign_with_pool sm2_auth_sign_with_pool
#define SM2_AUTH_mutual_auth_and_key_agreement                                 \
    sm2_auth_mutual_auth_and_key_agreement
#define SM2_AUTH_mutual_auth_and_key_agreement_v2                              \
    sm2_auth_mutual_auth_and_key_agreement_v2
#define SM2_AUTH_generate_ephemeral_keypair sm2_auth_generate_ephemeral_keypair
#define SM2_AUTH_derive_session_key sm2_auth_derive_session_key
#define SM2_AUTH_derive_session_key_ephemeral                                  \
    sm2_auth_derive_session_key_ephemeral
#define SM2_AUTH_sm4_encrypt sm2_auth_sm4_encrypt
#define SM2_AUTH_sm4_decrypt sm2_auth_sm4_decrypt
#define SM2_AUTH_sm4_aead_encrypt sm2_auth_sm4_aead_encrypt
#define SM2_AUTH_sm4_aead_decrypt sm2_auth_sm4_aead_decrypt

#endif
