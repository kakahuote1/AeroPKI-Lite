/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2ECQV_CLIENT_H
#define SM2ECQV_CLIENT_H

#include "../sm2_pki_client.h"

typedef sm2_pki_client_ctx_t SM2_PKI_CLIENT_CTX;
typedef sm2_pki_error_t SM2_PKI_CLIENT_ERROR;

#define SM2_PKI_CLIENT_init sm2_pki_client_init
#define SM2_PKI_CLIENT_cleanup sm2_pki_client_cleanup
#define SM2_PKI_CLIENT_add_trusted_ca sm2_pki_client_add_trusted_ca
#define SM2_PKI_CLIENT_import_cert sm2_pki_client_import_cert
#define SM2_PKI_CLIENT_enable_precompute sm2_pki_client_enable_precompute
#define SM2_PKI_CLIENT_disable_precompute sm2_pki_client_disable_precompute
#define SM2_PKI_sign sm2_pki_sign
#define SM2_PKI_verify sm2_pki_verify
#define SM2_PKI_batch_verify sm2_pki_batch_verify
#define SM2_PKI_key_agreement sm2_pki_key_agreement
#define SM2_PKI_encrypt sm2_pki_encrypt
#define SM2_PKI_decrypt sm2_pki_decrypt

#endif
