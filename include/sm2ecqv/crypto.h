/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2ECQV_CRYPTO_H
#define SM2ECQV_CRYPTO_H

#include "../sm2_crypto.h"

typedef sm2_pki_error_t SM2_CRYPTO_ERROR;

#define SM2_CRYPTO_SUCCESS SM2_PKI_SUCCESS

#define SM2_CRYPTO_sm4_encrypt sm2_pki_sm4_encrypt
#define SM2_CRYPTO_sm4_decrypt sm2_pki_sm4_decrypt
#define SM2_CRYPTO_error_from_ic sm2_pki_error_from_ic

#endif
