/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_crypto.h
 * @brief Phase4 crypto component wrappers and unified error mapping.
 */

#ifndef SM2_CRYPTO_H
#define SM2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "sm2_auth.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        SM2_PKI_SUCCESS = 0,
        SM2_PKI_ERR_PARAM = -100,
        SM2_PKI_ERR_MEMORY = -101,
        SM2_PKI_ERR_CRYPTO = -102,
        SM2_PKI_ERR_VERIFY = -103,
        SM2_PKI_ERR_STATE = -104,
        SM2_PKI_ERR_NOT_FOUND = -105,
        SM2_PKI_ERR_CONFLICT = -106
    } sm2_pki_error_t;

    sm2_pki_error_t sm2_pki_error_from_ic(sm2_ic_error_t err);

    sm2_pki_error_t sm2_pki_random(uint8_t *buf, size_t len);
    sm2_pki_error_t sm2_pki_sm3_hash(const uint8_t *input, size_t input_len,
        uint8_t output[SM3_DIGEST_LENGTH]);

    sm2_pki_error_t sm2_crypto_sign(const sm2_private_key_t *private_key,
        const uint8_t *message, size_t message_len,
        sm2_auth_signature_t *signature);

    sm2_pki_error_t sm2_crypto_verify(const sm2_ec_point_t *public_key,
        const uint8_t *message, size_t message_len,
        const sm2_auth_signature_t *signature);

    sm2_pki_error_t sm2_pki_sm4_encrypt(const uint8_t key[16],
        const uint8_t iv[16], const uint8_t *plaintext, size_t plaintext_len,
        uint8_t *ciphertext, size_t *ciphertext_len);

    sm2_pki_error_t sm2_pki_sm4_decrypt(const uint8_t key[16],
        const uint8_t iv[16], const uint8_t *ciphertext, size_t ciphertext_len,
        uint8_t *plaintext, size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* SM2_CRYPTO_H */
