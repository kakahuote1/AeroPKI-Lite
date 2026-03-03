/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_crypto.c
 * @brief Phase4 crypto component wrappers and unified error mapping.
 */

#include "sm2_crypto.h"
#include "sm2_implicit_cert.h"

sm2_pki_error_t sm2_pki_error_from_ic(sm2_ic_error_t err)
{
    switch (err)
    {
        case SM2_IC_SUCCESS:
            return SM2_PKI_SUCCESS;
        case SM2_IC_ERR_PARAM:
        case SM2_IC_ERR_CBOR:
            return SM2_PKI_ERR_PARAM;
        case SM2_IC_ERR_MEMORY:
            return SM2_PKI_ERR_MEMORY;
        case SM2_IC_ERR_VERIFY:
            return SM2_PKI_ERR_VERIFY;
        case SM2_IC_ERR_CRYPTO:
        default:
            return SM2_PKI_ERR_CRYPTO;
    }
}

sm2_pki_error_t sm2_pki_random(uint8_t *buf, size_t len)
{
    return sm2_pki_error_from_ic(sm2_ic_generate_random(buf, len));
}

sm2_pki_error_t sm2_pki_sm3_hash(
    const uint8_t *input, size_t input_len, uint8_t output[SM3_DIGEST_LENGTH])
{
    return sm2_pki_error_from_ic(sm2_ic_sm3_hash(input, input_len, output));
}

sm2_pki_error_t sm2_crypto_sign(const sm2_private_key_t *private_key,
    const uint8_t *message, size_t message_len, sm2_auth_signature_t *signature)
{
    return sm2_pki_error_from_ic(
        sm2_auth_sign(private_key, message, message_len, signature));
}

sm2_pki_error_t sm2_crypto_verify(const sm2_ec_point_t *public_key,
    const uint8_t *message, size_t message_len,
    const sm2_auth_signature_t *signature)
{
    return sm2_pki_error_from_ic(
        sm2_auth_verify_signature(public_key, message, message_len, signature));
}

sm2_pki_error_t sm2_pki_sm4_encrypt(const uint8_t key[16], const uint8_t iv[16],
    const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext,
    size_t *ciphertext_len)
{
    return sm2_pki_error_from_ic(sm2_auth_sm4_encrypt(
        key, iv, plaintext, plaintext_len, ciphertext, ciphertext_len));
}

sm2_pki_error_t sm2_pki_sm4_decrypt(const uint8_t key[16], const uint8_t iv[16],
    const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext,
    size_t *plaintext_len)
{
    return sm2_pki_error_from_ic(sm2_auth_sm4_decrypt(
        key, iv, ciphertext, ciphertext_len, plaintext, plaintext_len));
}
