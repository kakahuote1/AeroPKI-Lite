/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_implicit_cert.h
 * @brief Lightweight SM2 ECQV Implicit Certificate Implementation.
 * @details Core definitions for ECQV data structures, error codes, and crypto
 * operations optimized for resource-constrained aviation systems.
 * @version 1.2.0
 * @copyright Apache-2.0
 */

#ifndef SM2_IMPLICIT_CERT_H
#define SM2_IMPLICIT_CERT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ========================================== */
    /* Constants & Macros */
    /* ========================================== */

#define SM2_KEY_LEN 32
#define SM2_COMPRESSED_KEY_LEN 33
#define SM3_DIGEST_LENGTH 32

/* Key Usage (Reference: X.509 KeyUsage) */
#define SM2_KU_DIGITAL_SIGNATURE 0x01
#define SM2_KU_NON_REPUDIATION 0x02
#define SM2_KU_KEY_ENCIPHERMENT 0x04
#define SM2_KU_DATA_ENCIPHERMENT 0x08
#define SM2_KU_KEY_AGREEMENT 0x10

#define SM2_CERT_TYPE_IMPLICIT 0x01

/* Optional certificate field mask bits */
#define SM2_IC_FIELD_SUBJECT_ID 0x0001
#define SM2_IC_FIELD_ISSUER_ID 0x0002
#define SM2_IC_FIELD_VALID_FROM 0x0004
#define SM2_IC_FIELD_VALID_DURATION 0x0008
#define SM2_IC_FIELD_KEY_USAGE 0x0010
#define SM2_IC_FIELD_MASK_ALL                                                  \
    (SM2_IC_FIELD_SUBJECT_ID | SM2_IC_FIELD_ISSUER_ID                          \
        | SM2_IC_FIELD_VALID_FROM | SM2_IC_FIELD_VALID_DURATION                \
        | SM2_IC_FIELD_KEY_USAGE)

    /* ========================================== */
    /* Data Structures */
    /* ========================================== */

    /**
     * @brief Represents an SM2 Elliptic Curve point (Affine coordinates).
     */
    typedef struct
    {
        uint8_t x[SM2_KEY_LEN];
        uint8_t y[SM2_KEY_LEN];
    } sm2_ec_point_t;

    /**
     * @brief Represents an SM2 Private Key (Big-endian integer).
     */
    typedef struct
    {
        uint8_t d[SM2_KEY_LEN];
    } sm2_private_key_t;

    /**
     * @brief The Implicit Certificate structure.
     * @note Optimized for storage. Contains the public key reconstruction data
     * (V) instead of the full public key or explicit signature.
     */
    typedef struct
    {
        uint8_t type; /* /< Certificate Type */
        uint64_t serial_number; /* /< Unique Serial Number */
        uint16_t field_mask; /* /< Optional fields presence bitmap */

        uint8_t subject_id[256]; /* /< Subject Identifier */
        size_t subject_id_len;

        uint8_t issuer_id[256]; /* /< Issuer Identifier */
        size_t issuer_id_len;

        uint64_t valid_from; /* /< Validity Start (Unix Timestamp) */
        uint64_t valid_duration; /* /< Validity Duration (Seconds) */

        uint8_t key_usage; /* /< Key Usage Bitmap */

        /** * @brief Public Key Reconstruction Data (Point V).
         * @note stored in compressed format (02/03 + X) to save space.
         */
        uint8_t public_recon_key[SM2_COMPRESSED_KEY_LEN];
    } sm2_implicit_cert_t;

    /**
     * @brief Container for the result of a certificate issuance.
     */
    typedef struct
    {
        sm2_implicit_cert_t cert; /* /< The generated certificate */
        uint8_t private_recon_value[SM2_KEY_LEN]; /* /< Private key */
        /* /< reconstruction data (s) */
    } sm2_ic_cert_result_t;

    /**
     * @brief Certificate Request structure from the device.
     */
    typedef struct
    {
        uint8_t subject_id[256];
        size_t subject_id_len;
        uint8_t key_usage;
        sm2_ec_point_t temp_public_key; /* /< Ephemeral Public Key (R_U) */
    } sm2_ic_cert_request_t;

    /**
     * @brief Certificate issuance context.
     * @note Holds per-request/per-service issuance policy to avoid mutable
     * globals.
     */
    typedef struct
    {
        uint16_t field_mask; /* /< Optional fields template for issued certs */
    } sm2_ic_issue_ctx_t;

    /**
     * @brief Error Codes.
     */
    typedef enum
    {
        SM2_IC_SUCCESS = 0,
        SM2_IC_ERR_PARAM = -1,
        SM2_IC_ERR_MEMORY = -2,
        SM2_IC_ERR_CRYPTO = -3,
        SM2_IC_ERR_VERIFY = -4,
        SM2_IC_ERR_CBOR = -5
    } sm2_ic_error_t;

    /* ========================================== */
    /* Public API */
    /* ========================================== */

    /* Cryptographic Primitives Abstraction */
    sm2_ic_error_t sm2_ic_generate_random(uint8_t *buf, size_t len);
    sm2_ic_error_t sm2_ic_sm3_hash(
        const uint8_t *input, size_t input_len, uint8_t *output);
    sm2_ic_error_t sm2_ic_sm2_point_mult(sm2_ec_point_t *point,
        const uint8_t *scalar, size_t scalar_len,
        const sm2_ec_point_t *base_point);

    /* Certificate issuance policy control */
    void sm2_ic_issue_ctx_init(sm2_ic_issue_ctx_t *ctx);
    sm2_ic_error_t sm2_ic_issue_ctx_set_field_mask(
        sm2_ic_issue_ctx_t *ctx, uint16_t field_mask);
    uint16_t sm2_ic_issue_ctx_get_field_mask(const sm2_ic_issue_ctx_t *ctx);

    /* ECQV Core Protocol */
    sm2_ic_error_t sm2_ic_create_cert_request(sm2_ic_cert_request_t *request,
        const uint8_t *subject_id, size_t subject_id_len, uint8_t key_usage,
        sm2_private_key_t *temp_private_key);
    sm2_ic_error_t sm2_ic_ca_generate_cert_with_ctx(
        sm2_ic_cert_result_t *result, const sm2_ic_cert_request_t *request,
        const uint8_t *issuer_id, size_t issuer_id_len,
        const sm2_private_key_t *ca_private_key,
        const sm2_ec_point_t *ca_public_key,
        const sm2_ic_issue_ctx_t *issue_ctx);
    sm2_ic_error_t sm2_ic_ca_generate_cert(sm2_ic_cert_result_t *result,
        const sm2_ic_cert_request_t *request, const uint8_t *issuer_id,
        size_t issuer_id_len, const sm2_private_key_t *ca_private_key,
        const sm2_ec_point_t *ca_public_key);
    sm2_ic_error_t sm2_ic_reconstruct_keys(sm2_private_key_t *private_key,
        sm2_ec_point_t *public_key, const sm2_ic_cert_result_t *cert_result,
        const sm2_private_key_t *temp_private_key,
        const sm2_ec_point_t *ca_public_key);
    sm2_ic_error_t sm2_ic_verify_cert(const sm2_implicit_cert_t *cert,
        const sm2_ec_point_t *public_key, const sm2_ec_point_t *ca_public_key);

    /* Serialization (CBOR) */
    sm2_ic_error_t sm2_ic_cbor_encode_cert(
        uint8_t *output, size_t *output_len, const sm2_implicit_cert_t *cert);
    sm2_ic_error_t sm2_ic_cbor_decode_cert(
        sm2_implicit_cert_t *cert, const uint8_t *input, size_t input_len);

#ifdef __cplusplus
}
#endif

#endif /* SM2_IMPLICIT_CERT_H */
