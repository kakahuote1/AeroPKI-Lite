/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

static int test_cbor_read_head(const uint8_t *buf, size_t len, size_t *offset,
    uint8_t expected_major, uint64_t *val)
{
    if (!buf || !offset || !val || *offset >= len)
        return 0;
    uint8_t byte = buf[*offset];
    uint8_t major = byte >> 5;
    uint8_t info = byte & 0x1F;
    (*offset)++;
    if (major != expected_major)
        return 0;

    if (info < 24)
    {
        *val = info;
        return 1;
    }
    if (info == 24)
    {
        if (*offset + 1 > len)
            return 0;
        *val = buf[(*offset)++];
        return 1;
    }
    if (info == 25)
    {
        if (*offset + 2 > len)
            return 0;
        *val = ((uint64_t)buf[*offset] << 8) | buf[*offset + 1];
        (*offset) += 2;
        return 1;
    }
    if (info == 26)
    {
        if (*offset + 4 > len)
            return 0;
        *val = 0;
        for (int i = 0; i < 4; i++)
            *val = (*val << 8) | buf[(*offset)++];
        return 1;
    }
    if (info == 27)
    {
        if (*offset + 8 > len)
            return 0;
        *val = 0;
        for (int i = 0; i < 8; i++)
            *val = (*val << 8) | buf[(*offset)++];
        return 1;
    }
    return 0;
}

void test_setup_ca()
{
    TEST_ASSERT(sm2_ic_generate_random(g_ca_priv.d, 32) == SM2_IC_SUCCESS,
        "CA KeyGen Failed");
    TEST_ASSERT(sm2_ic_sm2_point_mult(&g_ca_pub, g_ca_priv.d, 32, NULL)
            == SM2_IC_SUCCESS,
        "CA PubKey Failed");
    g_ca_initialized = 1;
    TEST_PASS();
}

static void test_full_lifecycle()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    uint8_t sub_id[] = "UAV_TEST_001";
    uint8_t iss_id[] = "ROOT_CA";
    uint8_t usage = SM2_KU_DIGITAL_SIGNATURE;

    TEST_ASSERT(sm2_ic_create_cert_request(
                    &req, sub_id, strlen((char *)sub_id), usage, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req Create");
    TEST_ASSERT(sm2_ic_ca_generate_cert(&res, &req, iss_id,
                    strlen((char *)iss_id), &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Cert Issue");
    TEST_ASSERT(
        res.cert.field_mask == SM2_IC_FIELD_MASK_ALL, "Default Field Mask");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Key Recon");
    TEST_ASSERT(
        sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) == SM2_IC_SUCCESS,
        "Cert Verify");

    TEST_PASS();
}

static void test_tampered_cert()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    sm2_ic_create_cert_request(
        &req, (uint8_t *)"DEV", 3, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);
    sm2_ic_ca_generate_cert(
        &res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub);
    sm2_ic_reconstruct_keys(&user_priv, &user_pub, &res, &temp_priv, &g_ca_pub);

    res.cert.serial_number++;
    TEST_ASSERT(
        sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) != SM2_IC_SUCCESS,
        "Serial Tamper Detected");

    res.cert.serial_number--;
    res.cert.public_recon_key[5] ^= 0xFF;
    TEST_ASSERT(
        sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) != SM2_IC_SUCCESS,
        "V-Key Tamper Detected");

    TEST_PASS();
}

static void test_cbor_robustness()
{
    sm2_implicit_cert_t cert;
    memset(&cert, 0, sizeof(cert));
    cert.type = SM2_CERT_TYPE_IMPLICIT;
    cert.serial_number = 1;
    cert.field_mask = 0;
    memset(cert.public_recon_key, 0xAB, SM2_COMPRESSED_KEY_LEN);

    uint8_t buf[1024];
    size_t len = sizeof(buf);

    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &len, &cert) == SM2_IC_SUCCESS,
        "Encode OK");

    len = 5;
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &len, &cert) == SM2_IC_ERR_MEMORY,
        "Buffer Overflow Protection");

    /* malformed #1: truncated CBOR */
    for (size_t i = 1; i < 16 && i < len; i++)
    {
        sm2_implicit_cert_t out;
        TEST_ASSERT(sm2_ic_cbor_decode_cert(&out, buf, i) == SM2_IC_ERR_CBOR,
            "Truncated Must Fail");
    }

    /* malformed #2: type mismatch for first cert field (type should be unsigned
     */
    /* int) */
    uint8_t bad_type[1024];
    memcpy(bad_type, buf, len);
    size_t off = 0;
    uint64_t arr_len = 0;
    TEST_ASSERT(test_cbor_read_head(bad_type, len, &off, 4, &arr_len) == 1,
        "Read Array Head");
    TEST_ASSERT(off < len, "Type Field Present");
    bad_type[off] = 0x41; /* major type 2 (byte string, len=1) */
    {
        sm2_implicit_cert_t out;
        TEST_ASSERT(
            sm2_ic_cbor_decode_cert(&out, bad_type, len) == SM2_IC_ERR_CBOR,
            "Type Mismatch Must Fail");
    }

    /* malformed #3: subject_id claimed length > 256 */
    uint8_t oversize[512];
    size_t o = 0;
    oversize[o++] = 0x85; /* array(5): type, serial, mask, subject, V */
    oversize[o++] = 0x01; /* type */
    oversize[o++] = 0x01; /* serial */
    oversize[o++] = 0x01; /* field_mask=SM2_IC_FIELD_SUBJECT_ID */
    oversize[o++] = 0x59; /* bytes with 2-byte length */
    oversize[o++] = 0x01;
    oversize[o++] = 0x01; /* len=257 */
    memset(oversize + o, 0x11, 257);
    o += 257;
    oversize[o++] = 0x58; /* bytes with 1-byte length */
    oversize[o++] = 0x21; /* len=33 */
    memset(oversize + o, 0x22, 33);
    o += 33;
    {
        sm2_implicit_cert_t out;
        TEST_ASSERT(
            sm2_ic_cbor_decode_cert(&out, oversize, o) == SM2_IC_ERR_CBOR,
            "Oversize Subject Must Fail");
    }

    TEST_PASS();
}

static void test_field_mask_template()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_issue_ctx_t issue_ctx;
    sm2_ic_issue_ctx_init(&issue_ctx);
    const uint16_t custom_mask
        = SM2_IC_FIELD_SUBJECT_ID | SM2_IC_FIELD_KEY_USAGE;
    TEST_ASSERT(sm2_ic_issue_ctx_set_field_mask(&issue_ctx, custom_mask)
            == SM2_IC_SUCCESS,
        "Set Custom Mask");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    uint8_t buf[512];
    size_t len = sizeof(buf);

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"MASK_CASE", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req Create");
    TEST_ASSERT(sm2_ic_ca_generate_cert_with_ctx(&res, &req,
                    (uint8_t *)"CA_MASK", 7, &g_ca_priv, &g_ca_pub, &issue_ctx)
            == SM2_IC_SUCCESS,
        "Cert Issue");
    TEST_ASSERT(res.cert.field_mask == custom_mask, "Mask Applied");
    TEST_ASSERT(res.cert.subject_id_len > 0, "Subject Kept");
    TEST_ASSERT(res.cert.issuer_id_len == 0, "Issuer Removed");
    TEST_ASSERT(res.cert.valid_from == 0, "ValidFrom Removed");
    TEST_ASSERT(res.cert.valid_duration == 0, "Duration Removed");
    TEST_ASSERT(res.cert.key_usage == SM2_KU_DIGITAL_SIGNATURE, "Usage Kept");

    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &len, &res.cert) == SM2_IC_SUCCESS,
        "CBOR Encode");
    sm2_implicit_cert_t decoded;
    TEST_ASSERT(sm2_ic_cbor_decode_cert(&decoded, buf, len) == SM2_IC_SUCCESS,
        "CBOR Decode");
    TEST_ASSERT(decoded.field_mask == custom_mask, "Mask Decode");
    TEST_ASSERT(decoded.issuer_id_len == 0, "Issuer Decode Removed");
    TEST_ASSERT(decoded.valid_from == 0, "ValidFrom Decode Removed");

    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Key Recon");
    TEST_ASSERT(
        sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) == SM2_IC_SUCCESS,
        "Cert Verify");

    TEST_PASS();
}

static void test_cert_size_reduction_by_mask()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_issue_ctx_t issue_ctx;
    sm2_ic_issue_ctx_init(&issue_ctx);
    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t full_cert;
    sm2_ic_cert_result_t slim_cert;
    uint8_t buf[1024];
    size_t full_len = sizeof(buf);
    size_t slim_len = sizeof(buf);

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"SIZE_CASE", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req Create");

    TEST_ASSERT(
        sm2_ic_issue_ctx_set_field_mask(&issue_ctx, SM2_IC_FIELD_MASK_ALL)
            == SM2_IC_SUCCESS,
        "Set Full Mask");
    TEST_ASSERT(sm2_ic_ca_generate_cert_with_ctx(&full_cert, &req,
                    (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub, &issue_ctx)
            == SM2_IC_SUCCESS,
        "Issue Full");
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &full_len, &full_cert.cert)
            == SM2_IC_SUCCESS,
        "Encode Full");

    TEST_ASSERT(
        sm2_ic_issue_ctx_set_field_mask(&issue_ctx, SM2_IC_FIELD_SUBJECT_ID)
            == SM2_IC_SUCCESS,
        "Set Slim Mask");
    TEST_ASSERT(sm2_ic_ca_generate_cert_with_ctx(&slim_cert, &req,
                    (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub, &issue_ctx)
            == SM2_IC_SUCCESS,
        "Issue Slim");
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &slim_len, &slim_cert.cert)
            == SM2_IC_SUCCESS,
        "Encode Slim");

    printf("   [SIZE] full=%zu bytes, slim=%zu bytes\n", full_len, slim_len);
    TEST_ASSERT(slim_len < full_len, "Slim Must Be Smaller");

    TEST_PASS();
}

static void test_performance()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_ic_create_cert_request(
        &req, (uint8_t *)"PERF", 4, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);

    int iterations = 1000;
    clock_t start = clock();

    for (int i = 0; i < iterations; i++)
    {
        sm2_ic_ca_generate_cert(
            &res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub);
    }

    double avg_time
        = ((double)(clock() - start)) / CLOCKS_PER_SEC * 1000.0 / iterations;
    printf(
        "   [PERF] Avg Issuance Time: %.3f ms (N=%d)\n", avg_time, iterations);
    TEST_PASS();
}

static void test_chain_success_rate()
{
    if (!g_ca_initialized)
        test_setup_ca();

    const int rounds = 2000;
    int success = 0;

    for (int i = 0; i < rounds; i++)
    {
        sm2_ic_cert_request_t req;
        sm2_private_key_t temp_priv;
        sm2_ic_cert_result_t res;
        sm2_private_key_t user_priv;
        sm2_ec_point_t user_pub;

        if (sm2_ic_create_cert_request(&req, (uint8_t *)"RATE_CASE", 9,
                SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            != SM2_IC_SUCCESS)
            continue;
        if (sm2_ic_ca_generate_cert(
                &res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            != SM2_IC_SUCCESS)
            continue;
        if (sm2_ic_reconstruct_keys(
                &user_priv, &user_pub, &res, &temp_priv, &g_ca_pub)
            != SM2_IC_SUCCESS)
            continue;
        if (sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub)
            != SM2_IC_SUCCESS)
            continue;
        success++;
    }

    double ratio = (double)success / (double)rounds;
    printf(
        "   [RATE] success=%d/%d (%.4f%%)\n", success, rounds, ratio * 100.0);
    TEST_ASSERT(ratio >= 0.999, "Chain Success Rate < 99.9%");
    TEST_PASS();
}

void run_test_ecqv_suite(void)
{
    RUN_TEST(test_setup_ca);
    RUN_TEST(test_full_lifecycle);
    RUN_TEST(test_tampered_cert);
    RUN_TEST(test_cbor_robustness);
    RUN_TEST(test_field_mask_template);
    RUN_TEST(test_cert_size_reduction_by_mask);
    RUN_TEST(test_performance);
    RUN_TEST(test_chain_success_rate);
}
