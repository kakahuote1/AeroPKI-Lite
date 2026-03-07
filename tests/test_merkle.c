/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file test_merkle.c
 * @brief Tests for Merkle tree (member/non-member proofs, CBOR codec,
 *        root signature, multiproof, epoch, hot-patch, k-anonymity).
 */

#include "test_common.h"
typedef struct
{
    const sm2_private_key_t *ca_priv;
    const sm2_ec_point_t *ca_pub;
} merkle_ca_sig_ctx_t;

static sm2_ic_error_t merkle_ca_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    merkle_ca_sig_ctx_t *ctx = (merkle_ca_sig_ctx_t *)user_ctx;
    if (!ctx->ca_priv)
        return SM2_IC_ERR_PARAM;

    sm2_auth_signature_t sig;
    sm2_ic_error_t ret = sm2_auth_sign(ctx->ca_priv, data, data_len, &sig);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*signature_len < sig.der_len)
        return SM2_IC_ERR_MEMORY;

    memcpy(signature, sig.der, sig.der_len);
    *signature_len = sig.der_len;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t merkle_ca_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    if (!user_ctx || !data || !signature)
        return SM2_IC_ERR_PARAM;

    merkle_ca_sig_ctx_t *ctx = (merkle_ca_sig_ctx_t *)user_ctx;
    if (!ctx->ca_pub)
        return SM2_IC_ERR_PARAM;
    if (signature_len == 0 || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
        return SM2_IC_ERR_VERIFY;

    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;

    return sm2_auth_verify_signature(ctx->ca_pub, data, data_len, &sig);
}
static void test_revocation_merkle_member_and_non_member()
{
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[] = { 500, 100, 300, 300, 900 };
    TEST_ASSERT(sm2_revocation_merkle_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 77)
            == SM2_IC_SUCCESS,
        "Merkle Build");
    TEST_ASSERT(tree.root_version == 77, "Merkle Root Version");
    TEST_ASSERT(tree.leaf_count == 4, "Merkle Dedup Leaf Count");

    sm2_rev_merkle_membership_proof_t mp;
    TEST_ASSERT(
        sm2_revocation_merkle_prove_member(&tree, 300, &mp) == SM2_IC_SUCCESS,
        "Member Proof Build");
    TEST_ASSERT(sm2_revocation_merkle_verify_member(tree.root_hash, &mp)
            == SM2_IC_SUCCESS,
        "Member Proof Verify");

    sm2_rev_merkle_non_membership_proof_t nmp;
    TEST_ASSERT(sm2_revocation_merkle_prove_non_member(&tree, 301, &nmp)
            == SM2_IC_SUCCESS,
        "NonMember Proof Build");
    TEST_ASSERT(sm2_revocation_merkle_verify_non_member(tree.root_hash, &nmp)
            == SM2_IC_SUCCESS,
        "NonMember Proof Verify");

    TEST_ASSERT(sm2_revocation_merkle_prove_non_member(&tree, 300, &nmp)
            == SM2_IC_ERR_VERIFY,
        "Member Cannot Use NonMember Proof");

    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_revocation_merkle_cbor_roundtrip()
{
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[] = { 11, 33, 55, 77, 99 };
    TEST_ASSERT(sm2_revocation_merkle_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 101)
            == SM2_IC_SUCCESS,
        "Merkle Build");

    sm2_rev_merkle_membership_proof_t mp;
    TEST_ASSERT(
        sm2_revocation_merkle_prove_member(&tree, 55, &mp) == SM2_IC_SUCCESS,
        "Member Proof");

    uint8_t member_buf[4096];
    size_t member_len = sizeof(member_buf);
    TEST_ASSERT(sm2_revocation_merkle_cbor_encode_member_proof(
                    &mp, member_buf, &member_len)
            == SM2_IC_SUCCESS,
        "Member CBOR Encode");

    sm2_rev_merkle_membership_proof_t mp_dec;
    TEST_ASSERT(sm2_revocation_merkle_cbor_decode_member_proof(
                    &mp_dec, member_buf, member_len)
            == SM2_IC_SUCCESS,
        "Member CBOR Decode");
    TEST_ASSERT(sm2_revocation_merkle_verify_member(tree.root_hash, &mp_dec)
            == SM2_IC_SUCCESS,
        "Member CBOR Verify");

    sm2_rev_merkle_non_membership_proof_t nmp;
    TEST_ASSERT(sm2_revocation_merkle_prove_non_member(&tree, 56, &nmp)
            == SM2_IC_SUCCESS,
        "NonMember Proof");

    uint8_t non_buf[8192];
    size_t non_len = sizeof(non_buf);
    TEST_ASSERT(sm2_revocation_merkle_cbor_encode_non_member_proof(
                    &nmp, non_buf, &non_len)
            == SM2_IC_SUCCESS,
        "NonMember CBOR Encode");

    sm2_rev_merkle_non_membership_proof_t nmp_dec;
    TEST_ASSERT(sm2_revocation_merkle_cbor_decode_non_member_proof(
                    &nmp_dec, non_buf, non_len)
            == SM2_IC_SUCCESS,
        "NonMember CBOR Decode");
    TEST_ASSERT(
        sm2_revocation_merkle_verify_non_member(tree.root_hash, &nmp_dec)
            == SM2_IC_SUCCESS,
        "NonMember CBOR Verify");

    if (member_len > 8)
    {
        sm2_ic_error_t tamper_ret;

        member_buf[8] ^= 0x01;
        tamper_ret = sm2_revocation_merkle_cbor_decode_member_proof(
            &mp_dec, member_buf, member_len);
        if (tamper_ret == SM2_IC_SUCCESS)
        {
            TEST_ASSERT(
                sm2_revocation_merkle_verify_member(tree.root_hash, &mp_dec)
                    == SM2_IC_ERR_VERIFY,
                "Member Tamper Verify Fail");
        }
        else
        {
            TEST_ASSERT(
                tamper_ret == SM2_IC_ERR_CBOR, "Member Tamper Decode Reject");
        }
    }

    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}
static void test_revocation_merkle_root_signature_and_light_verify()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[] = { 1001, 1002, 2001, 3003 };
    TEST_ASSERT(sm2_revocation_merkle_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030601ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };

    sm2_rev_merkle_root_record_t root_record;
    TEST_ASSERT(sm2_revocation_merkle_sign_root(&tree, 1000, 2000,
                    merkle_ca_sign_cb, &sig_ctx, &root_record)
            == SM2_IC_SUCCESS,
        "Root Sign");

    uint8_t root_buf[1024];
    size_t root_len = sizeof(root_buf);
    TEST_ASSERT(sm2_revocation_merkle_cbor_encode_root_record(
                    &root_record, root_buf, &root_len)
            == SM2_IC_SUCCESS,
        "Root CBOR Encode");

    sm2_rev_merkle_root_record_t root_dec;
    TEST_ASSERT(sm2_revocation_merkle_cbor_decode_root_record(
                    &root_dec, root_buf, root_len)
            == SM2_IC_SUCCESS,
        "Root CBOR Decode");

    TEST_ASSERT(sm2_revocation_merkle_verify_root_record(
                    &root_dec, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Root Verify");

    sm2_rev_merkle_membership_proof_t mp;
    TEST_ASSERT(
        sm2_revocation_merkle_prove_member(&tree, 2001, &mp) == SM2_IC_SUCCESS,
        "Member Proof");
    TEST_ASSERT(sm2_revocation_merkle_verify_member_with_root(
                    &root_dec, 1500, &mp, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Member Verify With Root");

    sm2_rev_merkle_non_membership_proof_t nmp;
    TEST_ASSERT(sm2_revocation_merkle_prove_non_member(&tree, 2002, &nmp)
            == SM2_IC_SUCCESS,
        "NonMember Proof");
    TEST_ASSERT(sm2_revocation_merkle_verify_non_member_with_root(
                    &root_dec, 1500, &nmp, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "NonMember Verify With Root");

    root_dec.signature[0] ^= 0x01;
    TEST_ASSERT(sm2_revocation_merkle_verify_root_record(
                    &root_dec, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Root Tamper Reject");
    root_dec.signature[0] ^= 0x01;

    TEST_ASSERT(sm2_revocation_merkle_verify_member_with_root(
                    &root_dec, 2001, &mp, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Root Expire Reject");

    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}
static void test_revocation_merkle_multiproof_roundtrip()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[64];
    for (size_t i = 0; i < 64; i++)
        revoked[i] = 1000 + i;

    TEST_ASSERT(sm2_revocation_merkle_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030602ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build");

    uint64_t queries[] = { 1010, 1011, 1012, 1020, 1021, 1030, 1031, 1032 };
    sm2_rev_merkle_multiproof_t mp;
    memset(&mp, 0, sizeof(mp));

    TEST_ASSERT(sm2_revocation_merkle_build_multiproof(
                    &tree, queries, sizeof(queries) / sizeof(queries[0]), &mp)
            == SM2_IC_SUCCESS,
        "Build MultiProof");
    TEST_ASSERT(mp.unique_hash_count > 0, "MultiProof Unique Hashes");
    TEST_ASSERT(sm2_revocation_merkle_verify_multiproof(tree.root_hash, &mp)
            == SM2_IC_SUCCESS,
        "Verify MultiProof");

    uint8_t mp_buf[65536];
    size_t mp_len = sizeof(mp_buf);
    TEST_ASSERT(
        sm2_revocation_merkle_cbor_encode_multiproof(&mp, mp_buf, &mp_len)
            == SM2_IC_SUCCESS,
        "MultiProof CBOR Encode");

    sm2_rev_merkle_multiproof_t mp_dec;
    memset(&mp_dec, 0, sizeof(mp_dec));
    TEST_ASSERT(
        sm2_revocation_merkle_cbor_decode_multiproof(&mp_dec, mp_buf, mp_len)
            == SM2_IC_SUCCESS,
        "MultiProof CBOR Decode");
    TEST_ASSERT(sm2_revocation_merkle_verify_multiproof(tree.root_hash, &mp_dec)
            == SM2_IC_SUCCESS,
        "Verify MultiProof Decoded");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_merkle_root_record_t root_record;
    TEST_ASSERT(sm2_revocation_merkle_sign_root(&tree, 1000, 2000,
                    merkle_ca_sign_cb, &sig_ctx, &root_record)
            == SM2_IC_SUCCESS,
        "Sign Root For MultiProof");
    TEST_ASSERT(sm2_revocation_merkle_verify_multiproof_with_root(
                    &root_record, 1500, &mp_dec, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Verify MultiProof With Root");

    mp_dec.unique_hashes[0][0] ^= 0x01;
    TEST_ASSERT(sm2_revocation_merkle_verify_multiproof(tree.root_hash, &mp_dec)
            == SM2_IC_ERR_VERIFY,
        "MultiProof Tamper Reject");

    sm2_revocation_merkle_multiproof_cleanup(&mp_dec);
    sm2_revocation_merkle_multiproof_cleanup(&mp);
    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_revocation_merkle_multiproof_bandwidth_gain()
{
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[2048];
    for (size_t i = 0; i < 2048; i++)
        revoked[i] = 100000 + i;

    TEST_ASSERT(sm2_revocation_merkle_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030603ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build Large");

    const size_t ks[] = { 8, 16, 32 };
    for (size_t t = 0; t < sizeof(ks) / sizeof(ks[0]); t++)
    {
        size_t k = ks[t];
        uint64_t queries[32];
        for (size_t i = 0; i < k; i++)
            queries[i] = revoked[900 + i];

        sm2_rev_merkle_multiproof_t mp;
        memset(&mp, 0, sizeof(mp));
        TEST_ASSERT(
            sm2_revocation_merkle_build_multiproof(&tree, queries, k, &mp)
                == SM2_IC_SUCCESS,
            "Build MultiProof K");

        uint8_t multi_buf[262144];
        size_t multi_len = sizeof(multi_buf);
        TEST_ASSERT(sm2_revocation_merkle_cbor_encode_multiproof(
                        &mp, multi_buf, &multi_len)
                == SM2_IC_SUCCESS,
            "Encode MultiProof K");

        size_t single_total = 0;
        for (size_t i = 0; i < k; i++)
        {
            sm2_rev_merkle_membership_proof_t member;
            TEST_ASSERT(
                sm2_revocation_merkle_prove_member(&tree, queries[i], &member)
                    == SM2_IC_SUCCESS,
                "Single Proof Build");

            uint8_t single_buf[8192];
            size_t single_len = sizeof(single_buf);
            TEST_ASSERT(sm2_revocation_merkle_cbor_encode_member_proof(
                            &member, single_buf, &single_len)
                    == SM2_IC_SUCCESS,
                "Single Proof Encode");
            single_total += single_len;
        }

        TEST_ASSERT(single_total > 0, "Single Total NonZero");
        TEST_ASSERT(multi_len < single_total, "MultiProof Smaller");

        double reduction = 1.0 - ((double)multi_len / (double)single_total);
        printf(
            "   [MULTIPROOF] k=%zu, single=%zu, multi=%zu, reduction=%.2f%%\n",
            k, single_total, multi_len, reduction * 100.0);

        if (k == 16)
        {
            TEST_ASSERT(reduction >= 0.60, "k=16 MultiProof Reduction < 60%");
        }

        sm2_revocation_merkle_multiproof_cleanup(&mp);
    }

    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}
static void test_revocation_merkle_epoch_directory_cached_proof()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[2048];
    for (size_t i = 0; i < 2048; i++)
        revoked[i] = 200000 + i;

    TEST_ASSERT(sm2_revocation_merkle_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030604ULL)
            == SM2_IC_SUCCESS,
        "Build Tree");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_merkle_epoch_directory_t dir;
    memset(&dir, 0, sizeof(dir));
    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(
                    &tree, 42, 8, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    uint8_t dir_buf[262144];
    size_t dir_len = sizeof(dir_buf);
    TEST_ASSERT(sm2_revocation_merkle_cbor_encode_epoch_directory(
                    &dir, dir_buf, &dir_len)
            == SM2_IC_SUCCESS,
        "Epoch Directory Encode");

    sm2_rev_merkle_epoch_directory_t dir_dec;
    memset(&dir_dec, 0, sizeof(dir_dec));
    TEST_ASSERT(sm2_revocation_merkle_cbor_decode_epoch_directory(
                    &dir_dec, dir_buf, dir_len)
            == SM2_IC_SUCCESS,
        "Epoch Directory Decode");

    TEST_ASSERT(sm2_revocation_merkle_verify_epoch_directory(
                    &dir_dec, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Epoch Directory Verify");

    uint64_t target = revoked[777];
    sm2_rev_merkle_membership_proof_t full;
    TEST_ASSERT(sm2_revocation_merkle_prove_member(&tree, target, &full)
            == SM2_IC_SUCCESS,
        "Full Member Proof");

    sm2_rev_merkle_cached_member_proof_t cached;
    TEST_ASSERT(
        sm2_revocation_merkle_prove_member_cached(&tree, target, 8, &cached)
            == SM2_IC_SUCCESS,
        "Cached Member Proof");

    uint8_t full_buf[8192];
    size_t full_len = sizeof(full_buf);
    TEST_ASSERT(sm2_revocation_merkle_cbor_encode_member_proof(
                    &full, full_buf, &full_len)
            == SM2_IC_SUCCESS,
        "Full Proof Encode");

    uint8_t cached_buf[8192];
    size_t cached_len = sizeof(cached_buf);
    TEST_ASSERT(sm2_revocation_merkle_cbor_encode_cached_member_proof(
                    &cached, cached_buf, &cached_len)
            == SM2_IC_SUCCESS,
        "Cached Proof Encode");

    sm2_rev_merkle_cached_member_proof_t cached_dec;
    TEST_ASSERT(sm2_revocation_merkle_cbor_decode_cached_member_proof(
                    &cached_dec, cached_buf, cached_len)
            == SM2_IC_SUCCESS,
        "Cached Proof Decode");

    TEST_ASSERT(sm2_revocation_merkle_verify_member_cached(
                    &dir_dec, 1500, &cached_dec, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Cached Proof Verify");

    double reduction = 1.0 - ((double)cached_len / (double)full_len);
    printf("   [EPOCH-CACHE] full=%zu, cached=%zu, reduction=%.2f%%\n",
        full_len, cached_len, reduction * 100.0);
    TEST_ASSERT(reduction >= 0.40, "Epoch Cache Reduction < 40%");

    sm2_revocation_merkle_epoch_directory_cleanup(&dir_dec);
    sm2_revocation_merkle_epoch_directory_cleanup(&dir);
    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_revocation_merkle_hot_patch_priority()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[] = { 900001, 900002, 900003 };
    TEST_ASSERT(sm2_revocation_merkle_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 501)
            == SM2_IC_SUCCESS,
        "Build Tree");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_merkle_epoch_directory_t dir;
    memset(&dir, 0, sizeof(dir));
    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(
                    &tree, 50, 6, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    sm2_crl_delta_item_t patch1[] = { { 999999, true } };
    TEST_ASSERT(sm2_revocation_merkle_epoch_apply_hot_patch(
                    &dir, 1, patch1, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Apply Patch v1");

    sm2_rev_status_t st;
    TEST_ASSERT(sm2_revocation_merkle_epoch_query_patch_first(
                    &dir, 1500, 999999, merkle_ca_verify_cb, &sig_ctx, &st)
            == SM2_IC_SUCCESS,
        "Patch Query v1");
    TEST_ASSERT(st == SM2_REV_STATUS_REVOKED, "Patch Priority Revoked");

    sm2_crl_delta_item_t patch2[] = { { 999999, false } };
    TEST_ASSERT(sm2_revocation_merkle_epoch_apply_hot_patch(
                    &dir, 2, patch2, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Apply Patch v2");
    TEST_ASSERT(sm2_revocation_merkle_epoch_query_patch_first(
                    &dir, 1500, 999999, merkle_ca_verify_cb, &sig_ctx, &st)
            == SM2_IC_SUCCESS,
        "Patch Query v2");
    TEST_ASSERT(st == SM2_REV_STATUS_GOOD, "Patch Override Good");

    TEST_ASSERT(sm2_revocation_merkle_epoch_apply_hot_patch(
                    &dir, 2, patch1, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Patch Version Monotonic");

    sm2_revocation_merkle_epoch_directory_cleanup(&dir);
    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_revocation_merkle_epoch_switch_monotonic()
{
    if (!g_ca_initialized)
        test_setup_ca();

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };

    sm2_rev_merkle_tree_t t1, t2;
    memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2));

    uint64_t revoked1[] = { 1001, 1002, 1003 };
    uint64_t revoked2[] = { 1001, 1002, 1003, 1004, 1005 };

    TEST_ASSERT(sm2_revocation_merkle_build(
                    &t1, revoked1, sizeof(revoked1) / sizeof(revoked1[0]), 10)
            == SM2_IC_SUCCESS,
        "Build T1");
    TEST_ASSERT(sm2_revocation_merkle_build(
                    &t2, revoked2, sizeof(revoked2) / sizeof(revoked2[0]), 11)
            == SM2_IC_SUCCESS,
        "Build T2");

    sm2_rev_merkle_epoch_directory_t d1, d2, local;
    memset(&d1, 0, sizeof(d1));
    memset(&d2, 0, sizeof(d2));
    memset(&local, 0, sizeof(local));

    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(
                    &t1, 60, 4, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d1)
            == SM2_IC_SUCCESS,
        "Build D1");
    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(
                    &t2, 61, 4, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d2)
            == SM2_IC_SUCCESS,
        "Build D2");

    TEST_ASSERT(sm2_revocation_merkle_epoch_switch(
                    &local, &d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D1");
    TEST_ASSERT(sm2_revocation_merkle_epoch_switch(
                    &local, &d2, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D2");
    TEST_ASSERT(sm2_revocation_merkle_epoch_switch(
                    &local, &d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Older Epoch");

    sm2_revocation_merkle_epoch_directory_cleanup(&local);
    sm2_revocation_merkle_epoch_directory_cleanup(&d2);
    sm2_revocation_merkle_epoch_directory_cleanup(&d1);
    sm2_revocation_merkle_cleanup(&t2);
    sm2_revocation_merkle_cleanup(&t1);
    TEST_PASS();
}
static void test_revocation_merkle_k_anon_query_baseline()
{
    sm2_rev_merkle_k_anon_query_t query;
    uint64_t real = 700001;
    uint64_t decoys[]
        = { 700010, 700011, 700012, 700013, 700014, 700015, 700016, 700001 };

    TEST_ASSERT(sm2_revocation_merkle_build_k_anon_query(real, decoys,
                    sizeof(decoys) / sizeof(decoys[0]), 8, 0x1234, &query)
            == SM2_IC_SUCCESS,
        "Build K-Anon Query");
    TEST_ASSERT(query.serial_count == 8, "K-Anon Serial Count");
    TEST_ASSERT(query.real_index < query.serial_count, "Real Index Range");
    TEST_ASSERT(
        query.serials[query.real_index] == real, "Real Serial Positioned");

    for (size_t i = 0; i < query.serial_count; i++)
    {
        for (size_t j = i + 1; j < query.serial_count; j++)
        {
            TEST_ASSERT(query.serials[i] != query.serials[j], "Unique Serials");
        }
    }

    uint64_t wire_serials[SM2_REV_MERKLE_K_ANON_MAX];
    size_t wire_count = sizeof(wire_serials) / sizeof(wire_serials[0]);
    TEST_ASSERT(sm2_revocation_merkle_export_k_anon_serials(
                    &query, wire_serials, &wire_count)
            == SM2_IC_SUCCESS,
        "Export K-Anon Serials");
    TEST_ASSERT(wire_count == query.serial_count, "Wire Count Match");

    bool found_real = false;
    for (size_t i = 0; i < wire_count; i++)
    {
        if (wire_serials[i] == real)
            found_real = true;
    }
    TEST_ASSERT(found_real, "Wire Includes Real Serial");
    TEST_PASS();
}

static void test_revocation_merkle_k_anon_export_min_metadata()
{
    sm2_rev_merkle_k_anon_query_t query;
    uint64_t real = 800001;
    uint64_t decoys[] = { 800010, 800011, 800012, 800013 };

    TEST_ASSERT(sm2_revocation_merkle_build_k_anon_query(real, decoys,
                    sizeof(decoys) / sizeof(decoys[0]), 4, 0x5678, &query)
            == SM2_IC_SUCCESS,
        "Build K-Anon Query 4");

    uint64_t too_small[2];
    size_t small_count = sizeof(too_small) / sizeof(too_small[0]);
    TEST_ASSERT(sm2_revocation_merkle_export_k_anon_serials(
                    &query, too_small, &small_count)
            == SM2_IC_ERR_MEMORY,
        "Export Size Probe");
    TEST_ASSERT(small_count == 4, "Required Count Returned");

    uint64_t exact[4];
    size_t exact_count = sizeof(exact) / sizeof(exact[0]);
    TEST_ASSERT(
        sm2_revocation_merkle_export_k_anon_serials(&query, exact, &exact_count)
            == SM2_IC_SUCCESS,
        "Export Exact Buffer");
    TEST_ASSERT(exact_count == 4, "Exact Count");
    TEST_PASS();
}

static void test_revocation_merkle_k_anon_policy_tradeoff()
{
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    enum
    {
        revoked_n = 2048,
        k = 16
    };

    uint64_t *revoked = (uint64_t *)calloc(revoked_n, sizeof(uint64_t));
    uint64_t *decoys = (uint64_t *)calloc(revoked_n - 1, sizeof(uint64_t));
    TEST_ASSERT(revoked != NULL && decoys != NULL, "Alloc K-Anon Buffers");

    for (size_t i = 0; i < revoked_n; i++)
        revoked[i] = 500000ULL + i;

    uint64_t real = revoked[1024];
    size_t decoy_count = 0;
    for (size_t i = 0; i < revoked_n; i++)
    {
        if (revoked[i] == real)
            continue;
        decoys[decoy_count++] = revoked[i];
    }

    TEST_ASSERT(
        sm2_revocation_merkle_build(&tree, revoked, revoked_n, 2026030605ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build For K-Anon Tradeoff");

    const uint8_t clusters[3] = { 0, 50, 100 };
    size_t proof_bytes[3] = { 0, 0, 0 };
    double risks[3] = { 0.0, 0.0, 0.0 };
    uint64_t spans[3] = { 0, 0, 0 };

    for (size_t i = 0; i < 3; i++)
    {
        sm2_rev_merkle_k_anon_query_t query;
        sm2_rev_merkle_k_anon_policy_t policy;
        sm2_rev_merkle_multiproof_t mp;
        uint8_t mp_buf[262144];
        size_t mp_len = sizeof(mp_buf);

        memset(&policy, 0, sizeof(policy));
        memset(&mp, 0, sizeof(mp));
        policy.cluster_level = clusters[i];

        TEST_ASSERT(sm2_revocation_merkle_build_k_anon_query_with_policy(real,
                        decoys, decoy_count, k, 0xA55A5AA5ULL, &policy, &query)
                == SM2_IC_SUCCESS,
            "Build K-Anon Query With Policy");
        TEST_ASSERT(sm2_revocation_merkle_build_multiproof(
                        &tree, query.serials, query.serial_count, &mp)
                == SM2_IC_SUCCESS,
            "Build K-Anon MultiProof");
        TEST_ASSERT(
            sm2_revocation_merkle_cbor_encode_multiproof(&mp, mp_buf, &mp_len)
                == SM2_IC_SUCCESS,
            "Encode K-Anon MultiProof");
        TEST_ASSERT(sm2_revocation_merkle_estimate_k_anon_risk(
                        &query, real, &risks[i], &spans[i])
                == SM2_IC_SUCCESS,
            "Estimate K-Anon Risk");

        proof_bytes[i] = mp_len;
        printf("   [K-ANON-TRADEOFF] cluster=%u, proof=%zu, span=%llu, "
               "risk=%.6f\n",
            (unsigned)clusters[i], mp_len, (unsigned long long)spans[i],
            risks[i]);

        sm2_revocation_merkle_multiproof_cleanup(&mp);
    }

    TEST_ASSERT(
        proof_bytes[2] <= proof_bytes[0], "Cluster100 Proof Not Smaller");
    TEST_ASSERT(spans[2] <= spans[0], "Cluster100 Span Not Smaller");
    TEST_ASSERT(risks[2] >= risks[0], "Cluster100 Risk Not Higher");

    sm2_revocation_merkle_cleanup(&tree);
    free(decoys);
    free(revoked);
    TEST_PASS();
}

static bool serial_in_prefix(
    const uint64_t *decoys, size_t prefix_len, uint64_t serial)
{
    for (size_t i = 0; i < prefix_len; i++)
    {
        if (decoys[i] == serial)
            return true;
    }
    return false;
}

static void test_revocation_merkle_multiproof_dynamic_growth_path()
{
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    uint64_t revoked[2048];
    for (size_t i = 0; i < sizeof(revoked) / sizeof(revoked[0]); i++)
        revoked[i] = 910000ULL + i;

    TEST_ASSERT(sm2_revocation_merkle_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030701ULL)
            == SM2_IC_SUCCESS,
        "Build Tree For Dynamic Growth");

    uint64_t query = revoked[1024];
    sm2_rev_merkle_multiproof_t mp;
    memset(&mp, 0, sizeof(mp));

    TEST_ASSERT(sm2_revocation_merkle_build_multiproof(&tree, &query, 1, &mp)
            == SM2_IC_SUCCESS,
        "Build MultiProof Dynamic Growth");
    TEST_ASSERT(mp.query_count == 1, "Query Count");
    TEST_ASSERT(mp.unique_hash_count > 1, "Dynamic Growth Triggered");
    TEST_ASSERT(sm2_revocation_merkle_verify_multiproof(tree.root_hash, &mp)
            == SM2_IC_SUCCESS,
        "Verify Dynamic Growth MultiProof");

    sm2_revocation_merkle_multiproof_cleanup(&mp);
    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_revocation_merkle_k_anon_risk_weights_effective()
{
    uint64_t real = 920000ULL;
    uint64_t decoys[64];
    for (size_t i = 0; i < sizeof(decoys) / sizeof(decoys[0]); i++)
        decoys[i] = real + 1ULL + (uint64_t)i;

    sm2_rev_merkle_k_anon_query_t q_default, q_weighted;
    sm2_rev_merkle_k_anon_policy_t p_default, p_weighted;
    memset(&q_default, 0, sizeof(q_default));
    memset(&q_weighted, 0, sizeof(q_weighted));
    memset(&p_default, 0, sizeof(p_default));
    memset(&p_weighted, 0, sizeof(p_weighted));

    p_default.cluster_level = 60;
    p_default.risk_weight_k = 40;
    p_default.risk_weight_span = 45;
    p_default.risk_weight_nearest = 15;

    p_weighted.cluster_level = 60;
    p_weighted.risk_weight_k = 5;
    p_weighted.risk_weight_span = 5;
    p_weighted.risk_weight_nearest = 90;

    TEST_ASSERT(sm2_revocation_merkle_build_k_anon_query_with_policy(real,
                    decoys, sizeof(decoys) / sizeof(decoys[0]), 16, 0x11223344,
                    &p_default, &q_default)
            == SM2_IC_SUCCESS,
        "Build Default Weight Query");
    TEST_ASSERT(sm2_revocation_merkle_build_k_anon_query_with_policy(real,
                    decoys, sizeof(decoys) / sizeof(decoys[0]), 16, 0x11223344,
                    &p_weighted, &q_weighted)
            == SM2_IC_SUCCESS,
        "Build Weighted Query");

    TEST_ASSERT(
        q_default.serial_count == q_weighted.serial_count, "Query Size Match");
    for (size_t i = 0; i < q_default.serial_count; i++)
    {
        TEST_ASSERT(q_default.serials[i] == q_weighted.serials[i],
            "Policy Weight Does Not Change Selection");
    }

    double risk_default = 0.0;
    double risk_weighted = 0.0;
    uint64_t span_default = 0;
    uint64_t span_weighted = 0;
    TEST_ASSERT(sm2_revocation_merkle_estimate_k_anon_risk(
                    &q_default, real, &risk_default, &span_default)
            == SM2_IC_SUCCESS,
        "Estimate Default Risk");
    TEST_ASSERT(sm2_revocation_merkle_estimate_k_anon_risk(
                    &q_weighted, real, &risk_weighted, &span_weighted)
            == SM2_IC_SUCCESS,
        "Estimate Weighted Risk");
    TEST_ASSERT(span_default == span_weighted, "Span Stable");

    double diff = (risk_default > risk_weighted)
        ? (risk_default - risk_weighted)
        : (risk_weighted - risk_default);
    TEST_ASSERT(diff > 0.01, "Risk Weight Should Affect Score");
    TEST_PASS();
}

static void test_revocation_merkle_k_anon_candidate_window_limit()
{
    uint64_t real = 930000ULL;
    uint64_t decoys[256];
    const size_t narrow_window = 10;

    for (size_t i = 0; i < narrow_window; i++)
        decoys[i] = real + 10000ULL + (uint64_t)(i * 100U);
    for (size_t i = narrow_window; i < sizeof(decoys) / sizeof(decoys[0]); i++)
        decoys[i] = real + 1ULL + (uint64_t)(i - narrow_window);

    sm2_rev_merkle_k_anon_policy_t p_narrow, p_full;
    sm2_rev_merkle_k_anon_query_t q_narrow, q_full;
    memset(&p_narrow, 0, sizeof(p_narrow));
    memset(&p_full, 0, sizeof(p_full));
    memset(&q_narrow, 0, sizeof(q_narrow));
    memset(&q_full, 0, sizeof(q_full));

    p_narrow.cluster_level = 100;
    p_narrow.candidate_scan_limit = (uint16_t)narrow_window;
    p_full.cluster_level = 100;
    p_full.candidate_scan_limit = 0;

    TEST_ASSERT(sm2_revocation_merkle_build_k_anon_query_with_policy(real,
                    decoys, sizeof(decoys) / sizeof(decoys[0]), 8, 0x55667788,
                    &p_narrow, &q_narrow)
            == SM2_IC_SUCCESS,
        "Build Narrow Window Query");
    TEST_ASSERT(
        sm2_revocation_merkle_build_k_anon_query_with_policy(real, decoys,
            sizeof(decoys) / sizeof(decoys[0]), 8, 0x55667788, &p_full, &q_full)
            == SM2_IC_SUCCESS,
        "Build Full Window Query");

    for (size_t i = 0; i < q_narrow.serial_count; i++)
    {
        if (q_narrow.serials[i] == real)
            continue;
        TEST_ASSERT(
            serial_in_prefix(decoys, narrow_window, q_narrow.serials[i]),
            "Narrow Window Must Pick Prefix Candidates");
    }

    double risk_narrow = 0.0;
    double risk_full = 0.0;
    uint64_t span_narrow = 0;
    uint64_t span_full = 0;
    TEST_ASSERT(sm2_revocation_merkle_estimate_k_anon_risk(
                    &q_narrow, real, &risk_narrow, &span_narrow)
            == SM2_IC_SUCCESS,
        "Estimate Narrow Risk");
    TEST_ASSERT(sm2_revocation_merkle_estimate_k_anon_risk(
                    &q_full, real, &risk_full, &span_full)
            == SM2_IC_SUCCESS,
        "Estimate Full Risk");
    TEST_ASSERT(span_narrow > span_full, "Narrow Window Should Increase Span");
    TEST_PASS();
}
static void test_revocation_merkle_phase8_metric_bundle()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));

    enum
    {
        revoked_n = 2048,
        k = 16
    };

    uint64_t *revoked = (uint64_t *)calloc(revoked_n, sizeof(uint64_t));
    TEST_ASSERT(revoked != NULL, "Alloc Metric Tree Data");
    for (size_t i = 0; i < revoked_n; i++)
        revoked[i] = 600000ULL + i;

    TEST_ASSERT(
        sm2_revocation_merkle_build(&tree, revoked, revoked_n, 2026030606ULL)
            == SM2_IC_SUCCESS,
        "Build Metric Tree");

    uint64_t queries[k];
    for (size_t i = 0; i < k; i++)
        queries[i] = revoked[900 + i];

    sm2_rev_merkle_multiproof_t mp;
    memset(&mp, 0, sizeof(mp));
    TEST_ASSERT(sm2_revocation_merkle_build_multiproof(&tree, queries, k, &mp)
            == SM2_IC_SUCCESS,
        "Build Metric MultiProof");

    uint8_t mp_buf[262144];
    size_t mp_len = sizeof(mp_buf);
    TEST_ASSERT(
        sm2_revocation_merkle_cbor_encode_multiproof(&mp, mp_buf, &mp_len)
            == SM2_IC_SUCCESS,
        "Encode Metric MultiProof");

    size_t single_total = 0;
    size_t sibling_refs = 0;
    for (size_t i = 0; i < k; i++)
    {
        sm2_rev_merkle_membership_proof_t member;
        uint8_t single_buf[8192];
        size_t single_len = sizeof(single_buf);

        TEST_ASSERT(
            sm2_revocation_merkle_prove_member(&tree, queries[i], &member)
                == SM2_IC_SUCCESS,
            "Build Single Proof");
        TEST_ASSERT(sm2_revocation_merkle_cbor_encode_member_proof(
                        &member, single_buf, &single_len)
                == SM2_IC_SUCCESS,
            "Encode Single Proof");

        single_total += single_len;
        sibling_refs += member.sibling_count;
    }

    TEST_ASSERT(single_total > 0, "Metric Single Total Zero");
    TEST_ASSERT(sibling_refs > 0, "Metric Sibling Refs Zero");
    TEST_ASSERT(mp.unique_hash_count <= sibling_refs, "Unique Hashes Overflow");

    double reuse_rate
        = 1.0 - ((double)mp.unique_hash_count / (double)sibling_refs);
    double bandwidth_gain = 1.0 - ((double)mp_len / (double)single_total);

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_merkle_epoch_directory_t dir;
    memset(&dir, 0, sizeof(dir));
    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(
                    &tree, 66, 8, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Metric Epoch Directory");

    sm2_rev_merkle_membership_proof_t full;
    sm2_rev_merkle_cached_member_proof_t cached;
    TEST_ASSERT(sm2_revocation_merkle_prove_member(&tree, queries[0], &full)
            == SM2_IC_SUCCESS,
        "Build Full Proof For Cache");
    TEST_ASSERT(
        sm2_revocation_merkle_prove_member_cached(&tree, queries[0], 8, &cached)
            == SM2_IC_SUCCESS,
        "Build Cached Proof For Cache");

    TEST_ASSERT(full.sibling_count > 0, "Full Sibling Count Zero");
    double cache_hit_rate
        = (double)cached.omitted_top_levels / (double)full.sibling_count;

    printf("   [P8-METRIC] reuse=%.2f%%, cache_hit=%.2f%%, bandwidth=%.2f%%\n",
        reuse_rate * 100.0, cache_hit_rate * 100.0, bandwidth_gain * 100.0);

    TEST_ASSERT(reuse_rate >= 0.30, "Reuse Rate < 30%");
    TEST_ASSERT(cache_hit_rate >= 0.40, "Cache Hit < 40%");
    TEST_ASSERT(bandwidth_gain >= 0.60, "Bandwidth Gain < 60%");

    sm2_revocation_merkle_epoch_directory_cleanup(&dir);
    sm2_revocation_merkle_multiproof_cleanup(&mp);
    sm2_revocation_merkle_cleanup(&tree);
    free(revoked);
    TEST_PASS();
}
/* ----- Negative / Boundary Tests (Phase 3 hardening) ----- */

static void test_merkle_empty_tree_prove_member_fails(void)
{
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));
    TEST_ASSERT(
        sm2_revocation_merkle_build(&tree, NULL, 0, 1) == SM2_IC_SUCCESS,
        "Build empty tree");
    TEST_ASSERT(tree.leaf_count == 0, "Empty tree has 0 leaves");

    sm2_rev_merkle_membership_proof_t mp;
    TEST_ASSERT(
        sm2_revocation_merkle_prove_member(&tree, 42, &mp) == SM2_IC_ERR_VERIFY,
        "prove_member on empty tree must fail");

    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_expired_root_record_rejected(void)
{
    uint64_t revoked[] = { 10, 20, 30 };
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));
    TEST_ASSERT(
        sm2_revocation_merkle_build(&tree, revoked, 3, 1) == SM2_IC_SUCCESS,
        "Build tree");

    merkle_ca_sig_ctx_t ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_merkle_root_record_t root;
    TEST_ASSERT(sm2_revocation_merkle_sign_root(
                    &tree, 1000, 2000, merkle_ca_sign_cb, &ctx, &root)
            == SM2_IC_SUCCESS,
        "Sign root");

    /* now_ts=3000 > valid_until=2000 -> should reject */
    TEST_ASSERT(sm2_revocation_merkle_verify_root_record(
                    &root, 3000, merkle_ca_verify_cb, &ctx)
            == SM2_IC_ERR_VERIFY,
        "Expired root must be rejected");

    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_hot_patch_stale_version_rejected(void)
{
    uint64_t revoked[] = { 100, 200, 300 };
    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));
    TEST_ASSERT(
        sm2_revocation_merkle_build(&tree, revoked, 3, 1) == SM2_IC_SUCCESS,
        "Build tree");

    merkle_ca_sig_ctx_t ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_merkle_epoch_directory_t dir;
    memset(&dir, 0, sizeof(dir));
    TEST_ASSERT(sm2_revocation_merkle_build_epoch_directory(
                    &tree, 1, 4, 1000, 9000, merkle_ca_sign_cb, &ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build epoch dir");

    sm2_crl_delta_item_t patch1 = { 400, true };
    TEST_ASSERT(sm2_revocation_merkle_epoch_apply_hot_patch(
                    &dir, 5, &patch1, 1, merkle_ca_sign_cb, &ctx)
            == SM2_IC_SUCCESS,
        "Hot patch v5");

    /* Apply same version again -> should fail */
    sm2_crl_delta_item_t patch2 = { 500, true };
    sm2_ic_error_t stale_ret = sm2_revocation_merkle_epoch_apply_hot_patch(
        &dir, 5, &patch2, 1, merkle_ca_sign_cb, &ctx);
    TEST_ASSERT(
        stale_ret != SM2_IC_SUCCESS, "Stale patch version must be rejected");

    /* Apply older version -> should fail */
    sm2_ic_error_t older_ret = sm2_revocation_merkle_epoch_apply_hot_patch(
        &dir, 3, &patch2, 1, merkle_ca_sign_cb, &ctx);
    TEST_ASSERT(
        older_ret != SM2_IC_SUCCESS, "Older patch version must be rejected");

    sm2_revocation_merkle_epoch_directory_cleanup(&dir);
    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_multiproof_over_limit_rejected(void)
{
    uint64_t serials[SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1];
    for (size_t i = 0; i < SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1; i++)
        serials[i] = (uint64_t)(i + 1);

    sm2_rev_merkle_tree_t tree;
    memset(&tree, 0, sizeof(tree));
    TEST_ASSERT(sm2_revocation_merkle_build(
                    &tree, serials, SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1, 1)
            == SM2_IC_SUCCESS,
        "Build tree");

    sm2_rev_merkle_multiproof_t mp;
    memset(&mp, 0, sizeof(mp));
    sm2_ic_error_t ret = sm2_revocation_merkle_build_multiproof(
        &tree, serials, SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1, &mp);
    TEST_ASSERT(ret == SM2_IC_ERR_PARAM,
        "Multiproof over MULTI_MAX_QUERIES must be rejected");

    sm2_revocation_merkle_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_quorum_dedup_node_id(void)
{
    sm2_rev_quorum_vote_t votes[3];
    memset(votes, 0, sizeof(votes));

    uint8_t node_a[] = "node_A";
    uint8_t node_b[] = "node_B";

    /* Vote 0 and Vote 1: same node_id, different revocation status */
    memcpy(votes[0].node_id, node_a, sizeof(node_a));
    votes[0].node_id_len = sizeof(node_a);
    votes[0].proof_valid = true;
    votes[0].root_version = 10;
    votes[0].status = SM2_REV_STATUS_REVOKED;
    memset(votes[0].root_hash, 0xAA, SM2_REV_SYNC_DIGEST_LEN);

    memcpy(votes[1].node_id, node_a, sizeof(node_a));
    votes[1].node_id_len = sizeof(node_a);
    votes[1].proof_valid = true;
    votes[1].root_version = 10;
    votes[1].status = SM2_REV_STATUS_GOOD;
    memset(votes[1].root_hash, 0xAA, SM2_REV_SYNC_DIGEST_LEN);

    memcpy(votes[2].node_id, node_b, sizeof(node_b));
    votes[2].node_id_len = sizeof(node_b);
    votes[2].proof_valid = true;
    votes[2].root_version = 10;
    votes[2].status = SM2_REV_STATUS_REVOKED;
    memset(votes[2].root_hash, 0xAA, SM2_REV_SYNC_DIGEST_LEN);

    sm2_rev_quorum_result_t result;
    sm2_ic_error_t ret = sm2_revocation_quorum_evaluate(votes, 3, 2, &result);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "Quorum evaluate ok");
    TEST_ASSERT(result.unique_node_count == 2,
        "Duplicate node_id must be deduped (2 unique)");

    TEST_PASS();
}
void run_test_merkle_suite(void)
{
    test_setup_ca();
    RUN_TEST(test_revocation_merkle_member_and_non_member);
    RUN_TEST(test_revocation_merkle_cbor_roundtrip);
    RUN_TEST(test_revocation_merkle_root_signature_and_light_verify);
    RUN_TEST(test_revocation_merkle_multiproof_roundtrip);
    RUN_TEST(test_revocation_merkle_multiproof_bandwidth_gain);
    RUN_TEST(test_revocation_merkle_epoch_directory_cached_proof);
    RUN_TEST(test_revocation_merkle_hot_patch_priority);
    RUN_TEST(test_revocation_merkle_epoch_switch_monotonic);
    RUN_TEST(test_revocation_merkle_k_anon_query_baseline);
    RUN_TEST(test_revocation_merkle_k_anon_export_min_metadata);
    RUN_TEST(test_revocation_merkle_k_anon_policy_tradeoff);
    RUN_TEST(test_revocation_merkle_multiproof_dynamic_growth_path);
    RUN_TEST(test_revocation_merkle_k_anon_risk_weights_effective);
    RUN_TEST(test_revocation_merkle_k_anon_candidate_window_limit);
    RUN_TEST(test_revocation_merkle_phase8_metric_bundle);
    /* -- Phase 3 negative / boundary tests -- */
    RUN_TEST(test_merkle_empty_tree_prove_member_fails);
    RUN_TEST(test_merkle_expired_root_record_rejected);
    RUN_TEST(test_merkle_hot_patch_stale_version_rejected);
    RUN_TEST(test_merkle_multiproof_over_limit_rejected);
    RUN_TEST(test_merkle_quorum_dedup_node_id);
}
