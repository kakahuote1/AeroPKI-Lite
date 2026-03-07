/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Demo Test 2:
 * Merkle accumulator capabilities:
 * 1) member/non-member proof verification,
 * 2) multiproof bandwidth reduction,
 * 3) k-anonymity query packing and risk estimate.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sm2_revocation.h"

static int check_ic(sm2_ic_error_t err, const char *step)
{
    if (err != SM2_IC_SUCCESS)
    {
        printf("[FAIL] %s, err=%d\n", step, (int)err);
        return 0;
    }
    printf("[OK]   %s\n", step);
    return 1;
}

int main(void)
{
    sm2_ic_error_t ret;

    enum
    {
        revoked_n = 1024,
        k = 16
    };

    uint64_t *revoked = NULL;
    uint64_t *decoys = NULL;
    size_t decoy_count = 0;

    sm2_rev_merkle_tree_t tree;
    sm2_rev_merkle_membership_proof_t mp_real;
    sm2_rev_merkle_non_membership_proof_t nmp;
    sm2_rev_merkle_k_anon_query_t kq;
    sm2_rev_merkle_multiproof_t multi;

    uint8_t multi_buf[262144];
    size_t multi_len = sizeof(multi_buf);

    memset(&tree, 0, sizeof(tree));
    memset(&mp_real, 0, sizeof(mp_real));
    memset(&nmp, 0, sizeof(nmp));
    memset(&kq, 0, sizeof(kq));
    memset(&multi, 0, sizeof(multi));

    revoked = (uint64_t *)calloc(revoked_n, sizeof(uint64_t));
    decoys = (uint64_t *)calloc(revoked_n - 1, sizeof(uint64_t));
    if (!revoked || !decoys)
    {
        printf("[FAIL] Allocate buffers\n");
        free(decoys);
        free(revoked);
        return 1;
    }
    printf("[OK]   Allocate buffers\n");

    for (size_t i = 0; i < revoked_n; i++)
        revoked[i] = 700000ULL + i;

    uint64_t real_serial = revoked[512];
    uint64_t good_serial = 799999ULL;

    for (size_t i = 0; i < revoked_n; i++)
    {
        if (revoked[i] == real_serial)
            continue;
        decoys[decoy_count++] = revoked[i];
    }

    ret = sm2_revocation_merkle_build(&tree, revoked, revoked_n, 2026030701ULL);
    if (!check_ic(ret, "Build Merkle Tree"))
        goto cleanup;

    ret = sm2_revocation_merkle_prove_member(&tree, real_serial, &mp_real);
    if (!check_ic(ret, "Build Member Proof"))
        goto cleanup;

    ret = sm2_revocation_merkle_verify_member(tree.root_hash, &mp_real);
    if (!check_ic(ret, "Verify Member Proof"))
        goto cleanup;

    ret = sm2_revocation_merkle_prove_non_member(&tree, good_serial, &nmp);
    if (!check_ic(ret, "Build Non-Member Proof"))
        goto cleanup;

    ret = sm2_revocation_merkle_verify_non_member(tree.root_hash, &nmp);
    if (!check_ic(ret, "Verify Non-Member Proof"))
        goto cleanup;

    ret = sm2_revocation_merkle_build_k_anon_query(
        real_serial, decoys, decoy_count, k, 0xA55AA55AULL, &kq);
    if (!check_ic(ret, "Build K-Anon Query"))
        goto cleanup;

    ret = sm2_revocation_merkle_build_multiproof(
        &tree, kq.serials, kq.serial_count, &multi);
    if (!check_ic(ret, "Build Multi-Proof"))
        goto cleanup;

    ret = sm2_revocation_merkle_verify_multiproof(tree.root_hash, &multi);
    if (!check_ic(ret, "Verify Multi-Proof"))
        goto cleanup;

    ret = sm2_revocation_merkle_cbor_encode_multiproof(
        &multi, multi_buf, &multi_len);
    if (!check_ic(ret, "Encode Multi-Proof"))
        goto cleanup;

    size_t single_total = 0;
    for (size_t i = 0; i < kq.serial_count; i++)
    {
        sm2_rev_merkle_membership_proof_t mp_each;
        uint8_t mp_buf[8192];
        size_t mp_len = sizeof(mp_buf);

        memset(&mp_each, 0, sizeof(mp_each));
        ret = sm2_revocation_merkle_prove_member(
            &tree, kq.serials[i], &mp_each);
        if (ret != SM2_IC_SUCCESS)
        {
            printf("[FAIL] Build Single Proof #%zu, err=%d\n", i, (int)ret);
            goto cleanup;
        }

        ret = sm2_revocation_merkle_cbor_encode_member_proof(
            &mp_each, mp_buf, &mp_len);
        if (ret != SM2_IC_SUCCESS)
        {
            printf("[FAIL] Encode Single Proof #%zu, err=%d\n", i, (int)ret);
            goto cleanup;
        }
        single_total += mp_len;
    }

    double reduction = 0.0;
    if (single_total > 0)
        reduction = ((double)(single_total - multi_len) * 100.0)
            / (double)single_total;

    double risk_score = 0.0;
    uint64_t span = 0;
    ret = sm2_revocation_merkle_estimate_k_anon_risk(
        &kq, real_serial, &risk_score, &span);
    if (!check_ic(ret, "Estimate K-Anon Risk"))
        goto cleanup;

    printf("[METRIC] single_total=%zu bytes, multiproof=%zu bytes, "
           "reduction=%.2f%%\n",
        single_total, multi_len, reduction);
    printf("[METRIC] k=%zu, real_index=%zu, span=%llu, risk=%.6f\n",
        kq.serial_count, kq.real_index, (unsigned long long)span, risk_score);

    if (!(multi_len < single_total))
    {
        printf("[FAIL] Multi-Proof is not smaller than single proofs\n");
        goto cleanup;
    }
    printf("[OK]   Multi-Proof bandwidth reduction confirmed\n");

    if (!(risk_score >= 0.0 && risk_score <= 1.0))
    {
        printf("[FAIL] K-Anon risk score out of range\n");
        goto cleanup;
    }
    printf("[OK]   K-Anon risk score in valid range\n");

    printf("[PASS] demo_test_merkle_flow\n");
    sm2_revocation_merkle_multiproof_cleanup(&multi);
    sm2_revocation_merkle_cleanup(&tree);
    free(decoys);
    free(revoked);
    return 0;

cleanup:
    sm2_revocation_merkle_multiproof_cleanup(&multi);
    sm2_revocation_merkle_cleanup(&tree);
    free(decoys);
    free(revoked);
    return 1;
}
