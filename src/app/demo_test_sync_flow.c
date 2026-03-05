/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Demo Test 2:
 * Offline encounter sync (Cuckoo Sync) with signed packet export/apply.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm2_revocation.h"

typedef struct
{
    uint8_t key;
} demo_sig_state_t;

static sm2_ic_error_t demo_sign(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    demo_sig_state_t *st = (demo_sig_state_t *)user_ctx;
    uint8_t digest[SM3_DIGEST_LENGTH];
    uint8_t *buf = NULL;

    if (!st || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;
    if (*signature_len < SM3_DIGEST_LENGTH)
        return SM2_IC_ERR_MEMORY;

    buf = (uint8_t *)calloc(data_len + 1, 1);
    if (!buf)
        return SM2_IC_ERR_MEMORY;

    buf[0] = st->key;
    memcpy(buf + 1, data, data_len);

    if (sm2_ic_sm3_hash(buf, data_len + 1, digest) != SM2_IC_SUCCESS)
    {
        free(buf);
        return SM2_IC_ERR_CRYPTO;
    }

    memcpy(signature, digest, SM3_DIGEST_LENGTH);
    *signature_len = SM3_DIGEST_LENGTH;
    free(buf);
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t demo_verify(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    demo_sig_state_t *st = (demo_sig_state_t *)user_ctx;
    uint8_t expect[SM3_DIGEST_LENGTH];
    uint8_t *buf = NULL;

    if (!st || !data || !signature)
        return SM2_IC_ERR_PARAM;
    if (signature_len != SM3_DIGEST_LENGTH)
        return SM2_IC_ERR_VERIFY;

    buf = (uint8_t *)calloc(data_len + 1, 1);
    if (!buf)
        return SM2_IC_ERR_MEMORY;

    buf[0] = st->key;
    memcpy(buf + 1, data, data_len);

    if (sm2_ic_sm3_hash(buf, data_len + 1, expect) != SM2_IC_SUCCESS)
    {
        free(buf);
        return SM2_IC_ERR_CRYPTO;
    }

    free(buf);
    return memcmp(expect, signature, SM3_DIGEST_LENGTH) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}

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
    sm2_revocation_ctx_t a;
    sm2_revocation_ctx_t b;
    sm2_rev_sync_hello_t hello_b;
    sm2_rev_sync_plan_t plan_a2b;
    sm2_rev_sync_packet_t packet;
    sm2_crl_delta_item_t items[] = { { 880001, true }, { 880002, true } };
    sm2_crl_delta_t delta = { 0, 1, items, 2 };
    sm2_rev_status_t status = SM2_REV_STATUS_UNKNOWN;
    sm2_rev_source_t source = SM2_REV_SOURCE_NONE;
    demo_sig_state_t sig_state;
    sm2_ic_error_t err = SM2_IC_SUCCESS;

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&hello_b, 0, sizeof(hello_b));
    memset(&plan_a2b, 0, sizeof(plan_a2b));
    memset(&packet, 0, sizeof(packet));
    memset(&sig_state, 0, sizeof(sig_state));
    sig_state.key = 0x5A;

    /* 1) Initialize two offline nodes */
    err = sm2_revocation_init(&a, 64, 300, 1000);
    if (!check_ic(err, "Init Node A"))
        goto cleanup;
    err = sm2_revocation_init(&b, 64, 300, 1000);
    if (!check_ic(err, "Init Node B"))
        goto cleanup;

    err = sm2_revocation_set_sync_identity(
        &a, (const uint8_t *)"NODE_A", 6, 1, 2048);
    if (!check_ic(err, "Set Sync Identity A"))
        goto cleanup;
    err = sm2_revocation_set_sync_identity(
        &b, (const uint8_t *)"NODE_B", 6, 1, 2048);
    if (!check_ic(err, "Set Sync Identity B"))
        goto cleanup;

    /* 2) Node A has a newer local revocation delta */
    err = sm2_revocation_apply_crl_delta(&a, &delta, 1010);
    if (!check_ic(err, "Apply Delta On A"))
        goto cleanup;

    /* 3) B sends hello, A computes sync plan */
    err = sm2_revocation_sync_hello(&b, 1020, &hello_b);
    if (!check_ic(err, "B Hello"))
        goto cleanup;

    err = sm2_revocation_sync_plan(&a, &hello_b, &plan_a2b);
    if (!check_ic(err, "A Plan For B"))
        goto cleanup;
    if (plan_a2b.action == SM2_REV_SYNC_ACTION_NONE)
    {
        printf("[FAIL] plan action is NONE, expected DELTA/FULL\n");
        goto cleanup;
    }

    /* 4) A exports signed packet, B verifies and applies */
    err = sm2_revocation_sync_export_delta(
        &a, &plan_a2b, 1021, 9001, demo_sign, &sig_state, &packet);
    if (!check_ic(err, "Export Delta Packet"))
        goto cleanup;

    err = sm2_revocation_sync_apply(&b, &packet, 1022, demo_verify, &sig_state);
    if (!check_ic(err, "Apply Delta Packet On B"))
        goto cleanup;

    /* 5) Verify revocation state converged on B */
    err = sm2_revocation_query(&b, 880001, 1023, &status, &source);
    if (!check_ic(err, "Query Serial 880001 On B"))
        goto cleanup;
    if (status != SM2_REV_STATUS_REVOKED)
    {
        printf("[FAIL] serial 880001 not revoked on B\n");
        goto cleanup;
    }

    err = sm2_revocation_query(&b, 880002, 1023, &status, &source);
    if (!check_ic(err, "Query Serial 880002 On B"))
        goto cleanup;
    if (status != SM2_REV_STATUS_REVOKED)
    {
        printf("[FAIL] serial 880002 not revoked on B\n");
        goto cleanup;
    }

    printf("[PASS] demo_test_sync_flow\n");
    sm2_revocation_sync_packet_cleanup(&packet);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    return 0;

cleanup:
    sm2_revocation_sync_packet_cleanup(&packet);
    sm2_revocation_cleanup(&b);
    sm2_revocation_cleanup(&a);
    return 1;
}
