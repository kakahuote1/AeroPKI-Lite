/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

static void test_revocation_delta_and_cuckoo()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 64, 300, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");

    sm2_crl_delta_item_t delta_items[] = { { 1001, true }, { 1002, true } };
    sm2_crl_delta_t d1 = { 0, 1, delta_items, 2 };
    TEST_ASSERT(
        sm2_revocation_apply_crl_delta(&ctx, &d1, 120) == SM2_IC_SUCCESS,
        "Apply Delta 1");
    TEST_ASSERT(sm2_revocation_crl_version(&ctx) == 1, "Version 1");
    TEST_ASSERT(sm2_revocation_local_count(&ctx) == 2, "Local Count 2");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 1001, 130, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Revoked");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "1001 Revoked");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER, "Source Local");

    TEST_ASSERT(sm2_revocation_query(&ctx, 2000, 130, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Good");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "2000 Good");

    sm2_crl_delta_item_t delta_items2[] = { { 1001, false } };
    sm2_crl_delta_t d2 = { 1, 2, delta_items2, 1 };
    TEST_ASSERT(
        sm2_revocation_apply_crl_delta(&ctx, &d2, 140) == SM2_IC_SUCCESS,
        "Apply Delta 2");
    TEST_ASSERT(sm2_revocation_crl_version(&ctx) == 2, "Version 2");

    TEST_ASSERT(sm2_revocation_query(&ctx, 1001, 145, &status, &source)
            == SM2_IC_SUCCESS,
        "Query 1001 Removed");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "1001 Good After Remove");

    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_ttl_expire()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 32, 10, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");

    sm2_crl_delta_item_t items[] = { { 3333, true } };
    sm2_crl_delta_t d = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 105) == SM2_IC_SUCCESS,
        "Apply Delta");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_revocation_query(&ctx, 3333, 110, &status, &source)
            == SM2_IC_SUCCESS,
        "Query Before TTL");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Revoked Before TTL");

    TEST_ASSERT(sm2_revocation_query(&ctx, 3333, 116, &status, &source)
            == SM2_IC_SUCCESS,
        "Query After TTL");
    TEST_ASSERT(status == SM2_REV_STATUS_UNKNOWN, "Unknown After TTL");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_FILTER_STALE, "Stale Source");

    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_false_positive_rate()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 4096, 3600, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");

    enum
    {
        revoked_n = 2000
    };
    sm2_crl_delta_item_t *items = (sm2_crl_delta_item_t *)calloc(
        revoked_n, sizeof(sm2_crl_delta_item_t));
    TEST_ASSERT(items != NULL, "Alloc Delta Items");

    for (int i = 0; i < revoked_n; i++)
    {
        items[i].serial_number = (uint64_t)(100000 + i);
        items[i].revoked = true;
    }
    sm2_crl_delta_t d = { 0, 1, items, revoked_n };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 110) == SM2_IC_SUCCESS,
        "Apply Large Delta");

    enum
    {
        query_n = 50000
    };
    int false_positive = 0;
    for (int i = 0; i < query_n; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        uint64_t serial
            = (uint64_t)(500000 + i); /* disjoint from revoked range */
        TEST_ASSERT(sm2_revocation_query(&ctx, serial, 200, &status, &source)
                == SM2_IC_SUCCESS,
            "Query Non Member");
        if (status == SM2_REV_STATUS_REVOKED)
            false_positive++;
    }

    double fpr = (double)false_positive / (double)query_n;
    printf("   [CF-FPR] fp=%d/%d (%.6f)\n", false_positive, query_n, fpr);
    TEST_ASSERT(fpr <= 0.01, "False Positive Rate > 1%");

    free(items);
    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_false_positive_rate_constrained()
{
    sm2_revocation_ctx_t ctx;
    TEST_ASSERT(sm2_revocation_init(&ctx, 64, 3600, 100) == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_revocation_set_online(&ctx, false) == SM2_IC_SUCCESS,
        "Set Offline");
    TEST_ASSERT(
        sm2_revocation_config_local_filter(&ctx, 12, 4, 500) == SM2_IC_SUCCESS,
        "Constrained Filter Config");

    enum
    {
        revoked_n = 300
    };
    sm2_crl_delta_item_t *items = (sm2_crl_delta_item_t *)calloc(
        revoked_n, sizeof(sm2_crl_delta_item_t));
    TEST_ASSERT(items != NULL, "Alloc Delta Items");
    for (int i = 0; i < revoked_n; i++)
    {
        items[i].serial_number = (uint64_t)(700000 + i);
        items[i].revoked = true;
    }
    sm2_crl_delta_t d = { 0, 1, items, revoked_n };
    TEST_ASSERT(sm2_revocation_apply_crl_delta(&ctx, &d, 110) == SM2_IC_SUCCESS,
        "Apply Constrained Delta");

    enum
    {
        query_n = 50000
    };
    int false_positive = 0;
    for (int i = 0; i < query_n; i++)
    {
        sm2_rev_status_t status;
        sm2_rev_source_t source;
        uint64_t serial = (uint64_t)(900000 + i);
        TEST_ASSERT(sm2_revocation_query(&ctx, serial, 200, &status, &source)
                == SM2_IC_SUCCESS,
            "Constrained Query");
        if (status == SM2_REV_STATUS_REVOKED)
            false_positive++;
    }

    double fpr = (double)false_positive / (double)query_n;
    printf("   [CF-FPR-CONSTRAINED] fp=%d/%d (%.6f)\n", false_positive, query_n,
        fpr);
    TEST_ASSERT(false_positive > 0, "Constrained FP Should Be Observable");
    TEST_ASSERT(fpr <= 0.05, "Constrained FPR > 5%");

    free(items);
    sm2_revocation_cleanup(&ctx);
    TEST_PASS();
}

void run_test_cuckoo_suite(void)
{
    RUN_TEST(test_revocation_delta_and_cuckoo);
    RUN_TEST(test_revocation_ttl_expire);
    RUN_TEST(test_revocation_false_positive_rate);
    RUN_TEST(test_revocation_false_positive_rate_constrained);
}
