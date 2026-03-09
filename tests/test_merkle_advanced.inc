{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;

    uint64_t revoked[2048];
    for (size_t i = 0; i < 2048; i++)
        revoked[i] = 200000 + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030604ULL)
            == SM2_IC_SUCCESS,
        "Build Tree");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_epoch_dir_t *dir = NULL;
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    tree, 42, 8, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    uint8_t dir_buf[262144];
    size_t dir_len = sizeof(dir_buf);
    TEST_ASSERT(
        sm2_rev_epoch_dir_encode(dir, dir_buf, &dir_len) == SM2_IC_SUCCESS,
        "Epoch Directory Encode");

    sm2_rev_epoch_dir_t *dir_dec = NULL;
    TEST_ASSERT(
        sm2_rev_epoch_dir_decode(&dir_dec, dir_buf, dir_len) == SM2_IC_SUCCESS,
        "Epoch Directory Decode");

    TEST_ASSERT(
        sm2_rev_epoch_dir_verify(dir_dec, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Epoch Directory Verify");

    uint64_t target = revoked[777];
    sm2_rev_member_proof_t full;
    TEST_ASSERT(
        sm2_rev_tree_prove_member(tree, target, &full) == SM2_IC_SUCCESS,
        "Full Member Proof");

    sm2_rev_cached_member_proof_t cached;
    TEST_ASSERT(sm2_rev_epoch_prove_member_cached(tree, target, 8, &cached)
            == SM2_IC_SUCCESS,
        "Cached Member Proof");

    uint8_t full_buf[8192];
    size_t full_len = sizeof(full_buf);
    TEST_ASSERT(sm2_rev_member_proof_encode(&full, full_buf, &full_len)
            == SM2_IC_SUCCESS,
        "Full Proof Encode");

    uint8_t cached_buf[8192];
    size_t cached_len = sizeof(cached_buf);
    TEST_ASSERT(
        sm2_rev_cached_member_proof_encode(&cached, cached_buf, &cached_len)
            == SM2_IC_SUCCESS,
        "Cached Proof Encode");

    sm2_rev_cached_member_proof_t cached_dec;
    TEST_ASSERT(
        sm2_rev_cached_member_proof_decode(&cached_dec, cached_buf, cached_len)
            == SM2_IC_SUCCESS,
        "Cached Proof Decode");

    TEST_ASSERT(sm2_rev_epoch_verify_member_cached(
                    dir_dec, 1500, &cached_dec, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Cached Proof Verify");

    double reduction = 1.0 - ((double)cached_len / (double)full_len);
    printf("   [EPOCH-CACHE] full=%zu, cached=%zu, reduction=%.2f%%\n",
        full_len, cached_len, reduction * 100.0);
    TEST_ASSERT(reduction >= 0.40, "Epoch Cache Reduction < 40%");

    sm2_rev_epoch_dir_cleanup(&dir_dec);
    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_epoch_patch_priority()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;

    uint64_t revoked[] = { 900001, 900002, 900003 };
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 501)
            == SM2_IC_SUCCESS,
        "Build Tree");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_epoch_dir_t *dir = NULL;
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    tree, 50, 6, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    sm2_crl_delta_item_t patch1[] = { { 999999, true } };
    TEST_ASSERT(sm2_rev_epoch_apply_patch(
                    dir, 1, patch1, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Apply Patch v1");

    sm2_rev_status_t st;
    TEST_ASSERT(sm2_rev_epoch_lookup(
                    dir, 1500, 999999, merkle_ca_verify_cb, &sig_ctx, &st)
            == SM2_IC_SUCCESS,
        "Patch Query v1");
    TEST_ASSERT(st == SM2_REV_STATUS_REVOKED, "Patch Priority Revoked");

    sm2_crl_delta_item_t patch2[] = { { 999999, false } };
    TEST_ASSERT(sm2_rev_epoch_apply_patch(
                    dir, 2, patch2, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Apply Epoch Patch");
    TEST_ASSERT(sm2_rev_epoch_lookup(
                    dir, 1500, 999999, merkle_ca_verify_cb, &sig_ctx, &st)
            == SM2_IC_SUCCESS,
        "Epoch Lookup Updated");
    TEST_ASSERT(st == SM2_REV_STATUS_GOOD, "Patch Override Good");

    TEST_ASSERT(sm2_rev_epoch_apply_patch(
                    dir, 2, patch1, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Patch Version Monotonic");

    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_epoch_switch_monotonic()
{
    if (!g_ca_initialized)
        test_setup_ca();

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };

    sm2_rev_tree_t *t1 = NULL;
    sm2_rev_tree_t *t2 = NULL;

    uint64_t revoked1[] = { 1001, 1002, 1003 };
    uint64_t revoked2[] = { 1001, 1002, 1003, 1004, 1005 };

    TEST_ASSERT(sm2_rev_tree_build(
                    &t1, revoked1, sizeof(revoked1) / sizeof(revoked1[0]), 10)
            == SM2_IC_SUCCESS,
        "Build T1");
    TEST_ASSERT(sm2_rev_tree_build(
                    &t2, revoked2, sizeof(revoked2) / sizeof(revoked2[0]), 11)
            == SM2_IC_SUCCESS,
        "Build T2");

    sm2_rev_epoch_dir_t *d1 = NULL;
    sm2_rev_epoch_dir_t *d2 = NULL;
    sm2_rev_epoch_dir_t *local = NULL;

    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    t1, 60, 4, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d1)
            == SM2_IC_SUCCESS,
        "Build D1");
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    t2, 61, 4, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d2)
            == SM2_IC_SUCCESS,
        "Build D2");

    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D1");
    TEST_ASSERT(local != NULL, "Local Directory Materialized");
    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d2, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D2");
    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Older Epoch");

    sm2_rev_epoch_dir_cleanup(&local);
    sm2_rev_epoch_dir_cleanup(&d2);
    sm2_rev_epoch_dir_cleanup(&d1);
    sm2_rev_tree_cleanup(&t2);
    sm2_rev_tree_cleanup(&t1);
    TEST_PASS();
}
static void test_rev_kanon_query_baseline()
{
    sm2_rev_kanon_query_t query;
    uint64_t real = 700001;
    uint64_t decoys[]
        = { 700010, 700011, 700012, 700013, 700014, 700015, 700016, 700001 };

    TEST_ASSERT(sm2_rev_kanon_build_query(real, decoys,
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
    TEST_ASSERT(sm2_rev_kanon_export_serials(&query, wire_serials, &wire_count)
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

static void test_rev_kanon_export_min_metadata()
{
    sm2_rev_kanon_query_t query;
    uint64_t real = 800001;
    uint64_t decoys[] = { 800010, 800011, 800012, 800013 };

    TEST_ASSERT(sm2_rev_kanon_build_query(real, decoys,
                    sizeof(decoys) / sizeof(decoys[0]), 4, 0x5678, &query)
            == SM2_IC_SUCCESS,
        "Build K-Anon Query 4");

    uint64_t too_small[2];
    size_t small_count = sizeof(too_small) / sizeof(too_small[0]);
    TEST_ASSERT(sm2_rev_kanon_export_serials(&query, too_small, &small_count)
            == SM2_IC_ERR_MEMORY,
        "Export Size Probe");
    TEST_ASSERT(small_count == 4, "Required Count Returned");

    uint64_t exact[4];
    size_t exact_count = sizeof(exact) / sizeof(exact[0]);
    TEST_ASSERT(sm2_rev_kanon_export_serials(&query, exact, &exact_count)
            == SM2_IC_SUCCESS,
        "Export Exact Buffer");
    TEST_ASSERT(exact_count == 4, "Exact Count");
    TEST_PASS();
}

static void test_rev_kanon_policy_tradeoff()
{
    sm2_rev_tree_t *tree = NULL;

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

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked, revoked_n, 2026030605ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build For K-Anon Tradeoff");

    const uint8_t clusters[3] = { 0, 50, 100 };
    size_t proof_bytes[3] = { 0, 0, 0 };
    double risks[3] = { 0.0, 0.0, 0.0 };
    uint64_t spans[3] = { 0, 0, 0 };

    for (size_t i = 0; i < 3; i++)
    {
        sm2_rev_kanon_query_t query;
        sm2_rev_kanon_policy_t policy;
        sm2_rev_multi_proof_t *mp = NULL;
        uint8_t mp_buf[262144];
        size_t mp_len = sizeof(mp_buf);

        memset(&policy, 0, sizeof(policy));
        policy.cluster_level = clusters[i];

        TEST_ASSERT(sm2_rev_kanon_build_query_with_policy(real, decoys,
                        decoy_count, k, 0xA55A5AA5ULL, &policy, &query)
                == SM2_IC_SUCCESS,
            "Build K-Anon Query With Policy");
        TEST_ASSERT(sm2_rev_multi_proof_build(
                        tree, query.serials, query.serial_count, &mp)
                == SM2_IC_SUCCESS,
            "Build K-Anon MultiProof");
        TEST_ASSERT(
            sm2_rev_multi_proof_encode(mp, mp_buf, &mp_len) == SM2_IC_SUCCESS,
            "Encode K-Anon MultiProof");
        TEST_ASSERT(
            sm2_rev_kanon_estimate_risk(&query, real, &risks[i], &spans[i])
                == SM2_IC_SUCCESS,
            "Estimate K-Anon Risk");

        proof_bytes[i] = mp_len;
        printf("   [K-ANON-TRADEOFF] cluster=%u, proof=%zu, span=%llu, "
               "risk=%.6f\n",
            (unsigned)clusters[i], mp_len, (unsigned long long)spans[i],
            risks[i]);

        sm2_rev_multi_proof_cleanup(&mp);
    }

    TEST_ASSERT(
        proof_bytes[2] <= proof_bytes[0], "Cluster100 Proof Not Smaller");
    TEST_ASSERT(spans[2] <= spans[0], "Cluster100 Span Not Smaller");
    TEST_ASSERT(risks[2] >= risks[0], "Cluster100 Risk Not Higher");

    sm2_rev_tree_cleanup(&tree);
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

static void test_rev_multi_proof_dynamic_growth_path()
{
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];

    uint64_t revoked[2048];
    for (size_t i = 0; i < sizeof(revoked) / sizeof(revoked[0]); i++)
        revoked[i] = 910000ULL + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030701ULL)
            == SM2_IC_SUCCESS,
        "Build Tree For Dynamic Growth");
    merkle_read_root_hash_or_fail(tree, root_hash);

    uint64_t query = revoked[1024];
    sm2_rev_multi_proof_t *mp = NULL;

    TEST_ASSERT(
        sm2_rev_multi_proof_build(tree, &query, 1, &mp) == SM2_IC_SUCCESS,
        "Build MultiProof Dynamic Growth");
    TEST_ASSERT(sm2_rev_multi_proof_query_count(mp) == 1, "Query Count");
    TEST_ASSERT(sm2_rev_multi_proof_unique_hash_count(mp) > 1,
        "Dynamic Growth Triggered");
    TEST_ASSERT(sm2_rev_multi_proof_verify(root_hash, mp) == SM2_IC_SUCCESS,
        "Verify Dynamic Growth MultiProof");

    sm2_rev_multi_proof_cleanup(&mp);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_kanon_risk_weights_effective()
{
    uint64_t real = 920000ULL;
    uint64_t decoys[64];
    for (size_t i = 0; i < sizeof(decoys) / sizeof(decoys[0]); i++)
        decoys[i] = real + 1ULL + (uint64_t)i;

    sm2_rev_kanon_query_t q_default, q_weighted;
    sm2_rev_kanon_policy_t p_default, p_weighted;
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

    TEST_ASSERT(sm2_rev_kanon_build_query_with_policy(real, decoys,
                    sizeof(decoys) / sizeof(decoys[0]), 16, 0x11223344,
                    &p_default, &q_default)
            == SM2_IC_SUCCESS,
        "Build Default Weight Query");
    TEST_ASSERT(sm2_rev_kanon_build_query_with_policy(real, decoys,
                    sizeof(decoys) / sizeof(decoys[0]), 16, 0x11223344,
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
    TEST_ASSERT(sm2_rev_kanon_estimate_risk(
                    &q_default, real, &risk_default, &span_default)
            == SM2_IC_SUCCESS,
        "Estimate Default Risk");
    TEST_ASSERT(sm2_rev_kanon_estimate_risk(
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

static void test_rev_kanon_candidate_window_limit()
{
    uint64_t real = 930000ULL;
    uint64_t decoys[256];
    const size_t narrow_window = 10;

    for (size_t i = 0; i < narrow_window; i++)
        decoys[i] = real + 10000ULL + (uint64_t)(i * 100U);
    for (size_t i = narrow_window; i < sizeof(decoys) / sizeof(decoys[0]); i++)
        decoys[i] = real + 1ULL + (uint64_t)(i - narrow_window);

    sm2_rev_kanon_policy_t p_narrow, p_full;
    sm2_rev_kanon_query_t q_narrow, q_full;
    memset(&p_narrow, 0, sizeof(p_narrow));
    memset(&p_full, 0, sizeof(p_full));
    memset(&q_narrow, 0, sizeof(q_narrow));
    memset(&q_full, 0, sizeof(q_full));

    p_narrow.cluster_level = 100;
    p_narrow.candidate_scan_limit = (uint16_t)narrow_window;
    p_full.cluster_level = 100;
    p_full.candidate_scan_limit = 0;

    TEST_ASSERT(sm2_rev_kanon_build_query_with_policy(real, decoys,
                    sizeof(decoys) / sizeof(decoys[0]), 8, 0x55667788,
                    &p_narrow, &q_narrow)
            == SM2_IC_SUCCESS,
        "Build Narrow Window Query");
    TEST_ASSERT(
        sm2_rev_kanon_build_query_with_policy(real, decoys,
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
    TEST_ASSERT(
        sm2_rev_kanon_estimate_risk(&q_narrow, real, &risk_narrow, &span_narrow)
            == SM2_IC_SUCCESS,
        "Estimate Narrow Risk");
    TEST_ASSERT(
        sm2_rev_kanon_estimate_risk(&q_full, real, &risk_full, &span_full)
            == SM2_IC_SUCCESS,
        "Estimate Full Risk");
    TEST_ASSERT(span_narrow > span_full, "Narrow Window Should Increase Span");
    TEST_PASS();
}
static void test_rev_phase8_metric_bundle()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;

    enum
    {
        revoked_n = 2048,
        k = 16
    };

    uint64_t *revoked = (uint64_t *)calloc(revoked_n, sizeof(uint64_t));
    TEST_ASSERT(revoked != NULL, "Alloc Metric Tree Data");
    for (size_t i = 0; i < revoked_n; i++)
        revoked[i] = 600000ULL + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked, revoked_n, 2026030606ULL)
            == SM2_IC_SUCCESS,
        "Build Metric Tree");

    uint64_t queries[k];
    for (size_t i = 0; i < k; i++)
        queries[i] = revoked[900 + i];

    sm2_rev_multi_proof_t *mp = NULL;
    TEST_ASSERT(
        sm2_rev_multi_proof_build(tree, queries, k, &mp) == SM2_IC_SUCCESS,
        "Build Metric MultiProof");

    uint8_t mp_buf[262144];
    size_t mp_len = sizeof(mp_buf);
    TEST_ASSERT(
        sm2_rev_multi_proof_encode(mp, mp_buf, &mp_len) == SM2_IC_SUCCESS,
        "Encode Metric MultiProof");

    size_t single_total = 0;
    size_t sibling_refs = 0;
    for (size_t i = 0; i < k; i++)
    {
        sm2_rev_member_proof_t member;
        uint8_t single_buf[8192];
        size_t single_len = sizeof(single_buf);

        TEST_ASSERT(sm2_rev_tree_prove_member(tree, queries[i], &member)
                == SM2_IC_SUCCESS,
            "Build Single Proof");
        TEST_ASSERT(
            sm2_rev_member_proof_encode(&member, single_buf, &single_len)
                == SM2_IC_SUCCESS,
            "Encode Single Proof");

        single_total += single_len;
        sibling_refs += member.sibling_count;
    }

    TEST_ASSERT(single_total > 0, "Metric Single Total Zero");
    TEST_ASSERT(sibling_refs > 0, "Metric Sibling Refs Zero");
    TEST_ASSERT(sm2_rev_multi_proof_unique_hash_count(mp) <= sibling_refs,
        "Unique Hashes Overflow");

    double reuse_rate = 1.0
        - ((double)sm2_rev_multi_proof_unique_hash_count(mp)
            / (double)sibling_refs);
    double bandwidth_gain = 1.0 - ((double)mp_len / (double)single_total);

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_epoch_dir_t *dir = NULL;
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    tree, 66, 8, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Metric Epoch Directory");

    sm2_rev_member_proof_t full;
    sm2_rev_cached_member_proof_t cached;
    TEST_ASSERT(
        sm2_rev_tree_prove_member(tree, queries[0], &full) == SM2_IC_SUCCESS,
        "Build Full Proof For Cache");
    TEST_ASSERT(sm2_rev_epoch_prove_member_cached(tree, queries[0], 8, &cached)
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

    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_multi_proof_cleanup(&mp);
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    TEST_PASS();
}
/* ----- Negative / Boundary Tests (Phase 3 hardening) ----- */
