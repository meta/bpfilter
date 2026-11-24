/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
}

/**
 * The flow_hash value from BPF_PROG_TEST_RUN is not deterministic.
 * Use UINT32_MAX as a value unlikely to match the actual hash,
 * verifying the eq path rejects non-matching values.
 */
static void meta_flow_hash_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // eq UINT32_MAX — extremely unlikely to match actual hash -> ACCEPT
    BFT_CHAIN_SET(
        bf::Chain("test_meta_fhash", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_HASH, BF_MATCHER_EQ,
                                 bft_u32_payload(UINT_MAX))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fhash", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_fhash", 0, 0, -1);

    // not eq UINT32_MAX should match since flow_hash is very unlikely to be
    // UINT32_MAX
    BFT_CHAIN_SET(
        bf::Chain("test_meta_fhash", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_HASH, BF_MATCHER_EQ,
                                 bft_u32_payload(UINT_MAX), true)},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fhash", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_fhash", 0, 1, -1);
}

/**
 * Range [0, UINT32_MAX] covers all possible hash values -> always matches.
 */
static void meta_flow_hash_range(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_meta_fhash", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_HASH, BF_MATCHER_RANGE,
                                 bft_u32_range(0, UINT_MAX))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fhash", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_fhash", 0, 1, -1);

    // Range [UINT_MAX, UINT_MAX] should not match
    BFT_CHAIN_SET(
        bf::Chain("test_meta_fhash", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_HASH, BF_MATCHER_RANGE,
                                 bft_u32_range(UINT_MAX, UINT_MAX))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fhash", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_fhash", 0, 0, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_FLOW_HASH);

    suite << MatcherTest(BF_MATCHER_META_FLOW_HASH, BF_MATCHER_EQ,
                         meta_flow_hash_eq);
    suite << MatcherTest(BF_MATCHER_META_FLOW_HASH, BF_MATCHER_RANGE,
                         meta_flow_hash_range);

    return suite.run();
}
