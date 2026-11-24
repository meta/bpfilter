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
 * Verify meta.mark eq matches packets whose skb mark equals the configured
 * value. BPF_PROG_TEST_RUN always provides mark=0, so the test uses that
 * known value to confirm a match and a non-zero value to confirm a non-match.
 */
static void meta_mark_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // BPF_PROG_TEST_RUN gives mark=0; match eq 0
    BFT_CHAIN_SET(bf::Chain("test_meta_mark", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_META_MARK, BF_MATCHER_EQ,
                                           bft_u32_payload(0))},
                              bf_counter()));

    // mark=0 matches eq 0 -> DROP
    bft_assert_prog_run(
        "test_meta_mark", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_mark", 0, 1, -1);

    // eq 42 should not match since mark is 0
    BFT_CHAIN_SET(bf::Chain("test_meta_mark", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_META_MARK, BF_MATCHER_EQ,
                                           bft_u32_payload(42))},
                              bf_counter()));

    bft_assert_prog_run(
        "test_meta_mark", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_mark", 0, 0, -1);

    // not eq 0 should NOT match since mark=0
    BFT_CHAIN_SET(bf::Chain("test_meta_mark", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_META_MARK, BF_MATCHER_EQ,
                                           bft_u32_payload(0), true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_meta_mark", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_mark", 0, 0, -1);

    // not eq 42 should match since mark=0 != 42
    BFT_CHAIN_SET(bf::Chain("test_meta_mark", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_META_MARK, BF_MATCHER_EQ,
                                           bft_u32_payload(42), true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_meta_mark", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_mark", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_MARK);

    suite << MatcherTest(BF_MATCHER_META_MARK, BF_MATCHER_EQ, meta_mark_eq);

    return suite.run();
}
