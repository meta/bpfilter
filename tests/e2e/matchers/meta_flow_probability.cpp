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
 * Verify meta.flow_probability eq at 100% always matches and at 0% never
 * matches. Also verifies the protocol guard: an ICMP packet must not match
 * since the matcher requires a TCP or UDP flow hash and skips non-TCP/UDP
 * traffic.
 */
static void meta_flow_probability_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // 100.0f always matches
    BFT_CHAIN_SET(
        bf::Chain("test_meta_fprob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_PROBABILITY,
                                 BF_MATCHER_EQ, bft_float_payload(100.0f))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fprob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_fprob", 0, 1, -1);

    // 0.0f should never match
    BFT_CHAIN_SET(
        bf::Chain("test_meta_fprob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_PROBABILITY,
                                 BF_MATCHER_EQ, bft_float_payload(0.0f))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fprob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_fprob", 0, 0, -1);

    // Negated 100.0f should never match
    BFT_CHAIN_SET(bf::Chain("test_meta_fprob", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_META_FLOW_PROBABILITY,
                                           BF_MATCHER_EQ,
                                           bft_float_payload(100.0f), true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_meta_fprob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_fprob", 0, 0, -1);

    // Negated 0.0f should always match
    BFT_CHAIN_SET(
        bf::Chain("test_meta_fprob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_PROBABILITY,
                                 BF_MATCHER_EQ, bft_float_payload(0.0f), true)},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fprob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_fprob", 0, 1, -1);

    // meta_flow_probability explicitly guards against non-TCP/UDP L4: an ICMP
    // packet must be skipped (jumps to next rule) and the drop verdict must
    // not fire even at 100% probability.
    BFT_CHAIN_SET(
        bf::Chain("test_meta_fprob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_FLOW_PROBABILITY,
                                 BF_MATCHER_EQ, bft_float_payload(100.0f))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_fprob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_fprob", 0, 0, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_FLOW_PROBABILITY);

    suite << MatcherTest(BF_MATCHER_META_FLOW_PROBABILITY, BF_MATCHER_EQ,
                         meta_flow_probability_eq);

    return suite.run();
}
