/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "Set.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
}

/**
 * Verify that icmp.type eq N matches a packet with ICMP type N and
 * does not match a packet with a different type. Also verifies the
 * protocol guard: a TCP packet must not match an ICMP rule. Counter
 * must be updated only for the matching packet.
 */
static void icmp_type_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_icmp_type", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ, {8})},
                    bf_counter()));

    // ICMP type=8 (echo request) should match the rule -> DROP
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictDrop());

    // ICMP type=0 (echo reply) should not match -> ACCEPT (policy)
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 0, .code = 0},
        test->verdictAccept());

    // TCP packet must not match an ICMP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_type", 0, 1, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_icmp_type", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ,
                                           {8}, true)},
                              bf_counter()));

    // ICMP type=8 should not match -> ACCEPT (policy)
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictAccept());

    // ICMP type=0 should match -> DROP
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 0, .code = 0},
        test->verdictDrop());

    // TCP packet must not match an ICMP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_type", 0, 1, -1);
}

/**
 * Verify that icmp.type in {set} matches packets whose type is in the
 * set and does not match packets with types outside the set.
 */
static void icmp_type_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_ICMP_TYPE});
    set << std::vector<uint8_t> {8} << std::vector<uint8_t> {0};

    BFT_CHAIN_SET(
        bf::Chain("test_icmp_type", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    // ICMP type=8 is in set -> DROP
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictDrop());

    // ICMP type=0 is also in set -> DROP
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 0, .code = 0},
        test->verdictDrop());

    // ICMP type=3 is not in set -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_type", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 3, .code = 0},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_type", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_ICMP_TYPE);

    suite << MatcherTest(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ, icmp_type_eq);
    suite << MatcherTest(BF_MATCHER_ICMP_TYPE, BF_MATCHER_IN, icmp_type_in);

    return suite.run();
}
