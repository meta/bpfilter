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
 * Verify that icmp.code eq N matches a packet with ICMP code N and
 * does not match a packet with a different code. Also verifies the
 * protocol guard: a TCP packet must not match an ICMP rule regardless
 * of what bytes happen to sit at the ICMP code offset. Counter must be
 * updated only for the matching packet.
 */
static void icmp_code_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_icmp_code", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ, {3})},
                    bf_counter()));

    // ICMP code=3 should match the rule -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 3},
        test->verdictDrop());

    // ICMP code=0 should not match -> ACCEPT (policy)
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictAccept());

    // TCP packet must not match an ICMP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_code", 0, 1, -1);

    // Try with negation
    BFT_CHAIN_SET(bf::Chain("test_icmp_code", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ,
                                           {3}, true)},
                              bf_counter()));

    // ICMP code=3 should NOT match the rule -> ACCEPT (policy)
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 3},
        test->verdictAccept());

    // ICMP code=0 should match -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictDrop());

    // TCP packet must not match an ICMP rule (protocol guard) -> ACCEPT
    // This does not change for matcher negation
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_code", 0, 1, -1);

    BFT_CHAIN_SET(bf::Chain("test_icmp_code", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ,
                                           {3}, true)},
                              bf_counter()));

    // ICMP code=3 should not match -> ACCEPT (policy)
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 3},
        test->verdictAccept());

    // ICMP code=0 should match -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictDrop());

    // TCP packet must not match an ICMP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_code", 0, 1, -1);
}

/**
 * Verify that icmp.code in {set} matches packets whose code is in the
 * set and does not match packets with codes outside the set.
 */
static void icmp_code_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_ICMP_CODE});
    set << std::vector<uint8_t> {3} << std::vector<uint8_t> {0};

    BFT_CHAIN_SET(
        bf::Chain("test_icmp_code", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    // ICMP code=3 is in set -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 3},
        test->verdictDrop());

    // ICMP code=0 is also in set -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictDrop());

    // ICMP code=5 is not in set -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 5},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_code", 0, 2, -1);

    // Try with negation
    BFT_CHAIN_SET(bf::Chain("test_icmp_code", test->hook(), BF_VERDICT_ACCEPT)
                  << set
                  << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set, true)},
                              bf_counter()));

    // ICMP code=3 is in set so negation is -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 3},
        test->verdictAccept());

    // ICMP code=0 is also in set so negation is -> ACCEPT
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictAccept());

    // ICMP code=5 is not in set so negation is -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 5},
        test->verdictDrop());

    bft_assert_counter_eq("test_icmp_code", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_ICMP_CODE);

    suite << MatcherTest(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ, icmp_code_eq);
    suite << MatcherTest(BF_MATCHER_ICMP_CODE, BF_MATCHER_IN, icmp_code_in);

    return suite.run();
}
