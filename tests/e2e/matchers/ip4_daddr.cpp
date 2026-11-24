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
 * Verify ip4.daddr eq matches packets to the configured destination address
 * and rejects all others. Counter tracks only matching packets.
 */
static void ip4_daddr_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_ip4_daddr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                                           {192, 0, 2, 2})},
                              bf_counter()));

    bft_assert_prog_run(
        "test_ip4_daddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_prog_run(
        "test_ip4_daddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.3"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_daddr", 0, 1, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_ip4_daddr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                                           {192, 0, 2, 2}, true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_ip4_daddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_prog_run(
        "test_ip4_daddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.3"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_daddr", 0, 1, -1);
}

/**
 * Verify ip4.daddr in {set} matches packets whose destination address is a
 * member of the set and rejects packets with addresses outside the set.
 * Counter tracks only matching packets.
 */
static void ip4_daddr_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP4_DADDR});
    set << std::vector<uint8_t> {192, 0, 2, 2}
        << std::vector<uint8_t> {192, 0, 2, 3};

    BFT_CHAIN_SET(
        bf::Chain("test_ip4_daddr", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    bft_assert_prog_run(
        "test_ip4_daddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=192.0.2.3 is also in set -> DROP
    bft_assert_prog_run(
        "test_ip4_daddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.3"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_prog_run(
        "test_ip4_daddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.4"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_daddr", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP4_DADDR);

    suite << MatcherTest(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ, ip4_daddr_eq);
    suite << MatcherTest(BF_MATCHER_IP4_DADDR, BF_MATCHER_IN, ip4_daddr_in);

    return suite.run();
}
