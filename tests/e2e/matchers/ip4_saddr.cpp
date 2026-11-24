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
 * Verify ip4.saddr eq matches packets from the configured source address
 * and rejects all others. Counter tracks only matching packets.
 */
static void ip4_saddr_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_ip4_saddr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                                           {192, 0, 2, 1})},
                              bf_counter()));

    // saddr=192.0.2.1 should match -> DROP
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=192.0.2.3 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.3", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_saddr", 0, 1, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_ip4_saddr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                                           {192, 0, 2, 1}, true)},
                              bf_counter()));

    // saddr=192.0.2.1 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // saddr=192.0.2.3 should match -> DROP
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.3", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_saddr", 0, 1, -1);
}

/**
 * Verify ip4.saddr in {set} matches packets whose source address is a member
 * of the set and rejects packets with addresses outside the set. Counter
 * tracks only matching packets.
 */
static void ip4_saddr_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP4_SADDR});
    set << std::vector<uint8_t> {192, 0, 2, 1}
        << std::vector<uint8_t> {192, 0, 2, 2};

    BFT_CHAIN_SET(
        bf::Chain("test_ip4_saddr", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    // saddr=192.0.2.1 is in set -> DROP
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=192.0.2.2 is also in set -> DROP
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.2", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=192.0.2.3 is not in set -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.3", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_saddr", 0, 2, -1);

    // "not in" on an empty set matches the packet
    auto empty_set = bf::Set({BF_MATCHER_IP4_SADDR});
    BFT_CHAIN_SET(bf::Chain("test_ip4_saddr", test->hook(), BF_VERDICT_ACCEPT)
                  << empty_set
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher::in(empty_set, true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // Packets without an IPv4 source address are not matched
    bft_assert_prog_run(
        "test_ip4_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_saddr", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP4_SADDR);

    suite << MatcherTest(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ, ip4_saddr_eq);
    suite << MatcherTest(BF_MATCHER_IP4_SADDR, BF_MATCHER_IN, ip4_saddr_in);

    return suite.run();
}
