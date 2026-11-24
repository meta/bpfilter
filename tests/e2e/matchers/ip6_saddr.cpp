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
 * Verify ip6.saddr eq matches packets from the configured IPv6 source address
 * and rejects all others. Counter tracks only matching packets.
 */
static void ip6_saddr_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_ip6_saddr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                                           bft_ipv6_addr("2001:db8::1"))},
                              bf_counter()));

    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::3", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // saddr=2001:db8::1 with a truncated TCP header still matches -> DROP
    auto pkt =
        bft::Ethernet() / bft::IPv6 {.saddr = "2001:db8::1"} / bft::TCP {};
    pkt.len -= 1;
    bft_assert_prog_run("test_ip6_saddr", test->hook(), pkt,
                        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_saddr", 0, 2, -1);

    // Try with negation
    BFT_CHAIN_SET(bf::Chain("test_ip6_saddr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                                           bft_ipv6_addr("2001:db8::1"), true)},
                              bf_counter()));

    // saddr=2001:db8::1 matches, but negated -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // saddr=2001:db8::3 doesn't match, negated -> DROP
    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::3", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_saddr", 0, 1, -1);

    BFT_CHAIN_SET(bf::Chain("test_ip6_saddr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                                           bft_ipv6_addr("2001:db8::1"), true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::3", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_saddr", 0, 1, -1);
}

/**
 * Verify ip6.saddr in {set} matches packets whose IPv6 source address is a
 * member of the set and rejects packets with addresses outside the set.
 * Counter tracks only matching packets.
 */
static void ip6_saddr_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP6_SADDR});
    set << bft_ipv6_addr("2001:db8::1") << bft_ipv6_addr("2001:db8::2");

    BFT_CHAIN_SET(
        bf::Chain("test_ip6_saddr", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=2001:db8::2 is also in set -> DROP
    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::2", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_prog_run(
        "test_ip6_saddr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::3", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_saddr", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP6_SADDR);

    suite << MatcherTest(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ, ip6_saddr_eq);
    suite << MatcherTest(BF_MATCHER_IP6_SADDR, BF_MATCHER_IN, ip6_saddr_in);

    return suite.run();
}
