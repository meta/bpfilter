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
 * Verify ip6.dnet eq matches packets whose IPv6 destination address falls
 * within the configured prefix and rejects those outside. Exercises the /32,
 * /128 (no-masking code path), and /0 (match-all) prefix lengths.
 */
static void ip6_dnet_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_ip6_dnet", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                           bft_ip6_lpm_key(32, "2001:db8::"))},
                              bf_counter()));

    // daddr=2001:db8::2 is in 2001:db8::/32 -> DROP
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=2001:db8:: (network base address) is in 2001:db8::/32 -> DROP
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=2001:db9::2 is not in 2001:db8::/32 -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db9::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_dnet", 0, 2, -1);

    // /128 (single host): exercises the no-masking code path.
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                 bft_ip6_lpm_key(128, "2001:db8::2"))},
                    bf_counter()));

    // daddr=2001:db8::2 exactly matches the /128 -> DROP
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=2001:db8::3 does not match the /128 -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::3"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_dnet", 0, 1, -1);

    // /0 (match all): any destination address matches.
    BFT_CHAIN_SET(bf::Chain("test_ip6_dnet", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                           bft_ip6_lpm_key(0, "::"))},
                              bf_counter()));

    // any daddr matches /0 -> DROP
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "fe80::1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_dnet", 0, 1, -1);

    // Negation: /32 not eq
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                 bft_ip6_lpm_key(32, "2001:db8::"), true)},
                    bf_counter()));

    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db9::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_dnet", 0, 1, -1);

    // /128 not eq: daddr matching the exact host -> does not match ->
    // ACCEPT; daddr differing by one bit -> matches -> DROP. Exercises the
    // no-masking code path.
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                 bft_ip6_lpm_key(128, "2001:db8::2"), true)},
                    bf_counter()));

    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::3"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_dnet", 0, 1, -1);

    // /0 not eq: /0 covers the entire address space; not eq /0 never
    // matches.
    BFT_CHAIN_SET(bf::Chain("test_ip6_dnet", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                           bft_ip6_lpm_key(0, "::"), true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "fe80::1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_dnet", 0, 0, -1);
}

/**
 * Verify ip6.dnet in {set} matches packets whose IPv6 destination address
 * falls within any prefix in the set and rejects those outside all set
 * members.
 */
static void ip6_dnet_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP6_DNET});
    set << bft_ip6_lpm_key(32, "2001:db8::") << bft_ip6_lpm_key(64, "fd00::");

    BFT_CHAIN_SET(
        bf::Chain("test_ip6_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    // daddr=fd00::1 matches fd00::/64 in set -> DROP
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "fd00::1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=2001:db8::2 matches 2001:db8::/32 (first set element) -> DROP
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=fe80::1 not in any set subnet -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "fe80::1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_dnet", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP6_DNET);

    suite << MatcherTest(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ, ip6_dnet_eq);
    suite << MatcherTest(BF_MATCHER_IP6_DNET, BF_MATCHER_IN, ip6_dnet_in);

    return suite.run();
}
