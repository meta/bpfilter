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
 * Verify that icmpv6.code eq N matches a packet with ICMPv6 code N and
 * does not match a packet with a different code. Also verifies the
 * protocol guard: an IPv4/TCP packet must not match an ICMPv6 rule.
 * Counter must be updated only for the matching packet.
 */
static void icmpv6_code_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_icmpv6_code", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_EQ, {3})},
                    bf_counter()));

    // ICMPv6 code=3 should match -> DROP
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 3},
        test->verdictDrop());

    // ICMPv6 code=0 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 0},
        test->verdictAccept());

    // IPv4/TCP packet must not match an ICMPv6 rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmpv6_code", 0, 1, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_icmpv6_code", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_ICMPV6_CODE,
                                           BF_MATCHER_EQ, {3}, true)},
                              bf_counter()));

    // ICMPv6 code=3 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 3},
        test->verdictAccept());

    // ICMPv6 code=0 should match -> DROP
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 0},
        test->verdictDrop());

    // IPv4/TCP packet must not match an ICMPv6 rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmpv6_code", 0, 1, -1);
}

/**
 * Verify that icmpv6.code in {set} matches packets whose code is in
 * the set and does not match packets with codes outside the set.
 */
static void icmpv6_code_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_ICMPV6_CODE});
    set << std::vector<uint8_t> {3} << std::vector<uint8_t> {0};

    BFT_CHAIN_SET(
        bf::Chain("test_icmpv6_code", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    // ICMPv6 code=3 is in set -> DROP
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 3},
        test->verdictDrop());

    // ICMPv6 code=0 is also in set -> DROP
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 0},
        test->verdictDrop());

    // ICMPv6 code=5 is not in set -> ACCEPT
    bft_assert_prog_run(
        "test_icmpv6_code", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 5},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmpv6_code", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_ICMPV6_CODE);

    suite << MatcherTest(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_EQ, icmpv6_code_eq);
    suite << MatcherTest(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_IN, icmpv6_code_in);

    return suite.run();
}
