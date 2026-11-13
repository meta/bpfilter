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
 * Verify ip6.nexthdr eq matches packets whose IPv6 next header field equals
 * the configured value and rejects packets with a different next header. The
 * next header still matches if the L4 header is truncated.
 */
static void ip6_nexthdr_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // IPPROTO_TCP = 6
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ, {6})}));

    // TCP over IPv6 -> nexthdr=6 -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP after a Fragment header with reserved=8 -> nexthdr=6 -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
                            bft::IPv6Fragment {.reserved = 8} / bft::TCP {},
                        test->verdictDrop());

    // UDP over IPv6 -> nexthdr=17 -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictAccept());

    // Truncated TCP header -> nexthdr=6 -> DROP
    auto pkt = bft::Ethernet() / bft::IPv6 {} / bft::TCP {};
    pkt.len -= 1;
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(), pkt,
                        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 3, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_IP6_NEXTHDR,
                                           BF_MATCHER_EQ, {6}, true)}));

    // TCP -> nexthdr=6 -> not eq does not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // UDP -> nexthdr=17 -> not eq matches -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 1, -1);
}

/**
 * Verify ip6.nexthdr in {set} matches packets whose next header value is a
 * member of the set and rejects packets with next header values outside the
 * set.
 */
static void ip6_nexthdr_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP6_NEXTHDR});
    set << std::vector<uint8_t> {6} // TCP
        << std::vector<uint8_t> {17}; // UDP

    BFT_CHAIN_SET(
        bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {}, {bf::Matcher::in(set)}));

    // TCP -> nexthdr=6 in set -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // UDP -> nexthdr=17 is also in set -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    // ICMPv6 -> nexthdr=58 not in set -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 0},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP6_NEXTHDR);

    suite << MatcherTest(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ, ip6_nexthdr_eq);
    suite << MatcherTest(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_IN, ip6_nexthdr_in);

    return suite.run();
}
