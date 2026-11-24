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
 * Verify ip4.proto eq matches packets whose IPv4 protocol field equals the
 * configured value and rejects packets with a different protocol.
 */
static void ip4_proto_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // IPPROTO_TCP = 6
    BFT_CHAIN_SET(
        bf::Chain("test_ip4_proto", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ, {6})},
                    bf_counter()));

    // TCP packet -> protocol=6 -> DROP
    bft_assert_prog_run(
        "test_ip4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // UDP packet -> protocol=17 -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_proto", 0, 1, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_ip4_proto", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                                           {6}, true)},
                              bf_counter()));

    // TCP -> protocol=6 -> not eq does not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // UDP -> protocol=17 -> not eq matches -> DROP
    bft_assert_prog_run(
        "test_ip4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_proto", 0, 1, -1);
}

/**
 * Verify ip4.proto in {set} matches packets whose IPv4 protocol is a member
 * of the set and rejects packets with protocols outside the set.
 */
static void ip4_proto_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP4_PROTO});
    set << std::vector<uint8_t> {6} // TCP
        << std::vector<uint8_t> {17}; // UDP

    BFT_CHAIN_SET(
        bf::Chain("test_ip4_proto", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    // TCP -> protocol=6 in set -> DROP
    bft_assert_prog_run(
        "test_ip4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // UDP -> protocol=17 is also in set -> DROP
    bft_assert_prog_run(
        "test_ip4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    // ICMP -> protocol=1 not in set -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_proto", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP4_PROTO);

    suite << MatcherTest(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ, ip4_proto_eq);
    suite << MatcherTest(BF_MATCHER_IP4_PROTO, BF_MATCHER_IN, ip4_proto_in);

    return suite.run();
}
