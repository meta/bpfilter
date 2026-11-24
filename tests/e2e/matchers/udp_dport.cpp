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
 * Verify udp.dport eq matches UDP packets to the configured destination port
 * over both IPv4 and IPv6 and rejects non-matching ports. Also verifies the
 * protocol guard: a TCP packet must not match a UDP rule.
 */
static void udp_dport_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_udp_dport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_UDP_DPORT, BF_MATCHER_EQ,
                                           bft_port_be(53))},
                              bf_counter()));

    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    // UDP over IPv6 dport=53 should also match -> DROP
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 5353},
        test->verdictAccept());

    // TCP dport=53 must not match a UDP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 53},
        test->verdictAccept());

    bft_assert_counter_eq("test_udp_dport", 0, 2, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_udp_dport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_UDP_DPORT, BF_MATCHER_EQ,
                                           bft_port_be(53), true)},
                              bf_counter()));

    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictAccept());

    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 5353},
        test->verdictDrop());

    // TCP dport=5353 must not match a UDP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 5353},
        test->verdictAccept());

    bft_assert_counter_eq("test_udp_dport", 0, 1, -1);
}

/**
 * Verify udp.dport in {set} matches UDP packets whose destination port is a
 * member of the set and rejects those with destination ports outside the set.
 */
static void udp_dport_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_UDP_DPORT});
    set << bft_port_be(53) << bft_port_be(5353);

    BFT_CHAIN_SET(
        bf::Chain("test_udp_dport", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    // UDP dport=5353 is also in set -> DROP
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 5353},
        test->verdictDrop());

    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 8080},
        test->verdictAccept());

    bft_assert_counter_eq("test_udp_dport", 0, 2, -1);
}

/**
 * Verify udp.dport range [min, max] matches UDP packets within the inclusive
 * bounds and rejects those outside. Tests the minimum, midpoint, and maximum
 * boundary values.
 */
static void udp_dport_range(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_udp_dport", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_UDP_DPORT, BF_MATCHER_RANGE,
                                 bft_port_range(50, 100))},
                    bf_counter()));

    // UDP dport=50 is at range minimum -> DROP
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 50},
        test->verdictDrop());

    // UDP dport=53 is in range -> DROP
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    // UDP dport=100 is at range maximum -> DROP
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 100},
        test->verdictDrop());

    // UDP dport=49 is below range -> ACCEPT
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 49},
        test->verdictAccept());

    // UDP dport=101 is above range -> ACCEPT
    bft_assert_prog_run(
        "test_udp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 101},
        test->verdictAccept());

    bft_assert_counter_eq("test_udp_dport", 0, 3, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_UDP_DPORT);

    suite << MatcherTest(BF_MATCHER_UDP_DPORT, BF_MATCHER_EQ, udp_dport_eq);
    suite << MatcherTest(BF_MATCHER_UDP_DPORT, BF_MATCHER_IN, udp_dport_in);
    suite << MatcherTest(BF_MATCHER_UDP_DPORT, BF_MATCHER_RANGE,
                         udp_dport_range);

    return suite.run();
}
