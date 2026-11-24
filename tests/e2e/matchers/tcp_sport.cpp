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
 * Verify tcp.sport eq matches TCP packets from the configured source port over
 * both IPv4 and IPv6 and rejects non-matching ports. Also verifies the
 * protocol guard: a UDP packet must not match a TCP rule.
 */
static void tcp_sport_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_tcp_sport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                           bft_port_be(12345))},
                              bf_counter()));

    // TCP sport=12345 should match -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP over IPv6 sport=12345 should also match -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP sport=54321 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 54321, .dport = 80},
        test->verdictAccept());

    // UDP sport=12345 must not match a TCP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_sport", 0, 2, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_tcp_sport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                           bft_port_be(12345), true)},
                              bf_counter()));

    // TCP sport=12345 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // TCP sport=54321 should match -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 54321, .dport = 80},
        test->verdictDrop());

    // UDP sport=54321 must not match a TCP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 54321, .dport = 53},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_sport", 0, 1, -1);
}

/**
 * Verify tcp.sport in {set} matches TCP packets whose source port is a member
 * of the set and rejects those with source ports outside the set.
 */
static void tcp_sport_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_TCP_SPORT});
    set << bft_port_be(12345) << bft_port_be(80);

    BFT_CHAIN_SET(
        bf::Chain("test_tcp_sport", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, {bf::Matcher::in(set)}, bf_counter()));

    // TCP sport=12345 is in set -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP sport=80 is also in set -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 80, .dport = 443},
        test->verdictDrop());

    // TCP sport=54321 is not in set -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 54321, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_sport", 0, 2, -1);
}

/**
 * Verify tcp.sport range [min, max] matches TCP packets within the inclusive
 * bounds and rejects those outside. Tests the minimum, midpoint, and maximum
 * boundary values.
 */
static void tcp_sport_range(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_tcp_sport", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_TCP_SPORT, BF_MATCHER_RANGE,
                                 bft_port_range(1000, 2000))},
                    bf_counter()));

    // TCP sport=1000 is at range minimum -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 1000, .dport = 80},
        test->verdictDrop());

    // TCP sport=1500 is in range -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 1500, .dport = 80},
        test->verdictDrop());

    // TCP sport=2000 is at range maximum -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 2000, .dport = 80},
        test->verdictDrop());

    // TCP sport=999 is below range -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 999, .dport = 80},
        test->verdictAccept());

    // TCP sport=2001 is above range -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 2001, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_sport", 0, 3, -1);

    // Try with negation
    BFT_CHAIN_SET(
        bf::Chain("test_tcp_sport", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_TCP_SPORT, BF_MATCHER_RANGE,
                                 bft_port_range(1000, 2000), true)},
                    bf_counter()));

    // TCP sport=1500 is in range, but negated -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 1500, .dport = 80},
        test->verdictAccept());

    // TCP sport=999 is below range, negated -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 999, .dport = 80},
        test->verdictDrop());

    // TCP sport=2001 is above range, negated -> DROP
    bft_assert_prog_run(
        "test_tcp_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 2001, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_tcp_sport", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_TCP_SPORT);

    suite << MatcherTest(BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ, tcp_sport_eq);
    suite << MatcherTest(BF_MATCHER_TCP_SPORT, BF_MATCHER_IN, tcp_sport_in);
    suite << MatcherTest(BF_MATCHER_TCP_SPORT, BF_MATCHER_RANGE,
                         tcp_sport_range);

    return suite.run();
}
