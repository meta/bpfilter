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
 * Verify tcp.dport eq matches TCP packets to the configured destination port
 * over both IPv4 and IPv6 and rejects non-matching ports. Also verifies the
 * protocol guard: a UDP packet must not match a TCP rule.
 */
static void tcp_dport_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_tcp_dport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                           bft_port_be(80))}));

    // TCP dport=80 should match -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP over IPv6 dport=80 should also match -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP dport=80 after a Fragment header with reserved=8 -> DROP
    bft_assert_prog_run("test_tcp_dport", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
                            bft::IPv6Fragment {.reserved = 8} /
                            bft::TCP {.dport = 80},
                        test->verdictDrop());

    // TCP dport=80 with a Fragment header first -> DROP
    bft_assert_prog_run("test_tcp_dport", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6Fragment {} /
                            bft::TCP {.dport = 80},
                        test->verdictDrop());

    // TCP dport=443 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 443},
        test->verdictAccept());

    // UDP dport=80 must not match a TCP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_dport", 0, 4, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_tcp_dport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                           bft_port_be(80), true)}));

    // TCP dport=80 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // TCP dport=443 should match -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 443},
        test->verdictDrop());

    // UDP dport=443 must not match a TCP rule (protocol guard) -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::UDP {.sport = 12345, .dport = 443},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_dport", 0, 1, -1);
}

/**
 * Verify tcp.dport in {set} matches TCP packets whose destination port is a
 * member of the set and rejects those with destination ports outside the set.
 */
static void tcp_dport_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_TCP_DPORT});
    set << bft_port_be(80) << bft_port_be(443);

    BFT_CHAIN_SET(
        bf::Chain("test_tcp_dport", test->hook(), BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {}, {bf::Matcher::in(set)}));

    // TCP dport=80 is in set -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP dport=443 is also in set -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 443},
        test->verdictDrop());

    // TCP dport=8080 is not in set -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 8080},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_dport", 0, 2, -1);
}

/**
 * Verify tcp.dport range [min, max] matches TCP packets within the inclusive
 * bounds and rejects those outside. Tests the minimum, midpoint, and maximum
 * boundary values.
 */
static void tcp_dport_range(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_tcp_dport", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_TCP_DPORT, BF_MATCHER_RANGE,
                                 bft_port_range(80, 443))}));

    // TCP dport=80 is at range minimum -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP dport=200 is in range -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 200},
        test->verdictDrop());

    // TCP dport=443 is at range maximum -> DROP
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 443},
        test->verdictDrop());

    // TCP dport=79 is below range -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 79},
        test->verdictAccept());

    // TCP dport=444 is above range -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_dport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 444},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_dport", 0, 3, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_TCP_DPORT);

    suite << MatcherTest(BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ, tcp_dport_eq);
    suite << MatcherTest(BF_MATCHER_TCP_DPORT, BF_MATCHER_IN, tcp_dport_in);
    suite << MatcherTest(BF_MATCHER_TCP_DPORT, BF_MATCHER_RANGE,
                         tcp_dport_range);

    return suite.run();
}
