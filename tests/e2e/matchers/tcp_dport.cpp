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

// Append N IPv6 Destination Options headers to a partial packet.
template<size_t N>
static auto withDstOpts(auto stack)
{
    if constexpr (N == 0)
        return stack;
    else
        return withDstOpts<N - 1>(stack / bft::IPv6DstOpts {});
}

/**
 * Verify tcp.dport eq matches TCP packets to the configured destination port
 * over both IPv4 and IPv6 and rejects non-matching ports. Also verifies the
 * protocol guard: a UDP packet must not match a TCP rule. With 16 IPv6
 * extension headers the rule still matches, with 17 the packet is dropped and
 * counted as an error, unless the chain has no L4 matcher.
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

    // An ip6.nexthdr rule selects the IPv6 parser that stores the headers
    for (bool store_nexthdr: {false, true}) {
        auto chain =
            bf::Chain("test_tcp_dport", test->hook(), BF_VERDICT_ACCEPT);

        chain << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                          {bf::Matcher(BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                       bft_port_be(80))});
        if (store_nexthdr) {
            chain << bf::Rule(
                BF_VERDICT_ACCEPT, bf_counter(), {},
                {bf::Matcher(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ, {6})});
        }
        BFT_CHAIN_SET(chain);

        // 16 extension headers -> DROP
        bft_assert_prog_run("test_tcp_dport", test->hook(),
                            withDstOpts<16>(bft::Ethernet() / bft::IPv6 {}) /
                                bft::TCP {.dport = 80},
                            test->verdictDrop());

        bft_assert_error_counter_eq("test_tcp_dport", 0);

        // 17 extension headers -> DROP before the rules, counted as an error
        bft_assert_prog_run("test_tcp_dport", test->hook(),
                            withDstOpts<17>(bft::Ethernet() / bft::IPv6 {}) /
                                bft::TCP {.dport = 80},
                            test->verdictDrop());

        bft_assert_counter_eq("test_tcp_dport", 0, 1, -1);
        bft_assert_error_counter_eq("test_tcp_dport", 1);
    }

    // Without L4 matchers, the rules still apply to 17 extension headers
    BFT_CHAIN_SET(bf::Chain("test_tcp_dport", test->hook(), BF_VERDICT_DROP)
                  << bf::Rule(BF_VERDICT_ACCEPT, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                                           bft_ipv6_addr("2001:db8::1"))}));

    bft_assert_prog_run("test_tcp_dport", test->hook(),
                        withDstOpts<17>(bft::Ethernet() / bft::IPv6 {}) /
                            bft::TCP {.dport = 80},
                        test->verdictAccept());

    bft_assert_error_counter_eq("test_tcp_dport", 0);
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
