/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
}

/**
 * Verify tcp.flags eq matches only when the flags field equals the configured
 * value exactly, over both IPv4 and IPv6. A packet with additional flags set
 * must not match.
 */
static void tcp_flags_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // SYN = 0x02
    BFT_CHAIN_SET(
        bf::Chain("test_tcp_flags", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_TCP_FLAGS, BF_MATCHER_EQ, {0x02})},
                    bf_counter()));

    // SYN only -> exact match -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true},
        test->verdictDrop());

    // SYN over IPv6 -> exact match -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true},
        test->verdictDrop());

    // SYN+ACK -> not exact match for SYN-only -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true, .ack = true},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_flags", 0, 2, -1);

    // Try with negation
    BFT_CHAIN_SET(bf::Chain("test_tcp_flags", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_TCP_FLAGS, BF_MATCHER_EQ,
                                           {0x02}, true)},
                              bf_counter()));

    // SYN only -> exact match, but negated -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true},
        test->verdictAccept());

    // SYN+ACK -> not exact match, negated -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true, .ack = true},
        test->verdictDrop());

    bft_assert_counter_eq("test_tcp_flags", 0, 1, -1);
}

/**
 * Verify tcp.flags any {mask} matches if at least one bit in the mask is set
 * in the packet's flags field. A packet with no bits from the mask set must
 * not match.
 */
static void tcp_flags_any(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // SYN|ACK = 0x12
    BFT_CHAIN_SET(
        bf::Chain("test_tcp_flags", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY, {0x12})},
                    bf_counter()));

    // SYN only -> has SYN bit from mask -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true},
        test->verdictDrop());

    // SYN+ACK -> both bits overlap with SYN|ACK mask -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true, .ack = true},
        test->verdictDrop());

    // RST only -> no overlap with SYN|ACK -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .rst = true},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_flags", 0, 2, -1);

    // Try with negation
    BFT_CHAIN_SET(bf::Chain("test_tcp_flags", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY,
                                           {0x12}, true)},
                              bf_counter()));

    // SYN only -> has SYN bit from mask, but negated -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true},
        test->verdictAccept());

    // RST only -> no overlap with SYN|ACK, negated -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .rst = true},
        test->verdictDrop());

    bft_assert_counter_eq("test_tcp_flags", 0, 1, -1);
}

/**
 * Verify tcp.flags all {mask} matches only if every bit in the mask is set in
 * the packet's flags field. A superset of the required bits also matches;
 * missing even one required bit must not match.
 */
static void tcp_flags_all(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // SYN|ACK = 0x12
    BFT_CHAIN_SET(
        bf::Chain("test_tcp_flags", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ALL, {0x12})},
                    bf_counter()));

    // SYN+ACK -> all bits present -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true, .ack = true},
        test->verdictDrop());

    // SYN+ACK+FIN -> superset of required bits -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345,
                      .dport = 80,
                      .fin = true,
                      .syn = true,
                      .ack = true},
        test->verdictDrop());

    // SYN only -> missing ACK bit -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true},
        test->verdictAccept());

    bft_assert_counter_eq("test_tcp_flags", 0, 2, -1);

    // Try with negation
    BFT_CHAIN_SET(bf::Chain("test_tcp_flags", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ALL,
                                           {0x12}, true)},
                              bf_counter()));

    // SYN+ACK -> all bits present, but negated -> ACCEPT
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true, .ack = true},
        test->verdictAccept());

    // SYN only -> missing ACK bit, negated -> DROP
    bft_assert_prog_run(
        "test_tcp_flags", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::TCP {.sport = 12345, .dport = 80, .syn = true},
        test->verdictDrop());

    bft_assert_counter_eq("test_tcp_flags", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_TCP_FLAGS);

    suite << MatcherTest(BF_MATCHER_TCP_FLAGS, BF_MATCHER_EQ, tcp_flags_eq);
    suite << MatcherTest(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY, tcp_flags_any);
    suite << MatcherTest(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ALL, tcp_flags_all);

    return suite.run();
}
