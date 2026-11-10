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
 * Verify meta.l4_proto eq matches packets whose L4 protocol equals the
 * configured value and rejects packets with a different protocol. The L4
 * protocol still matches if bpfilter doesn't parse it or if the L4 header is
 * truncated.
 */
static void meta_l4_proto_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_meta_l4_proto", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ,
                                 bft_u16_payload(6))}));

    // TCP packet -> l4_proto=6 -> DROP
    bft_assert_prog_run(
        "test_meta_l4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // UDP packet -> l4_proto=17 -> ACCEPT
    bft_assert_prog_run(
        "test_meta_l4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictAccept());

    // Truncated TCP header -> l4_proto=6 -> DROP
    auto ip4_tcp = bft::Ethernet() / bft::IPv4 {} / bft::TCP {};
    ip4_tcp.len -= 1;
    bft_assert_prog_run("test_meta_l4_proto", test->hook(), ip4_tcp,
                        test->verdictDrop());

    bft_assert_counter_eq("test_meta_l4_proto", 0, 2, -1);

    BFT_CHAIN_SET(
        bf::Chain("test_meta_l4_proto", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ,
                                 bft_u16_payload(47))}));

    // GRE, which bpfilter doesn't parse, with a zeroed 4-byte header -> DROP
    bft::Packet gre;
    gre.len = bft::Ethernet().write(gre.data.data(), bft::IPv4::ether_type);
    gre.len += bft::IPv4 {}.write(gre.data.data() + gre.len, 47, 4);
    gre.len += 4;
    bft_assert_prog_run("test_meta_l4_proto", test->hook(), gre,
                        test->verdictDrop());

    bft_assert_counter_eq("test_meta_l4_proto", 0, 1, -1);

    // Negation
    BFT_CHAIN_SET(
        bf::Chain("test_meta_l4_proto", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ,
                                 bft_u16_payload(6), true)}));

    // TCP -> l4_proto=6 -> not eq does not match -> ACCEPT
    bft_assert_prog_run(
        "test_meta_l4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // UDP -> l4_proto=17 -> not eq matches -> DROP
    bft_assert_prog_run(
        "test_meta_l4_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_l4_proto", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_L4_PROTO);

    suite << MatcherTest(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ,
                         meta_l4_proto_eq);

    return suite.run();
}
