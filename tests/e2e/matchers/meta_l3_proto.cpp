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
 * Verify meta.l3_proto eq matches packets whose Ethernet type equals the
 * configured value. Tests both ETH_P_IP and ETH_P_IPV6 to confirm the matcher
 * distinguishes between them.
 */
static void meta_l3_proto_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // ETH_P_IP = 0x0800
    BFT_CHAIN_SET(
        bf::Chain("test_meta_l3_proto", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ,
                                 bft_u16_payload(0x0800))},
                    bf_counter()));

    // IPv4 packet -> ETH_P_IP -> DROP
    bft_assert_prog_run(
        "test_meta_l3_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // IPv6 packet -> ETH_P_IPV6 != ETH_P_IP -> ACCEPT
    bft_assert_prog_run(
        "test_meta_l3_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_l3_proto", 0, 1, -1);

    // ETH_P_IPV6 = 0x86DD
    BFT_CHAIN_SET(
        bf::Chain("test_meta_l3_proto", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ,
                                 bft_u16_payload(0x86DD))},
                    bf_counter()));

    // IPv6 packet -> ETH_P_IPV6 -> DROP
    bft_assert_prog_run(
        "test_meta_l3_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // IPv4 packet -> ETH_P_IP != ETH_P_IPV6 -> ACCEPT
    bft_assert_prog_run(
        "test_meta_l3_proto", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_l3_proto", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_L3_PROTO);

    suite << MatcherTest(BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ,
                         meta_l3_proto_eq);

    return suite.run();
}
