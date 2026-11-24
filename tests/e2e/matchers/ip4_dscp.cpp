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

// TOS byte for DSCP=8 (CS1) with ECN=3: (8 << 2) | 3
static constexpr uint8_t kTosCS1Ecn3 = (8 << 2) | 3;

/**
 * Verify ip4.dscp eq matches packets whose DSCP field equals the configured
 * value. The matcher compares only the upper 6 bits of the TOS byte (the DSCP
 * field) and ignores the 2-bit ECN field, so a packet with the same DSCP but
 * non-zero ECN still matches.
 */
static void ip4_dscp_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // DSCP 8 (CS1): raw 6-bit value, maps to TOS byte 0x20 when ECN=0
    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dscp", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_IP4_DSCP, BF_MATCHER_EQ, {8})},
                    bf_counter()));

    // tos=0x20 (DSCP=8, ECN=0) matches -> DROP
    bft_assert_prog_run("test_ip4_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv4 {.saddr = "192.0.2.1",
                                       .daddr = "192.0.2.2",
                                       .tos = 8 << 2} /
                            bft::TCP {},
                        test->verdictDrop());

    // tos=0 (DSCP=0) does not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_dscp", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2", .tos = 0} /
            bft::TCP {},
        test->verdictAccept());

    // tos=kTosCS1Ecn3 has the same DSCP (8) as 0x20 but ECN=3; the matcher
    // ignores ECN bits, so this still matches -> DROP
    bft_assert_prog_run("test_ip4_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv4 {.saddr = "192.0.2.1",
                                       .daddr = "192.0.2.2",
                                       .tos = kTosCS1Ecn3} /
                            bft::TCP {},
                        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_dscp", 0, 2, -1);

    // Negation
    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dscp", test->hook(), BF_VERDICT_ACCEPT) << bf::Rule(
            BF_VERDICT_DROP,
            {bf::Matcher(BF_MATCHER_IP4_DSCP, BF_MATCHER_EQ, {8}, true)},
            bf_counter()));

    // tos=0x20 (DSCP=8) matches the reference value, not eq does not fire -> ACCEPT
    bft_assert_prog_run("test_ip4_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv4 {.saddr = "192.0.2.1",
                                       .daddr = "192.0.2.2",
                                       .tos = 8 << 2} /
                            bft::TCP {},
                        test->verdictAccept());

    // tos=0 (DSCP=0) does not match the reference value, not eq fires -> DROP
    bft_assert_prog_run(
        "test_ip4_dscp", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2", .tos = 0} /
            bft::TCP {},
        test->verdictDrop());

    // tos=kTosCS1Ecn3 has the same DSCP (8); ECN is ignored, so DSCP still
    // matches the reference value -> ACCEPT
    bft_assert_prog_run("test_ip4_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv4 {.saddr = "192.0.2.1",
                                       .daddr = "192.0.2.2",
                                       .tos = kTosCS1Ecn3} /
                            bft::TCP {},
                        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_dscp", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP4_DSCP);

    suite << MatcherTest(BF_MATCHER_IP4_DSCP, BF_MATCHER_EQ, ip4_dscp_eq);

    return suite.run();
}
