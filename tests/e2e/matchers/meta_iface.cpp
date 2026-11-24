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
 * BPF_PROG_TEST_RUN provides a hook-dependent ifindex (not necessarily 0).
 * Use UINT32_MAX as a value guaranteed to never match any real interface.
 */
static void meta_iface_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // eq UINT32_MAX — no real interface has this index -> ACCEPT
    BFT_CHAIN_SET(bf::Chain("test_meta_iface", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP,
                              {bf::Matcher(BF_MATCHER_META_IFACE, BF_MATCHER_EQ,
                                           bft_u32_payload(UINT_MAX))},
                              bf_counter()));

    bft_assert_prog_run(
        "test_meta_iface", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_iface", 0, 0, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_IFACE);

    suite << MatcherTest(BF_MATCHER_META_IFACE, BF_MATCHER_EQ, meta_iface_eq);

    return suite.run();
}
