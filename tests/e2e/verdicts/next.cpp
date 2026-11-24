/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
#include <bpfilter/ctx.h>
#include <bpfilter/logger.h>
}

/* All hooks that support BPF_PROG_TEST_RUN (excludes BF_FLAVOR_CGROUP_SOCK_ADDR). */
static constexpr enum bf_hook kTestableHooks[] = {
    BF_HOOK_XDP,
    BF_HOOK_TC_INGRESS,
    BF_HOOK_TC_EGRESS,
    BF_HOOK_NF_PRE_ROUTING,
    BF_HOOK_NF_LOCAL_IN,
    BF_HOOK_NF_FORWARD,
    BF_HOOK_NF_LOCAL_OUT,
    BF_HOOK_NF_POST_ROUTING,
    BF_HOOK_CGROUP_SKB_INGRESS,
    BF_HOOK_CGROUP_SKB_EGRESS,
};

/**
 * Verify NEXT as a rule verdict returns the flavor-specific NEXT return code
 * when the rule matches, and falls through to chain policy on non-match.
 *
 * Chain policy is DROP. A rule matches TCP packets and returns NEXT. TCP
 * packets must yield the hook's NEXT return code; UDP packets, which do not
 * match, must yield DROP.
 */
static void next_rule_verdict(void **state)
{
    (void)state;

    for (auto hook: kTestableHooks) {
        assert_int_equal(0, bf_ruleset_flush());

        // IPPROTO_TCP = 6
        BFT_CHAIN_SET(bf::Chain("test_next", hook, BF_VERDICT_DROP) << bf::Rule(
                          BF_VERDICT_NEXT, {bf::Matcher(BF_MATCHER_IP4_PROTO,
                                                        BF_MATCHER_EQ, {6})}));

        bft_assert_prog_run("test_next", hook,
                            bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                            bft_hook_next(hook));

        bft_assert_prog_run("test_next", hook,
                            bft::Ethernet() / bft::IPv4 {} / bft::UDP {},
                            bft_hook_drop(hook));
    }
}

/**
 * Verify NEXT as chain policy returns the flavor-specific NEXT return code
 * when no rule matches the packet.
 *
 * Chain policy is NEXT. A rule matches TCP packets and returns DROP. TCP
 * packets must yield DROP; UDP packets, which do not match any rule, must
 * fall through to the NEXT policy.
 */
static void next_policy(void **state)
{
    (void)state;

    for (auto hook: kTestableHooks) {
        assert_int_equal(0, bf_ruleset_flush());

        // IPPROTO_TCP = 6
        BFT_CHAIN_SET(bf::Chain("test_next", hook, BF_VERDICT_NEXT) << bf::Rule(
                          BF_VERDICT_DROP, {bf::Matcher(BF_MATCHER_IP4_PROTO,
                                                        BF_MATCHER_EQ, {6})}));

        bft_assert_prog_run("test_next", hook,
                            bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                            bft_hook_drop(hook));

        bft_assert_prog_run("test_next", hook,
                            bft::Ethernet() / bft::IPv4 {} / bft::UDP {},
                            bft_hook_next(hook));
    }
}

/**
 * Verify NEXT is terminal: when a rule fires NEXT, subsequent rules are not
 * evaluated.
 *
 * Two TCP-matching rules are installed on TC_INGRESS: rule 0 has a counter
 * and returns NEXT, rule 1 has a counter and returns DROP. After one TCP
 * packet, rule 0's counter must be 1 and rule 1's counter must stay 0.
 */
static void next_is_terminal(void **state)
{
    (void)state;

    // IPPROTO_TCP = 6
    BFT_CHAIN_SET(
        bf::Chain("test_next_term", BF_HOOK_TC_INGRESS, BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_NEXT,
                    {bf::Matcher(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ, {6})},
                    bf_counter())
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ, {6})},
                    bf_counter()));

    bft_assert_prog_run("test_next_term", BF_HOOK_TC_INGRESS,
                        bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                        bft_hook_next(BF_HOOK_TC_INGRESS));

    bft_assert_counter_eq("test_next_term", 0, 1, -1);
    bft_assert_counter_eq("test_next_term", 1, 0, -1);
}

int main()
{
    const std::vector<CMUnitTest> tests = {
        cmocka_unit_test_setup_teardown(next_rule_verdict,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(next_policy, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(next_is_terminal,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    return _cmocka_run_group_tests("NEXT verdict", tests.data(), tests.size(),
                                   bft_e2e_setup, bft_e2e_teardown);
}
