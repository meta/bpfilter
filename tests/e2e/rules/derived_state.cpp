/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <cerrno>
#include <vector>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "Set.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>
}

static struct bf_rule *first_rule(struct bf_chain *chain)
{
    return static_cast<struct bf_rule *>(
        bf_list_node_get_data(bf_list_get_head(&chain->rules)));
}

/**
 * Fill the set and enable logging after the rule is added to the chain: the
 * rule state and the chain flags stored in the chain are stale. The program
 * must be generated from the chain's current content.
 */
static void stale_derived_state(void **state)
{
    std::vector<uint8_t> addr = {192, 0, 2, 1};
    auto blocked = bf::Set({BF_MATCHER_IP4_SADDR}, "blocked");
    auto chain =
        (bf::Chain("test_derived_state", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
         << blocked
         << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                     {bf::Matcher::in(blocked)}))
            .get();
    auto *set = const_cast<struct bf_set *>(
        bf_chain_get_set_by_name(chain.get(), "blocked"));
    struct bf_rule *rule = first_rule(chain.get());

    (void)state;

    assert_true(rule->disabled);
    assert_int_equal(0, bf_set_add_elem(set, addr.data()));
    rule->log = BF_FLAG(BF_LOG_OPT_INTERNET);

    assert_int_equal(0, bf_chain_set(chain.get(), nullptr));

    bft_assert_prog_run(
        "test_derived_state", BF_HOOK_XDP,
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        bft_hook_drop(BF_HOOK_XDP));
}

/**
 * Chain validation doesn't check rule verdicts: an out-of-range verdict
 * must fail the call, not abort the process.
 */
static void invalid_verdict(void **state)
{
    auto chain =
        (bf::Chain("test_invalid_verdict", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
         << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                     {bf::Matcher::alwaysMatch()}))
            .get();

    (void)state;

    first_rule(chain.get())->verdict = static_cast<bf_verdict>(_BF_VERDICT_MAX);

    assert_int_equal(-EINVAL, bf_chain_set(chain.get(), nullptr));
}

int main()
{
    const std::vector<CMUnitTest> tests = {
        cmocka_unit_test_setup_teardown(stale_derived_state,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(invalid_verdict, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    return _cmocka_run_group_tests("Derived rule state", tests.data(),
                                   tests.size(), bft_e2e_setup,
                                   bft_e2e_teardown);
}
