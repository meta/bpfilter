/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <arpa/inet.h>
#include <errno.h>

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>
#include <bpfilter/runtime.h>
#include <bpfilter/set.h>

#include "bpfilter/matcher.h"
#include "fake.h"
#include "test.h"

static void new_and_free(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    size_t i = 0;

    (void)state;

    assert_ok(bf_chain_new(&chain, "name", 0, 0, NULL, NULL));
    bf_chain_free(&chain);
    assert_null(chain);

    assert_ok(bf_list_add_tail(&rules, bft_rule_dummy(0)));
    assert_ok(bf_list_add_tail(&rules, bft_rule_dummy(0)));

    assert_ok(bf_chain_new(&chain, "name", 0, 0, NULL, &rules));
    bf_list_foreach (&chain->rules, rule_node) {
        assert_int_equal(
            i++, ((struct bf_rule *)(bf_list_node_get_data(rule_node)))->index);
    }
}

static void new_failure_preserves_inputs(void **state)
{
    _clean_bf_hashset_ bf_hashset sets = bf_set_hashset_default();
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *set = NULL;
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    assert_ok(
        bf_set_new_from_raw(&set, "addresses", "(ip4.saddr)", "{192.0.2.1}"));
    assert_ok(bf_rule_new(&rule));
    assert_ok(bft_rule_add_named_set_matcher(rule, set, false));
    bf_rule_mark_set(rule, 1);
    assert_ok(bf_hashset_add(&sets, (void **)&set));
    assert_ok(bf_list_push(&rules, (void **)&rule));

    // XDP chains cannot set packet marks.
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            &sets, &rules));
    assert_null(chain);
    assert_int_equal(bf_hashset_size(&sets), 1);
    assert_int_equal(bf_list_size(&rules), 1);
    assert_non_null(
        bf_hashset_get(&sets, &(struct bf_set) {.name = "addresses"}));
}

static void pack_and_unpack(void **state)
{
    _free_bf_chain_ struct bf_chain *chain0 = NULL;
    _free_bf_chain_ struct bf_chain *chain1 = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_non_null(chain0 = bft_chain_dummy(true));

    assert_ok(bf_wpack_new(&wpack));
    assert_ok(bf_chain_pack(chain0, wpack));
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_chain_new_from_pack(&chain1, bf_rpack_root(rpack)));

    assert_true(bft_chain_equal(chain0, chain1));
}

static void copy_preserves_configuration(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{192.0.2.1}", false);
    _free_bf_chain_ struct bf_chain *copy = NULL;

    (void)state;

    assert_non_null(source);
    assert_ok(bf_chain_new_from_copy(&copy, source));
    assert_true(bft_chain_equal(source, copy));
}

static void copy_rebinds_shared_set_references(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{192.0.2.1}", false);
    _free_bf_chain_ struct bf_chain *copy = NULL;
    const struct bf_set *source_set;
    const struct bf_set *copied_set;
    struct bf_rule *rule;
    uint32_t address = htonl(0xc0000201);

    (void)state;

    assert_non_null(source);
    source_set = bf_chain_get_set_by_name(source, "addresses");
    rule = bf_list_get_at(&source->rules, 0);
    assert_ok(bft_rule_add_named_set_matcher(rule, source_set, true));

    assert_ok(bf_chain_new_from_copy(&copy, source));
    copied_set = bf_chain_get_set_by_name(copy, "addresses");
    assert_non_null(copied_set);
    assert_ptr_not_equal(source_set, copied_set);
    assert_int_equal(bf_hashset_size(&copy->sets), 1);
    bf_chain_free(&source);

    rule = bf_list_get_at(&copy->rules, 0);
    assert_int_equal(bf_list_size(&rule->matchers), 2);
    bf_list_foreach (&rule->matchers, node) {
        assert_ptr_equal(copied_set, bf_chain_get_set_for_matcher(
                                         copy, bf_list_node_get_data(node)));
    }
    assert_true(bf_hashset_contains(&copied_set->elems, &address));
}

static void copy_resets_chain_counters(void **state)
{
    _free_bf_chain_ struct bf_chain *source = bft_chain_dummy(false);
    _free_bf_chain_ struct bf_chain *copy = NULL;

    (void)state;

    assert_non_null(source);
    source->policy_counters = (struct bf_counter) {.count = 1, .size = 64};
    source->error_counters = (struct bf_counter) {.count = 2, .size = 128};

    assert_ok(bf_chain_new_from_copy(&copy, source));
    assert_int_equal(copy->policy_counters.count, 0);
    assert_int_equal(copy->policy_counters.size, 0);
    assert_int_equal(copy->error_counters.count, 0);
    assert_int_equal(copy->error_counters.size, 0);
    assert_int_equal(source->policy_counters.count, 1);
    assert_int_equal(source->error_counters.count, 2);
}

static void copy_set_updates_do_not_change_source(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{192.0.2.1}", false);
    _free_bf_chain_ struct bf_chain *copy = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;
    const struct bf_set *source_set;
    const struct bf_set *copied_set;

    (void)state;

    assert_non_null(source);
    assert_ok(bf_chain_new_from_copy(&copy, source));
    assert_ok(
        bf_set_new_from_raw(&to_add, "added", "(ip4.saddr)", "{192.0.2.2}"));
    assert_ok(bf_chain_apply_set_delta(copy, "addresses", to_add, NULL));

    source_set = bf_chain_get_set_by_name(source, "addresses");
    copied_set = bf_chain_get_set_by_name(copy, "addresses");
    assert_non_null(source_set);
    assert_non_null(copied_set);
    assert_int_equal(bf_hashset_size(&source_set->elems), 1);
    assert_int_equal(bf_hashset_size(&copied_set->elems), 2);
}

static void copy_set_matcher_survives_source_free(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{192.0.2.1}", false);
    _free_bf_chain_ struct bf_chain *copy = NULL;
    const struct bf_rule *rule;
    const struct bf_set *set;

    (void)state;

    assert_non_null(source);
    assert_ok(bf_chain_new_from_copy(&copy, source));
    bf_chain_free(&source);

    rule = bf_list_get_at(&copy->rules, 0);
    assert_non_null(rule);
    set =
        bf_chain_get_set_for_matcher(copy, bf_list_get_at(&rule->matchers, 0));
    assert_non_null(set);
    assert_string_equal(set->name, "addresses");
    assert_int_equal(bf_hashset_size(&set->elems), 1);
}

static void copy_preserves_disabled_empty_set_rule(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{}", false);
    _free_bf_chain_ struct bf_chain *copy = NULL;
    const struct bf_rule *rule;

    (void)state;

    assert_non_null(source);
    assert_ok(bf_chain_new_from_copy(&copy, source));
    rule = bf_list_get_at(&copy->rules, 0);
    assert_non_null(rule);
    assert_true(rule->disabled);
}

static void copy_preserves_negated_empty_set_rule(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{}", true);
    _free_bf_chain_ struct bf_chain *copy = NULL;
    const struct bf_rule *rule;

    (void)state;

    assert_non_null(source);
    assert_ok(bf_chain_new_from_copy(&copy, source));
    rule = bf_list_get_at(&copy->rules, 0);
    assert_non_null(rule);
    assert_false(rule->disabled);
    assert_true(bf_matcher_get_negate(bf_list_get_at(&rule->matchers, 0)));
}

static void copy_missing_set_leaves_destination_unchanged(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{192.0.2.1}", false);
    _free_bf_chain_ struct bf_chain *destination = bft_chain_dummy(false);
    struct bf_chain *original = destination;
    void *taken = NULL;

    (void)state;

    assert_non_null(source);
    assert_non_null(destination);
    assert_ok(bf_hashset_take(
        &source->sets, bf_chain_get_set_by_name(source, "addresses"), &taken));

    assert_err(bf_chain_new_from_copy(&destination, source));
    assert_ok(bf_hashset_add(&source->sets, &taken));
    assert_ptr_equal(destination, original);
    assert_true(bf_list_is_empty(&destination->rules));
    assert_true(bf_hashset_is_empty(&destination->sets));
}

static void anonymous_matchers_survive_chain_copy(void **state)
{
    _free_bf_chain_ struct bf_chain *source =
        bft_chain_with_set("(ip4.saddr)", "{192.0.2.1}", false);
    _free_bf_chain_ struct bf_chain *copy = NULL;
    _free_bf_chain_ struct bf_chain *restored = NULL;
    _free_bf_set_ struct bf_set *unused = NULL;
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    struct bf_rule *rule;
    const void *data;
    size_t data_len;

    (void)state;

    assert_non_null(source);
    assert_ok(bf_set_new_from_raw(&unused, "unused", "(tcp.dport)", "{80}"));
    assert_ok(bf_chain_add_set(source, unused));
    TAKE_PTR(unused);
    rule = bf_list_get_at(&source->rules, 0);
    assert_ok(bf_matcher_new_for_anon_set_from_raw(&matcher, "(ip4.saddr)",
                                                   "{192.0.2.2}", true));
    assert_ok(bf_list_push(&rule->matchers, (void **)&matcher));

    assert_ok(bf_chain_new_from_copy(&copy, source));
    assert_true(bft_chain_equal(source, copy));
    bf_chain_free(&source);
    assert_int_equal(bf_hashset_size(&copy->sets), 2);
    assert_non_null(bf_chain_get_set_by_name(copy, "unused"));

    assert_ok(bf_wpack_new(&wpack));
    assert_ok(bf_chain_pack(copy, wpack));
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_chain_new_from_pack(&restored, bf_rpack_root(rpack)));
    assert_true(bft_chain_equal(copy, restored));
    bf_chain_free(&copy);

    rule = bf_list_get_at(&restored->rules, 0);
    bf_list_delete(&rule->matchers, bf_list_get_tail(&rule->matchers));
    assert_int_equal(bf_hashset_size(&restored->sets), 2);
    assert_non_null(bf_chain_get_set_by_name(restored, "addresses"));
    assert_non_null(bf_chain_get_set_by_name(restored, "unused"));
}

static void reject_anonymous_chain_set(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(false);
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    assert_non_null(chain);
    assert_ok(bf_set_new_from_raw(&set, NULL, "(ip4.saddr)", "{192.0.2.1}"));
    assert_int_equal(bf_chain_add_set(chain, set), -EINVAL);
    assert_true(bf_hashset_is_empty(&chain->sets));
    assert_ok(bf_set_add_elem_raw(set, "192.0.2.2"));
}

static void dump(void **state)
{
    _free_bf_chain_ struct bf_chain *chain0 = bft_chain_dummy(false);
    _free_bf_chain_ struct bf_chain *chain1 = bft_chain_dummy(true);

    (void)state;

    assert_non_null(chain0);
    assert_non_null(chain1);

    bf_chain_dump(chain0, EMPTY_PREFIX);
    bf_chain_dump(chain1, EMPTY_PREFIX);
}

static void get_set_from_matcher(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(true);
    struct bf_rule *r0 = bf_list_node_get_data(bf_list_get_head(&chain->rules));
    struct bf_matcher *r0_m0 =
        bf_list_node_get_data(bf_list_get_head(&r0->matchers));
    struct bf_matcher *r0_m2 =
        bf_list_node_get_data(bf_list_get_tail(&r0->matchers));

    struct bf_rule *r1 = bf_list_node_get_data(
        bf_list_node_next(bf_list_get_head(&chain->rules)));
    struct bf_matcher *r1_m0 =
        bf_list_node_get_data(bf_list_get_head(&r1->matchers));

    struct bf_rule *r5 = bf_list_node_get_data(bf_list_get_tail(&chain->rules));
    struct bf_matcher *r5_m0 =
        bf_list_node_get_data(bf_list_get_head(&r5->matchers));

    bf_hashset_elem *snode = chain->sets.head;
    struct bf_set *set0 = snode->data;
    struct bf_set *set1 = snode->next->data;
    struct bf_set *set2 = snode->next->next->data;

    (void)state;

    assert_ptr_equal(set0, bf_chain_get_set_for_matcher(chain, r0_m0));
    assert_ptr_equal(set1, bf_chain_get_set_for_matcher(chain, r0_m2));
    assert_ptr_equal(set2, bf_chain_get_set_for_matcher(chain, r5_m0));

    assert_null(bf_chain_get_set_for_matcher(chain, r1_m0));
}

static void mixed_enabled_disabled_log_flag(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_hashset_ bf_hashset sets = bf_set_hashset_default();
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    _free_bf_set_ struct bf_set *set0 = bft_set_dummy("empty", 0);
    _free_bf_set_ struct bf_set *set1 = bft_set_dummy("populated", 4);
    struct bf_rule *r0 = NULL;
    struct bf_rule *r1 = NULL;

    (void)state;

    assert_non_null(set0);
    assert_non_null(set1);
    assert_ok(bf_rule_new(&r0));
    r0->log = 1;
    assert_ok(bft_rule_add_named_set_matcher(r0, set0, false));
    assert_ok(bf_list_add_tail(&rules, r0));

    assert_ok(bf_rule_new(&r1));
    assert_ok(bft_rule_add_named_set_matcher(r1, set1, false));
    assert_ok(bf_list_add_tail(&rules, r1));

    assert_ok(bf_hashset_add(&sets, (void **)&set0));
    assert_ok(bf_hashset_add(&sets, (void **)&set1));

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS, BF_VERDICT_ACCEPT,
                           &sets, &rules));

    assert_true(r0->disabled);
    assert_false(r1->disabled);
    assert_int_equal(chain->flags & BF_FLAG(BF_CHAIN_LOG), 0);
}

static void apply_set_delta_updates_derived_state(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_hashset_ bf_hashset sets = bf_set_hashset_default();
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    _free_bf_set_ struct bf_set *set = NULL;
    _free_bf_set_ struct bf_set *delta_set = NULL;
    _free_bf_set_ struct bf_set *invalid_delta = NULL;
    struct bf_rule *rule = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_TCP_SPORT};

    enum bf_matcher_type invalid_key[] = {BF_MATCHER_UDP_SPORT};

    const struct bf_set *matcher_set = NULL;
    uint16_t port = htons(80);
    uint8_t nexthdr = IPPROTO_TCP;

    (void)state;

    assert_ok(bf_set_new(&set, "set", key, ARRAY_SIZE(key)));
    matcher_set = set;
    assert_ok(bf_hashset_add(&sets, (void **)&set));

    assert_ok(bf_set_new(&delta_set, "set", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_add_elem(delta_set, &port));

    assert_ok(bf_rule_new(&rule));
    rule->log = BF_LOG_OPT_DEFAULT;
    rule->log_rate_ns = 1;

    assert_ok(bft_rule_add_named_set_matcher(rule, matcher_set, false));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ,
                                  &nexthdr, sizeof(nexthdr), false));
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                           &sets, &rules));
    assert_true(rule->disabled);
    assert_int_equal(chain->flags, 0);

    assert_ok(bf_chain_apply_set_delta(chain, "set", delta_set, NULL));
    assert_false(rule->disabled);
    assert_int_equal(
        chain->flags,
        BF_FLAGS(BF_CHAIN_LOG, BF_CHAIN_LOG_RATELIMIT, BF_CHAIN_STORE_NEXTHDR));

    assert_ok(bf_chain_apply_set_delta(chain, "set", NULL, delta_set));
    assert_true(rule->disabled);
    assert_int_equal(chain->flags, 0);

    assert_int_equal(
        bf_chain_apply_set_delta(chain, "missing", delta_set, NULL), -ENOENT);

    assert_int_equal(bf_chain_apply_set_delta(chain, "set", NULL, NULL),
                     -EINVAL);

    assert_ok(bf_set_new(&invalid_delta, "set", invalid_key,
                         ARRAY_SIZE(invalid_key)));
    assert_int_equal(
        bf_chain_apply_set_delta(chain, "set", invalid_delta, NULL), -EINVAL);
}

static void empty_set_only_disables_in_rules(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_hashset_ bf_hashset sets = bf_set_hashset_default();
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    _free_bf_set_ struct bf_set *set = NULL;
    struct bf_rule *in_rule = NULL;
    struct bf_rule *not_in_rule = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_TCP_SPORT};

    const struct bf_set *matcher_set = NULL;

    (void)state;

    assert_ok(bf_set_new(&set, "set", key, ARRAY_SIZE(key)));
    matcher_set = set;
    assert_ok(bf_hashset_add(&sets, (void **)&set));

    assert_ok(bf_rule_new(&in_rule));
    assert_ok(bft_rule_add_named_set_matcher(in_rule, matcher_set, false));
    assert_ok(bf_list_add_tail(&rules, in_rule));

    assert_ok(bf_rule_new(&not_in_rule));
    assert_ok(bft_rule_add_named_set_matcher(not_in_rule, matcher_set, true));
    assert_ok(bf_list_add_tail(&rules, not_in_rule));

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                           &sets, &rules));

    // Rule containing an "in" matcher with an empty set is disabled
    assert_true(in_rule->disabled);
    // Rule containing a "not in" matcher with an empty set is not disabled
    assert_false(not_in_rule->disabled);
}

static void incompatible_matchers_disable_rule(void **state)
{
    (void)state;

    // L3 conflict: IPv4 + IPv6 matchers.
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint32_t ip4_addr = 0;
        uint8_t ip6_addr[16] = {};

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                                      &ip4_addr, sizeof(ip4_addr), false));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP6_DADDR, BF_MATCHER_EQ,
                                      ip6_addr, sizeof(ip6_addr), false));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_true(rule->disabled);
    }

    // L4 conflict: TCP + UDP matchers.
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint16_t port = 0;

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port), false));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_UDP_DPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port), false));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_true(rule->disabled);
    }

    // L3 conflict via set: ip4.daddr set + ip6.daddr matcher.
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_hashset_ bf_hashset sets = bf_set_hashset_default();
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        _free_bf_set_ struct bf_set *set = NULL;
        struct bf_rule *rule = NULL;

        enum bf_matcher_type key[] = {BF_MATCHER_IP4_DADDR};

        const struct bf_set *matcher_set = NULL;
        uint8_t ip6_addr[16] = {};

        assert_ok(bf_set_new(&set, "s", key, ARRAY_SIZE(key)));
        assert_ok(bf_set_add_elem(set, (uint8_t[4]) {10, 0, 0, 1}));
        matcher_set = set;
        assert_ok(bf_hashset_add(&sets, (void **)&set));

        assert_ok(bf_rule_new(&rule));
        assert_ok(bft_rule_add_named_set_matcher(rule, matcher_set, false));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP6_DADDR, BF_MATCHER_EQ,
                                      ip6_addr, sizeof(ip6_addr), false));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, &sets, &rules));
        assert_true(rule->disabled);
    }

    // No conflict: same protocol at same layer (TCP sport + TCP dport).
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint16_t port = 0;

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port), false));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port), false));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_false(rule->disabled);
    }

    // No conflict: different layers (IPv4 + TCP).
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint32_t ip4_addr = 0;
        uint16_t port = 0;

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                                      &ip4_addr, sizeof(ip4_addr), false));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port), false));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_false(rule->disabled);
    }
}

static void policy_validation(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;

    (void)state;

    assert_ok(bf_chain_new(&chain, "next", BF_HOOK_TC_EGRESS, BF_VERDICT_NEXT,
                           NULL, NULL));
    bf_chain_free(&chain);

    assert_err(bf_chain_new(&chain, "bad", BF_HOOK_TC_EGRESS,
                            BF_VERDICT_CONTINUE, NULL, NULL));
    assert_err(bf_chain_new(&chain, "bad", BF_HOOK_TC_EGRESS,
                            BF_VERDICT_REDIRECT, NULL, NULL));
}

static void set_component_unsupported_hook(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_hashset_ bf_hashset sets = bf_set_hashset_default();
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    _free_bf_set_ struct bf_set *set = NULL;
    struct bf_rule *rule = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    const struct bf_set *matcher_set = NULL;

    (void)state;

    // Set component unsupported for hook: ip4.saddr on CONNECT4.
    assert_ok(bf_set_new(&set, "s", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_add_elem(set, (uint8_t[4]) {10, 0, 0, 1}));
    matcher_set = set;
    assert_ok(bf_hashset_add(&sets, (void **)&set));

    assert_ok(bf_rule_new(&rule));
    assert_ok(bft_rule_add_named_set_matcher(rule, matcher_set, false));
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_err(bf_chain_new(&chain, "test", BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
                            BF_VERDICT_ACCEPT, &sets, &rules));

    // Supported component: ip4.daddr on CONNECT4 should succeed.
    bf_list_clean(&rules);
    bf_hashset_clean(&sets);

    enum bf_matcher_type daddr_key[] = {BF_MATCHER_IP4_DADDR};

    assert_ok(bf_set_new(&set, "s2", daddr_key, ARRAY_SIZE(daddr_key)));
    assert_ok(bf_set_add_elem(set, (uint8_t[4]) {10, 0, 0, 1}));
    matcher_set = set;
    assert_ok(bf_hashset_add(&sets, (void **)&set));

    assert_ok(bf_rule_new(&rule));
    assert_ok(bft_rule_add_named_set_matcher(rule, matcher_set, false));
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
                           BF_VERDICT_ACCEPT, &sets, &rules));
}

static void sock_addr_log_flag(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *r0 = NULL;

    (void)state;

    assert_ok(bf_rule_new(&r0));
    r0->log = BF_LOG_OPT_DEFAULT;
    assert_ok(bf_list_add_tail(&rules, r0));

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
                           BF_VERDICT_ACCEPT, NULL, &rules));

    assert_false(r0->disabled);
    assert_int_not_equal(chain->flags & BF_FLAG(BF_CHAIN_LOG), 0);
}

static void invalid_log_opts_for_hook(void **state)
{
    (void)state;

    {
        // Per-field log options on a sock_addr hook
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *r0 = NULL;

        assert_ok(bf_rule_new(&r0));
        r0->log = BF_LOG_PACKET_HEADERS;
        assert_ok(bf_list_add_tail(&rules, r0));

        assert_err(bf_chain_new(&chain, "test",
                                BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
                                BF_VERDICT_ACCEPT, NULL, &rules));
    }

    {
        // 5-tuple logging on a sock_addr hook
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *r0 = NULL;

        assert_ok(bf_rule_new(&r0));
        r0->log = BF_FLAG(BF_LOG_OPT_5_TUPLE);
        assert_ok(bf_list_add_tail(&rules, r0));

        assert_err(bf_chain_new(&chain, "test",
                                BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
                                BF_VERDICT_ACCEPT, NULL, &rules));
    }

    {
        // 5-tuple is exclusive from packet layer options
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *r0 = NULL;

        assert_ok(bf_rule_new(&r0));
        r0->log = BF_FLAG(BF_LOG_OPT_5_TUPLE) | BF_FLAG(BF_LOG_OPT_INTERNET);
        assert_ok(bf_list_add_tail(&rules, r0));

        assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                                NULL, &rules));
    }
}

static void named_reference_stability(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *target = NULL;
    _free_bf_set_ struct bf_set *unrelated = NULL;
    _free_bf_rule_ struct bf_rule *rule = NULL;
    _free_bf_rule_ struct bf_rule *foreign_rule = NULL;
    struct bf_set unrelated_key = {.name = "unrelated"};
    const struct bf_set *stored;
    struct bf_matcher *matcher;
    void *taken = NULL;

    (void)state;

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
                           NULL));
    assert_ok(
        bf_set_new_from_raw(&target, "target", "(ip4.saddr)", "{192.0.2.1}"));
    assert_ok(
        bf_set_new_from_raw(&unrelated, "unrelated", "(ip4.saddr)", "{}"));
    assert_ok(bf_rule_new(&rule));
    assert_ok(bft_rule_add_named_set_matcher(rule, target, false));
    matcher = bf_list_node_get_data(bf_list_get_head(&rule->matchers));
    assert_null(bf_chain_get_set_for_matcher(chain, matcher));
    assert_err(bf_chain_add_rule(chain, rule));
    assert_ok(bf_chain_add_set(chain, unrelated));
    TAKE_PTR(unrelated);
    assert_ok(bf_chain_add_set(chain, target));
    stored = TAKE_PTR(target);
    assert_ok(bf_chain_add_rule(chain, rule));
    TAKE_PTR(rule);

    // Growth and deletion of an earlier set must preserve the reference.
    for (size_t i = 0; i < 64; ++i) {
        _free_bf_set_ struct bf_set *extra = NULL;
        char name[32];

        (void)snprintf(name, sizeof(name), "extra_%zu", i);
        assert_ok(bf_set_new_from_raw(&extra, name, "(ip4.saddr)", "{}"));
        assert_ok(bf_chain_add_set(chain, extra));
        TAKE_PTR(extra);
    }
    assert_ok(bf_hashset_delete(&chain->sets, &unrelated_key));
    assert_ptr_equal(stored, bf_chain_get_set_for_matcher(chain, matcher));

    // Reinserting the target changes its iteration position, not its identity.
    assert_ok(bf_hashset_take(&chain->sets, stored, &taken));
    assert_null(bf_chain_get_set_for_matcher(chain, matcher));
    assert_ok(bf_hashset_add(&chain->sets, &taken));
    assert_ptr_equal(stored, bf_chain_get_set_for_matcher(chain, matcher));

    assert_ok(bf_set_new_from_copy(&target, stored));
    assert_err(bf_chain_add_set(chain, target));
    assert_non_null(target);
    assert_ptr_equal(stored, bf_chain_get_set_by_name(chain, "target"));

    // A different object with the same name cannot reference the stored set.
    assert_ok(bf_rule_new(&foreign_rule));
    assert_ok(bft_rule_add_named_set_matcher(foreign_rule, target, false));
    assert_err(bf_chain_add_rule(chain, foreign_rule));
}

static void unpack_duplicate_sets(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *set = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_set_new_from_raw(&set, "duplicate", "(ip4.saddr)", "{}"));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_str(wpack, "name", "test");
    bf_wpack_kv_enum(wpack, "hook", BF_HOOK_XDP);
    bf_wpack_kv_enum(wpack, "policy", BF_VERDICT_ACCEPT);
    bf_wpack_open_array(wpack, "sets");
    for (size_t i = 0; i < 2; ++i) {
        bf_wpack_open_object(wpack, NULL);
        assert_ok(bf_set_pack(set, wpack));
        bf_wpack_close_object(wpack);
    }
    bf_wpack_close_array(wpack);
    bf_wpack_open_array(wpack, "rules");
    bf_wpack_close_array(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_err(bf_chain_new_from_pack(&chain, bf_rpack_root(rpack)));
    assert_null(chain);
}

static void get_set_by_name(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(true);
    const struct bf_set *set = chain->sets.head->data;

    (void)state;

    assert_ptr_equal(set, bf_chain_get_set_by_name(chain, set->name));
    assert_null(bf_chain_get_set_by_name(chain, "bft_set_missing"));
}

static void redirect_validation(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;

    (void)state;

    // NF does not support REDIRECT, even after an unconditional DROP.
    assert_ok(bf_rule_new(&rule));
    rule->verdict = BF_VERDICT_DROP;
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_ok(bf_rule_new(&rule));
    rule->verdict = BF_VERDICT_REDIRECT;
    bf_rule_set_redirect(rule, 1, BF_REDIRECT_EGRESS);
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_NF_LOCAL_IN,
                            BF_VERDICT_ACCEPT, NULL, &rules));
    bf_list_clean(&rules);

    // XDP does not support ingress redirects.
    assert_ok(bf_rule_new(&rule));
    rule->verdict = BF_VERDICT_REDIRECT;
    bf_rule_set_redirect(rule, 1, BF_REDIRECT_INGRESS);
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            NULL, &rules));
    bf_list_clean(&rules);

    // XDP supports egress redirects.
    assert_ok(bf_rule_new(&rule));
    rule->verdict = BF_VERDICT_REDIRECT;
    bf_rule_set_redirect(rule, 1, BF_REDIRECT_EGRESS);
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
                           &rules));
    bf_chain_free(&chain);

    // TC supports ingress redirects.
    assert_ok(bf_rule_new(&rule));
    rule->verdict = BF_VERDICT_REDIRECT;
    bf_rule_set_redirect(rule, 1, BF_REDIRECT_INGRESS);
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_INGRESS,
                           BF_VERDICT_ACCEPT, NULL, &rules));
}

static void matcher_operator_validation(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;
    uint32_t addr = 0;
    uint8_t flags = 1;

    (void)state;

    // An unconditional DROP must not hide an unsupported scalar operator.
    assert_ok(bf_rule_new(&rule));
    rule->verdict = BF_VERDICT_DROP;
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR, BF_MATCHER_ANY,
                                  &addr, sizeof(addr), false));
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            NULL, &rules));
    bf_list_clean(&rules);

    // Membership requires a SET matcher, not a scalar IN matcher.
    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR, BF_MATCHER_IN,
                                  &addr, sizeof(addr), false));
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            NULL, &rules));
    bf_list_clean(&rules);

    // Reject an operator past the enum bounds.
    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR,
                                  _BF_MATCHER_OP_MAX, &addr, sizeof(addr),
                                  false));
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            NULL, &rules));
    bf_list_clean(&rules);

    // Reject a negative operator.
    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR, -1, &addr,
                                  sizeof(addr), false));
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            NULL, &rules));
    bf_list_clean(&rules);

    // ANY is supported for TCP flags, unlike IPv4 addresses.
    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY,
                                  &flags, sizeof(flags), false));
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
                           &rules));
}

static void verdict_validation(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;

    (void)state;

    // Reject a verdict past the enum bounds.
    assert_ok(bf_rule_new(&rule));
    rule->verdict = _BF_VERDICT_MAX;
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            NULL, &rules));
    bf_list_clean(&rules);

    // Reject a negative verdict.
    assert_ok(bf_rule_new(&rule));
    rule->verdict = -1;
    assert_ok(bf_list_add_tail(&rules, rule));
    assert_err(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                            NULL, &rules));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(new_failure_preserves_inputs),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(copy_preserves_configuration),
        cmocka_unit_test(copy_rebinds_shared_set_references),
        cmocka_unit_test(copy_resets_chain_counters),
        cmocka_unit_test(copy_set_updates_do_not_change_source),
        cmocka_unit_test(copy_set_matcher_survives_source_free),
        cmocka_unit_test(copy_preserves_disabled_empty_set_rule),
        cmocka_unit_test(copy_preserves_negated_empty_set_rule),
        cmocka_unit_test(copy_missing_set_leaves_destination_unchanged),
        cmocka_unit_test(anonymous_matchers_survive_chain_copy),
        cmocka_unit_test(reject_anonymous_chain_set),
        cmocka_unit_test(dump),
        cmocka_unit_test(get_set_from_matcher),
        cmocka_unit_test(mixed_enabled_disabled_log_flag),
        cmocka_unit_test(apply_set_delta_updates_derived_state),
        cmocka_unit_test(empty_set_only_disables_in_rules),
        cmocka_unit_test(incompatible_matchers_disable_rule),
        cmocka_unit_test(sock_addr_log_flag),
        cmocka_unit_test(invalid_log_opts_for_hook),
        cmocka_unit_test(policy_validation),
        cmocka_unit_test(set_component_unsupported_hook),
        cmocka_unit_test(get_set_by_name),
        cmocka_unit_test(named_reference_stability),
        cmocka_unit_test(unpack_duplicate_sets),
        cmocka_unit_test(redirect_validation),
        cmocka_unit_test(matcher_operator_validation),
        cmocka_unit_test(verdict_validation),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
