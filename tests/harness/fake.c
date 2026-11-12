/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "fake.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/random.h>
#include <unistd.h>

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/helper.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "bpfilter/hook.h"

static int _bft_list_dummy_pack(const void *data, bf_wpack_t *pack)
{
    const size_t *_data = data;

    bf_wpack_kv_u64(pack, "size_t", *_data);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

bf_list *bft_list_dummy(size_t len, bft_list_dummy_inserter inserter)
{
    _free_bf_list_ bf_list *list = NULL;
    bf_list_ops ops = bf_list_ops_default(bf_freep, _bft_list_dummy_pack);
    int r;

    r = bf_list_new(&list, &ops);
    if (r)
        return NULL;

    for (size_t i = 0; i < len; ++i) {
        _cleanup_free_ size_t *value = malloc(sizeof(i));
        if (!value)
            return NULL;

        *value = i;

        r = inserter(list, value);
        if (r)
            return NULL;

        TAKE_PTR(value);
    }

    return TAKE_PTR(list);
}

bool bft_list_dummy_eq(const void *lhs, const void *rhs)
{
    const size_t *_lhs = lhs;
    const size_t *_rhs = rhs;

    return *_lhs == *_rhs;
}

const void *bft_get_randomly_filled_buffer(size_t len)
{
    _cleanup_free_ uint8_t *buffer = NULL;
    _cleanup_close_ int fd = -1;
    ssize_t random_len;

    buffer = malloc(len);
    if (!buffer)
        return NULL;

    random_len = getrandom(buffer, len, 0);
    if (random_len != len)
        return NULL;

    return TAKE_PTR(buffer);
}

int bft_rule_add_named_set_matcher(struct bf_rule *rule,
                                   const struct bf_set *set, bool negate)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    int r;

    assert(rule);

    r = bf_matcher_new_for_named_set(&matcher, set, negate);
    if (r)
        return r;

    return bf_list_push(&rule->matchers, (void **)&matcher);
}

struct bf_chain *bft_chain_dummy(bool with_rules)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    int r;

    r = bf_chain_new(&chain, "bft_chain_dummy", BF_HOOK_TC_EGRESS,
                     BF_VERDICT_ACCEPT, NULL, NULL, NULL);
    if (r)
        return NULL;

    if (with_rules) {
        {
            // Create a rule with SET, any matcher, SET
            _free_bf_set_ struct bf_set *set0 = bft_set_dummy("first", 4);
            _free_bf_set_ struct bf_set *set1 = bft_set_dummy("second", 4);
            _free_bf_rule_ struct bf_rule *rule = NULL;
            uint32_t ip = 0xff;

            r = bf_rule_new(&rule);
            if (r)
                return NULL;

            r = bft_rule_add_named_set_matcher(rule, set0, false);
            if (r)
                return NULL;

            r = bf_rule_add_matcher(rule, BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                                    &ip, sizeof(ip), false);
            if (r)
                return NULL;

            r = bft_rule_add_named_set_matcher(rule, set1, false);
            if (r)
                return NULL;

            r = bf_hashset_add(&chain->sets, (void **)&set0);
            if (r)
                return NULL;

            r = bf_hashset_add(&chain->sets, (void **)&set1);
            if (r)
                return NULL;

            r = bf_chain_add_rule(chain, rule);
            if (r)
                return NULL;

            TAKE_PTR(rule);
        }

        for (size_t i = 0; i < 4; ++i) {
            _free_bf_rule_ struct bf_rule *rule = bft_rule_dummy(4);

            r = bf_chain_add_rule(chain, rule);
            if (r)
                return NULL;

            TAKE_PTR(rule);
        }

        {
            // Create a rule with a single set, no other matcher

            _free_bf_set_ struct bf_set *set0 = bft_set_dummy("third", 4);
            _free_bf_rule_ struct bf_rule *rule = NULL;

            r = bf_rule_new(&rule);
            if (r)
                return NULL;

            r = bft_rule_add_named_set_matcher(rule, set0, false);
            if (r)
                return NULL;

            r = bf_hashset_add(&chain->sets, (void **)&set0);
            if (r)
                return NULL;

            r = bf_chain_add_rule(chain, rule);
            if (r)
                return NULL;

            TAKE_PTR(rule);
        }
    }

    return TAKE_PTR(chain);
}

struct bf_chain *bft_chain_with_set(const char *key, const char *elements,
                                    bool negate)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *set = NULL;
    _free_bf_rule_ struct bf_rule *rule = NULL;
    int r;

    r = bf_chain_new(&chain, "source", BF_HOOK_TC_EGRESS, BF_VERDICT_ACCEPT,
                     NULL, NULL, NULL);
    if (r)
        return NULL;

    r = bf_set_new_from_raw(&set, "addresses", key, elements);
    if (r)
        return NULL;

    r = bf_rule_new(&rule);
    if (r)
        return NULL;

    rule->verdict = BF_VERDICT_DROP;
    rule->has_counters = 1;
    r = bft_rule_add_named_set_matcher(rule, set, negate);
    if (r)
        return NULL;

    r = bf_chain_add_set(chain, set);
    if (r)
        return NULL;
    TAKE_PTR(set);

    r = bf_chain_add_rule(chain, rule);
    if (r)
        return NULL;
    TAKE_PTR(rule);

    return TAKE_PTR(chain);
}

struct bf_rule *bft_rule_dummy(size_t n_matchers)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;
    int r;

    r = bf_rule_new(&rule);
    if (r)
        return NULL;

    rule->index = 0;
    rule->log = BF_FLAGS(BF_LOG_OPT_INTERNET, BF_LOG_OPT_TRANSPORT);
    rule->log_rate_ns = 500000000ULL; // 500ms
    rule->mark = 0x17;
    rule->has_counters = 1;
    rule->verdict = BF_VERDICT_ACCEPT;

    for (size_t i = 0; i < n_matchers; ++i) {
        _free_bf_matcher_ struct bf_matcher *matcher = NULL;
        char data[64] = {};

        matcher = bft_matcher_dummy(data, ARRAY_SIZE(data));
        if (!matcher)
            return NULL;

        r = bf_list_push(&rule->matchers, (void **)&matcher);
        if (r)
            return NULL;
    }

    return TAKE_PTR(rule);
}

struct bf_matcher *bft_matcher_dummy(const void *data, size_t data_len)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)bf_matcher_new(&matcher, BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ, data,
                         data_len, false);

    return TAKE_PTR(matcher);
}

struct bf_set *bft_set_dummy(const char *name, size_t n_elems)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_DADDR, BF_MATCHER_TCP_SPORT};

    int r;

    r = bf_set_new(&set, name, key, ARRAY_SIZE(key));
    if (r)
        return NULL;

    for (size_t i = 0; i < n_elems; ++i) {
        uint8_t elem[set->elem_size];

        memset(elem, (uint8_t)i, set->elem_size);

        r = bf_set_add_elem(set, elem);
        if (r)
            return NULL;
    }

    return TAKE_PTR(set);
}
