/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/chain.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/core/hashset.h"
#include "bpfilter/core/list.h"
#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/hook.h"
#include "bpfilter/logger.h"
#include "bpfilter/matcher.h"
#include "bpfilter/pack.h"
#include "bpfilter/rule.h"
#include "bpfilter/set.h"
#include "bpfilter/verdict.h"

/**
 * @brief Check if a rule can't match because it references an unmatchable set.
 *
 * Check if a rule contains a matcher on a set that can't match any packet:
 * - `... in {}`: the reference value can't be found in the set, because the
 *   set is empty. The rule will never match.
 * - `... not in {}`: the set is empty, but we test for the negative: the
 *   reference value won't be in the set. The rule can match.
 *
 * @param chain Chain containing the sets. Can't be NULL.
 * @param rule Rule to check. Can't be NULL.
 * @return 0 if the rule has no set matcher, or a set matcher that might match
 *         a packet. 1 if the rule contains a set matcher that can't match any
 *         packet. A negative errno value on failure.
 */
static int _bf_rule_has_unmatchable_set_matcher(const struct bf_chain *chain,
                                                const struct bf_rule *rule)
{
    assert(chain);
    assert(rule);

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        const struct bf_set *set;

        if (bf_matcher_get_type(matcher) != BF_MATCHER_SET)
            continue;

        set = bf_chain_get_set_for_matcher(chain, matcher);
        if (!set) {
            return bf_err_r(-EINVAL, "rule %u references non-existent set",
                            rule->index);
        }

        if (bf_set_is_empty(set) && !bf_matcher_get_negate(matcher)) {
            bf_warn("rule %u references empty set, rule will be disabled",
                    rule->index);
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Check a single matcher type against per-layer header tracking.
 *
 * @param type Matcher type to check.
 * @param layer_hdr_id Per-layer header ID tracking array.
 * @return 0 if compatible, 1 if incompatible, negative errno on error.
 */
static int _bf_rule_check_layer(enum bf_matcher_type type,
                                uint32_t layer_hdr_id[_BF_MATCHER_LAYER_MAX])
{
    const struct bf_matcher_meta *meta;

    assert(layer_hdr_id);

    meta = bf_matcher_get_meta(type);
    if (!meta) {
        return bf_err_r(-EINVAL, "missing meta for '%s'",
                        bf_matcher_type_to_str(type));
    }

    if (meta->layer <= BF_MATCHER_NO_LAYER)
        return 0;

    if (layer_hdr_id[meta->layer] == UINT32_MAX) {
        layer_hdr_id[meta->layer] = meta->hdr_id;
        return 0;
    }

    if (layer_hdr_id[meta->layer] != meta->hdr_id)
        return 1;

    return 0;
}

/**
 * @brief Check if a rule has matchers on the same layer but different
 * protocols.
 *
 * A rule matching on e.g. both IPv4 source address and IPv6 destination
 * address can never match a packet (a packet is either IPv4 or IPv6, not
 * both). Same for layer 4 (e.g. TCP vs UDP). Such rules should be disabled.
 *
 * @param chain Chain containing the sets.
 * @param rule Rule to check.
 * @return 0 if no conflict, 1 if the rule contains incompatible matchers, or
 *         a negative errno value on failure.
 */
static int _bf_rule_has_incompatible_matchers(const struct bf_chain *chain,
                                              const struct bf_rule *rule)
{
    uint32_t layer_hdr_id[_BF_MATCHER_LAYER_MAX];

    assert(chain);
    assert(rule);

    for (int i = 0; i < _BF_MATCHER_LAYER_MAX; ++i)
        layer_hdr_id[i] = UINT32_MAX;

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        int r = 0;

        if (bf_matcher_get_type(matcher) == BF_MATCHER_SET) {
            const struct bf_set *set =
                bf_chain_get_set_for_matcher(chain, matcher);

            if (!set) {
                return bf_err_r(-ENOENT, "rule %u references non-existent set",
                                rule->index);
            }

            for (size_t i = 0; i < set->n_comps && !r; ++i)
                r = _bf_rule_check_layer(set->key[i], layer_hdr_id);
        } else {
            r = _bf_rule_check_layer(bf_matcher_get_type(matcher),
                                     layer_hdr_id);
        }

        if (r < 0)
            return r;
        if (r) {
            bf_warn(
                "rule %u has incompatible matchers on the same layer, rule will be disabled",
                rule->index);
            return 1;
        }
    }

    return 0;
}

static int _bf_chain_check_rule(struct bf_chain *chain, struct bf_rule *rule)
{
    const uint8_t tuple = BF_FLAG(BF_LOG_OPT_5_TUPLE);
    int r;

    assert(rule);

    if (rule->verdict < 0 || rule->verdict >= _BF_VERDICT_MAX) {
        return bf_err_r(-EINVAL, "unknown verdict %d in rule %u", rule->verdict,
                        rule->index);
    }

    if (rule->verdict == BF_VERDICT_REDIRECT) {
        enum bf_flavor flavor = bf_hook_to_flavor(chain->hook);

        if (flavor != BF_FLAVOR_XDP && flavor != BF_FLAVOR_TC) {
            return bf_err_r(-ENOTSUP, "redirect is not supported by %s hook",
                            bf_hook_to_str(chain->hook));
        }

        if (flavor == BF_FLAVOR_XDP &&
            rule->redirect_dir != BF_REDIRECT_EGRESS) {
            return bf_err_r(-ENOTSUP,
                            "XDP redirect only supports 'out' direction");
        }
    }

    r = _bf_rule_has_unmatchable_set_matcher(chain, rule);
    if (r < 0)
        return r;
    rule->disabled = r;

    if (!rule->disabled) {
        r = _bf_rule_has_incompatible_matchers(chain, rule);
        if (r < 0)
            return r;

        rule->disabled = r;
    }

    if (rule->log != BF_LOG_OPT_DEFAULT && (rule->log & tuple) &&
        rule->log != tuple) {
        return bf_err_r(
            -EINVAL,
            "5-tuple logging can't be combined with packet layer options");
    }

    if (rule->log && rule->log != BF_LOG_OPT_DEFAULT &&
        bf_hook_to_flavor(chain->hook) == BF_FLAVOR_CGROUP_SOCK_ADDR) {
        return bf_err_r(
            -ENOTSUP,
            "per-field log options are not supported by %s, use 'log'",
            bf_hook_to_str(chain->hook));
    }

    if (rule->log && !rule->disabled)
        chain->flags |= BF_FLAG(BF_CHAIN_LOG);

    if (rule->log && rule->log_rate_ns && !rule->disabled)
        chain->flags |= BF_FLAG(BF_CHAIN_LOG_RATELIMIT);

    if (bf_rule_mark_is_set(rule) &&
        bf_hook_to_flavor(chain->hook) != BF_FLAVOR_TC &&
        bf_hook_to_flavor(chain->hook) != BF_FLAVOR_CGROUP_SKB) {
        return bf_err_r(-EINVAL, "%s chains can't set packet mark",
                        bf_hook_to_str(chain->hook));
    }

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        enum bf_matcher_type type = bf_matcher_get_type(matcher);
        enum bf_matcher_op op = bf_matcher_get_op(matcher);
        const struct bf_matcher_meta *meta;

        // Track if the chain uses IPv6 nexthdr matcher.
        if (type == BF_MATCHER_IP6_NEXTHDR && !rule->disabled)
            chain->flags |= BF_FLAG(BF_CHAIN_STORE_NEXTHDR);

        // Ensure the matcher is compatible with the chain's hook.
        meta = bf_matcher_get_meta(type);
        if (!meta) {
            return bf_err_r(-EINVAL, "unknown matcher type %d in rule", type);
        }

        if (op < 0 || op >= _BF_MATCHER_OP_MAX ||
            (type == BF_MATCHER_SET && op != BF_MATCHER_IN) ||
            (type != BF_MATCHER_SET &&
             (op == BF_MATCHER_IN || !bf_matcher_get_ops(type, op)))) {
            return bf_err_r(-EINVAL,
                            "unsupported operator %d for matcher %s in rule %u",
                            op, bf_matcher_type_to_str(type), rule->index);
        }

        if (meta->unsupported_hooks & BF_FLAG(chain->hook)) {
            return bf_err_r(-ENOTSUP, "matcher %s is not compatible with %s",
                            bf_matcher_type_to_str(type),
                            bf_hook_to_str(chain->hook));
        }

        if (type == BF_MATCHER_SET) {
            const struct bf_set *set =
                bf_chain_get_set_for_matcher(chain, matcher);

            if (!set) {
                return bf_err_r(-ENOENT, "rule %u references non-existent set",
                                rule->index);
            }

            for (size_t i = 0; i < set->n_comps; ++i) {
                const struct bf_matcher_meta *comp_meta =
                    bf_matcher_get_meta(set->key[i]);

                if (!comp_meta) {
                    return bf_err_r(-EINVAL,
                                    "missing meta for set component '%s'",
                                    bf_matcher_type_to_str(set->key[i]));
                }

                if (comp_meta->unsupported_hooks & BF_FLAG(chain->hook)) {
                    return bf_err_r(-ENOTSUP,
                                    "set component '%s' not compatible with %s",
                                    bf_matcher_type_to_str(set->key[i]),
                                    bf_hook_to_str(chain->hook));
                }
            }
        }
    }

    return 0;
}

static int _bf_chain_validate_rules(struct bf_chain *chain)
{
    int r;

    assert(chain);

    chain->flags = 0;

    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        r = _bf_chain_check_rule(chain, rule);
        if (r)
            return r;
    }

    return 0;
}

int bf_chain_new(struct bf_chain **chain, const char *name, enum bf_hook hook,
                 enum bf_verdict policy, bf_hashset *sets, bf_list *rules)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    size_t ridx = 0;
    int r;

    assert(chain && name);
    if (hook >= _BF_HOOK_MAX)
        return bf_err_r(-EINVAL, "unknown hook type");
    if (!bf_verdict_is_valid_policy(policy))
        return bf_err_r(-EINVAL, "invalid policy '%s'",
                        bf_verdict_to_str(policy));

    if (sets) {
        bf_hashset_foreach (sets, set_node) {
            const struct bf_set *set = set_node->data;

            if (!bf_set_is_valid_name(set->name))
                return bf_err_r(-EINVAL, "chain sets must have valid names");
        }
    }

    _chain = calloc(1, sizeof(*_chain));
    if (!_chain)
        return -ENOMEM;

    _chain->name = strdup(name);
    if (!_chain->name)
        return -ENOMEM;

    _chain->hook = hook;
    _chain->policy = policy;

    _chain->sets = bf_set_hashset_default();
    if (sets)
        _chain->sets = bf_hashset_move(sets);

    _chain->rules = bf_list_default(bf_rule_free, bf_rule_pack);
    if (rules)
        _chain->rules = bf_list_move(rules);
    bf_list_foreach (&_chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        rule->index = ridx++;
    }

    r = _bf_chain_validate_rules(_chain);
    if (r) {
        if (rules)
            *rules = bf_list_move(&_chain->rules);
        if (sets)
            *sets = bf_hashset_move(&_chain->sets);
        return r;
    }

    *chain = TAKE_PTR(_chain);

    return 0;
}

int bf_chain_new_from_pack(struct bf_chain **chain, bf_rpack_node_t node)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    _cleanup_free_ char *name = NULL;
    enum bf_hook hook;
    enum bf_verdict policy;
    bf_rpack_node_t array, array_node;
    _clean_bf_hashset_ bf_hashset sets = bf_set_hashset_default();
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    int r;

    r = bf_rpack_kv_str(node, "name", &name);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.name");

    r = bf_rpack_kv_enum(node, "hook", &hook, 0, _BF_HOOK_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.hook");

    r = bf_rpack_kv_enum(node, "policy", &policy, 0, _BF_VERDICT_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.policy");

    r = bf_rpack_kv_array(node, "sets", &array);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.sets");
    bf_rpack_array_foreach (array, array_node) {
        _free_bf_set_ struct bf_set *set = NULL;

        r = bf_set_new_from_pack(&set, array_node);
        if (r)
            return bf_err_r(r, "failed to unpack bf_set into bf_chain.sets");

        if (bf_set_is_anonymous(set))
            return bf_err_r(-EINVAL, "anonymous set outside a matcher");

        r = bf_hashset_add(&sets, (void **)&set);
        if (r)
            return bf_err_r(r, "failed to add unpacked set to chain");
    }

    r = bf_rpack_kv_array(node, "rules", &array);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.rules");
    bf_rpack_array_foreach (array, array_node) {
        _free_bf_rule_ struct bf_rule *rule = NULL;

        r = bf_list_emplace(&rules, bf_rule_new_from_pack, rule, array_node,
                            &sets);
        if (r) {
            return bf_err_r(r, "failed to unpack bf_rule into bf_chain.rules");
        }
    }

    r = bf_chain_new(&_chain, name, hook, policy, &sets, &rules);
    if (r)
        return bf_err_r(r, "failed to create bf_chain from pack");

    *chain = TAKE_PTR(_chain);

    return 0;
}

void bf_chain_free(struct bf_chain **chain)
{
    assert(chain);

    if (!*chain)
        return;

    bf_list_clean(&(*chain)->rules);
    bf_hashset_clean(&(*chain)->sets);
    BF_FREEP(&(*chain)->name);
    BF_FREEP(chain);
}

int bf_chain_pack(const struct bf_chain *chain, bf_wpack_t *pack)
{
    int r;

    assert(chain);
    assert(pack);

    bf_wpack_kv_str(pack, "name", chain->name);
    bf_wpack_kv_enum(pack, "hook", chain->hook);
    bf_wpack_kv_enum(pack, "policy", chain->policy);

    bf_wpack_open_array(pack, "sets");
    bf_hashset_foreach (&chain->sets, set_node) {
        bf_wpack_open_object(pack, NULL);
        r = bf_set_pack(set_node->data, pack);
        if (r)
            return r;
        bf_wpack_close_object(pack);
    }
    bf_wpack_close_array(pack);
    bf_wpack_kv_list(pack, "rules", &chain->rules);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix)
{
    assert(chain);
    assert(prefix);

    DUMP(prefix, "struct bf_chain at %p", chain);
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "name: %s", chain->name);
    DUMP(prefix, "flags: %02x", chain->flags);
    DUMP(prefix, "hook: %s", bf_hook_to_str(chain->hook));
    DUMP(prefix, "policy: %s", bf_verdict_to_str(chain->policy));

    DUMP(prefix, "sets: bf_hashset<bf_set>[%lu]",
         bf_hashset_size(&chain->sets));
    bf_dump_prefix_push(prefix);
    bf_hashset_foreach (&chain->sets, set_node) {
        if (!set_node->next)
            bf_dump_prefix_last(prefix);

        bf_set_dump(set_node->data, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "rules: bf_list<bf_rule>[%lu]",
         bf_list_size(&chain->rules));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&chain->rules, rule_node) {
        if (bf_list_is_tail(&chain->rules, rule_node))
            bf_dump_prefix_last(prefix);

        bf_rule_dump(bf_list_node_get_data(rule_node), prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "policy_counters: struct bf_counter");
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "count: %lu", chain->policy_counters.count);
    DUMP(prefix, "size: %lu", chain->policy_counters.size);
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "error_counters: struct bf_counter");
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "count: %lu", chain->error_counters.count);
    DUMP(prefix, "size: %lu", chain->error_counters.size);
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule)
{
    int r;

    assert(chain);
    assert(rule);

    rule->index = bf_list_size(&chain->rules);
    r = _bf_chain_check_rule(chain, rule);
    if (r)
        return r;

    return bf_list_add_tail(&chain->rules, rule);
}

int bf_chain_add_set(struct bf_chain *chain, struct bf_set *set)
{
    assert(chain && set);

    if (!bf_set_is_valid_name(set->name))
        return bf_err_r(-EINVAL, "only named sets can be added to a chain");

    return bf_hashset_add(&chain->sets, (void **)&set);
}

const struct bf_set *
bf_chain_get_set_for_matcher(const struct bf_chain *chain,
                             const struct bf_matcher *matcher)
{
    const struct bf_set *set;

    assert(chain);
    assert(matcher);

    if (bf_matcher_get_type(matcher) != BF_MATCHER_SET)
        return NULL;

    memcpy(&set, bf_matcher_payload(matcher), sizeof(struct bf_set *));
    if (bf_set_is_anonymous(set))
        return set;

    return bf_hashset_get(&chain->sets, set) == set ? set : NULL;
}

static struct bf_set *_bf_chain_get_set_by_name(struct bf_chain *chain,
                                                const char *set_name)
{
    struct bf_set key = {.name = set_name};

    assert(chain);
    assert(set_name);

    return bf_hashset_get(&chain->sets, &key);
}

const struct bf_set *bf_chain_get_set_by_name(const struct bf_chain *chain,
                                              const char *set_name)
{
    return _bf_chain_get_set_by_name((struct bf_chain *)chain, set_name);
}

int bf_chain_apply_set_delta(struct bf_chain *chain, const char *set_name,
                             const struct bf_set *to_add,
                             const struct bf_set *to_remove)
{
    _free_bf_set_ struct bf_set *add_copy = NULL;
    _free_bf_set_ struct bf_set *remove_copy = NULL;
    struct bf_set *set;
    int r;

    assert(chain);
    assert(set_name);

    if (!to_add && !to_remove)
        return bf_err_r(-EINVAL, "to_add and to_remove can't both be NULL");

    set = _bf_chain_get_set_by_name(chain, set_name);
    if (!set)
        return bf_err_r(-ENOENT, "set '%s' does not exist", set_name);

    if ((to_add && !bf_set_same_key(set, to_add)) ||
        (to_remove && !bf_set_same_key(set, to_remove)))
        return bf_err_r(-EINVAL, "set key format mismatch");

    if (to_add) {
        r = bf_set_new_from_copy(&add_copy, to_add);
        if (r)
            return r;

        r = bf_set_add_many(set, &add_copy);
        if (r)
            return bf_err_r(r, "failed to calculate set union");
    }

    if (to_remove) {
        r = bf_set_new_from_copy(&remove_copy, to_remove);
        if (r)
            return r;

        r = bf_set_remove_many(set, &remove_copy);
        if (r)
            return bf_err_r(r, "failed to calculate set difference");
    }

    r = _bf_chain_validate_rules(chain);
    if (r)
        return bf_err_r(r, "failed to validate chain after set update");

    return 0;
}

int bf_chain_new_from_copy(struct bf_chain **dest, const struct bf_chain *src)
{
    _free_bf_chain_ struct bf_chain *copy = NULL;
    int r;

    assert(dest);
    assert(src);

    if (src->hook < 0 || src->hook >= _BF_HOOK_MAX)
        return bf_err_r(-EINVAL, "unknown source chain hook type");

    r = bf_chain_new(&copy, src->name, src->hook, src->policy, NULL, NULL);
    if (r)
        return r;

    r = bf_hashset_reserve(&copy->sets, bf_hashset_size(&src->sets));
    if (r)
        return r;

    bf_hashset_foreach (&src->sets, set_node) {
        _free_bf_set_ struct bf_set *set = NULL;

        r = bf_set_new_from_copy(&set, set_node->data);
        if (r)
            return r;

        r = bf_hashset_add(&copy->sets, (void **)&set);
        if (r)
            return r;
    }

    bf_list_foreach (&src->rules, rule_node) {
        _free_bf_rule_ struct bf_rule *rule = NULL;

        r = bf_rule_new_from_copy(&rule, bf_list_node_get_data(rule_node));
        if (r)
            return r;

        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            const struct bf_set *set;

            if (bf_matcher_get_type(matcher) != BF_MATCHER_SET)
                continue;

            set = bf_chain_get_set_for_matcher(src, matcher);
            if (!set)
                return bf_err_r(-ENOENT,
                                "matcher set not found in source chain");
            if (!set->name)
                continue;

            set = bf_chain_get_set_by_name(copy, set->name);
            if (!set)
                return bf_err_r(-ENOENT,
                                "matcher set not found in copied chain");

            memcpy((void *)bf_matcher_payload(matcher), &set,
                   sizeof(struct bf_set *));
        }

        r = bf_chain_add_rule(copy, rule);
        if (r)
            return r;

        TAKE_PTR(rule);
    }

    *dest = TAKE_PTR(copy);

    return 0;
}
