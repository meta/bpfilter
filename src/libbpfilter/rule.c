/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/rule.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/core/list.h"
#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "bpfilter/matcher.h"
#include "bpfilter/pack.h"
#include "bpfilter/runtime.h"
#include "bpfilter/verdict.h"

static const char *_bf_log_opt_strs[] = {
    [BF_LOG_OPT_LINK] = "link",
    [BF_LOG_OPT_INTERNET] = "internet",
    [BF_LOG_OPT_TRANSPORT] = "transport",
    [BF_LOG_OPT_5_TUPLE] = "5-tuple",
};
static_assert_enum_mapping(_bf_log_opt_strs, _BF_LOG_OPT_MAX);

const char *bf_log_opt_to_str(enum bf_log_opt hdr)
{
    if (hdr < 0 || hdr >= _BF_LOG_OPT_MAX)
        return "<bf_log_opt unknown>";

    return _bf_log_opt_strs[hdr];
}

int bf_log_opt_from_str(const char *str, enum bf_log_opt *hdr)
{
    assert(hdr);

    for (int i = 0; i < _BF_LOG_OPT_MAX; ++i) {
        if (bf_streq_i(str, _bf_log_opt_strs[i])) {
            *hdr = (enum bf_log_opt)i;
            return 0;
        }
    }

    return -EINVAL;
}

int bf_rule_new(struct bf_rule **rule)
{
    _free_bf_rule_ struct bf_rule *_rule = NULL;

    assert(rule);

    _rule = calloc(1, sizeof(*_rule));
    if (!_rule)
        return -ENOMEM;

    _rule->matchers = bf_list_default(bf_matcher_free, bf_matcher_pack);

    *rule = TAKE_PTR(_rule);

    return 0;
}

int bf_rule_new_from_pack(struct bf_rule **rule, bf_rpack_node_t node,
                          const bf_hashset *sets)
{
    _free_bf_rule_ struct bf_rule *_rule = NULL;
    bf_rpack_node_t m_nodes, m_node;
    bool has_counters;
    int r;

    assert(rule);

    r = bf_rule_new(&_rule);
    if (r)
        return bf_err_r(r, "failed to create bf_rule from pack");

    r = bf_rpack_kv_u32(node, "index", &_rule->index);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.index");

    r = bf_rpack_kv_u8(node, "log", &_rule->log);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.log");

    if (bf_rpack_kv_contains(node, "log_rate_ns")) {
        r = bf_rpack_kv_u64(node, "log_rate_ns", &_rule->log_rate_ns);
        if (r)
            return bf_rpack_key_err(r, "bf_rule.log_rate_ns");
    }

    if (bf_rpack_kv_contains(node, "has_counters")) {
        r = bf_rpack_kv_bool(node, "has_counters", &has_counters);
        if (r)
            return bf_rpack_key_err(r, "bf_rule.has_counters");
    } else if (bf_rpack_kv_contains(node, "counters")) {
        r = bf_rpack_kv_bool(node, "counters", &has_counters);
        if (r)
            return bf_rpack_key_err(r, "bf_rule.counters");
    } else {
        return bf_err_r(-ENOENT, "missing bf_rule counters flag in pack");
    }
    _rule->has_counters = has_counters;

    r = bf_rpack_kv_u64(node, "mark", &_rule->mark);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.mark");

    r = bf_rpack_kv_enum(node, "verdict", &_rule->verdict, 0, _BF_VERDICT_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.verdict");

    if (bf_rpack_kv_contains(node, "redirect_ifindex")) {
        r = bf_rpack_kv_u32(node, "redirect_ifindex", &_rule->redirect_ifindex);
        if (r)
            return bf_rpack_key_err(r, "bf_rule.redirect_ifindex");
    }

    if (bf_rpack_kv_contains(node, "redirect_dir")) {
        r = bf_rpack_kv_enum(node, "redirect_dir", &_rule->redirect_dir, 0,
                             _BF_REDIRECT_DIR_MAX);
        if (r)
            return bf_rpack_key_err(r, "bf_rule.redirect_dir");
    }

    if (bf_rpack_kv_contains(node, "reject_type")) {
        r = bf_rpack_kv_enum(node, "reject_type", &_rule->reject_type, 0,
                             _BF_REJECT_TYPE_MAX);
        if (r)
            return bf_rpack_key_err(r, "bf_rule.reject_type");
    }

    r = bf_rpack_kv_array(node, "matchers", &m_nodes);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.matchers");
    bf_rpack_array_foreach (m_nodes, m_node) {
        _free_bf_matcher_ struct bf_matcher *matcher = NULL;

        r = bf_list_emplace(&_rule->matchers, bf_matcher_new_from_pack, matcher,
                            m_node, sets);
        if (r) {
            return bf_err_r(
                r, "failed to unpack bf_matcher into bf_rule.matchers");
        }
    }

    *rule = TAKE_PTR(_rule);

    return 0;
}

int bf_rule_new_from_copy(struct bf_rule **dest, const struct bf_rule *src)
{
    _free_bf_rule_ struct bf_rule *copy = NULL;
    int r;

    assert(dest);
    assert(src);

    if (src->verdict < 0 || src->verdict >= _BF_VERDICT_MAX ||
        src->redirect_dir < 0 || src->redirect_dir >= _BF_REDIRECT_DIR_MAX) {
        return bf_err_r(-EINVAL,
                        "invalid source rule verdict or redirect direction");
    }

    if (src->reject_type < 0 || src->reject_type >= _BF_REJECT_TYPE_MAX)
        return bf_err_r(-EINVAL, "invalid source rule reject type");

    r = bf_rule_new(&copy);
    if (r)
        return r;

    copy->index = src->index;
    copy->log = src->log;
    copy->log_rate_ns = src->log_rate_ns;
    copy->has_counters = src->has_counters;
    copy->mark = src->mark;
    copy->verdict = src->verdict;
    copy->redirect_ifindex = src->redirect_ifindex;
    copy->redirect_dir = src->redirect_dir;
    copy->reject_type = src->reject_type;

    bf_list_foreach (&src->matchers, matcher_node) {
        _free_bf_matcher_ struct bf_matcher *matcher = NULL;

        r = bf_list_emplace(&copy->matchers, bf_matcher_new_from_copy, matcher,
                            bf_list_node_get_data(matcher_node));
        if (r)
            return r;
    }

    *dest = TAKE_PTR(copy);

    return 0;
}

void bf_rule_free(struct bf_rule **rule)
{
    assert(rule);

    if (!*rule)
        return;

    bf_list_clean(&(*rule)->matchers);

    free(*rule);
    *rule = NULL;
}

int bf_rule_pack(const struct bf_rule *rule, bf_wpack_t *pack)
{
    assert(rule);
    assert(pack);

    bf_wpack_kv_u32(pack, "index", rule->index);
    bf_wpack_kv_u8(pack, "log", rule->log);
    bf_wpack_kv_u64(pack, "log_rate_ns", rule->log_rate_ns);
    bf_wpack_kv_bool(pack, "has_counters", rule->has_counters);
    bf_wpack_kv_u64(pack, "mark", rule->mark);
    bf_wpack_kv_int(pack, "verdict", rule->verdict);
    bf_wpack_kv_u32(pack, "redirect_ifindex", rule->redirect_ifindex);
    bf_wpack_kv_int(pack, "redirect_dir", rule->redirect_dir);
    bf_wpack_kv_int(pack, "reject_type", rule->reject_type);

    bf_wpack_kv_list(pack, "matchers", &rule->matchers);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_rule_dump(const struct bf_rule *rule, prefix_t *prefix)
{
    assert(rule);
    assert(prefix);

    DUMP(prefix, "struct bf_rule at %p", rule);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "index: %u", rule->index);

    // Matchers
    DUMP(prefix, "matchers: %lu", bf_list_size(&rule->matchers));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        if (bf_list_is_tail(&rule->matchers, matcher_node))
            bf_dump_prefix_last(prefix);

        bf_matcher_dump(matcher, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "log: %02x", rule->log);

    DUMP(prefix, "has_counters: %s", rule->has_counters ? "yes" : "no");
    if (rule->has_counters) {
        DUMP(prefix, "counters: struct bf_counter");
        bf_dump_prefix_push(prefix);
        DUMP(prefix, "count: %lu", rule->counters.count);
        DUMP(prefix, "size: %lu", rule->counters.size);
        bf_dump_prefix_pop(prefix);
    }

    DUMP(prefix, "disabled: %s", rule->disabled ? "yes" : "no");
    DUMP(prefix, "mark: 0x%" PRIx64, rule->mark);
    DUMP(prefix, "verdict: %s", bf_verdict_to_str(rule->verdict));
    if (bf_rule_has_redirect(rule)) {
        DUMP(prefix, "redirect_ifindex: %u", rule->redirect_ifindex);
        DUMP(prefix, "redirect_dir: %s",
             bf_redirect_dir_to_str(rule->redirect_dir));
    } else {
        DUMP(prefix, "redirect_ifindex: <not set>");
        DUMP(prefix, "redirect_dir: <not set>");
    }
    if (rule->verdict == BF_VERDICT_REJECT) {
        DUMP(bf_dump_prefix_last(prefix), "reject_type: %s",
             bf_reject_type_to_str(rule->reject_type));
    } else {
        DUMP(bf_dump_prefix_last(prefix), "reject_type: <not set>");
    }

    bf_dump_prefix_pop(prefix);
}

int bf_rule_add_matcher(struct bf_rule *rule, enum bf_matcher_type type,
                        enum bf_matcher_op op, const void *payload,
                        size_t payload_len, bool negate)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    int r;

    assert(rule);

    r = bf_matcher_new(&matcher, type, op, payload, payload_len, negate);
    if (r)
        return r;

    r = bf_list_add_tail(&rule->matchers, matcher);
    if (r)
        return r;

    TAKE_PTR(matcher);

    return 0;
}
