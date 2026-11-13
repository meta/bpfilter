/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/core/hashset.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>

#define BF_RULE_MARK_MASK (0x00000000ffffffffULL)

/**
 * @brief Return the string representation of a `bf_log_opt` enumeration value.
 *
 * @param hdr `bf_log_opt` enumeration value.
 * @return A pointer to the C-string representation of `hdr`.
 */
const char *bf_log_opt_to_str(enum bf_log_opt hdr);

/**
 * @brief Return the `bf_log_opt` enumeration value corresponding to a string.
 *
 * @pre
 * - `str` is a non-NULL pointer to a C-string.
 * - `hdr != NULL`
 * @post
 * - On failure, `hdr` is unchanged.
 *
 * @param str String to get the corresponding `bf_log_opt` enumeration value for.
 * @param hdr On success, contains the `bf_log_opt` enumeration value
 *        corresponding to `str`.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_log_opt_from_str(const char *str, enum bf_log_opt *hdr);

#define _free_bf_rule_ __attribute__((__cleanup__(bf_rule_free)))

/**
 * @struct bf_rule
 *
 * Represents a rule to match against packets.
 *
 * @var bf_rule::index
 *  Rule's index. Identifies the rule's within other rules from the same chain.
 */
struct bf_rule
{
    uint32_t index;
    bf_list matchers;
    uint8_t log;

    /** Minimum interval between two log events for this rule, in nanoseconds.
     * Zero means no rate limiting: every match is logged. */
    uint64_t log_rate_ns;

    /** Mark to set to the packet's `sk_buff`. Only support for some hooks.
     * The leftmost 32 bits are set to 1 if a mark is defined, or 0 otherwise.
     * See `bf_rule_mark_is_set`. */
    uint64_t mark;

    /** If set, the rule records matched elements count, and `bf_rule::counters`
     * is valid. */
    uint8_t has_counters:1;

    /** Element and size counters for matched traffic. Only valid if
     * `has_counters == 1`. This field is used when reading a chain, not when
     * creating it. This field is not serialized.
     *
     * @todo Use this field to allow users to initialize the rule's counters
     * to a specific value. */
    struct bf_counter counters;

    /** If true, skip this rule during flag calculation and code generation. */
    bool disabled;

    enum bf_verdict verdict;

    /** Target interface index for REDIRECT verdict. 0 if not set. */
    uint32_t redirect_ifindex;
    /** Direction for REDIRECT verdict. */
    enum bf_redirect_dir redirect_dir;

    /** Reply sent by the REJECT verdict. Ignored for the other verdicts. */
    enum bf_reject_type reject_type;
};

static_assert(
    _BF_LOG_OPT_MAX < 8,
    "bf_log_opt has more than 8 values, it won't fit in bf_rule.log's 8 bits");

/**
 * Allocated and initialise a new rule.
 *
 * On failure, @p rule is left unchanged.
 *
 * @param rule On success, points to the allocated rule. Must be non NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_rule_new(struct bf_rule **rule);

/**
 * @brief Allocate and initialize a new rule from serialized data.
 *
 * @param rule Rule object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*rule` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized rule. Can't be NULL.
 * @param sets Sets used to resolve named matcher references. Can be NULL if
 *        no matcher references a named set.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_rule_new_from_pack(struct bf_rule **rule, bf_rpack_node_t node,
                          const bf_hashset *sets);

/**
 * @brief Allocate a copy of a rule and its matchers.
 *
 * Anonymous sets are deep-copied. Named sets remain borrowed from the same
 * owner as the source rule. That owner must outlive the copied rule, including
 * its destruction.
 *
 * Runtime counters and disabled state are reset. Adding the copy to a chain
 * assigns its index, validates set references, and recalculates disabled state.
 *
 * @warning Before inserting the copy into another chain, replace its named-set
 * matchers with matchers that borrow that chain's sets. Matching names alone
 * do not rebind references. To copy a complete chain, use
 * `bf_chain_new_from_copy()`, which rebinds references to the copied sets.
 *
 * @param dest Destination rule. Unchanged on failure. Can't be NULL.
 * @param src Rule to copy. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_rule_new_from_copy(struct bf_rule **dest, const struct bf_rule *src);

/**
 * Free a rule.
 *
 * Free @p rule and set it to NULL. If @p rule is NULL, nothing is done.
 *
 * @param rule Rule to free. Must be non-NULL.
 */
void bf_rule_free(struct bf_rule **rule);

/**
 * @brief Serialize a rule.
 *
 * @param rule Rule to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the matcher rule. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_rule_pack(const struct bf_rule *rule, bf_wpack_t *pack);

/**
 * Dump a rule.
 *
 * @param rule Rule to dump. Must not be NULL.
 * @param prefix Prefix for each printed line.
 */
void bf_rule_dump(const struct bf_rule *rule, prefix_t *prefix);

/**
 * Create a new matcher and add it to the rule.
 *
 * @param rule Rule to add the matcher to. Can't be NULL.
 * @param type Matcher type. `BF_MATCHER_SET` is not supported. Create set
 *        matchers with their constructors and add them to `rule->matchers`.
 * @param op Comparison operator.
 * @param payload Payload of the matcher, its content and size depends on @p
 *        type . Can be NULL but only if `payload_len` is 0, in which case
 *        there is no payload.
 * @param payload_len Length of the input payload.
 * @param negate If true, negate the matcher's comparison.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_rule_add_matcher(struct bf_rule *rule, enum bf_matcher_type type,
                        enum bf_matcher_op op, const void *payload,
                        size_t payload_len, bool negate);

static inline void bf_rule_mark_set(struct bf_rule *rule, uint32_t mark)
{
    assert(rule);

    rule->mark = ~BF_RULE_MARK_MASK | mark;
}

static inline uint32_t bf_rule_mark_get(const struct bf_rule *rule)
{
    assert(rule);

    return rule->mark & BF_RULE_MARK_MASK;
}

static inline bool bf_rule_mark_is_set(const struct bf_rule *rule)
{
    assert(rule);

    return rule->mark >> 32;
}

static inline void bf_rule_set_redirect(struct bf_rule *rule, uint32_t ifindex,
                                        enum bf_redirect_dir dir)
{
    assert(rule);

    rule->redirect_ifindex = ifindex;
    rule->redirect_dir = dir;
}

static inline bool bf_rule_has_redirect(const struct bf_rule *rule)
{
    assert(rule);

    return rule->redirect_ifindex != 0;
}
