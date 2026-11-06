/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/core/hashset.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/hook.h>
#include <bpfilter/pack.h>
#include <bpfilter/verdict.h>

struct bf_hookopts;
struct bf_matcher;
struct bf_rule;
struct bf_set;

#define _free_bf_chain_ __attribute__((cleanup(bf_chain_free)))

/**
 * @brief Features used by the rules defined in the chain.
 *
 * Some features used by the rules have an impact at the chain or program level,
 * these flags are used to define which feature is used at the chain level,  and
 * generate the bytecode accordingly.
 *
 * For example, a pointer to the log ring buffer is store in the program's
 * runtime context. This pointer should not be populated if no rule is has a
 * 'log' instruction.
 *
 * Grouping the list of required features at the chain level prevents us from
 * parsing all the rules and matchers everytime the feature would affect the
 * bytecode.
 */
enum bf_chain_flags
{
    /** A rule will log data to the ring buffer. */
    BF_CHAIN_LOG,

    /** A rule uses rate-limited logging (log ... every). */
    BF_CHAIN_LOG_RATELIMIT,

    /** A rule will filter on IPv6 nexthdr field. */
    BF_CHAIN_STORE_NEXTHDR,

    _BF_CHAIN_FLAGS_MAX,
};

struct bf_chain
{
    const char *name;
    uint8_t flags;
    enum bf_hook hook;
    enum bf_verdict policy;

    /// Owning collection of named sets. Anonymous sets belong to matchers.
    bf_hashset sets;
    bf_list rules;

    /// Policy counters. Not serialized.
    struct bf_counter policy_counters;

    /// Error counters. Not serialized.
    struct bf_counter error_counters;
};

/**
 * Allocate and initialize a `bf_chain` object.
 *
 * The content of `sets` and `rules` is stolen by the constructor if the
 * function succeeds, in which case the source lists are empty and the chain
 * is responsible for the data. Otherwise, both list are unchanged.
 *
 * @param chain `bf_chain` object to allocate and initialize. On failure,
 *        this parameter is unchanged. Can't be NULL.
 * @param name Name of the chain. Can't be NULL.
 * @param hook Expected hook to attach the chain to.
 * @param policy Default action of the chain if no rule matched.
 * @param sets Owning collection of named sets, initialized with
 *        bf_set_hashset_default(). Names must be unique within the chain.
 * @param rules List of rules.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_chain_new(struct bf_chain **chain, const char *name, enum bf_hook hook,
                 enum bf_verdict policy, bf_hashset *sets, bf_list *rules);

/**
 * @brief Allocate and initialize a new chain from serialized data.
 *
 * @param chain Chain object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*chain` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_new_from_pack(struct bf_chain **chain, bf_rpack_node_t node);

/**
 * Deallocate a `bf_chain` object.
 *
 * @param chain `bf_chain` object to cleanup and deallocate. If `*chain`
 *        is NULL, this function has no effect. Can't be NULL.
 */
void bf_chain_free(struct bf_chain **chain);

/**
 * @brief Serialize a chain.
 *
 * @param chain Chain to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the chain into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_chain_pack(const struct bf_chain *chain, bf_wpack_t *pack);

/**
 * Dump the content of a `bf_chain` object.
 *
 * @param chain `bf_chain` object to print. Can't be NULL.
 * @param prefix Prefix to use for the dump. Can't be NULL.
 */
void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix);

/**
 * Insert a rule into the chain.
 *
 * The chain will own the rule and is responsible for freeing it. The rule's
 * index will automatically be updated.
 *
 * A rule without any matcher matches unconditionally.
 *
 * @param chain Chain to insert the rule into. Can't be NULL.
 * @param rule Rule to insert into the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule);

/**
 * @brief Insert a named set into a chain.
 *
 * The chain will own the set and is responsible for freeing it. To reference
 * the set in a matcher, use `bf_matcher_new_for_named_set`.
 *
 * @param chain Chain to insert the rule into. Can't be NULL.
 * @param set Set to insert into the chain. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_chain_add_set(struct bf_chain *chain, struct bf_set *set);

/**
 * @brief Get the set used by a matcher.
 *
 * @param chain Chain to get the set from. Can't be NULL.
 * @param matcher Matching filtering on a set. Can't be NULL.
 * @return The set `matcher` filters on, or NULL if the set can't be found or
 *         if `matcher->type` is not `BF_MATCHER_SET`.
 *         The pointer is borrowed. Anonymous sets belong to their matcher.
 */
const struct bf_set *
bf_chain_get_set_for_matcher(const struct bf_chain *chain,
                             const struct bf_matcher *matcher);

/**
 * @brief Get a set from the chain by name.
 *
 * Returns a pointer to the set with the given name. The returned pointer
 * is owned by the chain and should not be freed by the caller.
 *
 * @param chain Chain to get the set from. Can't be NULL.
 * @param set_name Name of the set to retrieve. Can't be NULL.
 * @return Pointer to the set, or NULL if not found.
 */
const struct bf_set *bf_chain_get_set_by_name(const struct bf_chain *chain,
                                              const char *set_name);

/**
 * @brief Apply element additions and removals to a set owned by a chain.
 *
 * Each non-NULL delta must have the same key format as the set named by
 * `set_name`. At least one delta must be non-NULL.
 *
 * @param chain Chain containing the set to update. Can't be NULL.
 * @param set_name Name of the set to update. Can't be NULL.
 * @param to_add Set containing elements to add. Can be NULL if `to_remove` is
 *        non-NULL.
 * @param to_remove Set containing elements to remove. Can be NULL if `to_add`
 *        is non-NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_apply_set_delta(struct bf_chain *chain, const char *set_name,
                             const struct bf_set *to_add,
                             const struct bf_set *to_remove);

/** Allocate and initialize a chain as a copy of another chain.
 *
 * @param dest The destination chain. It will be allocated during the call.
 *        Can't be NULL.
 * @param src The source chain, to copy from. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_chain_new_from_copy(struct bf_chain **dest, const struct bf_chain *src);
