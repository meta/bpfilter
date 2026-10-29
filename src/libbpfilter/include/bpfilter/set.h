// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <bpfilter/core/hashset.h>
#include <bpfilter/dump.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>

/**
 * @file set.h
 *
 * A set represent a set of data of the same type. They allow bpfilter to
 * perform O(1) lookup in large pools of data of the same type.
 *
 * For example, a set would be useful to match a network packet against many
 * different IP addresses. Instead of creating a different rule for each IP
 * address, they could be added into a set and the BPF program would comparing
 * the packet's IP address to the whole set a once.
 *
 * Sets are implemented as BPF hash maps, allowing for O(1) lookup for a given
 * key.
 */

#define _free_bf_set_ __attribute__((__cleanup__(bf_set_free)))

/// Maximum number of components (matchers) allowed in a set key/element.
#define BF_SET_MAX_N_COMPS 8

/**
 * @brief Set object, used to group data of the same type to speed up filtering.
 *
 * Sets are composed of two key elements:
 * - Key: defines how the data in the set is structure, using `bf_matcher_type`
 *   values.
 * - Elements: values stored in the set, to compare values from the packet
 *   against.
 */
struct bf_set
{
    /** Immutable name of the set. NULL for anonymous sets. */
    const char *name;

    /** Key of the set. Can't contain more than `BF_SET_MAX_N_COMPS` types. */
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];

    /** Number of components (types) present in the key. */
    size_t n_comps;

    /** Elements of the set. */
    bf_hashset elems;

    /** Size of a single element. All elements have the same size, it's derived
     * from the key. */
    size_t elem_size;

    /** If a set key has a single component which filters on a network address,
     * use a LPM trie structure instead of the standard hash map. */
    bool use_trie;

    /** Minimum number of elements the set's BPF map should have room for.
     * 0 by default: the map is sized to fit the set's elements. This is a
     * lower bound, not a limit: the map grows past `min_size` if the set
     * contains more elements. Only used to size the BPF map: `elems` is not
     * pre-allocated for `min_size` elements. */
    size_t min_size;
};

/**
 * @brief Check whether a set name can be supplied by a user.
 *
 * Names must be non-empty and contain only ASCII letters, digits, underscores,
 * and hyphens.
 *
 * @param name Name to validate. Can be NULL, which is not a valid name.
 * @return true if the name is valid for a user-defined set, false otherwise.
 */
bool bf_set_is_valid_name(const char *name);

/**
 * @brief Check whether a set is anonymous (no name).
 *
 * @param set Set to check. Can't be NULL.
 * @return true if the set is anonymous, false if it has a user-defined name.
 */
bool bf_set_is_anonymous(const struct bf_set *set);

/**
 * @brief Initialize an empty owning collection of named sets.
 *
 * @return An empty hashset that preserves insertion order and frees its sets.
 */
bf_hashset bf_set_hashset_default(void);

/**
 * @brief Validate a set's key layout and element size without modifying it.
 *
 * @param set Set to validate. Can't be NULL.
 * @return 0 on success, or a negative errno value for an invalid component
 *         count, unsupported key, or inconsistent element size.
 */
int bf_set_validate(const struct bf_set *set);

/**
 * @brief Allocate and initialise a new set.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param name Name of the set. Non-NULL names must satisfy
 *        `bf_set_is_valid_name()`. NULL creates an anonymous set.
 * @param key Key of the set, as an array of `bf_matcher_type`. Not all the
 *        matcher types can be used as set key components. Can't be NULL.
 * @param n_comps Number of components in `key`.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_set_new(struct bf_set **set, const char *name,
               const enum bf_matcher_type *key, size_t n_comps);

/**
 * @brief Allocate and initialise a new set from a raw key and payload values.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param name Name of the set. Non-NULL names must satisfy
 *        `bf_set_is_valid_name()`. NULL creates an anonymous set.
 * @param raw_key Set key, as a string of comma-separated matcher types enclosed
 *        in parentheses. Can't be NULL.
 * @param raw_payload Set payload, to parse according to `raw_key`. Can't be
 *        NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_set_new_from_raw(struct bf_set **set, const char *name,
                        const char *raw_key, const char *raw_payload);

/**
 * @brief Allocate and initialize a new set from serialized data.
 *
 * @param set Set object to allocate and initialize from the serialized data.
 *        The caller will own the object. On failure, `*set` is unchanged.
 *        Can't be NULL.
 * @param node Node containing the serialized set. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_set_new_from_pack(struct bf_set **set, bf_rpack_node_t node);

/**
 * @brief Allocate and initialise a set as a copy of another set.
 *
 * @param dest Destination set. The caller owns the object on success. Can't be
 *        NULL.
 * @param src Set to copy. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_set_new_from_copy(struct bf_set **dest, const struct bf_set *src);

void bf_set_free(struct bf_set **set);

/**
 * @brief Serialize a set.
 *
 * @param set Set to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the set into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_set_pack(const struct bf_set *set, bf_wpack_t *pack);

void bf_set_dump(const struct bf_set *set, prefix_t *prefix);

/**
 * @brief Check if a set is empty.
 *
 * @param set Initialised set. Can't be NULL.
 * @return True if the set has no elements, false otherwise.
 */
bool bf_set_is_empty(const struct bf_set *set);

/**
 * @brief Check whether two sets have the same key format.
 *
 * @param lhs First set. Can't be NULL.
 * @param rhs Second set. Can't be NULL.
 * @return true if both sets have the same key components, false otherwise.
 */
bool bf_set_same_key(const struct bf_set *lhs, const struct bf_set *rhs);

/**
 * @brief Pre-allocate capacity for at least `count` elements.
 *
 * @param set Initialised set. Can't be NULL.
 * @param count Expected number of elements.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_set_reserve(struct bf_set *set, size_t count);

/**
 * @brief Insert an element into a set, if it is not already present.
 *
 * @param set Set to insert the element into. Can't be NULL.
 * @param elem Element to insert. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_set_add_elem(struct bf_set *set, const void *elem);

/**
 * @brief Parse a raw element and insert it into a set.
 *
 * The element is parsed according to `set->key`.
 *
 * @param set Set to parse the element for. Can't be NULL.
 * @param raw_elem Raw element to parse. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_set_add_elem_raw(struct bf_set *set, const char *raw_elem);

/**
 * @brief Add elements to destination set.
 *
 * Adds all elements from `*to_add` to `dest`. Both sets must have the same
 * key format. On success, takes ownership of `*to_add` and frees it.
 *
 * @param dest Destination set to add elements to. Can't be NULL.
 * @param to_add Source set containing elements to add. Can't be NULL. On
 *        success, `*to_add` is freed and set to NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-EINVAL`: set key format doesn't match between dest and to_add.
 */
int bf_set_add_many(struct bf_set *dest, struct bf_set **to_add);

/**
 * @brief Remove elements from destination set.
 *
 * Removes all elements present in `*to_remove` from `dest`. Both sets must
 * have the same key format. Elements in `*to_remove` that aren't present in
 * `dest` are ignored. On success, takes ownership of `*to_remove` and frees it.
 *
 * @param dest Destination set to remove elements from. Can't be NULL.
 * @param to_remove Source set containing elements to remove. Can't be NULL.
 *        On success, `*to_remove` is freed and set to NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-EINVAL`: set key format doesn't match between dest and to_remove.
 */
int bf_set_remove_many(struct bf_set *dest, struct bf_set **to_remove);
