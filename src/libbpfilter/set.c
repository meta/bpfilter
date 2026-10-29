// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/set.h"

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/core/hashset.h"
#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"

#define _BF_SET_NAME_CHARS                                                     \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

/// Mask value of matcher types supporting LPM trie maps.
#define _BF_SET_USE_TRIE_MASK                                                  \
    (BF_FLAGS(BF_MATCHER_IP4_SNET, BF_MATCHER_IP4_DNET, BF_MATCHER_IP6_SNET,   \
              BF_MATCHER_IP6_DNET))

static uint64_t _bf_set_elem_hash(const void *data, void *ctx)
{
    return bf_fnv1a(data, *(const size_t *)ctx, bf_fnv1a_init());
}

static bool _bf_set_elem_equal(const void *lhs, const void *rhs, void *ctx)
{
    return memcmp(lhs, rhs, *(const size_t *)ctx) == 0;
}

static void _bf_set_elem_free(void **data, void *ctx)
{
    (void)ctx;
    BF_FREEP(data);
}

static const bf_hashset_ops _bf_set_elem_ops = {
    .hash = _bf_set_elem_hash,
    .equal = _bf_set_elem_equal,
    .free = _bf_set_elem_free,
};

static uint64_t _bf_set_name_hash(const void *data, void *ctx)
{
    const struct bf_set *set = data;

    (void)ctx;

    return bf_fnv1a(set->name, strlen(set->name), bf_fnv1a_init());
}

static bool _bf_set_name_equal(const void *lhs, const void *rhs, void *ctx)
{
    const struct bf_set *left = lhs;
    const struct bf_set *right = rhs;

    (void)ctx;

    return bf_streq(left->name, right->name);
}

static void _bf_set_collection_free(void **data, void *ctx)
{
    (void)ctx;

    bf_set_free((struct bf_set **)data);
}

bf_hashset bf_set_hashset_default(void)
{
    const bf_hashset_ops ops = {
        .hash = _bf_set_name_hash,
        .equal = _bf_set_name_equal,
        .free = _bf_set_collection_free,
    };

    return bf_hashset_default(&ops, NULL);
}

bool bf_set_is_valid_name(const char *name)
{
    return name && *name && name[strspn(name, _BF_SET_NAME_CHARS)] == '\0';
}

bool bf_set_is_anonymous(const struct bf_set *set)
{
    assert(set);

    return !set->name;
}

/** Validate a key and calculate its element size without allocating a set. */
static int _bf_set_key_size(const enum bf_matcher_type *key, size_t n_comps,
                            size_t *elem_size)
{
    uint64_t mask = 0;
    size_t size = 0;

    assert(key);
    assert(elem_size);

    if (n_comps == 0)
        return bf_err_r(-EINVAL, "at least 1 key component is required");

    if (n_comps > BF_SET_MAX_N_COMPS) {
        return bf_err_r(-E2BIG,
                        "a set key can't contain more than %d components",
                        BF_SET_MAX_N_COMPS);
    }

    for (size_t i = 0; i < n_comps; ++i) {
        const struct bf_matcher_ops *ops;

        ops = bf_matcher_get_ops(key[i], BF_MATCHER_IN);
        if (!ops) {
            return bf_err_r(-ENOTSUP,
                            "matcher '%s' (%d) is not supported as a set key",
                            bf_matcher_type_to_str(key[i]), key[i]);
        }
        size += ops->ref_payload_size;

        mask |= BF_FLAG(key[i]);
    }

    if (n_comps > 1 && mask & _BF_SET_USE_TRIE_MASK) {
        return bf_err_r(
            -EINVAL,
            "network matchers can't be used in combination with other matchers in a set");
    }

    *elem_size = size;

    return 0;
}

int bf_set_validate(const struct bf_set *set)
{
    size_t elem_size;
    int r;

    assert(set);

    r = _bf_set_key_size(set->key, set->n_comps, &elem_size);
    if (r)
        return r;

    if (set->elem_size != elem_size)
        return bf_err_r(-EINVAL, "set element size does not match its key");

    return 0;
}

int bf_set_new(struct bf_set **set, const char *name,
               const enum bf_matcher_type *key, size_t n_comps)
{
    _free_bf_set_ struct bf_set *_set = NULL;
    size_t elem_size;
    int r;

    assert(set);
    assert(key);

    if (name && !bf_set_is_valid_name(name))
        return bf_err_r(-EINVAL, "invalid set name '%s'", name);

    r = _bf_set_key_size(key, n_comps, &elem_size);
    if (r)
        return r;

    _set = calloc(1, sizeof(*_set));
    if (!_set)
        return -ENOMEM;

    if (name) {
        _set->name = strdup(name);
        if (!_set->name)
            return bf_err_r(-ENOMEM, "failed to allocate memory for set name");
    }

    memcpy(&_set->key, key, n_comps * sizeof(enum bf_matcher_type));
    _set->n_comps = n_comps;
    _set->elem_size = elem_size;
    _set->min_size = 0;
    _set->use_trie = n_comps == 1 && (BF_FLAG(key[0]) & _BF_SET_USE_TRIE_MASK);
    bf_hashset_init(&_set->elems, &_bf_set_elem_ops, &_set->elem_size);

    *set = TAKE_PTR(_set);

    return 0;
}

/**
 * @brief Parse a set's raw key into an array of `bf_matcher_type`.
 *
 * @param raw_key Raw set key, as a string of comma-separated matcher types
 *        enclosed in parentheses. Can't be NULL.
 * @param key Set key, parsed from `raw_key`. Can't be NULL.
 * @param n_comps Number of components in `key`. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
static int _bf_set_parse_key(const char *raw_key, enum bf_matcher_type *key,
                             size_t *n_comps)
{
    _cleanup_free_ char *_raw_key = NULL;
    char *tmp, *saveptr, *token;

    assert(raw_key);
    assert(key);
    assert(n_comps);

    _raw_key = strdup(raw_key);
    if (!_raw_key) {
        return bf_err_r(-ENOMEM, "failed to duplicate set raw key '%s'",
                        raw_key);
    }

    *n_comps = 0;

    tmp = _raw_key;
    while ((token = strtok_r(tmp, "(),", &saveptr))) {
        int r;

        if (*n_comps == BF_SET_MAX_N_COMPS) {
            return bf_err_r(-E2BIG, "set keys are limited to %d components",
                            BF_SET_MAX_N_COMPS);
        }

        token = bf_trim(token);

        r = bf_matcher_type_from_str(token, &key[*n_comps]);
        if (r)
            return bf_err_r(r, "failed to parse set key component '%s'", token);

        tmp = NULL;
        ++*n_comps;
    }

    if (!*n_comps)
        return bf_err_r(-EINVAL, "set key can't have no component");

    return 0;
}

static int _bf_set_expand_range(struct bf_set *set, const char *token,
                                const struct bf_matcher_ops *range_ops)
{
    uint16_t bounds[2];
    int r;

    assert(set);
    assert(token);
    assert(range_ops);

    r = range_ops->parse(set->key[0], BF_MATCHER_RANGE, bounds, token);
    if (r)
        return bf_err_r(r, "failed to parse set element range '%s'", token);

    for (uint32_t value = bounds[0]; value <= bounds[1]; ++value) {
        _cleanup_free_ uint16_t *range_elem = NULL;
        void *range_data;

        range_elem = malloc(set->elem_size);
        if (!range_elem)
            return bf_err_r(-ENOMEM, "failed to allocate a new set element");

        *range_elem = htobe16((uint16_t)value);

        range_data = range_elem;
        r = bf_hashset_add(&set->elems, &range_data);
        if (!r)
            range_elem = NULL;
        if (r && r != -EEXIST)
            return bf_err_r(r, "failed to insert element into set");
    }

    return 0;
}

int bf_set_add_elem_raw(struct bf_set *set, const char *raw_elem)
{
    _cleanup_free_ void *elem = NULL;
    _cleanup_free_ char *_raw_elem = NULL;
    const struct bf_matcher_ops *range_ops = NULL;
    char *tmp, *saveptr, *token;
    size_t elem_offset = 0;
    size_t comp_idx = 0;
    int r;

    assert(set);
    assert(raw_elem);

    _raw_elem = strdup(raw_elem);
    if (!_raw_elem) {
        return bf_err_r(-ENOMEM,
                        "failed to create a copy of the raw element '%s'",
                        raw_elem);
    }

    elem = calloc(1, set->elem_size);
    if (!elem)
        return bf_err_r(-ENOMEM, "failed to allocate a new set element");

    if (set->n_comps == 1 && (set->key[0] == BF_MATCHER_TCP_SPORT ||
                              set->key[0] == BF_MATCHER_TCP_DPORT ||
                              set->key[0] == BF_MATCHER_UDP_SPORT ||
                              set->key[0] == BF_MATCHER_UDP_DPORT ||
                              set->key[0] == BF_MATCHER_META_SPORT ||
                              set->key[0] == BF_MATCHER_META_DPORT)) {
        range_ops = bf_matcher_get_ops(set->key[0], BF_MATCHER_RANGE);
    }

    tmp = _raw_elem;
    while ((token = strtok_r(tmp, ",", &saveptr))) {
        const struct bf_matcher_ops *ops;

        if (comp_idx >= set->n_comps) {
            return bf_err_r(
                -EINVAL,
                "set element has more components than defined in the key '%s'",
                token);
        }

        token = bf_trim(token);

        ops = bf_matcher_get_ops(set->key[comp_idx], BF_MATCHER_IN);
        if (!ops) {
            return bf_err_r(-EINVAL, "matcher type '%s' has no matcher_ops",
                            bf_matcher_type_to_str(set->key[comp_idx]));
        }

        if (range_ops && strchr(token, '-')) {
            if (strchr(raw_elem, ',')) {
                return bf_err_r(
                    -EINVAL,
                    "set element has more components than defined in the key: '%s'",
                    token);
            }
            return _bf_set_expand_range(set, token, range_ops);
        }

        r = ops->parse(set->key[comp_idx], BF_MATCHER_IN, elem + elem_offset,
                       token);
        if (r) {
            return bf_err_r(r, "failed to parse set element component '%s'",
                            token);
        }

        elem_offset += ops->ref_payload_size;
        tmp = NULL;
        ++comp_idx;
    }

    if (comp_idx != set->n_comps) {
        return bf_err_r(-EINVAL, "missing component in set element '%s'",
                        raw_elem);
    }

    r = bf_hashset_add(&set->elems, &elem);
    if (r == -EEXIST)
        return 0;
    if (r)
        return bf_err_r(r, "failed to insert element into set");

    return 0;
}

int bf_set_new_from_raw(struct bf_set **set, const char *name,
                        const char *raw_key, const char *raw_payload)
{
    _free_bf_set_ struct bf_set *_set = NULL;
    _cleanup_free_ char *_raw_payload = NULL;
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];
    char *raw_elem, *tmp, *saveptr;
    size_t n_comps;
    int r;

    assert(set);
    assert(raw_key);
    assert(raw_payload);

    r = _bf_set_parse_key(raw_key, key, &n_comps);
    if (r)
        return bf_err_r(r, "failed to parse set key '%s'", raw_key);

    r = bf_set_new(&_set, name, key, n_comps);
    if (r)
        return r;

    _raw_payload = strdup(raw_payload);
    if (!_raw_payload)
        return bf_err_r(-ENOMEM, "failed to copy set raw payload '%s'",
                        raw_payload);

    tmp = _raw_payload;
    while ((raw_elem = strtok_r(tmp, "{};\n", &saveptr))) {
        tmp = NULL;
        raw_elem = bf_trim(raw_elem);

        /* While strtok_r() won't return empty token, the trimmed version of the
         * token can be empty! */
        if (raw_elem[0] == '\0')
            continue;

        r = bf_set_add_elem_raw(_set, raw_elem);
        if (r)
            return bf_err_r(r, "failed to parse set element '%s'", raw_elem);
    }

    *set = TAKE_PTR(_set);

    return 0;
}

int bf_set_new_from_pack(struct bf_set **set, bf_rpack_node_t node)
{
    _free_bf_set_ struct bf_set *_set = NULL;
    _cleanup_free_ char *name = NULL;
    bf_rpack_node_t child, comp_node, elem_node;
    size_t n_comps = 0;
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];
    int r;

    assert(set);

    r = bf_rpack_kv_node(node, "name", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_set.name");

    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_str(child, &name);
        if (r)
            return bf_rpack_key_err(r, "bf_set.name");
    }

    r = bf_rpack_kv_array(node, "key", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_set.key");
    bf_rpack_array_foreach (child, comp_node) {
        ++n_comps;
        if (n_comps > BF_SET_MAX_N_COMPS) {
            return bf_err_r(
                -E2BIG,
                "bf_set.key in pack contains %lu key components, only %d allowed",
                n_comps, BF_SET_MAX_N_COMPS);
        }

        r = bf_rpack_enum(comp_node, &key[i], 0, _BF_MATCHER_TYPE_MAX);
        if (r)
            return bf_rpack_key_err(r, "bf_set.key");
    }

    r = bf_set_new(&_set, name, key, n_comps);
    if (r)
        return bf_err_r(r, "failed to create bf_set from pack");

    r = bf_rpack_kv_size(node, "min_size", &_set->min_size);
    if (r)
        return bf_rpack_key_err(r, "bf_set.min_size");

    r = bf_rpack_kv_array(node, "elements", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_set.elements");
    bf_rpack_array_foreach (child, elem_node) {
        const void *elem;
        size_t elem_len;

        r = bf_rpack_bin(elem_node, &elem, &elem_len);
        if (r)
            return bf_rpack_key_err(r, "bf_set.elements");

        if (elem_len != _set->elem_size) {
            return bf_err_r(-EINVAL,
                            "bf_set pack element is %lu bytes, it must be %lu",
                            elem_len, _set->elem_size);
        }

        r = bf_set_add_elem(_set, elem);
        if (r)
            return bf_err_r(r, "failed to insert element to bf_set");
    }

    *set = TAKE_PTR(_set);

    return 0;
}

int bf_set_new_from_copy(struct bf_set **dest, const struct bf_set *src)
{
    _free_bf_set_ struct bf_set *copy = NULL;
    int r;

    assert(dest);
    assert(src);

    r = bf_set_new(&copy, src->name, src->key, src->n_comps);
    if (r)
        return r;

    copy->min_size = src->min_size;

    if (!bf_set_is_empty(src) && copy->elem_size != src->elem_size)
        return bf_err_r(-EINVAL, "invalid source set element size");

    r = bf_set_reserve(copy, bf_hashset_size(&src->elems));
    if (r)
        return r;

    bf_hashset_foreach (&src->elems, elem) {
        r = bf_set_add_elem(copy, elem->data);
        if (r)
            return r;
    }

    *dest = TAKE_PTR(copy);

    return 0;
}

void bf_set_free(struct bf_set **set)
{
    assert(set);

    if (!*set)
        return;

    bf_hashset_clean(&(*set)->elems);
    BF_FREEP(&(*set)->name);
    BF_FREEP(set);
}

int bf_set_pack(const struct bf_set *set, bf_wpack_t *pack)
{
    assert(set);
    assert(pack);

    if (set->name)
        bf_wpack_kv_str(pack, "name", set->name);
    else
        bf_wpack_kv_nil(pack, "name");

    bf_wpack_open_array(pack, "key");
    for (size_t i = 0; i < set->n_comps; ++i)
        bf_wpack_enum(pack, set->key[i]);
    bf_wpack_close_array(pack);

    bf_wpack_kv_u64(pack, "min_size", set->min_size);

    bf_wpack_open_array(pack, "elements");
    bf_hashset_foreach (&set->elems, elem)
        bf_wpack_bin(pack, elem->data, set->elem_size);
    bf_wpack_close_array(pack);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_set_dump(const struct bf_set *set, prefix_t *prefix)
{
    size_t dump_idx = 0;

    assert(set);
    assert(prefix);

    DUMP(prefix, "struct bf_set at %p", set);
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "name: %s", set->name ?: "<anonymous>");
    DUMP(prefix, "key: bf_matcher_type[%zu]", set->n_comps);
    bf_dump_prefix_push(prefix);
    for (size_t i = 0; i < set->n_comps; ++i) {
        if (i == set->n_comps - 1)
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "%s", bf_matcher_type_to_str(set->key[i]));
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "elem_size: %lu", set->elem_size);
    DUMP(prefix, "min_size: %lu", set->min_size);
    DUMP(bf_dump_prefix_last(prefix), "elems: bf_hashset<bytes>[%lu]",
         bf_hashset_size(&set->elems));

    bf_dump_prefix_push(prefix);
    bf_hashset_foreach (&set->elems, elem) {
        if (++dump_idx == bf_hashset_size(&set->elems))
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "void * @ %p", elem->data);
        bf_dump_prefix_push(prefix);
        bf_dump_hex(prefix, elem->data, set->elem_size);
        bf_dump_prefix_pop(prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_set_add_elem(struct bf_set *set, const void *elem)
{
    _cleanup_free_ void *_elem = NULL;
    int r;

    assert(set);
    assert(elem);

    _elem = malloc(set->elem_size);
    if (!_elem)
        return -ENOMEM;

    memcpy(_elem, elem, set->elem_size);

    r = bf_hashset_add(&set->elems, &_elem);
    if (r == -EEXIST)
        return 0;
    if (r)
        return r;

    return 0;
}

bool bf_set_is_empty(const struct bf_set *set)
{
    assert(set);

    return bf_hashset_is_empty(&set->elems);
}

int bf_set_reserve(struct bf_set *set, size_t count)
{
    assert(set);

    return bf_hashset_reserve(&set->elems, count);
}

bool bf_set_same_key(const struct bf_set *lhs, const struct bf_set *rhs)
{
    assert(lhs);
    assert(rhs);

    if (lhs->n_comps != rhs->n_comps)
        return false;

    return memcmp(lhs->key, rhs->key,
                  lhs->n_comps * sizeof(enum bf_matcher_type)) == 0;
}

int bf_set_add_many(struct bf_set *dest, struct bf_set **to_add)
{
    int r;

    assert(dest);
    assert(to_add);
    assert(*to_add);

    if (!bf_set_same_key(dest, *to_add))
        return bf_err_r(-EINVAL, "set key format mismatch");

    bf_hashset_foreach (&(*to_add)->elems, elem) {
        _cleanup_free_ void *data = NULL;

        r = bf_hashset_take(&(*to_add)->elems, elem->data, &data);
        if (r)
            return bf_err_r(r, "failed to take element from source set");

        r = bf_hashset_add(&dest->elems, &data);
        if (r == -EEXIST)
            continue;
        if (r)
            return bf_err_r(r, "failed to add element to set");
    }

    bf_set_free(to_add);

    return 0;
}

int bf_set_remove_many(struct bf_set *dest, struct bf_set **to_remove)
{
    int r;

    assert(dest);
    assert(to_remove);
    assert(*to_remove);

    if (!bf_set_same_key(dest, *to_remove))
        return bf_err_r(-EINVAL, "set key format mismatch");

    bf_hashset_foreach (&(*to_remove)->elems, elem) {
        r = bf_hashset_delete(&dest->elems, elem->data);
        if (r && r != -ENOENT)
            return bf_err_r(r, "failed to remove element from set");
    }

    bf_set_free(to_remove);

    return 0;
}
