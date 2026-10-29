/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdlib.h>

#include <bpfilter/set.h>

#include "bpfilter/dump.h"
#include "bpfilter/pack.h"
#include "fake.h"
#include "mock.h"
#include "test.h"

static void name_is_valid(void **state)
{
    const char *valid[] = {"test", "Set_012-abc", "0", "_", "-"};
    const char *invalid[] = {
        NULL,          "",           "two words",
        "tab\tname",   "line\nname", "name.with.dot",
        "name/slash",  "name:colon", "@name",
        "caf\xc3\xa9",
    };

    (void)state;

    for (size_t i = 0; i < ARRAY_SIZE(valid); ++i)
        assert_true(bf_set_is_valid_name(valid[i]));

    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
        assert_false(bf_set_is_valid_name(invalid[i]));
}

static void new_with_invalid_names(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;
    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};
    const char *names[] = {
        "", "two words", "name.with.dot", "name/slash", "caf\xc3\xa9",
    };

    (void)state;

    for (size_t i = 0; i < ARRAY_SIZE(names); ++i) {
        assert_err(bf_set_new(&set, names[i], key, ARRAY_SIZE(key)));
        assert_null(set);
        assert_err(bf_set_new_from_raw(&set, names[i], "(ip4.saddr)", "{}"));
        assert_null(set);
    }

    assert_ok(bf_set_new(&set, "named", key, ARRAY_SIZE(key)));
    assert_false(bf_set_is_anonymous(set));
}

static void new_and_free(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;
    _free_bf_set_ struct bf_set *other = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;
    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    (void)state;

    // Free set manually
    assert_ok(bf_set_new(&set, "test_set", key, ARRAY_SIZE(key)));
    assert_non_null(set);
    assert_string_equal(set->name, "test_set");
    assert_false(bf_set_is_anonymous(set));
    assert_int_equal(set->n_comps, 1);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_SADDR);
    bf_set_free(&set);
    assert_null(set);

    // Free set using the cleanup attribute
    assert_ok(bf_set_new(&set, NULL, key, ARRAY_SIZE(key)));
    assert_null(set->name);
    assert_true(bf_set_is_anonymous(set));

    assert_ok(bf_set_new_from_raw(&other, NULL, "(ip4.saddr)", "{192.0.2.1}"));
    assert_true(bf_set_is_anonymous(other));
    assert_null(other->name);

    // Copies of anonymous sets remain anonymous.
    assert_ok(bf_set_new_from_copy(&copy, other));
    assert_true(bf_set_is_anonymous(copy));
    assert_null(copy->name);
    assert_true(bft_set_eq_ordered(copy, other));

    // The copy remains independent after the source is freed.
    bf_set_free(&other);

    assert_true(bf_set_is_anonymous(copy));
    assert_ok(bf_set_add_elem_raw(copy, "203.0.113.1"));
    assert_int_equal(bf_hashset_size(&copy->elems), 2);
}

static void new_with_multiple_keys(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_DADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_set_new(&set, "multi_key_set", key, ARRAY_SIZE(key)));
    assert_non_null(set);
    assert_int_equal(set->n_comps, 2);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_DADDR);
    assert_int_equal(set->key[1], BF_MATCHER_TCP_SPORT);
    assert_ok(bf_set_validate(set));

    set->key[0] = BF_MATCHER_IP4_SNET;
    assert_int_equal(bf_set_validate(set), -EINVAL);
}

static void new_with_invalid_params(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};
    const enum bf_matcher_type invalid_keys[] = {
        (enum bf_matcher_type) - 1,
        _BF_MATCHER_TYPE_MAX,
        BF_MATCHER_META_PROBABILITY,
    };

    (void)state;

    // Test with 0 components
    assert_err(bf_set_new(&set, "test", key, 0));

    // Test with too many components
    enum bf_matcher_type large_key[BF_SET_MAX_N_COMPS + 1];
    for (size_t i = 0; i <= BF_SET_MAX_N_COMPS; ++i)
        large_key[i] = BF_MATCHER_IP4_SADDR;
    assert_err(bf_set_new(&set, "test", large_key, BF_SET_MAX_N_COMPS + 1));

    assert_ok(bf_set_new(&set, "test", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_validate(set));

    set->n_comps = 0;
    assert_int_equal(bf_set_validate(set), -EINVAL);
    set->n_comps = BF_SET_MAX_N_COMPS + 1;
    assert_int_equal(bf_set_validate(set), -E2BIG);
    set->n_comps = ARRAY_SIZE(key);

    for (size_t i = 0; i < ARRAY_SIZE(invalid_keys); ++i) {
        set->key[0] = invalid_keys[i];
        assert_int_equal(bf_set_validate(set), -ENOTSUP);
    }
    set->key[0] = key[0];

    ++set->elem_size;
    assert_int_equal(bf_set_validate(set), -EINVAL);
    --set->elem_size;
    assert_ok(bf_set_validate(set));
}

static void new_with_trie_key(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SNET};

    (void)state;

    // Network matchers should enable trie
    assert_ok(bf_set_new(&set, "trie_set", key, ARRAY_SIZE(key)));
    assert_true(set->use_trie);
    assert_ok(bf_set_validate(set));
}

static void new_with_invalid_network_combination(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SNET, BF_MATCHER_TCP_SPORT};

    (void)state;

    // Network matchers can't be combined with other matchers
    assert_err(bf_set_new(&set, "invalid_set", key, ARRAY_SIZE(key)));
}

static void add_elem(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem = 0x01020304; // 1.2.3.4

    (void)state;

    assert_ok(bf_set_new(&set, "test", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_add_elem(set, &elem));
    assert_int_equal(bf_hashset_size(&set->elems), 1);
}

static void add_multiple_elems(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_DADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_set_new(&set, "test", key, ARRAY_SIZE(key)));

    // Add 5 elements
    for (size_t i = 0; i < 5; ++i) {
        uint8_t elem[set->elem_size];
        memset(elem, (uint8_t)i, set->elem_size);
        assert_ok(bf_set_add_elem(set, elem));
    }

    assert_int_equal(bf_hashset_size(&set->elems), 5);
}

static void add_duplicate(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem = 0x01020304;

    (void)state;

    assert_ok(bf_set_new(&set, "test", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_add_elem(set, &elem));
    assert_ok(bf_set_add_elem(set, &elem));
    assert_int_equal(bf_hashset_size(&set->elems), 1);
}

static void reserve(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    (void)state;

    assert_ok(bf_set_new(&set, "test", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_reserve(set, 50));

    for (uint32_t i = 0; i < 50; ++i) {
        uint32_t addr = 0x0A000001 + i;
        assert_ok(bf_set_add_elem(set, &addr));
    }
    assert_int_equal(bf_hashset_size(&set->elems), 50);
}

static void pack_and_unpack_named(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *destination = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Create and pack the source set
    assert_non_null(source = bft_set_dummy("Set_012-abc", 4));
    source->min_size = 16;
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "set");
    assert_ok(bf_set_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination set
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "set", &node));
    assert_ok(bf_set_new_from_pack(&destination, node));

    assert_int_equal(destination->min_size, 16);
    assert_true(bft_set_eq_ordered(source, destination));

    assert_ok(bf_set_new_from_copy(&copy, source));
    assert_true(bft_set_eq_ordered(source, copy));
}

static void pack_and_unpack_anon(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *destination = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Create and pack the source set
    assert_non_null(source = bft_set_dummy(NULL, 4));
    assert_true(bf_set_is_anonymous(source));
    source->min_size = 16;

    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "set");
    assert_ok(bf_set_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination set
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "set", &node));
    assert_ok(bf_set_new_from_pack(&destination, node));

    assert_int_equal(destination->min_size, 16);
    assert_true(bft_set_eq_ordered(source, destination));

    assert_ok(bf_set_new_from_copy(&copy, source));
    assert_true(bft_set_eq_ordered(source, copy));
}

static void copy_preserves_configuration(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;

    (void)state;

    assert_ok(bf_set_new_from_raw(&source, "addresses",
                                  "(ip4.saddr, tcp.dport)",
                                  "{192.0.2.1, 80; 192.0.2.2, 443}"));
    source->min_size = 16;

    assert_ok(bf_set_new_from_copy(&copy, source));
    assert_true(bft_set_eq_ordered(source, copy));
}

static void copy_removal_does_not_change_source(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;
    _free_bf_set_ struct bf_set *to_remove = NULL;

    (void)state;

    assert_ok(bf_set_new_from_raw(&source, "addresses", "(ip4.saddr)",
                                  "{192.0.2.1; 192.0.2.2}"));
    assert_ok(bf_set_new_from_raw(&to_remove, "removed", "(ip4.saddr)",
                                  "{192.0.2.1}"));
    assert_ok(bf_set_new_from_copy(&copy, source));
    assert_ok(bf_set_remove_many(copy, &to_remove));

    assert_int_equal(bf_hashset_size(&source->elems), 2);
    assert_int_equal(bf_hashset_size(&copy->elems), 1);
}

static void copy_accepts_elements_after_source_free(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;

    (void)state;

    assert_ok(bf_set_new_from_raw(&source, "addresses", "(ip4.saddr)",
                                  "{192.0.2.1}"));
    assert_ok(bf_set_new_from_copy(&copy, source));
    bf_set_free(&source);
    assert_ok(bf_set_add_elem_raw(copy, "192.0.2.2"));
    assert_ok(bf_set_add_elem_raw(copy, "192.0.2.1"));

    assert_int_equal(bf_hashset_size(&copy->elems), 2);
}

static void copy_network_set_survives_source_free(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;

    (void)state;

    assert_ok(bf_set_new_from_raw(&source, "networks", "(ip4.snet)",
                                  "{192.0.2.0/24; 198.51.100.0/24}"));
    assert_ok(bf_set_new_from_copy(&copy, source));
    assert_true(bft_set_eq_ordered(source, copy));
    bf_set_free(&source);
    assert_ok(bf_set_add_elem_raw(copy, "203.0.113.0/24"));

    assert_int_equal(bf_hashset_size(&copy->elems), 3);
}

static void copy_empty_set_accepts_elements_after_source_free(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *copy = NULL;

    (void)state;

    assert_ok(bf_set_new_from_raw(&source, "addresses", "(ip4.saddr)", "{}"));
    assert_ok(bf_set_new_from_copy(&copy, source));
    bf_set_free(&source);
    assert_ok(bf_set_add_elem_raw(copy, "192.0.2.1"));

    assert_int_equal(bf_hashset_size(&copy->elems), 1);
}

static void pack_and_unpack_err(void **state)
{
    const char *names[] = {
        "",           "two words",   "name.with.dot",
        "name/slash", "caf\xc3\xa9", "@anon:0123456789abcdef",
    };

    (void)state;

    for (size_t i = 0; i < ARRAY_SIZE(names); ++i) {
        _free_bf_set_ struct bf_set *source = NULL;
        _free_bf_set_ struct bf_set *destination = NULL;
        _free_bf_wpack_ bf_wpack_t *wpack = NULL;
        _free_bf_rpack_ bf_rpack_t *rpack = NULL;
        bf_rpack_node_t node;
        const void *data;
        size_t data_len;

        assert_non_null(source = bft_set_dummy("source", 4));
        BF_FREEP(&source->name);
        assert_non_null(source->name = strdup(names[i]));

        assert_ok(bf_wpack_new(&wpack));
        bf_wpack_open_object(wpack, "set");
        assert_ok(bf_set_pack(source, wpack));
        bf_wpack_close_object(wpack);
        assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

        assert_ok(bf_rpack_new(&rpack, data, data_len));
        assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "set", &node));
        assert_err(bf_set_new_from_pack(&destination, node));
        assert_null(destination);
    }
}

static void pack_and_unpack_empty(void **state)
{
    _free_bf_set_ struct bf_set *source = NULL;
    _free_bf_set_ struct bf_set *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    (void)state;

    // Create empty set and pack it
    assert_ok(bf_set_new(&source, "empty_set", key, ARRAY_SIZE(key)));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "set");
    assert_ok(bf_set_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "set", &node));
    assert_ok(bf_set_new_from_pack(&destination, node));

    assert_true(bft_set_eq_ordered(source, destination));
    assert_int_equal(bf_hashset_size(&destination->elems), 0);
}

static void dump(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;
    prefix_t prefix = {};

    (void)state;

    // Dump a set with elements
    assert_non_null(set = bft_set_dummy(NULL, 4));
    bf_set_dump(set, &prefix);
}

static void dump_empty(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    prefix_t prefix = {};

    (void)state;

    // Dump an empty set
    assert_ok(bf_set_new(&set, "empty", key, ARRAY_SIZE(key)));
    bf_set_dump(set, &prefix);
}

static void new_from_raw(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    // Test creating set from raw key and payload
    assert_ok(bf_set_new_from_raw(&set, "test_raw", "(ip4.saddr)",
                                  "{1.2.3.4; 5.6.7.8}"));
    assert_non_null(set);
    assert_string_equal(set->name, "test_raw");
    assert_int_equal(set->n_comps, 1);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_SADDR);
    assert_int_equal(bf_hashset_size(&set->elems), 2);
}

static void new_from_raw_blank_elements(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    // Blank elements are skipped, even before the first element
    assert_ok(bf_set_new_from_raw(&set, "test_blank", "(ip4.saddr)", "{ }"));
    assert_int_equal(bf_hashset_size(&set->elems), 0);

    bf_set_free(&set);

    assert_ok(
        bf_set_new_from_raw(&set, "test_blank", "(ip4.saddr)", "{ ; 1.2.3.4}"));
    assert_int_equal(bf_hashset_size(&set->elems), 1);

    bf_set_free(&set);

    assert_ok(bf_set_new_from_raw(&set, "test_blank", "(ip4.saddr)",
                                  "{ \n1.2.3.4\n}"));
    assert_int_equal(bf_hashset_size(&set->elems), 1);
}

static void new_from_raw_multiple_keys(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    // Test creating set with multiple key components
    assert_ok(bf_set_new_from_raw(&set, "test_multi", "(ip4.daddr, tcp.sport)",
                                  "{1.2.3.4, 80; 5.6.7.8, 443}"));
    assert_non_null(set);
    assert_int_equal(set->n_comps, 2);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_DADDR);
    assert_int_equal(set->key[1], BF_MATCHER_TCP_SPORT);
    assert_int_equal(bf_hashset_size(&set->elems), 2);
}

static void new_from_raw_port_range(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    // Range at the end
    assert_ok(bf_set_new_from_raw(&set, "test_range_end", "(tcp.dport)",
                                  "{11; 22; 27-30}"));
    assert_non_null(set);
    assert_int_equal(set->n_comps, 1);
    assert_int_equal(set->key[0], BF_MATCHER_TCP_DPORT);
    assert_int_equal(bf_hashset_size(&set->elems), 6);

    bf_set_free(&set);

    // Range at the beginning
    assert_ok(bf_set_new_from_raw(&set, "test_range_begin", "(tcp.dport)",
                                  "{27-30; 40; 50}"));
    assert_int_equal(bf_hashset_size(&set->elems), 6);

    bf_set_free(&set);

    // Range in the middle
    assert_ok(bf_set_new_from_raw(&set, "test_range_middle", "(tcp.dport)",
                                  "{11; 27-30; 50}"));
    assert_int_equal(bf_hashset_size(&set->elems), 6);

    bf_set_free(&set);

    // UDP source port range
    assert_ok(bf_set_new_from_raw(&set, "test_udp_range", "(udp.sport)",
                                  "{1000; 2000-2002}"));
    assert_non_null(set);
    assert_int_equal(set->n_comps, 1);
    assert_int_equal(set->key[0], BF_MATCHER_UDP_SPORT);
    assert_int_equal(bf_hashset_size(&set->elems), 4);
}

static void new_from_raw_port_range_boundaries(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    assert_ok(bf_set_new_from_raw(&set, "test_low", "(tcp.dport)", "{0-1}"));
    assert_int_equal(bf_hashset_size(&set->elems), 2);

    bf_set_free(&set);

    assert_ok(
        bf_set_new_from_raw(&set, "test_high", "(tcp.dport)", "{65535-65535}"));
    assert_int_equal(bf_hashset_size(&set->elems), 1);
}

static void new_from_raw_port_range_elements(void **state)
{
    _free_bf_set_ struct bf_set *range = NULL;
    _free_bf_set_ struct bf_set *ports = NULL;

    (void)state;

    // A range is stored exactly like the ports it covers
    assert_ok(bf_set_new_from_raw(&range, "test_range", "(udp.dport)",
                                  "{27-30; 9990-9992}"));
    assert_ok(bf_set_new_from_raw(&ports, "test_ports", "(udp.dport)",
                                  "{27; 28; 29; 30; 9990; 9991; 9992}"));
    assert_int_equal(bf_hashset_size(&range->elems), 7);
    bf_hashset_foreach (&range->elems, elem)
        assert_true(bf_hashset_contains(&ports->elems, elem->data));

    bf_set_free(&range);

    // A port covered by a range is only stored once
    assert_ok(bf_set_new_from_raw(&range, "test_overlap", "(tcp.dport)",
                                  "{27; 27-28}"));
    assert_int_equal(bf_hashset_size(&range->elems), 2);
}

static void new_from_raw_port_range_invalid(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    assert_err(bf_set_new_from_raw(&set, "test", "(tcp.dport)", "{27-17}"));
    assert_err(bf_set_new_from_raw(&set, "test", "(tcp.dport)", "{27-}"));
    assert_err(bf_set_new_from_raw(&set, "test", "(tcp.dport)", "{-17}"));
    assert_err(bf_set_new_from_raw(&set, "test", "(tcp.dport)", "{27-30, 80}"));
}

static void new_from_raw_port_range_multiple_keys(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    assert_err(bf_set_new_from_raw(&set, "test", "(ip4.daddr, tcp.dport)",
                                   "{1.2.3.4, 80-82}"));
}

static void new_from_raw_invalid(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;

    (void)state;

    // Test with invalid key format
    assert_err(bf_set_new_from_raw(&set, "test", "INVALID", "{1.2.3.4}"));

    // Test with empty key
    assert_err(bf_set_new_from_raw(&set, "test", "()", "{1.2.3.4}"));
}

static void add_many_basic(void **state)
{
    _free_bf_set_ struct bf_set *dest = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t elem3 = 0x03030303;

    (void)state;

    assert_ok(bf_set_new(&dest, "dest", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_new(&to_add, "to_add", key, ARRAY_SIZE(key)));

    assert_ok(bf_set_add_elem(dest, &elem1));
    assert_ok(bf_set_add_elem(dest, &elem2));

    assert_ok(bf_set_add_elem(to_add, &elem2));
    assert_ok(bf_set_add_elem(to_add, &elem3));

    assert_ok(bf_set_add_many(dest, &to_add));

    assert_int_equal(bf_hashset_size(&dest->elems), 3);
    assert_true(bf_hashset_contains(&dest->elems, &elem1));
    assert_true(bf_hashset_contains(&dest->elems, &elem2));
    assert_true(bf_hashset_contains(&dest->elems, &elem3));
    assert_null(to_add);
}

static void add_many_mismatched_key_count(void **state)
{
    _free_bf_set_ struct bf_set *dest = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_SADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_set_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_set_new(&to_add, "to_add", key2, ARRAY_SIZE(key2)));

    assert_err(bf_set_add_many(dest, &to_add));
    assert_non_null(to_add);
}

static void add_many_mismatched_key_type(void **state)
{
    _free_bf_set_ struct bf_set *dest = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_DADDR};

    (void)state;

    assert_ok(bf_set_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_set_new(&to_add, "to_add", key2, ARRAY_SIZE(key2)));

    assert_err(bf_set_add_many(dest, &to_add));
    assert_non_null(to_add);
}

static void remove_many_basic(void **state)
{
    _free_bf_set_ struct bf_set *dest = NULL;
    _free_bf_set_ struct bf_set *to_remove = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t elem3 = 0x03030303;

    (void)state;

    assert_ok(bf_set_new(&dest, "dest", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_new(&to_remove, "to_remove", key, ARRAY_SIZE(key)));

    assert_ok(bf_set_add_elem(dest, &elem1));
    assert_ok(bf_set_add_elem(dest, &elem2));
    assert_ok(bf_set_add_elem(dest, &elem3));

    assert_ok(bf_set_add_elem(to_remove, &elem2));

    assert_ok(bf_set_remove_many(dest, &to_remove));

    assert_int_equal(bf_hashset_size(&dest->elems), 2);
    assert_true(bf_hashset_contains(&dest->elems, &elem1));
    assert_false(bf_hashset_contains(&dest->elems, &elem2));
    assert_true(bf_hashset_contains(&dest->elems, &elem3));
    assert_null(to_remove);
}

static void remove_many_disjoint_sets(void **state)
{
    _free_bf_set_ struct bf_set *dest = NULL;
    _free_bf_set_ struct bf_set *to_remove = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t elem3 = 0x03030303;
    uint32_t elem4 = 0x04040404;

    (void)state;

    assert_ok(bf_set_new(&dest, "dest", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_new(&to_remove, "to_remove", key, ARRAY_SIZE(key)));

    assert_ok(bf_set_add_elem(dest, &elem1));
    assert_ok(bf_set_add_elem(dest, &elem2));

    assert_ok(bf_set_add_elem(to_remove, &elem3));
    assert_ok(bf_set_add_elem(to_remove, &elem4));

    assert_ok(bf_set_remove_many(dest, &to_remove));
    assert_int_equal(bf_hashset_size(&dest->elems), 2);
    assert_true(bf_hashset_contains(&dest->elems, &elem1));
    assert_true(bf_hashset_contains(&dest->elems, &elem2));
    assert_null(to_remove);
}

static void remove_many_mismatched_key_count(void **state)
{
    _free_bf_set_ struct bf_set *dest = NULL;
    _free_bf_set_ struct bf_set *to_remove = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_SADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_set_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_set_new(&to_remove, "to_remove", key2, ARRAY_SIZE(key2)));

    assert_err(bf_set_remove_many(dest, &to_remove));
    assert_non_null(to_remove);
}

static void remove_many_mismatched_key_type(void **state)
{
    _free_bf_set_ struct bf_set *dest = NULL;
    _free_bf_set_ struct bf_set *to_remove = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_DADDR};

    (void)state;

    assert_ok(bf_set_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_set_new(&to_remove, "to_remove", key2, ARRAY_SIZE(key2)));

    assert_err(bf_set_remove_many(dest, &to_remove));
    assert_non_null(to_remove);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(name_is_valid),
        cmocka_unit_test(new_with_invalid_names),
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(new_with_multiple_keys),
        cmocka_unit_test(new_with_invalid_params),
        cmocka_unit_test(new_with_trie_key),
        cmocka_unit_test(new_with_invalid_network_combination),
        cmocka_unit_test(add_elem),
        cmocka_unit_test(add_multiple_elems),
        cmocka_unit_test(add_duplicate),
        cmocka_unit_test(reserve),
        cmocka_unit_test(pack_and_unpack_named),
        cmocka_unit_test(pack_and_unpack_anon),
        cmocka_unit_test(copy_preserves_configuration),
        cmocka_unit_test(copy_removal_does_not_change_source),
        cmocka_unit_test(copy_accepts_elements_after_source_free),
        cmocka_unit_test(copy_network_set_survives_source_free),
        cmocka_unit_test(copy_empty_set_accepts_elements_after_source_free),
        cmocka_unit_test(pack_and_unpack_err),
        cmocka_unit_test(pack_and_unpack_empty),
        cmocka_unit_test(dump),
        cmocka_unit_test(dump_empty),
        cmocka_unit_test(new_from_raw),
        cmocka_unit_test(new_from_raw_blank_elements),
        cmocka_unit_test(new_from_raw_multiple_keys),
        cmocka_unit_test(new_from_raw_port_range),
        cmocka_unit_test(new_from_raw_port_range_boundaries),
        cmocka_unit_test(new_from_raw_port_range_elements),
        cmocka_unit_test(new_from_raw_port_range_invalid),
        cmocka_unit_test(new_from_raw_port_range_multiple_keys),
        cmocka_unit_test(new_from_raw_invalid),
        cmocka_unit_test(add_many_basic),
        cmocka_unit_test(add_many_mismatched_key_count),
        cmocka_unit_test(add_many_mismatched_key_type),
        cmocka_unit_test(remove_many_basic),
        cmocka_unit_test(remove_many_disjoint_sets),
        cmocka_unit_test(remove_many_mismatched_key_count),
        cmocka_unit_test(remove_many_mismatched_key_type),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
