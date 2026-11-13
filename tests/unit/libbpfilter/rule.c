/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/rule.h>
#include <bpfilter/set.h>

#include "bpfilter/core/list.h"
#include "bpfilter/pack.h"
#include "bpfilter/runtime.h"
#include "fake.h"
#include "test.h"

static void to_from_str(void **state)
{
    (void)state;

    assert_enum_to_from_str(enum bf_log_opt, bf_log_opt_to_str,
                            bf_log_opt_from_str, BF_LOG_OPT_LINK,
                            _BF_LOG_OPT_MAX);
}

static void new_and_free(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    // Free rule manually
    assert_ok(bf_rule_new(&rule));
    bf_rule_free(&rule);
    assert_null(rule);

    // Free rule using the cleanup attribute
    assert_ok(bf_rule_new(&rule));
}

static void copy_configuration_and_ownership(void **state)
{
    _free_bf_set_ struct bf_set *set = NULL;
    _free_bf_rule_ struct bf_rule *source = bft_rule_dummy(2);
    _free_bf_rule_ struct bf_rule *copy = NULL;
    const struct bf_matcher *set_matcher;

    (void)state;

    assert_non_null(source);
    source->index = 7;
    source->verdict = BF_VERDICT_REDIRECT;
    source->counters = (struct bf_counter) {.count = 7, .size = 1024};
    source->disabled = true;
    bf_rule_mark_set(source, 0x1234);
    bf_rule_set_redirect(source, 8, BF_REDIRECT_EGRESS);
    assert_ok(bf_set_new_from_raw(&set, "rule_copy_set", "(ip4.saddr)", "{}"));
    assert_ok(bft_rule_add_named_set_matcher(source, set, true));

    assert_ok(bf_rule_new_from_copy(&copy, source));
    assert_true(bft_rule_equal(source, copy));
    assert_int_equal(copy->counters.count, 0);
    assert_int_equal(copy->counters.size, 0);
    assert_false(copy->disabled);
    assert_int_equal(source->counters.count, 7);
    bf_rule_mark_set(copy, 0x4321);
    assert_int_equal(bf_rule_mark_get(source), 0x1234);

    bf_rule_free(&source);
    set_matcher = bf_list_node_get_data(bf_list_get_tail(&copy->matchers));
    assert_int_equal(bf_matcher_get_type(set_matcher), BF_MATCHER_SET);
    assert_true(bf_matcher_get_negate(set_matcher));
    assert_ok(bf_set_add_elem_raw(set, "192.0.2.1"));
}

static void copy_failure_preserves_destination(void **state)
{
    _free_bf_rule_ struct bf_rule *source = bft_rule_dummy(1);
    _free_bf_rule_ struct bf_rule *destination = bft_rule_dummy(0);
    struct bf_rule *original = destination;

    (void)state;

    assert_non_null(source);
    assert_non_null(destination);
    source->verdict = _BF_VERDICT_MAX;
    assert_err(bf_rule_new_from_copy(&destination, source));
    assert_ptr_equal(destination, original);
    assert_int_equal(bf_list_size(&destination->matchers), 0);

    source->verdict = BF_VERDICT_REJECT;
    source->reject_type = _BF_REJECT_TYPE_MAX;
    assert_err(bf_rule_new_from_copy(&destination, source));
    assert_ptr_equal(destination, original);
}

static void pack_and_unpack(void **state)
{
    _free_bf_rule_ struct bf_rule *source = NULL;
    _free_bf_rule_ struct bf_rule *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Pack the source rule
    assert_non_null(source = bft_rule_dummy(8));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "rule");
    assert_ok(bf_rule_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack in the destination counter
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "rule", &node));
    assert_ok(bf_rule_new_from_pack(&destination, node, NULL));

    assert_true(bft_rule_equal(source, destination));
}

static void unpack_invalid_reject_type(void **state)
{
    _free_bf_rule_ struct bf_rule *source = NULL;
    _free_bf_rule_ struct bf_rule *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    assert_non_null(source = bft_rule_dummy(0));
    source->verdict = BF_VERDICT_REJECT;
    source->reject_type = _BF_REJECT_TYPE_MAX;

    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "rule");
    assert_ok(bf_rule_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "rule", &node));
    assert_err(bf_rule_new_from_pack(&destination, node, NULL));
}

static void unpack_error(void **state)
{
    _free_bf_rule_ struct bf_rule *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_u32(wpack, "index", 8);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_err(bf_rule_new_from_pack(&destination, bf_rpack_root(rpack), NULL));
}

static void dump(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    assert_non_null(rule = bft_rule_dummy(8));

    // Dump a list with matchers
    bf_rule_dump(rule, EMPTY_PREFIX);

    // Dump a list without matchers
    bf_list_clean(&rule->matchers);
    bf_rule_dump(rule, EMPTY_PREFIX);

    // Dump a REJECT rule
    rule->verdict = BF_VERDICT_REJECT;
    bf_rule_dump(rule, EMPTY_PREFIX);
}

static void add_matcher(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;
    _free_bf_matcher_ struct bf_matcher *matcher0 = NULL;
    _free_bf_matcher_ struct bf_matcher *matcher1 = NULL;
    (void)state;

    assert_non_null(rule = bft_rule_dummy(0));

    assert_non_null(matcher0 = bft_matcher_dummy("hello", 6));
    assert_ok(bf_rule_add_matcher(
        rule, bf_matcher_get_type(matcher0), bf_matcher_get_op(matcher0),
        bf_matcher_payload(matcher0), bf_matcher_payload_len(matcher0), false));
    assert_int_equal(bf_list_size(&rule->matchers), 1);
    assert_true(bft_matcher_equal(
        matcher0, bf_list_node_get_data(bf_list_get_tail(&rule->matchers))));

    assert_non_null(matcher1 = bft_matcher_dummy("", 1));
    assert_ok(bf_rule_add_matcher(
        rule, bf_matcher_get_type(matcher1), bf_matcher_get_op(matcher1),
        bf_matcher_payload(matcher1), bf_matcher_payload_len(matcher1), false));
    assert_int_equal(bf_list_size(&rule->matchers), 2);
    assert_true(bft_matcher_equal(
        matcher1, bf_list_node_get_data(bf_list_get_tail(&rule->matchers))));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(to_from_str),
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(copy_configuration_and_ownership),
        cmocka_unit_test(copy_failure_preserves_destination),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(unpack_invalid_reject_type),
        cmocka_unit_test(unpack_error),
        cmocka_unit_test(dump),
        cmocka_unit_test(add_matcher),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
