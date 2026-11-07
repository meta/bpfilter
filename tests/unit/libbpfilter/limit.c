/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdlib.h>

#include <bpfilter/limit.h>

#include "bpfilter/pack.h"
#include "test.h"

static void valid_matcher(void **state)
{
    const char *bad_matchers[] = {
        "", "a", "10", "10/", "10/aa", "a/s", "-1/s",
    };

    const char *good_matchers[] = {
        "0/s",
        "1/s",
        "10/s",
        "100000/s",
    };

    (void)state;

    for (size_t i = 0; i < ARRAY_SIZE(bad_matchers); ++i) {
        _free_bf_limit_ struct bf_ratelimit *limit = NULL;
        assert_err(bf_limit_new_from_raw(&limit, bad_matchers[i]));
    }

    for (size_t i = 0; i < ARRAY_SIZE(good_matchers); ++i) {
        _free_bf_limit_ struct bf_ratelimit *limit = NULL;
        assert_ok(bf_limit_new_from_raw(&limit, good_matchers[i]));
    }
}

static void new_and_free(void **state)
{
    _free_bf_limit_ struct bf_ratelimit *limit = NULL;

    (void)state;

    // New
    assert_ok(bf_limit_new(&limit, 10, 1000));
    assert_non_null(limit);
    assert_int_equal(limit->limit, 10);
    assert_int_equal(limit->duration, 1000);
    bf_limit_free(&limit);
    assert_null(limit);

    // New from raw
    bf_limit_new_from_raw(&limit, "10/s");
    assert_non_null(limit);
    assert_int_equal(limit->limit, 10);
    assert_int_equal(limit->duration, 1000000000);
    bf_limit_free(&limit);
    assert_null(limit);
}

static void pack_and_unpack(void **state)
{
    _free_bf_limit_ struct bf_ratelimit *source = NULL;
    _free_bf_limit_ struct bf_ratelimit *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Create and pack the source limit
    assert_ok(bf_limit_new(&source, 10, 1000));
    assert_non_null(source);
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "limit");
    assert_ok(bf_limit_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination set
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "limit", &node));
    assert_ok(bf_limit_new_from_pack(&destination, node));

    assert_int_equal(destination->limit, 10);
    assert_int_equal(destination->duration, 1000);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(valid_matcher),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
