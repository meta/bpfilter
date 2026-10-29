/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/limits.h>

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/ctx.h>
#include <bpfilter/hook.h>
#include <bpfilter/set.h>

#include "fake.h"
#include "test.h"

static void ruleset_get(void **state)
{
    (void)state;

    {
        // Empty ruleset
        _clean_bf_list_ bf_list chains = bf_list_default(NULL, NULL);
        _clean_bf_list_ bf_list hookopts = bf_list_default(NULL, NULL);

        assert_ok(bf_ruleset_get(&chains, &hookopts));
        assert_int_equal(bf_list_size(&chains), 0);
        assert_int_equal(bf_list_size(&hookopts), 0);
    }

    {
        // Skip corrupt chains
        struct bft_tmpdir *tmpdir = *state;
        _clean_bf_list_ bf_list chains = bf_list_default(NULL, NULL);
        _clean_bf_list_ bf_list hookopts = bf_list_default(NULL, NULL);
        char path[PATH_MAX];

        /* A chain dir with no `bf_ctx` map looks valid to readdir() but cannot be
         * deserialized; bf_ruleset_get must surface that as a successful empty
         * walk, not a hard error. */
        (void)snprintf(path, sizeof(path), "%s/bpfilter", tmpdir->dir_path);
        (void)mkdir(path, 0755);

        (void)snprintf(path, sizeof(path), "%s/bpfilter/orphan",
                       tmpdir->dir_path);
        assert_ok(mkdir(path, 0755));

        assert_ok(bf_ruleset_get(&chains, &hookopts));
        assert_int_equal(bf_list_size(&chains), 0);
        assert_int_equal(bf_list_size(&hookopts), 0);
    }
}

static void ruleset_set(void **state)
{
    _clean_bf_list_ bf_list chains =
        bf_list_default(bf_chain_free, bf_chain_pack);
    _clean_bf_list_ bf_list hookopts =
        bf_list_default(bf_hookopts_free, bf_hookopts_pack);

    (void)state;

    // Mismatched list sizes should fail
    assert_ok(bf_list_add_tail(&chains, bft_chain_dummy(false)));
    assert_err(bf_ruleset_set(&chains, &hookopts));
}

static void ruleset_flush(void **state)
{
    (void)state;

    // Empty ruleset
    assert_ok(bf_ruleset_flush());
}

static void chain_set(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(false);

    (void)state;

    assert_err(bf_chain_set(chain, NULL));
}

static void chain_get(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;

    (void)state;

    assert_err(bf_chain_get("invalid_chain", &chain, &hookopts));
}

static void chain_prog_fd(void **state)
{
    (void)state;

    assert_err(bf_chain_prog_fd("invalid_chain"));
}

static void chain_logs_fd(void **state)
{
    (void)state;

    assert_err(bf_chain_logs_fd("invalid_chain"));
}

static void chain_load(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(true);

    (void)state;

    assert_err(bf_chain_load(chain));
}

static void chain_attach(void **state)
{
    struct bf_hookopts hookopts = {};

    (void)state;

    assert_err(bf_chain_attach("invalid_chain", &hookopts));
}

static void chain_update(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(true);

    (void)state;

    assert_err(bf_chain_update(chain));
}

static void chain_update_set(void **state)
{
    _free_bf_set_ struct bf_set *set0 = bft_set_dummy(NULL, 3);
    _free_bf_set_ struct bf_set *set1 = bft_set_dummy(NULL, 2);

    (void)state;

    assert_err(bf_chain_update_set("invalid_name", set0, set1));
}

static void chain_flush(void **state)
{
    (void)state;

    assert_err(bf_chain_flush("invalid_chain"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(ruleset_get, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(ruleset_set, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(ruleset_flush, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_set, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_get, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_prog_fd, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_logs_fd, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_load, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_attach, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_update, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_update_set, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(chain_flush, bft_setup_ctx,
                                        bft_teardown_ctx),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
