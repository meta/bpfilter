/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "state.h"

#include <linux/limits.h>

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>

#include "cgen/handle.h"
#include "core/lock.h"
#include "test.h"

static void discover_empty(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_list_ bf_list *chains = NULL;
    _free_bf_list_ bf_list *handles = NULL;

    (void)state;

    assert_ok(bf_lock_init(&lock, BF_LOCK_READ));
    assert_ok(bf_state_discover(&lock, &chains, &handles));
    assert_non_null(chains);
    assert_non_null(handles);
    assert_int_equal(bf_list_size(chains), 0);
    assert_int_equal(bf_list_size(handles), 0);
}

static void discover_skips_corrupt(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_list_ bf_list *chains = NULL;
    _free_bf_list_ bf_list *handles = NULL;
    char pindir_path[PATH_MAX];
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    _cleanup_close_ int fd = -1;

    /* The pin directory is now created unconditionally by `bf_ctx_setup`
     * (I1); just make sure it exists, don't treat an existing one as an
     * error. */
    (void)snprintf(pindir_path, sizeof(pindir_path), "%s/bpfilter",
                   tmpdir->dir_path);
    (void)mkdir(pindir_path, 0755);

    /* Create a chain dir without a `bf_ctx` map: it should be warn-and-skipped
     * during discovery. */
    (void)snprintf(dir_path, sizeof(dir_path), "%s/bpfilter/orphan_chain",
                   tmpdir->dir_path);
    assert_ok(mkdir(dir_path, 0755));

    /* Drop a regular file alongside the chain dirs to verify the !DT_DIR
     * branch is skipped. */
    (void)snprintf(file_path, sizeof(file_path), "%s/bpfilter/stray_file",
                   tmpdir->dir_path);
    assert_fd(fd = open(file_path, O_CREAT | O_WRONLY, 0644));

    assert_ok(bf_lock_init(&lock, BF_LOCK_READ));
    assert_ok(bf_state_discover(&lock, &chains, &handles));
    assert_non_null(chains);
    assert_non_null(handles);
    assert_int_equal(bf_list_size(chains), 0);
    assert_int_equal(bf_list_size(handles), 0);
}

static void restore_corrupt_returns_error(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    char pindir_path[PATH_MAX];
    char dir_path[PATH_MAX];

    (void)snprintf(pindir_path, sizeof(pindir_path), "%s/bpfilter",
                   tmpdir->dir_path);
    (void)mkdir(pindir_path, 0755);

    (void)snprintf(dir_path, sizeof(dir_path), "%s/bpfilter/broken",
                   tmpdir->dir_path);
    assert_ok(mkdir(dir_path, 0755));

    /* Chain dir exists but the `bf_ctx` map is missing: bf_state_restore
     * fails, and the error must be propagated (not swallowed as -ENOENT). */
    assert_ok(bf_lock_init_for_chain(&lock, "broken", BF_LOCK_READ,
                                     BF_LOCK_READ, false));
    assert_err(bf_state_restore(&lock, &chain, &handle));
    assert_null(chain);
    assert_null(handle);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(discover_empty, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(discover_skips_corrupt, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(restore_corrupt_returns_error,
                                        bft_setup_ctx, bft_teardown_ctx),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
