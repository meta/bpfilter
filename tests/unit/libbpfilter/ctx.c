/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/limits.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpfilter/core/list.h>
#include <bpfilter/ctx.h>

#include "core/lock.h"
#include "test.h"

static void no_setup(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    /* All ctx accessors must reject calls made before bf_ctx_setup. */
    assert_int_equal(bf_lock_init(&lock, BF_LOCK_READ), -EINVAL);
    assert_int_equal(bf_ctx_token(), -1);
    assert_null(bf_ctx_get_elfstub(0));
    assert_null(bf_ctx_get_bpffs_path());
    assert_false(bf_ctx_is_verbose(BF_VERBOSE_DEBUG));
}

static void is_setup(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;

    (void)state;

    assert_false(bf_ctx_is_setup());

    assert_ok(bft_tmpdir_new(&tmpdir));
    assert_ok(bf_ctx_setup(false, tmpdir->dir_path, 0));
    assert_true(bf_ctx_is_setup());

    bf_ctx_teardown();
    assert_false(bf_ctx_is_setup());
}

static void bpffs_path_matches_setup(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    const char *path;

    /* The accessor must return the path the caller passed to bf_ctx_setup. */
    path = bf_ctx_get_bpffs_path();
    assert_non_null(path);
    assert_string_equal(path, tmpdir->dir_path);
}

static void bpffs_path_is_owned_copy(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    char path_buf[PATH_MAX];
    const char *stored;

    (void)state;

    /* This test runs without the bft_setup_ctx fixture so we control the
     * lifetime of the bpffs_path buffer passed to bf_ctx_setup. */
    assert_ok(bft_tmpdir_new(&tmpdir));

    /* Copy the bpffs path into a local mutable buffer, then hand it to
     * bf_ctx_setup. */
    (void)snprintf(path_buf, sizeof(path_buf), "%s", tmpdir->dir_path);
    assert_ok(bf_ctx_setup(false, path_buf, BF_FLAG(BF_VERBOSE_DEBUG)));

    /* Stomp on the caller's buffer. The ctx must hold its own strdup'd copy:
     * before this fix, ctx->bpffs_path aliased the caller's storage and the
     * accessor would return the corrupted contents (or worse, dangling memory
     * once the caller's buffer went out of scope). */
    memset(path_buf, 'X', sizeof(path_buf) - 1);
    path_buf[sizeof(path_buf) - 1] = '\0';

    stored = bf_ctx_get_bpffs_path();
    assert_non_null(stored);
    assert_ptr_not_equal(stored, path_buf);
    assert_string_equal(stored, tmpdir->dir_path);

    /* Tear down before the tmpdir cleanup so the ctx releases its copy while
     * the bpffs path is still on disk. ASan/leak detectors would flag a
     * missing free here, exercising the matching BF_FREEP() in _bf_ctx_free. */
    bf_ctx_teardown();
}

static void verbose_flags(void **state)
{
    (void)state;

    assert_true(bf_ctx_is_verbose(BF_VERBOSE_DEBUG));
    assert_false(bf_ctx_is_verbose(BF_VERBOSE_BPF));
    assert_false(bf_ctx_is_verbose(BF_VERBOSE_BYTECODE));
}

static void setup_twice_fails(void **state)
{
    /* The fixture has already called bf_ctx_setup successfully. A second
     * call without an intervening teardown must reject with -EBUSY rather
     * than silently overwriting (and leaking) the existing global context. */
    struct bft_tmpdir *tmpdir = *state;

    assert_err(
        bf_ctx_setup(false, tmpdir->dir_path, BF_FLAG(BF_VERBOSE_DEBUG)));

    /* The original context is untouched and remains usable. */
    assert_non_null(bf_ctx_get_bpffs_path());
    assert_string_equal(bf_ctx_get_bpffs_path(), tmpdir->dir_path);
    assert_true(bf_ctx_is_verbose(BF_VERBOSE_DEBUG));
}

static void setup_after_teardown(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;

    (void)state;

    /* No fixture: this test manages the setup/teardown sequence itself. */
    assert_ok(bft_tmpdir_new(&tmpdir));

    /* Setup, then teardown, then setup again: the second setup must succeed
     * because teardown clears the global context. */
    assert_ok(bf_ctx_setup(false, tmpdir->dir_path, 0));
    bf_ctx_teardown();

    assert_ok(bf_ctx_setup(false, tmpdir->dir_path, 0));
    bf_ctx_teardown();
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(no_setup),
        cmocka_unit_test(is_setup),
        cmocka_unit_test(bpffs_path_is_owned_copy),
        cmocka_unit_test(setup_after_teardown),
        cmocka_unit_test_setup_teardown(bpffs_path_matches_setup, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(verbose_flags, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(setup_twice_fails, bft_setup_ctx,
                                        bft_teardown_ctx),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
