/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

// clang-format off
#include <stdarg.h> // NOLINT: required by cmocka.h
#include <stddef.h> // NOLINT: required by cmocka.h
#include <stdint.h> // NOLINT: required by cmocka.h
#include <setjmp.h> // NOLINT: required by cmocka.h
#include <cmocka.h> // NOLINT: required by cmocka.h
// clang-format on

#include <linux/kcmp.h>
#include <linux/limits.h>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpfilter/hook.h>

#include "fake.h"

struct bf_set;
struct bf_counter;

#define assert_ok(expr) assert_true((expr) == 0)
#define assert_err(expr) assert_true((expr) < 0)
#define assert_int_gt(expr, ref) assert_true((expr) > (ref))
#define assert_int_gte(expr, ref) assert_true((expr) >= (ref))
#define assert_int_lt(expr, ref) assert_true((expr) < (ref))
#define assert_int_lte(expr, ref) assert_true((expr) <= (ref))

#define assert_dir_exists(tmpdir, name)                                        \
    do {                                                                       \
        char _path[PATH_MAX];                                                  \
        struct stat _st;                                                       \
                                                                               \
        (void)snprintf(_path, sizeof(_path), "%s/%s", (tmpdir)->dir_path,      \
                       (name));                                                \
        assert_int_equal(stat(_path, &_st), 0);                                \
        assert_true(S_ISDIR(_st.st_mode));                                     \
    } while (0)

#define assert_dir_not_exists(tmpdir, name)                                    \
    do {                                                                       \
        char _path[PATH_MAX];                                                  \
        struct stat _st;                                                       \
                                                                               \
        (void)snprintf(_path, sizeof(_path), "%s/%s", (tmpdir)->dir_path,      \
                       (name));                                                \
        assert_int_not_equal(stat(_path, &_st), 0);                            \
    } while (0)

#define assert_enum_to_str(type, to_str, first, max)                           \
    do {                                                                       \
        for (type _start = first; _start < max; ++_start)                      \
            assert_non_null(to_str(_start));                                   \
        assert_non_null(to_str(first - 1));                                    \
        assert_non_null(to_str(max));                                          \
    } while (0)

#define assert_enum_to_from_str(type, to_str, from_str, first, max)            \
    do {                                                                       \
        type back;                                                             \
        for (type _start = first; _start < max; ++_start) {                    \
            const char *str = to_str(_start);                                  \
            assert_non_null(str);                                              \
            assert_ok(((int (*)(const char *, type *))from_str)(str, &back));  \
            assert_int_equal(_start, back);                                    \
        }                                                                      \
        assert_non_null(to_str(first - 1));                                    \
        assert_non_null(to_str(max));                                          \
        assert_err(from_str(NULL, &back));                                     \
        assert_err(from_str("", &back));                                       \
        assert_err(from_str("invalid", &back));                                \
    } while (0)

#define assert_fd_equal(fd0, fd1)                                              \
    do {                                                                       \
        assert_int_equal(                                                      \
            syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, (fd0), (fd1)),    \
            0);                                                                \
    } while (0)
#define assert_fd_empty(fd) assert_int_equal(fd, -1)
#define assert_fd(fd) assert_int_gte(fd, 0)

#define assert_rule_equal(rule0, rule1)                                        \
    do {                                                                       \
        assert_true(bft_rule_equal(rule0, rule1));                             \
    } while (0)

/**
 * @brief Compare two `bf_list` objects.
 *
 * @param lhs First list to compare.
 * @param rhs Second list to compare.
 * @param cb Callback used to compare the nodes payload. If `NULL`, the node's
 *        payload is not compared. If set, `cb` is called with the payload
 *        of `lhs` and `rhs` node, for each node.
 * @return True if both lists are equal, false otherwise.
 */
bool bft_list_eq(const bf_list *lhs, const bf_list *rhs, bft_list_eq_cb cb);

bool bft_set_eq_ordered(const struct bf_set *lhs, const struct bf_set *rhs);
bool bft_counter_eq(const struct bf_counter *lhs, const struct bf_counter *rhs);
bool bft_chain_equal(const struct bf_chain *chain0,
                     const struct bf_chain *chain1);

/**
 * @brief Compares two rules for equality.
 *
 * @note `has_counters` is used in the comparison, but the counters values are
 * ignored.
 *
 * @return True if the rules are identical, false otherwise.
 */
bool bft_rule_equal(const struct bf_rule *rule0, const struct bf_rule *rule1);
bool bft_matcher_equal(const struct bf_matcher *matcher0,
                       const struct bf_matcher *matcher1);

int btf_setup_redirect_streams(void **state);
int bft_teardown_redirect_streams(void **state);

#define bft_streams_flush(streams)                                             \
    do {                                                                       \
        (void)fflush((streams)->new_stdout);                                   \
        (void)fflush((streams)->new_stderr);                                   \
    } while (0)

struct bft_streams
{
    FILE *new_stdout;
    FILE *old_stdout;
    char *stdout_buf;
    size_t stdout_len;

    FILE *new_stderr;
    FILE *old_stderr;
    char *stderr_buf;
    size_t stderr_len;
};

int bft_streams_new(struct bft_streams **streams);
void bft_stream_free(struct bft_streams **streams);

int btf_setup_create_sockets(void **state);
int bft_teardown_close_sockets(void **state);

struct bft_sockets
{
    int client_fd;
    int server_fd;
};

int bft_sockets_new(struct bft_sockets **sockets);
void bft_sockets_free(struct bft_sockets **sockets);

/**
 * @brief Assert that a rule's counter matches expected values.
 *
 * Fetches the counters for `chain_name`, walks to the counter at
 * `rule_idx`, and asserts that the packet count equals `packets`.
 * If `bytes >= 0`, the byte count is also checked.
 *
 * @param chain_name Name of the chain to query. Can't be NULL.
 * @param rule_idx Zero-based index of the rule whose counter to check.
 * @param packets Expected packet count.
 * @param bytes Expected byte count, or -1 to skip the check.
 */
void bft_assert_counter_eq(const char *chain_name, size_t rule_idx,
                           uint64_t packets, int64_t bytes);

/**
 * @brief Assert that a chain's error counter matches `packets`.
 *
 * @param chain_name Name of the chain to query. Can't be NULL.
 * @param packets Expected packet count.
 */
void bft_assert_error_counter_eq(const char *chain_name, uint64_t packets);

int btf_setup_create_tmpdir(void **state);
int bft_teardown_close_tmpdir(void **state);

struct bft_tmpdir
{
    char path_template[1024];
    char *dir_path;
};

#define _free_bft_tmpdir_ __attribute__((cleanup(bft_tmpdir_free)))

int bft_tmpdir_new(struct bft_tmpdir **tmpdir);
void bft_tmpdir_free(struct bft_tmpdir **tmpdir);

/**
 * @brief Return the BPF "accept" return value for the given hook.
 *
 * @param hook Hook to query.
 * @return The flavor-specific accept verdict (e.g. XDP_PASS, NF_ACCEPT).
 */
int bft_hook_accept(enum bf_hook hook);

/**
 * @brief Return the BPF "drop" return value for the given hook.
 *
 * @param hook Hook to query.
 * @return The flavor-specific drop verdict (e.g. XDP_DROP, NF_DROP).
 */
int bft_hook_drop(enum bf_hook hook);

/**
 * @brief Return the BPF "next" return value for the given hook.
 *
 * Maps BF_VERDICT_NEXT to its flavor-specific return code: TCX_NEXT (-1) for
 * TC, XDP_PASS for XDP, NF_ACCEPT for NF, and 1 for cgroup_skb.
 *
 * @param hook Hook to query.
 * @return The flavor-specific next verdict.
 */
int bft_hook_next(enum bf_hook hook);

/**
 * @brief Initialize the global test `bf_ctx`.
 *
 * @pre
 * - `state` is not NULL.
 * @post
 * - On success: `*state` is a pointer to a valid heap-allocated `bft_tmpdir`
 *   object, and the global `bf_ctx` has been initalized with the temporary
 *   directory.
 * - On failure: `*state` is unchanged.
 *
 * @param state Pointer to a custom object, provided by CMocka.
 * @return 0 on success, or a negative errno value on failure.
 */
int bft_setup_ctx(void **state);

/**
 * @brief Cleanup the global test `bf_ctx`.
 *
 * @pre
 * - `state` is not NULL, `*state` points to a valid `bft_tmpdir`.
 * @post
 * - The `bft_tmpdir` has been deallocated, `*state` is NULL.
 *
 * @param state Pointer to a custom test object, provided by CMocka.
 * @return 0 on success, or a negative errno value on failure.
 */
int bft_teardown_ctx(void **state);
