/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <bpfilter/core/list.h>
#include <bpfilter/ctx.h>

struct bf_chain;
struct bf_set;
struct bf_hookopts;

/**
 * @file bpfilter.h
 *
 * Public API for libbpfilter.
 *
 * **Lifecycle**
 *
 * Every caller must initialise the library before using any other function,
 * and tear it down when done:
 *
 * @code{.c}
 * int r = bf_ctx_setup(false, "/sys/fs/bpf", 0);
 * if (r < 0)
 *     // handle error
 *
 * // use bf_ruleset_*, bf_chain_*, ...
 *
 * bf_ctx_teardown();
 * @endcode
 *
 * `bf_ctx_setup` and `bf_ctx_teardown` are declared in `<bpfilter/ctx.h>`,
 * which is included by this header. Calling any API function before
 * `bf_ctx_setup` succeeds returns `-EINVAL`.
 */

/**
 * @brief Get the current ruleset.
 *
 * @param chains List of `bf_chain` to be filled.
 * @param hookopts List of hook options objects.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_ruleset_get(bf_list *chains, bf_list *hookopts);

/**
 * @brief Load a ruleset.
 *
 * The library will flush the whole ruleset and install the chains defined in
 * the provided lists instead.
 *
 * `hookopts` should contain as many elements as `chains`, so they can be
 * mapped 1 to 1. If a chain shouldn't be attached, the corresponding entry
 * in `hookopts` should be NULL.
 *
 * The caller retains ownership of both lists and their contents on success
 * and failure. Preparation recomputes `bf_rule::index`, `bf_rule::disabled`,
 * and `bf_chain::flags` in each caller-provided chain. These fields may also
 * change if the operation fails. Caller counters remain unchanged. The new
 * programs start with zero kernel counters.
 *
 * @param chains List of chains to define. Can't be NULL.
 * @param hookopts List of hook options to attach the chains in `chain`. Can't
 *        be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_ruleset_set(bf_list *chains, bf_list *hookopts);

/**
 * @brief Remove the current ruleset.
 *
 * @return 0 on success, or a negative error value on failure.
 */
int bf_ruleset_flush(void);

/**
 * @brief Set a chain.
 *
 * If a chain with the same name already exists, it is detached and unloaded.
 * The new chain is loaded, and attached if hook options are defined.
 *
 * The caller retains ownership of `chain` and `hookopts` on success and
 * failure. Preparation recomputes `bf_rule::index`, `bf_rule::disabled`, and
 * `bf_chain::flags` in the caller's chain. These fields may also change if
 * the operation fails. Caller counters remain unchanged. The new program
 * starts with zero kernel counters.
 *
 * @param chain Chain to set. Can't be NULL.
 * @param hookopts Hook options to attach the chain. If NULL, the chain is not
 *        attached.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_set(struct bf_chain *chain, struct bf_hookopts *hookopts);

/**
 * @brief Get a chain.
 *
 * @param name Name of the chain to look for. Can't be NULL.
 * @param chain On success, contains a pointer to the chain. The caller is
 *        responsible for freeing it. Can't be NULL.
 * @param hookopts On success, contains a pointer to the chain's hook options if
 *        the chain is attached, NULL otherwise. The caller is responsible for
 *        freeing it. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 */
int bf_chain_get(const char *name, struct bf_chain **chain,
                 struct bf_hookopts **hookopts);

/**
 * @brief Get the file descriptor of a chain's program.
 *
 * @warning Do not use this function. `bf_chain_prog_fd` is designed to
 * simplify end-to-end tests of the generated programs, to validate bytecode
 * generation. It should be considered unstable, and manipulating the BPF
 * program directly could cause issues with bpfilter itself. Eventually, this
 * API will be disabled for non-tests use cases.
 *
 * @pre
 * - `name` is a non-NULL pointer to a C-string.
 *
 * @param name Name of the chain to get the program from.
 * @return File descriptor of the chain's program, or a negative error value
 *         on failure. The caller owns the file descriptor and must close it.
 */
int bf_chain_prog_fd(const char *name);

/**
 * @brief Get the file descriptor of a chain's logs buffer.
 *
 * The file descriptor keeps receiving the chain's logs after
 * `bf_chain_update_set()`. After `bf_chain_update()`, `bf_chain_set()`, or
 * `bf_ruleset_set()`, call `bf_chain_logs_fd()` again to get the new logs
 * buffer.
 *
 * @pre
 * - `name` is a non-NULL pointer to a C-string.
 *
 * @param name Name of the chain to get the log buffer from.
 * @return File descriptor of the chain's logs buffer, or a negative error
 *         value on failure. The caller owns the file descriptor and must
 *         close it.
 */
int bf_chain_logs_fd(const char *name);

/**
 * @brief Load a chain.
 *
 * If a chain with the same name already exists, `-EEXIST` is returned.
 *
 * The caller retains ownership of `chain` on success and failure.
 * Preparation recomputes `bf_rule::index`, `bf_rule::disabled`, and
 * `bf_chain::flags` in the caller's chain. These fields may also change if
 * the operation fails. Caller counters remain unchanged. The new program
 * starts with zero kernel counters.
 *
 * @param chain Chain to load. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_load(struct bf_chain *chain);

/**
 * @brief Attach a chain.
 *
 * If the chain doesn't exist, `-ENOENT` is returned.
 *
 * @param name Name of the chain to attach. Can't be NULL.
 * @param hookopts Hook options to attach the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 * - `-EBUSY`: chain is already attached.
 */
int bf_chain_attach(const char *name, const struct bf_hookopts *hookopts);

/**
 * @brief Update a chain.
 *
 * The chain to update must exist, and `chain` must use the same hook.
 * On success, if the chain is attached, the new program atomically replaces
 * the existing one and the chain stays attached.
 *
 * The caller retains ownership of `chain` on success and failure.
 * Preparation recomputes `bf_rule::index`, `bf_rule::disabled`, and
 * `bf_chain::flags` in the caller's chain. These fields may also change if
 * the operation fails. Caller counters remain unchanged. The replacement
 * starts with zero kernel counters.
 *
 * Preparation failures leave the installed chain intact. A failure while
 * pinning or persisting the updated program can detach the chain and leave
 * state that cannot be restored. In that case, `bf_chain_flush()` also fails.
 * Recovery requires manually removing the chain's bpffs directory.
 *
 * @param chain Chain to update. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 * - `-EINVAL`: `chain` doesn't use the same hook as the existing chain.
 */
int bf_chain_update(const struct bf_chain *chain);

/**
 * @brief Update a named set in an existing chain using delta operations.
 *
 * The chain to update must exist. This operation triggers regeneration of
 * the chain's BPF program with the updated set data. Elements from `to_add`
 * are added to the set, and elements from `to_remove` are removed. If
 * `to_remove` has elements that already aren't present in the program,
 * these elements are ignored.
 *
 * The operation borrows both delta sets without modifying them or taking
 * ownership. It edits a private candidate and transfers rule, policy, and
 * error counters before publication. Preparation failures leave the
 * installed chain intact. A failure while pinning or persisting the
 * updated program can detach the chain and leave state that cannot be
 * restored. In that case, `bf_chain_flush()` also fails. Recovery requires
 * manually removing the chain's bpffs directory.
 *
 * @param name Name of the chain containing the set. Can't be NULL.
 * @param to_add Set containing elements to add. The set name and key format
 *        must match the existing set in the chain. Can't be NULL.
 * @param to_remove Set containing elements to remove. The set name and key
 *        format must match the existing set in the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name or set not found in chain.
 * - `-EINVAL`: set key format doesn't match existing set.
 */
int bf_chain_update_set(const char *name, const struct bf_set *to_add,
                        const struct bf_set *to_remove);

/**
 * @brief Remove a chain.
 *
 * @param name Name of the chain to flush. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 */
int bf_chain_flush(const char *name);
