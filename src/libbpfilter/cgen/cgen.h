/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/pack.h>

struct bf_chain;
struct bf_handle;
struct bf_hookopts;
struct bf_lock;

#define _free_bf_cgen_ __attribute__((cleanup(bf_cgen_free)))

/**
 * @struct bf_cgen
 *
 * A codegen is a BPF bytecode generation context used to create a BPF program
 * for a given set of rules, sets, and policy (a chain).
 */
struct bf_cgen
{
    /// Chain containing the rules, sets, and policy.
    struct bf_chain *chain;

    /** Handle containing BPF object references (prog_fd, maps, link).
     * Created by default in `bf_cgen_new`. Passed to `bf_program` during
     * generation, which populates it. The program is discarded after
     * generation, only the handle is kept. */
    struct bf_handle *handle;
};

/**
 * Allocate and initialise a new codegen.
 *
 * @param cgen Codegen to allocate and initialise. Can't be NULL.
 * @param chain Chain containing the codegen's rules, sets, and policy. On
 *        success, the new codegen will take ownership of the chain, and
 *        @c *chain will be NULL. Can't be NULL, and @c *chain must point to
 *        a valid @ref bf_chain .
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_new(struct bf_cgen **cgen, struct bf_chain **chain);

/**
 * @brief Allocate and initialize a codegen from a pinned context map.
 *
 * Opens the `bf_ctx` context map pinned in the chain directory referenced by
 * `lock`, reads the serialized cgen data, and deserializes it.
 *
 * @param cgen Codegen to allocate and initialize. Can't be NULL.
 * @param lock Lock providing the chain directory file descriptor. Must hold
 *        a valid `chain_fd`. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_cgen_new_from_dir_fd(struct bf_cgen **cgen, struct bf_lock *lock);

/**
 * Free a codegen.
 *
 * If one or more programs are loaded, they won't be unloaded. Use @ref
 * bf_cgen_unload first to ensure programs are unloaded. This behaviour
 * is expected so @ref bf_cgen can be freed without unloading the BPF
 * program, during a restart for example.
 *
 * @param cgen Codegen to free. Can't be NULL.
 */
void bf_cgen_free(struct bf_cgen **cgen);

/**
 * @brief Serialize a codegen.
 *
 * @param cgen Codegen to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the codegen into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_cgen_pack(const struct bf_cgen *cgen, bf_wpack_t *pack);

/**
 * @brief Set a chain.
 *
 * Generate and load a new chain. Attach the chain if `hookopts` is not NULL. It
 * is assumed that no chain with the same name exist.
 *
 * @param cgen Codegen to attach to the kernel. Can't be NULL.
 * @param hookopts Hook options.
 * @param lock Lock providing the chain directory file descriptor. Must hold a
 *        valid `chain_fd`. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_set(struct bf_cgen *cgen, struct bf_hookopts **hookopts,
                struct bf_lock *lock);

/**
 * Create and load a `bf_program` into the kernel.
 *
 * Create a new `bf_program` for `cgen`, and generate it based on the chain
 * stored in the codegen. Once the generation is complete, the program is
 * loaded into the kernel.
 *
 * @param cgen Codegen to load into the kernel. Can't be NULL.
 * @param lock Lock providing the chain directory file descriptor. Must hold a
 *        valid `chain_fd`. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_load(struct bf_cgen *cgen, struct bf_lock *lock);

/**
 * Attach a loaded program to a hook.
 *
 * `ns` is the namespace the codegen should switch to before attaching the
 * program. This is required to ensure the interface index the program is
 * attached to (for XDP and TC programs) is correct, and the interface index
 * the program filters on (e.g. `meta.iface`, for all hooks) is correct too.
 *
 * @param cgen Codegen to attach to the kernel. Can't be NULL.
 * @param hookopts Hook options. Can't be NULL.
 * @param lock Lock providing the chain directory file descriptor. Must hold a
 *        valid `chain_fd`. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_attach(struct bf_cgen *cgen, struct bf_hookopts **hookopts,
                   struct bf_lock *lock);

/**
 * Flags to control the behavior of `bf_cgen_update`.
 */
enum bf_cgen_update_flags
{
    /** Preserve counter values from the old program. */
    BF_CGEN_UPDATE_PRESERVE_COUNTERS,

    /** Reuse the log ring buffer of the old program, if it has one. */
    BF_CGEN_UPDATE_PRESERVE_LOGS,

    _BF_CGEN_UPDATE_MAX,
};

/**
 * Update the program attached to the hook.
 *
 * A new program will be generated based on `new_chain`, before it is loaded
 * into the kernel. The link used by the codegen is updated to point to the
 * new program.
 *
 * On success, the new program is stored in the codegen, and the previous
 * program is unloaded and freed.
 *
 * The caller keeps ownership of `*new_chain` and must free it.
 *
 * @post
 * - On success: the codegen holds the new chain, and `*new_chain` points to
 *   the codegen's previous chain.
 * - On failure: `*new_chain` and the pinned context are unchanged, and
 *   `cgen` still holds the previous chain and handle. The link and the
 *   pins point to the previous program, unless restoring them fails.
 *
 * @param cgen Codegen to update. Can't be NULL.
 * @param new_chain Chain containing the new rules, sets, and policy.
 *        Can't be NULL.
 * @param flags Flags to control update behavior. 0 if no flags.
 * @param lock Lock providing the chain directory file descriptor. Must hold a
 *        valid `chain_fd`. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain,
                   uint32_t flags, struct bf_lock *lock);

/**
 * Detach a program from the kernel.
 *
 * The program is not unloaded or unpinned from the filesystem.
 *
 * @param cgen Codegen to detach. Can't be NULL.
 */
void bf_cgen_detach(struct bf_cgen *cgen);

/**
 * Unload a program from the kernel.
 *
 * @param cgen Codege to unload. Can't be NULL.
 * @param lock Lock providing the chain directory file descriptor. Must hold a
 *        valid `chain_fd`. Can't be NULL.
 */
void bf_cgen_unload(struct bf_cgen *cgen, struct bf_lock *lock);

void bf_cgen_dump(const struct bf_cgen *cgen, prefix_t *prefix);

/**
 * @enum bf_counter_type
 *
 * Special counter types for @ref bf_cgen_get_counter .
 */
enum bf_counter_type
{
    BF_COUNTER_POLICY = -2,
    BF_COUNTER_ERRORS = -1,
};

/**
 * @brief Load the chain's counters from the BPF counters map.
 *
 * Refresh `cgen->chain` with the current counter values stored in the BPF
 * counters map:
 * - Rule counters are loaded into `bf_rule.counters` for rules with
 *   `has_counters == 1` only; rules with `has_counters == 0` are left
 *   untouched.
 * - The chain's policy and error counters are always loaded into
 *   `bf_chain.policy_counters` and `bf_chain.error_counters`, regardless of
 *   any rule's `has_counters` value.
 *
 * On failure, `cgen->chain` may be partially updated: counters loaded before
 * the failing lookup retain their new values, the others are left unchanged.
 * Callers that need transactional semantics must snapshot the chain before
 * the call.
 *
 * @pre
 * - `cgen` is not NULL.
 * - `cgen->handle->cmap` is populated, i.e. the chain has been loaded into
 *   the kernel. Calling this function on a cgen without a counters map
 *   returns an error.
 * @post
 * - On success: every rule with `has_counters == 1` has its `counters` field
 *   refreshed, and the chain's `policy_counters` and `error_counters` are
 *   refreshed.
 * - On failure: `cgen->chain` may be partially updated (see above).
 *
 * @param cgen Codegen to load counters for.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_cgen_load_counters(struct bf_cgen *cgen);

/**
 * Get packets and bytes counter at a specific index.
 *
 * Counters are referenced by their index in the counters map or the enum
 * values defined by @ref bf_counter_type .
 *
 * The counter from all the program generated from @p cgen are summarised
 * together.
 *
 * @param cgen Codegen to get the counter for. Can't be NULL.
 * @param counter_idx Index of the counter to get. If @p counter_idx doesn't
 *        correspond to a valid index, -E2BIG is returned.
 * @param counter Counter structure to fill with the counter values. Can't be
 *        NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_cgen_get_counter(const struct bf_cgen *cgen,
                        enum bf_counter_type counter_idx,
                        struct bf_counter *counter);
