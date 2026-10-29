/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/core/list.h>
#include <bpfilter/pack.h>

struct bf_chain;
struct bf_handle;
struct bf_lock;

#define BF_STATE_PIN_NAME "bf_ctx"

/**
 * @brief Serialize a chain and handle using the persisted format.
 *
 * @param chain Chain to serialize. Can't be NULL.
 * @param handle Handle to serialize. Can't be NULL.
 * @param pack Serialization destination. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_state_pack(const struct bf_chain *chain, const struct bf_handle *handle,
                  bf_wpack_t *pack);

/**
 * @brief Restore chain and handle from bpffs.
 *
 * Both output arguments remain unchanged on failure. On success, the caller
 * owns both outputs. Pins are not modified.
 *
 * @param lock Lock holding the chain directory. Can't be NULL.
 * @param chain Output chain. Can't be NULL.
 * @param handle Output handle. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_state_restore(struct bf_lock *lock, struct bf_chain **chain,
                     struct bf_handle **handle);

/**
 * @brief Persist a chain and handle through a temporary context pin.
 *
 * @param lock Lock holding the chain directory for writing. Can't be NULL.
 * @param chain Chain to persist. Can't be NULL.
 * @param handle Handle to persist. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_state_persist(struct bf_lock *lock, const struct bf_chain *chain,
                     const struct bf_handle *handle);

/**
 * @brief Discover separately owned chains and handles in corresponding lists.
 *
 * Each chain is restored under its own READ lock. The lock is released before
 * the next entry. Staging directories are ignored. Per-entry failures are
 * logged and skipped. Directory read failures return partial results.
 *
 * @param lock Locked pin directory, without a chain lock. Can't be NULL.
 * @param chains Output owning list of chains. Can't be NULL. Its nodes match
 *        the nodes in `handles` in order. Unchanged on setup failure.
 * @param handles Output owning list of handles. Can't be NULL. Unchanged on
 *        setup failure.
 * @return 0 on success, or a negative errno value on setup failure.
 */
int bf_state_discover(struct bf_lock *lock, bf_list **chains,
                      bf_list **handles);
