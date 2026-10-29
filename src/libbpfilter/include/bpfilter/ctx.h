/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <bpfilter/dump.h>
#include <bpfilter/elfstub.h>

/**
 * @file ctx.h
 *
 * Global runtime context for `bpfilter`.
 *
 * This file contains the definition of the `bf_ctx` structure, which is
 * the main structure used to store the runtime context.
 *
 * All the public `bf_ctx_*` functions manipulate a private global context.
 * Chain state is persisted in per-chain bpffs context maps and loaded on
 * demand by public chain and ruleset operations. The global context does
 * not cache chain state.
 */

enum bf_verbose
{
    BF_VERBOSE_DEBUG,
    BF_VERBOSE_BPF,
    BF_VERBOSE_BYTECODE,
    _BF_VERBOSE_MAX,
};

/**
 * Initialise the global context.
 *
 * Only one global context may exist at a time. Calling `bf_ctx_setup` while
 * a context is already initialised returns `-EBUSY` and leaves the existing
 * context untouched; the caller must `bf_ctx_teardown` first to re-initialise.
 *
 * @param with_bpf_token If true, create a BPF token from bpffs.
 * @param bpffs_path Path to the bpffs mountpoint. Can't be NULL.
 * @param verbose Bitmask of verbose flags.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_setup(bool with_bpf_token, const char *bpffs_path, uint16_t verbose);

/**
 * Teardown the global context.
 */
void bf_ctx_teardown(void);

/**
 * @brief Check if the global context is setup.
 *
 * @return True if the global context is setup, false otherwise.
 */
bool bf_ctx_is_setup(void);

/**
 * Dump the global context.
 *
 * @param prefix Prefix to use for the dump.
 */
void bf_ctx_dump(prefix_t *prefix);

/**
 * Get the BPF token file descriptor.
 *
 * @return The BPF token file descriptor, or -1 if no token is used.
 */
int bf_ctx_token(void);

/**
 * @brief Get a ELF stub from its ID.
 *
 * @param id ID of the ELF stub to retrieve.
 * @return The requested ELF stub.
 */
const struct bf_elfstub *bf_ctx_get_elfstub(enum bf_elfstub_id id);

/**
 * @return true if the given verbose flag is set.
 */
bool bf_ctx_is_verbose(enum bf_verbose opt);

/**
 * @return Path to the configured BPF filesystem.
 */
const char *bf_ctx_get_bpffs_path(void);
