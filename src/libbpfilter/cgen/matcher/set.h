/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

struct bf_matcher;
struct bf_codegen;

/**
 * @brief Generate the map-lookup sequence shared by all set codegen paths.
 *
 * Emits: load set FD, compute key pointer, call `bpf_map_lookup_elem`,
 * jump to next rule if the lookup returns NULL.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param matcher Set matcher (carries the set index in its payload).
 *        Can't be NULL.
 * @param key_offset Byte offset from `R10` (stack pointer) where the key
 *        starts. Use `BF_PROG_SCR_OFF()` for scratch area offsets.
 * @return 0 on success, or negative errno on error.
 */
int bf_set_generate_map_lookup(struct bf_codegen *program,
                               const struct bf_matcher *matcher,
                               int key_offset);

/**
 * @brief Generate a complete LPM trie key and map lookup.
 *
 * Writes prefixlen (`addr_size * 8`) at `scratch[4]`, copies `addr_size` bytes
 * from `R6 + src_offset` to `scratch[8]` via `bf_stub_load`, then calls
 * `bf_set_generate_map_lookup` with key at `scratch[4]`.
 *
 * `R6` must already point to the base of the data (header pointer for
 * packet flavors, ctx pointer for `cgroup_sock_addr`).
 *
 * @param program Program to emit into. Can't be NULL.
 * @param matcher Set matcher (carries the set index). Can't be NULL.
 * @param src_offset Byte offset from `R6` where the address starts.
 * @param addr_size Size of the address in bytes (4 for IPv4, 16 for IPv6).
 * @return 0 on success, or negative errno on error.
 */
int bf_set_generate_trie_lookup(struct bf_codegen *program,
                                const struct bf_matcher *matcher,
                                size_t src_offset, size_t addr_size);
