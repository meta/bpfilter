/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include <bpfilter/core/list.h>

/**
 * @file elfstub.h
 *
 * ELF stubs are a mechanism to integrate clang-compiled BPF bytecode into
 * bpfilter-generated BPF programs. Complex logic is more easily implemented
 * in C and integrated into the final program that developed in BPF bytecode
 * directly.
 *
 * ELF stubs source code is part of bpfilter's sources, they are compiled
 * using clang, the ELF file is stored in a C array and accessible to the
 * libbpfilter at runtime.
 *
 * **Creating a new ELF stub**
 *
 * 1. Add a new source file for the BPF program in the library's codebase (in
 *    the `bpf` folder, as `$NAME.bpf.c`).
 * 2. Declare the ELF stub in libbpfilter's CMakeLists.txt (in
 *    `bf_target_add_elfstubs()`).
 * 3. Add a new ID for this stub in `bf_elfstub_id`.
 * 4. Write the BPF C code: define a single function (additional inline
 *    functions and macros are allowed).
 *
 * **Technicalities**
 *
 * At build time, ELF stubs are compiled by clang as BPF program. As such, they
 * are bound to the same limitations as any other BPF program. `xxd` is used to
 * convert the ELF file into a C array (with size), which is included in a
 * generated `rawstubs.h` header file.
 *
 * `rawstubs.h` defines an array of `bf_rawstub` structures containing:
 * - `const void *elf`: pointer to the ELF data.
 * - `size_t len`: size of the ELF file.
 *
 * Each ELF stub can be manipulated through an instance of `bf_rawstub`, all
 * the instances are stored in an array, which is as big as `_BF_ELFSTUB_MAX`.
 *
 * However, the ELF stubs are not accessed directly through the `bf_rawstub`
 * structure, as it's not usable as-is. Instead, the `bf_context` will extract
 * the actual bytecode from the ELF file, and relocate the kfunc calls. During
 * generation, `bf_ctx_get_elfstub` is used to retrieve a pointer to
 * `bf_elfstub` containing the BPF instructions to be copied in the program.
 *
 * **Limitations**
 *
 * Not any BPF program can be integrated into a bpfilter program, this section
 * lists the current set of limitations:
 * - Maps are not supported: BPF maps can be defined, but they are not
 *   integrated by bpfilter into the program, so the final BPF program won't
 *   be verifiable.
 * - Function are not supported: each ELF stub source code should contain a
 *   single function to be integrated. Inline functions are allowed, as they're
 *   not real functions in the final ELF file.
 *
 * Those limitations might evolve, as new BPF features are developed and the ELF
 * stub implementation is improved.
 *
 * While map are not supported, `bpf_printk()` can be used, as bpfilter is
 * able to add the strings to its own map.
 */

struct bpf_insn;

/**
 * @brief Identifiers for the ELF stubs.
 *
 * Each identifier represents a valid ELF stub. If an ELF stub doesn’t have its
 * identifier, it doesn’t exist from bpfilter’s standpoint.
 */
enum bf_elfstub_id
{
    /**
     * Parse IPv6 extension headers.
     *
     * `__u8 bf_parse_ipv6(struct bf_runtime *ctx)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     *
     * **Return** The L4 protocol on success, or 0 if the program fails creating
     *            a dynamic pointer slice.
     */
    BF_ELFSTUB_PARSE_IPV6_EH,

    /**
     * Parse IPv6 extension headers filling runtime context for ip6.nexthdr rule.
     *
     * `__u8 bf_parse_ipv6(struct bf_runtime *ctx)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     *
     * **Return** The L4 protocol on success, or 0 if the program fails creating
     *            a dynamic pointer slice.
     */
    BF_ELFSTUB_PARSE_IPV6_NH,

    /**
     * Update the counters for a given rule.
     *
     * `__u8 bf_update_counters(struct bf_runtime *ctx, void *map, __u64 key)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     * - `map`: address of the counters map.
     * - `key`: key of the map to update.
     *
     * **Return** 0 on success, or 1 on error.
     */
    BF_ELFSTUB_UPDATE_COUNTERS,

    /**
     * Log user-requested packet headers to a ring buffer.
     *
     * `int bf_pkt_log(struct bf_runtime *ctx, __u32 rule_id, __u8 headers, __u32 verdict, __u32 l3_l4_proto)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     * - `rule_id`: id of the matched rule.
     * - `headers`: user-requested headers to log.
     * - `verdict`: verdict of the matched rule.
     * - `l3_l4_proto`: layer 3 (internet) and layer 4 (transport) protocols packed (l3 << 16 | l4)
     *
     * **Return** 0 on success, or negative errno value on failure.
     */
    BF_ELFSTUB_PKT_LOG,

    /**
     * Calculate flow hash from packet 5-tuple + IPv6 flow label.
     *
     * `__u32 bf_flow_hash(struct bf_runtime *ctx, __u16 l3_proto, __u8 l4_proto)`
     *
     * Computes a 32-bit hash by combining source/destination addresses,
     * source/destination ports (TCP/UDP), protocol, and IPv6 flow label,
     * then applies an xxHash32 avalanche finalizer for uniform distribution.
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     * - `l3_proto`: L3 protocol ID (network byte order).
     * - `l4_proto`: L4 protocol ID.
     *
     * **Return** The computed 32-bit flow hash with uniform distribution.
     */
    BF_ELFSTUB_FLOW_HASH,

    /**
     * Log socket address metadata to a ring buffer.
     *
     * `int bf_sock_addr_log(struct bf_runtime *ctx, __u32 rule_id, __u32 verdict, __u32 l3_l4_proto, __u8 captured_fields)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     * - `rule_id`: id of the matched rule.
     * - `verdict`: verdict of the matched rule.
     * - `l3_l4_proto`: layer 3 and layer 4 protocols packed (l3 << 16 | l4).
     * - `captured_fields`: bitmask of conditional fields captured in the
     *   log entry (see `BF_LOG_SOCK_ADDR_*`).
     *
     * **Return** 0 on success, or negative errno value on failure.
     */
    BF_ELFSTUB_SOCK_ADDR_LOG,

    /**
     * Log a packet 5-tuple to a ring buffer.
     *
     * `int bf_pkt_5_tuple_log(struct bf_runtime *ctx, __u32 rule_id, __u32 verdict, __u32 l3_l4_proto)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     * - `rule_id`: id of the matched rule.
     * - `verdict`: verdict of the matched rule.
     * - `l3_l4_proto`: layer 3 and layer 4 protocols packed as
     *   `(l3 << 16 | l4)`.
     *
     * **Return** 0 on success, or negative errno value on failure.
     */
    BF_ELFSTUB_PKT_5_TUPLE_LOG,

    /** 
     * Check if `limit` packets have already been seen in the last unit of time
     * 
     * `__u8 bf_ratelimit(void *map, __u32 limit, __u32 duration, __u32 key)`
     *
     * **Parameters**
     * - `map`: address of the rate limit map.
     * - `limit`: number of packets allowed to pass in one unit of time.
     * - `duration`: the amount of time to wait before resetting the rate limit.
     * - `key`: key of the map rate limit map.
     *
     * **Return** 0 if in the allowed limit (inclusive), or 1 if over the limit.
     */
    BF_ELFSTUB_LIMIT,

    _BF_ELFSTUB_MAX,
};

struct bf_printk_str
{
    size_t insn_idx;
    const char *str;
};

/**
 * @brief Processed ELF stub to be integrated into a BPF program.
 */
struct bf_elfstub
{
    enum bf_elfstub_id id;
    struct bpf_insn *insns;
    size_t ninsns;
    bf_list strs;
};

#define _free_bf_elfstub_ __attribute__((__cleanup__(bf_elfstub_free)))

/**
 * @brief Allocate and initialize a new ELF stub.
 *
 * The corresponding raw ELF stub will be read, its text section will be copied
 * into the final ELF, and the calls to kfuncs will be relocated according to
 * the host's kernel.
 *
 * @param stub ELF stub to allocate and initialize. Can't be NULL.
 * @param id Identifier of the raw ELF stub to initialize.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_elfstub_new(struct bf_elfstub **stub, enum bf_elfstub_id id);

/**
 * Deinitialise and deallocate an ELF stub.
 *
 * @param stub ELF stub. Can't be NULL.
 */
void bf_elfstub_free(struct bf_elfstub **stub);
