/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/core/vector.h>
#include <bpfilter/dump.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/pack.h>

#include "cgen/fixup.h"
#include "cgen/printer.h"
#include "cgen/runtime.h"
#include "filter.h"

/**
 * @file program.h
 *
 * @ref bf_program is used to represent a BPF program. It contains the BPF
 * bytecode, as well as the required maps and metadata.
 *
 * **Workflow**
 *
 * The program is composed of different steps:
 * 1. Initialize the generic context
 * 2. Preprocess the packet's headers: gather information about the packet's
 *    size, the protocols available, the input interface...
 * 3. Execute the filtering rules: execute all the rules defined in the program
 *    sequentially. If a rule matches the packet, apply its verdict and return.
 * 4. Apply the policy if no rule matched: if no rule matched the packet, return
 *    the chain's policy (default action).
 *
 * **Memory layout**
 *
 * The program will use the BPF registers to following way:
 * - @c r0 : return value
 * - @c r1 to @c r5 (included): general purpose registers
 * - @c r6 : address of the header currently filtered on
 * - @c r7 : L3 protocol ID
 * - @c r8 : L4 protocol ID
 * - @c r9 : unused
 * - @c r10 : frame pointer
 *
 * This convention is followed throughout the project and must be followed all
 * the time to prevent incompatibilities. Debugging this kind of issues is not
 * fun, so stick to it.
 *
 * @warning L3 and L4 protocol IDs **must** be stored in registers, no on the
 * stack, as older verifier aren't able to keep track of scalar values located
 * on the stack. This means the verification will fail because the verifier
 * can't verify branches properly.
 *
 * `bf_runtime` is used to represent the layout of the first stack frame in the
 * program. It is filled during preprocessing and contains data required for
 * packet filtering.
 *
 * **About preprocessing**
 *
 * The packets are preprocessed according to the program type (i.e. BPF flavor).
 * Each flavor needs to perform the following steps during preprocessing:
 * - Store the packet size and the input interface index into the runtime context
 * - Create a BPF dynamic pointer for the packet
 * - Preprocess the L2, L3, and L4 headers
 *
 * The header's preprocessing is required to discover the protocols used in the
 * packet: processing L2 will provide us with information about L3, and so on. The
 * logic used to process layer X is responsible for discovering layer X+1: the L2
 * header preprocessing logic will discover the L3 protocol ID. When processing
 * layer X, if the protocol is not supported, the protocol ID is reset to 0 (so
 * we won't execute the rules for this layer) and subsequent layers are not
 * processed (because we can't discover their protocol).
 *
 * For example, assuming IPv6 and TCP are the only supported protocols:
 * - L2 processing: discover the packet's ethertype (IPv6), and store it into
 *   @c r7 .
 * - L3 processing: the protocol ID in @c r7 is supported (IPv6), so a slice is
 *   created, and the L4 protocol ID is read from the IPV6 header into @c r8 .
 * - L4 processing: the protocol ID in @c r8 is supported (TCP), so a slice
 *   is created.
 * - The program can now start executing the rules.
 *
 * However, assuming only IPv6 and UDP are supported:
 * - L2 processing: discover the packet's ethertype (IPv6), and store it into
 *   @c r7 .
 * - L3 processing: the protocol ID in @c r7 is supported (IPv6), so a slice is
 *   created, and the L4 protocol ID is read from the IPV6 header into @c r8 .
 * - L4 processing: the protocol ID in @c r8 is no supported (TCP), @c r8 is
 *   set to 0 and we stop processing this layer.
 * - The program can now start executing the rules. No layer 4 rule will be
 *   executed as @c r8 won't match any protocol ID.
 */

#define EMIT(program, x)                                                       \
    ({                                                                         \
        int __r = bf_program_emit((program), (x));                             \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_KFUNC_CALL(program, function)                                     \
    ({                                                                         \
        int __r = bf_program_emit_kfunc_call((program), (function));           \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP(program, type, insn)                                        \
    ({                                                                         \
        int __r = bf_program_emit_fixup((program), (type), (insn), NULL);      \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP_ELFSTUB(program, elfstub_id)                                \
    ({                                                                         \
        int __r = bf_program_emit_fixup_elfstub((program), (elfstub_id));      \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP_JMP_NEXT_RULE(program, insn)                                \
    ({                                                                         \
        int __r = bf_program_emit_fixup(                                       \
            (program), BF_FIXUP_TYPE_JMP_NEXT_RULE, (insn), NULL);             \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_LOAD_COUNTERS_FD_FIXUP(program, reg)                              \
    ({                                                                         \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup(                                       \
            (program), BF_FIXUP_TYPE_COUNTERS_MAP_FD, ld_insn[0], NULL);       \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_LOAD_LOG_FD_FIXUP(program, reg)                                   \
    ({                                                                         \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup((program), BF_FIXUP_TYPE_LOG_MAP_FD,   \
                                        ld_insn[0], NULL);                     \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_LOAD_STATE_FD_FIXUP(program, reg)                                 \
    ({                                                                         \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup((program), BF_FIXUP_TYPE_STATE_MAP_FD, \
                                        ld_insn[0], NULL);                     \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

/**
 * Load a specific set's file descriptor.
 *
 * @note Similarly to every @c EMIT_* macro, it must be called from a function
 * returning an @c int , if the call fails, the macro will return a negative
 * errno value.
 *
 * @param program Program to generate the bytecode for. Can't be NULL.
 * @param reg Register to store the set file descriptor in.
 * @param set Non-owning pointer to the referenced `bf_set`. The set must
 *        live at least until `bf_program_load()` returns.
 */
#define EMIT_LOAD_SET_FD_FIXUP(program, reg, set)                              \
    ({                                                                         \
        union bf_fixup_attr __attr;                                            \
        memset(&__attr, 0, sizeof(__attr));                                    \
        __attr.set_ptr = (set);                                                \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup((program), BF_FIXUP_TYPE_SET_MAP_FD,   \
                                        ld_insn[0], &__attr);                  \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

struct bf_chain;
struct bf_counter;
struct bf_hookopts;
struct bf_handle;
struct bf_set;
struct bf_set_group;

struct bf_program
{
    enum bf_flavor flavor;

    /// Log messages printer
    struct bf_printer *printer;

    /** Handle containing BPF object references (prog_fd, maps, link).
     * Non-owning pointer, passed in from `bf_cgen` via `bf_program_new()`.
     * Populated during load/attach. */
    struct bf_handle *handle;

    /* Bytecode */
    uint32_t elfstubs_location[_BF_ELFSTUB_MAX];
    bf_vector img;
    bf_list fixups;

    /** Non-empty sets from `runtime.chain->sets`, partitioned into groups
     * that each back a single BPF map. Hash-keyed sets sharing a key
     * format are placed in the same group; each LPM trie set sits in a
     * group of its own. A set's position within a group is its bit index
     * in the map's bitmask value. Not serialized. */
    bf_list set_groups;

    /** Runtime data used to interact with the program and cache information.
     * This data is not serialized. */
    struct
    {
        /** Hook-specific ops to use to generate the program. */
        const struct bf_flavor_ops *ops;

        /** Chain the program is generated from. This is a non-owning pointer:
         * the @ref bf_program doesn't have to manage its lifetime. */
        const struct bf_chain *chain;
    } runtime;
};

#define _free_bf_program_ __attribute__((__cleanup__(bf_program_free)))

/**
 * @brief Allocate and initialize a new `bf_program` object.
 *
 * @param program `bf_program` object to allocate and initialize. Can't be NULL.
 * @param chain Chain the program is generated from. Can't be NULL.
 * @param handle Handle to store BPF object references in. The program borrows
 *        this pointer (non-owning). Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_program_new(struct bf_program **program, const struct bf_chain *chain,
                   struct bf_handle *handle);

void bf_program_free(struct bf_program **program);

void bf_program_dump(const struct bf_program *program, prefix_t *prefix);

static inline int bf_program_emit(struct bf_program *program,
                                  struct bpf_insn insn)
{
    assert(program);

    return bf_vector_add(&program->img, &insn);
}

int bf_program_emit_kfunc_call(struct bf_program *program, const char *name);
int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn,
                          const union bf_fixup_attr *attr);
int bf_program_emit_fixup_elfstub(struct bf_program *program,
                                  enum bf_elfstub_id id);
int bf_program_generate(struct bf_program *program);

/**
 * @brief Get the bit position of a set within its group.
 *
 * Hash-keyed sets sharing a key format are grouped together and share a
 * single BPF map; LPM trie sets each live in a group of size 1. Either
 * way, each set's elements are stored in the group's map with a bitmask
 * value where one bit identifies which set owns the element. This
 * function returns that bit's position for `set` within its group (always
 * 0 for LPM trie sets).
 *
 * @param program Program whose groups have been built. Can't be NULL.
 * @param set Set to locate in the program's groups. Can't be NULL.
 * @param bit_index Output: position of `set` within its group's bit layout.
 *        Can't be NULL.
 * @return 0 on success, `-ENOENT` if `set` is not part of any group (for
 *         example, because it is empty).
 */
int bf_program_set_bit_index(const struct bf_program *program,
                             const struct bf_set *set, size_t *bit_index);

/**
 * Load the BPF program into the kernel.
 *
 * Prior to loading the BPF program, multiple BPF maps are created to store
 * the counters, the debug strings, and the sets. If `prog->handle` already has
 * a log map, it is reused instead of creating a new one. If the program can't
 * be loaded, the maps created by this function are destroyed, and a reused log
 * map is only closed.
 *
 * Once the loading succeeds, the program and the maps are pinned to the
 * filesystem. If the BPF objects can't be pinned, the program is unloaded and
 * the maps destroyed.
 *
 * @param prog Program to load into the kernel. Can't be NULL and must contain
 *        instructions.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_program_load(struct bf_program *prog);

int bf_program_get_counter(const struct bf_program *program,
                           uint32_t counter_idx, struct bf_counter *counter);
int bf_program_set_counters(struct bf_program *program,
                            const struct bf_counter *counters);

size_t bf_program_chain_counter_idx(const struct bf_program *program);
size_t bf_program_error_counter_idx(const struct bf_program *program);
