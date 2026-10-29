/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/core/list.h>
#include <bpfilter/helper.h>

/**
 * @file swich.h
 *
 * @ref bf_swich is used to generate a switch-case logic in BPF bytecode, the
 * logic is the following:
 * - Create a new @ref bf_swich object and initialize it. Use @ref bf_swich_get
 *   to simplify this step. A @ref bf_swich object contains a pointer to the
 *   generated program, and the register to perform the switch comparison against.
 * - Call @ref EMIT_SWICH_OPTION to define the various cases for the switch, and
 *   the associated BPF bytecode to run.
 * - Call @ref EMIT_SWICH_DEFAULT to define the default case of the switch,
 *   this is optional.
 * - Call @ref bf_swich_generate to generate the BPF bytecode for the switch.
 *
 * Once @ref bf_swich_generate has been called, this is what the switch
 * structure will look like in BPF bytecode:
 * @code{.c}
 *  if case 1 matches REG, jump to case 1 code
 *  if case 2 matches REG, jump to case 2 code
 *  else jump to default code
 *  case 1 code
 *      jump after the switch
 *  case 2 code
 *      jump after the switch
 *  default code
 * @endcode
 *
 * @note
 * I am fully aware it's supposed to be spelled @c switch and not @c swich , but
 * both @c switch and @c case are reserved keywords in C, so I had to come
 * up with a solution to avoid clashes, and @c swich could be pronounced
 * similarly to @c switch , at least to my non-native speak ear.
 */

struct bf_codegen;

/// Cleanup attribute for a @ref bf_swich variable.
#define _clean_bf_swich_ __attribute__((cleanup(bf_swich_cleanup)))

/**
 * Create, initialize, and return a new @ref bf_swich object.
 *
 * @param program @ref bf_codegen object to create the switch in.
 * @param reg Register to use to compare the cases values to.
 * @return A new @ref bf_swich object.
 */
#define bf_swich_get(program, reg)                                             \
    ({                                                                         \
        struct bf_swich __swich = {};                                          \
        int __r = bf_swich_init(&__swich, (program), (reg));                   \
        if (__r)                                                               \
            return __r;                                                        \
        __swich;                                                               \
    })

/**
 * Add a case to the @ref bf_swich
 *
 * @param swich Pointer to a valid @ref bf_swich .
 * @param imm Immediate value to compare against the switch's register.
 * @param ... BPF instructions to execute if the case matches.
 */
#define EMIT_SWICH_OPTION(swich, imm, ...)                                     \
    do {                                                                       \
        const struct bpf_insn __insns[] = {__VA_ARGS__};                       \
        int __r =                                                              \
            bf_swich_add_option((swich), (imm), __insns, ARRAY_SIZE(__insns)); \
        if (__r < 0)                                                           \
            return __r;                                                        \
    } while (0)

/**
 * Set the default instruction if no cases of the switch matches the register.
 *
 * Defining a default option to a @ref bf_swich is optional. If this macro is
 * called twice, the existing default options will be replaced by the new ones.
 *
 * @param swich Pointer to a valid @ref bf_swich .
 * @param ... BPF instructions to execute if no case matches.
 */
#define EMIT_SWICH_DEFAULT(swich, ...)                                         \
    do {                                                                       \
        const struct bpf_insn __insns[] = {__VA_ARGS__};                       \
        int __r = bf_swich_set_default((swich), __insns, ARRAY_SIZE(__insns)); \
        if (__r < 0)                                                           \
            return __r;                                                        \
    } while (0)

/**
 * @struct bf_swich
 *
 * Context used to define a switch-case structure in BPF bytecode.
 */
struct bf_swich
{
    /// Program to generate the switch-case in.
    struct bf_codegen *program;
    /// Register to compare to the various cases of the switch.
    int reg;
    /// List of options (cases) for the switch.
    bf_list options;
    /// Default option, if no case matches the switch's register.
    struct bf_swich_option *default_opt;
};

/**
 * Initialise a @ref bf_swich object.
 *
 * @param swich @ref bf_swich object to initialize, can't be NULL.
 * @param program @ref bf_codegen object to generate the switch-case for. Can't
 *        be NULL.
 * @param reg Register to compare to the cases of the switch.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_swich_init(struct bf_swich *swich, struct bf_codegen *program, int reg);

/**
 * Cleanup a @ref bf_swich object.
 *
 * Once this function returns, the @p swich object can be reused by calling
 * @ref bf_swich_init .
 *
 * @param swich The @ref bf_swich object to clean up.
 */
void bf_swich_cleanup(struct bf_swich *swich);

/**
 * Add an option (case) to the switch object.
 *
 * @param swich @ref bf_swich object to add the option to. Can't be NULL.
 * @param imm Immediate value to compare the switch's register to. If the
 *        values are equal, the option's instructions are executed.
 * @param insns Array of BPF instructions to execute if the case matches.
 * @param insns_len Number of instructions in @p insns .
 * @return 0 on success, or negative errno value on failure.
 */
int bf_swich_add_option(struct bf_swich *swich, uint32_t imm,
                        const struct bpf_insn *insns, size_t insns_len);

/**
 * Set the switch's default actions if no case matches.
 *
 * @param swich @ref bf_swich object to set the default action for. Can't be
 *        NULL.
 * @param insns Array of BPF instructions to execute.
 * @param insns_len Number of instructions in @p insns .
 * @return 0 on success, or negative errno value on failure.
 */
int bf_swich_set_default(struct bf_swich *swich, const struct bpf_insn *insns,
                         size_t insns_len);

/**
 * Generate the bytecode for the switch.
 *
 * The BPF program doesn't contain any of the instructions of the @ref bf_swich
 * until this function is called.
 *
 * @todo If no ``default`` case is defined, the switch should jump after the
 * last case.
 *
 * @param swich @ref bf_swich object to generate the bytecode for. Can't be
 *        NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_swich_generate(struct bf_swich *swich);
