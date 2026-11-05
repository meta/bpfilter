/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/swich.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <bpfilter/core/list.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#include "cgen/codegen.h"
#include "cgen/jmp.h"
#include "filter.h"

/// Cleanup attribute for a @ref bf_swich_option variable.
#define _free_bf_swich_option_ __attribute__((cleanup(_bf_swich_option_free)))

/**
 * @struct bf_swich_option
 *
 * Represent a @c case of the switch: contains the instructions to execute if
 * the switch's register is equal to a specific value.
 */
struct bf_swich_option
{
    /// Immediate value to match against the switch's register.
    uint32_t imm;
    /// Jump context used to jump from the comparison to the bytecode to
    /// execute, then to the end of the switch.
    struct bf_jmpctx jmp;
    /// Number of instructions for this option.
    size_t insns_len;
    /// Instructions to execute, as a flexible array member.
    struct bpf_insn insns[];
};

static void _bf_swich_option_free(struct bf_swich_option **option);

/**
 * Allocate and initialize a new switch option (case).
 *
 * @param option Switch option to allocate and initialize. Can't be NULL.
 * @param imm Immediate value to match against the switch's register.
 * @param insns Instructions to execute if the option matches.
 * @param insns_len Number of instructions in @p insns .
 * @return 0 on success, or negative errno value on failure.
 */
static int _bf_swich_option_new(struct bf_swich_option **option, uint32_t imm,
                                const struct bpf_insn *insns, size_t insns_len)
{
    _free_bf_swich_option_ struct bf_swich_option *_option = NULL;

    assert(option);
    assert(insns);

    _option = malloc(sizeof(*_option) + (sizeof(struct bpf_insn) * insns_len));
    if (!_option)
        return -ENOMEM;

    _option->imm = imm;
    _option->insns_len = insns_len;
    memcpy(_option->insns, insns, sizeof(struct bpf_insn) * insns_len);

    *option = TAKE_PTR(_option);

    return 0;
}

/**
 * Free a switch option.
 *
 * Free @p option is it points to valid memory. If @p option points to a NULL
 * pointer, nothing is done.
 *
 * @param option Option to free. Can't be NULL.
 */
static void _bf_swich_option_free(struct bf_swich_option **option)
{
    assert(option);

    if (!*option)
        return;

    free(*option);
    *option = NULL;
}

int bf_swich_init(struct bf_swich *swich, struct bf_codegen *program, int reg)
{
    assert(swich);
    assert(program);

    swich->program = program;
    swich->reg = reg;

    bf_list_init(
        &swich->options,
        (bf_list_ops[]) {{.free = (bf_list_ops_free)_bf_swich_option_free}});

    swich->default_opt = NULL;

    return 0;
}

void bf_swich_cleanup(struct bf_swich *swich)
{
    assert(swich);

    bf_list_clean(&swich->options);
    _bf_swich_option_free(&swich->default_opt);
}

int bf_swich_add_option(struct bf_swich *swich, uint32_t imm,
                        const struct bpf_insn *insns, size_t insns_len)
{
    _free_bf_swich_option_ struct bf_swich_option *option = NULL;
    int r;

    assert(swich);
    assert(insns);

    r = _bf_swich_option_new(&option, imm, insns, insns_len);
    if (r)
        return r;

    r = bf_list_add_tail(&swich->options, option);
    if (r)
        return r;

    TAKE_PTR(option);

    return 0;
}

int bf_swich_set_default(struct bf_swich *swich, const struct bpf_insn *insns,
                         size_t insns_len)
{
    _free_bf_swich_option_ struct bf_swich_option *option = NULL;
    int r;

    assert(swich);
    assert(insns);

    if (swich->default_opt) {
        bf_warn("default bf_swich option already exists, replacing it");
        _bf_swich_option_free(&swich->default_opt);
    }

    r = _bf_swich_option_new(&option, 0, insns, insns_len);
    if (r)
        return r;

    swich->default_opt = TAKE_PTR(option);

    return 0;
}

int bf_swich_generate(struct bf_swich *swich)
{
    struct bf_codegen *program = swich->program;

    // Match an option against the value and jump to the related bytecode
    bf_list_foreach (&swich->options, option_node) {
        struct bf_swich_option *option = bf_list_node_get_data(option_node);

        option->jmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, swich->reg, option->imm, 0));
    }

    // Insert the default option if any
    if (swich->default_opt)
        swich->default_opt->jmp = bf_jmpctx_get(program, BPF_JMP_A(0));

    // Insert each option's bytecode
    bf_list_foreach (&swich->options, option_node) {
        struct bf_swich_option *option = bf_list_node_get_data(option_node);

        bf_jmpctx_cleanup(&option->jmp);
        for (size_t i = 0; i < option->insns_len; ++i)
            EMIT(program, option->insns[i]);
        option->jmp = bf_jmpctx_get(program, BPF_JMP_A(0));
    }

    // Insert the default instructions
    if (swich->default_opt) {
        bf_jmpctx_cleanup(&swich->default_opt->jmp);
        for (size_t i = 0; i < swich->default_opt->insns_len; ++i)
            EMIT(program, swich->default_opt->insns[i]);
    }

    bf_list_foreach (&swich->options, option_node) {
        struct bf_swich_option *option = bf_list_node_get_data(option_node);

        bf_jmpctx_cleanup(&option->jmp);
    }

    return 0;
}
