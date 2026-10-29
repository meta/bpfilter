/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

/**
 * @file jmp.h
 *
 * @ref bf_jmpctx is a helper structure to manage jump instructions in the
 * program. A @ref bf_jmpctx will insert a new jump instruction in the BPF
 * program and update its jump offset when the @ref bf_jmpctx is deleted.
 *
 * Example:
 * @code{.c}
 *  // Within a function body
 *  {
 *      _clean_bf_jmpctx_ struct bf_jmpctx ctx =
 *          bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0, 0));
 *      int ret;
 *      int r;
 *
 *      r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret);
 *      if (r)
 *          return r;
 *
 *      EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret));
 *      EMIT(program, BPF_EXIT_INSN());
 *  }
 * @endcode
 *
 * @c ctx is a variable local to the scope, marked with @c _clean_bf_jmpctx_ .
 * The second argument to @c bf_jmpctx_get is the jump instruction to emit, with
 * the correct condition. When the scope is exited, the jump instruction is
 * automatically updated to point to the first instruction outside of the scope.
 *
 * Hence, all the instructions emitted within the scope will be executed if the
 * condition is not met. If the condition is met, then the program execution
 * will skip the instructions defined in the scope and continue.
 */

struct bf_codegen;

/**
 * Cleanup attribute for a @ref bf_jmpctx variable.
 */
#define _clean_bf_jmpctx_ __attribute__((cleanup(bf_jmpctx_cleanup)))

#define bf_jmpctx_default() {.program = NULL}

/**
 * Create a new @ref bf_jmpctx variable.
 *
 * @param program The program to emit the jump instruction to. It must be
 *        non-NULL.
 * @param insn The jump instruction to emit.
 * @return A new @ref bf_jmpctx variable.
 */
#define bf_jmpctx_get(program, insn)                                           \
    ({                                                                         \
        size_t __idx = (program)->img.size;                                    \
        int __r = bf_codegen_emit((program), (insn));                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
        (struct bf_jmpctx) {.program = (program), .insn_idx = __idx};          \
    })

/**
 * A helper structure to manage jump instructions in the program.
 *
 * @var bf_jmpctx::program
 *  The program to emit the jump instruction to.
 * @var bf_jmpctx::insn_idx
 *  The index of the jump instruction in the program's image.
 */
struct bf_jmpctx
{
    struct bf_codegen *program;
    size_t insn_idx;
};

/**
 * Cleanup function for @ref bf_jmpctx.
 *
 * @param ctx The @ref bf_jmpctx variable to clean up.
 */
void bf_jmpctx_cleanup(struct bf_jmpctx *ctx);
