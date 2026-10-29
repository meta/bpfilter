/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/jmp.h"

#include <linux/bpf.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>

#include "cgen/codegen.h"

void bf_jmpctx_cleanup(struct bf_jmpctx *ctx)
{
    if (ctx->program) {
        size_t off;
        struct bpf_insn *insn =
            bf_vector_get(&ctx->program->img, ctx->insn_idx);
        if (!insn) {
            bf_abort("jump fixup references invalid instruction index %lu",
                     ctx->insn_idx);
        }

        off = ctx->program->img.size - ctx->insn_idx - 1U;

        if (off > SHRT_MAX)
            bf_warn("jump offset overflow: %ld", off);

        insn->off = (int16_t)off;
    }
}
