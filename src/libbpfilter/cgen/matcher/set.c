/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/set.h"

#include <limits.h>
#include <stdint.h>

#include <bpfilter/chain.h>
#include <bpfilter/matcher.h>
#include <bpfilter/set.h>

#include "cgen/codegen.h"
#include "cgen/matcher/cmp.h"
#include "cgen/stub.h"

int bf_set_generate_map_lookup(struct bf_codegen *program,
                               const struct bf_matcher *matcher, int key_offset)
{
    const struct bf_set *set;
    size_t bit_index;
    int r;

    assert(program);
    assert(matcher);

    set = bf_chain_get_set_for_matcher(program->runtime.chain, matcher);
    if (!set) {
        return bf_err_r(-ENOENT, "matcher set not found in %s",
                        program->runtime.chain->name);
    }

    r = bf_codegen_set_bit_index(program, set, &bit_index);
    if (r) {
        return bf_err_r(r, "set '%s' not assigned to any group",
                        set->name ?: "<anonymous>");
    }

    EMIT_LOAD_SET_FD_FIXUP(program, BPF_REG_1, set);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, key_offset));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    /* On lookup miss skip the bitmask byte load; r0 stays 0, which the
     * final cmp-against-0 below treats as "bit not set". */
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2));
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_0,
                              (int16_t)(bit_index / CHAR_BIT)));
    EMIT(program,
         BPF_ALU32_IMM(BPF_AND, BPF_REG_0, 1U << (bit_index % CHAR_BIT)));

    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(bf_cmp_get_jmp_ins(matcher), BPF_REG_0, 0, 0));

    return 0;
}

int bf_set_generate_trie_lookup(struct bf_codegen *program,
                                const struct bf_matcher *matcher,
                                size_t src_offset, size_t addr_size)
{
    int r;

    assert(program);
    assert(matcher);

    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, (uint32_t)(addr_size * 8)));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(4)));

    r = bf_stub_load(program, src_offset, addr_size, BF_PROG_SCR_OFF(8));
    if (r)
        return r;

    return bf_set_generate_map_lookup(program, matcher, BF_PROG_SCR_OFF(4));
}
