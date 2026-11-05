/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/cmp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/codegen.h"
#include "cgen/jmp.h"

uint8_t bf_cmp_get_jmp_ins(const struct bf_matcher *matcher)
{
    bool continue_on_equal;

    assert(matcher);

    switch (bf_matcher_get_op(matcher)) {
    case BF_MATCHER_EQ:
    case BF_MATCHER_ALL:
        continue_on_equal = true;
        break;
    case BF_MATCHER_ANY:
    case BF_MATCHER_IN:
        continue_on_equal = false;
        break;
    default:
        bf_abort("invalid matcher op to get jmp instruction %d",
                 bf_matcher_get_op(matcher));
    }

    continue_on_equal ^= bf_matcher_get_negate(matcher);

    return continue_on_equal ? BPF_JNE : BPF_JEQ;
}

#define _BF_MASK_LAST_BYTE 15

static inline uint64_t _bf_read_u64(const void *ptr)
{
    uint64_t val;

    memcpy(&val, ptr, sizeof(val));

    return val;
}

/**
 * @brief Emit a 4-instruction sequence to build a 64-bit immediate from 8 bytes.
 *
 * Produces:
 * @code
 * MOV32_IMM(dst, high32) -> LSH(dst, 32) -> MOV32_IMM(scratch, low32) -> OR(dst, scratch)
 * @endcode
 *
 * @param program Program to emit into. Can't be NULL.
 * @param dst_reg Destination register for the 64-bit value.
 * @param scratch_reg Scratch register (clobbered).
 * @param data 64-bit value to load.
 */
static int _bf_cmp_build_imm64(struct bf_codegen *program, int dst_reg,
                               int scratch_reg, uint64_t data)
{
    EMIT(program, BPF_MOV32_IMM(dst_reg, (uint32_t)(data >> 32)));
    EMIT(program, BPF_ALU64_IMM(BPF_LSH, dst_reg, 32));
    EMIT(program, BPF_MOV32_IMM(scratch_reg, (uint32_t)data));
    EMIT(program, BPF_ALU64_REG(BPF_OR, dst_reg, scratch_reg));

    return 0;
}

/**
 * @brief Compute a network prefix mask.
 *
 * @param prefixlen Prefix length in bits.
 * @param mask Output buffer. Can't be NULL.
 * @param mask_len Size of mask buffer in bytes (4 or 16).
 */
static void _bf_prefix_to_mask(unsigned int prefixlen, uint8_t *mask,
                               size_t mask_len)
{
    assert(mask);

    memset(mask, 0x00, mask_len);
    memset(mask, 0xff, prefixlen / 8);
    if (prefixlen % 8)
        mask[prefixlen / 8] = (0xff << (8 - (prefixlen % 8))) & 0xff;
}

int bf_cmp_value(struct bf_codegen *program, const struct bf_matcher *matcher,
                 const void *ref, unsigned int size, int reg)
{
    enum bf_matcher_op op = bf_matcher_get_op(matcher);
    uint8_t jmp_op;

    assert(program);
    assert(matcher);
    assert(ref);

    if (op != BF_MATCHER_EQ)
        return bf_err_r(-EINVAL, "unsupported operator %d", op);

    jmp_op = bf_cmp_get_jmp_ins(matcher);

    switch (size) {
    case 1:
    case 2: {
        /* Small values: compare directly via JMP_IMM.
         * For size 1, ref is uint8_t; for size 2, ref is uint16_t.
         * Both fit in a signed 32-bit immediate. */
        uint32_t val =
            (size == 1) ? *(const uint8_t *)ref : *(const uint16_t *)ref;

        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(jmp_op, reg, val, 0));
        break;
    }
    case 4: {
        /* 32-bit values: may exceed signed 32-bit immediate range, so
         * use MOV32_IMM into R2 + JMP_REG. */
        uint32_t val = *(const uint32_t *)ref;

        EMIT(program, BPF_MOV32_IMM(BPF_REG_2, val));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(jmp_op, reg, BPF_REG_2, 0));
        break;
    }
    case 8: {
        /* 64-bit values: build immediate in R2 via `_bf_cmp_build_imm64`,
         * then compare with `JMP_REG`. */
        int r;

        r = _bf_cmp_build_imm64(program, BPF_REG_2, BPF_REG_3,
                                _bf_read_u64(ref));
        if (r)
            return r;
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(jmp_op, reg, BPF_REG_2, 0));
        break;
    }
    case 16: {
        /* 128-bit values: reg holds low 64 bits, reg+1 holds high 64 bits.
         * Compare each half against the reference. */
        const uint8_t *addr = ref;
        int r;

        r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                _bf_read_u64(addr));
        if (r)
            return r;

        if (jmp_op == BPF_JNE) {
            EMIT_FIXUP_JMP_NEXT_RULE(program,
                                     BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                    _bf_read_u64(addr + 8));
            if (r)
                return r;
            EMIT_FIXUP_JMP_NEXT_RULE(
                program, BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));
        } else {
            /* JEQ: the address must differ in at least one half.
             * If the first half differs, the matcher matched — jump
             * past the second half check and the unconditional
             * jump-to-next-rule. If the first half matches, check the
             * second half: if it also matches, the full address is
             * equal, so the matcher fails — jump to next rule. */
            _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_default();
            _clean_bf_jmpctx_ struct bf_jmpctx j1 = bf_jmpctx_default();

            j0 =
                bf_jmpctx_get(program, BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                    _bf_read_u64(addr + 8));
            if (r)
                return r;
            j1 = bf_jmpctx_get(program,
                               BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));

            EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));
        }
        break;
    }
    default:
        return bf_err_r(-EINVAL, "unsupported comparison size %u", size);
    }

    return 0;
}

int bf_cmp_masked_value(struct bf_codegen *program,
                        const struct bf_matcher *matcher, const void *ref,
                        unsigned int prefixlen, unsigned int size, int reg)
{
    enum bf_matcher_op op = bf_matcher_get_op(matcher);
    uint8_t jmp_op;

    assert(program);
    assert(matcher);
    assert(ref);

    if (op != BF_MATCHER_EQ)
        return bf_err_r(-EINVAL, "unsupported operator %d", op);

    jmp_op = bf_cmp_get_jmp_ins(matcher);

    switch (size) {
    case 4: {
        uint32_t mask;
        const uint32_t *addr = ref;

        _bf_prefix_to_mask(prefixlen, (uint8_t *)&mask, 4);

        EMIT(program, BPF_MOV32_IMM(BPF_REG_2, *addr));

        if (mask != ~0U) {
            EMIT(program, BPF_MOV32_IMM(BPF_REG_3, mask));
            EMIT(program, BPF_ALU32_REG(BPF_AND, reg, BPF_REG_3));
            EMIT(program, BPF_ALU32_REG(BPF_AND, BPF_REG_2, BPF_REG_3));
        }

        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(jmp_op, reg, BPF_REG_2, 0));
        break;
    }
    case 16: {
        uint8_t mask[16];
        uint8_t masked_lo[8], masked_hi[8];
        const uint8_t *addr = ref;
        int r;

        _bf_prefix_to_mask(prefixlen, mask, 16);

        // Apply mask to loaded reg/reg+1 if not a full /128
        if (mask[_BF_MASK_LAST_BYTE] != (uint8_t)~0) {
            r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                    _bf_read_u64(mask));
            if (r)
                return r;
            EMIT(program, BPF_ALU64_REG(BPF_AND, reg, BPF_REG_3));

            r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                    _bf_read_u64(mask + 8));
            if (r)
                return r;
            EMIT(program, BPF_ALU64_REG(BPF_AND, reg + 1, BPF_REG_3));
        }

        for (int i = 0; i < 8; i++)
            masked_lo[i] = addr[i] & mask[i];
        for (int i = 0; i < 8; i++)
            masked_hi[i] = addr[i + 8] & mask[i + 8];

        r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                _bf_read_u64(masked_lo));
        if (r)
            return r;

        if (jmp_op == BPF_JNE) {
            EMIT_FIXUP_JMP_NEXT_RULE(program,
                                     BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                    _bf_read_u64(masked_hi));
            if (r)
                return r;
            EMIT_FIXUP_JMP_NEXT_RULE(
                program, BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));
        } else {
            _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_default();
            _clean_bf_jmpctx_ struct bf_jmpctx j1 = bf_jmpctx_default();

            j0 =
                bf_jmpctx_get(program, BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            r = _bf_cmp_build_imm64(program, BPF_REG_3, BPF_REG_4,
                                    _bf_read_u64(masked_hi));
            if (r)
                return r;
            j1 = bf_jmpctx_get(program,
                               BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));

            EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));
        }
        break;
    }
    default:
        return bf_err_r(-EINVAL, "unsupported masked comparison size %u", size);
    }

    return 0;
}

int bf_cmp_range(struct bf_codegen *program, const struct bf_matcher *matcher,
                 uint32_t min, uint32_t max, int reg)
{
    assert(program);
    assert(matcher);

    if (bf_matcher_get_negate(matcher)) {
        _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_default();
        _clean_bf_jmpctx_ struct bf_jmpctx j1 = bf_jmpctx_default();

        j0 = bf_jmpctx_get(program, BPF_JMP32_IMM(BPF_JLT, reg, min, 0));
        j1 = bf_jmpctx_get(program, BPF_JMP32_IMM(BPF_JGT, reg, max, 0));
        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

        return 0;
    }

    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP32_IMM(BPF_JLT, reg, min, 0));
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP32_IMM(BPF_JGT, reg, max, 0));

    return 0;
}

int bf_cmp_bitfield(struct bf_codegen *program,
                    const struct bf_matcher *matcher, uint32_t flags, int reg)
{
    enum bf_matcher_op op = bf_matcher_get_op(matcher);

    assert(program);
    assert(matcher);

    if (op != BF_MATCHER_ANY && op != BF_MATCHER_ALL)
        return bf_err_r(-EINVAL, "unsupported operator %d", op);

    EMIT(program, BPF_ALU32_IMM(BPF_AND, reg, flags));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP32_IMM(bf_cmp_get_jmp_ins(matcher), reg,
                               op == BF_MATCHER_ANY ? 0 : flags, 0));

    return 0;
}
