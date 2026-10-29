/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

struct bf_matcher;
struct bf_codegen;

/**
 * @brief Get the BPF jump opcode for a matcher, accounting for negation.
 *
 * Returns the BPF opcode to use in a jump-to-next-rule instruction. The
 * returned opcode encodes the "skip if not matching" semantics, with the
 * matcher's `bf_matcher_op` and negation flag already folded in.
 *
 * Not valid for `BF_MATCHER_RANGE`, which requires two separate jump
 * instructions with different opcodes.
 *
 * @param matcher Matcher to query. Can't be NULL.
 * @return BPF jump opcode (e.g. `BPF_JNE` or `BPF_JEQ`).
 */
uint8_t bf_cmp_get_jmp_ins(const struct bf_matcher *matcher);

/**
 * @brief Compare the value in `reg` against a reference value.
 *
 * Only valid for `BF_MATCHER_EQ` operator (use `negate` flag for
 * inequality).
 *
 * For size 16, the value spans `reg` (low 64 bits) and `reg + 1`
 * (high 64 bits). Clobbers `BPF_REG_2` for size 4/8 and
 * `BPF_REG_3`/`BPF_REG_4` for size 16.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param matcher Matcher to query for op and negation. Can't be NULL.
 * @param ref Pointer to reference value. Can't be NULL.
 * @param size Comparison width in bytes: 1, 2, 4, 8, or 16.
 * @param reg BPF register holding the value to compare.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_value(struct bf_codegen *program, const struct bf_matcher *matcher,
                 const void *ref, unsigned int size, int reg);

/**
 * @brief Mask the value in `reg` by `prefixlen`, then compare.
 *
 * Only valid for `BF_MATCHER_EQ` operator (use `negate` flag for
 * inequality).
 *
 * For size 16, the value spans `reg` and `reg + 1`. Modifies `reg`
 * (and `reg + 1`) in-place. Clobbers `BPF_REG_2`/`BPF_REG_3` for
 * size 4 and `BPF_REG_3`/`BPF_REG_4` for size 16.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param matcher Matcher to query for op and negation. Can't be NULL.
 * @param ref Pointer to unmasked reference value. Can't be NULL.
 * @param prefixlen Prefix length in bits (1-32 for size 4, 1-128 for size 16).
 * @param size Comparison width in bytes: 4 or 16.
 * @param reg BPF register holding the value to compare.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_masked_value(struct bf_codegen *program,
                        const struct bf_matcher *matcher, const void *ref,
                        unsigned int prefixlen, unsigned int size, int reg);

/**
 * @brief Check `min <= reg <= max`, for values up to 32 bits.
 *
 * Only valid for `BF_MATCHER_RANGE` operator. If the matcher's
 * negation flag is set, matches when the value is outside the range.
 *
 * All values must be in host byte order; the caller is responsible for
 * any conversion (e.g., `BSWAP` for network-order port values).
 *
 * @param program Program to emit into. Can't be NULL.
 * @param matcher Matcher to query for negation. Can't be NULL.
 * @param min Minimum value.
 * @param max Maximum value.
 * @param reg BPF register holding the value to compare.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_range(struct bf_codegen *program, const struct bf_matcher *matcher,
                 uint32_t min, uint32_t max, int reg);

/**
 * @brief Check `reg` against a bitmask, for values up to 32 bits.
 *
 * Only valid for `BF_MATCHER_ANY` and `BF_MATCHER_ALL` operators.
 *
 * ANY: `(reg & flags) != 0`
 * ALL: `(reg & flags) == flags`
 *
 * @param program Program to emit into. Can't be NULL.
 * @param matcher Matcher to query for op and negation. Can't be NULL.
 * @param flags Bitmask to check against.
 * @param reg BPF register holding the value to check.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_bitfield(struct bf_codegen *program,
                    const struct bf_matcher *matcher, uint32_t flags, int reg);
