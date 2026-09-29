/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/meta.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h> // NOLINT

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/elfstub.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "bpfilter/core/list.h"
#include "bpfilter/limit.h"
#include "cgen/jmp.h"
#include "cgen/matcher/cmp.h"
#include "cgen/program.h"
#include "cgen/runtime.h"
#include "filter.h"

/** @todo Add support for input and output interface filtering based on the
 * program's hook. */
static int _bf_matcher_generate_meta_iface(struct bf_program *program,
                                           const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(ifindex)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(bf_cmp_get_jmp_ins(matcher), BPF_REG_1,
                             *(uint32_t *)bf_matcher_payload(matcher), 0));

    return 0;
}

static int
_bf_matcher_generate_meta_probability(struct bf_program *program,
                                      const struct bf_matcher *matcher)
{
    float proba = *(float *)bf_matcher_payload(matcher);
    uint32_t threshold = (uint32_t)((double)UINT32_MAX * (proba / 100.0));

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32));

    /* Compare with a 32-bit jump: struct bpf_insn.imm is signed, and the
     * 64-bit BPF_JMP class sign-extends it before the comparison. Any
     * threshold above INT32_MAX (every probability above 50%) would then
     * compare r0 against 0xffffffff80000000 or more and never jump, so the
     * rule would match 100% of the packets (and 0% when negated). BPF_JMP32
     * compares the low 32 bits unsigned, which is what bpf_get_prandom_u32()
     * returns. Same approach as meta.flow_probability below. */
    if (bf_matcher_get_negate(matcher)) {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP32_IMM(BPF_JLE, BPF_REG_0, threshold, 0));
    } else {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP32_IMM(BPF_JGT, BPF_REG_0, threshold, 0));
    }

    return 0;
}

static int
_bf_matcher_generate_meta_flow_probability(struct bf_program *program,
                                           const struct bf_matcher *matcher)
{
    float proba = *(float *)bf_matcher_payload(matcher);
    uint32_t threshold = (uint32_t)((double)UINT32_MAX * (proba / 100.0));

    // Ensure L3 is IPv4 or IPv6, skip to next rule otherwise
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 2));
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 1));
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

    // Ensure L4 is TCP or UDP, skip to next rule otherwise
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 2));
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 1));
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

    /* Calculate flow hash using the bf_flow_hash elfstub.
     *
     * The elfstub computes a 32-bit hash from the packet's 5-tuple
     * (src ip, dst ip, src port, dst port, protocol) plus IPv6 flow label.
     * This ensures all packets in a flow get the same hash value, making
     * the probability decision consistent per-flow rather than per-packet.
     *
     * Arguments:
     * - r1: pointer to bf_runtime context
     * - r2: L3 protocol ID (from r7, set by prologue)
     * - r3: L4 protocol ID (from r8, set by prologue)
     *
     * Return: hash value in r0 */
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                -(int)sizeof(struct bf_runtime))); // r1 = ctx
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7)); // r2 = l3_proto
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_8)); // r3 = l4_proto

    // Call the elfstub - result in r0
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_FLOW_HASH);

    /* Compare the computed hash with the threshold based on probability.
     * The hash is uniformly distributed across 32 bits, so we compare against
     * UINT32_MAX * (proba / 100.0) to select the desired percentage of flows. */
    if (bf_matcher_get_negate(matcher)) {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP32_IMM(BPF_JLE, BPF_REG_0, threshold, 0));
    } else {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP32_IMM(BPF_JGT, BPF_REG_0, threshold, 0));
    }

    return 0;
}

static int _bf_matcher_generate_meta_limit(struct bf_program *program,
                                           const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    uint32_t key = *(uint64_t *)bf_matcher_payload(matcher);
    struct bf_ratelimit *node =
        bf_list_get_at(&program->runtime.chain->limits, key);

    uint32_t limit = node->limit;
    uint32_t duration = node->duration;

    EMIT_LOAD_LIMIT_FD_FIXUP(program, BPF_REG_1);
    EMIT(program, BPF_MOV32_IMM(BPF_REG_2, limit));
    EMIT(program, BPF_MOV32_IMM(BPF_REG_3, duration));
    EMIT(program, BPF_MOV32_IMM(BPF_REG_4, key));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_LIMIT);

    if (bf_matcher_get_negate(matcher)) {
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 0, 0));
    } else {
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 0, 0));
    }

    return 0;
}

int bf_matcher_generate_meta(struct bf_program *program,
                             const struct bf_matcher *matcher)
{
    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_IFACE:
        return _bf_matcher_generate_meta_iface(program, matcher);
    case BF_MATCHER_META_L3_PROTO: {
        uint16_t be_val = htobe16(*(uint16_t *)bf_matcher_payload(matcher));
        return bf_cmp_value(program, matcher, &be_val, 2, BPF_REG_7);
    }
    case BF_MATCHER_META_L4_PROTO:
        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 1,
                            BPF_REG_8);
    case BF_MATCHER_META_PROBABILITY:
        return _bf_matcher_generate_meta_probability(program, matcher);
    case BF_MATCHER_META_FLOW_PROBABILITY:
        return _bf_matcher_generate_meta_flow_probability(program, matcher);
    case BF_MATCHER_META_LIMIT:
        return _bf_matcher_generate_meta_limit(program, matcher);
    case BF_MATCHER_META_PID:
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
    case BF_MATCHER_META_MARK:
    case BF_MATCHER_META_FLOW_HASH:
        return bf_err_r(-ENOTSUP,
                        "matcher '%s' requires flavor-specific dispatch",
                        bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    }
}
