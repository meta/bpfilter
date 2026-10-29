/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/tc.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/pkt_cls.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/btf.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/matcher.h>
#include <bpfilter/verdict.h>

#include "cgen/codegen.h"
#include "cgen/matcher/cmp.h"
#include "cgen/packet.h"
#include "cgen/stub.h"
#include "filter.h"

static int _bf_tc_gen_inline_prologue(struct bf_codegen *program)
{
    int r;

    assert(program);

    // Copy the packet size into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct __sk_buff, len)));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    /** The @c __sk_buff structure contains two fields related to the interface
     * index: @c ingress_ifindex and @c ifindex . @c ingress_ifindex is the
     * interface index the packet has been received on. However, we use
     * @c ifindex which is the interface index the packet is processed by: if
     * a packet is redirected locally from interface #1 to interface #2, then
     * @c ingress_ifindex will contain @c 1 but @c ifindex will contains @c 2 .
     * For egress, only @c ifindex is used.
     */
    if ((r = bf_btf_get_field_off("__sk_buff", "ifindex")) < 0)
        return r;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, r));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(ifindex)));

    r = bf_stub_make_ctx_skb_dynptr(program, BPF_REG_1);
    if (r)
        return r;

    r = bf_stub_parse_l2_ethhdr(program);
    if (r)
        return r;

    r = bf_stub_parse_l3_hdr(program);
    if (r)
        return r;

    r = bf_stub_parse_l4_hdr(program);
    if (r)
        return r;

    return 0;
}

static int _bf_tc_gen_inline_epilogue(struct bf_codegen *program)
{
    (void)program;

    return 0;
}

static int _bf_tc_gen_inline_set_mark(struct bf_codegen *program, uint32_t mark)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, mark));
    EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2,
                              offsetof(struct __sk_buff, mark)));

    return 0;
}

static int _bf_tc_gen_inline_matcher(struct bf_codegen *program,
                                     const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_MARK:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
                                  offsetof(struct __sk_buff, mark)));

        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 4,
                            BPF_REG_1);
    case BF_MATCHER_META_FLOW_HASH:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_get_hash_recalc));

        if (bf_matcher_get_op(matcher) == BF_MATCHER_RANGE) {
            uint32_t *hash = (uint32_t *)bf_matcher_payload(matcher);
            return bf_cmp_range(program, matcher, hash[0], hash[1], BPF_REG_0);
        }

        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 4,
                            BPF_REG_0);
    default:
        return bf_packet_gen_inline_matcher(program, matcher);
    }
}

/**
 * @brief Generate bytecode to redirect a packet using TC.
 *
 * TC redirect supports both ingress and egress directions via the
 * BPF_F_INGRESS flag passed to bpf_redirect().
 *
 * @param program Program to generate bytecode for. Can't be NULL.
 * @param ifindex Target interface index.
 * @param dir Direction: ingress or egress.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_tc_gen_inline_redirect(struct bf_codegen *program,
                                      uint32_t ifindex,
                                      enum bf_redirect_dir dir)
{
    uint64_t flags = dir == BF_REDIRECT_INGRESS ? BPF_F_INGRESS : 0;

    assert(program);

    // bpf_redirect(ifindex, flags)
    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, ifindex));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, flags));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_redirect));

    // Return value from bpf_redirect() is TC_ACT_REDIRECT on success
    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @param ret_code TC return code. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_tc_get_verdict(enum bf_verdict verdict, int *ret_code)
{
    assert(ret_code);

    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        *ret_code = TCX_PASS;
        return 0;
    case BF_VERDICT_DROP:
        *ret_code = TCX_DROP;
        return 0;
    case BF_VERDICT_NEXT:
        *ret_code = TCX_NEXT;
        return 0;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_tc = {
    .gen_inline_prologue = _bf_tc_gen_inline_prologue,
    .gen_inline_epilogue = _bf_tc_gen_inline_epilogue,
    .gen_inline_set_mark = _bf_tc_gen_inline_set_mark,
    .gen_inline_redirect = _bf_tc_gen_inline_redirect,
    .get_verdict = _bf_tc_get_verdict,
    .gen_inline_matcher = _bf_tc_gen_inline_matcher,
    .gen_inline_log = bf_packet_gen_inline_log,
};
