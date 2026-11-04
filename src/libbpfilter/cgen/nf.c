/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/nf.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <bpfilter/btf.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/verdict.h>

#include "cgen/jmp.h"
#include "cgen/matcher/cmp.h"
#include "cgen/packet.h"
#include "cgen/program.h"
#include "cgen/stub.h"
#include "cgen/swich.h"
#include "filter.h"

#define BF_NF_PRIO_EVEN 2
#define BF_NF_PRIO_ODD 1

// Forward definition to avoid headers clusterfuck.
uint16_t htons(uint16_t hostshort);

static inline bool _bf_nf_hook_is_ingress(enum bf_hook hook)
{
    return hook == BF_HOOK_NF_PRE_ROUTING || hook == BF_HOOK_NF_LOCAL_IN ||
           hook == BF_HOOK_NF_FORWARD;
}

static int _bf_nf_gen_inline_prologue(struct bf_program *program)
{
    int r;
    int offset;

    assert(program);

    // Copy the ifindex from to bpf_nf_ctx.state.{in,out}.ifindex the runtime context
    if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "state")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, offset));
    if (_bf_nf_hook_is_ingress(program->runtime.chain->hook)) {
        if ((offset = bf_btf_get_field_off("nf_hook_state", "in")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, offset));
    } else {
        if ((offset = bf_btf_get_field_off("nf_hook_state", "out")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, offset));
    }

    if ((offset = bf_btf_get_field_off("net_device", "ifindex")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_3, offset));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, BF_PROG_CTX_OFF(ifindex)));

    /* BPF_PROG_TYPE_NETFILTER doesn't provide access to the Ethernet header,
     * so we can't parse it and discover the L3 protocol ID.
     * Instead, we use the nf_hook_state.pf value and convert it to the
     * corresponding ethertype. */
    if ((offset = bf_btf_get_field_off("nf_hook_state", "pf")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_2, offset));

    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_3);

        EMIT_SWICH_OPTION(&swich, AF_INET,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IP)));
        EMIT_SWICH_OPTION(&swich, AF_INET6,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IPV6)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_CTX_OFF(l2_hdr), 0));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset), 0));

    // Calculate the packet size (+ETH_HLEN) and store it into the runtime context
    if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "skb")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, offset));
    if ((offset = bf_btf_get_field_off("sk_buff", "len")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, ETH_HLEN));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(pkt_size)));

    r = bf_stub_make_ctx_skb_dynptr(program, BPF_REG_1);
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

static int _bf_nf_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

static int _bf_nf_gen_inline_matcher(struct bf_program *program,
                                     const struct bf_matcher *matcher)
{
    int offset;

    assert(program);
    assert(matcher);

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_MARK:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
        if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "skb")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, offset));
        if ((offset = bf_btf_get_field_off("sk_buff", "mark")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offset));

        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 4,
                            BPF_REG_1);
    default:
        return bf_packet_gen_inline_matcher(program, matcher);
    }
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @param ret_code Netfilter return code. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_nf_get_verdict(enum bf_verdict verdict, int *ret_code)
{
    assert(ret_code);

    switch (verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_NEXT:
        *ret_code = NF_ACCEPT;
        return 0;
    case BF_VERDICT_DROP:
        *ret_code = NF_DROP;
        return 0;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_nf = {
    .gen_inline_prologue = _bf_nf_gen_inline_prologue,
    .gen_inline_epilogue = _bf_nf_gen_inline_epilogue,
    .get_verdict = _bf_nf_get_verdict,
    .gen_inline_matcher = _bf_nf_gen_inline_matcher,
    .gen_inline_log = bf_packet_gen_inline_log,
};
