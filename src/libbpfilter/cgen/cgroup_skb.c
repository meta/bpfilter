/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgroup_skb.h"

#include <linux/bpf_common.h>
#include <linux/if_ether.h>

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
#include "linux/bpf.h"

static int _bf_cgroup_skb_gen_inline_prologue(struct bf_codegen *program)
{
    int offset;
    int r;

    assert(program);

    // Copy the packet size (+ETH_HLEN) into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct __sk_buff, len)));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, ETH_HLEN));
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

    /* BPF_PROG_TYPE_CGROUP_SKB doesn't provide access to the Ethernet header,
     * so we can't parse it and discover the L3 protocol ID.
     * Instead, we use __sk_buff.protocol: the packet's ethertype, in network
     * byte order, as in the Ethernet header. Don't use __sk_buff.family: it is
     * the socket's family, and an AF_INET6 socket can send and receive IPv4
     * packets. */
    if ((offset = bf_btf_get_field_off("__sk_buff", "protocol")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offset));

    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_CTX_OFF(l2_hdr), 0));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset), 0));

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

static int _bf_cgroup_skb_gen_inline_epilogue(struct bf_codegen *program)
{
    (void)program;

    return 0;
}

static int _bf_cgroup_skb_gen_inline_set_mark(struct bf_codegen *program,
                                              uint32_t mark)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, mark));
    EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2,
                              offsetof(struct __sk_buff, mark)));

    return 0;
}

static int _bf_cgroup_skb_gen_inline_matcher(struct bf_codegen *program,
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
    default:
        return bf_packet_gen_inline_matcher(program, matcher);
    }
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @param ret_code Cgroup return code. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgroup_skb_get_verdict(enum bf_verdict verdict, int *ret_code)
{
    assert(ret_code);

    switch (verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_NEXT:
        *ret_code = 1;
        return 0;
    case BF_VERDICT_DROP:
        *ret_code = 0;
        return 0;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_cgroup_skb = {
    .gen_inline_prologue = _bf_cgroup_skb_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_skb_gen_inline_epilogue,
    .gen_inline_set_mark = _bf_cgroup_skb_gen_inline_set_mark,
    .get_verdict = _bf_cgroup_skb_get_verdict,
    .gen_inline_matcher = _bf_cgroup_skb_gen_inline_matcher,
    .gen_inline_log = bf_packet_gen_inline_log,
};
