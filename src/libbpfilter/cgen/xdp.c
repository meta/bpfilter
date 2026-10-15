/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/xdp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/verdict.h>

#include "cgen/packet.h"
#include "cgen/program.h"
#include "cgen/stub.h"
#include "filter.h"

/**
 * Generate XDP program prologue.
 *
 * @warning @ref bf_stub_parse_l2_ethhdr will check for L3 protocol. If L3 is
 * not IPv4, the program will be terminated.
 *
 * @param program Program to generate the prologue for. Must not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_xdp_gen_inline_prologue(struct bf_program *program)
{
    int r;

    assert(program);

    // Calculate the packet size and store it into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, data)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct xdp_md, data_end)));
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_3, BPF_REG_2));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    // Store the ingress ifindex into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, ingress_ifindex)));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(ifindex)));

    r = bf_stub_make_ctx_xdp_dynptr(program, BPF_REG_1);
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

static int _bf_xdp_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

/**
 * @brief Generate bytecode to redirect a packet using XDP.
 *
 * XDP redirect only supports egress direction - the packet is always
 * transmitted out of the target interface. The BPF_F_INGRESS flag is
 * ignored by XDP's bpf_redirect().
 *
 * @param program Program to generate bytecode for. Can't be NULL.
 * @param ifindex Target interface index.
 * @param dir Direction (must be BF_REDIRECT_EGRESS for XDP).
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_xdp_gen_inline_redirect(struct bf_program *program,
                                       uint32_t ifindex,
                                       enum bf_redirect_dir dir)
{
    assert(program);

    (void)dir;

    // bpf_redirect(ifindex, flags) - flags are ignored for XDP
    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, ifindex));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_redirect));

    // Return value from bpf_redirect() is the action (XDP_REDIRECT on success)
    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @param ret_code XDP return code. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_xdp_get_verdict(enum bf_verdict verdict, int *ret_code)
{
    assert(ret_code);

    switch (verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_NEXT:
        *ret_code = XDP_PASS;
        return 0;
    case BF_VERDICT_DROP:
        *ret_code = XDP_DROP;
        return 0;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_xdp = {
    .gen_inline_prologue = _bf_xdp_gen_inline_prologue,
    .gen_inline_epilogue = _bf_xdp_gen_inline_epilogue,
    .gen_inline_redirect = _bf_xdp_gen_inline_redirect,
    .get_verdict = _bf_xdp_get_verdict,
    .gen_inline_matcher = bf_packet_gen_inline_matcher,
    .gen_inline_log = bf_packet_gen_inline_log,
};
