/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/xdp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/elfstub.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/verdict.h>

#include "cgen/codegen.h"
#include "cgen/jmp.h"
#include "cgen/packet.h"
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
static int _bf_xdp_gen_inline_prologue(struct bf_codegen *program)
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

static int _bf_xdp_gen_inline_epilogue(struct bf_codegen *program)
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
static int _bf_xdp_gen_inline_redirect(struct bf_codegen *program,
                                       uint32_t ifindex,
                                       enum bf_redirect_dir dir)
{
    assert(program);

    if (dir != BF_REDIRECT_EGRESS)
        return bf_err_r(-ENOTSUP, "XDP redirect only supports 'out' direction");

    // bpf_redirect(ifindex, flags) - flags are ignored for XDP
    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, ifindex));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_redirect));

    // Return value from bpf_redirect() is the action (XDP_REDIRECT on success)
    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

/**
 * ICMP type and code of the reply sent for each reject type.
 */
static const struct
{
    uint8_t icmp_type;
    uint8_t icmp_code;
} _bf_xdp_reject_replies[] = {
    [BF_REJECT_PORT_UNREACH] = {ICMP_DEST_UNREACH, ICMP_PORT_UNREACH},
};
static_assert_enum_mapping(_bf_xdp_reject_replies, _BF_REJECT_TYPE_MAX);

/**
 * @brief Generate bytecode to reply to the packets of a given L3 protocol.
 *
 * If the packet's L3 protocol is @p l3_proto , call the ELF stub @p stub to
 * replace the packet with the reply, and return the stub's verdict.
 *
 * @param program Program to generate bytecode for. Can't be NULL.
 * @param l3_proto L3 protocol ID, in host byte order.
 * @param stub ELF stub building the reply. It takes the runtime context, the
 *        reply's type, and code as arguments, and returns an XDP verdict.
 * @param type Type of the reply, specific to the reply's protocol.
 * @param code Code of the reply, specific to the reply's protocol.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_xdp_gen_inline_reject_reply(struct bf_codegen *program,
                                           uint16_t l3_proto,
                                           enum bf_elfstub_id stub,
                                           uint8_t type, uint8_t code)
{
    // The L3 protocol ID is stored in r7
    _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(l3_proto), 0));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, type));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_3, code));
    EMIT_FIXUP_ELFSTUB(program, stub);
    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

/**
 * @brief Generate bytecode to reject a packet using XDP.
 *
 * The reply is built in place of the original packet by an ELF stub, then
 * sent back through the ingress interface with `XDP_TX`. Packets the stub
 * can't reply to are dropped, as well as the non-IPv4 packets.
 *
 * @param program Program to generate bytecode for. Can't be NULL.
 * @param type Reply to send.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_xdp_gen_inline_reject(struct bf_codegen *program,
                                     enum bf_reject_type type)
{
    int r;

    assert(program);

    if ((unsigned int)type >= _BF_REJECT_TYPE_MAX)
        return bf_err_r(-EINVAL, "unknown reject type %d", type);

    r = _bf_xdp_gen_inline_reject_reply(program, ETH_P_IP,
                                        BF_ELFSTUB_XDP_REJECT_ICMP,
                                        _bf_xdp_reject_replies[type].icmp_type,
                                        _bf_xdp_reject_replies[type].icmp_code);
    if (r)
        return r;

    EMIT(program, BPF_MOV64_IMM(BPF_REG_0, XDP_DROP));
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
    .gen_inline_reject = _bf_xdp_gen_inline_reject,
    .get_verdict = _bf_xdp_get_verdict,
    .gen_inline_matcher = bf_packet_gen_inline_matcher,
    .gen_inline_log = bf_packet_gen_inline_log,
};
