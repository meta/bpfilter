/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/stub.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h> // NOLINT
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <endian.h>
#include <stddef.h>

#include <bpfilter/ctx.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/matcher.h>
#include <bpfilter/verdict.h>

#include "cgen/codegen.h"
#include "cgen/jmp.h"
#include "cgen/printer.h"
#include "cgen/swich.h"
#include "filter.h"

#define _BF_LOW_EH_BITMASK 0x1801800000000801ULL

/**
 * Generate stub to create a dynptr.
 *
 * @param program Program to generate the stub for. Must not be NULL.
 * @param arg_reg Register where the first argument to the dynptr creation
 *        function is located (SKB or xdp_md structure).
 * @param kfunc Name of the kfunc to use to create the dynamic pointer.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_make_ctx_dynptr(struct bf_codegen *program, int arg_reg,
                                    const char *kfunc)
{
    int ret_code;
    int r;

    assert(program);
    assert(kfunc);

    // Call bpf_dynptr_from_xxx()
    if (arg_reg != BPF_REG_1)
        EMIT(program, BPF_MOV64_IMM(BPF_REG_1, arg_reg));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(dynptr)));
    EMIT_KFUNC_CALL(program, kfunc);

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

        // Update the error counter
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_codegen_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create a new dynamic pointer");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    return 0;
}

int bf_stub_make_ctx_xdp_dynptr(struct bf_codegen *program, int md_reg)
{
    assert(program);

    return _bf_stub_make_ctx_dynptr(program, md_reg, "bpf_dynptr_from_xdp");
}

int bf_stub_make_ctx_skb_dynptr(struct bf_codegen *program, int skb_reg)
{
    assert(program);

    return _bf_stub_make_ctx_dynptr(program, skb_reg, "bpf_dynptr_from_skb");
}

int bf_stub_parse_l2_ethhdr(struct bf_codegen *program)
{
    int ret_code;
    int r;

    assert(program);

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l2)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_4, sizeof(struct ethhdr)));

    EMIT(program,
         BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4, BF_PROG_CTX_OFF(l2_size)));

    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        // Update the error counter
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_codegen_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L2 dynamic pointer slice");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L2 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l2_hdr)));

    // Store the L3 protocol ID in r7
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0,
                              offsetof(struct ethhdr, h_proto)));

    // Set bf_runtime.l3_offset
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset),
                             sizeof(struct ethhdr)));

    return 0;
}

int bf_stub_parse_l3_hdr(struct bf_codegen *program)
{
    _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_default();
    int ret_code;
    int r;

    assert(program);

    /* Store the size of the L3 protocol header in r4, depending on the protocol
     * ID stored in r7. If the protocol is not supported, we store 0 into r7
     * and we skip the instructions below. */
    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_7);

        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IP),
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct iphdr)));
        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IPV6),
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct ipv6hdr)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    _ = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, 0, 0));

    EMIT(program,
         BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4, BF_PROG_CTX_OFF(l3_size)));

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l2)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_codegen_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L3 dynamic pointer slice");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L3 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l3_hdr)));

    /* Unsupported L3 protocols have been filtered out at the beginning of this
     * function and would jump over the block below, so there is no need to
     * worry about them here. */
    {
        // IPv4
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_0, 0));
        EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0f));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10,
                                  BF_PROG_CTX_OFF(l3_offset)));
        EMIT(program, BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2));
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                                  BF_PROG_CTX_OFF(l4_offset)));
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_0,
                                  offsetof(struct iphdr, protocol)));
    }

    {
        // IPv6
        struct bf_jmpctx tcpjmp, udpjmp, noehjmp, ehjmp;
        struct bpf_insn ld64[2] = {BPF_LD_IMM64(BPF_REG_2, _BF_LOW_EH_BITMASK)};
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IPV6), 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_0,
                                  offsetof(struct ipv6hdr, nexthdr)));

        /* Fast path for TCP and UDP: quickly recognize the most used protocol
         * to process them as fast as possible. */
        tcpjmp = bf_jmpctx_get(program,
                               BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 0));
        udpjmp = bf_jmpctx_get(program,
                               BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 0));

        /* For all the EH protocol numbers <64, use a bitmask:
         * mask = (1<<0) | (1<<43) | (1<<44) | (1<<50) | (1<<51) | (1<<60)
         *
         * Pseudo-code:
         * - r3 = 1 << r8 (nexthdr)
         * - r3 = r3 & mask
         * - if r3 != 0: go to slow path (EH present) */
        EMIT(program, ld64[0]);
        EMIT(program, ld64[1]);
        EMIT(program, BPF_JMP_IMM(BPF_JGE, BPF_REG_8, 64, 4));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, 1));
        EMIT(program, BPF_ALU64_REG(BPF_LSH, BPF_REG_3, BPF_REG_8));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BPF_REG_3, BPF_REG_2));
        EMIT(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 4));

        // EH with protocol numbers >64 are processed individually
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 135, 3));
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 139, 2));
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 140, 1));

        // If no EH matched, nexthdr is L4, skip EH processing
        noehjmp = bf_jmpctx_get(program, BPF_JMP_A(0));

        // Process EH
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        // If any rule filters on ipv6.nexthdr, store the EH in the runtime context
        // during process, so we won't have to process the EH again.
        if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR))
            EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_PARSE_IPV6_NH);
        else
            EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_PARSE_IPV6_EH);
        EMIT(program, BPF_MOV64_REG(BPF_REG_8, BPF_REG_0));

        ehjmp = bf_jmpctx_get(program, BPF_JMP_A(0));

        // If no EH found, all the jmp will end up here
        bf_jmpctx_cleanup(&tcpjmp);
        bf_jmpctx_cleanup(&udpjmp);
        bf_jmpctx_cleanup(&noehjmp);

        // Process IPv6 header, no EH (BPF_REG_8 already contains nexthdr)
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10,
                                  BF_PROG_CTX_OFF(l3_offset)));
        EMIT(program,
             BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, sizeof(struct ipv6hdr)));
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(l4_offset)));

        bf_jmpctx_cleanup(&ehjmp);
    }

    return 0;
}

int bf_stub_parse_l4_hdr(struct bf_codegen *program)
{
    _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_default();
    int r;

    assert(program);

    // r8 is set to 0 below if the L4 header can't be parsed
    EMIT(program,
         BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_8, BF_PROG_CTX_OFF(l4_proto)));

    /* Parse the L4 protocol and handle unuspported protocol, similarly to
     * bf_stub_parse_l3_hdr() above. */
    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_8);

        EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct tcphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_UDP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMPV6,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmp6hdr)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_8, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    _ = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));

    EMIT(program,
         BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4, BF_PROG_CTX_OFF(l4_size)));

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, BF_PROG_CTX_OFF(l4_offset)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l4)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    /* If the function call failed (e.g. the packet is too short), continue as
     * if the L4 protocol was not supported: the rules and the chain policy
     * still apply. */
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_codegen_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L4 dynamic pointer slice");

        /* No L4 protocol (r8 = 0) and no L4 header (r0 = NULL, the calls
         * above overwrote r0). */
        EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, 0));
    }

    // Store the L4 header address (NULL on failure) into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l4_hdr)));

    return 0;
}

int bf_stub_rule_check_protocol(struct bf_codegen *program,
                                const struct bf_matcher_meta *meta)
{
    assert(program);
    assert(meta);

    switch (meta->layer) {
    case BF_MATCHER_LAYER_3:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7,
                                 htobe16((uint16_t)meta->hdr_id), 0));
        break;
    case BF_MATCHER_LAYER_4:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8, (uint8_t)meta->hdr_id, 0));
        break;
    default:
        return bf_err_r(-EINVAL, "rule can't check for layer ID %d",
                        meta->layer);
    }

    return 0;
}

int bf_stub_load_header(struct bf_codegen *program,
                        const struct bf_matcher_meta *meta, int reg)
{
    assert(program);
    assert(meta);

    switch (meta->layer) {
    case BF_MATCHER_LAYER_3:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));
        break;
    case BF_MATCHER_LAYER_4:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));
        break;
    default:
        return bf_err_r(-EINVAL,
                        "layer ID %d is not a valid layer to load header for",
                        meta->layer);
    }

    return 0;
}

int bf_stub_load(struct bf_codegen *program, size_t src_offset, size_t size,
                 int dst_offset)
{
    size_t src_off = src_offset;
    int dst_off = dst_offset;
    size_t remaining_size = size;

    assert(program);

    while (remaining_size) {
        int bpf_size = BPF_B;
        size_t copy_bytes = 1;

        if (BF_ALIGNED_64(src_off) && BF_ALIGNED_64(dst_off) &&
            remaining_size >= 8) {
            bpf_size = BPF_DW;
            copy_bytes = 8;
        } else if (BF_ALIGNED_32(src_off) && BF_ALIGNED_32(dst_off) &&
                   remaining_size >= 4) {
            bpf_size = BPF_W;
            copy_bytes = 4;
        } else if (BF_ALIGNED_16(src_off) && BF_ALIGNED_16(dst_off) &&
                   remaining_size >= 2) {
            bpf_size = BPF_H;
            copy_bytes = 2;
        }

        EMIT(program, BPF_LDX_MEM(bpf_size, BPF_REG_1, BPF_REG_6, src_off));
        EMIT(program, BPF_STX_MEM(bpf_size, BPF_REG_10, BPF_REG_1, dst_off));

        remaining_size -= copy_bytes;
        src_off += copy_bytes;
        dst_off += (int)copy_bytes;
    }

    return 0;
}

int bf_stub_store(struct bf_codegen *program, int reg, size_t size,
                  int dst_offset)
{
    int dst_off = dst_offset;
    size_t remaining_size = size;

    assert(program);

    if (size > 8)
        return bf_err_r(-E2BIG, "bf_stub_store copies at most 8 bytes");

    while (remaining_size) {
        int bpf_size = BPF_B;
        size_t copy_bytes = 1;

        if (BF_ALIGNED_64(dst_off) && remaining_size >= 8) {
            bpf_size = BPF_DW;
            copy_bytes = 8;
        } else if (BF_ALIGNED_32(dst_off) && remaining_size >= 4) {
            bpf_size = BPF_W;
            copy_bytes = 4;
        } else if (BF_ALIGNED_16(dst_off) && remaining_size >= 2) {
            bpf_size = BPF_H;
            copy_bytes = 2;
        }

        EMIT(program, BPF_STX_MEM(bpf_size, BPF_REG_10, reg, dst_off));

        remaining_size -= copy_bytes;
        dst_off += (int)copy_bytes;

        if (remaining_size)
            EMIT(program, BPF_ALU64_IMM(BPF_RSH, reg, copy_bytes * 8));
    }

    return 0;
}

int bf_stub_stx_payload(struct bf_codegen *program,
                        const struct bf_matcher_meta *meta, size_t offset)
{
    assert(program);
    assert(meta);

    return bf_stub_load(program, meta->hdr_payload_offset,
                        meta->hdr_payload_size, BF_PROG_SCR_OFF(offset));
}
