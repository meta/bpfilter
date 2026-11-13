/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/packet.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h> // NOLINT
#include <linux/ipv6.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <bpfilter/chain.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>

#include "cgen/codegen.h"
#include "cgen/matcher/cmp.h"
#include "cgen/matcher/meta.h"
#include "cgen/matcher/set.h"
#include "cgen/runtime.h"
#include "cgen/stub.h"
#include "filter.h"

/**
 * Packet matcher codegen follows a three-stage pipeline:
 *
 * 1. Protocol check: `_bf_codegen_generate_rule()` (in codegen.c) emits
 *    deduplicated guards for protocol-specific matchers before the matcher
 *    loop, so each protocol-specific guard is emitted at most once per rule.
 *
 * 2. Header + field load: the header base address is loaded into `R6`, then
 *    `_bf_matcher_pkt_load_field()` reads the target field into the specified
 *    register (and `reg+1` for 128-bit values such as IPv6 addresses).
 *
 * 3. Comparison:  A `bf_cmp_*` function compares the value in the
 *    specified register against the matcher's reference payload.
 */

#define BF_IPV6_EH_HOPOPTS(x) ((x) << 0)
#define BF_IPV6_EH_ROUTING(x) ((x) << 1)
#define BF_IPV6_EH_FRAGMENT(x) ((x) << 2)
#define BF_IPV6_EH_AH(x) ((x) << 3)
#define BF_IPV6_EH_DSTOPTS(x) ((x) << 4)
#define BF_IPV6_EH_MH(x) ((x) << 5)

/**
 * @brief Load a packet field from the header into the specified register.
 *
 * `R6` must already point to the header base. For 128-bit fields (IPv6
 * addresses), the low 8 bytes are loaded into `reg` and the high 8 bytes into
 * `reg + 1`.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param meta Matcher metadata describing field offset and size. Can't be NULL.
 * @param reg BPF register to load the value into.
 * @return 0 on success, negative errno on error.
 */
static int _bf_matcher_pkt_load_field(struct bf_codegen *program,
                                      const struct bf_matcher_meta *meta,
                                      int reg)
{
    switch (meta->hdr_payload_size) {
    case 1:
        EMIT(program,
             BPF_LDX_MEM(BPF_B, reg, BPF_REG_6, meta->hdr_payload_offset));
        break;
    case 2:
        EMIT(program,
             BPF_LDX_MEM(BPF_H, reg, BPF_REG_6, meta->hdr_payload_offset));
        break;
    case 4:
        EMIT(program,
             BPF_LDX_MEM(BPF_W, reg, BPF_REG_6, meta->hdr_payload_offset));
        break;
    case 8:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, BPF_REG_6, meta->hdr_payload_offset));
        break;
    case 16:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, BPF_REG_6, meta->hdr_payload_offset));
        EMIT(program, BPF_LDX_MEM(BPF_DW, reg + 1, BPF_REG_6,
                                  meta->hdr_payload_offset + 8));
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int _bf_matcher_pkt_prepare_header(struct bf_codegen *program,
                                          enum bf_matcher_type type,
                                          const struct bf_matcher_meta *meta)
{
    assert(program);
    assert(meta);

    switch (type) {
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 2));
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 1));
        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10,
                                  BF_PROG_CTX_OFF(l4_hdr)));
        return 0;
    default:
        return bf_stub_load_header(program, meta, BPF_REG_6);
    }
}

static int _bf_matcher_pkt_load(struct bf_codegen *program,
                                const struct bf_matcher_meta *meta, int reg)
{
    int r;

    r = bf_stub_load_header(program, meta, BPF_REG_6);
    if (r)
        return r;

    return _bf_matcher_pkt_load_field(program, meta, reg);
}

/**
 * @brief Generic load + value compare for matchers whose field size and offset
 * are fully described by `_bf_matcher_metas`.
 *
 * Emits: header load -> field load -> `bf_cmp_value`.
 *
 * @param program Program to generate bytecode into. Can't be NULL.
 * @param matcher Matcher to generate bytecode for. Can't be NULL.
 * @param meta Matcher metadata describing field size and offset. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
static int _bf_matcher_pkt_load_and_cmp(struct bf_codegen *program,
                                        const struct bf_matcher *matcher,
                                        const struct bf_matcher_meta *meta)
{
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    return bf_cmp_value(program, matcher, bf_matcher_payload(matcher),
                        meta->hdr_payload_size, BPF_REG_1);
}

static int _bf_matcher_pkt_generate_net(struct bf_codegen *program,
                                        const struct bf_matcher *matcher,
                                        const struct bf_matcher_meta *meta)
{
    const uint32_t prefixlen = *(const uint32_t *)bf_matcher_payload(matcher);
    const void *data =
        (const uint8_t *)bf_matcher_payload(matcher) + sizeof(uint32_t);
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    return bf_cmp_masked_value(program, matcher, data, prefixlen,
                               meta->hdr_payload_size, BPF_REG_1);
}

static int _bf_matcher_pkt_generate_port(struct bf_codegen *program,
                                         const struct bf_matcher *matcher,
                                         const struct bf_matcher_meta *meta)
{
    int r;

    r = _bf_matcher_pkt_prepare_header(program, bf_matcher_get_type(matcher),
                                       meta);
    if (r)
        return r;

    r = _bf_matcher_pkt_load_field(program, meta, BPF_REG_1);
    if (r)
        return r;

    if (bf_matcher_get_op(matcher) == BF_MATCHER_RANGE) {
        uint16_t *ports = (uint16_t *)bf_matcher_payload(matcher);
        /* Convert the big-endian value stored in the packet into a
         * little-endian value for x86 and arm before comparing it to the
         * reference value. This is a JLT/JGT comparison, we need to have the
         * MSB where the machine expects then. */
        EMIT(program, BPF_BSWAP(BPF_REG_1, 16));
        return bf_cmp_range(program, matcher, ports[0], ports[1], BPF_REG_1);
    }

    return bf_cmp_value(program, matcher, bf_matcher_payload(matcher),
                        meta->hdr_payload_size, BPF_REG_1);
}

static int
_bf_matcher_pkt_generate_tcp_flags(struct bf_codegen *program,
                                   const struct bf_matcher *matcher,
                                   const struct bf_matcher_meta *meta)
{
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    switch (bf_matcher_get_op(matcher)) {
    case BF_MATCHER_ANY:
    case BF_MATCHER_ALL:
        return bf_cmp_bitfield(program, matcher,
                               *(uint8_t *)bf_matcher_payload(matcher),
                               BPF_REG_1);
    case BF_MATCHER_EQ:
        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher),
                            meta->hdr_payload_size, BPF_REG_1);
    default:
        return bf_err_r(-EINVAL, "unsupported operator %d",
                        bf_matcher_get_op(matcher));
    }
}

static int _bf_matcher_pkt_generate_l4_proto(struct bf_program *program,
                                             const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(l4_proto)));

    return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 1,
                        BPF_REG_1);
}

static int
_bf_matcher_pkt_generate_ip6_nexthdr(struct bf_codegen *program,
                                     const struct bf_matcher *matcher)
{
    const uint8_t ehdr = *(uint8_t *)bf_matcher_payload(matcher);
    uint8_t eh_mask;
    uint8_t jmp_op;

    jmp_op = bf_cmp_get_jmp_ins(matcher);

    switch (ehdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
    case IPPROTO_FRAGMENT:
    case IPPROTO_AH:
    case IPPROTO_MH:
        eh_mask = (BF_IPV6_EH_HOPOPTS(ehdr == IPPROTO_HOPOPTS) |
                   BF_IPV6_EH_ROUTING(ehdr == IPPROTO_ROUTING) |
                   BF_IPV6_EH_FRAGMENT(ehdr == IPPROTO_FRAGMENT) |
                   BF_IPV6_EH_AH(ehdr == IPPROTO_AH) |
                   BF_IPV6_EH_DSTOPTS(ehdr == IPPROTO_DSTOPTS) |
                   BF_IPV6_EH_MH(ehdr == IPPROTO_MH));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10,
                                  BF_PROG_CTX_OFF(ipv6_eh)));
        EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, eh_mask));

        /* Extension header check: after AND with eh_mask, a non-zero
         * result means the header is present. For EQ (jmp_op=JNE),
         * we want to skip if zero (not present), so we use the
         * *opposite* opcode here. */
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(jmp_op == BPF_JNE ? BPF_JEQ : BPF_JNE,
                                 BPF_REG_1, 0, 0));
        break;
    default:
        return _bf_matcher_pkt_generate_l4_proto(program, matcher);
    }

    return 0;
}

static int _bf_matcher_pkt_generate_ip4_dscp(struct bf_codegen *program,
                                             const struct bf_matcher *matcher,
                                             const struct bf_matcher_meta *meta)
{
    uint8_t dscp;
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    dscp = *(uint8_t *)bf_matcher_payload(matcher);

    /* IPv4 TOS byte: [DSCP 6b] [ECN 2b]. Mask with 0xfc to isolate
     * the 6-bit DSCP field, then compare against dscp << 2. */
    EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xfc));

    EMIT_FIXUP_JMP_NEXT_RULE(program,
                             BPF_JMP_IMM(bf_cmp_get_jmp_ins(matcher), BPF_REG_1,
                                         (uint8_t)dscp << 2, 0));

    return 0;
}

static int _bf_matcher_pkt_generate_ip6_dscp(struct bf_codegen *program,
                                             const struct bf_matcher *matcher,
                                             const struct bf_matcher_meta *meta)
{
    uint8_t dscp;
    int r;

    r = bf_stub_load_header(program, meta, BPF_REG_6);
    if (r)
        return r;

    dscp = *(uint8_t *)bf_matcher_payload(matcher);

    /* IPv6 DSCP occupies bits 6-11 of the header (big-endian view):
     *   [version 4b] [DSCP 6b] [ECN 2b] [flow label (high 4b)]
     * Load 2 bytes, convert to big-endian, mask with 0x0fc0 to isolate
     * the 6-bit DSCP field, then compare against dscp << 6. */
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6, 0));
    EMIT(program, BPF_ENDIAN(BPF_TO_BE, BPF_REG_1, 16));
    EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0fc0));

    EMIT_FIXUP_JMP_NEXT_RULE(program,
                             BPF_JMP_IMM(bf_cmp_get_jmp_ins(matcher), BPF_REG_1,
                                         (uint16_t)dscp << 6, 0));

    return 0;
}

static int _bf_matcher_pkt_generate_set(struct bf_codegen *program,
                                        const struct bf_matcher *matcher)
{
    const struct bf_set *set;
    size_t offset = 0;
    int r;

    assert(program);
    assert(matcher);

    set = bf_chain_get_set_for_matcher(program->runtime.chain, matcher);
    if (!set) {
        return bf_err_r(-ENOENT, "matcher set not found in %s",
                        program->runtime.chain->name);
    }

    if (set->use_trie) {
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(set->key[0]);

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for '%s'",
                            bf_matcher_type_to_str(set->key[0]));
        }

        r = bf_stub_load_header(program, meta, BPF_REG_6);
        if (r)
            return bf_err_r(r, "failed to load protocol header into BPF_REG_6");

        return bf_set_generate_trie_lookup(
            program, matcher, meta->hdr_payload_offset, meta->hdr_payload_size);
    }

    for (size_t i = 0; i < set->n_comps; ++i) {
        enum bf_matcher_type type = set->key[i];
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for '%s'",
                            bf_matcher_type_to_str(type));
        }

        r = _bf_matcher_pkt_prepare_header(program, type, meta);
        if (r)
            return bf_err_r(r, "failed to load protocol header into BPF_REG_6");

        r = bf_stub_stx_payload(program, meta, offset);
        if (r) {
            return bf_err_r(r,
                            "failed to generate bytecode to load packet data");
        }

        offset += meta->hdr_payload_size;
    }

    return bf_set_generate_map_lookup(program, matcher, BF_PROG_SCR_OFF(0));
}

int bf_packet_gen_inline_matcher(struct bf_codegen *program,
                                 const struct bf_matcher *matcher)
{
    const struct bf_matcher_meta *meta;

    assert(program);
    assert(matcher);

    meta = bf_matcher_get_meta(bf_matcher_get_type(matcher));

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_IFACE:
    case BF_MATCHER_META_L3_PROTO:
    case BF_MATCHER_META_PROBABILITY:
    case BF_MATCHER_META_FLOW_PROBABILITY:
        return bf_matcher_generate_meta(program, matcher);
    case BF_MATCHER_META_L4_PROTO:
        return _bf_matcher_pkt_generate_l4_proto(program, matcher);
    case BF_MATCHER_META_MARK:
    case BF_MATCHER_META_FLOW_HASH:
    case BF_MATCHER_META_PID:
        return bf_err_r(-ENOTSUP,
                        "matcher '%s' is not supported by this flavor",
                        bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
    case BF_MATCHER_IP4_DSCP:
        return _bf_matcher_pkt_generate_ip4_dscp(program, matcher, meta);
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_DADDR:
    case BF_MATCHER_IP4_PROTO:
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_DADDR:
    case BF_MATCHER_ICMP_TYPE:
    case BF_MATCHER_ICMP_CODE:
    case BF_MATCHER_ICMPV6_TYPE:
    case BF_MATCHER_ICMPV6_CODE:
        return _bf_matcher_pkt_load_and_cmp(program, matcher, meta);
    case BF_MATCHER_IP4_SNET:
    case BF_MATCHER_IP4_DNET:
    case BF_MATCHER_IP6_SNET:
    case BF_MATCHER_IP6_DNET:
        return _bf_matcher_pkt_generate_net(program, matcher, meta);
    case BF_MATCHER_TCP_SPORT:
    case BF_MATCHER_TCP_DPORT:
    case BF_MATCHER_UDP_SPORT:
    case BF_MATCHER_UDP_DPORT:
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
        return _bf_matcher_pkt_generate_port(program, matcher, meta);
    case BF_MATCHER_TCP_FLAGS:
        return _bf_matcher_pkt_generate_tcp_flags(program, matcher, meta);
    case BF_MATCHER_IP6_NEXTHDR:
        return _bf_matcher_pkt_generate_ip6_nexthdr(program, matcher);
    case BF_MATCHER_IP6_DSCP:
        return _bf_matcher_pkt_generate_ip6_dscp(program, matcher, meta);
    case BF_MATCHER_SET:
        return _bf_matcher_pkt_generate_set(program, matcher);
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    }
}

int bf_packet_gen_inline_log(struct bf_codegen *program,
                             const struct bf_rule *rule)
{
    assert(program);
    assert(rule);

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, rule->index));

    if (rule->log == BF_FLAG(BF_LOG_OPT_5_TUPLE)) {
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, rule->verdict));

        // Pack l3_proto and l4_proto
        EMIT(program, BPF_MOV64_REG(BPF_REG_4, BPF_REG_7));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 16));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_4, BPF_REG_8));

        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_PKT_5_TUPLE_LOG);
    } else {
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, rule->log == BF_LOG_OPT_DEFAULT ?
                                                   BF_LOG_PACKET_HEADERS :
                                                   rule->log));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_4, rule->verdict));

        // Pack l3_proto and l4_proto
        EMIT(program, BPF_MOV64_REG(BPF_REG_5, BPF_REG_7));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_5, 16));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_5, BPF_REG_8));

        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_PKT_LOG);
    }

    return 0;
}
