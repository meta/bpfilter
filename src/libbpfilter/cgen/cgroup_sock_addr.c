/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgroup_sock_addr.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <assert.h>
#include <bpf/libbpf.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/btf.h>
#include <bpfilter/chain.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/flavor.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/runtime.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "cgen/jmp.h"
#include "cgen/matcher/cmp.h"
#include "cgen/matcher/meta.h"
#include "cgen/matcher/set.h"
#include "cgen/program.h"
#include "cgen/runtime.h"
#include "cgen/stub.h"
#include "filter.h"

// Forward definition to avoid header conflicts.
uint16_t htons(uint16_t hostshort);

static int _bf_cgroup_sock_addr_gen_inline_prologue(struct bf_program *program)
{
    assert(program);

    /* `R6` = `bpf_sock_addr` context pointer. Unlike packet-based flavors where
     * `R6` changes per header, the socket context is fixed so we set it once. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));

    // The counters stub reads `pkt_size` unconditionally; zero it out.
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_CTX_OFF(pkt_size), 0));

    /* Take the L3 protocol from the hook, not from `bpf_sock_addr.family`: the
     * kernel also runs the IPv4 hooks for dual-stack `AF_INET6` UDP sockets. */
    switch (program->runtime.chain->hook) {
    case BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4:
    case BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4:
        EMIT(program, BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IP)));
        break;
    case BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6:
    case BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6:
        EMIT(program, BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IPV6)));
        break;
    default:
        return bf_err_r(-ENOTSUP, "unexpected hook: %s",
                        bf_hook_to_str(program->runtime.chain->hook));
    }

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6,
                              offsetof(struct bpf_sock_addr, protocol)));

    return 0;
}

static int _bf_cgroup_sock_addr_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

/**
 * @brief Load a field from the `bpf_sock_addr` context into a register.
 *
 * `R6` must already point to the context. For 16-byte fields, the low
 * 8 bytes go into `reg` and the high 8 bytes into `reg + 1`.
 *
 * When the field offset is not 8-byte aligned, 8- and 16-byte loads fall
 * back to 4-byte reads packed via shift/or. This clobbers `reg + 1` for
 * 8-byte loads and `reg + 2` for 16-byte loads.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param offset Byte offset into `struct bpf_sock_addr`.
 * @param size Field size in bytes: 1, 2, 4, 8, or 16.
 * @param reg BPF register to load the value into.
 * @return 0 on success, negative errno on error.
 */
static int _bf_cgroup_sock_addr_load_field(struct bf_program *program,
                                           size_t offset, size_t size, int reg)
{
    assert(program);

    switch (size) {
    case 1:
        EMIT(program, BPF_LDX_MEM(BPF_B, reg, BPF_REG_6, offset));
        break;
    case 2:
        EMIT(program, BPF_LDX_MEM(BPF_H, reg, BPF_REG_6, offset));
        break;
    case 4:
        EMIT(program, BPF_LDX_MEM(BPF_W, reg, BPF_REG_6, offset));
        break;
    case 8:
        if (offset % 8 == 0) {
            EMIT(program, BPF_LDX_MEM(BPF_DW, reg, BPF_REG_6, offset));
        } else {
            EMIT(program, BPF_LDX_MEM(BPF_W, reg, BPF_REG_6, offset));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 1, BPF_REG_6, offset + 4));
            EMIT(program, BPF_ALU64_IMM(BPF_LSH, reg + 1, 32));
            EMIT(program, BPF_ALU64_REG(BPF_OR, reg, reg + 1));
        }
        break;
    case 16:
        if (offset % 8 == 0) {
            EMIT(program, BPF_LDX_MEM(BPF_DW, reg, BPF_REG_6, offset));
            EMIT(program, BPF_LDX_MEM(BPF_DW, reg + 1, BPF_REG_6, offset + 8));
        } else {
            EMIT(program, BPF_LDX_MEM(BPF_W, reg, BPF_REG_6, offset));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 2, BPF_REG_6, offset + 4));
            EMIT(program, BPF_ALU64_IMM(BPF_LSH, reg + 2, 32));
            EMIT(program, BPF_ALU64_REG(BPF_OR, reg, reg + 2));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 1, BPF_REG_6, offset + 8));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 2, BPF_REG_6, offset + 12));
            EMIT(program, BPF_ALU64_IMM(BPF_LSH, reg + 2, 32));
            EMIT(program, BPF_ALU64_REG(BPF_OR, reg + 1, reg + 2));
        }
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

/**
 * @brief Store a register value at an offset from `BPF_REG_10`.
 *
 * Counterpart to `_bf_cgroup_sock_addr_load_field`. For 16-byte stores,
 * `reg` holds the low 8 bytes and `reg + 1` the high 8 bytes, matching
 * the layout produced by `_bf_cgroup_sock_addr_load_field`.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param offset Byte offset from `BPF_REG_10`.
 * @param size Field size in bytes: 1, 2, 4, 8, or 16.
 * @param reg BPF register holding the value to store.
 * @return 0 on success, negative errno on error.
 */
static int _bf_cgroup_sock_addr_store_field(struct bf_program *program,
                                            int offset, size_t size, int reg)
{
    assert(program);

    switch (size) {
    case 1:
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, reg, offset));
        break;
    case 2:
        EMIT(program, BPF_STX_MEM(BPF_H, BPF_REG_10, reg, offset));
        break;
    case 4:
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, reg, offset));
        break;
    case 8:
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, reg, offset));
        break;
    case 16:
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, reg, offset));
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, reg + 1, offset + 8));
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int _bf_cgroup_sock_addr_load_and_cmp(struct bf_program *program,
                                             const struct bf_matcher *matcher,
                                             size_t offset, size_t size)
{
    int r;

    assert(program);
    assert(matcher);

    r = _bf_cgroup_sock_addr_load_field(program, offset, size, BPF_REG_1);
    if (r)
        return r;

    return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), size,
                        BPF_REG_1);
}

static int _bf_cgroup_sock_addr_generate_net(struct bf_program *program,
                                             const struct bf_matcher *matcher,
                                             size_t offset, size_t size)
{
    uint32_t prefixlen;
    const void *data;
    int r;

    assert(program);
    assert(matcher);

    prefixlen = *(const uint32_t *)bf_matcher_payload(matcher);
    data = (const uint8_t *)bf_matcher_payload(matcher) + sizeof(uint32_t);

    r = _bf_cgroup_sock_addr_load_field(program, offset, size, BPF_REG_1);
    if (r)
        return r;

    return bf_cmp_masked_value(program, matcher, data, prefixlen, size,
                               BPF_REG_1);
}

/* `user_port` is a __u32 in network byte order with the upper 16 bits
 * guaranteed zero by the kernel ABI. Loaded as `BPF_W` so EQ/NE compare
 * the full 32-bit register (safe because upper bits are zero). For range
 * comparisons, `BSWAP` converts to host order (and zeroes the upper bits). */
static int _bf_cgroup_sock_addr_generate_port(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    int r;

    assert(program);
    assert(matcher);

    r = _bf_cgroup_sock_addr_load_field(
        program, offsetof(struct bpf_sock_addr, user_port), 4, BPF_REG_1);
    if (r)
        return r;

    if (bf_matcher_get_op(matcher) == BF_MATCHER_RANGE) {
        uint16_t *ports = (uint16_t *)bf_matcher_payload(matcher);
        EMIT(program, BPF_BSWAP(BPF_REG_1, 16));
        return bf_cmp_range(program, matcher, ports[0], ports[1], BPF_REG_1);
    }

    return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 2,
                        BPF_REG_1);
}

static ssize_t _bf_cgroup_sock_addr_ctx_offset(enum bf_matcher_type type)
{
    switch (type) {
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_SNET:
        return offsetof(struct bpf_sock_addr, msg_src_ip4);
    case BF_MATCHER_IP4_DADDR:
    case BF_MATCHER_IP4_DNET:
        return offsetof(struct bpf_sock_addr, user_ip4);
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_SNET:
        return offsetof(struct bpf_sock_addr, msg_src_ip6);
    case BF_MATCHER_IP6_DADDR:
    case BF_MATCHER_IP6_DNET:
        return offsetof(struct bpf_sock_addr, user_ip6);
    case BF_MATCHER_IP4_PROTO:
        return offsetof(struct bpf_sock_addr, protocol);
    case BF_MATCHER_META_DPORT:
    case BF_MATCHER_TCP_DPORT:
    case BF_MATCHER_UDP_DPORT:
        return offsetof(struct bpf_sock_addr, user_port);
    default:
        return -ENOTSUP;
    }
}

static int _bf_cgroup_sock_addr_generate_set(struct bf_program *program,
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
        ssize_t ctx_off = _bf_cgroup_sock_addr_ctx_offset(set->key[0]);

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for set component '%s'",
                            bf_matcher_type_to_str(set->key[0]));
        }

        if (ctx_off < 0) {
            return bf_err_r(
                (int)ctx_off,
                "set component '%s' not supported for cgroup_sock_addr",
                bf_matcher_type_to_str(set->key[0]));
        }

        return bf_set_generate_trie_lookup(program, matcher, (size_t)ctx_off,
                                           meta->hdr_payload_size);
    }

    for (size_t i = 0; i < set->n_comps; ++i) {
        enum bf_matcher_type type = set->key[i];
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);
        ssize_t ctx_off = _bf_cgroup_sock_addr_ctx_offset(type);

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for set component '%s'",
                            bf_matcher_type_to_str(type));
        }

        /* The PID is not part of the context, a helper returns it. The key
         * components are packed, so the store offset might be misaligned:
         * `bf_stub_store` splits the store accordingly. */
        if (type == BF_MATCHER_META_PID) {
            EMIT(program, BPF_EMIT_CALL(BPF_FUNC_get_current_pid_tgid));
            EMIT(program, BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32));

            r = bf_stub_store(program, BPF_REG_0, meta->hdr_payload_size,
                              BF_PROG_SCR_OFF(offset));
            if (r)
                return r;

            offset += meta->hdr_payload_size;
            continue;
        }

        if (ctx_off < 0) {
            return bf_err_r(
                (int)ctx_off,
                "set component '%s' not supported for cgroup_sock_addr",
                bf_matcher_type_to_str(type));
        }

        /* The BPF verifier enforces specific ctx access widths on
         * `bpf_sock_addr` fields. `bf_stub_load()` reads
         * `meta->hdr_payload_size` bytes from ctx:
         *   - Ports (`hdr_payload_size == 2`): `user_port` is a 4-byte
         *     `__u32`, but the 2-byte narrow read is accepted and rewritten
         *     to the NBO port value.
         *   - Protocol (`hdr_payload_size == 1`): only 4-byte reads are
         *     allowed, so a 1-byte `bf_stub_load()` would be rejected. Reuse
         *     `BPF_REG_8`, which the prologue loaded with a 4-byte read. */
        if (type == BF_MATCHER_IP4_PROTO) {
            EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_8,
                                      BF_PROG_SCR_OFF(offset)));
        } else {
            r = bf_stub_load(program, (size_t)ctx_off, meta->hdr_payload_size,
                             BF_PROG_SCR_OFF(offset));
            if (r)
                return r;
        }

        offset += meta->hdr_payload_size;
    }

    return bf_set_generate_map_lookup(program, matcher, BF_PROG_SCR_OFF(0));
}

static int
_bf_cgroup_sock_addr_gen_inline_matcher(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_L3_PROTO:
    case BF_MATCHER_META_L4_PROTO:
    case BF_MATCHER_META_PROBABILITY:
        return bf_matcher_generate_meta(program, matcher);
    case BF_MATCHER_META_PID:
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_get_current_pid_tgid));
        EMIT(program, BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32));
        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 4,
                            BPF_REG_0);
    case BF_MATCHER_IP4_SADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip4), 4);
    case BF_MATCHER_IP4_SNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip4), 4);
    case BF_MATCHER_IP4_DADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip4), 4);
    case BF_MATCHER_IP4_DNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip4), 4);
    case BF_MATCHER_IP4_PROTO:
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_8));
        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 1,
                            BPF_REG_1);
    case BF_MATCHER_IP6_SADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip6), 16);
    case BF_MATCHER_IP6_SNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip6), 16);
    case BF_MATCHER_IP6_DADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip6), 16);
    case BF_MATCHER_IP6_DNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip6), 16);
    case BF_MATCHER_META_DPORT:
    case BF_MATCHER_TCP_DPORT:
    case BF_MATCHER_UDP_DPORT:
        return _bf_cgroup_sock_addr_generate_port(program, matcher);
    case BF_MATCHER_SET:
        return _bf_cgroup_sock_addr_generate_set(program, matcher);
    default:
        return bf_err_r(-ENOTSUP,
                        "matcher '%s' not supported for cgroup_sock_addr",
                        bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
    }
}

/**
 * @brief Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @param ret_code Cgroup return code. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgroup_sock_addr_get_verdict(enum bf_verdict verdict,
                                            int *ret_code)
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

#define _BF_SOCK_ADDR_NS_PID_OFF                                               \
    BF_PROG_SCR_OFF(offsetof(struct bf_runtime_sock_addr, ns_pid))

/* The kernel pointers dereferenced to reach the namespace-local PID are staged
 * in the scratch area, right after `bf_runtime_sock_addr`. */
#define _BF_SOCK_ADDR_NS_PID_WALK_OFF                                          \
    BF_PROG_SCR_OFF(sizeof(struct bf_runtime_sock_addr))

static_assert(sizeof(struct bf_runtime_sock_addr) + sizeof(__u64) <= 64,
              "no room left in the scratch area for the PID namespace walk");

/**
 * @brief Store the process' namespace-local PID into the staging area.
 *
 * `bpf_get_current_pid_tgid()` reports the PID as seen from the initial PID
 * namespace. The namespace-local one is only reachable through the kernel
 * structures: `current->group_leader->thread_pid->numbers[level].nr`, with
 * `level` the depth of the process' own PID namespace. `level` is 0 in the
 * initial namespace, where this yields the same value as
 * `bpf_get_current_pid_tgid()`.
 *
 * `numbers` is indexed with a runtime value, and the verifier rejects variable
 * offsets on BTF pointers, so the walk uses `bpf_probe_read_kernel()` and
 * computes the addresses as scalars.
 *
 * `ns_pid` is left to 0 if `level` is 0: the process' only PID is the one
 * reported by `bpf_get_current_pid_tgid()`. The PID allocator never hands out
 * 0, so 0 unambiguously means "no namespace-local PID to report", including
 * when the walk failed: `bpf_probe_read_kernel()` zeroes its destination on
 * failure, so an unreadable address leaves the slot zeroed instead of stale.
 *
 * @todo `pid.level` and `upid.nr` are assumed to be 4 bytes: `level` is loaded
 * back from the slot with `BPF_W`, and `ns_pid` is a `__u32`. Validate their
 * size against the BTF data, so a kernel changing either of them fails the
 * program generation instead of logging a wrong PID.
 *
 * @param program Program to emit the instructions into. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgroup_sock_addr_store_ns_pid(struct bf_program *program)
{
    int group_leader_off;
    int thread_pid_off;
    int level_off;
    int r;

    assert(program);

    // Keep the pre-zeroed ns_pid when lockdown blocks kernel reads.
    r = libbpf_probe_bpf_helper(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                                BPF_FUNC_probe_read_kernel, NULL);
    if (r <= 0)
        return r;

    /* The pointers are only needed to reach the next one, they are read into
     * the walk slot. `level` and the PID itself are read into the `ns_pid`
     * slot, which then holds the 0 to report if the walk stops at the initial
     * namespace. */

    // Walk: current->group_leader
    group_leader_off = bf_btf_get_field_off("task_struct", "group_leader");
    if (group_leader_off < 0)
        return group_leader_off;

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_get_current_task));
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program,
         BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, _BF_SOCK_ADDR_NS_PID_WALK_OFF));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 8));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_0));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, group_leader_off));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel));

    // Walk: current->group_leader->thread_pid
    thread_pid_off = bf_btf_get_field_off("task_struct", "thread_pid");
    if (thread_pid_off < 0)
        return thread_pid_off;

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program,
         BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, _BF_SOCK_ADDR_NS_PID_WALK_OFF));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 8));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_10,
                              _BF_SOCK_ADDR_NS_PID_WALK_OFF));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, thread_pid_off));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel));

    // Walk: current->group_leader->thread_pid->level
    level_off = bf_btf_get_field_off("pid", "level");
    if (level_off < 0)
        return level_off;

    /* R9 is callee-saved and free at this point: the rate limiter in
     * `_bf_program_generate_log()` is done with it. It keeps `thread_pid`
     * across the `level` read, to index `numbers` with it. */
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_10,
                              _BF_SOCK_ADDR_NS_PID_WALK_OFF));
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, _BF_SOCK_ADDR_NS_PID_OFF));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 4));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_9));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, level_off));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel));

    /* Walk: current->group_leader->thread_pid->numbers[level].nr, skipped
     * for the initial namespace: the slot then keeps the level, which is the
     * 0 to report. */
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, _BF_SOCK_ADDR_NS_PID_OFF));

    {
        int numbers_off;
        int nr_off;
        int upid_size;
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_3, 0, 0));

        numbers_off = bf_btf_get_field_off("pid", "numbers");
        if (numbers_off < 0)
            return numbers_off;

        nr_off = bf_btf_get_field_off("upid", "nr");
        if (nr_off < 0)
            return nr_off;

        upid_size = bf_btf_get_type_size("upid");
        if (upid_size < 0)
            return upid_size;

        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program,
             BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, _BF_SOCK_ADDR_NS_PID_OFF));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 4));
        EMIT(program, BPF_ALU64_IMM(BPF_MUL, BPF_REG_3, upid_size));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, numbers_off + nr_off));
        EMIT(program, BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_9));
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel));
    }

    return 0;
}

static int _bf_cgroup_sock_addr_gen_inline_log(struct bf_program *program,
                                               const struct bf_rule *rule)
{
    uint8_t captured_fields = 0;
    bool has_saddr = false;
    size_t addr_size = 0;
    size_t saddr_off = 0;
    size_t daddr_off = 0;
    int r;

    assert(program);
    assert(rule);

    // Zero the staging area: connect hooks have no source address,
    // and IPv4 hooks only write 4 of the 16 address bytes.
    for (int i = 0; i < (int)sizeof(struct bf_runtime_sock_addr); i += 8)
        EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_SCR_OFF(i), 0));

    switch (program->runtime.chain->hook) {
    case BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4:
        has_saddr = true;
        saddr_off = offsetof(struct bpf_sock_addr, msg_src_ip4);
        __attribute__((fallthrough));
    case BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4:
        addr_size = 4;
        daddr_off = offsetof(struct bpf_sock_addr, user_ip4);
        break;
    case BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6:
        has_saddr = true;
        saddr_off = offsetof(struct bpf_sock_addr, msg_src_ip6);
        __attribute__((fallthrough));
    case BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6:
        addr_size = 16;
        daddr_off = offsetof(struct bpf_sock_addr, user_ip6);
        break;
    default:
        return bf_err_r(-ENOTSUP, "unexpected hook: %s",
                        bf_hook_to_str(program->runtime.chain->hook));
    }

    if (has_saddr) {
        captured_fields |= BF_LOG_SOCK_ADDR_SADDR;
        r = _bf_cgroup_sock_addr_load_field(program, saddr_off, addr_size,
                                            BPF_REG_1);
        if (r)
            return r;
        r = _bf_cgroup_sock_addr_store_field(
            program,
            BF_PROG_SCR_OFF(offsetof(struct bf_runtime_sock_addr, saddr)),
            addr_size, BPF_REG_1);
        if (r)
            return r;
    }

    r = _bf_cgroup_sock_addr_load_field(program, daddr_off, addr_size,
                                        BPF_REG_1);
    if (r)
        return r;
    r = _bf_cgroup_sock_addr_store_field(
        program, BF_PROG_SCR_OFF(offsetof(struct bf_runtime_sock_addr, daddr)),
        addr_size, BPF_REG_1);
    if (r)
        return r;

    /* Destination port: valid for all cgroup_sock_addr hooks.
     * user_port is __be32; BSWAP 16 converts to host order. */
    r = _bf_cgroup_sock_addr_load_field(
        program, offsetof(struct bpf_sock_addr, user_port), 4, BPF_REG_1);
    if (r)
        return r;
    EMIT(program, BPF_BSWAP(BPF_REG_1, 16));
    r = _bf_cgroup_sock_addr_store_field(
        program, BF_PROG_SCR_OFF(offsetof(struct bf_runtime_sock_addr, dport)),
        2, BPF_REG_1);
    if (r)
        return r;

    r = _bf_cgroup_sock_addr_store_ns_pid(program);
    if (r)
        return r;

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, rule->index));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_3, rule->verdict));
    EMIT(program, BPF_MOV64_REG(BPF_REG_4, BPF_REG_7));
    EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 16));
    EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_4, BPF_REG_8));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_5, captured_fields));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_SOCK_ADDR_LOG);

    return 0;
}

const struct bf_flavor_ops bf_flavor_ops_cgroup_sock_addr = {
    .gen_inline_prologue = _bf_cgroup_sock_addr_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_sock_addr_gen_inline_epilogue,
    .get_verdict = _bf_cgroup_sock_addr_get_verdict,
    .gen_inline_matcher = _bf_cgroup_sock_addr_gen_inline_matcher,
    .gen_inline_log = _bf_cgroup_sock_addr_gen_inline_log,
};
