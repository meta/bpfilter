/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <bpfilter/runtime.h>

/**
 * @file runtime.h
 *
 * At runtime, the BPF programs have access to a 512 bytes stack. bpfilter will
 * use the stack to store runtime data, such as the program's argument, the
 * packet size...
 *
 * `bf_runtime` defines the layout of the data stored on the stack of the
 * BPF program and simplifies its access.
 *
 * This header can be included into C stubs to be integrated into the generated
 * BPF programs.
 */

/**
 * @brief Return the offset of a field in the runtime context, from `BPF_REG_10`.
 *
 * @param field Field to get the offset of.
 * @return Offset of `field` in the runtime context based on `BPF_REG_10`.
 */
#define BF_PROG_CTX_OFF(field)                                                 \
    (-(int)sizeof(struct bf_runtime) + (int)offsetof(struct bf_runtime, field))

/**
 * @brief Return the offset of an index in the scratch area, from `BPF_REG_10`.
 *
 * @param index Index of the scratch area entry to get the offset of.
 * @return Offset of `index` in the scratch area based on `BPF_REG_10`.
 */
#define BF_PROG_SCR_OFF(index)                                                 \
    (-(int)sizeof(struct bf_runtime) +                                         \
     (int)offsetof(struct bf_runtime, scratch) + (int)(index))

/**
 * @brief Pre-read socket address fields for `cgroup_sock_addr` logging.
 *
 * The BPF verifier restricts which `bpf_sock_addr` context fields a program
 * can access based on its attach type (e.g. `msg_src_ip4` is only valid for
 * `UDP4_SENDMSG`, `user_ip4` only for IPv4 hooks). Because the `sock_addr_log`
 * ELF stub is shared across all hook types, it cannot read these fields
 * directly.
 *
 * Instead, the per-hook inline codegen pre-reads the permitted fields into
 * this struct before calling the stub. The stub then copies from here into
 * the log entry, avoiding any restricted context access.
 */
struct bf_runtime_sock_addr
{
    /** Source address (IPv4: first 4 bytes, IPv6: all 16). */
    __u8 bf_aligned(8) saddr[16];

    /** Destination address (IPv4: first 4 bytes, IPv6: all 16). */
    __u8 bf_aligned(8) daddr[16];

    /** Destination port in host byte order. */
    __u16 bf_aligned(8) dport;

    /**
     * PID of the process in its own PID namespace, 0 if it runs in the
     * initial one.
     */
    __u32 bf_aligned(8) ns_pid;
};

static_assert(sizeof(struct bf_runtime_sock_addr) <= 64,
              "bf_runtime_sock_addr must fit in the scratch area");

/**
 * @brief Per-rule mutable state stored in the program's state map.
 *
 * One entry per rule, accessible from BPF programs via a single-entry array
 * map looked up in the program prologue.
 */
struct bf_rule_state
{
    /** Timestamp of the last log event for this rule, in nanoseconds.
     * Zero-initialised; compared against `bpf_ktime_get_ns()` to enforce
     * per-rule log rate limiting. */
    __u64 last_log_ts;
};

/**
 * @brief Runtime stack layout for the generated BPF programs.
 *
 * This runtime context is located at `r10 - sizeof(struct bf_runtime)`, it is
 * valid during the whole lifetime of the BPF program.
 *
 * Access to the packet data is performed through a BPF dynamic pointer, this
 * pointer is stored in the runtime context, as well as the scratch areas used
 * to store the header slices.
 *
 * Each slice storage area is big enough to store the largest protocol header
 * for a given layer. The BPF subsystem might copy the requested data into the
 * slice storage area or not. In any case, a pointer to the data is returned,
 * this pointer is stored in the runtime context and will be used to access the
 * data.
 *
 * L3 and L4 protocol identifiers are used to check which matcher should be
 * applied to a given packet. They can't be stored in the runtime context as
 * the verifier might not be able to keep track of them, leading to verification
 * failures.
 *
 * @warning Not all the BPF verifier versions are born equal, as older ones
 * might require stack access to be 8-bytes aligned to work properly. Hence, all
 * fields of the runtime context are aligned to 8 bytes, and `bf_runtime` size
 * must be a multiple of 8.
 */
struct bf_runtime
{
    /** Argument passed to the BPF program, its content depends on the BPF
     * program flavor:
     * - `BF_FLAVOR_XDP`: `struct xdp_md *`
     * - `BF_FLAVOR_TC`: `struct struct __sk_buff *`
     * - `BF_FLAVOR_CGROUP_SKB`: `struct __sk_buff *`
     * - `BF_FLAVOR_NF`: `struct bpf_nf_ctx *`
     * - `BF_FLAVOR_CGROUP_SOCK_ADDR`: `struct bpf_sock_addr *` */
    void *arg;

    /** BPF dynamic pointer to access the packet data. Dynamic pointers are
     * used with for program flavor. */
    struct bpf_dynptr dynptr;

    /** Ring buffer map containing the logged packets. */
    void *log_map;

    /** Base pointer into the single-entry state map value.
     * NULL if the chain has no logging rules. Set in the program prologue
     * via `bpf_map_lookup_elem`; each rule's state is at
     * `state_map + rule_index * sizeof(struct bf_rule_state)`. */
    void *state_map;

    /** Total size of the packet, or 0 for non-packet flavors. */
    __u64 pkt_size;

    /** IPv6 extension header mask */
    __u8 ipv6_eh;

    __u8 l2_size;
    __u8 l3_size;
    __u8 l4_size;

    /** Offset of the layer 3 protocol header. */
    __u32 bf_aligned(8) l3_offset;

    /** Offset of the layer 4 protocol header. */
    __u32 bf_aligned(8) l4_offset;

    /** On ingress, index of the input interface. On egress, index of the
     * output interface. */
    __u32 bf_aligned(8) ifindex;

    /** Pointer to the L2 protocol header (in a dynamic pointer slice). */
    void *l2_hdr;

    /** Pointer to the L3 protocol header (in a dynamic pointer slice). */
    void *l3_hdr;

    /** Pointer to the L4 protocol header (in a dynamic pointer slice). */
    void *l4_hdr;

    /** Layer 2 header. */
    __u8 bf_aligned(8) l2[BF_L2_SLICE_LEN];

    /** Layer 3 header. */
    __u8 bf_aligned(8) l3[BF_L3_SLICE_LEN];

    /** Layer 4 header. */
    __u8 bf_aligned(8) l4[BF_L4_SLICE_LEN];

    /** Scratch area. */
    __u8 bf_aligned(8) scratch[64];
};

static_assert(sizeof(struct bf_runtime) % 8 == 0,
              "bf_runtime should be aligned to 8 bytes");

/**
 * @brief Keep timestamps to allow for rate limiting
 *
 */
struct bf_ratelimit_data
{
    /** Current timestamp (at the last call of the BPF) */
    __u64 current;

    /** Last time the rate limit was reset */
    __u64 last_time;
};

extern void *bpf_dynptr_slice(const struct bpf_dynptr *, __u32, void *, __u32);
extern int bpf_dynptr_from_xdp(struct xdp_md *, __u64, struct bpf_dynptr *);
