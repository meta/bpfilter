/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define bf_aligned(x) __attribute__((aligned(x)))

/**
 * @brief Give an anonymous union or struct a name only for Doxygen.
 *
 * Allows anonymous unions/structs in code while keeping Doxygen's parser happy.
 */
#ifdef DOXYGEN
#define BF_ANONYMOUS_MEMBER(name) name
#else
#define BF_ANONYMOUS_MEMBER(name)
#endif

// _Static_assert doesn't exist in C++
#ifndef __cplusplus
#define static_assert _Static_assert
#endif

#include <linux/in6.h>

#include <asm/types.h>

/**
 * @brief Size of the L2 header buffer.
 *
 * Only Ethernet is supported at L2, so the buffer should be as big as the
 * Ethernet header, aligned to 8 bytes.
 */
#define BF_L2_SLICE_LEN 16
static_assert(BF_L2_SLICE_LEN % 8 == 0,
              "BF_L2_SLICE_LEN should be aligned to 8 bytes");

/**
 * @brief Size of the L3 header buffer.
 *
 * The buffer should be able to contain the largest supported L3 protocol header
 * among, aligned on 8 bytes:
 * - IPv4: 20 bytes (ignoring the options)
 * - IPv6: 40 bytes (ignoring the extension headers)
 */
#define BF_L3_SLICE_LEN 40
static_assert(BF_L3_SLICE_LEN % 8 == 0,
              "BF_L3_SLICE_LEN should be aligned to 8 bytes");

/**
 * @brief Size of the L4 header buffer.
 *
 * The buffer should be able to contain the largest supported L4 protocol header
 * among, aligned to 8 bytes:
 * - UDP: 8 bytes
 * - TCP: 20 bytes
 * - ICMP: 8 bytes (ignoring the payload)
 * - ICMPV6: 4 bytes (ignoring the body)
 */
#define BF_L4_SLICE_LEN 24
static_assert(BF_L4_SLICE_LEN % 8 == 0,
              "BF_L4_SLICE_LEN should be aligned to 8 bytes");

/** Size of the process name buffer, matches TASK_COMM_LEN. */
#define BF_COMM_LEN 16

/**
 * @brief Log option identifiers for per-rule logging.
 */
enum bf_log_opt
{
    /**
     * Link layer header: Ethernet, ...
     */
    BF_LOG_OPT_LINK,

    /**
     * Internet header: IPv4, IPv6, ...
     */
    BF_LOG_OPT_INTERNET,

    /**
     * Transport header: TCP, UDP, ...
     *
     * ICMPv6 is an internet layer (L3) header, but it's encapsulated inside an
     * IPv6 packet, so it's considered a transport layer (L4) header in
     * bpfilter.
     */
    BF_LOG_OPT_TRANSPORT,

    /**
     * Packet 5-tuple: source and destination addresses and ports, and the
     * transport protocol.
     */
    BF_LOG_OPT_5_TUPLE,

    _BF_LOG_OPT_MAX,

    /** Log all available data for the hook type. */
    BF_LOG_OPT_DEFAULT = 0xFF,
};

/** Log all available packet headers. */
#define BF_LOG_PACKET_HEADERS                                                  \
    ((1ULL << (unsigned int)BF_LOG_OPT_LINK) |                                 \
     (1ULL << (unsigned int)BF_LOG_OPT_INTERNET) |                             \
     (1ULL << (unsigned int)BF_LOG_OPT_TRANSPORT))

/**
 * @brief Log entry type discriminator.
 */
enum bf_log_type
{
    /** Packet-based log entry (XDP, TC, NF, cgroup_skb). */
    BF_LOG_TYPE_PACKET,

    /** Socket address log entry (cgroup_sock_addr). */
    BF_LOG_TYPE_SOCK_ADDR,

    /** Packet 5-tuple log entry (XDP, TC, NF, cgroup_skb). */
    BF_LOG_TYPE_PACKET_5_TUPLE,

    _BF_LOG_TYPE_MAX,
};

/**
 * @brief Packet log payload fields (XDP, TC, NF, cgroup_skb).
 */
struct bf_log_pkt
{
    /** Total size of the packet, including the payload. */
    __u64 pkt_size;

    /** User-requested headers, as defined in the rule. */
    __u8 req_headers:4;

    /** Logged headers, as not all hooks can access all headers. */
    __u8 headers:4;

    /** Layer 2 header. */
    bf_aligned(8) __u8 l2hdr[BF_L2_SLICE_LEN];

    /** Layer 3 header. */
    bf_aligned(8) __u8 l3hdr[BF_L3_SLICE_LEN];

    /** Layer 4 header. */
    bf_aligned(8) __u8 l4hdr[BF_L4_SLICE_LEN];
};

/** Source address field was captured. */
#define BF_LOG_SOCK_ADDR_SADDR (1U << 0U)

/**
 * @brief Socket address log payload fields (cgroup_sock_addr).
 */
struct bf_log_sock_addr
{
    /** Root namespace PID (tgid) of the process. */
    __u32 pid;

    /** Destination port in host byteorder. */
    __u16 dport;

    /** Bitmask of conditional fields captured in this log entry. */
    __u8 captured_fields;

    /** Process name. */
    bf_aligned(8) __u8 comm[BF_COMM_LEN];

    /** Source address (4 bytes for IPv4, 16 for IPv6). */
    bf_aligned(8) __u8 saddr[sizeof(struct in6_addr)];

    /** Destination address (4 bytes for IPv4, 16 for IPv6). */
    bf_aligned(8) __u8 daddr[sizeof(struct in6_addr)];

    /**
        * PID (tgid) of the process in its own PID namespace.
        *
        * 0 if the process runs in the initial PID namespace, as its only PID is
        * already reported in `pid`, or if the kernel structures couldn't be read.
        * The PID allocator never returns 0, so a non-zero value always carries
        * something `pid` doesn't.
        */
    __u32 ns_pid;
};

/**
 * @brief Packet 5-tuple log payload fields (XDP, TC, NF, cgroup_skb).
 */
struct bf_log_pkt_5_tuple
{
    /** Source address (4 bytes for IPv4, 16 for IPv6). */
    bf_aligned(8) __u8 saddr[sizeof(struct in6_addr)];

    /** Destination address (4 bytes for IPv4, 16 for IPv6). */
    bf_aligned(8) __u8 daddr[sizeof(struct in6_addr)];

    /** Source port in host byteorder. */
    __u16 sport;

    /** Destination port in host byteorder. */
    __u16 dport;
};

/**
 * @brief Log structure published by a chain when the `log` action is hit.
 *
 * The structure is published into a log buffer by the chain, when a hit rule
 * has a `log` action defined.
 *
 * All fields are stored in host byteorder unless noted otherwise.
 */
struct bf_log
{
    /** Timestamp of the event. */
    __u64 ts;

    /** ID of the rule triggering the log. */
    __u32 rule_id;

    /** Verdict of the rule triggering the log. */
    __u32 verdict;

    /** Layer 3 (internet) protocol identifier. */
    __u16 l3_proto;

    /** Layer 4 (transport) protocol identifier. */
    __u8 l4_proto;

    /** Log entry type. */
    __u8 log_type;

    /**
     * Flavor-specific payload, discriminated by `log_type`.
     *
     * - `BF_LOG_TYPE_PACKET`: use `pkt` — raw packet headers in network
     *   byteorder.
     * - `BF_LOG_TYPE_SOCK_ADDR`: use `sock_addr` — socket address, port,
     *   and process metadata.
     * - `BF_LOG_TYPE_PACKET_5_TUPLE`: use `pkt_5_tuple` — packet source and
     *   destination addresses and ports.
     */
    union
    {
        struct bf_log_pkt pkt;
        struct bf_log_sock_addr sock_addr;
        struct bf_log_pkt_5_tuple pkt_5_tuple;
    } BF_ANONYMOUS_MEMBER(payload);
};

struct bf_ip4_lpm_key
{
    __u32 prefixlen;
    __u32 data;
};

struct bf_ip6_lpm_key
{
    __u32 prefixlen;
    __u8 data[16];
    __u32 _padding;
};
