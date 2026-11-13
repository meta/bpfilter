/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include <stddef.h>

#include "cgen/runtime.h"

#define BF_IPV6_EXT_MAX_CHAIN 6
#define BF_IPV6_FRAG_OFFSET 0xfff8

/* Number of bytes of the transport header quoted after the IPv6 header and its
 * extension headers, as for ICMP. */
#define BF_ICMPV6_QUOTE_L4_LEN 8

/* The reply must not exceed the minimum IPv6 MTU (RFC 4443 section 2.4), so
 * at most 1280 - 40 - 8 bytes are quoted. */
#define BF_ICMPV6_QUOTE_MAX_LEN 1232

#define BF_REJECT_HOP_LIMIT 64

/* First bytes of an IPv6 extension header, which is at least 8 bytes long.
 * frag_off is only defined for the fragment header. */
struct bf_ipv6_ext_hdr
{
    __u8 nexthdr;
    __u8 hdrlen;
    __be16 frag_off;
};

static __always_inline __u16 bf_csum_fold(__s64 csum)
{
    __u32 sum = (__u32)csum;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (__u16)~sum;
}

static __always_inline bool bf_ip6_is_unicast(const struct in6_addr *addr)
{
    // Not :: and not multicast (ff00::/8)
    return (addr->s6_addr32[0] | addr->s6_addr32[1] | addr->s6_addr32[2] |
            addr->s6_addr32[3]) &&
           addr->s6_addr[0] != 0xff;
}

static __always_inline bool bf_ip6_is_ext_hdr(__u8 nexthdr)
{
    // Extension headers skipped by the kernel's ipv6_skip_exthdr()
    return nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING ||
           nexthdr == IPPROTO_FRAGMENT || nexthdr == IPPROTO_AH ||
           nexthdr == IPPROTO_DSTOPTS;
}

/**
 * Reply to an IPv6 packet with an ICMPv6 error, in place.
 *
 * The reply quotes the original IPv6 header, its extension headers, and the
 * first 8 bytes of the transport header, which the sender needs to find the
 * socket the error is for. Its addresses are the original addresses swapped.
 * No reply is sent to link-layer broadcast or multicast frames, to packets
 * from or to a non-unicast address, to fragments other than the first, to
 * ICMPv6 errors, or to malformed packets: they are dropped.
 *
 * @param ctx Runtime context of the program.
 * @param type ICMPv6 type of the reply.
 * @param code ICMPv6 code of the reply.
 * @return `XDP_TX` if the packet has been replaced by the reply, `XDP_DROP`
 *         otherwise.
 */
int bf_xdp_reject_icmp6(struct bf_runtime *ctx, __u8 type, __u8 code)
{
    struct xdp_md *xdp = ctx->arg;
    struct icmp6hdr icmp6h = {};
    struct ipv6hdr ip6h = {};
    struct ipv6hdr orig;
    __be32 pseudo_tail[2];
    __u8 mac[ETH_ALEN];
    struct ethhdr eth;
    __u32 payload_len;
    __u32 quote_len;
    __u8 nexthdr;
    __u32 off;
    __s64 csum;

    if (bpf_xdp_load_bytes(xdp, 0, &eth, sizeof(eth)) ||
        bpf_xdp_load_bytes(xdp, ETH_HLEN, &orig, sizeof(orig)))
        return XDP_DROP;

    if (eth.h_proto != bpf_htons(ETH_P_IPV6) || eth.h_dest[0] & 1 ||
        eth.h_source[0] & 1)
        return XDP_DROP;

    payload_len = bpf_ntohs(orig.payload_len);
    if (orig.version != 6 ||
        ETH_HLEN + sizeof(orig) + payload_len > ctx->pkt_size)
        return XDP_DROP;

    if (!bf_ip6_is_unicast(&orig.saddr) || !bf_ip6_is_unicast(&orig.daddr))
        return XDP_DROP;

    /* Look for the fragment header and the ICMPv6 header through the
     * extension headers. */
    nexthdr = orig.nexthdr;
    off = ETH_HLEN + sizeof(orig);
    for (int i = 0; i < BF_IPV6_EXT_MAX_CHAIN && bf_ip6_is_ext_hdr(nexthdr);
         ++i) {
        struct bf_ipv6_ext_hdr ext;

        if (bpf_xdp_load_bytes(xdp, off, &ext, sizeof(ext)))
            return XDP_DROP;

        if (nexthdr == IPPROTO_FRAGMENT) {
            if (ext.frag_off & bpf_htons(BF_IPV6_FRAG_OFFSET))
                return XDP_DROP;
            off += 8;
        } else if (nexthdr == IPPROTO_AH) {
            off += (ext.hdrlen + 2) * 4;
        } else {
            off += (ext.hdrlen + 1) * 8;
        }

        nexthdr = ext.nexthdr;
    }

    if (bf_ip6_is_ext_hdr(nexthdr))
        return XDP_DROP;

    if (nexthdr == IPPROTO_ICMPV6) {
        __u8 icmp6_type;

        if (bpf_xdp_load_bytes(xdp, off, &icmp6_type, sizeof(icmp6_type)) ||
            !(icmp6_type & ICMPV6_INFOMSG_MASK))
            return XDP_DROP;
    }

    // Extension headers are 8-byte aligned, so is the quote
    quote_len = off - ETH_HLEN + BF_ICMPV6_QUOTE_L4_LEN;
    if (quote_len > sizeof(orig) + payload_len ||
        quote_len > BF_ICMPV6_QUOTE_MAX_LEN || quote_len % 8)
        return XDP_DROP;

    __builtin_memcpy(mac, eth.h_dest, ETH_ALEN);
    __builtin_memcpy(eth.h_dest, eth.h_source, ETH_ALEN);
    __builtin_memcpy(eth.h_source, mac, ETH_ALEN);

    ip6h.version = 6;
    ip6h.payload_len = bpf_htons(sizeof(icmp6h) + quote_len);
    ip6h.nexthdr = IPPROTO_ICMPV6;
    ip6h.hop_limit = BF_REJECT_HOP_LIMIT;
    ip6h.saddr = orig.daddr;
    ip6h.daddr = orig.saddr;

    /* The ICMPv6 checksum covers the pseudo-header (addresses, length, and
     * next header), the ICMPv6 header, and the quote. */
    pseudo_tail[0] = bpf_htonl(sizeof(icmp6h) + quote_len);
    pseudo_tail[1] = bpf_htonl(IPPROTO_ICMPV6);
    icmp6h.icmp6_type = type;
    icmp6h.icmp6_code = code;
    csum = bpf_csum_diff(NULL, 0, (__be32 *)&ip6h.saddr,
                         sizeof(ip6h.saddr) + sizeof(ip6h.daddr), 0);
    csum = bpf_csum_diff(NULL, 0, pseudo_tail, sizeof(pseudo_tail), csum);
    csum = bpf_csum_diff(NULL, 0, (__be32 *)&icmp6h, sizeof(icmp6h), csum);
    for (__u32 i = 0; i < BF_ICMPV6_QUOTE_MAX_LEN / 8 && i * 8 < quote_len;
         ++i) {
        __be32 chunk[2];

        if (bpf_xdp_load_bytes(xdp, ETH_HLEN + i * 8, chunk, sizeof(chunk)))
            return XDP_DROP;

        csum = bpf_csum_diff(NULL, 0, chunk, sizeof(chunk), csum);
    }
    icmp6h.icmp6_cksum = bf_csum_fold(csum);

    /* Make room for the new IPv6 and ICMPv6 headers in front of the original
     * IPv6 header, which becomes the start of the quote, then cut the packet
     * after the quote. */
    if (bpf_xdp_adjust_head(xdp, -(int)(sizeof(ip6h) + sizeof(icmp6h))))
        return XDP_DROP;

    if (bpf_xdp_adjust_tail(
            xdp, (int)(ETH_HLEN + sizeof(ip6h) + sizeof(icmp6h) + quote_len) -
                     (int)bpf_xdp_get_buff_len(xdp)))
        return XDP_DROP;

    if (bpf_xdp_store_bytes(xdp, 0, &eth, sizeof(eth)) ||
        bpf_xdp_store_bytes(xdp, ETH_HLEN, &ip6h, sizeof(ip6h)) ||
        bpf_xdp_store_bytes(xdp, ETH_HLEN + sizeof(ip6h), &icmp6h,
                            sizeof(icmp6h)))
        return XDP_DROP;

    return XDP_TX;
}
