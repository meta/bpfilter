/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include <stddef.h>

#include "cgen/runtime.h"

#define BF_IP_DF 0x4000
#define BF_IP_OFFSET 0x1fff
#define BF_IP_MAX_HDR_LEN 60

/* Number of bytes of the original datagram quoted after its header, as
 * required by RFC 792. */
#define BF_ICMP_QUOTE_LEN 8

/* ICMP types the kernel doesn't consider errors (see icmp_pointers in
 * net/ipv4/icmp.c): echo reply (0), echo request (8), timestamp (13, 14),
 * information (15, 16), and address mask (17, 18) requests and replies. Any
 * other type is an error, or unknown. */
#define BF_ICMP_INFO_TYPES 0x7e101
#define BF_ICMP_MAX_TYPE 18

#define BF_REJECT_TTL 64

/* ICMP error header. linux/icmp.h can't be used as it includes libc
 * headers. */
struct bf_icmphdr
{
    __u8 type;
    __u8 code;
    __sum16 checksum;
    __be32 unused;
};

static __always_inline __u16 bf_csum_fold(__s64 csum)
{
    __u32 sum = (__u32)csum;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (__u16)~sum;
}

static __always_inline bool bf_ip4_is_unicast(__be32 addr)
{
    __u32 host = bpf_ntohl(addr);

    // Not 0.0.0.0, multicast (224.0.0.0/4), or limited broadcast
    return host && (host & 0xf0000000) != 0xe0000000 && host != 0xffffffff;
}

/**
 * Reply to an IPv4 packet with an ICMP error, in place.
 *
 * The reply quotes the original IP header and the first 8 bytes of its
 * payload, its addresses are the original addresses swapped. No reply is sent
 * to link-layer broadcast or multicast frames, to packets from or to a
 * non-unicast address, to fragments other than the first, to ICMP errors, or
 * to malformed packets: they are dropped.
 *
 * @param ctx Runtime context of the program.
 * @param type ICMP type of the reply.
 * @param code ICMP code of the reply.
 * @return `XDP_TX` if the packet has been replaced by the reply, `XDP_DROP`
 *         otherwise.
 */
int bf_xdp_reject_icmp(struct bf_runtime *ctx, __u8 type, __u8 code)
{
    struct xdp_md *xdp = ctx->arg;
    __u8 hdr[BF_IP_MAX_HDR_LEN] = {};
    __u8 data[BF_ICMP_QUOTE_LEN];
    struct iphdr *orig = (struct iphdr *)hdr;
    struct bf_icmphdr icmph = {};
    struct iphdr iph = {};
    __u8 mac[ETH_ALEN];
    struct ethhdr eth;
    __u32 hdr_len;
    __u32 tot_len;
    __s64 csum;

    if (bpf_xdp_load_bytes(xdp, 0, &eth, sizeof(eth)) ||
        bpf_xdp_load_bytes(xdp, ETH_HLEN, hdr, sizeof(struct iphdr)))
        return XDP_DROP;

    if (eth.h_proto != bpf_htons(ETH_P_IP) || eth.h_dest[0] & 1 ||
        eth.h_source[0] & 1)
        return XDP_DROP;

    hdr_len = (hdr[0] & 0x0f) * 4;
    tot_len = bpf_ntohs(orig->tot_len);
    if (orig->version != 4 || hdr_len < sizeof(struct iphdr) ||
        tot_len < hdr_len + BF_ICMP_QUOTE_LEN ||
        ETH_HLEN + tot_len > ctx->pkt_size)
        return XDP_DROP;

    if (orig->frag_off & bpf_htons(BF_IP_OFFSET) ||
        !bf_ip4_is_unicast(orig->saddr) || !bf_ip4_is_unicast(orig->daddr))
        return XDP_DROP;

    /* hdr is zeroed: the bytes after the header don't change the checksum,
     * and the verifier requires the buffer to be initialized as the size of
     * the load is not constant. */
    if (bpf_xdp_load_bytes(xdp, ETH_HLEN, hdr, hdr_len) ||
        bpf_xdp_load_bytes(xdp, ETH_HLEN + hdr_len, data, sizeof(data)))
        return XDP_DROP;

    csum = bpf_csum_diff(NULL, 0, (__be32 *)hdr, sizeof(hdr), 0);
    if (bf_csum_fold(csum))
        return XDP_DROP;

    if (orig->protocol == IPPROTO_ICMP &&
        (data[0] > BF_ICMP_MAX_TYPE || !(BF_ICMP_INFO_TYPES & (1 << data[0]))))
        return XDP_DROP;

    __builtin_memcpy(mac, eth.h_dest, ETH_ALEN);
    __builtin_memcpy(eth.h_dest, eth.h_source, ETH_ALEN);
    __builtin_memcpy(eth.h_source, mac, ETH_ALEN);

    iph.version = 4;
    iph.ihl = sizeof(iph) / 4;
    iph.tot_len =
        bpf_htons(sizeof(iph) + sizeof(icmph) + hdr_len + BF_ICMP_QUOTE_LEN);
    iph.frag_off = bpf_htons(BF_IP_DF);
    iph.ttl = BF_REJECT_TTL;
    iph.protocol = IPPROTO_ICMP;
    iph.saddr = orig->daddr;
    iph.daddr = orig->saddr;
    iph.check =
        bf_csum_fold(bpf_csum_diff(NULL, 0, (__be32 *)&iph, sizeof(iph), 0));

    /* The ICMP checksum covers the ICMP header and the quoted bytes. The
     * header length is a multiple of 4, so the quoted payload is 16-bit
     * aligned. */
    icmph.type = type;
    icmph.code = code;
    csum = bpf_csum_diff(NULL, 0, (__be32 *)data, sizeof(data), csum);
    csum = bpf_csum_diff(NULL, 0, (__be32 *)&icmph, sizeof(icmph), csum);
    icmph.checksum = bf_csum_fold(csum);

    /* Make room for the new IP and ICMP headers in front of the original IP
     * header, which becomes the quoted header, then cut the packet after the
     * quoted payload. */
    if (bpf_xdp_adjust_head(xdp, -(int)(sizeof(iph) + sizeof(icmph))))
        return XDP_DROP;

    if (bpf_xdp_adjust_tail(xdp, (int)(ETH_HLEN + sizeof(iph) + sizeof(icmph) +
                                       hdr_len + BF_ICMP_QUOTE_LEN) -
                                     (int)bpf_xdp_get_buff_len(xdp)))
        return XDP_DROP;

    if (bpf_xdp_store_bytes(xdp, 0, &eth, sizeof(eth)) ||
        bpf_xdp_store_bytes(xdp, ETH_HLEN, &iph, sizeof(iph)) ||
        bpf_xdp_store_bytes(xdp, ETH_HLEN + sizeof(iph), &icmph, sizeof(icmph)))
        return XDP_DROP;

    return XDP_TX;
}
