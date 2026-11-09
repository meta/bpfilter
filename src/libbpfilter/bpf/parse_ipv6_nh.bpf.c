/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

#define EH_COMMON_OFFSET 1
#define EH_COMMON_SHIFT 3
#define EH_AH_OFFSET 2
#define EH_AH_SHIFT 2
#define EH_FRAG_OFFSET 8
#define EH_FRAG_SHIFT 0

/* The following defines are the same of src/bpfilter/cgen/matcher/ip6.c */
#define BF_IPV6_EH_HOPOPTS(x) ((x) << 0)
#define BF_IPV6_EH_ROUTING(x) ((x) << 1)
#define BF_IPV6_EH_FRAGMENT(x) ((x) << 2)
#define BF_IPV6_EH_AH(x) ((x) << 3)
#define BF_IPV6_EH_DSTOPTS(x) ((x) << 4)
#define BF_IPV6_EH_MH(x) ((x) << 5)

__u8 bf_parse_ipv6(struct bf_runtime *ctx)
{
    struct ipv6hdr *ip6hdr = ctx->l3_hdr;
    __u8 next_hdr_type = ip6hdr->nexthdr;
    ctx->ipv6_eh = 0;
    ctx->l4_offset = ctx->l3_offset + sizeof(struct ipv6hdr);

    // Walk one header past the cap to detect packets with too many headers
    for (int i = 0; i <= BF_IPV6_EH_MAX; ++i) {
        struct ipv6_opt_hdr _ext;
        struct ipv6_opt_hdr *ext =
            bpf_dynptr_slice(&ctx->dynptr, ctx->l4_offset, &_ext, sizeof(_ext));

        if (!ext)
            return next_hdr_type;

        switch (next_hdr_type) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        case IPPROTO_FRAGMENT:
        case IPPROTO_AH:
        case IPPROTO_MH:
            break;
        default:
            return next_hdr_type;
        }

        __u8 hdrlen = ext->hdrlen;
        __u8 offset;
        __u8 shift;
        ctx->ipv6_eh |=
            (BF_IPV6_EH_HOPOPTS(next_hdr_type == IPPROTO_HOPOPTS) |
             BF_IPV6_EH_ROUTING(next_hdr_type == IPPROTO_ROUTING) |
             BF_IPV6_EH_FRAGMENT(next_hdr_type == IPPROTO_FRAGMENT) |
             BF_IPV6_EH_AH(next_hdr_type == IPPROTO_AH) |
             BF_IPV6_EH_DSTOPTS(next_hdr_type == IPPROTO_DSTOPTS) |
             BF_IPV6_EH_MH(next_hdr_type == IPPROTO_MH));

        if (next_hdr_type == IPPROTO_AH) {
            offset = EH_AH_OFFSET;
            shift = EH_AH_SHIFT;
        } else if (next_hdr_type == IPPROTO_FRAGMENT) {
            // Fixed size: the second byte is reserved, not a length
            hdrlen = 0;
            offset = EH_FRAG_OFFSET;
            shift = EH_FRAG_SHIFT;
        } else {
            offset = EH_COMMON_OFFSET;
            shift = EH_COMMON_SHIFT;
        }

        ctx->l4_offset += (hdrlen + offset) << shift;
        next_hdr_type = ext->nexthdr;
    }

    return BF_IPV6_EH_TOO_MANY;
}
