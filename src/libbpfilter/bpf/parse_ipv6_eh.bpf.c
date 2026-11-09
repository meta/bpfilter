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

__u8 bf_parse_ipv6(struct bf_runtime *ctx)
{
    struct ipv6hdr *ip6hdr = ctx->l3_hdr;
    __u8 next_hdr_type = ip6hdr->nexthdr;

    ctx->l4_offset = ctx->l3_offset + sizeof(struct ipv6hdr);

    // Walk one header past the cap to detect packets with too many headers
    for (int i = 0; i <= BF_IPV6_EH_MAX; ++i) {
        struct ipv6_opt_hdr _ext;
        struct ipv6_opt_hdr *ext =
            bpf_dynptr_slice(&ctx->dynptr, ctx->l4_offset, &_ext, sizeof(_ext));
        if (!ext)
            return 0;

        switch (next_hdr_type) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_MH:
            next_hdr_type = ext->nexthdr;
            ctx->l4_offset += (ext->hdrlen + 1) * 8;
            break;
        case IPPROTO_AH:
            next_hdr_type = ext->nexthdr;
            ctx->l4_offset += (ext->hdrlen + 2) * 4;
            break;
        case IPPROTO_FRAGMENT:
            // Fixed size: the second byte is reserved, not a length
            next_hdr_type = ext->nexthdr;
            ctx->l4_offset += 8;
            break;
        default:
            return next_hdr_type;
        }
    }

    return BF_IPV6_EH_TOO_MANY;
}
