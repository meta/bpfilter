/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

#define BF_VLAN_MAX_TAGS 16

struct bf_vlan_hdr
{
    __be16 tci;
    __be16 proto;
};

int bf_parse_l2(struct bf_runtime *ctx, __be16 proto)
{
    __u32 offset = ctx->l3_offset;

    for (int i = 0;; ++i) {
        switch (proto) {
        case bpf_htons(ETH_P_8021Q):
        case bpf_htons(ETH_P_8021AD): {
            struct bf_vlan_hdr buf;
            const struct bf_vlan_hdr *tag;

            if (i == BF_VLAN_MAX_TAGS)
                return -1;

            tag = bpf_dynptr_slice(&ctx->dynptr, offset, &buf, sizeof(buf));
            if (!tag)
                return -1;

            // Dispatch on the encapsulated EtherType at the next offset.
            proto = tag->proto;
            offset += sizeof(*tag);
            break;
        }
        default:
            ctx->l3_offset = offset;
            return proto;
        }
    }
}
