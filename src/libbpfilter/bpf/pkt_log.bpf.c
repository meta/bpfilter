/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/errno.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

int bf_pkt_log(struct bf_runtime *ctx, __u32 rule_id, __u8 headers,
               __u32 verdict, __u32 l3_l4_proto)
{
    struct bf_log *log;
    __u16 l3_proto = (__u16)(l3_l4_proto >> 16);
    __u8 l4_proto = (__u8)l3_l4_proto;

    log = bpf_ringbuf_reserve(ctx->log_map, sizeof(struct bf_log), 0);
    if (!log)
        return -ENOMEM;

    log->ts = bpf_ktime_get_ns();
    log->rule_id = rule_id;
    log->verdict = verdict;
    log->l3_proto = bpf_ntohs(l3_proto);
    log->l4_proto = l4_proto;
    log->log_type = BF_LOG_TYPE_PACKET;
    log->pkt.pkt_size = ctx->pkt_size;
    log->pkt.req_headers = headers;
    log->pkt.headers = 0;

    if (headers & (1 << BF_LOG_OPT_LINK) && ctx->l2_hdr &&
        ctx->l2_size <= BF_L2_SLICE_LEN &&
        !bpf_dynptr_read(log->pkt.l2hdr, ctx->l2_size, &ctx->dynptr, 0, 0)) {
        log->pkt.headers |= (1 << BF_LOG_OPT_LINK);
    }

    if (headers & (1 << BF_LOG_OPT_INTERNET) && ctx->l3_hdr &&
        ctx->l3_size <= BF_L3_SLICE_LEN &&
        !bpf_dynptr_read(log->pkt.l3hdr, ctx->l3_size, &ctx->dynptr,
                         ctx->l3_offset, 0)) {
        log->pkt.headers |= (1 << BF_LOG_OPT_INTERNET);
    }

    if (headers & (1 << BF_LOG_OPT_TRANSPORT) && ctx->l4_hdr &&
        ctx->l4_size <= BF_L4_SLICE_LEN &&
        !bpf_dynptr_read(log->pkt.l4hdr, ctx->l4_size, &ctx->dynptr,
                         ctx->l4_offset, 0)) {
        log->pkt.headers |= (1 << BF_LOG_OPT_TRANSPORT);
    }

    bpf_ringbuf_submit(log, 0);

    return 0;
}
