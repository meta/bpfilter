/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

__u8 bf_ratelimit(void *map, const __u32 limit, __u32 duration, __u32 key)
{
    struct bf_ratelimit *ratelimit;
    __u64 current_time_ns = bpf_ktime_get_ns();

    bpf_printk("%d, %d - %d", limit, duration, key);

    ratelimit = bpf_map_lookup_elem(map, &key);
    if (!ratelimit) {
        bpf_printk("failed to fetch the rule's ratelimit");
        return 1;
    }

    if (current_time_ns > ratelimit->last_time + duration) {
        ratelimit->current = 0;
        ratelimit->last_time = current_time_ns;
    }

    ratelimit->current++;
    return (ratelimit->current > limit);
}
