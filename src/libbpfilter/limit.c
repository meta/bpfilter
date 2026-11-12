/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/limit.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"

int bf_ratelimit_new(struct bf_ratelimit **ratelimit, uint32_t limit,
                     uint32_t duration)
{
    _free_bf_ratelimit_ struct bf_ratelimit *_ratelimit = NULL;

    assert(ratelimit);

    _ratelimit = calloc(1, sizeof(*_ratelimit));
    if (!_ratelimit)
        return -ENOMEM;

    _ratelimit->limit = limit;
    _ratelimit->duration = duration;

    *ratelimit = TAKE_PTR(_ratelimit);

    return 0;
}

int bf_ratelimit_new_from_raw(struct bf_ratelimit **ratelimit,
                              const char *raw_payload)
{
    _free_bf_ratelimit_ struct bf_ratelimit *_ratelimit = NULL;
    char *endptr;
    uint32_t limit;
    uint32_t duration;
    unsigned long parsed;
    int r;

    assert(ratelimit);
    assert(raw_payload);

    errno = 0;
    parsed = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (errno != 0 || endptr[0] != '/' || endptr[1] != 's' ||
        endptr[2] != '\0' || parsed > UINT32_MAX)
        return bf_err_r(-EINVAL, "limit is not valid '%s'", raw_payload);
    limit = (uint32_t)parsed;

    duration = (uint32_t)BF_TIME_S;
    r = bf_ratelimit_new(&_ratelimit, limit, duration);
    if (r)
        return r;

    *ratelimit = TAKE_PTR(_ratelimit);

    return 0;
}

void bf_ratelimit_free(struct bf_ratelimit **ratelimit)
{
    assert(ratelimit);

    if (!*ratelimit)
        return;

    BF_FREEP(ratelimit);
}

int bf_ratelimit_new_from_pack(struct bf_ratelimit **ratelimit,
                               bf_rpack_node_t node)
{
    _free_bf_ratelimit_ struct bf_ratelimit *_ratelimit = NULL;
    bf_rpack_node_t child;
    uint32_t limit = 0;
    uint32_t duration = 0;
    int r;

    assert(ratelimit);

    r = bf_rpack_kv_node(node, "limit", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_limit.limit");
    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_u32(child, &limit);
        if (r)
            return bf_err_r(
                r, "failed to read ratelimit limit from bf_limit.limit pack");
    }

    r = bf_rpack_kv_node(node, "duration", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_limit.duration");
    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_u32(child, &duration);
        if (r) {
            return bf_err_r(
                r,
                "failed to read ratelimit duration from bf_limit.duration pack");
        }
    }

    r = bf_ratelimit_new(&_ratelimit, limit, duration);
    if (r)
        return bf_err_r(r, "failed to create bf_ratelimit from pack");

    *ratelimit = TAKE_PTR(_ratelimit);

    return 0;
}

int bf_ratelimit_pack(const struct bf_ratelimit *ratelimit, bf_wpack_t *pack)
{
    assert(ratelimit);
    assert(pack);

    bf_wpack_kv_u32(pack, "duration", ratelimit->duration);
    bf_wpack_kv_u32(pack, "limit", ratelimit->limit);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

int bf_ratelimit_new_from_copy(struct bf_ratelimit **dest,
                               const struct bf_ratelimit *src)
{
    _free_bf_ratelimit_ struct bf_ratelimit *copy = NULL;
    int r;

    assert(dest);
    assert(src);

    r = bf_ratelimit_new(&copy, src->limit, src->duration);
    if (r)
        return r;

    *dest = TAKE_PTR(copy);

    return 0;
}
