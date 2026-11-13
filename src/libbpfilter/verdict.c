/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/verdict.h"

#include <errno.h>
#include <stddef.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

static const char *_bf_redirect_dir_strs[] = {
    [BF_REDIRECT_INGRESS] = "in",
    [BF_REDIRECT_EGRESS] = "out",
};
static_assert_enum_mapping(_bf_redirect_dir_strs, _BF_REDIRECT_DIR_MAX);

const char *bf_redirect_dir_to_str(enum bf_redirect_dir dir)
{
    if (dir < 0 || dir >= _BF_REDIRECT_DIR_MAX)
        return "<bf_redirect_dir unknown>";

    return _bf_redirect_dir_strs[dir];
}

int bf_redirect_dir_from_str(const char *str, enum bf_redirect_dir *dir)
{
    assert(dir);

    for (size_t i = 0; i < _BF_REDIRECT_DIR_MAX; ++i) {
        if (bf_streq(_bf_redirect_dir_strs[i], str)) {
            *dir = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_reject_type_strs[] = {
    [BF_REJECT_PORT_UNREACH] = "port-unreachable",
};
static_assert_enum_mapping(_bf_reject_type_strs, _BF_REJECT_TYPE_MAX);

const char *bf_reject_type_to_str(enum bf_reject_type type)
{
    if (type < 0 || type >= _BF_REJECT_TYPE_MAX)
        return "<bf_reject_type unknown>";

    return _bf_reject_type_strs[type];
}

int bf_reject_type_from_str(const char *str, enum bf_reject_type *type)
{
    assert(type);

    for (size_t i = 0; i < _BF_REJECT_TYPE_MAX; ++i) {
        if (bf_streq(_bf_reject_type_strs[i], str)) {
            *type = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_verdict_strs[] = {
    [BF_VERDICT_ACCEPT] = "ACCEPT",     [BF_VERDICT_DROP] = "DROP",
    [BF_VERDICT_REDIRECT] = "REDIRECT", [BF_VERDICT_CONTINUE] = "CONTINUE",
    [BF_VERDICT_NEXT] = "NEXT",         [BF_VERDICT_REJECT] = "REJECT",
};
static_assert_enum_mapping(_bf_verdict_strs, _BF_VERDICT_MAX);

const char *bf_verdict_to_str(enum bf_verdict verdict)
{
    if (verdict < 0 || verdict >= _BF_VERDICT_MAX)
        return "<bf_verdict unknown>";

    return _bf_verdict_strs[verdict];
}

int bf_verdict_from_str(const char *str, enum bf_verdict *verdict)
{
    assert(verdict);

    for (size_t i = 0; i < _BF_VERDICT_MAX; ++i) {
        if (bf_streq(_bf_verdict_strs[i], str)) {
            *verdict = i;
            return 0;
        }
    }

    return -EINVAL;
}

bool bf_verdict_is_valid_policy(enum bf_verdict verdict)
{
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_DROP:
    case BF_VERDICT_NEXT:
        return true;
    default:
        return false;
    }
}
