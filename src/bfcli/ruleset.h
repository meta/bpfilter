
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/hook.h>
#include <bpfilter/limit.h>
#include <bpfilter/set.h>

#define bfc_ruleset_default()                                                  \
    {                                                                          \
        .chains = bf_list_default(bf_chain_free, bf_chain_pack),               \
        .sets = bf_set_hashset_default(),                                      \
        .limits = bf_list_default(bf_limit_free, bf_limit_pack),               \
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_pack),       \
    }

#define _clean_bfc_ruleset_ __attribute__((__cleanup__(bfc_ruleset_clean)))

struct bfc_ruleset
{
    bf_list chains;
    bf_hashset sets;
    bf_list hookopts;
    bf_list limits;
};

struct bfc_opts;

void bfc_ruleset_clean(struct bfc_ruleset *ruleset);

int bfc_ruleset_set(const struct bfc_opts *opts);
int bfc_ruleset_get(const struct bfc_opts *opts);
int bfc_ruleset_flush(const struct bfc_opts *opts);
