
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "ruleset.h"

#include <bpfilter/bpfilter.h>

#include "bpfilter/core/list.h"
#include "helper.h"
#include "opts.h"
#include "print.h"

void bfc_ruleset_clean(struct bfc_ruleset *ruleset)
{
    assert(ruleset);

    bf_list_clean(&ruleset->chains);
    bf_list_clean(&ruleset->hookopts);
    bf_list_clean(&ruleset->limits);
    bf_hashset_clean(&ruleset->sets);
}

int bfc_ruleset_set(const struct bfc_opts *opts)
{
    _clean_bfc_ruleset_ struct bfc_ruleset ruleset = bfc_ruleset_default();
    int r;

    if (opts->from_file)
        r = bfc_parse_file(opts->from_file, &ruleset);
    else
        r = bfc_parse_str(opts->from_str, &ruleset);
    if (r)
        return bf_err_r(r, "failed to parse ruleset");

    if (!opts->dry_run) {
        r = bf_ruleset_set(&ruleset.chains, &ruleset.hookopts);
        if (r)
            bf_err_r(r, "failed to set ruleset");
    } else {
        bf_info("--dry-run used, ruleset not applied");
    }

    return r;
}

int bfc_ruleset_get(const struct bfc_opts *opts)
{
    _clean_bf_list_ bf_list chains = bf_list_default(bf_chain_free, NULL);
    _clean_bf_list_ bf_list hookopts = bf_list_default(bf_hookopts_free, NULL);
    int r;

    assert(opts);

    r = bf_ruleset_get(&chains, &hookopts);
    if (r < 0)
        return bf_err_r(r, "failed to request ruleset");

    r = bfc_ruleset_dump(&chains, &hookopts, opts->no_set_content);
    if (r)
        return bf_err_r(r, "failed to dump ruleset");

    return 0;
}

int bfc_ruleset_flush(const struct bfc_opts *opts)
{
    (void)opts;

    return bf_ruleset_flush();
}
