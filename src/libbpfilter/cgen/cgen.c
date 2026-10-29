/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgen.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>

#include "cgen/codegen.h"
#include "cgen/dump.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "core/lock.h"
#include "state.h"

#define _BF_PROG_NAME "bf_prog"

int bf_cgen_new_from_dir_fd(struct bf_cgen **cgen, struct bf_lock *lock)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    int r;

    assert(cgen);
    assert(lock);

    _cgen = calloc(1, sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    r = bf_state_restore(lock, &_cgen->chain, &_cgen->handle);
    if (r)
        return r;

    *cgen = TAKE_PTR(_cgen);
    return 0;
}

int bf_cgen_new(struct bf_cgen **cgen, struct bf_chain **chain)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    int r;

    assert(cgen);
    assert(chain);

    _cgen = calloc(1, sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    _cgen->chain = TAKE_PTR(*chain);

    r = bf_handle_new(&_cgen->handle, _BF_PROG_NAME);
    if (r)
        return r;

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

void bf_cgen_free(struct bf_cgen **cgen)
{
    assert(cgen);

    if (!*cgen)
        return;

    bf_handle_free(&(*cgen)->handle);
    bf_chain_free(&(*cgen)->chain);

    free(*cgen);
    *cgen = NULL;
}

int bf_cgen_pack(const struct bf_cgen *cgen, bf_wpack_t *pack)
{
    assert(cgen);
    assert(pack);

    return bf_state_pack(cgen->chain, cgen->handle, pack);
}

void bf_cgen_dump(const struct bf_cgen *cgen, prefix_t *prefix)
{
    assert(cgen);
    assert(prefix);

    DUMP(prefix, "struct bf_cgen at %p", cgen);

    bf_dump_prefix_push(prefix);

    // Chain
    DUMP(prefix, "chain: struct bf_chain *");
    bf_dump_prefix_push(prefix);
    bf_chain_dump(cgen->chain, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "handle: struct bf_handle *");
    bf_dump_prefix_push(prefix);
    bf_handle_dump(cgen->handle, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_cgen_load_counters(struct bf_cgen *cgen)
{
    assert(cgen);

    return bf_handle_load_counters(cgen->handle, cgen->chain);
}

int bf_cgen_get_counter(const struct bf_cgen *cgen,
                        enum bf_counter_type counter_idx,
                        struct bf_counter *counter)
{
    assert(cgen);
    assert(counter);

    /* There are two more counter than rules. The special counters must
     * be accessed via the specific values, to avoid confusion. */
    enum bf_counter_type rule_count = bf_list_size(&cgen->chain->rules);
    if (counter_idx == BF_COUNTER_POLICY) {
        counter_idx = rule_count;
    } else if (counter_idx == BF_COUNTER_ERRORS) {
        counter_idx = rule_count + 1;
    } else if (counter_idx < 0 || counter_idx >= rule_count) {
        return -EINVAL;
    }

    return bf_handle_get_counter(cgen->handle, counter_idx, counter);
}

int bf_cgen_set(struct bf_cgen *cgen, struct bf_hookopts **hookopts,
                struct bf_lock *lock)
{
    _free_bf_codegen_ struct bf_codegen *prog = NULL;
    int r;

    assert(cgen);
    assert(lock);

    r = bf_codegen_new(&prog, cgen->chain, cgen->handle);
    if (r < 0)
        return r;

    r = bf_codegen_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_codegen");

    r = bf_codegen_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    if (hookopts) {
        r = bf_handle_attach(cgen->handle, cgen->chain->hook, hookopts);
        if (r < 0)
            return bf_err_r(r, "failed to load and attach the chain");
    }

    r = bf_handle_pin(cgen->handle, lock);
    if (r)
        return r;

    r = bf_state_persist(lock, cgen->chain, cgen->handle);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    return 0;
}

int bf_cgen_load(struct bf_cgen *cgen, struct bf_lock *lock)
{
    _free_bf_codegen_ struct bf_codegen *prog = NULL;
    int r;

    assert(cgen);
    assert(lock);

    r = bf_codegen_new(&prog, cgen->chain, cgen->handle);
    if (r < 0)
        return r;

    r = bf_codegen_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_codegen");

    r = bf_codegen_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    r = bf_handle_pin(cgen->handle, lock);
    if (r)
        return r;

    r = bf_state_persist(lock, cgen->chain, cgen->handle);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    bf_info("load %s", cgen->chain->name);

    if (bf_log_get_level() == BF_LOG_DBG)
        bf_cgen_dump(cgen, EMPTY_PREFIX);

    return 0;
}

int bf_cgen_attach(struct bf_cgen *cgen, struct bf_hookopts **hookopts,
                   struct bf_lock *lock)
{
    int r;

    assert(cgen);
    assert(hookopts);
    assert(lock);

    bf_info("attaching %s to %s", cgen->chain->name,
            bf_hook_to_str(cgen->chain->hook));
    bf_hookopts_dump(*hookopts, EMPTY_PREFIX);

    r = bf_handle_attach(cgen->handle, cgen->chain->hook, hookopts);
    if (r < 0)
        return bf_err_r(r, "failed to attach chain '%s'", cgen->chain->name);

    r = bf_link_pin(cgen->handle->link, lock);
    if (r) {
        bf_handle_detach(cgen->handle);
        return r;
    }

    r = bf_state_persist(lock, cgen->chain, cgen->handle);
    if (r) {
        bf_link_unpin(cgen->handle->link, lock);
        bf_handle_detach(cgen->handle);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    return r;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain,
                   uint32_t flags, struct bf_lock *lock)
{
    _free_bf_codegen_ struct bf_codegen *new_prog = NULL;
    _free_bf_handle_ struct bf_handle *new_handle = NULL;
    struct bf_handle *old_handle;
    int r;

    assert(cgen);
    assert(new_chain);
    assert(lock);

    if (flags & ~BF_FLAGS_MASK(_BF_CGEN_UPDATE_MAX))
        return bf_err_r(-EINVAL, "unknown update flags: 0x%x", flags);

    old_handle = cgen->handle;

    r = bf_handle_new(&new_handle, _BF_PROG_NAME);
    if (r)
        return r;

    r = bf_codegen_new(&new_prog, *new_chain, new_handle);
    if (r < 0)
        return bf_err_r(r, "failed to create a new bf_codegen");

    r = bf_codegen_generate(new_prog);
    if (r < 0) {
        return bf_err_r(r,
                        "failed to generate the bytecode for a new bf_codegen");
    }

    r = bf_codegen_load(new_prog);
    if (r)
        return bf_err_r(r, "failed to load new program");

    if (flags & BF_FLAG(BF_CGEN_UPDATE_PRESERVE_COUNTERS)) {
        if (bf_list_size(&cgen->chain->rules) !=
            bf_list_size(&(*new_chain)->rules)) {
            return bf_err_r(-EINVAL,
                            "rule count mismatch for counter transfer");
        }

        r = bf_handle_copy_counters(old_handle, new_handle,
                                    bf_list_size(&(*new_chain)->rules));
        if (r)
            return bf_err_r(r, "failed to transfer counters");
    }

    bf_handle_unpin(old_handle, lock);

    if (old_handle->link) {
        r = bf_link_update(old_handle->link, new_handle->prog_fd);
        if (r) {
            bf_err_r(r, "failed to update bf_link object with new program");
            if (bf_handle_pin(old_handle, lock) < 0)
                bf_err("failed to repin old handle, ignoring");
            return r;
        }

        // We updated the old link, we need to store it in the new handle
        bf_swap(new_handle->link, old_handle->link);
    }

    bf_swap(cgen->handle, new_handle);

    r = bf_handle_pin(cgen->handle, lock);
    if (r)
        return bf_err_r(r, "failed to pin new handle");

    r = bf_state_persist(lock, cgen->chain, cgen->handle);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    bf_chain_free(&cgen->chain);
    cgen->chain = TAKE_PTR(*new_chain);

    r = bf_state_persist(lock, cgen->chain, cgen->handle);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    return 0;
}

void bf_cgen_detach(struct bf_cgen *cgen)
{
    assert(cgen);

    bf_handle_detach(cgen->handle);
}

void bf_cgen_unload(struct bf_cgen *cgen, struct bf_lock *lock)
{
    assert(cgen);
    assert(lock);

    /* The chain's pin directory will be removed by bf_lock_release_chain()
     * if a `BF_LOCK_WRITE` lock is held. */
    unlinkat(lock->chain_fd, BF_STATE_PIN_NAME, 0);
    bf_handle_unpin(cgen->handle, lock);
    bf_handle_unload(cgen->handle);
}
