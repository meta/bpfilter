/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/ctx.h>

#include "bpfilter/chain.h"
#include "bpfilter/core/list.h"
#include "bpfilter/counter.h"
#include "bpfilter/helper.h"
#include "bpfilter/hook.h"
#include "bpfilter/logger.h"
#include "bpfilter/set.h"
#include "cgen/cgen.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "core/lock.h"
#include "state.h"

static int copy_hookopts(struct bf_hookopts **dest,
                         const struct bf_hookopts *src)
{
    struct bf_hookopts *copy;

    copy = bf_memdup(src, sizeof(*src));
    if (!copy)
        return -ENOMEM;

    if (src->cgpath) {
        copy->cgpath = strdup(src->cgpath);
        if (!copy->cgpath) {
            free(copy);
            return -ENOMEM;
        }
    }

    *dest = copy;

    return 0;
}

static void _bf_chain_unload(struct bf_handle *handle, struct bf_lock *lock)
{
    // The lock cleanup removes an empty chain directory under a WRITE lock.
    unlinkat(lock->chain_fd, BF_STATE_PIN_NAME, 0);
    bf_handle_unpin(handle, lock);
    bf_handle_unload(handle);
}

/**
 * @brief Unload every chain currently pinned in the pin directory.
 *
 * The caller must already hold a `BF_LOCK_WRITE` lock on the pin directory
 * (typically via `bf_lock_init(BF_LOCK_WRITE)`). For each chain entry, a
 * per-chain `BF_LOCK_WRITE` lock is acquired (so the chain dir is removed
 * by `bf_lock_release_chain` after unload).
 */
static int _bf_ruleset_flush(struct bf_lock *lock)
{
    _free_bf_list_ bf_list *cgens = NULL;
    int r;

    assert(lock);

    r = bf_ctx_get_cgens(lock, &cgens);
    if (r)
        return bf_err_r(r, "failed to discover chains during flush");

    bf_list_foreach (cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        r = bf_lock_acquire_chain(lock, cgen->chain->name, BF_LOCK_WRITE,
                                  false);
        if (r) {
            bf_warn_r(
                r,
                "failed to acquire WRITE lock on chain '%s' during flush, skipping",
                cgen->chain->name);
            continue;
        }

        bf_cgen_unload(cgen, lock);
        bf_lock_release_chain(lock);
    }

    return 0;
}

int bf_ruleset_get(bf_list *chains, bf_list *hookopts)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_list_ bf_list *cgens = NULL;
    _clean_bf_list_ bf_list _chains = bf_list_default_from(*chains);
    _clean_bf_list_ bf_list _hookopts = bf_list_default_from(*hookopts);
    int r;

    r = bf_lock_init(&lock, BF_LOCK_READ);
    if (r)
        return bf_err_r(r, "failed to acquire READ lock for ruleset get");

    r = bf_ctx_get_cgens(&lock, &cgens);
    if (r < 0)
        return bf_err_r(r, "failed to get cgen list");

    bf_list_foreach (cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);
        _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;

        r = bf_cgen_load_counters(cgen);
        if (r) {
            return bf_err_r(r, "failed to read counters for '%s'",
                            cgen->chain->name);
        }

        // cgen will be destroyed, we can steal the chain
        r = bf_list_push(&_chains, (void **)&cgen->chain);
        if (r)
            return r;

        if (cgen->handle->link && cgen->handle->link->hookopts) {
            r = copy_hookopts(&hookopts_copy, cgen->handle->link->hookopts);
            if (r)
                return bf_err_r(r, "failed to copy hookopts");
        }
        r = bf_list_add_tail(&_hookopts, hookopts_copy);
        if (r)
            return r;
        TAKE_PTR(hookopts_copy);
    }

    *chains = bf_list_move(&_chains);
    *hookopts = bf_list_move(&_hookopts);

    return 0;
}

int bf_ruleset_set(bf_list *chains, bf_list *hookopts)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    struct bf_list_node *chain_node = bf_list_get_head(chains);
    struct bf_list_node *hookopts_node = bf_list_get_head(hookopts);
    int r;

    if (bf_list_size(chains) != bf_list_size(hookopts))
        return -EINVAL;

    r = bf_lock_init(&lock, BF_LOCK_WRITE);
    if (r)
        return bf_err_r(r, "failed to acquire WRITE lock for ruleset set");

    r = _bf_ruleset_flush(&lock);
    if (r)
        return r;

    while (chain_node && hookopts_node) {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;
        _free_bf_chain_ struct bf_chain *chain_copy = NULL;
        _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        struct bf_hookopts *node_hookopts =
            bf_list_node_get_data(hookopts_node);

        r = bf_chain_new_from_copy(&chain_copy, chain);
        if (r)
            goto err_load;

        if (node_hookopts) {
            r = copy_hookopts(&hookopts_copy, node_hookopts);
            if (r)
                goto err_load;
        }

        r = bf_cgen_new(&cgen, &chain_copy);
        if (r)
            goto err_load;

        r = bf_lock_acquire_chain(&lock, cgen->chain->name, BF_LOCK_WRITE,
                                  true);
        if (r) {
            bf_err_r(r, "failed to acquire WRITE lock on chain '%s'",
                     cgen->chain->name);
            goto err_load;
        }

        r = bf_cgen_set(cgen, hookopts_copy ? &hookopts_copy : NULL, &lock);
        if (r) {
            bf_err_r(r, "failed to set chain '%s'", cgen->chain->name);
            bf_lock_release_chain(&lock);
            goto err_load;
        }

        bf_lock_release_chain(&lock);

        chain_node = bf_list_node_next(chain_node);
        hookopts_node = bf_list_node_next(hookopts_node);
    }

    return 0;

err_load:
    _bf_ruleset_flush(&lock);
    return r;
}

int bf_ruleset_flush(void)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    int r;

    r = bf_lock_init(&lock, BF_LOCK_WRITE);
    if (r)
        return bf_err_r(r, "failed to acquire WRITE lock for ruleset flush");

    return _bf_ruleset_flush(&lock);
}

int bf_chain_set(struct bf_chain *chain, struct bf_hookopts *hookopts)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_cgen_ struct bf_cgen *old_cgen = NULL;
    _free_bf_cgen_ struct bf_cgen *new_cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain_copy = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;
    int r;

    assert(chain);

    /* bf_chain_set is a namespace mutator: the previous chain (if any) is
     * destroyed and a fresh one is published under the same name. Take
     * pindir WRITE for the whole operation so the flush-then-load
     * sequence is atomic w.r.t. every other libbpfilter caller. */
    r = bf_lock_init(&lock, BF_LOCK_WRITE);
    if (r)
        return r;

    /* Unload any pre-existing chain under this name, and remove its pindir
     * entry so stage-and-rename can publish the new one. */
    r = bf_lock_acquire_chain(&lock, chain->name, BF_LOCK_WRITE, false);
    if (r == 0) {
        r = bf_ctx_get_cgen(&lock, &old_cgen);
        if (r && r != -ENOENT) {
            bf_lock_release_chain(&lock);
            return r;
        }
        if (old_cgen)
            bf_cgen_unload(old_cgen, &lock);
        /* Release drops the chain flock and (because we held WRITE)
         * removes the now-empty chain dir. */
        bf_lock_release_chain(&lock);
    } else if (r != -ENOENT) {
        return r;
    }

    r = bf_chain_new_from_copy(&chain_copy, chain);
    if (r)
        return r;

    if (hookopts) {
        r = copy_hookopts(&hookopts_copy, hookopts);
        if (r)
            return r;
    }

    r = bf_cgen_new(&new_cgen, &chain_copy);
    if (r)
        return r;

    /* Create the new chain dir via stage-and-rename (I3). */
    r = bf_lock_acquire_chain(&lock, chain->name, BF_LOCK_WRITE, true);
    if (r)
        return r;

    return bf_cgen_set(new_cgen, hookopts_copy ? &hookopts_copy : NULL, &lock);
}

int bf_chain_get(const char *name, struct bf_chain **chain,
                 struct bf_hookopts **hookopts)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_hookopts_ struct bf_hookopts *_hookopts = NULL;
    int r;

    assert(name);
    assert(chain);
    assert(hookopts);

    r = bf_lock_init_for_chain(&lock, name, BF_LOCK_READ, BF_LOCK_READ, false);
    if (r)
        return r;

    r = bf_state_restore(&lock, &_chain, &handle);
    if (r)
        return r;

    r = bf_handle_load_counters(handle, _chain);
    if (r)
        return bf_err_r(r, "failed to load counters for '%s'", _chain->name);

    if (handle->link && handle->link->hookopts) {
        r = copy_hookopts(&_hookopts, handle->link->hookopts);
        if (r)
            return r;
    }

    *chain = TAKE_PTR(_chain);
    *hookopts = TAKE_PTR(_hookopts);

    return 0;
}

int bf_chain_prog_fd(const char *name)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    int r;

    assert(name);

    r = bf_lock_init_for_chain(&lock, name, BF_LOCK_READ, BF_LOCK_READ, false);
    if (r)
        return r;

    r = bf_state_restore(&lock, &chain, &handle);
    if (r)
        return r;

    if (handle->prog_fd == -1)
        return bf_err_r(-ENODEV, "chain '%s' has no loaded program", name);

    return dup(handle->prog_fd);
}

int bf_chain_logs_fd(const char *name)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    int r;

    assert(name);

    r = bf_lock_init_for_chain(&lock, name, BF_LOCK_READ, BF_LOCK_READ, false);
    if (r)
        return r;

    r = bf_state_restore(&lock, &chain, &handle);
    if (r)
        return r;

    if (!handle->lmap)
        return bf_err_r(-ENOENT, "chain '%s' has no logs buffer", name);

    return dup(handle->lmap->fd);
}

int bf_chain_load(struct bf_chain *chain)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain_copy = NULL;
    int r;

    assert(chain);

    /* chain_load is a namespace mutator: pindir WRITE + chain WRITE on the
     * staged inode. Stage-and-rename (I3) returns `-EEXIST` if another
     * creator already claimed the name, which replaces the former
     * check-then-create sequence atomically. */
    r = bf_lock_init_for_chain(&lock, chain->name, BF_LOCK_WRITE, BF_LOCK_WRITE,
                               true);
    if (r)
        return r;

    r = bf_chain_new_from_copy(&chain_copy, chain);
    if (r)
        return r;

    r = bf_cgen_new(&cgen, &chain_copy);
    if (r)
        return r;

    return bf_cgen_load(cgen, &lock);
}

int bf_chain_attach(const char *name, const struct bf_hookopts *hookopts)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;
    int r;

    assert(name);
    assert(hookopts);

    r = bf_lock_init_for_chain(&lock, name, BF_LOCK_READ, BF_LOCK_WRITE, false);
    if (r)
        return r;

    r = bf_state_restore(&lock, &chain, &handle);
    if (r)
        return r;

    if (handle->link)
        return bf_err_r(-EBUSY, "chain '%s' is already linked to a hook", name);

    r = bf_hookopts_validate(hookopts, chain->hook);
    if (r)
        return bf_err_r(r, "failed to validate hook options");

    r = copy_hookopts(&hookopts_copy, hookopts);
    if (r)
        return r;

    bf_info("attaching %s to %s", chain->name, bf_hook_to_str(chain->hook));
    bf_hookopts_dump(hookopts_copy, EMPTY_PREFIX);

    r = bf_handle_attach(handle, chain->hook, &hookopts_copy);
    if (r)
        return bf_err_r(r, "failed to attach chain '%s'", name);

    r = bf_link_pin(handle->link, &lock);
    if (r) {
        bf_handle_detach(handle);
        return r;
    }

    r = bf_state_persist(&lock, chain, handle);
    if (r) {
        bf_link_unpin(handle->link, &lock);
        bf_handle_detach(handle);
        return bf_err_r(r, "failed to persist chain '%s'", name);
    }

    return 0;
}

int bf_chain_update(const struct bf_chain *chain)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *chain_copy = NULL;
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    int r;

    assert(chain);

    r = bf_lock_init_for_chain(&lock, chain->name, BF_LOCK_READ, BF_LOCK_WRITE,
                               false);
    if (r)
        return r;

    r = bf_ctx_get_cgen(&lock, &cgen);
    if (r)
        return r;

    if (chain->hook != cgen->chain->hook) {
        return bf_err_r(
            -EINVAL,
            "can't update chain '%s': hook %s doesn't match the existing hook %s",
            chain->name, bf_hook_to_str(chain->hook),
            bf_hook_to_str(cgen->chain->hook));
    }

    r = bf_chain_new_from_copy(&chain_copy, chain);
    if (r)
        return r;

    return bf_cgen_update(cgen, &chain_copy, 0, &lock);
}

int bf_chain_update_set(const char *name, const struct bf_set *to_add,
                        const struct bf_set *to_remove)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *new_chain = NULL;
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    int r;

    assert(name);
    assert(to_add);
    assert(to_remove);

    if (!bf_streq(to_add->name, to_remove->name))
        return bf_err_r(-EINVAL, "to_add->name must match to_remove->name");

    r = bf_lock_init_for_chain(&lock, name, BF_LOCK_READ, BF_LOCK_WRITE, false);
    if (r)
        return r;

    r = bf_ctx_get_cgen(&lock, &cgen);
    if (r)
        return r;

    r = bf_chain_new_from_copy(&new_chain, cgen->chain);
    if (r)
        return r;

    r = bf_chain_apply_set_delta(new_chain, to_add->name, to_add, to_remove);
    if (r)
        return r;

    r = bf_cgen_update(cgen, &new_chain,
                       BF_FLAGS(BF_CGEN_UPDATE_PRESERVE_COUNTERS,
                                BF_CGEN_UPDATE_PRESERVE_LOGS),
                       &lock);
    if (r)
        return bf_err_r(r, "failed to update chain with new set data");

    return 0;
}

int bf_chain_flush(const char *name)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    int r;

    assert(name);

    /* chain_flush removes the chain dir from the pindir namespace, so it
     * needs pindir WRITE (I2). */
    r = bf_lock_init_for_chain(&lock, name, BF_LOCK_WRITE, BF_LOCK_WRITE,
                               false);
    if (r)
        return r;

    r = bf_state_restore(&lock, &chain, &handle);
    if (r)
        return r;

    _bf_chain_unload(handle, &lock);

    return 0;
}
