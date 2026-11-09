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

#include "cgen/dump.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/program.h"
#include "core/lock.h"

#define _BF_PROG_NAME "bf_prog"
#define _BF_CTX_PIN_NAME "bf_ctx"
#define _BF_CTX_TMP_PIN_NAME "bf_ctx_tmp"

/**
 * @brief Persist the codegen state to a BPF context map in bpffs.
 *
 * Serializes the cgen, creates a `BPF_MAP_TYPE_ARRAY` map with 1 entry
 * containing the serialized data, pins it as `bf_ctx_tmp`, then atomically
 * renames to `bf_ctx`. The map fd is closed after pinning - this is a
 * one-shot operation.
 *
 * @param cgen Codegen to persist. Can't be NULL.
 * @param dir_fd File descriptor of the chain's bpffs pin directory. Must be
 *        valid.
 * @return 0 on success, or negative errno value on failure.
 */
static int _bf_cgen_persist(const struct bf_cgen *cgen, int dir_fd)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    _free_bf_map_ struct bf_map *map = NULL;
    const void *data;
    size_t data_len;
    uint32_t key = 0;
    int r;

    assert(cgen);

    r = bf_wpack_new(&pack);
    if (r)
        return bf_err_r(r, "failed to create wpack for bf_cgen");

    r = bf_cgen_pack(cgen, pack);
    if (r)
        return bf_err_r(r, "failed to pack bf_cgen");

    r = bf_wpack_get_data(pack, &data, &data_len);
    if (r)
        return bf_err_r(r, "failed to get data from bf_cgen wpack");

    r = bf_map_new(&map, _BF_CTX_PIN_NAME, BF_MAP_TYPE_CTX, sizeof(uint32_t),
                   data_len, 1);
    if (r)
        return bf_err_r(r, "failed to create context map");

    r = bf_map_set_elem(map, &key, (void *)data);
    if (r)
        return bf_err_r(r, "failed to write context to map");

    // Remove stale temporary pin if present.
    unlinkat(dir_fd, _BF_CTX_TMP_PIN_NAME, 0);

    r = bf_bpf_obj_pin(_BF_CTX_TMP_PIN_NAME, map->fd, dir_fd);
    if (r)
        return bf_err_r(r, "failed to pin context map");

    r = renameat(dir_fd, _BF_CTX_TMP_PIN_NAME, dir_fd, _BF_CTX_PIN_NAME);
    if (r) {
        r = -errno;
        unlinkat(dir_fd, _BF_CTX_TMP_PIN_NAME, 0);
        return bf_err_r(r, "failed to atomically replace context map pin");
    }

    return 0;
}

static int _bf_cgen_new_from_pack(struct bf_cgen **cgen, struct bf_lock *lock,
                                  bf_rpack_node_t node)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    bf_rpack_node_t child;
    int r;

    assert(cgen);
    assert(lock);

    _cgen = calloc(1, sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    r = bf_rpack_kv_obj(node, "chain", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_chain_new_from_pack(&_cgen->chain, child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_rpack_kv_node(node, "handle", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.handle");

    r = bf_handle_new_from_pack(&_cgen->handle, lock, child);
    if (r)
        return r;

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

int bf_cgen_new_from_dir_fd(struct bf_cgen **cgen, struct bf_lock *lock)
{
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_close_ int map_fd = -1;
    _cleanup_free_ void *data = NULL;
    struct bpf_map_info info;
    uint32_t key = 0;
    int r;

    assert(cgen);
    assert(lock);

    r = bf_bpf_obj_get(_BF_CTX_PIN_NAME, lock->chain_fd, &map_fd);
    if (r < 0)
        return bf_err_r(r, "failed to open pinned context map");

    r = bf_bpf_map_get_info(map_fd, &info);
    if (r)
        return bf_err_r(r, "failed to get context map info");

    if (info.value_size == 0)
        return bf_err_r(-EINVAL, "invalid serialized context size");

    data = malloc(info.value_size);
    if (!data)
        return -ENOMEM;

    r = bf_bpf_map_lookup_elem(map_fd, &key, data);
    if (r)
        return bf_err_r(r, "failed to read context from map");

    r = bf_rpack_new(&pack, data, info.value_size);
    if (r)
        return bf_err_r(r, "failed to create rpack for bf_cgen");

    r = _bf_cgen_new_from_pack(cgen, lock, bf_rpack_root(pack));
    if (r)
        return bf_err_r(r, "failed to deserialize cgen from context map");

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

    bf_wpack_open_object(pack, "chain");
    bf_chain_pack(cgen->chain, pack);
    bf_wpack_close_object(pack);

    bf_wpack_open_object(pack, "handle");
    bf_handle_pack(cgen->handle, pack);
    bf_wpack_close_object(pack);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
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
    int r;

    assert(cgen);

    bf_list_foreach (&cgen->chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (!rule->has_counters)
            continue;

        r = bf_cgen_get_counter(cgen, rule->index, &rule->counters);
        if (r) {
            return bf_err_r(r, "failed to load counter for rule %u",
                            rule->index);
        }
    }

    r = bf_cgen_get_counter(cgen, BF_COUNTER_POLICY,
                            &cgen->chain->policy_counters);
    if (r) {
        return bf_err_r(r, "failed to load policy counters for '%s'",
                        cgen->chain->name);
    }

    r = bf_cgen_get_counter(cgen, BF_COUNTER_ERRORS,
                            &cgen->chain->error_counters);
    if (r) {
        return bf_err_r(r, "failed to load error counters for '%s'",
                        cgen->chain->name);
    }

    return 0;
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
    _free_bf_program_ struct bf_program *prog = NULL;
    int r;

    assert(cgen);
    assert(lock);

    r = bf_program_new(&prog, cgen->chain, cgen->handle);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
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

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    return 0;
}

int bf_cgen_load(struct bf_cgen *cgen, struct bf_lock *lock)
{
    _free_bf_program_ struct bf_program *prog = NULL;
    int r;

    assert(cgen);
    assert(lock);

    r = bf_program_new(&prog, cgen->chain, cgen->handle);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    r = bf_handle_pin(cgen->handle, lock);
    if (r)
        return r;

    r = _bf_cgen_persist(cgen, lock->chain_fd);
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

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        bf_link_unpin(cgen->handle->link, lock);
        bf_handle_detach(cgen->handle);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    return r;
}

/**
 * @brief Transfer all counters from old handle to new handle.
 *
 * Copies counter values 1:1 for all rule counters plus policy and error
 * counters. The old and new chains must have the same number of rules.
 * Both handles must be loaded.
 *
 * @param old_handle Handle with the source counter map. Can't be NULL.
 * @param new_handle Handle with the destination counter map. Can't be NULL.
 * @param n_rules Number of rules in the chain.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgen_transfer_counters(const struct bf_handle *old_handle,
                                      struct bf_handle *new_handle,
                                      size_t n_rules)
{
    int r;

    assert(old_handle);
    assert(new_handle);

    if (!old_handle->cmap || !new_handle->cmap)
        return bf_err_r(-ENOENT, "missing counter map for counter transfer");

    // n_rules entries for rules, +1 for policy, +1 for errors.
    for (uint32_t i = 0; i < n_rules + 2; ++i) {
        struct bf_counter counter;

        r = bf_handle_get_counter(old_handle, i, &counter);
        if (r)
            return bf_err_r(r, "failed to read counter %u", i);

        if (!counter.count && !counter.size)
            continue;

        r = bf_handle_set_counter(new_handle, i, &counter);
        if (r)
            return bf_err_r(r, "failed to write counter %u", i);
    }

    return 0;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain,
                   uint32_t flags, struct bf_lock *lock)
{
    _free_bf_program_ struct bf_program *new_prog = NULL;
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

    r = bf_program_new(&new_prog, *new_chain, new_handle);
    if (r < 0)
        return bf_err_r(r, "failed to create a new bf_program");

    r = bf_program_generate(new_prog);
    if (r < 0) {
        return bf_err_r(r,
                        "failed to generate the bytecode for a new bf_program");
    }

    if ((flags & BF_FLAG(BF_CGEN_UPDATE_PRESERVE_LOGS)) && old_handle->lmap) {
        r = bf_map_dup(&new_handle->lmap, old_handle->lmap);
        if (r)
            return bf_err_r(r, "failed to reuse the log map");
    }

    r = bf_program_load(new_prog);
    if (r)
        return bf_err_r(r, "failed to load new program");

    if (flags & BF_FLAG(BF_CGEN_UPDATE_PRESERVE_COUNTERS)) {
        if (bf_list_size(&cgen->chain->rules) !=
            bf_list_size(&(*new_chain)->rules)) {
            return bf_err_r(-EINVAL,
                            "rule count mismatch for counter transfer");
        }

        r = _bf_cgen_transfer_counters(old_handle, new_handle,
                                       bf_list_size(&(*new_chain)->rules));
        if (r)
            return bf_err_r(r, "failed to transfer counters");
    }

    bf_handle_unpin(old_handle, lock);

    if (old_handle->link) {
        r = bf_link_update(old_handle->link, new_handle->prog_fd);
        if (r) {
            bf_err_r(r, "failed to update bf_link object with new program");
            goto err_rollback;
        }

        // We updated the old link, we need to store it in the new handle
        bf_swap(new_handle->link, old_handle->link);
    }

    r = bf_handle_pin(new_handle, lock);
    if (r) {
        bf_err_r(r, "failed to pin new handle");
        goto err_rollback;
    }

    r = _bf_cgen_persist(
        &(struct bf_cgen) {.chain = *new_chain, .handle = new_handle},
        lock->chain_fd);
    if (r) {
        bf_err_r(r, "failed to persist cgen for '%s'", (*new_chain)->name);
        bf_handle_unpin(new_handle, lock);
        goto err_rollback;
    }

    bf_swap(cgen->handle, new_handle);
    bf_swap(cgen->chain, *new_chain);

    return 0;

err_rollback:
    // The pinned context is only replaced on success: restore the old handle.
    if (new_handle->link) {
        int err = bf_link_update(new_handle->link, old_handle->prog_fd);
        if (err)
            bf_err_r(err, "failed to restore the old program on the link");

        bf_swap(old_handle->link, new_handle->link);
    }

    if (bf_handle_pin(old_handle, lock) < 0)
        bf_err("failed to repin old handle, ignoring");

    return r;
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
    unlinkat(lock->chain_fd, _BF_CTX_PIN_NAME, 0);
    bf_handle_unpin(cgen->handle, lock);
    bf_handle_unload(cgen->handle);
}
