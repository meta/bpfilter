/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "state.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/chain.h>
#include <bpfilter/ctx.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#include "cgen/handle.h"
#include "cgen/prog/map.h"
#include "core/lock.h"

#define _BF_STATE_TMP_PIN_NAME "bf_ctx_tmp"

static void _bf_state_free_dir(DIR **dir)
{
    if (*dir)
        closedir(*dir);
}

#define _free_dir_ __attribute__((cleanup(_bf_state_free_dir)))

int bf_state_pack(const struct bf_chain *chain, const struct bf_handle *handle,
                  bf_wpack_t *pack)
{
    assert(chain);
    assert(handle);
    assert(pack);

    bf_wpack_open_object(pack, "chain");
    bf_chain_pack(chain, pack);
    bf_wpack_close_object(pack);

    bf_wpack_open_object(pack, "handle");
    bf_handle_pack(handle, pack);
    bf_wpack_close_object(pack);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

int bf_state_persist(struct bf_lock *lock, const struct bf_chain *chain,
                     const struct bf_handle *handle)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    _free_bf_map_ struct bf_map *map = NULL;
    const void *data;
    size_t data_len;
    uint32_t key = 0;
    int dir_fd;
    int r;

    assert(lock);
    assert(chain);
    assert(handle);

    dir_fd = lock->chain_fd;

    r = bf_wpack_new(&pack);
    if (r)
        return bf_err_r(r, "failed to create wpack for chain state");

    r = bf_state_pack(chain, handle, pack);
    if (r)
        return bf_err_r(r, "failed to pack chain state");

    r = bf_wpack_get_data(pack, &data, &data_len);
    if (r)
        return bf_err_r(r, "failed to get data from chain state wpack");

    r = bf_map_new(&map, BF_STATE_PIN_NAME, BF_MAP_TYPE_CTX, sizeof(uint32_t),
                   data_len, 1);
    if (r)
        return bf_err_r(r, "failed to create context map");

    r = bf_map_set_elem(map, &key, (void *)data);
    if (r)
        return bf_err_r(r, "failed to write context to map");

    // Remove stale temporary pin if present.
    unlinkat(dir_fd, _BF_STATE_TMP_PIN_NAME, 0);

    r = bf_bpf_obj_pin(_BF_STATE_TMP_PIN_NAME, map->fd, dir_fd);
    if (r)
        return bf_err_r(r, "failed to pin context map");

    r = renameat(dir_fd, _BF_STATE_TMP_PIN_NAME, dir_fd, BF_STATE_PIN_NAME);
    if (r) {
        r = -errno;
        unlinkat(dir_fd, _BF_STATE_TMP_PIN_NAME, 0);
        return bf_err_r(r, "failed to atomically replace context map pin");
    }

    return 0;
}

static int _bf_state_unpack(struct bf_lock *lock, bf_rpack_node_t node,
                            struct bf_chain **chain, struct bf_handle **handle)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    _free_bf_handle_ struct bf_handle *_handle = NULL;
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_obj(node, "chain", &child);
    if (r)
        return bf_rpack_key_err(r, "state.chain");

    r = bf_chain_new_from_pack(&_chain, child);
    if (r)
        return bf_rpack_key_err(r, "state.chain");

    r = bf_rpack_kv_node(node, "handle", &child);
    if (r)
        return bf_rpack_key_err(r, "state.handle");

    r = bf_handle_new_from_pack(&_handle, lock, child);
    if (r)
        return r;

    *chain = TAKE_PTR(_chain);
    *handle = TAKE_PTR(_handle);

    return 0;
}

int bf_state_restore(struct bf_lock *lock, struct bf_chain **chain,
                     struct bf_handle **handle)
{
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_close_ int map_fd = -1;
    _cleanup_free_ void *data = NULL;
    struct bpf_map_info info;
    uint32_t key = 0;
    int r;

    assert(chain);
    assert(handle);
    assert(lock);

    if (!bf_ctx_is_setup())
        return bf_err_r(-EINVAL, "context is not initialized");

    r = bf_bpf_obj_get(BF_STATE_PIN_NAME, lock->chain_fd, &map_fd);
    if (r < 0) {
        return bf_err_r(r, "failed to open pinned context map of chain '%s'",
                        lock->chain_name);
    }

    r = bf_bpf_map_get_info(map_fd, &info);
    if (r) {
        return bf_err_r(r, "failed to get context map info of chain '%s'",
                        lock->chain_name);
    }

    if (info.value_size == 0) {
        return bf_err_r(-EINVAL,
                        "invalid serialized context size for chain '%s'",
                        lock->chain_name);
    }

    data = malloc(info.value_size);
    if (!data)
        return -ENOMEM;

    r = bf_bpf_map_lookup_elem(map_fd, &key, data);
    if (r) {
        return bf_err_r(r, "failed to read context of chain '%s' from map",
                        lock->chain_name);
    }

    r = bf_rpack_new(&pack, data, info.value_size);
    if (r) {
        return bf_err_r(r, "failed to create rpack for state of chain '%s'",
                        lock->chain_name);
    }

    r = _bf_state_unpack(lock, bf_rpack_root(pack), chain, handle);
    if (r) {
        return bf_err_r(r, "failed to deserialize state of chain '%s'",
                        lock->chain_name);
    }

    return 0;
}

int bf_state_discover(struct bf_lock *lock, bf_list **chains, bf_list **handles)
{
    _free_bf_list_ bf_list *_chains = NULL;
    _free_bf_list_ bf_list *_handles = NULL;
    _free_dir_ DIR *dir = NULL;
    struct dirent *entry;
    int iter_fd;
    int r;

    assert(lock);
    assert(chains);
    assert(handles);

    if (!bf_ctx_is_setup())
        return bf_err_r(-EINVAL, "context is not initialized");

    r = bf_list_new(&_chains,
                    &bf_list_ops_default(bf_chain_free, bf_chain_pack));
    if (r)
        return bf_err_r(r, "failed to allocate chain list");

    r = bf_list_new(&_handles,
                    &bf_list_ops_default(bf_handle_free, bf_handle_pack));
    if (r)
        return bf_err_r(r, "failed to allocate handle list");

    /* fdopendir() takes ownership of the fd: dup so lock->pindir_fd remains
     * valid for further uses. */
    iter_fd = dup(lock->pindir_fd);
    if (iter_fd < 0)
        return bf_err_r(-errno, "failed to dup pin directory fd");

    dir = fdopendir(iter_fd);
    if (!dir) {
        r = -errno;
        close(iter_fd);
        return bf_err_r(r, "failed to open pin directory for iteration");
    }

    while (true) {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _free_bf_handle_ struct bf_handle *handle = NULL;

        errno = 0;
        entry = readdir(dir);
        if (!entry && errno != 0) {
            bf_warn_r(errno, "readdir failed, returning partial results");
            break;
        }
        if (!entry)
            break;

        if (bf_streq(entry->d_name, ".") || bf_streq(entry->d_name, ".."))
            continue;

        if (entry->d_type != DT_DIR)
            continue;

        /* Skip in-flight staging directories owned by concurrent writers. */
        if (bf_strneq(entry->d_name, BF_LOCK_STAGING_PREFIX,
                      sizeof(BF_LOCK_STAGING_PREFIX) - 1))
            continue;

        r = bf_lock_acquire_chain(lock, entry->d_name, BF_LOCK_READ, false);
        if (r) {
            bf_warn_r(r, "failed to acquire READ lock on chain '%s', skipping",
                      entry->d_name);
            continue;
        }

        r = bf_state_restore(lock, &chain, &handle);
        if (r) {
            bf_warn_r(r, "failed to restore chain '%s', skipping",
                      entry->d_name);
            bf_lock_release_chain(lock);
            continue;
        }

        bf_lock_release_chain(lock);

        r = bf_list_push(_chains, (void **)&chain);
        if (r) {
            bf_warn_r(r, "failed to push chain '%s' to list, skipping",
                      entry->d_name);
            continue;
        }

        r = bf_list_push(_handles, (void **)&handle);
        if (r) {
            bf_list_delete(_chains, bf_list_get_tail(_chains));
            bf_warn_r(r, "failed to push handle '%s' to list, skipping",
                      entry->d_name);
        }
    }

    *chains = TAKE_PTR(_chains);
    *handles = TAKE_PTR(_handles);

    return 0;
}
