/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/handle.h"

#include <assert.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>

#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "core/lock.h"

#define _BF_LINK_NAME "bf_link"

int bf_handle_new(struct bf_handle **handle, const char *prog_name)
{
    _free_bf_handle_ struct bf_handle *_handle = NULL;

    assert(handle);
    assert(prog_name);

    _handle = calloc(1, sizeof(*_handle));
    if (!_handle)
        return -ENOMEM;

    (void)snprintf(_handle->prog_name, BPF_OBJ_NAME_LEN, "%s", prog_name);
    _handle->prog_fd = -1;
    _handle->sets = bf_list_default(bf_map_free, bf_map_pack);

    *handle = TAKE_PTR(_handle);

    return 0;
}

int bf_handle_new_from_pack(struct bf_handle **handle, struct bf_lock *lock,
                            bf_rpack_node_t node)
{
    _free_bf_handle_ struct bf_handle *_handle = NULL;
    _cleanup_free_ char *name = NULL;
    bf_rpack_node_t child, array_node;
    int dir_fd;
    int r;

    assert(handle);
    assert(lock);

    dir_fd = lock->chain_fd;

    r = bf_rpack_kv_str(node, "prog_name", &name);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.name");

    r = bf_handle_new(&_handle, name);
    if (r)
        return r;

    r = bf_bpf_obj_get(_handle->prog_name, dir_fd, &_handle->prog_fd);
    if (r < 0)
        return bf_err_r(r, "failed to restore bf_handle.prog_fd from pin");

    r = bf_rpack_kv_node(node, "link", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.link");
    if (!bf_rpack_is_nil(child)) {
        r = bf_link_new_from_pack(&_handle->link, dir_fd, child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.link");
    }

    r = bf_rpack_kv_node(node, "cmap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.cmap");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->cmap, dir_fd, child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.cmap");
    }

    r = bf_rpack_kv_node(node, "pmap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.pmap");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->pmap, dir_fd, child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.pmap");
    }

    r = bf_rpack_kv_node(node, "lmap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.lmap");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->lmap, dir_fd, child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.lmap");
    }

    r = bf_rpack_kv_node(node, "smap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.smap");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->smap, dir_fd, child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.smap");
    }

    r = bf_rpack_kv_node(node, "rmap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.rmap");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->rmap, dir_fd, child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.rmap");
    }

    r = bf_rpack_kv_array(node, "sets", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.sets");
    bf_rpack_array_foreach (child, array_node) {
        _free_bf_map_ struct bf_map *map = NULL;

        if (bf_rpack_is_nil(array_node)) {
            r = bf_list_add_tail(&_handle->sets, NULL);
            if (r)
                return r;
            continue;
        }

        r = bf_list_emplace(&_handle->sets, bf_map_new_from_pack, map, dir_fd,
                            array_node);
        if (r)
            return bf_err_r(r, "failed to unpack bf_map into bf_handle.sets");
    }

    *handle = TAKE_PTR(_handle);

    return 0;
}

void bf_handle_free(struct bf_handle **handle)
{
    assert(handle);

    if (!*handle)
        return;

    closep(&(*handle)->prog_fd);

    bf_link_free(&(*handle)->link);
    bf_map_free(&(*handle)->cmap);
    bf_map_free(&(*handle)->pmap);
    bf_map_free(&(*handle)->lmap);
    bf_map_free(&(*handle)->smap);
    bf_map_free(&(*handle)->rmap);
    bf_list_clean(&(*handle)->sets);

    free(*handle);
    *handle = NULL;
}

int bf_handle_pack(const struct bf_handle *handle, bf_wpack_t *pack)
{
    assert(handle);
    assert(pack);

    bf_wpack_kv_str(pack, "prog_name", handle->prog_name);

    if (handle->link) {
        bf_wpack_open_object(pack, "link");
        bf_link_pack(handle->link, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "link");
    }

    if (handle->cmap) {
        bf_wpack_open_object(pack, "cmap");
        bf_map_pack(handle->cmap, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "cmap");
    }

    if (handle->pmap) {
        bf_wpack_open_object(pack, "pmap");
        bf_map_pack(handle->pmap, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "pmap");
    }

    if (handle->lmap) {
        bf_wpack_open_object(pack, "lmap");
        bf_map_pack(handle->lmap, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "lmap");
    }

    if (handle->smap) {
        bf_wpack_open_object(pack, "smap");
        bf_map_pack(handle->smap, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "smap");
    }

    if (handle->rmap) {
        bf_wpack_open_object(pack, "rmap");
        bf_map_pack(handle->rmap, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "rmap");
    }

    bf_wpack_kv_list(pack, "sets", &handle->sets);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix)
{
    assert(handle);
    assert(prefix);

    DUMP(prefix, "struct bf_handle at %p", handle);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "prog_name: %s", handle->prog_name);
    DUMP(prefix, "prog_fd: %d", handle->prog_fd);

    if (handle->link) {
        DUMP(prefix, "link: struct bf_link *");
        bf_dump_prefix_push(prefix);
        bf_link_dump(handle->link, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "link: struct bf_link * (NULL)");
    }

    if (handle->cmap) {
        DUMP(prefix, "cmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->cmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "cmap: struct bf_map * (NULL)");
    }

    if (handle->pmap) {
        DUMP(prefix, "pmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->pmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "pmap: struct bf_map * (NULL)");
    }

    if (handle->lmap) {
        DUMP(prefix, "lmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->lmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "lmap: struct bf_map * (NULL)");
    }

    if (handle->smap) {
        DUMP(prefix, "smap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->smap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "smap: struct bf_map * (NULL)");
    }

    if (handle->rmap) {
        DUMP(prefix, "rmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->rmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "rmap: struct bf_map * (NULL)");
    }

    DUMP(bf_dump_prefix_last(prefix), "sets: bf_list<bf_map>[%lu]",
         bf_list_size(&handle->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&handle->sets, map_node) {
        struct bf_map *map = bf_list_node_get_data(map_node);

        if (bf_list_is_tail(&handle->sets, map_node))
            bf_dump_prefix_last(prefix);

        if (!map) {
            DUMP(prefix, "struct bf_map * (NULL)");
            continue;
        }

        bf_map_dump(map, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_handle_pin(struct bf_handle *handle, struct bf_lock *lock)
{
    int dir_fd;
    int r;

    assert(handle);
    assert(lock);

    dir_fd = lock->chain_fd;

    r = bf_bpf_obj_pin(handle->prog_name, handle->prog_fd, dir_fd);
    if (r) {
        bf_err_r(r, "failed to pin BPF program");
        goto err_unpin_all;
    }

    if (handle->cmap) {
        r = bf_map_pin(handle->cmap, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF counters map");
            goto err_unpin_all;
        }
    }

    if (handle->pmap) {
        r = bf_map_pin(handle->pmap, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF printer map");
            goto err_unpin_all;
        }
    }

    if (handle->lmap) {
        r = bf_map_pin(handle->lmap, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF log map");
            goto err_unpin_all;
        }
    }

    if (handle->smap) {
        r = bf_map_pin(handle->smap, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF state map");
            goto err_unpin_all;
        }
    }

    if (handle->rmap) {
        r = bf_map_pin(handle->rmap, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF rate limit map");
            goto err_unpin_all;
        }
    }

    bf_list_foreach (&handle->sets, set_node) {
        struct bf_map *map = bf_list_node_get_data(set_node);

        if (!map)
            continue;

        r = bf_map_pin(map, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF set map");
            goto err_unpin_all;
        }
    }

    if (handle->link) {
        r = bf_link_pin(handle->link, lock);
        if (r) {
            bf_err_r(r, "failed to pin BPF link");
            goto err_unpin_all;
        }
    }

    return 0;

err_unpin_all:
    bf_handle_unpin(handle, lock);
    return r;
}

void bf_handle_unpin(struct bf_handle *handle, struct bf_lock *lock)
{
    int dir_fd;

    assert(handle);
    assert(lock);

    dir_fd = lock->chain_fd;

    if (handle->cmap)
        bf_map_unpin(handle->cmap, dir_fd);
    if (handle->pmap)
        bf_map_unpin(handle->pmap, dir_fd);
    if (handle->lmap)
        bf_map_unpin(handle->lmap, dir_fd);
    if (handle->smap)
        bf_map_unpin(handle->smap, dir_fd);
    if (handle->rmap)
        bf_map_unpin(handle->rmap, dir_fd);

    bf_list_foreach (&handle->sets, set_node) {
        struct bf_map *map = bf_list_node_get_data(set_node);

        if (!map)
            continue;

        bf_map_unpin(map, dir_fd);
    }

    if (handle->link)
        bf_link_unpin(handle->link, lock);

    unlinkat(dir_fd, handle->prog_name, 0);
}

int bf_handle_get_counter(const struct bf_handle *handle, uint32_t counter_idx,
                          struct bf_counter *counter)
{
    _cleanup_free_ struct bf_counter *percpu = NULL;
    int num_cpus;
    int r;

    assert(handle);
    assert(counter);

    if (!handle->cmap)
        return bf_err_r(-ENOENT, "handle has no counters map");

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0)
        return bf_err_r(num_cpus, "failed to get number of possible CPUs");

    percpu = calloc(num_cpus, sizeof(*percpu));
    if (!percpu)
        return -ENOMEM;

    r = bf_bpf_map_lookup_elem(handle->cmap->fd, &counter_idx, percpu);
    if (r < 0)
        return bf_err_r(r, "failed to lookup counters map");

    counter->count = 0;
    counter->size = 0;
    for (int i = 0; i < num_cpus; i++) {
        counter->count += percpu[i].count;
        counter->size += percpu[i].size;
    }

    return 0;
}

int bf_handle_set_counter(struct bf_handle *handle, uint32_t counter_idx,
                          const struct bf_counter *counter)
{
    _cleanup_free_ struct bf_counter *percpu = NULL;
    int num_cpus;
    int r;

    assert(handle);
    assert(counter);

    if (!handle->cmap)
        return bf_err_r(-ENOENT, "handle has no counters map");

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0)
        return bf_err_r(num_cpus, "failed to get number of possible CPUs");

    percpu = calloc(num_cpus, sizeof(*percpu));
    if (!percpu)
        return -ENOMEM;

    percpu[0] = *counter;

    r = bf_bpf_map_update_elem(handle->cmap->fd, &counter_idx, percpu, 0);
    if (r < 0)
        return bf_err_r(r, "failed to update counters map");

    return 0;
}

int bf_handle_attach(struct bf_handle *handle, enum bf_hook hook,
                     struct bf_hookopts **hookopts)
{
    int r;

    assert(handle);
    assert(hookopts);

    if (handle->link)
        return bf_err_r(-EEXIST, "program is already attached");

    r = bf_link_new(&handle->link, _BF_LINK_NAME, hook, hookopts,
                    handle->prog_fd);
    if (r)
        return bf_err_r(r, "failed to attach bf_link");

    return 0;
}

void bf_handle_detach(struct bf_handle *handle)
{
    assert(handle);

    if (handle->link) {
        (void)bf_bpf_link_detach(handle->link->fd);
        if (handle->link->fd_extra >= 0)
            (void)bf_bpf_link_detach(handle->link->fd_extra);
    }

    bf_link_free(&handle->link);
}

void bf_handle_unload(struct bf_handle *handle)
{
    assert(handle);

    closep(&handle->prog_fd);

    /* Explicitly detach the BPF link before closing it. Relying solely on
     * close() is not sufficient when the link is pinned (the pin holds a
     * kernel reference that keeps the link alive). Using BPF_LINK_DETACH
     * ensures the program is removed from the hook immediately. */
    bf_handle_detach(handle);

    bf_link_free(&handle->link);
    bf_map_free(&handle->cmap);
    bf_map_free(&handle->pmap);
    bf_map_free(&handle->lmap);
    bf_map_free(&handle->smap);
    bf_map_free(&handle->rmap);
    bf_list_clean(&handle->sets);
}
