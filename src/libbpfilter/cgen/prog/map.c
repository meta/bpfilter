// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/prog/map.h"

#include <linux/bpf.h>

#include <bpf/btf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpf_types.h>
#include <bpfilter/btf.h>
#include <bpfilter/ctx.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#include "cgen/runtime.h"

#define _free_bf_btf_ __attribute__((__cleanup__(_bf_btf_free)))

static void _bf_btf_free(struct bf_btf **btf);

static int _bf_btf_new(struct bf_btf **btf)
{
    _free_bf_btf_ struct bf_btf *_btf = NULL;

    assert(btf);

    _btf = malloc(sizeof(struct bf_btf));
    if (!_btf)
        return -ENOMEM;

    _btf->fd = -1;

    _btf->btf = btf__new_empty();
    if (!_btf->btf)
        return -errno;

    *btf = TAKE_PTR(_btf);

    return 0;
}

static void _bf_btf_free(struct bf_btf **btf)
{
    assert(btf);

    if (!*btf)
        return;

    btf__free((*btf)->btf);
    closep(&(*btf)->fd);
    BF_FREEP(btf);
}

static int _bf_btf_load(struct bf_btf *btf)
{
    union bpf_attr attr = {};
    const void *raw;
    int r;

    assert(btf);

    raw = btf__raw_data(btf->btf, &attr.btf_size);
    if (!raw)
        return bf_err_r(errno, "failed to request BTF raw data");

    r = bf_bpf_btf_load(raw, attr.btf_size, bf_ctx_token());
    if (r < 0)
        return r;

    btf->fd = r;

    return 0;
}

/**
 * @brief Create the BTF data for the map.
 *
 * @param map Map to create the BTF data for. @c map.type will define the
 *        exact content of the BTF object. Can't be NULL.
 * @return A @ref bf_btf structure on success, or NULL on error. The
 *         @ref bf_btf structure is owned by the caller.
 */
static struct bf_btf *_bf_map_make_btf(const struct bf_map *map)
{
    _free_bf_btf_ struct bf_btf *btf = NULL;
    struct btf *kbtf;
    int r;

    assert(map);

    r = _bf_btf_new(&btf);
    if (r < 0)
        return NULL;

    kbtf = btf->btf;

    switch (map->type) {
    case BF_MAP_TYPE_COUNTERS:
        btf__add_int(kbtf, "u64", 8, 0);
        btf->key_type_id = btf__add_int(kbtf, "u32", 4, 0);
        btf->value_type_id = btf__add_struct(kbtf, "bf_counters", 16);
        btf__add_field(kbtf, "count", 1, 0, 0);
        btf__add_field(kbtf, "size", 1, 64, 0);
        break;
    case BF_MAP_TYPE_STATE: {
        int u32_id;
        int rule_state_id;

        // The map's single value holds one bf_rule_state per rule
        btf__add_int(kbtf, "u64", 8, 0);
        u32_id = btf__add_int(kbtf, "u32", 4, 0);
        rule_state_id = btf__add_struct(kbtf, "bf_rule_state",
                                        sizeof(struct bf_rule_state));
        btf__add_field(kbtf, "last_log_ts", 1, 0, 0);
        btf->key_type_id = u32_id;
        btf->value_type_id =
            btf__add_array(kbtf, u32_id, rule_state_id,
                           map->value_size / sizeof(struct bf_rule_state));
        break;
    }
    case BF_MAP_TYPE_PRINTER:
    case BF_MAP_TYPE_SET:
    case BF_MAP_TYPE_LOG:
    case BF_MAP_TYPE_CTX:
        // No BTF data available for these map types
        return NULL;
    default:
        bf_err_r(-ENOTSUP, "bf_map type %d is not supported", map->type);
        return NULL;
    }

    r = _bf_btf_load(btf);
    if (r) {
        bf_warn_r(r, "failed to load BTF data for %s, ignoring", map->name);
        return NULL;
    }

    return TAKE_PTR(btf);
}

static int _bf_map_new(struct bf_map **map, const char *name,
                       enum bf_map_type type, enum bf_bpf_map_type bpf_type,
                       size_t key_size, size_t value_size, size_t n_elems)
{
    _free_bf_map_ struct bf_map *_map = NULL;
    _free_bf_btf_ struct bf_btf *btf = NULL;
    _cleanup_close_ int fd = -1;

    assert(map);
    assert(name);

    if (name[0] == '\0')
        return bf_err_r(-EINVAL, "bf_map: name can't be empty");

    if (type != BF_MAP_TYPE_LOG && key_size == 0)
        return bf_err_r(-EINVAL, "bf_map %s: key size can't be 0", name);
    if (type == BF_MAP_TYPE_LOG && key_size != 0)
        return bf_err_r(-EINVAL, "bf_map %s: key size must be 0", name);

    if (type != BF_MAP_TYPE_LOG && value_size == 0)
        return bf_err_r(-EINVAL, "bf_map %s: value size can't be 0", name);
    if (type == BF_MAP_TYPE_LOG && value_size != 0)
        return bf_err_r(-EINVAL, "bf_map %s: value size must be 0", name);

    if (n_elems == 0) {
        return bf_err_r(-EINVAL, "bf_map %s: number of elements can't be 0",
                        name);
    }

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    _map->type = type;
    _map->bpf_type = bpf_type;
    _map->key_size = key_size;
    _map->value_size = value_size;
    _map->n_elems = n_elems;
    _map->fd = -1;

    bf_strncpy(_map->name, BPF_OBJ_NAME_LEN, name);

    btf = _bf_map_make_btf(_map);

    fd =
        bf_bpf_map_create(_map->name, _map->bpf_type, _map->key_size,
                          _map->value_size, _map->n_elems, btf, bf_ctx_token());
    if (fd < 0)
        return bf_err_r(fd, "bf_map %s: failed to create map", name);

    _map->fd = TAKE_FD(fd);
    *map = TAKE_PTR(_map);

    return 0;
}

int bf_map_new(struct bf_map **map, const char *name, enum bf_map_type type,
               size_t key_size, size_t value_size, size_t n_elems)
{
    static enum bf_bpf_map_type _map_type_to_bpf[_BF_MAP_TYPE_MAX] = {
        [BF_MAP_TYPE_COUNTERS] = BF_BPF_MAP_TYPE_PERCPU_ARRAY,
        [BF_MAP_TYPE_PRINTER] = BF_BPF_MAP_TYPE_ARRAY,
        [BF_MAP_TYPE_LOG] = BF_BPF_MAP_TYPE_RINGBUF,
        /* Unreachable: bf_map_new() rejects BF_MAP_TYPE_SET; use
         * bf_map_new_from_set() instead. Listed here to give the entry a
         * valid bf_bpf_map_type value. */
        [BF_MAP_TYPE_SET] = BF_BPF_MAP_TYPE_HASH,
        [BF_MAP_TYPE_CTX] = BF_BPF_MAP_TYPE_ARRAY,
        [BF_MAP_TYPE_STATE] = BF_BPF_MAP_TYPE_ARRAY,
    };

    assert(map);
    assert(name);

    if (type == BF_MAP_TYPE_SET) {
        return bf_err_r(
            -EINVAL,
            "use bf_map_new_from_set() to create a bf_map from a bf_set");
    }

    return _bf_map_new(map, name, type, _map_type_to_bpf[type], key_size,
                       value_size, n_elems);
}

int bf_map_new_from_set(struct bf_map **map, const char *name,
                        const struct bf_set *set, size_t n_elems,
                        size_t value_size)
{
    assert(map);
    assert(name);
    assert(set);

    return _bf_map_new(map, name, BF_MAP_TYPE_SET,
                       set->use_trie ? BF_BPF_MAP_TYPE_LPM_TRIE :
                                       BF_BPF_MAP_TYPE_HASH,
                       set->elem_size, value_size, n_elems);
}

int bf_map_new_from_pack(struct bf_map **map, int dir_fd, bf_rpack_node_t node)
{
    _free_bf_map_ struct bf_map *_map = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    assert(map);

    if (dir_fd < 0)
        return bf_err_r(-EBADFD, "dir_fd is invalid");

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    _map->fd = -1;

    r = bf_rpack_kv_str(node, "name", &name);
    if (r)
        return bf_rpack_key_err(r, "bf_map.name");
    if (strlen(name) == 0)
        return bf_err_r(-EINVAL, "map name can't be empty");
    bf_strncpy(_map->name, BPF_OBJ_NAME_LEN, name);

    r = bf_rpack_kv_enum(node, "type", &_map->type, 0, _BF_MAP_TYPE_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_map.type");

    r = bf_rpack_kv_enum(node, "bpf_type", &_map->bpf_type, 0,
                         __MAX_BPF_MAP_TYPE);
    if (r)
        return bf_rpack_key_err(r, "bf_map.bpf_type");

    r = bf_rpack_kv_size(node, "key_size", &_map->key_size);
    if (r)
        return bf_rpack_key_err(r, "bf_map.key_size");

    r = bf_rpack_kv_size(node, "value_size", &_map->value_size);
    if (r)
        return bf_rpack_key_err(r, "bf_map.value_size");

    r = bf_rpack_kv_size(node, "n_elems", &_map->n_elems);
    if (r)
        return bf_rpack_key_err(r, "bf_map.n_elems");
    if (_map->n_elems == 0)
        return bf_err_r(-EINVAL, "bf_map should not have 0 elements");

    r = bf_bpf_obj_get(_map->name, dir_fd, &_map->fd);
    if (r < 0)
        return bf_err_r(r, "failed to open pinned BPF map '%s'", _map->name);

    *map = TAKE_PTR(_map);

    return 0;
}

void bf_map_free(struct bf_map **map)
{
    assert(map);

    if (!*map)
        return;

    closep(&(*map)->fd);
    BF_FREEP(map);
}

int bf_map_pack(const struct bf_map *map, bf_wpack_t *pack)
{
    assert(map);
    assert(pack);

    bf_wpack_kv_str(pack, "name", map->name);
    bf_wpack_kv_enum(pack, "type", map->type);
    bf_wpack_kv_enum(pack, "bpf_type", map->bpf_type);
    bf_wpack_kv_u64(pack, "key_size", map->key_size);
    bf_wpack_kv_u64(pack, "value_size", map->value_size);
    bf_wpack_kv_u64(pack, "n_elems", map->n_elems);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

static const char *_bf_map_type_to_str(enum bf_map_type type)
{
    static const char *type_strs[] = {
        [BF_MAP_TYPE_COUNTERS] = "BF_MAP_TYPE_COUNTERS",
        [BF_MAP_TYPE_PRINTER] = "BF_MAP_TYPE_PRINTER",
        [BF_MAP_TYPE_LOG] = "BF_MAP_TYPE_LOG",
        [BF_MAP_TYPE_SET] = "BF_MAP_TYPE_SET",
        [BF_MAP_TYPE_CTX] = "BF_MAP_TYPE_CTX",
        [BF_MAP_TYPE_STATE] = "BF_MAP_TYPE_STATE",
    };

    static_assert_enum_mapping(type_strs, _BF_MAP_TYPE_MAX);
    assert(0 <= type && type < _BF_MAP_TYPE_MAX);

    return type_strs[type];
}

static const char *_bf_bpf_type_to_str(enum bf_bpf_map_type type)
{
    static const char *type_strs[] = {
        [BF_BPF_MAP_TYPE_HASH] = "BF_BPF_MAP_TYPE_HASH",
        [BF_BPF_MAP_TYPE_ARRAY] = "BF_BPF_MAP_TYPE_ARRAY",
        [BF_BPF_MAP_TYPE_PERCPU_ARRAY] = "BF_BPF_MAP_TYPE_PERCPU_ARRAY",
        [BF_BPF_MAP_TYPE_LPM_TRIE] = "BF_BPF_MAP_TYPE_LPM_TRIE",
        [BF_BPF_MAP_TYPE_RINGBUF] = "BF_BPF_MAP_TYPE_RINGBUF",
    };

    return type_strs[type] ? type_strs[type] : "<no mapping>";
}

void bf_map_dump(const struct bf_map *map, prefix_t *prefix)
{
    assert(map);
    assert(prefix);

    DUMP(prefix, "struct bf_map at %p", map);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "type: %s", _bf_map_type_to_str(map->type));
    DUMP(prefix, "name: %s", map->name);
    DUMP(prefix, "bpf_type: %s", _bf_bpf_type_to_str(map->bpf_type));
    DUMP(prefix, "key_size: %lu", map->key_size);
    DUMP(prefix, "value_size: %lu", map->value_size);
    DUMP(prefix, "n_elems: %lu", map->n_elems);

    bf_dump_prefix_last(prefix);
    DUMP(prefix, "fd: %d", map->fd);

    bf_dump_prefix_pop(prefix);
}

int bf_map_pin(const struct bf_map *map, int dir_fd)
{
    int r;

    assert(map);

    r = bf_bpf_obj_pin(map->name, map->fd, dir_fd);
    if (r < 0)
        return bf_err_r(r, "failed to pin BPF map '%s'", map->name);

    return 0;
}

void bf_map_unpin(const struct bf_map *map, int dir_fd)
{
    int r;

    assert(map);

    r = unlinkat(dir_fd, map->name, 0);
    if (r < 0 && errno != ENOENT) {
        // Do not warn on ENOENT, we want the file to be gone!
        bf_warn_r(
            errno,
            "failed to unlink BPF map '%s', assuming the map is not pinned",
            map->name);
    }
}

int bf_map_set_elem(const struct bf_map *map, void *key, void *value)
{
    assert(map);
    assert(key);
    assert(value);

    return bf_bpf_map_update_elem(map->fd, key, value, 0);
}
