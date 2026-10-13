/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/bpf_types.h>
#include <bpfilter/dump.h>
#include <bpfilter/pack.h>
#include <bpfilter/set.h>

enum bf_map_type
{
    BF_MAP_TYPE_COUNTERS,
    BF_MAP_TYPE_PRINTER,
    BF_MAP_TYPE_LOG,
    BF_MAP_TYPE_SET,
    BF_MAP_TYPE_CTX,

    /** Single-entry array map holding per-rule mutable state. The value is a
     * flat array of `bf_rule_state` entries, indexed by rule position. */
    BF_MAP_TYPE_STATE,

    _BF_MAP_TYPE_MAX,
};

#define BF_PIN_PATH_LEN 64

struct bf_map
{
    enum bf_map_type type;
    enum bf_bpf_map_type bpf_type;
    char name[BPF_OBJ_NAME_LEN];
    size_t key_size;
    size_t value_size;
    size_t n_elems;
    int fd;
};

#define _free_bf_map_ __attribute__((__cleanup__(bf_map_free)))

/**
 * @brief Allocates and initializes a new BPF map object.
 *
 * While `bf_map` is a bpfilter-specific representation of a BPF map, this
 * function will create an actual BPF map object.
 *
 * @param map BPF map object to allocate and initialize. Can't be NULL. On
 *        success, `*map` points to a valid `bf_map`. On failure,
 *        `*map` remain unchanged.
 * @param name Name of the map. Will be used as the name of the BPF object, but
 *        also as filename when pinning the map to the system. Can't be NULL or
 *        empty.
 * @param type Map type, defines the set of available operations.
 * @param key_size Size (in bytes) of a key in the map.
 * @param value_size Size (in bytes) of an element of the map.
 * @param n_elems Number of elements to reserve room for in the map.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_new(struct bf_map **map, const char *name, enum bf_map_type type,
               size_t key_size, size_t value_size, size_t n_elems);

/**
 * @brief Allocate and initialise a new BPF map object, from a set.
 *
 * @param map BPF map object to allocate and initialize. Can't be NULL. On
 *        success, `*map` points to a valid `bf_map`. On failure, `*map`
 *        remain unchanged. Can't be NULL.
 * @param name Name of the map. Will be used as the name of the BPF object, but
 *        also as filename when pinning the map to the system. Can't be NULL or
 *        empty.
 * @param set Set to create the map from. Can't be NULL.
 * @param n_elems Number of elements to reserve room for in the map.
 * @param value_size Size (in bytes) of the value field.
 * @return 0 on success, or a negative error value on error.
 */
int bf_map_new_from_set(struct bf_map **map, const char *name,
                        const struct bf_set *set, size_t n_elems,
                        size_t value_size);

/**
 * @brief Allocate and initialize a new map from serialized data.
 *
 * @note The new bf_map object will represent a BPF map from bpfilter's point
 * of view, but it's not a BPF map.
 *
 * @param map Map object to allocate and initialize from the serialized data.
 *        The caller will own the object. On failure, `*map` is unchanged.
 *        Can't be NULL.
 * @param dir_fd File descriptor of the directory containing the map's pin.
 *        Must be a valid file descriptor.
 * @param node Node containing the serialized map. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_new_from_pack(struct bf_map **map, int dir_fd, bf_rpack_node_t node);

/**
 * @brief Create a new map object referring to the same BPF map as `src`.
 *
 * The new object has its own file descriptor: the caller owns it and must
 * free it with `bf_map_free`, which doesn't affect `src`.
 *
 * @param map Map object to allocate. On failure, `*map` is unchanged. Can't
 *        be NULL.
 * @param src Map to duplicate. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_dup(struct bf_map **map, const struct bf_map *src);

/**
 * Free a BPF map object.
 *
 * The BPF map's file descriptor contained in `map` is closed and set to
 * `-1`. To prevent the BPF map from being destroyed, pin it beforehand.
 *
 * @param map @ref bf_map object to free. On success, `*map` is set to
 *            NULL. On failure, `*map` remain unchanged.
 */
void bf_map_free(struct bf_map **map);

/**
 * @brief Serialize a map.
 *
 * @param map Map to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the map into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_map_pack(const struct bf_map *map, bf_wpack_t *pack);

/**
 * Dump a BPF map object.
 *
 * @param map BPF map object to dump. Can't be NULL.
 * @param prefix String to prefix each log with. If no prefix is needed, use
 *               `EMPTY_PREFIX`. Can't be NULL.
 */
void bf_map_dump(const struct bf_map *map, prefix_t *prefix);

/**
 * @brief Pin the map to the system.
 *
 * @param map Map to pin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to pin the map into. Must be
 *        a valid file descriptor.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_pin(const struct bf_map *map, int dir_fd);

/**
 * @brief Unpin the map from the system.
 *
 * @param map Map to unpin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to unpin the map from. Must be
 *        a valid file descriptor.
 */
void bf_map_unpin(const struct bf_map *map, int dir_fd);

/**
 * @brief Insert or update an element to the map.
 *
 * If an element already exist in the map for `key` it is replaced, otherwise
 * it is inserted.
 *
 * @param map BPF map to update. Can't be NULL.
 * @param key Pointer to the element key. The key size has been defined with
 *            `bf_map_new`. Can't be NULL.
 * @param value Pointer to the value. The value size has been defined with
 *              `bf_map_new`. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_set_elem(const struct bf_map *map, void *key, void *value);
