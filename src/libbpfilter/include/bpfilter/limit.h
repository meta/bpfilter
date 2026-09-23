// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/core/hashset.h>
#include <bpfilter/dump.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>

#define BF_TIME_S 1000000000

#define _free_bf_limit_ __attribute__((cleanup(bf_limit_free)))

/**
 * @brief Ratelimit object, used to store the configuration of a ratelimit.
 */
struct bf_ratelimit
{
    /** Amount of times a packet is allowed to pass through. */
    uint32_t limit;

    /** Amount of time it takes in nano seconds for the ratelimit to reset. */
    uint32_t duration;
};

/**
 * @brief Allocate and initialise a new ratelimit.
 *
 * @param ratelimit Ratelimit to allocate and initialise. Can't be NULL.
 * @param limit Limit for the ratelimit.
 * @param duration Time in nanoseconds before each reset of the ratelimit.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_limit_new(struct bf_ratelimit **ratelimit, uint32_t limit,
                 uint32_t duration);

/**
 * @brief Allocate and initialise a new ratelimit from a raw payload value.
 *
 * @param ratelimit Ratelimit to allocate and initialise. Can't be NULL.
 * @param raw_payload Ratelimit payload. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_limit_new_from_raw(struct bf_ratelimit **ratelimit,
                          const char *raw_payload);

/**
 * @brief Allocate and initialize a new ratelimit from serialized data.
 *
 * @param ratelimit Ratelimit object to allocate and initialize from the serialized data.
 *        The caller will own the object. On failure, `*ratelimit` is unchanged.
 *        Can't be NULL.
 * @param node Node containing the serialized ratelimit. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_limit_new_from_pack(struct bf_ratelimit **ratelimit,
                           bf_rpack_node_t node);

/**
 * @brief Serialize a ratelimit.
 *
 * @param ratelimit Ratelimit to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the ratelimit into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_limit_pack(const struct bf_ratelimit *ratelimit, bf_wpack_t *pack);

void bf_limit_free(struct bf_ratelimit **ratelimit);
