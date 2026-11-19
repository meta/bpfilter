/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include <bpfilter/logger.h>

/**
 * Dump prefixed-formatted string.
 *
 * @param p Prefix string.
 * @param fmt Log format string.
 * @param ... Variadic argument list for @p fmt.
 */
#define DUMP(p, fmt, ...) bf_dbg("%s" fmt, (*p), ##__VA_ARGS__)

/**
 * Split 32 bits IPv4 representation into four 8 bits components.
 *
 * @param addr 32 bits IPv4 address to split.
 */
#define IP4_SPLIT(addr)                                                        \
    ((unsigned char *)&(addr))[0], ((unsigned char *)&(addr))[1],              \
        ((unsigned char *)&(addr))[2], ((unsigned char *)&(addr))[3]

/// Format to use with @ref IP4_SPLIT to print an IPv4.
#define IP4_FMT "%d.%d.%d.%d"

/**
 * Split a byte into 8 characters representing each bit.
 *
 * @param byte Byte to split.
 */
#define BIN_SPLIT(byte)                                                        \
    (((byte) & 0x80) + 0x30), (((byte) & 0x40) + 0x30),                        \
        (((byte) & 0x20) + 0x30), (((byte) & 0x10) + 0x30),                    \
        (((byte) & 0x08) + 0x30), (((byte) & 0x04) + 0x30),                    \
        (((byte) & 0x02) + 0x30), (((byte) & 0x01) + 0x30)

/// Format to use with BIN_SPLIT() to print a byte as 8 bits.
#define BIN_FMT "%c%c%c%c%c%c%c%c"

/// Maximum length of the prefix buffer.
#define DUMP_PREFIX_LEN 65

/// Empty prefix for dump functions
#define EMPTY_PREFIX ((prefix_t[]) {{}})

typedef char(prefix_t)[DUMP_PREFIX_LEN];

/**
 * Add a symbol to the prefix string.
 *
 * @param prefix Prefix string.
 */
void bf_dump_prefix_push(prefix_t *prefix);

/**
 * Convert previous node to make is the last of the branch.
 *
 * @param prefix Prefix string.
 * @return @p prefix
 */
prefix_t *bf_dump_prefix_last(prefix_t *prefix);

/**
 * Remove rightmost branch from the prefix string.
 *
 * When a subtree is completed and we backout to a different branch, we need
 * to remove the rightmost branch from the prefix to continue.
 *
 * @param prefix Prefix string.
 */
void bf_dump_prefix_pop(prefix_t *prefix);

/**
 * Dump the data buffer in hexedecimal format.
 *
 * Each byte in @p data will be printed as 0x%02x, with 8 bytes on each row.
 *
 * @param prefix Prefix string.
 * @param data Data buffer to print.
 * @param len Size of the data buffer.
 */
void bf_dump_hex(prefix_t *prefix, const void *data, size_t len);
