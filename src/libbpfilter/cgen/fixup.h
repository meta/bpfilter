/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include <bpfilter/dump.h>
#include <bpfilter/elfstub.h>

struct bf_set;

/**
 * Field to fixup in a @c bpf_insn structure.
 */
enum bf_fixup_insn
{
    BF_FIXUP_INSN_OFF,
    BF_FIXUP_INSN_IMM,
    _BF_FIXUP_INSN_MAX,
};

/**
 * Type of the fixup.
 *
 * Defines how a fixup should be processed.
 */
enum bf_fixup_type
{
    /// Jump to the beginning of the next rule.
    BF_FIXUP_TYPE_JMP_NEXT_RULE,
    /// Set the counters map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_COUNTERS_MAP_FD,
    /// Set the printer map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_PRINTER_MAP_FD,
    /// Set the log map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_LOG_MAP_FD,
    /// Set the state map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_STATE_MAP_FD,
    /// Set a set map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_SET_MAP_FD,
    /// Set the limit map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_LIMIT_MAP_FD,
    /// Call an ELF stub.
    BF_FIXUP_ELFSTUB_CALL,
    _BF_FIXUP_TYPE_MAX
};

union bf_fixup_attr
{
    /** Set referenced by a `BF_FIXUP_TYPE_SET_MAP_FD` fixup. The fixup
     * holds a non-owning pointer to a set in the generator's chain. */
    const struct bf_set *set_ptr;
    enum bf_elfstub_id elfstub_id;
};

struct bf_fixup
{
    enum bf_fixup_type type;
    size_t insn;
    union bf_fixup_attr attr;
};

#define _free_bf_fixup_ __attribute__((cleanup(bf_fixup_free)))

int bf_fixup_new(struct bf_fixup **fixup, enum bf_fixup_type type,
                 size_t insn_offset, const union bf_fixup_attr *attr);
void bf_fixup_free(struct bf_fixup **fixup);
void bf_fixup_dump(const struct bf_fixup *fixup, prefix_t *prefix);
