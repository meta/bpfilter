/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/program.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h> // NOLINT
#include <linux/limits.h>

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/btf.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/hashset.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/ctx.h>
#include <bpfilter/dump.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "cgen/cgroup_skb.h"
#include "cgen/cgroup_sock_addr.h"
#include "cgen/dump.h"
#include "cgen/fixup.h"
#include "cgen/handle.h"
#include "cgen/jmp.h"
#include "cgen/nf.h"
#include "cgen/printer.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/stub.h"
#include "cgen/tc.h"
#include "cgen/xdp.h"
#include "filter.h"

#define _BF_LOG_BUF_SIZE                                                       \
    (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */
#define _BF_LOG_MAP_N_ENTRIES 1000
#define _BF_LOG_MAP_SIZE                                                       \
    _bf_round_next_power_of_2(sizeof(struct bf_log) * _BF_LOG_MAP_N_ENTRIES)
#define _BF_SET_MAP_PREFIX "bf_set_"
#define _BF_COUNTER_MAP_NAME "bf_cmap"
#define _BF_PRINTER_MAP_NAME "bf_pmap"
#define _BF_LOG_MAP_NAME "bf_lmap"
#define _BF_STATE_MAP_NAME "bf_smap"

static inline size_t _bf_round_next_power_of_2(size_t value)
{
    if (value == 0)
        return 1;

    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
#if SIZE_MAX > 0xFFFFFFFFU
    value |= value >> 32;
#endif

    return ++value;
}

/**
 * @brief Sets sharing the same key format, collapsed to a single BPF map.
 *
 * For hash-keyed sets, one `bf_set_group` exists for every unique key
 * format among a chain's non-empty sets. The sets list preserves insertion
 * order; a set's position is its bit index within the group's bitmask
 * value.
 *
 * LPM trie sets are never grouped together: each non-empty trie set gets
 * its own group of size 1. See `_bf_program_build_set_groups()` for the
 * rationale.
 */
struct bf_set_group
{
    /** Non-empty sets that map to the same BPF map. For hash-keyed groups,
     * all sets share the same key format; LPM trie groups always hold a
     * single set. Non-owning pointers into the chain's `bf_set` list.
     * Never empty. */
    bf_list sets;

    /** Backing BPF map. Populated during `bf_program_load()`; the map is
     * owned by `bf_program->handle->sets`. */
    struct bf_map *map;
};

#define _free_bf_set_group_ __attribute__((__cleanup__(_bf_set_group_free)))

static void _bf_set_group_free(struct bf_set_group **group)
{
    assert(group);

    if (!*group)
        return;

    bf_list_clean(&(*group)->sets);
    BF_FREEP(group);
}

static int _bf_set_group_new(struct bf_set_group **group)
{
    _free_bf_set_group_ struct bf_set_group *_group = NULL;

    assert(group);

    _group = calloc(1, sizeof(*_group));
    if (!_group)
        return -ENOMEM;

    /* The list holds non-owning const struct bf_set * pointers; no free
     * callback. Groups are temporary (not serialized), so no pack callback
     * either. */
    _group->sets = bf_list_default(NULL, NULL);

    *group = TAKE_PTR(_group);

    return 0;
}

static struct bf_set_group *
_bf_program_find_set_group(const struct bf_program *program,
                           const struct bf_set *set)
{
    assert(program);

    if (!set)
        return NULL;

    bf_list_foreach (&program->set_groups, group_node) {
        struct bf_set_group *group = bf_list_node_get_data(group_node);
        bf_list_foreach (&group->sets, set_node) {
            if (bf_list_node_get_data(set_node) == set)
                return group;
        }
    }

    return NULL;
}

static int _bf_program_add_set_to_group(struct bf_program *program,
                                        const struct bf_set *set)
{
    _free_bf_set_group_ struct bf_set_group *group = NULL;
    int r;

    assert(program);
    assert(set);

    if (bf_hashset_is_empty(&set->elems))
        return 0;

    /* If a group with a matching key already exists, reuse it. For LPM trie,
     * sets can't be grouped (as we can't define which rule matches on which
     * prefix), so they always are the sole member of their group. */
    if (!set->use_trie) {
        bf_list_foreach (&program->set_groups, group_node) {
            struct bf_set_group *group = bf_list_node_get_data(group_node);
            const struct bf_set *head =
                bf_list_node_get_data(bf_list_get_head(&group->sets));

            if (bf_set_same_key(set, head)) {
                r = bf_list_add_tail(&group->sets, (void *)set);
                if (r)
                    return bf_err_r(r, "failed to add set to existing group");

                return 0;
            }
        }
    }

    r = _bf_set_group_new(&group);
    if (r)
        return bf_err_r(r, "failed to allocate set group");

    r = bf_list_add_tail(&group->sets, (void *)set);
    if (r)
        return bf_err_r(r, "failed to seed set group");

    r = bf_list_push(&program->set_groups, (void **)&group);
    if (r)
        return bf_err_r(r, "failed to register set group");

    return 0;
}

static int _bf_program_build_set_groups(struct bf_program *program)
{
    assert(program);

    bf_list_clean(&program->set_groups);
    program->set_groups = bf_list_default(_bf_set_group_free, NULL);

    bf_hashset_foreach (&program->runtime.chain->sets, set_node) {
        int r = _bf_program_add_set_to_group(program, set_node->data);
        if (r)
            return r;
    }

    bf_list_foreach (&program->runtime.chain->rules, rule_node) {
        const struct bf_rule *rule = bf_list_node_get_data(rule_node);

        bf_list_foreach (&rule->matchers, matcher_node) {
            const struct bf_matcher *matcher =
                bf_list_node_get_data(matcher_node);
            const struct bf_set *set;
            int r;

            if (bf_matcher_get_type(matcher) != BF_MATCHER_SET)
                continue;

            memcpy(&set, bf_matcher_payload(matcher), sizeof(struct bf_set *));
            if (!bf_set_is_anonymous(set))
                continue;

            r = _bf_program_add_set_to_group(program, set);
            if (r)
                return r;
        }
    }

    return 0;
}

int bf_program_set_bit_index(const struct bf_program *program,
                             const struct bf_set *set, size_t *bit_index)
{
    assert(program);
    assert(set);
    assert(bit_index);

    bf_list_foreach (&program->set_groups, group_node) {
        struct bf_set_group *group = bf_list_node_get_data(group_node);
        size_t i = 0;

        bf_list_foreach (&group->sets, set_node) {
            if (bf_list_node_get_data(set_node) == set) {
                *bit_index = i;
                return 0;
            }
            ++i;
        }
    }

    return -ENOENT;
}

static const struct bf_flavor_ops *bf_flavor_ops_get(enum bf_flavor flavor)
{
    static const struct bf_flavor_ops *flavor_ops[] = {
        [BF_FLAVOR_TC] = &bf_flavor_ops_tc,
        [BF_FLAVOR_NF] = &bf_flavor_ops_nf,
        [BF_FLAVOR_XDP] = &bf_flavor_ops_xdp,
        [BF_FLAVOR_CGROUP_SKB] = &bf_flavor_ops_cgroup_skb,
        [BF_FLAVOR_CGROUP_SOCK_ADDR] = &bf_flavor_ops_cgroup_sock_addr,
    };

    static_assert_enum_mapping(flavor_ops, _BF_FLAVOR_MAX);

    return flavor_ops[flavor];
}

int bf_program_new(struct bf_program **program, const struct bf_chain *chain,
                   struct bf_handle *handle)
{
    _free_bf_program_ struct bf_program *_program = NULL;
    int r;

    assert(program);
    assert(chain);
    assert(handle);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->flavor = bf_hook_to_flavor(chain->hook);
    _program->runtime.ops = bf_flavor_ops_get(_program->flavor);
    _program->runtime.chain = chain;
    _program->img = bf_vector_default(sizeof(struct bpf_insn));
    _program->fixups = bf_list_default(bf_fixup_free, NULL);
    _program->set_groups = bf_list_default(_bf_set_group_free, NULL);
    _program->handle = handle;

    r = bf_vector_reserve(&_program->img, 512);
    if (r)
        return r;

    r = bf_printer_new(&_program->printer);
    if (r)
        return r;

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_free(struct bf_program **program)
{
    assert(program);

    if (!*program)
        return;

    bf_list_clean(&(*program)->fixups);
    bf_list_clean(&(*program)->set_groups);
    bf_vector_clean(&(*program)->img);

    bf_printer_free(&(*program)->printer);

    free(*program);
    *program = NULL;
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    assert(program);
    assert(prefix);

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "handle: struct bf_handle *");
    bf_dump_prefix_push(prefix);
    bf_handle_dump(program->handle, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "printer: struct bf_printer *");
    bf_dump_prefix_push(prefix);
    bf_printer_dump(program->printer, prefix);
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "img: %p", program->img.data);
    DUMP(prefix, "img.size: %lu", program->img.size);
    DUMP(prefix, "img.cap: %lu", program->img.cap);

    DUMP(prefix, "fixups: bf_list<struct bf_fixup>[%lu]",
         bf_list_size(&program->fixups));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);

        if (bf_list_is_tail(&program->fixups, fixup_node))
            bf_dump_prefix_last(prefix);

        bf_fixup_dump(fixup, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "groups: bf_list<struct bf_set_group>[%lu]",
         bf_list_size(&program->set_groups));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&program->set_groups, group_node) {
        const struct bf_set_group *group = bf_list_node_get_data(group_node);
        size_t i = 0;

        if (bf_list_is_tail(&program->set_groups, group_node))
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "struct bf_set_group at %p (%lu set(s), map=%p)", group,
             bf_list_size(&group->sets), (void *)group->map);
        bf_dump_prefix_push(prefix);
        bf_list_foreach (&group->sets, set_node) {
            const struct bf_set *set = bf_list_node_get_data(set_node);

            if (bf_list_is_tail(&group->sets, set_node))
                bf_dump_prefix_last(prefix);
            DUMP(prefix, "bit %lu: bf_set '%s' (%lu element(s))", i,
                 set->name ?: "<anonymous>", bf_hashset_size(&set->elems));
            ++i;
        }
        bf_dump_prefix_pop(prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "runtime: <anonymous>");
    bf_dump_prefix_push(prefix);
    DUMP(bf_dump_prefix_last(prefix), "ops: %p", program->runtime.ops);
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

static void _bf_program_fixup_insn(struct bpf_insn *insn,
                                   enum bf_fixup_insn type, int32_t value)
{
    switch (type) {
    case BF_FIXUP_INSN_OFF:
        assert(!insn->off);
        assert(value < SHRT_MAX);
        insn->off = (int16_t)value;
        break;
    case BF_FIXUP_INSN_IMM:
        assert(!insn->imm);
        insn->imm = value;
        break;
    default:
        bf_abort(
            "unsupported fixup instruction type, this should not happen: %d",
            type);
        break;
    }
}

static int _bf_program_fixup(struct bf_program *program,
                             enum bf_fixup_type type)
{
    assert(program);
    assert(type >= 0 && type < _BF_FIXUP_TYPE_MAX);

    bf_list_foreach (&program->fixups, fixup_node) {
        enum bf_fixup_insn insn_type = _BF_FIXUP_INSN_MAX;
        int32_t value;
        size_t offset;
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        struct bpf_insn *insn;

        if (type != fixup->type)
            continue;

        insn = bf_vector_get(&program->img, fixup->insn);
        if (!insn) {
            return bf_err_r(-EINVAL,
                            "fixup references invalid instruction index %lu",
                            fixup->insn);
        }

        switch (type) {
        case BF_FIXUP_TYPE_JMP_NEXT_RULE:
            insn_type = BF_FIXUP_INSN_OFF;
            value = (int)(program->img.size - fixup->insn - 1U);
            break;
        case BF_FIXUP_TYPE_COUNTERS_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->cmap->fd;
            break;
        case BF_FIXUP_TYPE_PRINTER_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->pmap->fd;
            break;
        case BF_FIXUP_TYPE_LOG_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->lmap->fd;
            break;
        case BF_FIXUP_TYPE_STATE_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->smap->fd;
            break;
        case BF_FIXUP_TYPE_SET_MAP_FD: {
            const struct bf_set_group *group =
                _bf_program_find_set_group(program, fixup->attr.set_ptr);
            if (!group || !group->map) {
                return bf_err_r(
                    -ENOENT, "set map fixup: set '%s' not in any loaded group",
                    fixup->attr.set_ptr ?
                        (fixup->attr.set_ptr->name ?: "<anonymous>") :
                        "(null)");
            }
            insn_type = BF_FIXUP_INSN_IMM;
            value = group->map->fd;
            break;
        }
        case BF_FIXUP_ELFSTUB_CALL:
            insn_type = BF_FIXUP_INSN_IMM;
            offset = program->elfstubs_location[fixup->attr.elfstub_id] -
                     fixup->insn - 1;
            if (offset >= INT_MAX)
                return bf_err_r(-EINVAL, "invalid ELF stub call offset");
            value = (int32_t)offset;
            break;
        default:
            bf_abort("unsupported fixup type, this should not happen: %d",
                     type);
            break;
        }

        _bf_program_fixup_insn(insn, insn_type, value);
        bf_list_delete(&program->fixups, fixup_node);
    }

    return 0;
}

static int _bf_program_check_proto(struct bf_program *program,
                                   enum bf_matcher_type type,
                                   uint32_t *checked_layers)
{
    const struct bf_matcher_meta *meta;

    assert(program);
    assert(checked_layers);

    meta = bf_matcher_get_meta(type);
    if (!meta)
        return bf_err_r(-EINVAL, "missing meta for matcher type %d", type);

    if (*checked_layers & BF_FLAG(meta->layer))
        return 0;

    if (meta->layer == BF_MATCHER_LAYER_2 ||
        meta->layer == BF_MATCHER_LAYER_3 ||
        meta->layer == BF_MATCHER_LAYER_4) {
        int r = bf_stub_rule_check_protocol(program, meta);
        if (r)
            return r;
        *checked_layers |= BF_FLAG(meta->layer);
    }

    return 0;
}

static int _bf_program_generate_log(struct bf_program *program,
                                    const struct bf_rule *rule)
{
    _clean_bf_jmpctx_ struct bf_jmpctx l3_ctx = bf_jmpctx_default();
    _clean_bf_jmpctx_ struct bf_jmpctx l4_ctx = bf_jmpctx_default();
    _clean_bf_jmpctx_ struct bf_jmpctx null_ctx = bf_jmpctx_default();
    _clean_bf_jmpctx_ struct bf_jmpctx rate_ctx = bf_jmpctx_default();
    int r;

    assert(program);
    assert(rule);

    if (!rule->log)
        return 0;

    if (rule->log == BF_FLAG(BF_LOG_OPT_5_TUPLE)) {
        /* A 5-tuple is only complete for IPv4/IPv6 packets using TCP/UDP.
         * Skip only the log action for other packets, leaving the rule's
         * remaining actions and verdict unchanged. */
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 2));
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 1));
        l3_ctx = bf_jmpctx_get(program, BPF_JMP_A(0));

        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 2));
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 1));
        l4_ctx = bf_jmpctx_get(program, BPF_JMP_A(0));
    }

    if (rule->log_rate_ns) {
        const struct bpf_insn rate_insn[2] = {
            BPF_LD_IMM64(BPF_REG_1, rule->log_rate_ns),
        };

        /* Rate-limited log: check last_log_ts in the state map before logging.
         *
         * R9 (callee-saved) holds the pointer to this rule's state entry
         * across the bpf_ktime_get_ns() call. */
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_10,
                                  BF_PROG_CTX_OFF(state_map)));

        /* Skip the log if state_map is NULL. This shouldn't happen at runtime,
         * but the verifier requires the NULL check. */
        null_ctx =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 0, 0));

        if (rule->index > 0) {
            EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_9,
                                        (int)(rule->index *
                                              sizeof(struct bf_rule_state))));
        }

        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns));

        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_9, 0));
        EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_0));
        EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_2, BPF_REG_1));

        // Load log_rate_ns as a 64-bit immediate into R1.
        EMIT(program, rate_insn[0]);
        EMIT(program, rate_insn[1]);

        // Skip the log while delta is smaller than log_rate_ns.
        rate_ctx = bf_jmpctx_get(program,
                                 BPF_JMP_REG(BPF_JLT, BPF_REG_2, BPF_REG_1, 0));

        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 0));
    }

    r = program->runtime.ops->gen_inline_log(program, rule);
    if (r)
        return r;

    if (bf_ctx_is_verbose(BF_VERBOSE_BPF)) {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

        EMIT_PRINT(program, "failed to reserve a log entry in the ring buffer");
    }

    return 0;
}

/**
 * @brief Check whether matcher code generation can be skipped.
 *
 * A matcher needs no bytecode if it matches every packet the rule applies
 * to. Protocol checks emitted before the matcher are still generated, but
 * guards inside the matcher code are skipped.
 *
 * @param program Program to generate the matcher for. Can't be NULL.
 * @param matcher Matcher to check. Can't be NULL.
 * @return True if matcher code generation can be skipped, false otherwise.
 */
static bool _bf_program_matcher_is_noop(const struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    if (bf_matcher_get_type(matcher) == BF_MATCHER_META_PROBABILITY) {
        const float proba = *(const float *)bf_matcher_payload(matcher);

        return proba == 100.0F && !bf_matcher_get_negate(matcher);
    }

    if (bf_matcher_get_type(matcher) == BF_MATCHER_SET) {
        const struct bf_set *set =
            bf_chain_get_set_for_matcher(program->runtime.chain, matcher);

        /* ... not in {} will match every packet, so no need to generate the
         * bytecode for it. */
        if (bf_set_is_empty(set) && bf_matcher_get_negate(matcher))
            return true;
    }

    return false;
}

static int _bf_program_generate_rule(struct bf_program *program,
                                     struct bf_rule *rule)
{
    uint32_t checked_layers = 0;
    int ret_code;
    int r = 0;

    assert(program);
    assert(rule);
    assert(program->runtime.ops->gen_inline_matcher);
    assert(program->runtime.ops->gen_inline_log);

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        if (bf_matcher_get_type(matcher) == BF_MATCHER_SET) {
            const struct bf_set *set =
                bf_chain_get_set_for_matcher(program->runtime.chain, matcher);

            if (!set) {
                return bf_err_r(-ENOENT, "rule %u references non-existent set",
                                rule->index);
            }

            for (size_t i = 0; i < set->n_comps && !r; ++i) {
                r = _bf_program_check_proto(program, set->key[i],
                                            &checked_layers);
            }
        } else {
            r = _bf_program_check_proto(program, bf_matcher_get_type(matcher),
                                        &checked_layers);
        }

        if (r)
            return r;
    }

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        if (_bf_program_matcher_is_noop(program, matcher))
            continue;

        r = program->runtime.ops->gen_inline_matcher(program, matcher);
        if (r)
            return r;
    }

    if (bf_rule_mark_is_set(rule)) {
        if (!program->runtime.ops->gen_inline_set_mark) {
            return bf_err_r(-ENOTSUP, "set mark is not supported by %s",
                            program->runtime.chain->name);
        }

        r = program->runtime.ops->gen_inline_set_mark(program,
                                                      bf_rule_mark_get(rule));
        if (r) {
            return bf_err_r(r,
                            "failed to generate bytecode to set mark for '%s'",
                            program->runtime.chain->name);
        }
    }

    r = _bf_program_generate_log(program, rule);
    if (r)
        return r;

    if (rule->has_counters) {
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, rule->index));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);
    }

    switch (rule->verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_DROP:
    case BF_VERDICT_NEXT:
        r = program->runtime.ops->get_verdict(rule->verdict, &ret_code);
        if (r)
            return r;
        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
        break;
    case BF_VERDICT_REDIRECT:
        if (!program->runtime.ops->gen_inline_redirect) {
            return bf_err_r(-ENOTSUP, "redirect is not supported by %s hook",
                            bf_hook_to_str(program->runtime.chain->hook));
        }
        r = program->runtime.ops->gen_inline_redirect(
            program, rule->redirect_ifindex, rule->redirect_dir);
        if (r)
            return r;
        break;
    case BF_VERDICT_CONTINUE:
        // Fall through to next rule or default chain policy.
        break;
    default:
        bf_abort("unsupported verdict, this should not happen: %d",
                 rule->verdict);
        break;
    }

    return 0;
}

static int _bf_program_generate_elfstubs(struct bf_program *program)
{
    const struct bf_elfstub *elfstub;
    size_t start_at;
    int r;

    assert(program);

    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        size_t off = program->img.size;

        if (fixup->type != BF_FIXUP_ELFSTUB_CALL)
            continue;

        // Only generate each ELF stub once
        if (program->elfstubs_location[fixup->attr.elfstub_id])
            continue;

        bf_dbg("generate ELF stub for ID %d", fixup->attr.elfstub_id);

        elfstub = bf_ctx_get_elfstub(fixup->attr.elfstub_id);
        if (!elfstub) {
            return bf_err_r(-ENOENT, "no ELF stub found for ID %d",
                            fixup->attr.elfstub_id);
        }

        start_at = program->img.size;

        for (size_t i = 0; i < elfstub->ninsns; ++i) {
            r = bf_program_emit(program, elfstub->insns[i]);
            if (r)
                return bf_err_r(r, "failed to insert ELF stub instruction");
        }

        bf_list_foreach (&elfstub->strs, pstr_node) {
            _free_bf_fixup_ struct bf_fixup *fixup = NULL;
            struct bf_printk_str *pstr = bf_list_node_get_data(pstr_node);
            size_t insn_idx = start_at + pstr->insn_idx;
            const struct bf_printer_msg *msg =
                bf_printer_add_msg(program->printer, pstr->str);
            struct bpf_insn ld_insn[2] = {
                BPF_LD_MAP_FD(BPF_REG_1, 0),
            };

            ld_insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;
            ld_insn[1].imm = (int)bf_printer_msg_offset(msg);

            r = bf_vector_set(&program->img, insn_idx, &ld_insn[0]);
            if (r) {
                return bf_err_r(
                    r, "failed to set ELF stub instruction at index %lu",
                    insn_idx);
            }
            r = bf_vector_set(&program->img, insn_idx + 1, &ld_insn[1]);
            if (r) {
                return bf_err_r(
                    r, "failed to set ELF stub instruction at index %lu",
                    insn_idx + 1);
            }

            r = bf_fixup_new(&fixup, BF_FIXUP_TYPE_PRINTER_MAP_FD, insn_idx,
                             NULL);
            if (r)
                return r;

            r = bf_list_add_tail(&program->fixups, fixup);
            if (r)
                return r;

            TAKE_PTR(fixup);
        }

        program->elfstubs_location[fixup->attr.elfstub_id] = off;
    }

    return 0;
}

int bf_program_emit_kfunc_call(struct bf_program *program, const char *name)
{
    int r;

    assert(program);
    assert(name);

    r = bf_btf_get_id(name);
    if (r < 0)
        return r;

    EMIT(program, ((struct bpf_insn) {.code = BPF_JMP | BPF_CALL,
                                      .dst_reg = 0,
                                      .src_reg = BPF_PSEUDO_KFUNC_CALL,
                                      .off = 0,
                                      .imm = r}));

    return 0;
}

int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn, const union bf_fixup_attr *attr)
{
    _free_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    assert(program);

    EMIT(program, insn);

    r = bf_fixup_new(&fixup, type, program->img.size - 1, attr);
    if (r)
        return r;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    return 0;
}

int bf_program_emit_fixup_elfstub(struct bf_program *program,
                                  enum bf_elfstub_id id)
{
    _free_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    assert(program);

    EMIT(program, BPF_CALL_REL(0));

    r = bf_fixup_new(&fixup, BF_FIXUP_ELFSTUB_CALL, program->img.size - 1,
                     NULL);
    if (r)
        return r;

    fixup->attr.elfstub_id = id;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    return 0;
}

int bf_program_generate(struct bf_program *program)
{
    const struct bf_chain *chain = program->runtime.chain;
    bool next_reachable = true;
    int ret_code;
    int r;

    r = _bf_program_build_set_groups(program);
    if (r)
        return bf_err_r(r, "failed to build set groups");

    // Save the program's argument into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_CTX_OFF(arg)));

    // Reset the protocol ID registers
    EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));

    // @todo Avoid feature setup and maps needed only by unreachable rules.

    // If at least one rule logs the matched packets, populate ctx->log_map
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT_LOAD_LOG_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(log_map)));
    }

    // Zeroing IPv6 extension headers
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7,
                                  BF_PROG_CTX_OFF(ipv6_eh)));
    }

    r = program->runtime.ops->gen_inline_prologue(program);
    if (r)
        return r;

    // Populate ctx->state_map with the base pointer from the single-entry
    // state map. The key (0) is written to scratch[0..3] temporarily.
    // Placed after gen_inline_prologue so R1-R5 are free: the helper call
    // does not need to be followed by a ctx restore.
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG_RATELIMIT)) {
        EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_SCR_OFF(0), 0));
        EMIT_LOAD_STATE_FD_FIXUP(program, BPF_REG_1);
        EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0,
                                  BF_PROG_CTX_OFF(state_map)));
    }

    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);
        size_t n_fixups;

        if (rule->disabled)
            continue;

        r = _bf_program_generate_rule(program, rule);
        if (r)
            return r;

        n_fixups = bf_list_size(&program->fixups);
        r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_NEXT_RULE);
        if (r)
            return bf_err_r(r, "failed to generate next rule fixups");

        /* Resolving next-rule jumps removes their fixups and leaves all other
         * fixups unchanged. If the list shrinks, the rule has a jump to the
         * next rule. CONTINUE also reaches the next rule by falling through. */
        next_reachable = rule->verdict == BF_VERDICT_CONTINUE ||
                         bf_list_size(&program->fixups) < n_fixups;

        if (!next_reachable)
            break;
    }

    if (next_reachable) {
        r = program->runtime.ops->gen_inline_epilogue(program);
        if (r)
            return r;

        // Call the update counters function
        /// @todo Allow chains to have no counters at all.
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_program_chain_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

        r = program->runtime.ops->get_verdict(chain->policy, &ret_code);
        if (r)
            return r;
        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    r = _bf_program_generate_elfstubs(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_ELFSTUB_CALL);
    if (r)
        return bf_err_r(r, "failed to generate ELF stub call fixups");

    return 0;
}

static int _bf_program_load_printer_map(struct bf_program *program)
{
    _cleanup_free_ void *pstr = NULL;
    size_t pstr_len;
    uint32_t key = 0;
    int r;

    assert(program);

    r = bf_printer_assemble(program->printer, &pstr, &pstr_len);
    if (r)
        return bf_err_r(r, "failed to assemble printer map string");

    r = bf_map_new(&program->handle->pmap, _BF_PRINTER_MAP_NAME,
                   BF_MAP_TYPE_PRINTER, sizeof(uint32_t), pstr_len, 1);
    if (r)
        return bf_err_r(r, "failed to create the printer bf_map object");

    r = bf_map_set_elem(program->handle->pmap, &key, pstr);
    if (r)
        return bf_err_r(r, "failed to set print map elem");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_PRINTER_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup printer map FD");

    return 0;
}

static int _bf_program_load_counters_map(struct bf_program *program)
{
    int r;

    assert(program);

    r = bf_map_new(&program->handle->cmap, _BF_COUNTER_MAP_NAME,
                   BF_MAP_TYPE_COUNTERS, sizeof(uint32_t),
                   sizeof(struct bf_counter),
                   bf_list_size(&program->runtime.chain->rules) + 2);
    if (r)
        return bf_err_r(r, "failed to create the counters bf_map object");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_COUNTERS_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup counters map FD");

    return 0;
}

static int _bf_program_load_log_map(struct bf_program *program)
{
    int r;

    assert(program);

    // Do not create a log map if it's unused in the chain
    if (!(program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)))
        return 0;

    r = bf_map_new(&program->handle->lmap, _BF_LOG_MAP_NAME, BF_MAP_TYPE_LOG, 0,
                   0, _BF_LOG_MAP_SIZE);
    if (r)
        return bf_err_r(r, "failed to create the log bf_map object");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_LOG_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup log map FD");

    return 0;
}

static int _bf_program_load_state_map(struct bf_program *program)
{
    size_t n_rules;
    int r;

    assert(program);

    if (!(program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG_RATELIMIT)))
        return 0;

    n_rules = bf_list_size(&program->runtime.chain->rules);
    if (n_rules == 0)
        return 0;

    r = bf_map_new(&program->handle->smap, _BF_STATE_MAP_NAME,
                   BF_MAP_TYPE_STATE, sizeof(uint32_t),
                   n_rules * sizeof(struct bf_rule_state), 1);
    if (r)
        return bf_err_r(r, "failed to create the state bf_map object");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_STATE_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup state map FD");

    return 0;
}

static uint64_t _bf_dedup_hash(const void *data, void *ctx)
{
    return bf_fnv1a(data, *(const size_t *)ctx, bf_fnv1a_init());
}

static bool _bf_dedup_equal(const void *lhs, const void *rhs, void *ctx)
{
    return memcmp(lhs, rhs, *(const size_t *)ctx) == 0;
}

/**
 * @brief Load set maps, one BPF map per `bf_set_group`.
 *
 * Hash-keyed sets that share the same key format have already been
 * grouped by `_bf_program_build_set_groups()`; LPM trie sets each occupy
 * their own single-set group. Each group collapses to one BPF map whose
 * value is a bitmask: bit `i` of byte `i / CHAR_BIT` identifies the `i`-th
 * set in the group.
 *
 * Per-group keys and bitmask values are prepared in user space so a single
 * `bf_bpf_map_update_batch()` call populates the map on the kernel side.
 *
 * The map is created with room for `max(bf_set.min_size, element count)`
 * entries for each set in the group: a set that outgrows its `min_size`
 * grows the map on its own, it never borrows the room reserved for another
 * set of the group. Shared elements are stored once but counted once per
 * set, so the map over-reserves when grouped sets overlap; this is the cost
 * of keeping per-set reservations independent.
 * For each group, we calculate:
 * - `n_total_elems`: sum of `set.n_elems` for each sets of a group. Will count
 *   duplicates if any.
 * - `n_unique_elems`: same as `n_total_elems`, but doesn't count duplicate
 *   elements.
 * - `n_map_elems`: number of elements that we should have room for in the map,
 *   sum of `max(set.min_size, set.n_elems)` for each set in the group.
 *
 * Empty sets are not part of any group (see `_bf_program_build_set_groups()`),
 * so they get no map whatever their `min_size`: their reservation only takes
 * effect once they become non-empty and the program is regenerated.
 *
 * Group ownership of the created maps is transferred to `handle->sets`;
 * the `bf_set_group::map` pointer is a non-owning back-reference used by
 * `_bf_program_fixup()` when resolving `BF_FIXUP_TYPE_SET_MAP_FD` fixups.
 */
static int _bf_program_load_sets_maps(struct bf_program *new_prog)
{
    char name[BPF_OBJ_NAME_LEN];
    size_t map_idx = 0;
    int r;

    assert(new_prog);

    bf_list_foreach (&new_prog->set_groups, group_node) {
        struct bf_set_group *group = bf_list_node_get_data(group_node);
        const struct bf_set *key_set =
            bf_list_node_get_data(bf_list_get_head(&group->sets));
        size_t n_sets = bf_list_size(&group->sets);
        size_t i = 0;
        _cleanup_free_ uint8_t *keys = NULL;
        size_t key_size = key_set->elem_size;
        _cleanup_free_ uint8_t *values = NULL;
        size_t value_size = (n_sets + CHAR_BIT - 1) / CHAR_BIT;
        const bf_hashset_ops dedup_ops = {
            .hash = _bf_dedup_hash,
            .equal = _bf_dedup_equal,
            // The dedup hashset borrows elements from `bf_set`s.
            .free = NULL,
        };
        _clean_bf_hashset_ bf_hashset unique_elements =
            bf_hashset_default(&dedup_ops, &key_size);
        size_t n_total_elems = 0;
        size_t n_unique_elems;
        size_t n_map_elems = 0;
        _free_bf_map_ struct bf_map *new_map = NULL;
        struct bf_map *map_ref;

        /* Upper-bound the set capacity to avoid incremental rehashing, and
         * size the BPF map so every set is guaranteed room for
         * max(min_size, element count) entries, independently of the other
         * sets in the group. */
        bf_list_foreach (&group->sets, set_node) {
            const struct bf_set *set = bf_list_node_get_data(set_node);

            n_total_elems += bf_hashset_size(&set->elems);
            n_map_elems += bf_max(set->min_size, bf_hashset_size(&set->elems));
        }

        r = bf_hashset_reserve(&unique_elements, n_total_elems);
        if (r)
            return bf_err_r(r, "failed to reserve dedup hashset capacity");

        // Find all unique elements across all sets in this group.
        bf_list_foreach (&group->sets, set_node) {
            const struct bf_set *set = bf_list_node_get_data(set_node);

            bf_hashset_foreach (&set->elems, elem) {
                void *to_add = elem->data;
                r = bf_hashset_add(&unique_elements, &to_add);
                if (r && r != -EEXIST)
                    return bf_err_r(r, "failed to dedup element");
            }
        }
        n_unique_elems = bf_hashset_size(&unique_elements);

        // Compute bf_map keys and values for batch insertion.
        keys = calloc(n_unique_elems, key_size);
        if (!keys)
            return bf_err_r(-ENOMEM, "failed to allocate map keys");

        values = calloc(n_unique_elems, value_size);
        if (!values)
            return bf_err_r(-ENOMEM, "failed to allocate map values");

        bf_hashset_foreach (&unique_elements, hentry) {
            size_t bit_idx = 0;

            // Compute the key.
            memcpy(keys + (i * key_size), hentry->data, key_size);

            // Compute the value (bitmask).
            bf_list_foreach (&group->sets, set_node) {
                const struct bf_set *set = bf_list_node_get_data(set_node);

                if (bf_hashset_contains(&set->elems, hentry->data)) {
                    values[(i * value_size) + (bit_idx / CHAR_BIT)] |=
                        (uint8_t)(1U << (bit_idx % CHAR_BIT));
                }
                ++bit_idx;
            }
            ++i;
        }

        // Create the BPF map from the computed keys and values.
        (void)snprintf(name, BPF_OBJ_NAME_LEN, _BF_SET_MAP_PREFIX "%04x",
                       (uint16_t)map_idx++);

        r = bf_map_new_from_set(&new_map, name, key_set, n_map_elems,
                                value_size);
        if (r)
            return r;

        r = bf_bpf_map_update_batch(new_map->fd, keys, values, n_unique_elems,
                                    BPF_ANY);
        if (r)
            return bf_err_r(r, "failed to add set elements to the map");

        map_ref = new_map;
        r = bf_list_push(&new_prog->handle->sets, (void **)&new_map);
        if (r)
            return r;
        group->map = map_ref;
    }

    return _bf_program_fixup(new_prog, BF_FIXUP_TYPE_SET_MAP_FD);
}

int bf_program_load(struct bf_program *prog)
{
    _cleanup_free_ char *log_buf = NULL;
    bool log_enabled = bf_ctx_is_verbose(BF_VERBOSE_DEBUG);
    int r;

    assert(prog);

    r = _bf_program_load_sets_maps(prog);
    if (r)
        return bf_err_r(r, "failed to load the sets map");

    r = _bf_program_load_counters_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the counter map");

    r = _bf_program_load_printer_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the printer map");

    r = _bf_program_load_log_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the log map");

    r = _bf_program_load_state_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the state map");

    if (bf_ctx_is_verbose(BF_VERBOSE_BYTECODE))
        bf_program_dump_bytecode(prog);

retry_load:
    if (log_enabled) {
        log_buf = malloc(_BF_LOG_BUF_SIZE);
        if (!log_buf) {
            return bf_err_r(-ENOMEM,
                            "failed to allocate BPF_PROG_LOAD logs buffer");
        }
        log_buf[0] = '\0';
    }

    r = bf_bpf_prog_load(prog->handle->prog_name,
                         bf_hook_to_bpf_prog_type(prog->runtime.chain->hook),
                         prog->img.data, prog->img.size,
                         bf_hook_to_bpf_attach_type(prog->runtime.chain->hook),
                         log_buf, log_buf ? _BF_LOG_BUF_SIZE : 0,
                         bf_ctx_token(), &prog->handle->prog_fd);
    if (r && !log_enabled) {
        log_enabled = true;
        goto retry_load;
    }

    if (r) {
        return bf_err_r(r, "failed to load bf_program (%lu insns):\n%s\nerrno:",
                        prog->img.size, log_buf ? log_buf : "<NO LOG BUFFER>");
    }

    return r;
}

int bf_program_get_counter(const struct bf_program *program,
                           uint32_t counter_idx, struct bf_counter *counter)
{
    assert(program);
    assert(counter);

    return bf_handle_get_counter(program->handle, counter_idx, counter);
}

size_t bf_program_chain_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->runtime.chain->rules);
}

size_t bf_program_error_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->runtime.chain->rules) + 1;
}
