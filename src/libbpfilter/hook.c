/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/hook.h"

#include <linux/bpf.h>
#include <linux/netfilter.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "bpfilter/core/list.h"
#include "bpfilter/dump.h"
#include "bpfilter/flavor.h"
#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"

static const char *_bf_hook_strs[] = {
    [BF_HOOK_XDP] = "BF_HOOK_XDP",
    [BF_HOOK_TC_INGRESS] = "BF_HOOK_TC_INGRESS",
    [BF_HOOK_NF_PRE_ROUTING] = "BF_HOOK_NF_PRE_ROUTING",
    [BF_HOOK_NF_LOCAL_IN] = "BF_HOOK_NF_LOCAL_IN",
    [BF_HOOK_CGROUP_SKB_INGRESS] = "BF_HOOK_CGROUP_SKB_INGRESS",
    [BF_HOOK_CGROUP_SKB_EGRESS] = "BF_HOOK_CGROUP_SKB_EGRESS",
    [BF_HOOK_NF_FORWARD] = "BF_HOOK_NF_FORWARD",
    [BF_HOOK_NF_LOCAL_OUT] = "BF_HOOK_NF_LOCAL_OUT",
    [BF_HOOK_NF_POST_ROUTING] = "BF_HOOK_NF_POST_ROUTING",
    [BF_HOOK_TC_EGRESS] = "BF_HOOK_TC_EGRESS",
    [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4] = "BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4",
    [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6] = "BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6",
    [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4] = "BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4",
    [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6] = "BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6",
};
static_assert_enum_mapping(_bf_hook_strs, _BF_HOOK_MAX);

const char *bf_hook_to_str(enum bf_hook hook)
{
    if (hook < 0 || hook >= _BF_HOOK_MAX)
        return "<bf_hook unknown>";

    return _bf_hook_strs[hook];
}

int bf_hook_from_str(const char *str, enum bf_hook *hook)
{
    assert(hook);

    for (enum bf_hook i = 0; i < _BF_HOOK_MAX; ++i) {
        if (bf_streq(_bf_hook_strs[i], str)) {
            *hook = i;
            return 0;
        }
    }

    return -EINVAL;
}

enum bf_flavor bf_hook_to_flavor(enum bf_hook hook)
{
    static const enum bf_flavor flavors[] = {
        [BF_HOOK_XDP] = BF_FLAVOR_XDP,
        [BF_HOOK_TC_INGRESS] = BF_FLAVOR_TC,
        [BF_HOOK_NF_PRE_ROUTING] = BF_FLAVOR_NF,
        [BF_HOOK_NF_LOCAL_IN] = BF_FLAVOR_NF,
        [BF_HOOK_CGROUP_SKB_INGRESS] = BF_FLAVOR_CGROUP_SKB,
        [BF_HOOK_CGROUP_SKB_EGRESS] = BF_FLAVOR_CGROUP_SKB,
        [BF_HOOK_NF_FORWARD] = BF_FLAVOR_NF,
        [BF_HOOK_NF_LOCAL_OUT] = BF_FLAVOR_NF,
        [BF_HOOK_NF_POST_ROUTING] = BF_FLAVOR_NF,
        [BF_HOOK_TC_EGRESS] = BF_FLAVOR_TC,
        [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4] = BF_FLAVOR_CGROUP_SOCK_ADDR,
        [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6] = BF_FLAVOR_CGROUP_SOCK_ADDR,
        [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4] = BF_FLAVOR_CGROUP_SOCK_ADDR,
        [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6] = BF_FLAVOR_CGROUP_SOCK_ADDR,
    };

    static_assert_enum_mapping(flavors, _BF_HOOK_MAX);

    return flavors[hook];
}

enum bf_bpf_attach_type bf_hook_to_bpf_attach_type(enum bf_hook hook)
{
    static const enum bf_bpf_attach_type attach_types[] = {
        [BF_HOOK_XDP] = BF_BPF_XDP,
        [BF_HOOK_TC_INGRESS] = BF_BPF_TCX_INGRESS,
        [BF_HOOK_NF_PRE_ROUTING] = BF_BPF_NETFILTER,
        [BF_HOOK_NF_LOCAL_IN] = BF_BPF_NETFILTER,
        [BF_HOOK_CGROUP_SKB_INGRESS] = BF_BPF_CGROUP_INET_INGRESS,
        [BF_HOOK_CGROUP_SKB_EGRESS] = BF_BPF_CGROUP_INET_EGRESS,
        [BF_HOOK_NF_FORWARD] = BF_BPF_NETFILTER,
        [BF_HOOK_NF_LOCAL_OUT] = BF_BPF_NETFILTER,
        [BF_HOOK_NF_POST_ROUTING] = BF_BPF_NETFILTER,
        [BF_HOOK_TC_EGRESS] = BF_BPF_TCX_ENGRESS,
        [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4] = BF_BPF_CGROUP_INET4_CONNECT,
        [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6] = BF_BPF_CGROUP_INET6_CONNECT,
        [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4] = BF_BPF_CGROUP_UDP4_SENDMSG,
        [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6] = BF_BPF_CGROUP_UDP6_SENDMSG,
    };

    static_assert_enum_mapping(attach_types, _BF_HOOK_MAX);

    return attach_types[hook];
}

enum bf_bpf_prog_type bf_hook_to_bpf_prog_type(enum bf_hook hook)
{
    static const enum bf_bpf_prog_type prog_types[] = {
        [BF_HOOK_XDP] = BF_BPF_PROG_TYPE_XDP,
        [BF_HOOK_TC_INGRESS] = BF_BPF_PROG_TYPE_SCHED_CLS,
        [BF_HOOK_NF_PRE_ROUTING] = BF_BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_NF_LOCAL_IN] = BF_BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_CGROUP_SKB_INGRESS] = BF_BPF_PROG_TYPE_CGROUP_SKB,
        [BF_HOOK_CGROUP_SKB_EGRESS] = BF_BPF_PROG_TYPE_CGROUP_SKB,
        [BF_HOOK_NF_FORWARD] = BF_BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_NF_LOCAL_OUT] = BF_BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_NF_POST_ROUTING] = BF_BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_TC_EGRESS] = BF_BPF_PROG_TYPE_SCHED_CLS,
        [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4] = BF_BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        [BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6] = BF_BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4] = BF_BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        [BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6] = BF_BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    };

    static_assert_enum_mapping(prog_types, _BF_HOOK_MAX);

    return prog_types[hook];
}

enum bf_nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook)
{
    switch (hook) {
    case BF_HOOK_NF_PRE_ROUTING:
        return BF_NF_INET_PRE_ROUTING;
    case BF_HOOK_NF_LOCAL_IN:
        return BF_NF_INET_LOCAL_IN;
    case BF_HOOK_NF_FORWARD:
        return BF_NF_INET_FORWARD;
    case BF_HOOK_NF_LOCAL_OUT:
        return BF_NF_INET_LOCAL_OUT;
    case BF_HOOK_NF_POST_ROUTING:
        return BF_NF_INET_POST_ROUTING;
    default:
        bf_warn("bf_hook %s (%d) is not an bf_nf_inet_hooks value",
                bf_hook_to_str(hook), hook);
        return -EINVAL;
    }
}

enum bf_hook bf_hook_from_nf_hook(enum bf_nf_inet_hooks hook)
{
    switch (hook) {
    case BF_NF_INET_PRE_ROUTING:
        return BF_HOOK_NF_PRE_ROUTING;
    case BF_NF_INET_LOCAL_IN:
        return BF_HOOK_NF_LOCAL_IN;
    case BF_NF_INET_FORWARD:
        return BF_HOOK_NF_FORWARD;
    case BF_NF_INET_LOCAL_OUT:
        return BF_HOOK_NF_LOCAL_OUT;
    case BF_NF_INET_POST_ROUTING:
        return BF_HOOK_NF_POST_ROUTING;
    default:
        bf_warn("nf_inet_hooks %s (%d) is not a bf_hook value",
                bf_nf_hook_to_str(hook), hook);
        return -EINVAL;
    }
}

const char *bf_nf_hook_to_str(enum bf_nf_inet_hooks hook)
{
    switch (hook) {
    case BF_NF_INET_PRE_ROUTING:
        return "nf_prerouting";
    case BF_NF_INET_LOCAL_IN:
        return "nf_input";
    case BF_NF_INET_FORWARD:
        return "nf_forward";
    case BF_NF_INET_LOCAL_OUT:
        return "nf_output";
    case BF_NF_INET_POST_ROUTING:
        return "nf_postrouting";
    default:
        bf_warn("unknown nf_inet_hooks value %d", hook);
        return NULL;
    }
}

static int _bf_hookopts_ifindex_parse(struct bf_hookopts *hookopts,
                                      const char *raw_opt)
{
    unsigned long ifindex;

    assert(hookopts);
    assert(raw_opt);

    if (hookopts->used_opts & BF_FLAG(BF_HOOKOPTS_IFINDEX))
        return bf_err_r(-EEXIST, "ifindex= is defined multiple times");

    errno = 0;
    ifindex = strtoul(raw_opt, NULL, 0);
    if (errno != 0) {
        return bf_err_r(-errno, "failed to parse bf_hookopts type ifindex=%s",
                        raw_opt);
    }

    if (ifindex > INT_MAX)
        return bf_err_r(-E2BIG, "ifindex is too big: %lu", ifindex);

    hookopts->ifindex = (int)ifindex;
    hookopts->used_opts |= BF_FLAG(BF_HOOKOPTS_IFINDEX);

    return 0;
}

static void _bf_hookopts_ifindex_dump(const struct bf_hookopts *hookopts,
                                      prefix_t *prefix)
{
    assert(hookopts);
    assert(prefix);

    DUMP(prefix, "ifindex: %d", hookopts->ifindex);
}

static int _bf_hookopts_cgpath_parse(struct bf_hookopts *hookopts,
                                     const char *raw_opt)
{
    assert(hookopts);
    assert(raw_opt);

    if (hookopts->used_opts & BF_FLAG(BF_HOOKOPTS_CGPATH))
        return bf_err_r(-EEXIST, "cgpath= is defined multiple times");

    hookopts->cgpath = strdup(raw_opt);
    if (!hookopts->cgpath) {
        return bf_err_r(-ENOMEM, "failed to copy hook option cgpath=%s",
                        raw_opt);
    }

    hookopts->used_opts |= BF_FLAG(BF_HOOKOPTS_CGPATH);

    return 0;
}

static void _bf_hookopts_cgpath_dump(const struct bf_hookopts *hookopts,
                                     prefix_t *prefix)
{
    assert(hookopts);
    assert(prefix);

    DUMP(prefix, "cgpath: %s", hookopts->cgpath);
}

static int _bf_hookopts_family_parse(struct bf_hookopts *hookopts,
                                     const char *raw_opt)
{
    assert(hookopts);
    assert(raw_opt);

    if (hookopts->used_opts & BF_FLAG(BF_HOOKOPTS_FAMILY))
        return bf_err_r(-EEXIST, "family= is defined multiple times");

    if (bf_streq("inet4", raw_opt) || bf_streq("inet6", raw_opt)) {
        bf_warn(
            "family= hook option is deprecated for Netfilter chains, bpfilter will automatically filter on both the IPv4 and IPv6 families");
    } else {
        return bf_err_r(-ENOTSUP, "unknown netfilter family '%s'", raw_opt);
    }

    return 0;
}

static void _bf_hookopts_family_dump(const struct bf_hookopts *hookopts,
                                     prefix_t *prefix)
{
    assert(hookopts);
    assert(prefix);

    (void)hookopts;

    DUMP(prefix, "family: <deprecated>");
}

static int _bf_hookopts_priorities_parse(struct bf_hookopts *hookopts,
                                         const char *raw_opt)
{
    unsigned long priorities[2];
    _cleanup_free_ char *copy = NULL;
    char *right, *end;

    assert(hookopts);
    assert(raw_opt);

    if (hookopts->used_opts & BF_FLAG(BF_HOOKOPTS_PRIORITIES))
        return bf_err_r(-EEXIST, "priorities= is defined multiple times");

    copy = strdup(raw_opt);
    if (!copy)
        return -ENOMEM;

    end = copy + strlen(copy);

    right = strchr(copy, '-');
    if (!right)
        goto err_parsing;

    *right = '\0';
    ++right;
    if (end <= right)
        goto err_parsing;

    errno = 0;
    priorities[0] = strtoul(copy, NULL, 0);
    if (errno != 0)
        goto err_parsing;

    priorities[1] = strtoul(right, NULL, 0);
    if (errno != 0)
        goto err_parsing;

    if (priorities[0] > INT_MAX || priorities[1] > INT_MAX)
        return bf_err_r(-EINVAL, "priorities can't be bigger than %d", INT_MAX);

    if (priorities[0] == priorities[1])
        return bf_err_r(-EINVAL, "priorities must be different");

    if (!priorities[0] || !priorities[1])
        return bf_err_r(-EINVAL, "priorities can't be 0");

    hookopts->priorities[0] = (int)priorities[0];
    hookopts->priorities[1] = (int)priorities[1];
    hookopts->used_opts |= BF_FLAG(BF_HOOKOPTS_PRIORITIES);

    return 0;

err_parsing:
    return bf_err_r(-EINVAL, "failed to parse '%s', expecting '$INT-$INT'",
                    raw_opt);
}

static void _bf_hookopts_priorities_dump(const struct bf_hookopts *hookopts,
                                         prefix_t *prefix)
{
    assert(hookopts);
    assert(prefix);

    DUMP(prefix, "priorities: %d, %d", hookopts->priorities[0],
         hookopts->priorities[1]);
}

static struct bf_hookopts_ops
{
    const char *name;
    enum bf_hookopts_type type;
    uint32_t supported_by;
    uint32_t required_by;
    int (*parse)(struct bf_hookopts *, const char *);
    void (*dump)(const struct bf_hookopts *, prefix_t *);
} _bf_hookopts_ops[] = {
    [BF_HOOKOPTS_IFINDEX] =
        {
            .name = "ifindex",
            .type = BF_HOOKOPTS_IFINDEX,
            .required_by = BF_FLAGS(BF_FLAVOR_XDP, BF_FLAVOR_TC),
            .supported_by = 0,
            .parse = _bf_hookopts_ifindex_parse,
            .dump = _bf_hookopts_ifindex_dump,
        },
    [BF_HOOKOPTS_CGPATH] =
        {
            .name = "cgpath",
            .type = BF_HOOKOPTS_CGPATH,
            .required_by =
                BF_FLAGS(BF_FLAVOR_CGROUP_SKB, BF_FLAVOR_CGROUP_SOCK_ADDR),
            .supported_by = 0,
            .parse = _bf_hookopts_cgpath_parse,
            .dump = _bf_hookopts_cgpath_dump,
        },
    /** @deprecated Hook option `family=` is deprecated for Netfilter chains.
     * bpfilter will automatically filter on both the IPv4 and IPv6 families. */
    [BF_HOOKOPTS_FAMILY] =
        {
            .name = "family",
            .type = BF_HOOKOPTS_FAMILY,
            .required_by = 0,
            .supported_by = 0,
            .parse = _bf_hookopts_family_parse,
            .dump = _bf_hookopts_family_dump,
        },
    [BF_HOOKOPTS_PRIORITIES] =
        {
            .name = "priorities",
            .type = BF_HOOKOPTS_PRIORITIES,
            .required_by = BF_FLAGS(BF_FLAVOR_NF),
            .supported_by = 0,
            .parse = _bf_hookopts_priorities_parse,
            .dump = _bf_hookopts_priorities_dump,
        },
};

static_assert_enum_mapping(_bf_hookopts_ops, _BF_HOOKOPTS_MAX);

#define _bf_hookopts_is_required(type, flavor)                                 \
    (_bf_hookopts_ops[type].required_by & BF_FLAG(flavor))

#define _bf_hookopts_is_supported(type, flavor)                                \
    ((_bf_hookopts_ops[type].supported_by & BF_FLAG(flavor)) ||                \
     _bf_hookopts_is_required((type), (flavor)))

static struct bf_hookopts_ops *_bf_hookopts_get_ops(const char *key)
{
    assert(key);

    for (enum bf_hookopts_type type = 0; type < _BF_HOOKOPTS_MAX; ++type) {
        if (bf_streq(_bf_hookopts_ops[type].name, key))
            return &_bf_hookopts_ops[type];
    }

    return NULL;
}

int bf_hookopts_new(struct bf_hookopts **hookopts)
{
    assert(hookopts);

    *hookopts = calloc(1, sizeof(struct bf_hookopts));
    if (!*hookopts)
        return bf_err_r(-ENOMEM, "failed to allocate a new bf_hookopts object");

    return 0;
}

int bf_hookopts_new_from_pack(struct bf_hookopts **hookopts,
                              bf_rpack_node_t node)
{
    _free_bf_hookopts_ struct bf_hookopts *_hookopts = NULL;
    bf_rpack_node_t child;
    int r;

    assert(hookopts);

    r = bf_hookopts_new(&_hookopts);
    if (r)
        return bf_err_r(r, "failed to create bf_hookopts from pack");

    r = bf_rpack_kv_node(node, "ifindex", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_hookopts.ifindex");
    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_int(child, &_hookopts->ifindex);
        if (r)
            return bf_rpack_key_err(r, "bf_hookopt.ifindex");

        _hookopts->used_opts |= BF_FLAG(BF_HOOKOPTS_IFINDEX);
    }

    r = bf_rpack_kv_node(node, "cgpath", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_hookopts.cgpath");
    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_str(child, (char **)&_hookopts->cgpath);
        if (r)
            return bf_rpack_key_err(r, "bf_hookopts.cgpath");

        _hookopts->used_opts |= BF_FLAG(BF_HOOKOPTS_CGPATH);
    }

    r = bf_rpack_kv_node(node, "family", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_hookopts.family");
    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_uint(child, &_hookopts->family);
        if (r)
            return bf_rpack_key_err(r, "bf_hookopts.family");

        _hookopts->used_opts |= BF_FLAG(BF_HOOKOPTS_FAMILY);
    }

    r = bf_rpack_kv_node(node, "priorities", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_hookopts.priorities");
    if (!bf_rpack_is_nil(child)) {
        bf_rpack_node_t child, p_node;

        r = bf_rpack_kv_array(node, "priorities", &child);
        if (r)
            return bf_rpack_key_err(r, "bf_hookopts.priorities");
        if (bf_rpack_array_count(child) != 2) {
            return bf_err_r(
                -EINVAL, "bf_hookopts.priorities pack expects only 2 values");
        }

        bf_rpack_array_foreach (child, p_node) {
            r = bf_rpack_int(p_node, &_hookopts->priorities[i]);
            if (r) {
                return bf_rpack_key_err(
                    r, "failed to unpack bf_hookopts.priorities value");
            }
        }

        _hookopts->used_opts |= BF_FLAG(BF_HOOKOPTS_PRIORITIES);
    }

    *hookopts = TAKE_PTR(_hookopts);

    return 0;
}

void bf_hookopts_clean(struct bf_hookopts *hookopts)
{
    BF_FREEP(&hookopts->cgpath);
}

void bf_hookopts_free(struct bf_hookopts **hookopts)
{
    assert(hookopts);

    if (!*hookopts)
        return;

    bf_hookopts_clean(*hookopts);
    BF_FREEP(hookopts);
}

int bf_hookopts_pack(const struct bf_hookopts *hookopts, bf_wpack_t *pack)
{
    assert(hookopts);
    assert(pack);

    if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_IFINDEX))
        bf_wpack_kv_int(pack, "ifindex", hookopts->ifindex);
    else
        bf_wpack_kv_nil(pack, "ifindex");

    if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_CGPATH))
        bf_wpack_kv_str(pack, "cgpath", hookopts->cgpath);
    else
        bf_wpack_kv_nil(pack, "cgpath");

    if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_FAMILY))
        bf_wpack_kv_uint(pack, "family", hookopts->family);
    else
        bf_wpack_kv_nil(pack, "family");

    if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_PRIORITIES)) {
        bf_wpack_open_array(pack, "priorities");
        bf_wpack_int(pack, hookopts->priorities[0]);
        bf_wpack_int(pack, hookopts->priorities[1]);
        bf_wpack_close_array(pack);
    } else {
        bf_wpack_kv_nil(pack, "priorities");
    }

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_hookopts_dump(const struct bf_hookopts *hookopts, prefix_t *prefix)
{
    assert(hookopts);
    assert(prefix);

    DUMP(prefix, "struct bf_hookopts at %p", hookopts);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "used_opts: 0x%08x", hookopts->used_opts);

    for (enum bf_hookopts_type type = 0; type < _BF_HOOKOPTS_MAX; ++type) {
        if (type == _BF_HOOKOPTS_MAX - 1)
            bf_dump_prefix_last(prefix);

        if (bf_hookopts_is_used(hookopts, type))
            _bf_hookopts_ops[type].dump(hookopts, prefix);
        else
            DUMP(prefix, "%s: <unset>", _bf_hookopts_ops[type].name);
    }

    bf_dump_prefix_pop(prefix);
}

int bf_hookopts_parse_opt(struct bf_hookopts *hookopts, const char *raw_opt)
{
    char *value;
    struct bf_hookopts_ops *ops;
    int r;

    assert(hookopts);
    assert(raw_opt);

    value = strchr(raw_opt, '=');
    if (!value)
        return -ENOENT;

    *value = '\0';
    ++value;

    ops = _bf_hookopts_get_ops(raw_opt);
    if (!ops) {
        return bf_err_r(-ENOTSUP, "unknown hook option '%s', ignoring",
                        raw_opt);
    }

    r = ops->parse(hookopts, value);
    if (r < 0)
        return r;

    return 0;
}

int bf_hookopts_parse_opts(struct bf_hookopts *hookopts, bf_list *raw_opts)
{
    int r;

    assert(hookopts);
    assert(raw_opts);

    if (!raw_opts)
        return 0;

    bf_list_foreach (raw_opts, raw_opt_node) {
        r = bf_hookopts_parse_opt(hookopts,
                                  bf_list_node_get_data(raw_opt_node));
        if (r)
            return r;
    }

    return 0;
}

int bf_hookopts_validate(const struct bf_hookopts *hookopts, enum bf_hook hook)
{
    enum bf_flavor flavor = bf_hook_to_flavor(hook);

    assert(hookopts);

    for (enum bf_hookopts_type type = 0; type < _BF_HOOKOPTS_MAX; ++type) {
        struct bf_hookopts_ops *ops = &_bf_hookopts_ops[type];
        bool is_used = bf_hookopts_is_used(hookopts, type);
        bool is_required = _bf_hookopts_is_required(type, flavor);
        bool is_supported = _bf_hookopts_is_supported(type, flavor);

        if (is_required && !is_used) {
            return bf_err_r(-EINVAL,
                            "hook option '%s' is required for '%s' chains",
                            ops->name, bf_hook_to_str(hook));
        }

        if (is_used && !(is_supported | is_required)) {
            return bf_err_r(-ENOTSUP,
                            "hook option '%s' is not supported for '%s' chains",
                            ops->name, bf_hook_to_str(hook));
        }
    }

    return 0;
}
