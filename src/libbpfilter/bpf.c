// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/bpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpfilter/bpf_types.h"
#include "bpfilter/btf.h"
#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

#ifdef __i386__
#define _BF_NR_bpf 357
#elif defined(__x86_64__)
#define _BF_NR_bpf 321
#elif defined(__aarch64__)
#define _BF_NR_bpf 280
#elif defined(__loongarch__)
#define _BF_NR_bpf 280
#else
#error _BF_NR_bpf not defined. bpfilter does not support your arch.
#endif

int bf_bpf(enum bf_bpf_cmd cmd, union bpf_attr *attr)
{
    int r = (int)syscall(_BF_NR_bpf, cmd, attr, sizeof(*attr));
    if (r < 0)
        return -errno;

    return r;
}

int bf_bpf_prog_load(const char *name, enum bf_bpf_prog_type prog_type,
                     void *img, size_t img_len,
                     enum bf_bpf_attach_type attach_type, const char *log_buf,
                     size_t log_size, int token_fd, int *fd)
{
    union bpf_attr attr;
    int r;

    assert(name);
    assert(img);
    assert(fd);

    memset(&attr, 0, sizeof(attr));

    attr.prog_type = prog_type;
    attr.insns = bf_ptr_to_u64(img);
    attr.insn_cnt = (unsigned int)img_len;
    attr.license = bf_ptr_to_u64("GPL");
    attr.expected_attach_type = attach_type;
    attr.log_buf = bf_ptr_to_u64(log_buf);
    attr.log_size = log_size;
    attr.log_level = log_buf ? 1 : 0;

    (void)snprintf(attr.prog_name, BPF_OBJ_NAME_LEN, "%s", name);

    if (token_fd != -1) {
        attr.prog_token_fd = token_fd;
        attr.prog_flags |= (uint32_t)BPF_F_TOKEN_FD;
    }

    r = bf_bpf(BF_BPF_PROG_LOAD, &attr);
    if (r < 0)
        return r;

    *fd = r;

    return 0;
}

int bf_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr;

    assert(key);
    assert(value);

    memset(&attr, 0, sizeof(attr));

    attr.map_fd = fd;
    attr.key = (uint64_t)key;
    attr.value = (uint64_t)value;

    return bf_bpf(BF_BPF_MAP_LOOKUP_ELEM, &attr);
}

int bf_bpf_map_get_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr attr;

    assert(info);

    memset(&attr, 0, sizeof(attr));
    memset(info, 0, sizeof(*info));

    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = bf_ptr_to_u64(info);

    return bf_bpf(BF_BPF_OBJ_GET_INFO_BY_FD, &attr);
}

int bf_bpf_obj_pin(const char *path, int fd, int dir_fd)
{
    union bpf_attr attr;

    assert(path);
    assert(dir_fd >= 0);
    assert(path[0] == '/' ? !dir_fd : 1);

    memset(&attr, 0, sizeof(attr));

    attr.pathname = bf_ptr_to_u64(path);
    attr.bpf_fd = fd;
    attr.file_flags = dir_fd ? BPF_F_PATH_FD : 0;
    attr.path_fd = dir_fd;

    return bf_bpf(BF_BPF_OBJ_PIN, &attr);
}

int bf_bpf_obj_get(const char *path, int dir_fd, int *fd)
{
    union bpf_attr attr;
    int r;

    assert(path);
    assert(fd);
    assert(dir_fd >= 0);
    assert(path[0] == '/' ? !dir_fd : 1);

    memset(&attr, 0, sizeof(attr));

    attr.pathname = bf_ptr_to_u64(path);
    attr.file_flags = dir_fd ? BPF_F_PATH_FD : 0;
    attr.path_fd = dir_fd;

    r = bf_bpf(BF_BPF_OBJ_GET, &attr);
    if (r < 0)
        return r;

    *fd = r;

    return 0;
}

int bf_bpf_prog_run(int prog_fd, const void *pkt, size_t pkt_len,
                    const void *ctx, size_t ctx_len)
{
    union bpf_attr attr;
    int r;

    assert(pkt);
    assert(pkt_len > 0);
    assert(!(!!ctx ^ !!ctx_len));

    memset(&attr, 0, sizeof(attr));

    attr.test.prog_fd = prog_fd;
    attr.test.data_size_in = pkt_len;
    attr.test.data_in = (unsigned long long)pkt;
    attr.test.repeat = 1;

    if (ctx_len) {
        attr.test.ctx_size_in = ctx_len;
        attr.test.ctx_in = (unsigned long long)ctx;
    }

    r = bf_bpf(BF_BPF_PROG_TEST_RUN, &attr);
    if (r)
        return bf_err_r(r, "failed to run the test program");

    return (int)attr.test.retval;
}

int bf_bpf_token_create(int bpffs_fd)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.token_create.bpffs_fd = bpffs_fd;

    return bf_bpf(BF_BPF_TOKEN_CREATE, &attr);
}

int bf_bpf_btf_load(const void *btf_data, size_t btf_data_len, int token_fd)
{
    assert(btf_data);

    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.btf = bf_ptr_to_u64(btf_data);
    attr.btf_size = btf_data_len;

    if (token_fd != -1) {
        attr.btf_token_fd = token_fd;
        attr.btf_flags |= (uint32_t)BPF_F_TOKEN_FD;
    }

    return bf_bpf(BF_BPF_BTF_LOAD, &attr);
}

int bf_bpf_map_create(const char *name, enum bf_bpf_map_type type,
                      size_t key_size, size_t value_size, size_t n_elems,
                      const struct bf_btf *btf, int token_fd)
{
    assert(name);

    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = n_elems;

    // NO_PREALLOC is *required* for LPM_TRIE map
    if (type == BF_BPF_MAP_TYPE_LPM_TRIE)
        attr.map_flags |= (uint32_t)BPF_F_NO_PREALLOC;

    if (token_fd != -1) {
        attr.map_token_fd = token_fd;
        attr.map_flags |= (uint32_t)BPF_F_TOKEN_FD;
    };

    if (btf) {
        attr.btf_fd = btf->fd;
        attr.btf_key_type_id = btf->key_type_id;
        attr.btf_value_type_id = btf->value_type_id;
    }

    (void)snprintf(attr.map_name, BPF_OBJ_NAME_LEN, "%s", name);

    return bf_bpf(BF_BPF_MAP_CREATE, &attr);
}

int bf_bpf_map_update_elem(int map_fd, const void *key, const void *value,
                           int flags)
{
    assert(key);
    assert(value);

    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.map_fd = map_fd;
    attr.key = bf_ptr_to_u64(key);
    attr.value = bf_ptr_to_u64(value);
    attr.flags = flags;

    return bf_bpf(BF_BPF_MAP_UPDATE_ELEM, &attr);
}

int bf_bpf_map_update_batch(int map_fd, const void *keys, const void *values,
                            size_t count, int flags)
{
    assert(keys);
    assert(values);

    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.batch.map_fd = map_fd;
    attr.batch.keys = bf_ptr_to_u64(keys);
    attr.batch.values = bf_ptr_to_u64(values);
    attr.batch.count = count;
    attr.batch.flags = flags;

    return bf_bpf(BF_BPF_MAP_UPDATE_BATCH, &attr);
}

int bf_bpf_link_create(int prog_fd, int target_fd, enum bf_hook hook, int flags,
                       uint32_t family, int32_t priority)
{
    enum bf_bpf_attach_type attach_type;
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attach_type = bf_hook_to_bpf_attach_type(hook);

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = target_fd;
    attr.link_create.attach_type = attach_type;
    attr.link_create.flags = flags;

    if (attach_type == BF_BPF_NETFILTER) {
        attr.link_create.netfilter.pf = family;
        attr.link_create.netfilter.hooknum = bf_hook_to_nf_hook(hook);
        attr.link_create.netfilter.priority = priority;
    }

    return bf_bpf(BF_BPF_LINK_CREATE, &attr);
}

int bf_bpf_link_update(int link_fd, int new_prog_fd)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.link_update.link_fd = link_fd;
    attr.link_update.new_map_fd = new_prog_fd;

    return bf_bpf(BF_BPF_LINK_UPDATE, &attr);
}

int bf_bpf_link_detach(int link_fd)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.link_detach.link_fd = link_fd;

    return bf_bpf(BF_BPF_LINK_DETACH, &attr);
}
