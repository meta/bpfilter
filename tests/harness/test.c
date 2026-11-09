/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */
#define _XOPEN_SOURCE 700
#include "test.h"

#include <ftw.h>
#include <sys/socket.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>

#include "bpfilter/core/list.h"

void bft_assert_counter_eq(const char *chain_name, size_t rule_idx,
                           uint64_t packets, int64_t bytes)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hopts = NULL;
    struct bf_rule *rule;

    assert_non_null(chain_name);

    assert_ok(bf_chain_get(chain_name, &chain, &hopts));

    rule = bf_list_get_at(&chain->rules, rule_idx);
    assert_non_null(rule);
    assert_true(rule->has_counters);
    assert_int_equal(packets, rule->counters.count);
    if (bytes >= 0)
        assert_int_equal((uint64_t)bytes, rule->counters.size);
}

void bft_assert_error_counter_eq(const char *chain_name, uint64_t packets)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hopts = NULL;

    assert_non_null(chain_name);

    assert_ok(bf_chain_get(chain_name, &chain, &hopts));
    assert_int_equal(packets, chain->error_counters.count);
}

int btf_setup_redirect_streams(void **state)
{
    bf_log_set_level(BF_LOG_DBG);
    return bft_streams_new((struct bft_streams **)state);
}

int bft_teardown_redirect_streams(void **state)
{
    bf_log_set_level(BF_LOG_INFO);
    bft_stream_free((struct bft_streams **)state);
    return 0;
}

#define _free_bft_streams_ __attribute__((cleanup(bft_stream_free)))

int bft_streams_new(struct bft_streams **streams)
{
    _free_bft_streams_ struct bft_streams *_streams = NULL;
    int r;

    assert(streams);

    _streams = calloc(1, sizeof(*_streams));
    if (!_streams)
        return -ENOMEM;

    _streams->old_stdout = stdout;
    _streams->old_stderr = stderr;

    _streams->new_stdout =
        open_memstream(&_streams->stdout_buf, &_streams->stdout_len);
    if (!_streams->new_stdout) {
        (void)fprintf(_streams->old_stderr,
                      "failed to open new stdout stream\n");
        return -EINVAL;
    }

    _streams->new_stderr =
        open_memstream(&_streams->stderr_buf, &_streams->stderr_len);
    if (!_streams->new_stderr) {
        (void)fprintf(_streams->old_stderr,
                      "failed to open new stderr stream\n");
        return -EINVAL;
    }

    stdout = _streams->new_stdout;
    stderr = _streams->new_stderr;

    *streams = TAKE_PTR(_streams);

    return 0;
}

void bft_stream_free(struct bft_streams **streams)
{
    struct bft_streams *_streams;
    int r;

    assert(streams);

    _streams = *streams;
    if (!_streams)
        return;

    stdout = _streams->old_stdout;
    stderr = _streams->old_stderr;

    (void)fclose(_streams->new_stdout);
    (void)fclose(_streams->new_stderr);

    BF_FREEP(&_streams->stdout_buf);
    BF_FREEP(&_streams->stderr_buf);
    BF_FREEP(streams);
}

int btf_setup_create_sockets(void **state)
{
    return bft_sockets_new((struct bft_sockets **)state);
}

int bft_teardown_close_sockets(void **state)
{
    bft_sockets_free((struct bft_sockets **)state);
    return 0;
}

#define _free_bft_sockets_ __attribute__((cleanup(bft_sockets_free)))

int bft_sockets_new(struct bft_sockets **sockets)
{
    _free_bft_sockets_ struct bft_sockets *_sockets = NULL;
    int pair[2];
    int r;

    assert(sockets);

    _sockets = malloc(sizeof(*_sockets));
    if (!_sockets)
        return -ENOMEM;

    r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    if (r) {
        (void)fprintf(stderr, "failed to create socket pair: %d\n", errno);
        return -errno;
    }

    _sockets->client_fd = pair[0];
    _sockets->server_fd = pair[1];

    *sockets = TAKE_PTR(_sockets);

    return 0;
}

void bft_sockets_free(struct bft_sockets **sockets)
{
    struct bft_sockets *_sockets;

    assert(sockets);

    _sockets = *sockets;
    if (!_sockets)
        return;

    closep(&_sockets->client_fd);
    closep(&_sockets->server_fd);
    BF_FREEP(sockets);
}

int btf_setup_create_tmpdir(void **state)
{
    return bft_tmpdir_new((struct bft_tmpdir **)state);
}

int bft_teardown_close_tmpdir(void **state)
{
    bft_tmpdir_free((struct bft_tmpdir **)state);
    return 0;
}

#define _free_bft_tmpdir_ __attribute__((cleanup(bft_tmpdir_free)))

int bft_tmpdir_new(struct bft_tmpdir **tmpdir)
{
    _free_bft_tmpdir_ struct bft_tmpdir *_tmpdir = NULL;
    int r;

    _tmpdir = malloc(sizeof(*_tmpdir));
    if (!_tmpdir)
        return -ENOMEM;

    strncpy(_tmpdir->path_template, "/tmp/bft.XXXXXX",
            sizeof(_tmpdir->path_template));

    _tmpdir->dir_path = mkdtemp(_tmpdir->path_template);
    if (!_tmpdir)
        return -errno;

    *tmpdir = TAKE_PTR(_tmpdir);

    return 0;
}

static int _bft_unlink_cb(const char *fpath, const struct stat *sb,
                          int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;

    return remove(fpath);
}

void bft_tmpdir_free(struct bft_tmpdir **tmpdir)
{
    struct bft_tmpdir *_tmpdir;

    assert(tmpdir);

    _tmpdir = *tmpdir;
    if (!_tmpdir)
        return;

    nftw(_tmpdir->dir_path, _bft_unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
    BF_FREEP(tmpdir);
}

bool bft_list_eq(const bf_list *lhs, const bf_list *rhs, bft_list_eq_cb cb)
{
    if (bf_list_size(lhs) != bf_list_size(rhs))
        return false;

    if (!cb)
        return true;

    for (const bf_list_node *lhs_node = bf_list_get_head(lhs),
                            *rhs_node = bf_list_get_head(rhs);
         lhs_node && rhs_node; lhs_node = bf_list_node_next(lhs_node),
                            rhs_node = bf_list_node_next(rhs_node)) {
        if (!cb(bf_list_node_get_data(lhs_node),
                bf_list_node_get_data(rhs_node)))
            return false;
    }

    return true;
}

bool bft_counter_eq(const struct bf_counter *lhs, const struct bf_counter *rhs)
{
    return lhs->count == rhs->count && lhs->size == rhs->size;
}

bool bft_set_eq_ordered(const struct bf_set *lhs, const struct bf_set *rhs)
{
    if (bf_hashset_size(&lhs->elems) != bf_hashset_size(&rhs->elems))
        return false;

    if (lhs->elem_size != rhs->elem_size)
        return false;

    for (bf_hashset_elem *n0 = lhs->elems.head, *n1 = rhs->elems.head; n0 || n1;
         n0 = n0 ? n0->next : NULL, n1 = n1 ? n1->next : NULL) {
        if (!n0 || !n1 || memcmp(n0->data, n1->data, lhs->elem_size) != 0)
            return false;
    }

    return (lhs->name == rhs->name || bf_streq(lhs->name, rhs->name)) &&
           lhs->n_comps == rhs->n_comps &&
           0 == memcmp(lhs->key, rhs->key,
                       sizeof(enum bf_matcher_type) * lhs->n_comps) &&
           lhs->use_trie == rhs->use_trie && lhs->min_size == rhs->min_size;
}

bool bft_chain_equal(const struct bf_chain *chain0,
                     const struct bf_chain *chain1)
{
    if (!bf_streq(chain0->name, chain1->name))
        return false;

    if (chain0->flags != chain1->flags)
        return false;

    if (bf_hashset_size(&chain0->sets) != bf_hashset_size(&chain1->sets))
        return false;

    for (bf_hashset_elem *left = chain0->sets.head, *right = chain1->sets.head;
         left && right; left = left->next, right = right->next) {
        if (!bft_set_eq_ordered(left->data, right->data))
            return false;
    }

    return bf_streq(chain0->name, chain1->name) &&
           chain0->flags == chain1->flags && chain0->hook == chain1->hook &&
           chain0->policy == chain1->policy &&
           bft_list_eq(&chain0->rules, &chain1->rules,
                       (bft_list_eq_cb)bft_rule_equal);
}

bool bft_rule_equal(const struct bf_rule *rule0, const struct bf_rule *rule1)
{
    return rule0->index == rule1->index && rule0->log == rule1->log &&
           rule0->log_rate_ns == rule1->log_rate_ns &&
           rule0->mark == rule1->mark &&
           rule0->has_counters == rule1->has_counters &&
           rule0->verdict == rule1->verdict &&
           rule0->redirect_ifindex == rule1->redirect_ifindex &&
           rule0->redirect_dir == rule1->redirect_dir &&
           bft_list_eq(&rule0->matchers, &rule1->matchers,
                       (bft_list_eq_cb)bft_matcher_equal);
}

bool bft_matcher_equal(const struct bf_matcher *matcher0,
                       const struct bf_matcher *matcher1)
{
    if (bf_matcher_get_type(matcher0) == BF_MATCHER_SET &&
        bf_matcher_get_type(matcher1) == BF_MATCHER_SET) {
        const struct bf_set *set0;
        const struct bf_set *set1;

        memcpy(&set0, bf_matcher_payload(matcher0), sizeof(set0));
        memcpy(&set1, bf_matcher_payload(matcher1), sizeof(set1));
        return bf_matcher_get_op(matcher0) == bf_matcher_get_op(matcher1) &&
               bf_matcher_get_negate(matcher0) ==
                   bf_matcher_get_negate(matcher1) &&
               bft_set_eq_ordered(set0, set1);
    }

    return bf_matcher_get_type(matcher0) == bf_matcher_get_type(matcher1) &&
           bf_matcher_get_op(matcher0) == bf_matcher_get_op(matcher1) &&
           bf_matcher_get_negate(matcher0) == bf_matcher_get_negate(matcher1) &&
           bf_matcher_payload_len(matcher0) ==
               bf_matcher_payload_len(matcher1) &&
           0 == memcmp(bf_matcher_payload(matcher0),
                       bf_matcher_payload(matcher1),
                       bf_matcher_payload_len(matcher0));
}

int bft_setup_ctx(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    int r;

    r = bft_tmpdir_new(&tmpdir);
    if (r)
        return r;

    r = bf_ctx_setup(false, tmpdir->dir_path, BF_FLAG(BF_VERBOSE_DEBUG));
    if (r)
        return r;

    *state = TAKE_PTR(tmpdir);

    return 0;
}

int bft_teardown_ctx(void **state)
{
    struct bft_tmpdir *tmpdir = *state;

    bf_ctx_teardown();
    bft_tmpdir_free(&tmpdir);

    *state = NULL;

    return 0;
}
