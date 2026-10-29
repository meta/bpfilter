/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/btf.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/ctx.h>
#include <bpfilter/dump.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>

#include "cgen/cgen.h"
#include "core/lock.h"
#include "state.h"

#define _free_bf_ctx_ __attribute__((cleanup(_bf_ctx_free)))

/**
 * @struct bf_ctx
 *
 * bpfilter working context. Only one context is used during the library's
 * lifetime.
 */
struct bf_ctx
{
    /// BPF token file descriptor
    int token_fd;

    struct bf_elfstub *stubs[_BF_ELFSTUB_MAX];

    /// Pass a token to BPF system calls, obtained from bpffs.
    bool with_bpf_token;

    /// Path to the bpffs to pin the BPF objects into.
    const char *bpffs_path;

    /// Verbose flags.
    uint16_t verbose;
};

static void _bf_ctx_free(struct bf_ctx **ctx);

/// Global runtime context. Hidden in this translation unit.
static struct bf_ctx *_bf_global_ctx = NULL;

static int _bf_ctx_gen_token(const char *bpffs_path)
{
    _cleanup_close_ int mnt_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int token_fd = -1;

    mnt_fd = open(bpffs_path, O_DIRECTORY);
    if (mnt_fd < 0)
        return bf_err_r(errno, "failed to open '%s'", bpffs_path);

    bpffs_fd = openat(mnt_fd, ".", 0, O_RDWR);
    if (bpffs_fd < 0)
        return bf_err_r(errno, "failed to get bpffs FD from '%s'", bpffs_path);

    token_fd = bf_bpf_token_create(bpffs_fd);
    if (token_fd < 0) {
        return bf_err_r(token_fd, "failed to create BPF token for '%s'",
                        bpffs_path);
    }

    return TAKE_FD(token_fd);
}

/**
 * Create and initialize a new context.
 *
 * On failure, @p ctx is left unchanged.
 *
 * @param ctx New context to create. Can't be NULL.
 * @param with_bpf_token If true, create a BPF token from bpffs.
 * @param bpffs_path Path to the bpffs mountpoint. Can't be NULL.
 * @param verbose Bitmask of verbose flags.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_ctx_new(struct bf_ctx **ctx, bool with_bpf_token,
                       const char *bpffs_path, uint16_t verbose)
{
    _free_bf_ctx_ struct bf_ctx *_ctx = NULL;
    int r;

    assert(ctx);
    assert(bpffs_path);

    _ctx = calloc(1, sizeof(*_ctx));
    if (!_ctx)
        return -ENOMEM;

    _ctx->token_fd = -1;

    r = bf_btf_setup();
    if (r)
        return bf_err_r(r, "failed to load vmlinux BTF");

    _ctx->with_bpf_token = with_bpf_token;
    _ctx->verbose = verbose;

    _ctx->bpffs_path = strdup(bpffs_path);
    if (!_ctx->bpffs_path)
        return -ENOMEM;

    if (_ctx->with_bpf_token) {
        _cleanup_close_ int token_fd = -1;

        r = bf_btf_kernel_has_token();
        if (r == -ENOENT) {
            bf_err(
                "--with-bpf-token requested, but this kernel doesn't support BPF token");
            return r;
        }
        if (r)
            return bf_err_r(r, "failed to check for BPF token support");

        token_fd = _bf_ctx_gen_token(_ctx->bpffs_path);
        if (token_fd < 0)
            return bf_err_r(token_fd, "failed to generate a BPF token");

        _ctx->token_fd = TAKE_FD(token_fd);
    }

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id) {
        r = bf_elfstub_new(&_ctx->stubs[id], id);
        if (r)
            return bf_err_r(r, "failed to create ELF stub ID %u", id);
    }

    *ctx = TAKE_PTR(_ctx);

    return 0;
}

/**
 * Free a context.
 *
 * If @p ctx points to a NULL pointer, this function does nothing. Once
 * the function returns, @p ctx points to a NULL pointer.
 *
 * @param ctx Context to free. Can't be NULL.
 */
static void _bf_ctx_free(struct bf_ctx **ctx)
{
    assert(ctx);

    if (!*ctx)
        return;

    closep(&(*ctx)->token_fd);
    BF_FREEP(&(*ctx)->bpffs_path);

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id)
        bf_elfstub_free(&(*ctx)->stubs[id]);

    bf_btf_teardown();

    BF_FREEP(ctx);
}

/**
 * See @ref bf_ctx_dump for details.
 */
static void _bf_ctx_dump(const struct bf_ctx *ctx, prefix_t *prefix)
{
    DUMP(prefix, "struct bf_ctx at %p", ctx);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "token_fd: %d", ctx->token_fd);

    bf_dump_prefix_pop(prefix);
}

static void _bf_free_dir(DIR **dir)
{
    if (!*dir)
        return;

    closedir(*dir);
    *dir = NULL;
}

#define _free_dir_ __attribute__((__cleanup__(_bf_free_dir)))

/**
 * @brief Sweep leftover staging directories from a previous run.
 *
 * `core/lock.c` creates uniquely-named `.staging.*` directories while
 * publishing new chain dirs via `renameat2(RENAME_NOREPLACE)`. If a
 * process crashes between the `mkdirat` and the `renameat2`, the staging
 * dir is orphaned.
 *
 * This function walks the pindir under `BF_LOCK_WRITE` and removes any
 * `.staging.*` entry whose `flock(LOCK_EX | LOCK_NB)` succeeds (meaning
 * nobody currently owns it). Live staging dirs are left alone.
 *
 * Runs once from `bf_ctx_setup()`. Non-fatal: a failure to sweep only
 * leaves garbage behind, it does not compromise correctness.
 */
static void _bf_ctx_sweep_staging(void)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_dir_ DIR *dir = NULL;
    struct dirent *entry;
    int iter_fd;
    int r;

    r = bf_lock_init(&lock, BF_LOCK_WRITE);
    if (r) {
        bf_warn_r(r, "failed to lock pindir for staging sweep, skipping");
        return;
    }

    iter_fd = dup(lock.pindir_fd);
    if (iter_fd < 0) {
        bf_warn_r(-errno, "failed to dup pindir fd for staging sweep");
        return;
    }

    dir = fdopendir(iter_fd);
    if (!dir) {
        close(iter_fd);
        bf_warn_r(-errno, "failed to fdopendir pindir for staging sweep");
        return;
    }

    while ((entry = readdir(dir))) {
        _cleanup_close_ int stage_fd = -1;

        if (!bf_strneq(entry->d_name, BF_LOCK_STAGING_PREFIX,
                       sizeof(BF_LOCK_STAGING_PREFIX) - 1))
            continue;

        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN)
            continue;

        stage_fd = openat(lock.pindir_fd, entry->d_name, O_DIRECTORY);
        if (stage_fd < 0)
            continue;

        /* LOCK_NB: if the staging dir is still live, skip it. */
        if (flock(stage_fd, LOCK_EX | LOCK_NB) < 0)
            continue;

        if (bf_rmdir_at(lock.pindir_fd, entry->d_name, true)) {
            bf_warn("failed to sweep orphan staging dir '%s'", entry->d_name);
        } else {
            bf_dbg("removed left-over staging directory '%s'", entry->d_name);
        }
    }
}

int bf_ctx_setup(bool with_bpf_token, const char *bpffs_path, uint16_t verbose)
{
    int r;

    if (_bf_global_ctx)
        return bf_err_r(-EBUSY, "context is already initialized");

    r = _bf_ctx_new(&_bf_global_ctx, with_bpf_token, bpffs_path, verbose);
    if (r)
        return bf_err_r(r, "failed to create new context");

    /* Reclaim any orphan staging directory left by a previous crash. */
    _bf_ctx_sweep_staging();

    return 0;
}

void bf_ctx_teardown(void)
{
    _bf_ctx_free(&_bf_global_ctx);
}

bool bf_ctx_is_setup(void)
{
    return _bf_global_ctx != NULL;
}

void bf_ctx_dump(prefix_t *prefix)
{
    if (!_bf_global_ctx)
        return;

    _bf_ctx_dump(_bf_global_ctx, prefix);
}

int bf_ctx_get_cgen(struct bf_lock *lock, struct bf_cgen **cgen)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    int r;

    assert(lock);
    assert(cgen);

    if (!_bf_global_ctx)
        return bf_err_r(-EINVAL, "context is not initialized");

    r = bf_cgen_new_from_dir_fd(&_cgen, lock);
    if (r)
        return bf_err_r(r, "failed to load chain '%s' from bpffs",
                        lock->chain_name ? lock->chain_name : "(unknown)");

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

int bf_ctx_get_cgens(struct bf_lock *lock, bf_list **cgens)
{
    _free_bf_list_ bf_list *chains = NULL;
    _free_bf_list_ bf_list *handles = NULL;
    _free_bf_list_ bf_list *_cgens = NULL;
    struct bf_list_node *handle_node;
    int r;

    assert(lock);
    assert(cgens);

    r = bf_list_new(&_cgens, &bf_list_ops_default(bf_cgen_free, bf_cgen_pack));
    if (r)
        return r;

    r = bf_state_discover(lock, &chains, &handles);
    if (r)
        return r;

    handle_node = bf_list_get_head(handles);
    bf_list_foreach (chains, chain_node) {
        _free_bf_cgen_ struct bf_cgen *cgen = calloc(1, sizeof(*cgen));

        if (cgen) {
            cgen->chain = bf_list_node_take_data(chain_node);
            cgen->handle = bf_list_node_take_data(handle_node);
            r = bf_list_push(_cgens, (void **)&cgen);
            if (r)
                bf_warn_r(r, "failed to push restored chain, skipping");
        } else {
            bf_warn_r(-ENOMEM, "failed to allocate restored chain, skipping");
        }

        handle_node = bf_list_node_next(handle_node);
    }

    *cgens = TAKE_PTR(_cgens);
    return 0;
}

int bf_ctx_token(void)
{
    if (!_bf_global_ctx)
        return -1;

    return _bf_global_ctx->token_fd;
}

const struct bf_elfstub *bf_ctx_get_elfstub(enum bf_elfstub_id id)
{
    if (!_bf_global_ctx)
        return NULL;

    return _bf_global_ctx->stubs[id];
}

bool bf_ctx_is_verbose(enum bf_verbose opt)
{
    if (!_bf_global_ctx)
        return false;

    return _bf_global_ctx->verbose & BF_FLAG(opt);
}

const char *bf_ctx_get_bpffs_path(void)
{
    if (!_bf_global_ctx)
        return NULL;

    return _bf_global_ctx->bpffs_path;
}
