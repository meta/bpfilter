/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

/* `renameat2` and `RENAME_NOREPLACE` require _GNU_SOURCE from glibc. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "core/lock.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpfilter/ctx.h>
#include <bpfilter/helper.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>

#define BF_PERM_755 (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

/** Bounded retry count for the "recheck-after-flock" loop (P1). Each failed
 * attempt corresponds to a completed `unlink + recreate` by another
 * `BF_LOCK_WRITE` holder, so this budget is extremely generous in practice. */
#define BF_LOCK_MAX_RETRIES 8

/** Bounded retry count for the staging name collision loop. Collisions are
 * astronomically rare given the random suffix, so a small budget suffices. */
#define BF_LOCK_STAGING_NAME_RETRIES 4

/** Number of random bytes pulled from `/dev/urandom` for the staging suffix. */
#define BF_LOCK_STAGING_RAND_BYTES 8

/**
 * @brief Apply an `flock(2)` of the requested mode on `fd`.
 *
 * `BF_LOCK_NONE` is a no-op; `BF_LOCK_READ` maps to `LOCK_SH`; `BF_LOCK_WRITE`
 * maps to `LOCK_EX`. All requests are non-blocking (`LOCK_NB`): contention
 * returns `-EWOULDBLOCK` immediately rather than waiting.
 *
 * @param fd File descriptor to lock.
 * @param mode Locking mode, see `bf_lock_mode`.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_flock(int fd, enum bf_lock_mode mode)
{
    int op;

    if (mode >= _BF_LOCK_MAX)
        return -EINVAL;

    if (fd < 0)
        return -EBADFD;

    if (mode == BF_LOCK_NONE)
        return 0;

    op = (mode == BF_LOCK_WRITE) ? LOCK_EX | LOCK_NB : LOCK_SH | LOCK_NB;

    if (flock(fd, op) < 0)
        return -errno;

    return 0;
}

/**
 * @brief Fill `buf` with a unique staging name.
 *
 * The name has the form `<prefix><pid>_<hex>` where `<hex>` is a hex-encoded
 * random suffix pulled from `/dev/urandom`. Uniqueness isn't strictly required
 * (collisions cause `mkdirat(EEXIST)` and are retried by the caller), but a
 * unique name avoids any chance of contention on the staging flock.
 *
 * If `/dev/urandom` cannot be read, fall back to a name based on `pid` and
 * `time(NULL)`; the caller's retry loop will paper over the rare collision
 * that this fallback could produce.
 *
 * @param buf Buffer to write the staging name into.
 * @param size Size of `buf`.
 */
static void _bf_make_staging_name(char *buf, size_t size)
{
    unsigned char rand[BF_LOCK_STAGING_RAND_BYTES] = {0};
    char hex[(BF_LOCK_STAGING_RAND_BYTES * 2) + 1];
    _cleanup_close_ int fd = -1;
    ssize_t n = -1;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
        n = read(fd, rand, sizeof(rand));

    if (n != (ssize_t)sizeof(rand)) {
        /* Fallback: derive bytes from `time(NULL)` so two processes that
         * both fail to read /dev/urandom in the same second still differ on
         * `pid`. Collisions are handled by the caller's retry loop. */
        unsigned long fallback = (unsigned long)time(NULL);
        for (size_t i = 0; i < sizeof(rand); ++i)
            rand[i] = (unsigned char)(fallback >> (i * 8));
    }

    for (size_t i = 0; i < sizeof(rand); ++i)
        (void)snprintf(&hex[i * 2], 3, "%02x", rand[i]);

    /* bpffs rejects names starting with '.', so the prefix and format must
     * stick to [a-zA-Z0-9_-]. */
    (void)snprintf(buf, size, "%s%d_%s", BF_LOCK_STAGING_PREFIX, (int)getpid(),
                   hex);
}

/**
 * @brief Stage-and-rename primitive (I3).
 *
 * Create a uniquely-named staging directory under `pindir_fd`, open it,
 * acquire an exclusive flock on it, then atomically publish it as `name`
 * via `renameat2(RENAME_NOREPLACE)`.
 *
 * On success, returns a locked file descriptor referring to the inode now
 * reachable as `<pindir>/<name>`.
 *
 * On failure, any state created (staging dir) is cleaned up; no side
 * effects leak out.
 * @param pindir_fd File descriptor of the pin directory.
 * @param name Name of the directory (in the pin directory) to open.
 * @return The open and locked file descriptor on success, or a negative errno
 *         value on failure.
 */
static int _bf_lock_stage_and_publish(int pindir_fd, const char *name)
{
    char staging[NAME_MAX];
    _cleanup_close_ int fd = -1;
    int r;

    assert(name);

    /* 1. Create a unique staging directory. Retry a small number of times
     *    if we happen to collide with our own prior staging dirs (should
     *    be astronomically rare given the random suffix). */
    for (int attempt = 0; attempt < BF_LOCK_STAGING_NAME_RETRIES; ++attempt) {
        _bf_make_staging_name(staging, sizeof(staging));
        if (mkdirat(pindir_fd, staging, BF_PERM_755) == 0)
            break;
        if (errno != EEXIST) {
            return bf_err_r(-errno,
                            "failed to create staging dir '%s' under pindir",
                            staging);
        }
        if (attempt == BF_LOCK_STAGING_NAME_RETRIES - 1) {
            return bf_err_r(
                -EAGAIN,
                "failed to generate a unique staging dir name after retries");
        }
    }

    /* 2. Open the staging directory. */
    fd = openat(pindir_fd, staging, O_DIRECTORY);
    if (fd < 0) {
        r = -errno;
        (void)unlinkat(pindir_fd, staging, AT_REMOVEDIR);
        return bf_err_r(r, "failed to open staging dir '%s'", staging);
    }

    /* 3. Exclusively lock the staging inode. Cannot contend: we own the
     *    unique staging name. */
    r = _bf_flock(fd, BF_LOCK_WRITE);
    if (r) {
        (void)unlinkat(pindir_fd, staging, AT_REMOVEDIR);
        return bf_err_r(r, "failed to flock staging dir '%s'", staging);
    }

    /* 4. Publish atomically. `RENAME_NOREPLACE` ensures we lose cleanly to
     *    any concurrent creator that already claimed `name`. */
    if (renameat2(pindir_fd, staging, pindir_fd, name, RENAME_NOREPLACE) < 0) {
        r = -errno;
        /* Staging dir was never published; safe to remove (we hold its
         * flock, nobody else can observe or lock it). */
        (void)unlinkat(pindir_fd, staging, AT_REMOVEDIR);
        return r;
    }

    return TAKE_FD(fd);
}

/**
 * @brief Open an existing chain dir with the recheck-after-flock protocol
 * (P1).
 *
 * Between `openat` and `flock`, the name might be unlinked and recreated by
 * another `BF_LOCK_WRITE` holder, which would leave us holding a lock on an
 * orphaned inode. Detect this by comparing the inode we locked against the
 * one currently reachable via the name, and retry on mismatch.
 *
 * On success, returns a locked file descriptor whose inode is guaranteed to
 * be the one currently bound to `name`.
 * @param pindir_fd File descriptor of the directory containing `name`.
 * @param name Name of the directory to open and lock.
 * @param mode Locking mode for `name`.
 * @return Open and locked file descriptor to `name` in `pindir_fd`, or a
 *         negative errno value on failure.
 */
static int _bf_lock_open_existing(int pindir_fd, const char *name,
                                  enum bf_lock_mode mode)
{
    int r;

    assert(name);

    for (int attempt = 0; attempt < BF_LOCK_MAX_RETRIES; ++attempt) {
        _cleanup_close_ int fd = -1;
        struct stat open_st;
        struct stat live_st;

        fd = openat(pindir_fd, name, O_DIRECTORY);
        if (fd < 0)
            return -errno;

        r = _bf_flock(fd, mode);
        if (r)
            return r;

        if (fstat(fd, &open_st) < 0)
            return -errno;

        if (fstatat(pindir_fd, name, &live_st, AT_SYMLINK_NOFOLLOW) < 0) {
            /* Name is gone (ENOENT) or inaccessible. Retry. */
            continue;
        }

        if (open_st.st_dev == live_st.st_dev &&
            open_st.st_ino == live_st.st_ino)
            return TAKE_FD(fd);

        /* Mismatch: the name now resolves to a different inode. Our fd is
         * pinned to the orphaned inode; drop it and retry. The flock is
         * released when fd is closed. */
    }

    return bf_err_r(
        -EAGAIN,
        "failed to stably open chain '%s' after %d retries; likely extreme contention",
        name, BF_LOCK_MAX_RETRIES);
}

int bf_lock_init(struct bf_lock *lock, enum bf_lock_mode mode)
{
    _clean_bf_lock_ struct bf_lock _lock = bf_lock_default();
    const char *bpffs_path;
    int r;

    assert(lock);

    bpffs_path = bf_ctx_get_bpffs_path();
    if (!bpffs_path)
        return bf_err_r(-EINVAL, "context is not initialized");

    _lock.bpffs_fd = bf_opendir(bpffs_path);
    if (_lock.bpffs_fd < 0) {
        return bf_err_r(_lock.bpffs_fd, "failed to open bpffs at %s",
                        bpffs_path);
    }

    /* Create the pin directory lazily. Per I1, it is never removed by the
     * library, so subsequent `openat` calls always see the same inode. */
    _lock.pindir_fd = bf_opendir_at(_lock.bpffs_fd, "bpfilter", true);
    if (_lock.pindir_fd < 0) {
        return bf_err_r(_lock.pindir_fd,
                        "failed to open pin directory %s/bpfilter", bpffs_path);
    }

    r = _bf_flock(_lock.pindir_fd, mode);
    if (r)
        return r;

    _lock.pindir_lock = mode;

    bf_swap(*lock, _lock);

    return 0;
}

int bf_lock_init_for_chain(struct bf_lock *lock, const char *name,
                           enum bf_lock_mode pindir_mode,
                           enum bf_lock_mode chain_mode, bool create)
{
    _clean_bf_lock_ struct bf_lock _lock = bf_lock_default();
    int r;

    assert(lock);
    assert(name);

    if (create && pindir_mode != BF_LOCK_WRITE) {
        return bf_err_r(
            -EINVAL,
            "creating a chain requires BF_LOCK_WRITE on the pin directory");
    }

    r = bf_lock_init(&_lock, pindir_mode);
    if (r)
        return r;

    r = bf_lock_acquire_chain(&_lock, name, chain_mode, create);
    if (r)
        return r;

    bf_swap(*lock, _lock);

    return 0;
}

void bf_lock_cleanup(struct bf_lock *lock)
{
    assert(lock);

    // Quick exit if `lock` wasn't initialized
    if (lock->bpffs_fd < 0)
        return;

    bf_lock_release_chain(lock);

    /* Per I1, do NOT remove the pin directory. It persists for the
     * lifetime of the bpffs mount. */
    closep(&lock->pindir_fd);
    lock->pindir_lock = BF_LOCK_NONE;

    closep(&lock->bpffs_fd);
}

int bf_lock_acquire_chain(struct bf_lock *lock, const char *name,
                          enum bf_lock_mode mode, bool create)
{
    _cleanup_free_ char *_name = NULL;
    _cleanup_close_ int chain_fd = -1;

    assert(lock);
    assert(name);

    if (lock->bpffs_fd < 0 || lock->pindir_fd < 0) {
        return bf_err_r(
            -EBADFD,
            "attempting to acquire a chain lock on an invalid bf_lock");
    }

    if (lock->chain_fd >= 0) {
        return bf_err_r(-EINVAL, "bf_lock already locks chain '%s'",
                        lock->chain_name);
    }

    if (create) {
        if (mode != BF_LOCK_WRITE) {
            return bf_err_r(
                -EINVAL,
                "creating a chain requires BF_LOCK_WRITE on the chain directory");
        }
        if (lock->pindir_lock != BF_LOCK_WRITE) {
            return bf_err_r(
                -EINVAL,
                "creating a chain requires BF_LOCK_WRITE on the pin directory");
        }
    }

    _name = strdup(name);
    if (!_name)
        return -ENOMEM;

    if (create) {
        /* Stage-and-rename (I3). Returns a locked fd already reachable at
         * the final name. */
        chain_fd = _bf_lock_stage_and_publish(lock->pindir_fd, _name);
        if (chain_fd < 0)
            return chain_fd;
    } else {
        /* Recheck-after-flock (P1). Returns a locked fd for the live
         * inode of `name`, or an error. */
        chain_fd = _bf_lock_open_existing(lock->pindir_fd, _name, mode);
        if (chain_fd < 0)
            return chain_fd;
    }

    lock->chain_fd = TAKE_FD(chain_fd);
    lock->chain_name = TAKE_PTR(_name);
    lock->chain_lock = mode;

    return 0;
}

void bf_lock_release_chain(struct bf_lock *lock)
{
    assert(lock);

    if (lock->bpffs_fd < 0 || lock->pindir_fd < 0) {
        bf_warn("attempting to release a chain lock on an invalid bf_lock");
        return;
    }

    if (lock->chain_fd < 0)
        return;

    /* Only WRITE locks will be used to create or modify a chain, meaning
     * if a READ or NONE lock was held on a chain directory, that directory
     * hasn't been modified during the lifetime of the lock. So there is no
     * need to attempt to remove it.
     *
     * Per I2, this removal is only race-free against concurrent readers if
     * the caller also holds BF_LOCK_WRITE on the pin directory. The
     * locking matrix documented in `lock.h` ensures this. */
    if (lock->chain_lock == BF_LOCK_WRITE)
        (void)unlinkat(lock->pindir_fd, lock->chain_name, AT_REMOVEDIR);

    closep(&lock->chain_fd);

    BF_FREEP(&lock->chain_name);
    lock->chain_lock = BF_LOCK_NONE;
}
