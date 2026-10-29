/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

/**
 * @file lock.h
 *
 * Lock object(s) to prevent concurrent access to the ruleset and/or a
 * chain.
 *
 * Bundles the open file descriptors for `$BPFFS`, `$BPFFS/bpfilter` and
 * an optional chain directory under it, and locks them if requested.
 *
 * # Usage
 *
 * A `bf_lock` should be defined with `bf_lock_default()` to ensure it contains
 * valid defaults, which prevents API misuse and ensures `bf_lock_cleanup()` can
 * be called safely.
 *
 * The `bf_lock` can then be initialized using `bf_lock_init()` to only open
 * and lock the pin directory (`$BPFFS/bpfilter`). If `BF_LOCK_NONE` is used,
 * the pin directory is not locked (useful if the caller already holds a
 * compatible lock on it).
 *
 * Alternatively, you can open (and lock) both the pin directory and a chain
 * directory using `bf_lock_init_for_chain()`. The caller chooses the lock mode
 * for both the pin directory (`pindir_mode`) and the chain directory
 * (`chain_mode`) independently. If the chain directory doesn't exist yet,
 * `create=true` will create it atomically via stage-and-rename (see
 * "Invariants" below).
 *
 * `bf_lock` is cleaned up using `bf_lock_cleanup()`: it is safe to call on a
 * properly defined lock (using `bf_lock_default()`), an initialized lock, or an
 * already cleaned-up lock (i.e. `bf_lock_cleanup()` has already been called).
 * Use the `_clean_bf_lock_` variable attribute for automatic cleanup.
 *
 * # Locking matrix
 *
 * Operations on the pin directory and the chain directories should follow
 * this locking policy:
 *
 *    Operation  | Object  | Pindir lock | Chain dir lock
 *    -----------|---------|-------------|---------------------------
 *    Read       | Ruleset | `READ`      | `READ` (per chain, in loop)
 *    Read       | Chain   | `READ`      | `READ`
 *    Write      | Ruleset | `WRITE`     | `WRITE` (per chain, in loop)
 *    Write      | Chain   | `READ`      | `WRITE`
 *
 * Rationale:
 *  - Pindir `WRITE` is required for any operation that mutates the pin
 *    directory namespace (creating, removing, or renaming an entry). This
 *    excludes all other pindir lockers (readers and content mutators).
 *  - Pindir `READ` is sufficient for operations that only resolve existing
 *    names (pure readers and content mutators). It is compatible with other
 *    readers/content mutators on *different* chains but mutually exclusive
 *    with pindir `WRITE`.
 *  - Chain `WRITE` is required for any mutation of a chain directory's
 *    contents. Chain `READ` is compatible with other chain readers.
 *
 * Pindir `WRITE` is mutually exclusive with every other pindir lock, so it
 * should be reserved for namespace-level mutations. For single-chain content
 * mutations, take pindir `READ` + chain `WRITE`; for single-chain reads,
 * take pindir `READ` + chain `READ`.
 *
 * Ruleset-level operations iterate over every chain and must take a chain
 * lock around each per-chain step (using `bf_lock_acquire_chain()` /
 * `bf_lock_release_chain()`).
 *
 * # Invariants
 *
 * The locking scheme relies on three invariants enforced by the `bf_lock`
 * module:
 *  - **I1: pindir is immortal.** The pin directory `$BPFFS/bpfilter/` is
 *    created lazily by `bf_lock_init()` and never removed by the library.
 *    This prevents a "remove under reader" race where one process would
 *    `unlinkat` the pindir between another process's `openat` and `flock`,
 *    leaving the second process holding a lock on an orphaned inode.
 *  - **I2: chain dirs are only removed under `WRITE`.** A chain directory
 *    can only be removed while its owner holds `BF_LOCK_WRITE` on the chain
 *    itself **and** `BF_LOCK_WRITE` on the pin directory.
 *    `bf_lock_release_chain()` only attempts removal when the released chain
 *    lock is `BF_LOCK_WRITE`; callers must also hold the pindir `WRITE` lock
 *    for the removal to be race-free against concurrent readers (this is
 *    ensured by the locking matrix above).
 *  - **I3: chain dirs are created atomically.** Creation goes through a
 *    "stage and rename" protocol: a uniquely-named staging directory is
 *    created and locked first, then atomically published to its final name
 *    via `renameat2(RENAME_NOREPLACE)`. Two concurrent creators therefore
 *    cannot step on each other: the loser's `renameat2()` returns `EEXIST`
 *    and it rolls back its own staging directory. The winner's chain
 *    directory is never touched by the loser's cleanup.
 *
 * Ruleset-level operations iterate over every chain and must take a chain
 * lock around each per-chain step (using `bf_lock_acquire_chain` /
 * `bf_lock_release_chain`): the pindir lock alone does not protect against
 * a chain-level writer that holds only the chain's own `WRITE` lock.
 *
 * # API
 */

/**
 * @brief File lock mode used by `bf_lock`.
 */
enum bf_lock_mode
{
    /// `BF_LOCK_NONE` skips locking entirely (caller already holds a sufficient
    /// lock, e.g. an exclusive lock on a parent directory).
    BF_LOCK_NONE,

    /// `BF_LOCK_READ` requests a shared lock (multiple readers allowed).
    BF_LOCK_READ,

    /// `BF_LOCK_WRITE` requests an exclusive lock (single writer, no readers).
    BF_LOCK_WRITE,
    _BF_LOCK_MAX,
};

/**
 * @warning The `bf_lock` structure should only be modified by the locking API,
 * not directly, though callers can read any field safely (e.g. file
 * descriptors).
 */
struct bf_lock
{
    /// File descriptor of the bpffs directory, -1 if unset.
    int bpffs_fd;

    /// File descriptor of the pin directory (`$BPFFS/bpfilter`), -1 if unset.
    int pindir_fd;

    /// Lock mode held on `pindir_fd`; `BF_LOCK_NONE` if unlocked.
    enum bf_lock_mode pindir_lock;

    /// File descriptor of the chain directory, -1 if unset.
    int chain_fd;

    /// Name of the open chain, only valid when `chain_fd` is set.
    char *chain_name;

    /// Lock mode held on `chain_fd`; `BF_LOCK_NONE` if unlocked or unset.
    enum bf_lock_mode chain_lock;
};

/**
 * @brief Assign sane defaults to a `bf_lock` object.
 *
 * This macro should always be used for a `bf_lock` object with the
 * `_clean_bf_lock_` attribute.
 *
 * @return A `bf_lock` object with valid defaults.
 */
#define bf_lock_default()                                                      \
    ((struct bf_lock) {                                                        \
        .bpffs_fd = -1,                                                        \
        .pindir_fd = -1,                                                       \
        .pindir_lock = BF_LOCK_NONE,                                           \
        .chain_fd = -1,                                                        \
        .chain_name = NULL,                                                    \
        .chain_lock = BF_LOCK_NONE,                                            \
    })

/** Prefix for staging names used by I3. Callers that walk the pindir (e.g.
 * `bf_state_discover()`) must skip entries with this prefix.
 *
 * The prefix cannot start with a `.` because bpffs rejects `mkdir` for
 * names starting with a dot. It uses double underscore + "bf_staging_"
 * to minimise the chance of colliding with a user-chosen chain name:
 * the lexer that parses chain names accepts `[a-zA-Z0-9_]+` so a user
 * could technically create a chain with the same prefix, but in practice
 * they won't. */
#define BF_LOCK_STAGING_PREFIX "__bf_staging_"

/// Variable attribute to automatically cleanup a `bf_lock` object.
#define _clean_bf_lock_ __attribute__((cleanup(bf_lock_cleanup)))

/**
 * @brief Open and lock the pin directory.
 *
 * The pin directory (`$BPFFS/bpfilter`) is created if it doesn't exist.
 * Because of I1 (see file header), it is never removed by the library,
 * so the inode this function opens is stable for the lifetime of the
 * bpffs mount.
 *
 * @pre
 *  - The runtime context has been initialized.
 *  - `lock` is not NULL, and contains sane defaults (see `bf_lock_default()`).
 * @post
 *  - On success: `lock` holds a valid file descriptor on the bpffs, a valid
 *    file descriptor on the pin directory, and an `flock(2)` of mode `mode`
 *    on the pin directory. `lock->pindir_lock == mode`.
 *  - On failure: `lock` is unchanged.
 *
 * @param lock Handle to populate. Must be initialised via `bf_lock_default()`.
 * @param mode Lock mode for the pin directory.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_lock_init(struct bf_lock *lock, enum bf_lock_mode mode);

/**
 * @brief Open and lock the pin directory and a chain directory.
 *
 * Convenience wrapper that chains `bf_lock_init()` + `bf_lock_acquire_chain()`.
 * The caller controls the lock mode for the pin directory (`pindir_mode`)
 * and the chain directory (`chain_mode`) independently, per the locking
 * matrix.
 *
 * If the chain directory doesn't exist and `create=true`, it is created
 * atomically via stage-and-rename (I3). Creating a chain directory requires
 * `pindir_mode == BF_LOCK_WRITE` and `chain_mode == BF_LOCK_WRITE`.
 *
 * @note If you already own a lock on the pin directory, use
 * `bf_lock_acquire_chain()` instead.
 *
 * @pre
 *  - The runtime context has been initialized.
 *  - `lock` is not NULL, and contains sane defaults (see `bf_lock_default()`).
 *  - `name` is not NULL.
 *  - `create == true` implies `pindir_mode == BF_LOCK_WRITE` and
 *    `chain_mode == BF_LOCK_WRITE`.
 * @post
 *  - On success: `lock` holds file descriptors on the bpffs, the pin
 *    directory (locked with `pindir_mode`), and the chain directory
 *    (locked with `chain_mode`). `lock->chain_name == name` (owned copy).
 *  - On failure: `lock` is unchanged.
 *
 * @param lock Lock object to initialize.
 * @param name Name of the chain to lock.
 * @param pindir_mode Lock mode for the pin directory.
 * @param chain_mode Lock mode for the chain directory.
 * @param create If true, create the chain directory if it doesn't exist.
 *        Requires `pindir_mode == BF_LOCK_WRITE` and
 *        `chain_mode == BF_LOCK_WRITE`.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_lock_init_for_chain(struct bf_lock *lock, const char *name,
                           enum bf_lock_mode pindir_mode,
                           enum bf_lock_mode chain_mode, bool create);

/**
 * @brief Clean up resources held by a lock.
 *
 * Releases every lock held by `lock`, closes the open file descriptors,
 * and removes the chain directory if `BF_LOCK_WRITE` was held on it
 * (it might now be empty; `unlinkat(AT_REMOVEDIR)` silently fails if it
 * isn't).
 *
 * Per invariant I1, this function does **not** remove the pin directory
 * itself.
 *
 * This function can be called if `lock` has been assigned sensible defaults
 * (using `bf_lock_default`), initialized (using `bf_lock_init*`), or cleaned
 * up (using `bf_lock_cleanup`); it is idempotent.
 *
 * @pre
 *  - `lock` is not NULL, and is in a valid state.
 * @post
 *  - `lock` is in the default state (all fds are -1, all modes are
 *    `BF_LOCK_NONE`, `chain_name == NULL`).
 *
 * @param lock Handle to clean up.
 */
void bf_lock_cleanup(struct bf_lock *lock);

/**
 * @brief Lock a chain directory on an existing pin directory lock.
 *
 * `lock` must have been successfully initialised by `bf_lock_init`
 * (i.e. `bpffs_fd` and `pindir_fd` are valid) and must not already hold a
 * chain lock. Depending on `create`:
 *  - `create == false`: open and lock the existing chain directory. If the
 *    chain directory doesn't exist, returns `-ENOENT`. Uses the
 *    "recheck-after-flock" protocol (P1) to detect and retry against
 *    a concurrent `unlink + recreate` of the name.
 *  - `create == true`: create the chain directory atomically. Internally
 *    stages the new directory under a unique `.staging.*` name, acquires
 *    `BF_LOCK_WRITE` on the staged inode, then publishes it via
 *    `renameat2(RENAME_NOREPLACE)`. Requires `mode == BF_LOCK_WRITE` and
 *    the caller must hold `BF_LOCK_WRITE` on the pin directory. If another
 *    process created the chain first, returns `-EEXIST`.
 *
 * If creating, opening, or locking the directory fails, `lock` is left
 * unchanged.
 *
 * @pre
 *  - `lock` is not NULL, has been initialized, and doesn't hold a chain lock.
 *  - `name` is not NULL.
 *  - `create == true` implies `mode == BF_LOCK_WRITE` and
 *    `lock->pindir_lock == BF_LOCK_WRITE`.
 * @post
 *  - On success: `lock->chain_fd` is a valid open (and locked with `mode`)
 *    file descriptor to the chain directory. `lock->chain_name` is a
 *    heap-allocated copy of `name`, owned by `lock`.
 *  - On failure: `lock` is unchanged and remains in a valid state.
 *
 * @param lock Initialized `bf_lock`.
 * @param name Name of the chain to acquire.
 * @param mode Lock mode for the chain directory.
 * @param create If true, create the chain directory atomically if it
 *        doesn't exist.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_lock_acquire_chain(struct bf_lock *lock, const char *name,
                          enum bf_lock_mode mode, bool create);

/**
 * @brief Release a chain lock.
 *
 * Closes the chain file descriptor. If `BF_LOCK_WRITE` was held on the
 * chain, also attempts to remove the (possibly empty) chain pin directory
 * via `unlinkat(AT_REMOVEDIR)`; the removal silently no-ops if the
 * directory isn't empty. Callers relying on that removal being
 * race-free against concurrent readers must also hold the pindir
 * `BF_LOCK_WRITE` (I2).
 *
 * If `lock` doesn't hold a chain lock, this is a no-op.
 *
 * @pre
 *  - `lock` is not NULL, has been initialized.
 * @post
 *  - `lock` no longer holds a chain lock; `chain_fd == -1`,
 *    `chain_name == NULL`, `chain_lock == BF_LOCK_NONE`.
 *  - Other fields (bpffs/pindir fds and locks) are unchanged.
 *
 * @param lock Handle to release the chain from.
 */
void bf_lock_release_chain(struct bf_lock *lock);
