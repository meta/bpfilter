Memory and resource management
==============================

This document is the authoritative reference for memory and resource safety conventions in ``bpfilter``. It is the single source of truth for code review and can be used by AI agents.

``bpfilter`` relies heavily on GCC's and Clang's ``__attribute__((cleanup))`` together with a small set of conventions for ownership transfer and file-descriptor handling. The rules below describe what correct code looks like and how to verify it during review. Following these conventions eliminates entire classes of leaks, double-frees, and use-after-free bugs by making resource lifetimes explicit and locally verifiable.

This page is the deep reference. The Memory management section of :doc:`style` is a short pointer back here for contributors browsing the style guide.



Local verifiability
-------------------

The conventions in this document exist so that a reader can examine a single function and convince themselves it does not leak, double-free, or use freed memory, **without reading any of its callees**.

Cleanup attributes turn resource lifetime into a syntactic property: every owning local is visibly tagged with the destructor that will run when it goes out of scope. Ownership-transfer macros (``TAKE_PTR``, ``TAKE_FD``) make every escape from a local explicit. The output-parameter contract guarantees that a function returning an error never leaves the caller's locals in an indeterminate state.

If a function's correctness requires reading another function's body, one of these conventions has been broken. Most findings raised against this document can be characterised as "this code is not locally verifiable because ...".



Per-function contracts live in Doxygen
--------------------------------------

The generic conventions in this document are the **fallback**. The authoritative contract for any specific function lives in its Doxygen header (above the declaration in the public header, or above the definition for internal functions). While the Doxygen documentation is authoritative for a specific function, you should try to stick to the conventions defined in this document unless you have a good reason not to, in which case you should document it. When judging whether a call site is correct, read the callee's Doxygen for:

- **Ownership**: who owns the resources before the function call? After? The owner is responsible for the resources lifetime.
- **NULL-safety**: can pointer arguments be NULL?
- **Allocation**: are resources allocated? Who will own them?
- **Output-parameter semantics**: should caller-allocated resources be freed on error? Does the function changes the resources ownership on success?
- **Locking**: what are preconditions on held locks (read/write/none)?

If a callee's Doxygen contradicts the generic rules below, the Doxygen wins. The reason behind this drift in behaviour must be documented. Real examples from the codebase where the per-function contract overrides the defaults:

- ``bf_hashset_add(set, &data)`` transfers ownership of ``*data`` to the hashset on success (and sets ``*data`` to ``NULL``), but **not** on ``-EEXIST``: the caller retains ownership when the element was already present. Both naive assumptions ("inputs are borrowed" and "inputs are always taken") are wrong; only the per-return-code contract is correct, and getting it wrong produces either a leak (on success) or a double-free (on ``-EEXIST``).
- ``bf_set_add(dest, &to_add)`` and ``bf_set_remove(dest, &to_remove)`` consume their second argument on success: the function frees ``*to_add`` / ``*to_remove`` and sets the caller's pointer to ``NULL``. The generic rule "callers retain ownership of inputs" is reversed.
- ``bf_cgen_new(&cgen, hook, chain)`` takes ownership of ``chain`` on success: after the call returns, the new codegen owns the chain and the caller must not free it. Same reversal as above, but for a constructor.
- ``bf_vector_take(vec)`` is the inverse of the usual container contract: it transfers ownership of the vector's **backing buffer** out to the caller, leaving ``vec`` empty but reusable. The caller must ``free()`` the returned pointer.

Each of these is a place where reading the Doxygen carefully is the only way to write correct calling code — applying the generic rules below would produce either leaks or double-frees.

For struct fields, inline ``///`` comments often encode the element type or ownership (e.g. ``/// List of struct bf_rule``). Use those to validate container destructors and field cleanup.

If a function has no Doxygen, fall back on the conventions below.


Cleanup attributes
------------------

Use ``__attribute__((cleanup))`` to release owned resources at scope exit. Four macro families exist, with strict naming conventions.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Macro
     - Used for
   * - :c:macro:`_cleanup_free_`
     - Raw heap pointers freed via ``free()`` (the destructor is :c:func:`bf_freep`)
   * - :c:macro:`_cleanup_close_`
     - File descriptors closed via ``close()`` (the destructor is :c:func:`closep`)
   * - ``_free_bf_<type>_``
     - Heap-allocated ``bf_<type>`` objects
   * - ``_clean_bf_<type>_``
     - Stack-allocated ``bf_<type>`` values (lock, list, vector, hashset, ...)

Per-type macros live next to their ``bf_<type>_free`` / ``bf_<type>_clean`` declaration in the corresponding header. See e.g. ``chain.h``.

A pointer carrying a cleanup attribute **must be initialised** (typically to ``NULL``), otherwise the destructor runs on garbage when the scope exits early.

.. code:: c

    _free_bf_chain_ struct bf_chain *chain = NULL;  // Correct: initialised


Cleanup function contract
-------------------------

Every ``bf_<type>_free(struct bf_<type> **p)`` must:

- Return ``void``
- Take a **double pointer**
- Be a no-op when ``*p == NULL``
- Call :c:macro:`BF_FREEP` (or the right destructor chain) to free the heap-allocated object and set the pointer to NULL

.. code:: c

    void bf_chain_free(struct bf_chain **chain)
    {
        if (!*chain)
            return;

        // ... release nested resources ...

        BF_FREEP(*chain);
    }

The ``bf_<type>_clean(struct bf_<type> *p)`` variant (used by ``_clean_*``) tears down the fields of an automatic-storage object and must leave it in a state where calling it again is a no-op.


Ownership transfer
------------------

Two macros transfer ownership out of a local variable:

- :c:macro:`TAKE_PTR` (``p``) — returns ``p``, sets ``p = NULL``
- :c:macro:`TAKE_FD` (``fd``) — returns ``fd``, sets ``fd = -1``

These exist precisely so the cleanup attribute on the source variable becomes a no-op after the value escapes. Whenever a local with ``_free_*``, :c:macro:`_cleanup_free_`, or :c:macro:`_cleanup_close_` is assigned into an output parameter or struct field, the assignment **must** go through the appropriate ``TAKE_*``:

.. code:: c

    *out = TAKE_PTR(local);  // local becomes NULL, *out takes ownership

Assigning without ``TAKE_*`` leads to a double-free: the cleanup attribute on ``local`` will fire **and** the caller will free ``*out``.


File descriptors
----------------

- ``-1`` is the sentinel for "not open"
- New fd variables should be initialised to ``-1``
- Owned fds should carry :c:macro:`_cleanup_close_` or live in a struct whose cleanup function closes them
- Transfer ownership with :c:macro:`TAKE_FD`
- :c:func:`closep` ignores negative fds, so :c:macro:`_cleanup_close_` on an uninitialised variable is undefined behaviour, but :c:func:`closep` on a negative errno value is valid. Always initialise to ``-1``


Locking
-------

The :c:struct:`bf_lock` object (see :doc:`modules/core/locking`) bundles file descriptors and ``flock(2)`` locks on bpffs directories that protect the ruleset and individual chains. It has its own lifecycle that mirrors the cleanup-attribute discipline:

.. code:: c

    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    int r;

    r = bf_lock_init(&lock, BF_LOCK_READ);
    if (r)
        return r;

    // ... use lock.pindir_fd / lock.chain_fd ...

    // On scope exit, bf_lock_cleanup() releases every fd and every flock.

Rules:

- A :c:struct:`bf_lock` local **must** be declared with :c:macro:`_clean_bf_lock_` and initialised with :c:macro:`bf_lock_default`. :c:func:`bf_lock_cleanup` is idempotent on a defaulted, initialised, or already-cleaned lock, so the cleanup attribute is always safe to run.
- :c:func:`bf_lock_init` and :c:func:`bf_lock_init_for_chain` leave the lock unchanged on failure, so the cleanup attribute on an as-yet-uninitialised lock is a no-op.
- :c:struct:`bf_lock` values must never escape their scope. There is no ``TAKE_LOCK``: locks are stack-only and their ownership is non-transferable.
- For chain-level locking on an already-initialised lock, use :c:func:`bf_lock_acquire_chain` / :c:func:`bf_lock_release_chain`. The matching cleanup is still :c:func:`bf_lock_cleanup`; explicit release is only needed if the chain lock should be dropped before scope exit.

See the locking matrix and invariants in :doc:`modules/core/locking` for the policy that determines which mode each operation requires.


Output-parameter contract
-------------------------

Functions of the form ``int bf_x_new(struct bf_x **out, ...)`` follow a strict contract:

- Return ``0`` on success, negative errno on failure
- On failure, ``*out`` is **left unchanged**
- On success, ownership of ``*out`` transfers to the caller

A failure path that mutates ``*out`` is a bug: the caller may already have applied ``_free_bf_x_`` to its local, leading to a double-free or a free on a partially-constructed object. Trace every error return and confirm ``*out`` was not touched before it.


Memory helpers
--------------

These helpers in :doc:`modules/helpers` have non-obvious contracts worth memorising:

- :c:func:`bf_memdup` returns ``NULL`` if ``src == NULL``; caller frees the returned buffer
- :c:func:`bf_memcpy` tolerates ``src == NULL`` only when ``len == 0``
- :c:func:`bf_realloc` leaves ``p`` untouched on failure (unlike ``realloc``), so ``p`` is still owned by the caller and must be freed
- :c:func:`bf_read_file` allocates ``*buf``; caller frees. ``*buf`` is unchanged on failure


Lists, vectors, and hashsets
----------------------------

``bf_list``, ``bf_vector``, and ``bf_hashset`` each carry an element destructor. Verify on every use:

- The destructor matches the element type (``bf_rule_free`` for a list of rules, etc.)
- For nested containers, the inner free function is registered
- ``_free_`` is used when the container itself is heap-allocated, ``_clean_`` when it is on the stack


Kernel-side resources
---------------------

Some ``bpfilter`` objects wrap resources whose real owner is the kernel: ``bf_map`` (BPF maps), ``bf_link`` (BPF links), ``bf_handle`` (BPF programs, maps, and links). Each follows the standard heap-object discipline (``_free_bf_map_``, ``_free_bf_link_``, ``_free_bf_handle_``) and its ``bf_<type>_free`` closes the embedded fd as part of cleanup.

What makes these objects unusual is that closing the fd does **not** necessarily destroy the kernel resource. A BPF map, link, or program persists as long as any of the following holds a reference:

- An open fd anywhere in the system.
- A pin in bpffs.

Two consequences for reviewers:

- Forgetting ``_free_bf_link_`` on a local leaks the userspace struct *and* potentially detaches the BPF program from its hook when the kernel link's last reference goes away. Cleanup correctness has user-visible side effects beyond memory.
- Conversely, a pinned object survives the death of every userspace handle. ``bf_link_unpin`` removes the bpffs entry; until that runs, freeing the ``bf_link`` doesn't actually detach anything. See ``bf_link_free`` for the explicit warning.

Reviewing a change that allocates, transfers, or releases a ``bf_map`` / ``bf_link`` / ``bf_handle`` requires checking both the userspace lifetime (cleanup attribute, ``TAKE_PTR``) **and** the kernel-side lifetime (pinning / unpinning).


A worked example
----------------

The following constructor exercises every rule in this document. Each annotation calls out the invariant being relied on.

.. code:: c

    struct bf_widget
    {
        char *name;
        int fd;
    };

    #define _free_bf_widget_ __attribute__((cleanup(bf_widget_free)))

    int bf_widget_new(struct bf_widget **out, const char *name)
    {
        _free_bf_widget_ struct bf_widget *w = NULL;  // heap obj; cleanup runs unless TAKE_PTR
        _cleanup_free_ char *name_copy = NULL;        // raw heap; cleanup is free()
        _cleanup_close_ int fd = -1;                  // owned fd; -1 = closep no-op

        assert(out);
        assert(name);

        w = calloc(1, sizeof(*w));
        if (!w)
            return -ENOMEM;
        w->fd = -1;                                   // sentinel before any failure

        name_copy = strdup(name);
        if (!name_copy)
            return -ENOMEM;

        fd = open("/some/resource", O_RDWR);
        if (fd < 0)
            return -errno;

        w->name = TAKE_PTR(name_copy);                // now owned by *w
        w->fd = TAKE_FD(fd);                          // now owned by *w

        *out = TAKE_PTR(w);                           // ownership escapes to caller
        *
        return 0;
    }

Trace each return statement against the rules:

- First ``return -ENOMEM``: nothing has been initialised; ``w``, ``name_copy``, and ``fd`` are at their sentinel values, so all three cleanup attributes are no-ops.
- Second ``return -ENOMEM``: ``w`` is allocated with ``w->fd == -1`` and ``w->name == NULL``. ``bf_widget_free`` must therefore be NULL-safe on every field it touches, just like the cleanup-function contract requires.
- ``return -errno`` after ``open``: ``name_copy`` is non-NULL; ``_cleanup_free_`` will free it. ``w`` is freed by ``_free_bf_widget_``. ``fd`` is negative, so ``_cleanup_close_`` is a no-op.
- The success ``return 0``: every owning local has been transferred via ``TAKE_*``, so each cleanup attribute sees the sentinel value and runs as a no-op. Ownership of the widget is now in the caller's hands.

The caller side mirrors the contract:

.. code:: c

    int caller(void)
    {
        _free_bf_widget_ struct bf_widget *w = NULL;  // unchanged if call fails
        int r;

        r = bf_widget_new(&w, "thingy");
        if (r)
            return r;                                 // *out is unchanged; w stays NULL

        // ... use w ...

        return 0;                                     // bf_widget_free(&w) runs here
    }

Verifying both functions required reading exactly one body each: nowhere did the argument depend on inspecting the implementation of ``bf_widget_free``, ``calloc``, ``strdup``, ``open``, or any other callee. That is the local-verifiability principle in practice.


Common pitfalls
---------------

The bug classes below are recurring failure modes.

**Leak**
    Allocation, fd, or lock not released on some return path.

**Double-free**
    Manual ``free()`` plus a cleanup attribute on the same object; or ``TAKE_*`` missing on ownership transfer; or two cleanup attributes covering the same object.

**Use-after-free / use-after-move**
    Pointer dereferenced after ``TAKE_PTR``, or after the cleanup attribute already ran.

**Uninitialised cleanup**
    ``_free_*`` or ``_cleanup_*`` variable not given a value before a path that returns. For pointers this means missing ``= NULL``; for fds it means missing ``= -1``.

**Broken cleanup contract**
    ``bf_<type>_free`` that isn't NULL-safe, doesn't null out ``*ptr``, takes a single pointer, returns non-void, or has a mismatched ``_free_`` macro.

**Output-parameter mutation on failure**
    Function writes ``*out`` then returns an error, breaking the "unchanged on failure" guarantee.

**Container destructor mismatch**
    ``bf_list``/``bf_vector``/``bf_hashset`` registered with the wrong free function, or ``NULL`` when the element owns resources.

**Fd sentinel violation**
    Fd not initialised to ``-1``, or an explicit ``close(fd)`` on a path that also has ``_cleanup_close_``.

**Lock leak**
    ``bf_lock_init`` succeeded but ``_clean_bf_lock_`` is missing on the local, or the lock escapes its scope.


Dynamic verification
--------------------

When static review leaves a finding uncertain, confirm it by running the unit tests under sanitizers (see :doc:`tests` for the full test layout). With ``-DCMAKE_BUILD_TYPE=debug``, the address and undefined sanitizers are enabled by default:

.. code:: bash

    cmake -S . -B build -DCMAKE_BUILD_TYPE=debug
    make -C build

To narrow on a specific test:

.. code:: bash

    ctest --test-dir build --output-on-failure -R <pattern>


Automated review
----------------

The ``memory-auditor`` subagent applies the rules on this page to a change set (PR, git ref/range, path, or working-tree diff). Invoke it via the ``/memory-audit`` slash command, or let the main agent delegate to it automatically when it sees risky C changes.
