Coding style
============

This document describes the code style and guidelines to use for ``bpfilter`` contributors. ClangFormat is used to validate and enforce as many of those rules as possible based on ``.clang-format`` at the root of the repository. The ``check`` build target validates all source files, and the ``fixstyle`` build target can automatically fix all the violations.

.. note::

    The CI will use the ClangFormat version from the latest Fedora release. If you use a different version, you might trigger violation(s) during the CI run, which we expect you to fix.

Formatting
----------

- Use 4 spaces for indentation (no tabs)
- Line length is limited to 80 characters, but string literals should not be split (makes grepping for error messages easier)
- Opening braces should be on the next line for function, structure, and enumeration definition. For control statements, opening braces should be on the same line
- Single-statement bodies don't require braces. However, if either branch of an ``if``/``else`` uses braces, both must use braces

File structure
--------------

Header guards
^^^^^^^^^^^^^

Use ``#pragma once``, not ``#ifndef`` guards:

.. code:: c

    #pragma once

Include ordering
^^^^^^^^^^^^^^^^

Group and order includes as follows, with a blank line between groups:

1. System headers (``<linux/...>``, ``<errno.h>``, ``<stdlib.h>``)
2. External library headers (``<bpfilter/...>``)
3. Local project headers (``"module/file.h"``)

.. code:: c

    #include <linux/bpf.h>
    #include <errno.h>
    #include <stdlib.h>

    #include <bpfilter/chain.h>

    #include "cgen/codegen.h"
    #include "ctx.h"

Forward declarations
^^^^^^^^^^^^^^^^^^^^

Prefer forward declarations over includes when only a pointer to a type is needed:

.. code:: c

    struct bf_chain;
    struct bf_codegen;


Naming conventions
------------------

Functions and variables
^^^^^^^^^^^^^^^^^^^^^^^

- Lowercase with underscores: ``bf_chain_new()``, ``bf_ctx_setup()``
- Prefix with module name: ``bf_chain_*``, ``bf_codegen_*``, ``bf_ctx_*``
- Static functions and variables use leading underscore: ``_bf_ctx_free()``
- CLI utilities use ``bfc_`` prefix: ``bfc_parse_file()``
- Macros use uppercase with underscores: ``EMIT()``, ``TAKE_PTR()``, ``ARRAY_SIZE()``

Types
^^^^^

Structs use ``bf_`` prefix:

.. code:: c

    struct bf_chain
    {
        // Structure definition
    };

Enums use ``bf_`` prefix, values are uppercase with enum prefix:

.. code:: c

    enum bf_log_level
    {
        BF_LOG_DBG,
        BF_LOG_INFO,
        BF_LOG_WARN,
        BF_LOG_ERR,
        _BF_LOG_MAX,  // Sentinel value
    };

Sentinel values use leading underscore and ``_MAX`` suffix.


Functions
---------

Return values
^^^^^^^^^^^^^

- Return ``0`` on success, negative errno on failure (``-ENOMEM``, ``-EEXIST``)
- Cleanup functions return ``void`` and take double pointers

.. code:: c

    int bf_chain_new(struct bf_chain **chain);     // 0 or -errno
    void bf_chain_free(struct bf_chain **chain);   // Sets *chain to NULL
    bool bf_chain_is_empty(const struct bf_chain *chain);

Error checking
^^^^^^^^^^^^^^

Check errors with ``if (r)`` or ``if (r < 0)``:

.. code:: c

    r = bf_chain_new(&chain);
    if (r)
        return r;

Parameter validation
^^^^^^^^^^^^^^^^^^^^

Use ``assert()`` to validate preconditions:

.. code:: c

    int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule)
    {
        assert(chain);
        assert(rule);
        ...
    }

Only use ``assert()`` for pointer values. For other validation, use ``if ()`` with appropriate error logging and return codes.


Memory management
-----------------

See :doc:`memory` for the full reference on memory and resource management conventions: cleanup attributes (``_free_*``, ``_clean_*``, ``_cleanup_free_``, ``_cleanup_close_``), the cleanup-function contract, ownership transfer with ``TAKE_PTR`` / ``TAKE_FD`` / ``TAKE_STRUCT``, the file-descriptor sentinel, the output-parameter contract, memory-helper semantics, container destructors, and common pitfalls.

In short:

- Use ``__attribute__((cleanup))`` extensively. ``_free_*`` for heap-allocated objects, ``_clean_*`` for stack-allocated values with non-trivial teardown.
- Cleanup functions take a double pointer, are a no-op when ``*ptr == NULL``, and set ``*ptr`` to ``NULL`` after freeing.
- Use ``TAKE_PTR`` / ``TAKE_FD`` / ``TAKE_STRUCT`` whenever an owning local escapes (into an output parameter or a struct field).
- ``int bf_x_new(struct bf_x **out, ...)`` returns ``0`` or negative errno, and leaves ``*out`` unchanged on failure.



Error handling and logging
--------------------------

Logging macros
^^^^^^^^^^^^^^

Use the appropriate log level:

- ``bf_dbg()``: debug information
- ``bf_info()``: informational messages
- ``bf_warn()``: warnings
- ``bf_err()``: errors
- ``bf_abort()``: critical errors (terminates)

Log and return errors with ``bf_err_r()``:

.. code:: c

    if (!ptr)
        return bf_err_r(-ENOMEM, "failed to allocate chain");

This logs the error and returns the error code in one statement.

Error codes
^^^^^^^^^^^

Always use negative errno values: ``-ENOMEM``, ``-EINVAL``, ``-EEXIST``, ``-ENOENT``.


Comments
--------

Single-line vs multi-line
^^^^^^^^^^^^^^^^^^^^^^^^^

Use ``//`` for comments that fit on one line, ``/* */`` for longer comments:

.. code:: c

    // Single line comment

    /* Multi-line comment with aligned asterisks
     * and no empty lines. Close on the last text line. */

Avoid:

.. code:: c

    /*
        Empty lines and misaligned asterisks.
    */

Doxygen documentation
^^^^^^^^^^^^^^^^^^^^^

Not every function needs documentation. Skip documentation for trivial getters/setters. Document functions when:

- Behavior needs explanation
- Arguments have specific requirements
- Return values need clarification

For documented functions:

- First line is a brief description with ``@brief`` tag
- Use ``@param`` for parameters, ``@return`` for return values. To reference a parameter in a comment, do not use ``@p``, use backticks instead.
- For pre-requirements to a function or a parameter, use ``@pre``, keep ``@param`` to describe what a parameter is, not what's required from it. Use ``@post`` for post requirements: what the caller can expect once the function succeeds, or fails.
- Use backticks to reference function, variable, and parameter names
- Use ``@code{.c}`` for examples

.. code:: c

    /**
     * @brief Create a new chain from the given parameters.
     *
     * The caller takes ownership of the returned chain and must free it
     * with `bf_chain_free()`.
     *
     * @param chain On success, points to the new chain. Unchanged on
     *        failure.
     * @param type Type of chain to create.
     * @return 0 on success, negative errno on failure.
     */
    int bf_chain_new(struct bf_chain **chain, enum bf_chain_type type);

For Doxygen comments specifically, the first and last lines of multi-line documentation should be empty (unlike regular multi-line comments).


Structs
-------

Document struct purpose in the header. Use inline Doxygen comments for non-obvious fields:

.. code:: c

    /**
     * @brief Represents a filtering chain.
     */
    struct bf_chain
    {
        enum bf_chain_type type;
        struct bf_list rules;  /// List of `struct bf_rule`
        size_t rule_count;
        int flags; /// Bitmask of enum bf_chain_flags
    };


Macros
------

Helper macros
^^^^^^^^^^^^^

Use uppercase for utility macros:

.. code:: c

    ARRAY_SIZE(arr)      // Number of elements
    DUMP(prefix, fmt, ...)  // Debug output

Static assertions
^^^^^^^^^^^^^^^^^

Use ``static_assert()`` to validate assumptions at compile time. This catches errors early and documents invariants:

.. code:: c

    // Validate enum-to-string array size
    static_assert_enum_mapping(log_level_strs, _BF_LOG_MAX);

    // Validate struct size assumptions
    static_assert(sizeof(struct bf_header) == 16, "unexpected header size");


Testing
-------

See :doc:`tests` for testing conventions and guidelines.


Commit messages
---------------

Commit messages should be formatted as ``component: subcomponent: short description``:
- Lowercase, imperative mood ("add", "fix", "remove", not "added", "fixes")
- No period at the end
- Keep under 72 characters

Components are ``lib``, ``cli``, ``tests``, ``build``, ``tools``, ``doc``. Subcomponents reflect the directory structure (e.g., ``tests: e2e:``, ``lib: cgen: link:``). If you're unsure, check the commit history for a hint.

Examples:

.. code::

    lib: matcher: add meta.flow_hash matcher
    tests: e2e: fix end-to-end tests leaving files behind
    build: create targets to run tests suites individually

Use the commit description to explain why the change is necessary. The "what" is taken care of by the code changes. Details about a specific algorithm or complex changes should be documented in the code.
