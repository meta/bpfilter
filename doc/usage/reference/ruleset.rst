Ruleset syntax
==============

A ruleset is composed of one or more chains. A chain is defined by its name, its hook (with optional hook options), and its policy, followed by its named sets and its rules:

.. code-block:: text

    chain $NAME $HOOK[{$OPTIONS}] $POLICY
        [set $SET_NAME $KEY [min-size=$MIN_SIZE] in { $ELEMENTS }]...
        [rule
            [$MATCHER]...
            [log [$HEADERS] [every $FREQUENCY]]
            [counter]
            [mark $MARK]
            $VERDICT]...
    [...]

The reference uses the dollar sign (``$``) to prefix values that should be replaced by the user, and brackets (``[]``) for optional values (whether it's a literal or a user-provided value). ``...`` means the previous element can be repeated.

Indentation is not required, but it makes the ruleset easier to read.

.. note::

    ``bfcli`` will ignore everything from a ``#`` to the end of the line. Comments are not supported between the braces of a set.

Example
-------

.. code-block:: text

    # Block selected sources on an ingress interface.
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        set blocklist (ip4.saddr) in { 192.0.2.1; 192.0.2.2 }
        rule
            (ip4.saddr) in blocklist
            counter
            DROP

Don't forget to replace the interface index with the index of the interface you want to filter on, see :doc:`../how-to/block-addresses`.

Definitions
-----------

- :doc:`chains`: how to define a chain, and the policies it supports.
- :doc:`hooks`: the hooks a chain can be attached to, and their options.
- :doc:`rules`: how to define a rule, its actions, and its verdict.
- :doc:`matchers`: the matchers supported by ``bfcli``, with their operators and payloads.
- :doc:`sets`: named and anonymous sets, their keys, and their elements.

A chain defined without hook options can be loaded, but it won't be attached. The syntax is the same whatever the command: it's the command that decides whether an existing chain is replaced or updated, see :doc:`bfcli`.
