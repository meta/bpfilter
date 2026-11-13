Chains
======

Chains are defined such as:

.. code-block:: text

    chain $NAME $HOOK[{$OPTIONS}] $POLICY

With:
  - ``$NAME``: user-defined name for the chain.
  - ``$HOOK``: hook in the kernel to attach the chain to, see :doc:`hooks`.
  - ``$OPTIONS``: optional hook options, between braces. See :doc:`hooks`. Omit the braces if you don't define any option.
  - ``$POLICY``: action taken once the packet went through all the rules, if none of them stopped its processing:

    - ``ACCEPT``: forward the packet to the kernel.
    - ``DROP``: discard the packet.
    - ``NEXT``: pass the packet to the next BPF program. For TC hooks, this maps to ``TCX_NEXT``, deferring the decision to the next program in the TCX link. For other hooks, ``NEXT`` behaves identically to ``ACCEPT`` since these hooks do not distinguish between "accept" and "pass to next program."

    Note: ``CONTINUE``, ``REDIRECT``, and ``REJECT`` are not valid chain policies.


A chain contains its named sets, followed by its rules. See :doc:`ruleset`, :doc:`rules`, and :doc:`sets`.

Example
-------

.. code-block:: text

    chain block_destination BF_HOOK_NF_LOCAL_OUT{priorities=101-102} ACCEPT
        rule
            ip4.daddr eq 192.0.2.1
            counter
            DROP

See :doc:`../explanation/lifecycle` to understand the difference between a loaded chain and an attached chain.
