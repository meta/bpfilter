Inspect counters and logs
=========================

Is your chain doing what you expect? Counters will tell you how often a rule matched, and logs will show you what it matched.

Read the counters
-----------------

Let's use the chain created in :doc:`block-addresses` as an example:

.. code-block:: shell

    $ sudo bfcli chain get --name block_sources
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 8 packets 628 bytes; error 0 packets 0 bytes; parser-drop 0 packets 0 bytes
        set blocklist (ip4.saddr) in {
            192.0.2.1
            192.0.2.2
        }
        rule
            (ip4.saddr) in blocklist
            counters 3 packets 294 bytes
            DROP

``bfcli`` prints a ``counters`` line for every rule defined with ``counter``.
It shows the number of packets and bytes that matched the rule.
The chain's ``policy`` counter records packets that reached the policy.
The ``error`` counter records processing errors.
Packet hooks display a ``parser-drop`` counter reserved for packets dropped before rule evaluation because they fail parser requirements.

If you want to print all your chains at once, use ``sudo bfcli ruleset get``. Both commands accept ``--no-set-content``, which helps when large sets make the output unreadable.

Log the packets
---------------

Add ``log`` to the rule you are interested in. For example, edit ``block_sources.bf`` to log the packets dropped by our chain:

.. code-block:: text

    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        set blocklist (ip4.saddr) in { 192.0.2.1; 192.0.2.2 }
        rule
            (ip4.saddr) in blocklist
            log internet every 1s
            counter
            DROP

``log internet`` will log the layer 3 header of the packet, and ``every 1s`` limits the rule to one log entry per second. If you changed the blocklist with ``chain update-set``, update the set in the file too: ``chain update`` will replace the content of the set with the one in the file.

Validate the chain, then update it:

.. code-block:: shell

    $ bfcli chain update --from-file block_sources.bf --dry-run
    warning: Hook options are ignored when updating a chain
    info   : --dry-run used, chain not updated
    $ sudo bfcli chain update --from-file block_sources.bf
    warning: Hook options are ignored when updating a chain

``bfcli`` warns you that the hook options are ignored: the chain stays attached, but its counters are reset (see :doc:`update-chain`).

Read the logs
-------------

.. code-block:: shell

    $ sudo bfcli chain logs --name block_sources

    [17:47:28.387499] Rule #0 matched 98 bytes with verdict DROP
      IPv4      : 192.0.2.1       → 192.0.2.100     [icmp, TTL=64]

    [17:47:29.619157] Rule #0 matched 98 bytes with verdict DROP
      IPv4      : 192.0.2.1       → 192.0.2.100     [icmp, TTL=64]

    [17:47:30.835091] Rule #0 matched 98 bytes with verdict DROP
      IPv4      : 192.0.2.1       → 192.0.2.100     [icmp, TTL=64]
    ^C

``bfcli`` will print the log entries as they are published by the chain, so send some traffic from a blocked address while it runs. Every entry contains the index of the rule, its verdict, and the headers you requested. Hit ``Ctrl+C`` to quit: the chain keeps filtering.

If you don't need the full headers, ``log 5-tuple`` will print the addresses, ports, and protocol on a single line, but only for TCP and UDP packets. The ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks have no packet to log: use ``log`` alone, and bpfilter will log the process and the address it connects or sends to. See :doc:`../reference/rules` for all the ``log`` options.
