Hooks
=====

A hook is the location in the kernel a chain is attached to. It's defined once and for all when the chain is created. The hook options tell bpfilter how to attach the chain: to which interface, which cgroup, or with which Netfilter priorities.

Supported hooks
---------------

The following hooks are supported:

- ``BF_HOOK_XDP``: XDP hook.
- ``BF_HOOK_TC_INGRESS``: ingress TC hook.
- ``BF_HOOK_NF_PRE_ROUTING``: similar to ``nftables`` and ``iptables`` prerouting hook.
- ``BF_HOOK_NF_LOCAL_IN``: similar to ``nftables`` and ``iptables`` input hook.
- ``BF_HOOK_CGROUP_SKB_INGRESS``: ingress cgroup_skb hook.
- ``BF_HOOK_CGROUP_SKB_EGRESS``: egress cgroup_skb hook.
- ``BF_HOOK_NF_FORWARD``: similar to ``nftables`` and ``iptables`` forward hook.
- ``BF_HOOK_NF_LOCAL_OUT``: similar to ``nftables`` and ``iptables`` output hook.
- ``BF_HOOK_NF_POST_ROUTING``: similar to ``nftables`` and ``iptables`` postrouting hook.
- ``BF_HOOK_TC_EGRESS``: egress TC hook.
- ``BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4``: cgroup hook for IPv4 ``connect()`` syscalls.
- ``BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6``: cgroup hook for IPv6 ``connect()`` syscalls.
- ``BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4``: cgroup hook for IPv4 UDP ``sendmsg()`` syscalls.
- ``BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6``: cgroup hook for IPv6 UDP ``sendmsg()`` syscalls.


.. note::

    ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks operate on socket metadata rather than packet data. Supported matchers: ``meta.l3_proto``, ``meta.l4_proto``, ``meta.probability``, ``meta.dport``, ``meta.pid``, ``ip4.daddr``, ``ip4.dnet``, ``ip4.proto``, ``ip6.daddr``, ``ip6.dnet``, ``udp.dport``. Connect hooks additionally support ``tcp.dport``. Sendmsg hooks additionally support ``ip4.saddr``, ``ip4.snet``, ``ip6.saddr``, and ``ip6.snet``. Sets are supported with the same per-component restrictions: each set key component must be a matcher supported by the chain's hook. ``meta.dport`` is supported in sets, while ``meta.sport`` is unavailable on these hooks. ``meta.l3_proto`` follows the hook: ``ipv4`` on the ``*4`` hooks, ``ipv6`` on the ``*6`` hooks. For an ``AF_INET6`` socket with ``IPV6_V6ONLY`` off, UDP datagrams to an IPv4 address (``sockaddr_in`` or ``::ffff:a.b.c.d``) and UDP ``connect()`` with a ``sockaddr_in`` run the IPv4 hooks, while ``connect()`` to ``::ffff:a.b.c.d`` runs only the IPv6 hooks, where it matches ``ip6.daddr``.


Hook options
------------

``$OPTIONS`` are hook-specific comma separated key value pairs. A given hook option can only be specified once:

.. flat-table::
   :header-rows: 1
   :widths: 2 2 2 12
   :fill-cells:

   * - Option
     - Required by
     - Supported by
     - Notes
   * - ``ifindex=$IFINDEX``
     - ``BF_HOOK_XDP``, ``BF_HOOK_TC_INGRESS``, ``BF_HOOK_TC_EGRESS``
     - N/A
     - Interface index to attach the program to.
   * - ``cgpath=$CGROUP_PATH``
     - ``BF_HOOK_CGROUP_SKB_*``, ``BF_HOOK_CGROUP_SOCK_ADDR_*``
     - N/A
     - Path to the cgroup to attach to.
   * - ``family=$FAMILY``
     - N/A
     - N/A
     - Deprecated, bpfilter will automatically attach Netfilter chains to both IPv4 and IPv6 families.
   * - ``priorities=$INT1-$INT2``
     - ``BF_HOOK_NF_*``
     - N/A
     - ``INT1`` and ``INT2`` are different non-zero integers. Priority values to use when attaching the chain. Two values are required to ensure atomic update of the chain.

Example
-------

.. code-block:: text

    chain xdp_filter BF_HOOK_XDP{ifindex=2} ACCEPT
    chain local_input BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT
    chain workload_egress BF_HOOK_CGROUP_SKB_EGRESS{cgpath=/sys/fs/cgroup/my.slice} ACCEPT

If your chain was loaded without hook options, you can provide them to ``bfcli chain attach`` using ``--option``, for example ``--option ifindex=2``.

See :doc:`../explanation/hooks` to understand which packets each hook will see, and :doc:`bfcli` for the commands used to load and attach a chain.
