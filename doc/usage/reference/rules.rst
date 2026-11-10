Rules, actions, and verdicts
============================

Rules are defined such as:

.. code-block:: text

    rule
        [$MATCHER]...
        [log [$HEADERS] [every $FREQUENCY]]
        [counter]
        [mark $MARK]
        $VERDICT

With:
  - ``$MATCHER``: zero or more matchers: the packet has to match all of them. A matcher will either compare the packet's data to a value (see :doc:`matchers`), or check if it's in a set (see :doc:`sets`). Both can be mixed, in any order. A rule without matchers matches every packet or socket operation that reaches it.
  - ``log``: optional. Three forms are supported:

    - ``log $HEADERS``: log specific packet headers. ``$HEADERS`` is a comma-separated list of ``link`` (layer 2), ``internet`` (layer 3), and/or ``transport`` (layer 4). Only supported by packet-based hooks (XDP, TC, NF, cgroup_skb).
    - ``log 5-tuple``: log source and destination addresses and ports, and the transport protocol. This mode is only supported by packet-based hooks and only emits entries for IPv4/IPv6 packets using TCP or UDP. It is mutually exclusive with the packet-layer options; unsupported packets are not logged.
    - ``log``: log all available data for the hook type. For packet-based hooks, this is equivalent to ``log link,internet,transport``. For ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks, this records the process ID (as seen from the initial PID namespace, and from the process' own PID namespace if it isn't the initial one and kernel memory reads are available), process name, destination address, and destination port. Sendmsg hooks additionally include the source address.

    Each form accepts an optional ``every $FREQUENCY`` suffix to rate-limit log events. ``$FREQUENCY`` is a positive number (integer or decimal) followed by a unit: ``ns``, ``us``, ``ms``, or ``s`` (e.g. ``every 1s``, ``every 500ms``, ``every 1.5s``). At most one log entry is emitted per ``$FREQUENCY`` interval per rule. Without ``every``, every match is logged.

    Logging works with integrity and confidentiality lockdown enabled.
    Neither ``LOCKDOWN_BPF_READ_KERNEL`` nor ``LOCKDOWN_BPF_WRITE_USER`` needs
    to be disabled. Under confidentiality lockdown, socket logs omit the
    namespace-local PID. The initial-namespace PID and other socket fields
    remain available.

  - ``counter``: optional literal. If set, the filter will count the number of events matched by the rule. For packet-based hooks, this includes both the number of packets and the total bytes. For ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks, this counts the number of socket operations (``connect()`` or ``sendmsg()`` calls).
  - ``mark``: optional, ``$MARK`` must be a valid decimal or hexadecimal 32-bits value. If set, write the packet's marker value. This marker can be used later on in a rule (see ``meta.mark``) or with a TC filter. Only supported by TC (``BF_HOOK_TC_*``) and cgroup_skb (``BF_HOOK_CGROUP_SKB_*``) hooks.
  - ``$VERDICT``: action taken by the rule if the packet is matched against **all** the criteria: either ``ACCEPT``, ``DROP``, ``CONTINUE``, ``NEXT``, or ``REDIRECT``.

    - ``ACCEPT``: forward the packet to the kernel.
    - ``DROP``: discard the packet.
    - ``CONTINUE``: continue processing subsequent rules (non-terminal).
    - ``NEXT``: stop rule processing and pass the packet to the next BPF program. For TC hooks, this returns ``TCX_NEXT``. For other hooks, this is equivalent to ``ACCEPT``.
    - ``REDIRECT $IFACE $DIR``: redirect the packet to interface ``$IFACE`` in direction ``$DIR``. ``$IFACE`` can be an interface name (e.g., "eth0") or an interface index (e.g., "2"). ``$DIR`` is either ``in`` for ingress or ``out`` for egress.

``log``, ``counter``, and ``mark`` can be specified in any order, each at most once.

In a chain, as soon as a rule matches a packet, its actions are executed and its verdict is applied. If the verdict is ``ACCEPT``, ``DROP``, ``NEXT``, or ``REDIRECT``, the subsequent rules are not processed. Hence, the rules' order matters. If the packet went through all the rules and none of them stopped its processing, the chain's policy is applied.

Note ``CONTINUE`` means a packet can be counted more than once if multiple rules specify ``CONTINUE`` and ``counter``.

.. note::

    ``REDIRECT`` is only supported by the following hooks:
      - ``BF_HOOK_XDP``: only ``out`` direction is supported (XDP always transmits out of the target interface).
      - ``BF_HOOK_TC_INGRESS``, ``BF_HOOK_TC_EGRESS``: both ``in`` and ``out`` directions are supported.

    ``REDIRECT`` is **not** supported by Netfilter (``BF_HOOK_NF_*``), cgroup_skb (``BF_HOOK_CGROUP_SKB_*``), or cgroup_sock_addr (``BF_HOOK_CGROUP_SOCK_ADDR_*``) hooks.

.. note::

    ``NEXT`` has distinct behavior only for TC hooks (``BF_HOOK_TC_INGRESS``, ``BF_HOOK_TC_EGRESS``), where it maps to ``TCX_NEXT`` and defers to the next BPF program in the TCX link. For all other hooks (XDP, Netfilter, cgroup_skb, and cgroup_sock_addr), ``NEXT`` produces the same return code as ``ACCEPT``.

Example
-------

.. code-block:: text

    rule
        ip4.proto eq icmp
        icmp.type eq echo-request
        log internet every 1s
        counter
        DROP

If you want to read the counters and the logs of a chain, see :doc:`../how-to/inspect`.
