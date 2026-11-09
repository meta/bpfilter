Matchers
========

Matchers are defined such as:

.. code:: shell

    $TYPE [not] [$OP] $PAYLOAD

With:
  - ``$TYPE``: type of the matcher, defines which part of the processed network packet needs to be compared against. All the exact matcher types are defined below.
  - ``not``: optional comparison negation. When used, it prefixes an operator, e.g. ``tcp.sport not eq 80``, ``(ip4.saddr) not in foo``, or, with no operator, ``tcp.sport not 80`` (equivalent to ``tcp.sport not eq 80``).
  - ``$OP``: comparison operation, not all ``$TYPE`` of matchers support all the existing comparison operators:

    - ``eq``: exact equality. This is the default if no ``$OP`` is provided.
    - ``any``: match the packet against a set of data defined as the payload. If any of the member of the payload set is found in the packet, the matcher is positive. For example, if you want to match all the packets with the ``SYN`` or the ``ACK`` flag set: ``tcp.flags any syn,ack``.
    - ``all``: match the packet against a set of data defined as the payload. If all the member of the payload set are found in the packet, the matcher is positive, even if the packet contains more than only the members defined in the payload. For example, to match all the packets containing *at least* the ``ACK`` TCP flag: ``tcp.flags all ACK``.
    - ``in``: matches the packet against a hashed set of reference values. Using the ``in`` operator is useful when the packet's data needs to be compared against a large set of different values. The matcher's type is then used as the set's key, and must be enclosed in parentheses: ``(ip4.saddr) in {192.0.2.1; 192.0.2.2}`` is valid, ``ip4.saddr in {...}`` is not. The tables below describe the payload for a key made of a single matcher. See :doc:`sets` to combine multiple matchers in a key, to use named sets, and for the list of matchers supported by sets.
    - ``range``: matches in a range of values. Formatted as ``$START-$END``. Both ``$START`` and ``$END`` are included in the range.

  - ``$PAYLOAD``: payload to compare to the processed network packet. The exact payload format depends on ``$TYPE``.


Meta
----

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - Interface
      - ``meta.iface``
      - ``eq``
      - ``$INTERFACE``
      - For chains attached to an ingress hook, ``$INTERFACE`` is the input interface, for chains attached to an egress hook, ``$INTERFACE`` is the output interface. ``$INTERFACE`` must be an interface name (e.g., "eth0", "wlan0") or a decimal interface index (e.g., "1", "2").
    * - L3 protocol
      - ``meta.l3_proto``
      - ``eq``
      - ``$PROTOCOL``
      - ``$PROTOCOL`` must be an internet layer protocol name (e.g. "IPv6", case insensitive), or a valid decimal or hexadecimal `IEEE 802 number`_.
    * - L4 protocol
      - ``meta.l4_proto``
      - ``eq``
      - ``$PROTOCOL``
      - ``$PROTOCOL`` must be a transport layer protocol name (e.g. "ICMP", case insensitive), or a valid decimal or hexadecimal `internet protocol number`_.
    * - :rspan:`2` Source port
      - :rspan:`2` ``meta.sport``
      - ``eq``
      - ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Destination port
      - :rspan:`2` ``meta.dport``
      - ``eq``
      - ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - Probability
      - ``meta.probability``
      - ``eq``
      - ``$PROBABILITY``
      - ``$PROBABILITY`` is a floating-point percentage value (i.e., within [0%, 100%], e.g., "50%" or "33.33%"). For ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks, probability applies per socket operation: each ``connect()`` or ``sendmsg()`` call is independently accepted or dropped.
    * - Mark
      - ``meta.mark``
      - ``eq``
      - ``$MARK``
      - ``$MARK`` must be a valid decimal or hexadecimal 32-bits value. Incompatible with ``BF_HOOK_XDP`` and ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks.
    * - :rspan:`1` Flow hash
      - :rspan:`1` ``meta.flow_hash``
      - ``eq``
      - ``$HASH``
      - ``$HASH`` must be a decimal or hexadecimal 32-bits integer. Only compatible with ``BF_HOOK_TC_INGRESS`` and ``BF_HOOK_TC_EGRESS`` hooks.
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` must be decimal or hexadecimal 32-bits integers, with ``$START <= $END``. Only compatible with ``BF_HOOK_TC_INGRESS`` and ``BF_HOOK_TC_EGRESS`` hooks.
    * - Flow probability
      - ``meta.flow_probability``
      - ``eq``
      - ``$PROBABILITY``
      - ``$PROBABILITY`` is a floating-point percentage value (i.e., within [0%, 100%], e.g., "50%" or "33.33%"). Unlike ``meta.probability`` which uses per-packet randomness, ``meta.flow_probability`` computes a deterministic hash from the packet's 5-tuple (source/destination IP, source/destination port, protocol) ensuring all packets from the same flow get the same match decision. Only applies to IPv4/IPv6 packets with TCP or UDP on L4; packets with other protocols are skipped. Compatible with ``BF_HOOK_XDP``, ``BF_HOOK_TC_INGRESS``, ``BF_HOOK_TC_EGRESS``, ``BF_HOOK_CGROUP_SKB_INGRESS``, and ``BF_HOOK_CGROUP_SKB_EGRESS`` hooks.
    * - :rspan:`1` Process ID
      - :rspan:`1` ``meta.pid``
      - ``eq``
      - ``$PID``
      - :rspan:`1` ``$PID`` must be a decimal process ID (thread group ID), as seen from the initial PID namespace. This is the process ID reported by the log entries of ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks, not its namespace-local counterpart. Only compatible with ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks.
    * - ``in``
      - ``{$PID[;...]}``

.. note::

    On packet-based hooks, ``meta.sport`` and ``meta.dport`` are protocol-neutral across TCP and UDP. They do not match packets with other L4 protocols.

IPv4
----

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`1` Source address
      - :rspan:`1` ``ip4.saddr``
      - ``eq``
      - ``$ADDR``
      - :rspan:`3` ``$ADDR`` is an IPv4 address in dotted-decimal format, "ddd.ddd.ddd.ddd", where ddd is a decimal number of up to three digits in the range 0 to 255. To filter on an IPv4 network (using an IPv4 address and a subnet mask), see ``ip4.snet`` or ``ip4.dnet``.
    * - ``in``
      - ``{$ADDR[;...]}``
    * - :rspan:`1` Destination address
      - :rspan:`1` ``ip4.daddr``
      - ``eq``
      - ``$ADDR``
    * - ``in``
      - ``{$ADDR[;...]}``
    * - :rspan:`1` Source network
      - :rspan:`1` ``ip4.snet``
      - ``eq``
      - ``$ADDR/$MASK``
      - :rspan:`3` ``$ADDR`` is an IPv4 network address in dotted-decimal format, \"ddd.ddd.ddd.ddd\", where ddd is a decimal number of up to three digits in the range 0 to 255, ``$MASK`` is a subnet mask in the range 0 to 32.
    * - ``in``
      - ``{$ADDR/$MASK[;...]}``
    * - :rspan:`1` Destination network
      - :rspan:`1` ``ip4.dnet``
      - ``eq``
      - ``$ADDR/$MASK``
    * - ``in``
      - ``{$ADDR/$MASK[;...]}``
    * - Protocol
      - ``ip4.proto``
      - ``eq``
      - ``$PROTOCOL``
      - ``$PROTOCOL`` must be a transport layer protocol name (e.g. "ICMP", case insensitive), or a valid decimal or hexadecimal `internet protocol number`_.
    * - DSCP
      - ``ip4.dscp``
      - ``eq``
      - ``$DSCP``
      - ``$DSCP`` is a `DSCP class name`_ (e.g. "ef", "cs1", "af21", case insensitive) or a numeric value (0-63, decimal or hexadecimal). "be" is accepted as an alias for "cs0".


IPv6
----

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`1` Source address
      - :rspan:`1` ``ip6.saddr``
      - ``eq``
      - ``$ADDR``
      - :rspan:`3` ``$ADDR`` must be an IPv6 address composed of 8 hexadecimal numbers (abbreviations are supported). To filter on an IPv6 network (using an IPv6 address and a subnet mask), see ``ip6.snet`` or ``ip6.dnet``.
    * - ``in``
      - ``{$ADDR[;...]}``
    * - :rspan:`1` Destination address
      - :rspan:`1` ``ip6.daddr``
      - ``eq``
      - ``$ADDR``
    * - ``in``
      - ``{$ADDR[;...]}``
    * - :rspan:`1` Source network
      - :rspan:`1` ``ip6.snet``
      - ``eq``
      - ``$ADDR/$MASK``
      - :rspan:`3` ``$ADDR`` must be an IPv6 address composed of 8 hexadecimal numbers (abbreviations are supported), ``$MASK`` is a subnet mask in the range 0 to 128.
    * - ``in``
      - ``{$ADDR/$MASK[;...]}``
    * - :rspan:`1` Destination network
      - :rspan:`1` ``ip6.dnet``
      - ``eq``
      - ``$ADDR/$MASK``
    * - ``in``
      - ``{$ADDR/$MASK[;...]}``
    * - Next header
      - ``ip6.nexthdr``
      - ``eq``
      - ``$NEXT_HEADER``
      - ``$NEXT_HEADER`` is a transport layer protocol name (e.g. "ICMP", case insensitive), an IPv6 extension header name, or a valid decimal or hexadecimal `internet protocol number`_.
    * - DSCP
      - ``ip6.dscp``
      - ``eq``
      - ``$DSCP``
      - ``$DSCP`` is a `DSCP class name`_ (e.g. "ef", "cs1", "af21", case insensitive) or a numeric value (0-63, decimal or hexadecimal). "be" is accepted as an alias for "cs0".

.. tip::

    The following IPv6 extension header names are recognized by bpfilter: hop, routing, frag, ah, dst, mh.

    bpfilter parses up to 16 IPv6 extension headers. Chains matching on L4 fields (``meta.l4_proto``, ``meta.sport``, ``meta.dport``, ``meta.flow_probability``, ``ip6.nexthdr``, and the TCP, UDP, ICMP and ICMPv6 matchers) drop IPv6 packets with more extension headers and count them as errors.

TCP
---

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`2` Source port
      - :rspan:`2` ``tcp.sport``
      - ``eq``
      - ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Destination port
      - :rspan:`2` ``tcp.dport``
      - ``eq``
      - ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Flags
      - :rspan:`2` ``tcp.flags``
      - ``eq``
      - :rspan:`2` ``$FLAG[,...]``
      - :rspan:`2` ``$FLAG`` is a comma-separated list of one or more TCP flags (``fin``, ``syn``, ``rst``, ``psh``, ``ack``, ``urg``, ``ece``, or ``cwr``). Flags are case-insensitive.
    * - ``any``
    * - ``all``

.. tip::

   The ``tcp.flags`` operators can be confusing, as they can be used to match all, some, or none of the flags available in the TCP header. This section aims to provide clarity to their exact behavior:

   - ``eq``: the TCP header must contain the exact same flags as defined in the rule. The matcher ``tcp.flags eq syn,ack`` will match ``syn,ack``, but not ``syn,ack,fin`` nor ``rst``.
   - ``any``: the TCP header must contain any of the flags defined in the rule. The matcher ``tcp.flags any syn,ack`` will match ``syn``, or ``ack``, or ``syn,ack``, but not ``fin``.
   - ``all``: the TCP header must contain at least the flags defined in the rule. The matcher ``tcp.flags all syn,ack`` will match ``syn,ack,fin``, but not ``syn``, or ``ack,fin``.

   Each operator can be negated with ``not`` to invert the match:

   - ``not eq``: the TCP header must not contain the exact same flags. The matcher ``tcp.flags not eq syn`` will match ``ack``, or ``syn,ack``, but not ``syn`` alone.
   - ``not any``: none of the specified flags may be present. The matcher ``tcp.flags not any syn,ack`` will match ``fin`` or ``rst``, but not ``syn``, ``ack``, or ``syn,ack``.
   - ``not all``: not all of the specified flags are present. The matcher ``tcp.flags not all syn,ack`` will match ``syn`` or ``ack`` alone, but not ``syn,ack`` or ``syn,ack,fin``.


UDP
---

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`2` Source port
      - :rspan:`2` ``udp.sport``
      - ``eq``
      - ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Destination port
      - :rspan:`2` ``udp.dport``
      - ``eq``
      - ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.

ICMP
----

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - Type
      - ``icmp.type``
      - ``eq``
      - ``$TYPE``
      - ``$TYPE`` is an ICMP type name (e.g. "echo-reply", case insensitive), or a decimal or hexadecimal `ICMP type value`_.
    * - Code
      - ``icmp.code``
      - ``eq``
      - ``$CODE``
      - ``$CODE`` is a decimal or hexadecimal `ICMP code value`_.

.. tip::

    The following ICMP type names are recognized by bpfilter: echo-reply, destination-unreachable, source-quench, redirect, echo-request, time-exceeded, parameter-problem, timestamp-request, timestamp-reply, info-request, info-reply, address-mask-request, address-mask-reply, router-advertisement, router-solicitation.

ICMPv6
------

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - Type
      - ``icmpv6.type``
      - ``eq``
      - ``$TYPE``
      - ``$TYPE`` is an ICMPv6 type name (e.g. "echo-reply", case insensitive), or a decimal or hexadecimal `ICMPv6 type value`_.
    * - Code
      - ``icmpv6.code``
      - ``eq``
      - ``$CODE``
      - ``$CODE`` is a decimal or hexadecimal `ICMPv6 code value`_.

.. tip::

    The following ICMPv6 type names are recognized by bpfilter: destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, parameter-problem, mld2-listener-report.


.. _IEEE 802 number: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
.. _internet protocol number: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
.. _ICMP type value: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
.. _ICMP code value: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
.. _ICMPv6 type value: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-2
.. _DSCP class name: https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
.. _ICMPv6 code value: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-3
